//! SVCB and HTTPS record values (RFC 9460), in the presentation format this
//! server stores them in.
//!
//! # Why these types exist here
//!
//! They are what DDR (RFC 9462) is made of. A client that has this box as its
//! resolver discovers the box's *encrypted* endpoints by asking it for
//! `_dns.resolver.arpa. SVCB`, and without an SVCB type there is nothing to
//! answer with — which is why encrypted DNS on a Town OS box had to be
//! configured by hand on every client. See [`designation`].
//!
//! # Stored format
//!
//! One line of RFC 9460 §2.1 presentation format:
//!
//! ```text
//! <priority> <target> [key=value ...]
//! 1 dns.home. alpn=dot port=853
//! 2 dns.home. alpn=h2 dohpath=/dns-query{?dns}
//! 0 dns.home.
//! ```
//!
//! Priority `0` is AliasMode, where no params are allowed. Anything else is
//! ServiceMode. A target of `.` means "the owner name itself", which is what a
//! designation record uses when the endpoint is the box being asked.
//!
//! Parsing is deliberately strict — an unparseable value is rejected at the API
//! rather than stored and then silently skipped at serve time, because a record
//! that exists and never answers is the failure mode this codebase keeps
//! finding (a configured blocklist that never blocks, a metrics listener that
//! never binds).

use anyhow::{Context, Result, bail};
use hickory_proto::rr::Name;
use hickory_proto::rr::rdata::svcb::{Alpn, SVCB, SvcParamKey, SvcParamValue, Unknown};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

/// The name a DDR-aware client queries to discover its resolver's encrypted
/// endpoints (RFC 9462 §4).
pub const DDR_DESIGNATION_NAME: &str = "_dns.resolver.arpa.";

/// The `dohpath` SvcParamKey (RFC 9461 §5). hickory has no named variant for
/// it, so it is carried as an unknown key — which is exactly how the wire format
/// treats a key the implementation does not model.
const SVC_PARAM_KEY_DOHPATH: u16 = 7;

/// Parses one line of RFC 9460 presentation format into hickory's SVCB rdata.
///
/// `value` is the stored record value; the owner name and TTL are not part of
/// it.
pub fn parse(value: &str) -> Result<SVCB> {
    let mut fields = value.split_whitespace();
    let priority: u16 = fields
        .next()
        .context("SVCB value is empty: expected \"<priority> <target> [key=value ...]\"")?
        .parse()
        .context("SVCB priority must be a number in 0..=65535")?;

    let target_raw = fields.next().context(
        "SVCB value has no target name: expected \"<priority> <target> [key=value ...]\"",
    )?;
    let target = parse_target(target_raw)?;

    let mut params: Vec<(SvcParamKey, SvcParamValue)> = Vec::new();
    for field in fields {
        let (key, val) = match field.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (field, None),
        };
        params.push(parse_param(key, val)?);
    }

    if priority == 0 && !params.is_empty() {
        // RFC 9460 §2.4.2: AliasMode carries no parameters. Accepting them would
        // store something no client will honour.
        bail!(
            "SVCB priority 0 is AliasMode, which takes no parameters (got {} of them)",
            params.len()
        );
    }

    // The wire format requires strictly increasing key order, and a decoder is
    // required to reject an RRSet that violates it. Sorting here means an
    // operator can write the parameters in any order and still get a record
    // clients accept, rather than one that is silently dropped by every
    // validating client.
    params.sort_by_key(|(k, _)| u16::from(*k));
    if params
        .windows(2)
        .any(|w| u16::from(w[0].0) == u16::from(w[1].0))
    {
        bail!("SVCB parameters contain a duplicate key");
    }

    Ok(SVCB::new(priority, target, params))
}

/// The target name. `.` is the root label, which RFC 9460 §2.5 gives the special
/// meaning "the owner name" — the form a designation record uses when the
/// endpoint is the server being asked.
fn parse_target(raw: &str) -> Result<Name> {
    if raw == "." {
        return Ok(Name::root());
    }
    Name::from_utf8(raw).with_context(|| format!("SVCB target name '{}' is not a valid name", raw))
}

fn parse_param(key: &str, val: Option<&str>) -> Result<(SvcParamKey, SvcParamValue)> {
    match key {
        "alpn" => {
            let v = val.context("alpn= requires a value, e.g. alpn=h2 or alpn=dot,h2")?;
            let tokens: Vec<String> = v
                .split(',')
                .filter(|t| !t.is_empty())
                .map(|t| t.to_string())
                .collect();
            if tokens.is_empty() {
                bail!("alpn= must name at least one protocol");
            }
            Ok((SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(tokens))))
        }
        "no-default-alpn" => {
            if val.is_some() {
                bail!("no-default-alpn takes no value");
            }
            Ok((SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn))
        }
        "port" => {
            let v = val.context("port= requires a value")?;
            let port: u16 = v
                .parse()
                .with_context(|| format!("port='{}' is not a port number", v))?;
            Ok((SvcParamKey::Port, SvcParamValue::Port(port)))
        }
        "dohpath" => {
            // RFC 9461 §5: a URI template, carried as opaque bytes on the wire.
            // It must be relative and rooted, since the client joins it to the
            // scheme and authority it derived from the rest of the record.
            let v = val.context("dohpath= requires a value, e.g. dohpath=/dns-query{?dns}")?;
            if !v.starts_with('/') {
                bail!(
                    "dohpath='{}' must start with '/' — it is a path template, not a URL",
                    v
                );
            }
            Ok((
                SvcParamKey::Unknown(SVC_PARAM_KEY_DOHPATH),
                SvcParamValue::Unknown(Unknown(v.as_bytes().to_vec())),
            ))
        }
        other => {
            // `keyNNNNN=...` is the escape hatch RFC 9460 §2.1 defines for a key
            // the implementation does not model. Anything else is a typo, and a
            // typo'd key would be stored as nothing at all.
            let Some(num) = other.strip_prefix("key") else {
                bail!(
                    "unknown SVCB parameter '{}' (known: alpn, no-default-alpn, port, dohpath, keyNNNNN)",
                    other
                );
            };
            let num: u16 = num
                .parse()
                .with_context(|| format!("'{}' is not a keyNNNNN parameter", other))?;
            let bytes = val.map(|v| v.as_bytes().to_vec()).unwrap_or_default();
            Ok((
                SvcParamKey::Unknown(num),
                SvcParamValue::Unknown(Unknown(bytes)),
            ))
        }
    }
}

/// The record's wire-format RDATA, for DNSSEC canonicalisation.
///
/// Produced by encoding the same rdata that is served, rather than by a second
/// hand-written encoder: a signature is computed over these bytes and verified
/// against the ones on the wire, so two encoders that disagree by a byte make
/// every signature bogus — the failure being that the data validates as an
/// attack rather than as unsigned.
pub fn canonical_rdata(value: &str) -> Option<Vec<u8>> {
    let svcb = parse(value).ok()?;
    let mut buf = Vec::new();
    let mut encoder = BinEncoder::new(&mut buf);
    // Canonical form: no name compression. `BinEncoder` does not compress unless
    // asked, and SVCB target names are not compressible anyway (RFC 9460 §2.2).
    svcb.emit(&mut encoder).ok()?;
    Some(buf)
}

/// Builds the DDR designation records for a resolver (RFC 9462 §4).
///
/// `name` is the name the endpoints are reached and authenticated as — the one
/// the box's certificate carries — and the ports are whatever its listeners are
/// actually bound to. Returns presentation-format values, one per transport, in
/// the priority order a client should prefer them: DoH first (it survives the
/// DPI that filters :853), then DoT, then DoQ.
///
/// The caller stores these at [`DDR_DESIGNATION_NAME`]. That name is inside
/// `arpa.`, which this server never resolves upstream — but the refusal applies
/// only after local data has been consulted, so a designation this box holds is
/// answered from its own records and never leaves the box. That is exactly the
/// property DDR needs: the resolver, and only the resolver, answers for its own
/// designation.
///
/// `doh` is `(port, dohpath, http3)`. The last is whether that endpoint also
/// serves HTTP/3, and it belongs in the record rather than being left to
/// `Alt-Svc`: the header can only reach a client that has already opened a TCP
/// connection, so a client discovering this resolver for the first time would
/// take the h2 path and never learn there was another. The two values are
/// published together (`alpn=h2,h3`) rather than as separate records, because
/// they are one endpoint — same name, same port, same certificate — and RFC 9460
/// §7.1.1 makes `alpn` a list for exactly this.
pub fn designation(
    name: &str,
    doh: Option<(u16, &str, bool)>,
    dot: Option<u16>,
    doq: Option<u16>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut priority = 1u16;
    if let Some((port, path, http3)) = doh {
        let alpn = if http3 { "h2,h3" } else { "h2" };
        out.push(format!(
            "{} {} alpn={} port={} dohpath={}",
            priority, name, alpn, port, path
        ));
        priority += 1;
    }
    if let Some(port) = dot {
        out.push(format!("{} {} alpn=dot port={}", priority, name, port));
        priority += 1;
    }
    if let Some(port) = doq {
        out.push(format!("{} {} alpn=doq port={}", priority, name, port));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_mode_record_parses() {
        let svcb = parse("1 dns.home. alpn=dot port=853").expect("valid");
        assert_eq!(svcb.svc_priority(), 1);
        assert_eq!(svcb.target_name().to_utf8(), "dns.home.");
        assert_eq!(svcb.svc_params().len(), 2);
    }

    #[test]
    fn alias_mode_parses_and_refuses_parameters() {
        assert!(parse("0 dns.home.").is_ok());
        // RFC 9460 §2.4.2. Storing parameters here would be storing something no
        // client will act on.
        let err = parse("0 dns.home. alpn=dot").expect_err("AliasMode takes no parameters");
        assert!(format!("{:#}", err).contains("AliasMode"), "{:#}", err);
    }

    #[test]
    fn a_root_target_means_the_owner_name() {
        let svcb = parse("1 . alpn=dot").expect("valid");
        assert!(svcb.target_name().is_root());
    }

    #[test]
    fn parameters_are_sorted_into_wire_order() {
        // Written port-first; the wire format requires strictly increasing keys
        // (alpn=1 before port=3) and a decoder must reject an RRSet that is not.
        // Accepting the operator's order and fixing it beats storing a record
        // every validating client throws away.
        let svcb = parse("1 dns.home. port=853 alpn=dot").expect("valid");
        let keys: Vec<u16> = svcb
            .svc_params()
            .iter()
            .map(|(k, _)| u16::from(*k))
            .collect();
        assert_eq!(keys, vec![1, 3]);
    }

    #[test]
    fn a_duplicate_parameter_is_refused() {
        assert!(parse("1 dns.home. alpn=dot alpn=h2").is_err());
    }

    #[test]
    fn dohpath_is_carried_as_the_unknown_key_7() {
        let svcb = parse("1 dns.home. alpn=h2 dohpath=/dns-query{?dns}").expect("valid");
        let (key, val) = svcb
            .svc_params()
            .iter()
            .find(|(k, _)| u16::from(*k) == SVC_PARAM_KEY_DOHPATH)
            .expect("dohpath present");
        assert_eq!(u16::from(*key), 7);
        match val {
            SvcParamValue::Unknown(u) => {
                assert_eq!(String::from_utf8_lossy(&u.0), "/dns-query{?dns}");
            }
            other => panic!("dohpath should be an unknown param, got {:?}", other),
        }
    }

    #[test]
    fn a_dohpath_that_is_not_a_path_is_refused() {
        // A full URL here is the mistake worth catching: the client joins the
        // template to an authority it derived itself, so a URL would produce
        // nonsense rather than an error.
        assert!(parse("1 dns.home. dohpath=https://dns.home/dns-query").is_err());
    }

    #[test]
    fn an_unknown_parameter_name_is_refused_rather_than_dropped() {
        let err = parse("1 dns.home. alpen=dot").expect_err("typo must be refused");
        assert!(format!("{:#}", err).contains("alpen"), "{:#}", err);
        // ...but the documented escape hatch still works.
        assert!(parse("1 dns.home. key99=abc").is_ok());
    }

    #[test]
    fn a_malformed_value_is_refused() {
        assert!(parse("").is_err());
        assert!(parse("1").is_err(), "a target is required");
        assert!(parse("notanumber dns.home.").is_err());
        assert!(parse("1 dns.home. port=notaport").is_err());
    }

    #[test]
    fn canonical_rdata_is_the_wire_form_of_what_is_served() {
        // The bytes signed must be the bytes emitted, so this compares against
        // the encoder the serve path uses rather than against a literal: a
        // disagreement of one byte makes every signature bogus, which reads to a
        // validator as an attack rather than as unsigned data.
        let value = "1 dns.home. alpn=dot port=853";
        let bytes = canonical_rdata(value).expect("encodes");

        let mut expected = Vec::new();
        let mut encoder = BinEncoder::new(&mut expected);
        parse(value).unwrap().emit(&mut encoder).unwrap();
        assert_eq!(bytes, expected);

        // Priority is the first two bytes on the wire (RFC 9460 §2.2), which is
        // the cheapest check that this is SVCB RDATA and not something else.
        assert_eq!(&bytes[..2], &1u16.to_be_bytes());
        assert!(!bytes.is_empty());
    }

    #[test]
    fn canonical_rdata_rejects_what_parse_rejects() {
        // Signing something the serve path will not produce would sign a record
        // that never goes out — bogus rather than unsigned.
        assert!(canonical_rdata("not a svcb record").is_none());
    }

    #[test]
    fn the_designation_prefers_doh_then_dot_then_doq() {
        // DoH first because :443 survives the DPI that filters DoT's :853 —
        // the same ordering the resolver's own upstream chain uses.
        let recs = designation(
            "dns.home.",
            Some((443, "/dns-query{?dns}", false)),
            Some(853),
            Some(853),
        );
        assert_eq!(recs.len(), 3);
        assert!(recs[0].starts_with("1 dns.home. alpn=h2 port=443 dohpath=/dns-query{?dns}"));
        assert!(recs[1].starts_with("2 dns.home. alpn=dot port=853"));
        assert!(recs[2].starts_with("3 dns.home. alpn=doq port=853"));
        // Every one of them has to be a record this server will actually serve.
        for r in &recs {
            parse(r).unwrap_or_else(|e| panic!("designation {:?} must parse: {:#}", r, e));
        }
    }

    /// With HTTP/3 running, the DoH endpoint advertises both protocols on one
    /// record. Separate records would be two endpoints as far as a client is
    /// concerned — same name, same port, same certificate — and it would have to
    /// pick between them rather than negotiate.
    #[test]
    fn the_doh_designation_names_http3_when_it_is_served() {
        let with_h3 = designation(
            "dns.home.",
            Some((443, "/dns-query{?dns}", true)),
            None,
            None,
        );
        assert_eq!(with_h3.len(), 1);
        assert!(
            with_h3[0].starts_with("1 dns.home. alpn=h2,h3 port=443 dohpath=/dns-query{?dns}"),
            "{:?}",
            with_h3[0]
        );
        parse(&with_h3[0]).unwrap_or_else(|e| panic!("the h3 designation must parse: {:#}", e));

        // The control: with HTTP/3 off the token must be absent, or every client
        // that believes the record spends a QUIC timeout on a dead endpoint
        // before falling back to the h2 connection it could have had.
        let without = designation(
            "dns.home.",
            Some((443, "/dns-query{?dns}", false)),
            None,
            None,
        );
        assert!(!without[0].contains("h3"), "{:?}", without[0]);
    }

    #[test]
    fn a_transport_that_is_down_is_left_out_of_the_designation() {
        // Advertising an endpoint nothing is listening on is worse than
        // advertising none: a DDR client would prefer it and fail.
        let recs = designation("dns.home.", None, Some(853), None);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].starts_with("1 dns.home. alpn=dot port=853"));
        assert!(designation("dns.home.", None, None, None).is_empty());
    }
}
