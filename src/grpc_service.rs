use crate::db::{Database, DnsRecord, NetworkAssociation, NetworkScope, RecordKind};
use crate::dns_server::DnsServer;
use crate::rbl::{RblChecker, RblProvider};
use crate::ttl_drift::{TtlDriftConfig as TtlDriftCfg, TtlDriftMode};
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

pub mod proto {
    tonic::include_proto!("rolodex_dns");
}

use proto::rolodex_dns_service_server::RolodexDnsService;
#[allow(unused_imports)]
use proto::*;

/// Consecutive failed authentications from one source before it is locked out.
const AUTH_FAILURE_THRESHOLD: u32 = 5;
/// How long a source stays locked out after tripping the threshold. Doubles per
/// consecutive lockout.
const AUTH_LOCKOUT: Duration = Duration::from_secs(30);
/// Ceiling on the lockout, so a source that has been hammering is still allowed
/// to try again eventually rather than being written off forever.
const MAX_AUTH_LOCKOUT: Duration = Duration::from_secs(900);
/// A run of failures this far apart is not a run: the counter resets, so an
/// occasional mistyped token never accumulates into a lockout.
const AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(300);
/// Cap on the number of source addresses tracked at once. The table is keyed by
/// address, so without a bound a distributed flood grows it without limit. See
/// [`RolodexDnsGrpcService::prune_auth_failures`].
const MAX_TRACKED_AUTH_SOURCES: usize = 65536;
/// Key used when the transport reports no peer address. Should not happen on
/// TCP (the only transport that authenticates), but failures must be counted
/// against *something* rather than silently escaping the throttle.
const UNKNOWN_PEER: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// TTL for the DNSKEY records `SignZone` publishes at the zone apex.
const DNSKEY_TTL: u32 = 3600;

/// Whether `name` sits at or beneath `zone`, matching on label boundaries.
///
/// `ends_with` alone would put `notexample.com.` inside `example.com.`, which
/// during signing means signing another zone's records with this zone's key.
fn name_in_zone(name: &str, zone: &str) -> bool {
    let name = crate::db::normalize_name(name);
    let zone = crate::db::normalize_name(zone);
    if name == zone {
        return true;
    }
    if zone == "." {
        return true;
    }
    name.ends_with(&format!(".{}", zone))
}

/// Builds a runtime blocklist provider from the wire representation shared by
/// `RblConfig` and `DnsblConfig`, resolving the refusal codes.
///
/// A bad code is rejected outright (`InvalidArgument`) rather than dropped:
/// a code that silently does not apply turns the provider's "stop querying me"
/// answer back into a listing, which NXDOMAINs every name checked against it —
/// and it would do so with the RPC having reported success.
fn build_rbl_provider(
    zone: &str,
    enabled: bool,
    refusal_codes: &[String],
    refusal_cooldown_secs: u32,
) -> Result<RblProvider, String> {
    let codes = crate::rbl::resolve_refusal_codes(refusal_codes)
        .map_err(|e| format!("blocklist provider '{zone}': {e}"))?;
    Ok(RblProvider {
        zone: zone.to_string(),
        enabled,
        refusal_codes: codes.into(),
        cooldown: (refusal_cooldown_secs > 0)
            .then(|| std::time::Duration::from_secs(u64::from(refusal_cooldown_secs))),
    })
}

/// Renders a per-provider cooldown override for the wire; absent is `0`,
/// meaning "use the list-wide default".
fn cooldown_secs(cooldown: Option<std::time::Duration>) -> u32 {
    cooldown.map(|d| d.as_secs() as u32).unwrap_or(0)
}

/// The currently rotated-out providers, for a `Get*ConfigResponse`.
fn rotated_out_proto(rbl: &RblChecker) -> Vec<proto::RotatedProvider> {
    rbl.rotated_out()
        .into_iter()
        .map(|r| proto::RotatedProvider {
            zone: r.zone,
            code: r.code,
            seconds_remaining: r.seconds_remaining as u32,
        })
        .collect()
}

/// Failed-authentication state for one source address.
struct AuthFailures {
    /// Failures accumulated since the last reset or lockout.
    count: u32,
    /// When the most recent failure arrived, for the [`AUTH_FAILURE_WINDOW`] reset.
    last_failure: Instant,
    /// While set and in the future, every attempt from this source is refused
    /// without comparing the token at all.
    locked_until: Option<Instant>,
    /// Duration of the *next* lockout for this source.
    lockout: Duration,
}

/// The gRPC service implementation for managing rolodex-dns.
pub struct RolodexDnsGrpcService {
    db: Database,
    dns_server: Arc<DnsServer>,
    rbl: Arc<RblChecker>,
    /// The shared secret for TCP authentication. Empty means no auth required.
    shared_secret: String,
    /// Whether this connection is over a Unix socket (bypasses auth).
    is_unix: bool,
    /// External ACME directory URL advertised when minting EAB credentials.
    /// Empty when no ACME issuer is configured.
    acme_directory_url: String,
    /// Common name for the Rolodex root CA created on demand by ACME admin RPCs.
    acme_root_cn: String,
    /// Whether to automatically maintain reverse PTR records for A/AAAA records.
    auto_ptr: bool,
    /// Failed-authentication state per source address, for brute-force
    /// throttling. Keyed by IP so one attacker cannot lock the operator out.
    auth_failures: Arc<DashMap<IpAddr, AuthFailures>>,
}

impl RolodexDnsGrpcService {
    pub fn new(
        db: Database,
        dns_server: Arc<DnsServer>,
        rbl: Arc<RblChecker>,
        shared_secret: String,
        is_unix: bool,
    ) -> Self {
        Self {
            db,
            dns_server,
            rbl,
            shared_secret,
            is_unix,
            acme_directory_url: String::new(),
            acme_root_cn: "Rolodex Root CA".to_string(),
            auto_ptr: false,
            auth_failures: Arc::new(DashMap::new()),
        }
    }

    /// Sets the ACME issuer parameters used by the ACME admin RPCs.
    pub fn with_acme(mut self, directory_url: String, root_cn: String) -> Self {
        self.acme_directory_url = directory_url;
        if !root_cn.is_empty() {
            self.acme_root_cn = root_cn;
        }
        self
    }

    /// Enables or disables automatic reverse PTR maintenance for A/AAAA records.
    pub fn with_auto_ptr(mut self, auto_ptr: bool) -> Self {
        self.auto_ptr = auto_ptr;
        self
    }

    /// Builds the reverse PTR record for an A/AAAA forward record when auto-PTR
    /// is enabled and the value parses as an IP of the matching family. Returns
    /// `None` for other record types, an unparseable value, or when disabled.
    fn auto_ptr_record(
        &self,
        fwd_name: &str,
        kind: RecordKind,
        value: &str,
        ttl: u32,
    ) -> Option<DnsRecord> {
        if !self.auto_ptr {
            return None;
        }
        let ip = match kind {
            RecordKind::A => value
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .map(std::net::IpAddr::V4),
            RecordKind::AAAA => value
                .parse::<std::net::Ipv6Addr>()
                .ok()
                .map(std::net::IpAddr::V6),
            _ => None,
        }?;
        Some(DnsRecord {
            id: None,
            name: crate::db::reverse_ptr_name(ip),
            record_type: RecordKind::PTR,
            value: crate::db::normalize_name(fwd_name),
            ttl,
            priority: 0,
        })
    }

    /// Collects the reverse PTR records that correspond to the A/AAAA forward
    /// records currently matching `(name, type filter, value filter)`. Used to
    /// clean up PTRs when their forward records are removed.
    fn ptr_records_to_remove(
        &self,
        records: &[DnsRecord],
        type_filter: Option<RecordKind>,
        value_filter: &str,
    ) -> Vec<DnsRecord> {
        records
            .iter()
            .filter(|r| matches!(r.record_type, RecordKind::A | RecordKind::AAAA))
            .filter(|r| type_filter.is_none_or(|t| t == r.record_type))
            .filter(|r| value_filter.is_empty() || r.value == value_filter)
            .filter_map(|r| self.auto_ptr_record(&r.name, r.record_type, &r.value, r.ttl))
            .collect()
    }

    /// Validates the auth token. Unix socket connections always pass.
    ///
    /// Two properties beyond "is the token right":
    ///
    /// - **The comparison is constant-time.** `==` on `String` defers to `memcmp`,
    ///   which returns at the first differing byte, so the time taken leaks how
    ///   many leading bytes of the secret were guessed correctly — turning a
    ///   search over the whole secret into a byte-at-a-time one.
    /// - **Failures are throttled per source address** ([`Self::note_auth_failure`]).
    ///   A shared secret is a password, and an online guessing oracle with no
    ///   backoff is what makes a weak one fatal.
    fn check_auth(&self, peer: Option<SocketAddr>, token: &str) -> Result<(), Status> {
        if self.is_unix {
            return Ok(());
        }
        if self.shared_secret.is_empty() {
            return Ok(());
        }
        let source = peer.map(|p| p.ip());
        if let Some(retry_in) = self.throttled_for(source) {
            crate::metrics::metrics().grpc_auth_failures.inc();
            return Err(Status::resource_exhausted(format!(
                "too many failed authentication attempts; retry in {}s",
                retry_in.as_secs().max(1)
            )));
        }
        // `subtle::ConstantTimeEq` over the bytes. Slices of differing length
        // are unequal in constant time for a given pair of lengths; the length
        // of the configured secret is not what needs protecting here — the
        // per-byte match position is.
        if bool::from(token.as_bytes().ct_eq(self.shared_secret.as_bytes())) {
            self.clear_auth_failures(source);
            Ok(())
        } else {
            crate::metrics::metrics().grpc_auth_failures.inc();
            self.note_auth_failure(source);
            Err(Status::unauthenticated("invalid auth token"))
        }
    }

    /// How long `source` must wait before another attempt is considered, or
    /// `None` if it is not currently locked out.
    ///
    /// A served lockout is cleared here rather than by a sweeper, but the entry
    /// is kept: it carries the escalated backoff, so a source that comes
    /// straight back after serving one gets a longer one. `AUTH_FAILURE_WINDOW`
    /// is what eventually forgives it.
    fn throttled_for(&self, source: Option<IpAddr>) -> Option<Duration> {
        let key = source.unwrap_or(UNKNOWN_PEER);
        let mut entry = self.auth_failures.get_mut(&key)?;
        let locked_until = entry.locked_until?;
        match locked_until.checked_duration_since(Instant::now()) {
            Some(remaining) => Some(remaining),
            None => {
                entry.locked_until = None;
                None
            }
        }
    }

    /// Bounds the failure table.
    ///
    /// Entries are keyed by source address, so a distributed flood would grow it
    /// without limit — the same unbounded-table shape as an unswept nonce store,
    /// pointed at the mutex the control plane runs on. Over the cap, anything
    /// idle beyond `AUTH_FAILURE_WINDOW` and not currently locked out is
    /// dropped; if that does not get under the cap, new sources go untracked
    /// (degrading to plain `Unauthenticated` for them) rather than the table
    /// growing. Losing the throttle under a distributed attack is the lesser
    /// failure — the alternative is evicting the entries that are doing the
    /// work, which is what the attacker wants.
    fn prune_auth_failures(&self) -> bool {
        if self.auth_failures.len() < MAX_TRACKED_AUTH_SOURCES {
            return true;
        }
        let now = Instant::now();
        self.auth_failures.retain(|_, f| {
            f.locked_until.is_some_and(|until| until > now)
                || now.duration_since(f.last_failure) <= AUTH_FAILURE_WINDOW
        });
        self.auth_failures.len() < MAX_TRACKED_AUTH_SOURCES
    }

    /// Records a failed attempt from `source`, locking it out once
    /// [`AUTH_FAILURE_THRESHOLD`] failures have accumulated.
    ///
    /// Keyed by source address rather than globally so one attacker cannot lock
    /// the operator out of their own management plane. Consecutive lockouts
    /// double up to [`MAX_AUTH_LOCKOUT`]; a run of failures that goes quiet for
    /// [`AUTH_FAILURE_WINDOW`] starts over, so an occasional fat-fingered token
    /// never accumulates into a lockout.
    fn note_auth_failure(&self, source: Option<IpAddr>) {
        let key = source.unwrap_or(UNKNOWN_PEER);
        if !self.auth_failures.contains_key(&key) && !self.prune_auth_failures() {
            return;
        }
        let now = Instant::now();
        let mut entry = self.auth_failures.entry(key).or_insert(AuthFailures {
            count: 0,
            last_failure: now,
            locked_until: None,
            lockout: AUTH_LOCKOUT,
        });
        if now.duration_since(entry.last_failure) > AUTH_FAILURE_WINDOW {
            entry.count = 0;
            entry.lockout = AUTH_LOCKOUT;
        }
        entry.last_failure = now;
        entry.count += 1;
        if entry.count >= AUTH_FAILURE_THRESHOLD {
            let lockout = entry.lockout;
            entry.locked_until = Some(now + lockout);
            entry.lockout = (lockout * 2).min(MAX_AUTH_LOCKOUT);
            entry.count = 0;
            warn!(
                "Throttling gRPC authentication from {} for {}s after {} failed attempts",
                key,
                lockout.as_secs(),
                AUTH_FAILURE_THRESHOLD
            );
        }
    }

    /// Forgets a source's failure history. Called on every successful
    /// authentication, so a legitimate caller is never throttled by attempts
    /// that preceded it.
    fn clear_auth_failures(&self, source: Option<IpAddr>) {
        self.auth_failures.remove(&source.unwrap_or(UNKNOWN_PEER));
    }

    /// Counts one control-plane call against `method`.
    ///
    /// Called by each RPC alongside its `check_auth`. The label set is bounded by
    /// the service definition — every value is a literal in this file — so it
    /// cannot grow at runtime.
    fn count_rpc(&self, method: &'static str) {
        crate::metrics::metrics().grpc_requests.inc(method);
    }
}

#[tonic::async_trait]
impl RolodexDnsService for RolodexDnsGrpcService {
    async fn add_record(
        &self,
        request: Request<AddRecordRequest>,
    ) -> Result<Response<AddRecordResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("add_record");

        let record = req
            .record
            .ok_or_else(|| Status::invalid_argument("record is required"))?;

        let record_type = RecordKind::from_proto_i32(record.record_type)
            .ok_or_else(|| Status::invalid_argument("invalid record type"))?;

        let ttl = if record.ttl == 0 { 300 } else { record.ttl };

        let db_record = DnsRecord {
            id: None,
            name: record.name.clone(),
            record_type,
            value: record.value.clone(),
            ttl,
            priority: record.priority,
        };

        match self.db.add_record(&db_record) {
            Ok(_) => {
                if let Some(ptr) =
                    self.auto_ptr_record(&record.name, record_type, &record.value, ttl)
                {
                    if let Err(e) = self.db.add_record(&ptr) {
                        warn!(
                            "auto-PTR: failed to add {} -> {}: {}",
                            ptr.name, ptr.value, e
                        );
                    } else {
                        info!("auto-PTR: added {} -> {}", ptr.name, ptr.value);
                    }
                }
                self.dns_server.flush_cache();
                info!(
                    "Added record: {} {:?} {}",
                    record.name, record_type, record.value
                );
                Ok(Response::new(AddRecordResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(AddRecordResponse {
                success: false,
                message: format!("failed to add record: {}", e),
            })),
        }
    }

    async fn remove_record(
        &self,
        request: Request<RemoveRecordRequest>,
    ) -> Result<Response<RemoveRecordResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("remove_record");

        let record_type = RecordKind::from_proto_i32(req.record_type);

        // Gather the PTRs to clean up before the forward records are deleted.
        let ptr_targets = if self.auto_ptr {
            match self.db.lookup(&req.name, None) {
                Ok(recs) => self.ptr_records_to_remove(&recs, record_type, &req.value),
                Err(e) => {
                    warn!("auto-PTR: lookup for {} failed: {}", req.name, e);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        match self.db.remove_records(&req.name, record_type, &req.value) {
            Ok(count) => {
                for ptr in &ptr_targets {
                    if let Err(e) =
                        self.db
                            .remove_records(&ptr.name, Some(RecordKind::PTR), &ptr.value)
                    {
                        warn!("auto-PTR: failed to remove {}: {}", ptr.name, e);
                    }
                }
                self.dns_server.flush_cache();
                info!("Removed {} records for {}", count, req.name);
                Ok(Response::new(RemoveRecordResponse {
                    success: true,
                    removed_count: count as u32,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(RemoveRecordResponse {
                success: false,
                removed_count: 0,
                message: format!("failed to remove records: {}", e),
            })),
        }
    }

    async fn list_records(
        &self,
        request: Request<ListRecordsRequest>,
    ) -> Result<Response<ListRecordsResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_records");

        let record_type = if req.filter_by_type {
            RecordKind::from_proto_i32(req.record_type_filter)
        } else {
            None
        };

        match self.db.list_records(&req.name_filter, record_type) {
            Ok(records) => {
                let proto_records = records
                    .iter()
                    .map(|r| proto::DnsRecord {
                        name: r.name.clone(),
                        record_type: r.record_type.to_proto_i32(),
                        value: r.value.clone(),
                        ttl: r.ttl,
                        priority: r.priority,
                    })
                    .collect();
                Ok(Response::new(ListRecordsResponse {
                    records: proto_records,
                }))
            }
            Err(e) => Err(Status::internal(format!("failed to list records: {}", e))),
        }
    }

    async fn set_forwarders(
        &self,
        request: Request<SetForwarderRequest>,
    ) -> Result<Response<SetForwarderResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("set_forwarders");

        let mut addrs = Vec::new();
        for f in &req.forwarders {
            let addr: SocketAddr = f.parse().map_err(|e| {
                Status::invalid_argument(format!("invalid forwarder address '{}': {}", f, e))
            })?;
            addrs.push(addr);
        }

        self.dns_server.set_forwarders(addrs).await;
        info!("Updated forwarders: {:?}", req.forwarders);

        Ok(Response::new(SetForwarderResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn set_rbl_config(
        &self,
        request: Request<SetRblConfigRequest>,
    ) -> Result<Response<SetRblConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("set_rbl_config");

        let providers = req
            .providers
            .iter()
            .map(|p| {
                build_rbl_provider(
                    &p.zone,
                    p.enabled,
                    &p.refusal_codes,
                    p.refusal_cooldown_secs,
                )
            })
            .collect::<Result<Vec<RblProvider>, String>>()
            .map_err(Status::invalid_argument)?;

        self.rbl
            .set_refusal_cooldown(u64::from(req.refusal_cooldown_secs));
        self.rbl.set_config(req.enabled, providers).await;
        info!("Updated RBL config: enabled={}", req.enabled);

        Ok(Response::new(SetRblConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_rbl_config(
        &self,
        request: Request<GetRblConfigRequest>,
    ) -> Result<Response<GetRblConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_rbl_config");

        let (enabled, providers) = self.rbl.get_config().await;
        let default_cooldown = self.rbl.refusal_cooldown();
        let proto_providers = providers
            .iter()
            .map(|p| proto::RblConfig {
                zone: p.zone.clone(),
                enabled: p.enabled,
                refusal_codes: p.refusal_code_strings(),
                refusal_cooldown_secs: cooldown_secs(p.cooldown),
            })
            .collect();

        Ok(Response::new(GetRblConfigResponse {
            enabled,
            providers: proto_providers,
            refusal_cooldown_secs: default_cooldown.as_secs() as u32,
            rotated_out: rotated_out_proto(&self.rbl),
        }))
    }

    async fn set_dnsbl_config(
        &self,
        request: Request<SetDnsblConfigRequest>,
    ) -> Result<Response<SetDnsblConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("set_dnsbl_config");

        let providers = req
            .providers
            .iter()
            .map(|p| {
                build_rbl_provider(
                    &p.zone,
                    p.enabled,
                    &p.refusal_codes,
                    p.refusal_cooldown_secs,
                )
            })
            .collect::<Result<Vec<RblProvider>, String>>()
            .map_err(Status::invalid_argument)?;

        self.rbl
            .set_dnsbl_refusal_cooldown(u64::from(req.refusal_cooldown_secs));
        self.rbl.set_dnsbl_config(req.enabled, providers).await;
        // Blocking a domain changes what should/shouldn't be served from the
        // DNS response cache, so flush it to avoid serving a stale answer.
        self.dns_server.flush_cache();
        info!("Updated DNSBL config: enabled={}", req.enabled);

        Ok(Response::new(SetDnsblConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_dnsbl_config(
        &self,
        request: Request<GetDnsblConfigRequest>,
    ) -> Result<Response<GetDnsblConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_dnsbl_config");

        let (enabled, providers) = self.rbl.get_dnsbl_config().await;
        let default_cooldown = self.rbl.dnsbl_refusal_cooldown();
        let proto_providers = providers
            .iter()
            .map(|p| proto::DnsblConfig {
                zone: p.zone.clone(),
                enabled: p.enabled,
                refusal_codes: p.refusal_code_strings(),
                refusal_cooldown_secs: cooldown_secs(p.cooldown),
            })
            .collect();

        Ok(Response::new(GetDnsblConfigResponse {
            enabled,
            providers: proto_providers,
            refusal_cooldown_secs: default_cooldown.as_secs() as u32,
            rotated_out: rotated_out_proto(&self.rbl),
        }))
    }

    async fn flush_cache(
        &self,
        request: Request<FlushCacheRequest>,
    ) -> Result<Response<FlushCacheResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("flush_cache");

        self.rbl.flush_cache().await;
        info!("Flushed caches");

        Ok(Response::new(FlushCacheResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn create_network_scope(
        &self,
        request: Request<CreateNetworkScopeRequest>,
    ) -> Result<Response<CreateNetworkScopeResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("create_network_scope");

        let scope = req
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;

        if scope.name.is_empty() {
            return Err(Status::invalid_argument("scope name is required"));
        }

        let home_domain = if scope.home_domain.is_empty() {
            format!("{}.home", scope.name)
        } else {
            scope.home_domain.clone()
        };

        let db_scope = NetworkScope {
            name: scope.name.clone(),
            home_domain,
        };

        match self.db.create_network_scope(&db_scope) {
            Ok(_) => {
                // Register any additional owned TLDs supplied at creation time.
                for tld in &scope.tlds {
                    if let Err(e) = self.db.add_scope_tld(&scope.name, tld) {
                        return Ok(Response::new(CreateNetworkScopeResponse {
                            success: false,
                            message: format!("scope created but tld '{}' failed: {}", tld, e),
                        }));
                    }
                }
                self.dns_server.flush_cache();
                info!("Created network scope: {}", scope.name);
                Ok(Response::new(CreateNetworkScopeResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(CreateNetworkScopeResponse {
                success: false,
                message: format!("failed to create scope: {}", e),
            })),
        }
    }

    async fn delete_network_scope(
        &self,
        request: Request<DeleteNetworkScopeRequest>,
    ) -> Result<Response<DeleteNetworkScopeResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("delete_network_scope");

        if req.name.is_empty() {
            return Err(Status::invalid_argument("scope name is required"));
        }

        match self.db.delete_network_scope(&req.name) {
            Ok(true) => {
                info!("Deleted network scope: {}", req.name);
                Ok(Response::new(DeleteNetworkScopeResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(DeleteNetworkScopeResponse {
                success: false,
                message: format!("scope '{}' not found", req.name),
            })),
            Err(e) => Ok(Response::new(DeleteNetworkScopeResponse {
                success: false,
                message: format!("failed to delete scope: {}", e),
            })),
        }
    }

    async fn list_network_scopes(
        &self,
        request: Request<ListNetworkScopesRequest>,
    ) -> Result<Response<ListNetworkScopesResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_network_scopes");

        match self.db.list_network_scopes() {
            Ok(scopes) => {
                let mut proto_scopes = Vec::with_capacity(scopes.len());
                for s in &scopes {
                    let tlds = self.db.list_scope_tlds(&s.name).map_err(|e| {
                        Status::internal(format!("failed to list scope tlds: {}", e))
                    })?;
                    proto_scopes.push(proto::NetworkScope {
                        name: s.name.clone(),
                        home_domain: s.home_domain.clone(),
                        tlds,
                    });
                }
                Ok(Response::new(ListNetworkScopesResponse {
                    scopes: proto_scopes,
                }))
            }
            Err(e) => Err(Status::internal(format!("failed to list scopes: {}", e))),
        }
    }

    async fn join_network(
        &self,
        request: Request<JoinNetworkRequest>,
    ) -> Result<Response<JoinNetworkResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("join_network");

        if req.ip_address.is_empty() {
            return Err(Status::invalid_argument("ip_address is required"));
        }
        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }

        let ttl = if req.ttl_seconds == 0 {
            300
        } else {
            req.ttl_seconds
        };

        let assoc = NetworkAssociation {
            ip_address: req.ip_address.clone(),
            scope_name: req.scope_name.clone(),
            ttl_seconds: ttl,
        };

        match self.db.join_network(&assoc) {
            Ok(_) => {
                info!(
                    "IP {} joined network scope {} (TTL: {}s)",
                    req.ip_address, req.scope_name, ttl
                );
                Ok(Response::new(JoinNetworkResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(JoinNetworkResponse {
                success: false,
                message: format!("failed to join network: {}", e),
            })),
        }
    }

    async fn leave_network(
        &self,
        request: Request<LeaveNetworkRequest>,
    ) -> Result<Response<LeaveNetworkResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("leave_network");

        if req.ip_address.is_empty() {
            return Err(Status::invalid_argument("ip_address is required"));
        }

        match self.db.leave_network(&req.ip_address) {
            Ok(true) => {
                info!("IP {} left network", req.ip_address);
                Ok(Response::new(LeaveNetworkResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(LeaveNetworkResponse {
                success: false,
                message: format!("no association found for {}", req.ip_address),
            })),
            Err(e) => Ok(Response::new(LeaveNetworkResponse {
                success: false,
                message: format!("failed to leave network: {}", e),
            })),
        }
    }

    async fn get_network_associations(
        &self,
        request: Request<GetNetworkAssociationsRequest>,
    ) -> Result<Response<GetNetworkAssociationsResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_network_associations");

        let scope_filter = if req.scope_name.is_empty() {
            None
        } else {
            Some(req.scope_name.as_str())
        };

        match self.db.list_network_associations(scope_filter) {
            Ok(assocs) => {
                let proto_assocs = assocs
                    .iter()
                    .map(|a| proto::NetworkAssociation {
                        ip_address: a.ip_address.clone(),
                        scope_name: a.scope_name.clone(),
                        ttl_seconds: a.ttl_seconds,
                    })
                    .collect();
                Ok(Response::new(GetNetworkAssociationsResponse {
                    associations: proto_assocs,
                }))
            }
            Err(e) => Err(Status::internal(format!(
                "failed to list associations: {}",
                e
            ))),
        }
    }

    async fn add_scoped_record(
        &self,
        request: Request<AddScopedRecordRequest>,
    ) -> Result<Response<AddScopedRecordResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("add_scoped_record");

        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }

        let record = req
            .record
            .ok_or_else(|| Status::invalid_argument("record is required"))?;

        let record_type = RecordKind::from_proto_i32(record.record_type)
            .ok_or_else(|| Status::invalid_argument("invalid record type"))?;

        let ttl = if record.ttl == 0 { 300 } else { record.ttl };

        let db_record = DnsRecord {
            id: None,
            name: record.name.clone(),
            record_type,
            value: record.value.clone(),
            ttl,
            priority: record.priority,
        };

        match self.db.add_scoped_record(&req.scope_name, &db_record) {
            Ok(_) => {
                if let Some(ptr) =
                    self.auto_ptr_record(&record.name, record_type, &record.value, ttl)
                {
                    if let Err(e) = self.db.add_scoped_record(&req.scope_name, &ptr) {
                        warn!(
                            "auto-PTR: failed to add scoped {} -> {} in {}: {}",
                            ptr.name, ptr.value, req.scope_name, e
                        );
                    } else {
                        info!(
                            "auto-PTR: added scoped {} -> {} in {}",
                            ptr.name, ptr.value, req.scope_name
                        );
                    }
                }
                self.dns_server.flush_cache();
                info!(
                    "Added scoped record in {}: {} {:?} {}",
                    req.scope_name, record.name, record_type, record.value
                );
                Ok(Response::new(AddScopedRecordResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(AddScopedRecordResponse {
                success: false,
                message: format!("failed to add scoped record: {}", e),
            })),
        }
    }

    async fn remove_scoped_record(
        &self,
        request: Request<RemoveScopedRecordRequest>,
    ) -> Result<Response<RemoveScopedRecordResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("remove_scoped_record");

        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }

        let record_type = RecordKind::from_proto_i32(req.record_type);

        // Gather scoped PTRs to clean up before the forward records are deleted.
        let ptr_targets = if self.auto_ptr {
            let recs = self.db.lookup_scoped(&req.scope_name, &req.name, None);
            self.ptr_records_to_remove(&recs, record_type, &req.value)
        } else {
            Vec::new()
        };

        match self
            .db
            .remove_scoped_records(&req.scope_name, &req.name, record_type, &req.value)
        {
            Ok(count) => {
                for ptr in &ptr_targets {
                    if let Err(e) = self.db.remove_scoped_records(
                        &req.scope_name,
                        &ptr.name,
                        Some(RecordKind::PTR),
                        &ptr.value,
                    ) {
                        warn!(
                            "auto-PTR: failed to remove scoped {} in {}: {}",
                            ptr.name, req.scope_name, e
                        );
                    }
                }
                self.dns_server.flush_cache();
                info!(
                    "Removed {} scoped records from {} for {}",
                    count, req.scope_name, req.name
                );
                Ok(Response::new(RemoveScopedRecordResponse {
                    success: true,
                    removed_count: count as u32,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(RemoveScopedRecordResponse {
                success: false,
                removed_count: 0,
                message: format!("failed to remove scoped records: {}", e),
            })),
        }
    }

    async fn list_scoped_records(
        &self,
        request: Request<ListScopedRecordsRequest>,
    ) -> Result<Response<ListScopedRecordsResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_scoped_records");

        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }

        let record_type = if req.filter_by_type {
            RecordKind::from_proto_i32(req.record_type_filter)
        } else {
            None
        };

        match self
            .db
            .list_scoped_records(&req.scope_name, &req.name_filter, record_type)
        {
            Ok(records) => {
                let proto_records = records
                    .iter()
                    .map(|r| proto::DnsRecord {
                        name: r.name.clone(),
                        record_type: r.record_type.to_proto_i32(),
                        value: r.value.clone(),
                        ttl: r.ttl,
                        priority: r.priority,
                    })
                    .collect();
                Ok(Response::new(ListScopedRecordsResponse {
                    records: proto_records,
                }))
            }
            Err(e) => Err(Status::internal(format!(
                "failed to list scoped records: {}",
                e
            ))),
        }
    }

    async fn get_search_domains(
        &self,
        request: Request<GetSearchDomainsRequest>,
    ) -> Result<Response<GetSearchDomainsResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_search_domains");

        if req.ip_address.is_empty() {
            return Err(Status::invalid_argument("ip_address is required"));
        }

        match self.db.get_search_domains(&req.ip_address) {
            Ok(domains) => Ok(Response::new(GetSearchDomainsResponse {
                search_domains: domains,
            })),
            Err(e) => Err(Status::internal(format!(
                "failed to get search domains: {}",
                e
            ))),
        }
    }

    // ================================================================
    // Authoritative Zone Management
    // ================================================================

    async fn add_authoritative_zone(
        &self,
        request: Request<AddAuthoritativeZoneRequest>,
    ) -> Result<Response<AddAuthoritativeZoneResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("add_authoritative_zone");

        if req.zone.is_empty() {
            return Err(Status::invalid_argument("zone is required"));
        }

        match self.db.add_authoritative_zone(&req.zone) {
            Ok(_) => {
                info!("Added authoritative zone: {}", req.zone);
                Ok(Response::new(AddAuthoritativeZoneResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(AddAuthoritativeZoneResponse {
                success: false,
                message: format!("failed to add authoritative zone: {}", e),
            })),
        }
    }

    async fn remove_authoritative_zone(
        &self,
        request: Request<RemoveAuthoritativeZoneRequest>,
    ) -> Result<Response<RemoveAuthoritativeZoneResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("remove_authoritative_zone");

        if req.zone.is_empty() {
            return Err(Status::invalid_argument("zone is required"));
        }

        match self.db.remove_authoritative_zone(&req.zone) {
            Ok(true) => {
                info!("Removed authoritative zone: {}", req.zone);
                Ok(Response::new(RemoveAuthoritativeZoneResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(RemoveAuthoritativeZoneResponse {
                success: false,
                message: format!("zone '{}' not found", req.zone),
            })),
            Err(e) => Ok(Response::new(RemoveAuthoritativeZoneResponse {
                success: false,
                message: format!("failed to remove authoritative zone: {}", e),
            })),
        }
    }

    async fn list_authoritative_zones(
        &self,
        request: Request<ListAuthoritativeZonesRequest>,
    ) -> Result<Response<ListAuthoritativeZonesResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_authoritative_zones");

        match self.db.list_authoritative_zones() {
            Ok(zones) => Ok(Response::new(ListAuthoritativeZonesResponse { zones })),
            Err(e) => Err(Status::internal(format!(
                "failed to list authoritative zones: {}",
                e
            ))),
        }
    }

    // ================================================================
    // DNS Cache Management
    // ================================================================

    async fn get_cache_stats(
        &self,
        request: Request<GetCacheStatsRequest>,
    ) -> Result<Response<GetCacheStatsResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_cache_stats");

        let total = self.db.cache_count().unwrap_or(0);
        Ok(Response::new(GetCacheStatsResponse {
            total_entries: total,
            hit_count: 0,
            miss_count: 0,
        }))
    }

    async fn flush_dns_cache(
        &self,
        request: Request<FlushDnsCacheRequest>,
    ) -> Result<Response<FlushDnsCacheResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("flush_dns_cache");

        self.dns_server.flush_cache_explicit();
        match self.db.cache_flush() {
            Ok(_) => {
                info!("Flushed DNS cache");
                Ok(Response::new(FlushDnsCacheResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(FlushDnsCacheResponse {
                success: false,
                message: format!("failed to flush DNS cache: {}", e),
            })),
        }
    }

    // ================================================================
    // TTL Drift Configuration
    // ================================================================

    async fn set_ttl_drift_config(
        &self,
        request: Request<SetTtlDriftConfigRequest>,
    ) -> Result<Response<SetTtlDriftConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("set_ttl_drift_config");

        if let Some(config) = &req.config {
            let mode = match config.mode.as_str() {
                "fixed" => {
                    let secs = crate::ttl_drift::parse_duration_secs(&config.fixed_adjustment)
                        .unwrap_or(0);
                    TtlDriftMode::Fixed {
                        adjustment_secs: secs,
                    }
                }
                "logarithmic" => TtlDriftMode::Logarithmic {
                    multiplier: config.log_multiplier,
                },
                _ => TtlDriftMode::Disabled,
            };
            self.dns_server
                .set_ttl_drift_config(TtlDriftCfg { mode })
                .await;
            info!("TTL drift config set: {:?}", config);
        }

        Ok(Response::new(SetTtlDriftConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_ttl_drift_config(
        &self,
        request: Request<GetTtlDriftConfigRequest>,
    ) -> Result<Response<GetTtlDriftConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_ttl_drift_config");

        let drift = self.dns_server.get_ttl_drift_config().await;
        let (mode_str, fixed_adj, log_mult) = match &drift.mode {
            TtlDriftMode::Disabled => ("disabled".to_string(), String::new(), 0.0),
            TtlDriftMode::Fixed { adjustment_secs } => {
                ("fixed".to_string(), format!("{}s", adjustment_secs), 0.0)
            }
            TtlDriftMode::Logarithmic { multiplier } => {
                ("logarithmic".to_string(), String::new(), *multiplier)
            }
        };

        Ok(Response::new(GetTtlDriftConfigResponse {
            config: Some(TtlDriftConfig {
                mode: mode_str,
                fixed_adjustment: fixed_adj,
                log_multiplier: log_mult,
            }),
        }))
    }

    async fn get_query_latency_stats(
        &self,
        request: Request<GetQueryLatencyStatsRequest>,
    ) -> Result<Response<GetQueryLatencyStatsResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_query_latency_stats");

        match self.db.get_latency_stats() {
            Ok(stats) => {
                let proto_stats = stats
                    .iter()
                    .map(|(server, avg, count)| QueryLatencyStat {
                        server: server.clone(),
                        avg_latency_ms: *avg,
                        query_count: *count,
                    })
                    .collect();
                Ok(Response::new(GetQueryLatencyStatsResponse {
                    stats: proto_stats,
                }))
            }
            Err(e) => Err(Status::internal(format!(
                "failed to get latency stats: {}",
                e
            ))),
        }
    }

    // ================================================================
    // Local RBL Management
    // ================================================================

    async fn add_local_rbl_entry(
        &self,
        request: Request<AddLocalRblEntryRequest>,
    ) -> Result<Response<AddLocalRblEntryResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("add_local_rbl_entry");

        let entry = req
            .entry
            .ok_or_else(|| Status::invalid_argument("entry is required"))?;

        if entry.name.is_empty() {
            return Err(Status::invalid_argument("entry name is required"));
        }

        match self.db.add_local_rbl_entry(&entry.name, &entry.reason) {
            Ok(_) => {
                info!("Added local RBL entry: {}", entry.name);
                Ok(Response::new(AddLocalRblEntryResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(AddLocalRblEntryResponse {
                success: false,
                message: format!("failed to add local RBL entry: {}", e),
            })),
        }
    }

    async fn remove_local_rbl_entry(
        &self,
        request: Request<RemoveLocalRblEntryRequest>,
    ) -> Result<Response<RemoveLocalRblEntryResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("remove_local_rbl_entry");

        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        match self.db.remove_local_rbl_entry(&req.name) {
            Ok(true) => {
                info!("Removed local RBL entry: {}", req.name);
                Ok(Response::new(RemoveLocalRblEntryResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(RemoveLocalRblEntryResponse {
                success: false,
                message: format!("entry '{}' not found", req.name),
            })),
            Err(e) => Ok(Response::new(RemoveLocalRblEntryResponse {
                success: false,
                message: format!("failed to remove local RBL entry: {}", e),
            })),
        }
    }

    async fn list_local_rbl_entries(
        &self,
        request: Request<ListLocalRblEntriesRequest>,
    ) -> Result<Response<ListLocalRblEntriesResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_local_rbl_entries");

        match self.db.list_local_rbl_entries() {
            Ok(entries) => {
                let proto_entries = entries
                    .iter()
                    .map(|(name, reason)| LocalRblEntry {
                        name: name.clone(),
                        reason: reason.clone(),
                    })
                    .collect();
                Ok(Response::new(ListLocalRblEntriesResponse {
                    entries: proto_entries,
                }))
            }
            Err(e) => Err(Status::internal(format!(
                "failed to list local RBL entries: {}",
                e
            ))),
        }
    }

    async fn add_dnsbl_allowlist_entry(
        &self,
        request: Request<AddDnsblAllowlistEntryRequest>,
    ) -> Result<Response<AddDnsblAllowlistEntryResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("add_dnsbl_allowlist_entry");

        let entry = req
            .entry
            .ok_or_else(|| Status::invalid_argument("entry is required"))?;

        if entry.name.trim().is_empty() {
            return Err(Status::invalid_argument("entry name is required"));
        }

        match self
            .db
            .add_dnsbl_allowlist_entry(&entry.name, &entry.reason)
        {
            Ok(_) => {
                info!("Added DNSBL allowlist entry: {}", entry.name);
                Ok(Response::new(AddDnsblAllowlistEntryResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(AddDnsblAllowlistEntryResponse {
                success: false,
                message: format!("failed to add DNSBL allowlist entry: {}", e),
            })),
        }
    }

    async fn remove_dnsbl_allowlist_entry(
        &self,
        request: Request<RemoveDnsblAllowlistEntryRequest>,
    ) -> Result<Response<RemoveDnsblAllowlistEntryResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("remove_dnsbl_allowlist_entry");

        if req.name.trim().is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        match self.db.remove_dnsbl_allowlist_entry(&req.name) {
            Ok(true) => {
                info!("Removed DNSBL allowlist entry: {}", req.name);
                Ok(Response::new(RemoveDnsblAllowlistEntryResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(RemoveDnsblAllowlistEntryResponse {
                success: false,
                message: format!("entry '{}' not found", req.name),
            })),
            Err(e) => Ok(Response::new(RemoveDnsblAllowlistEntryResponse {
                success: false,
                message: format!("failed to remove DNSBL allowlist entry: {}", e),
            })),
        }
    }

    async fn list_dnsbl_allowlist_entries(
        &self,
        request: Request<ListDnsblAllowlistEntriesRequest>,
    ) -> Result<Response<ListDnsblAllowlistEntriesResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_dnsbl_allowlist_entries");

        match self.db.list_dnsbl_allowlist_entries() {
            Ok(entries) => {
                let proto_entries = entries
                    .iter()
                    .map(|(name, reason)| DnsblAllowlistEntry {
                        name: name.clone(),
                        reason: reason.clone(),
                    })
                    .collect();
                Ok(Response::new(ListDnsblAllowlistEntriesResponse {
                    entries: proto_entries,
                }))
            }
            Err(e) => Err(Status::internal(format!(
                "failed to list DNSBL allowlist entries: {}",
                e
            ))),
        }
    }

    // ================================================================
    // Transport Configuration (DoT/DoH/DoQ/Proxy)
    // ================================================================

    async fn set_dot_config(
        &self,
        request: Request<SetDotConfigRequest>,
    ) -> Result<Response<SetDotConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("set_dot_config");
        info!("DoT config set: {:?}", req.config);
        Ok(Response::new(SetDotConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_dot_config(
        &self,
        request: Request<GetDotConfigRequest>,
    ) -> Result<Response<GetDotConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_dot_config");
        Ok(Response::new(GetDotConfigResponse { config: None }))
    }

    async fn set_doh_config(
        &self,
        request: Request<SetDohConfigRequest>,
    ) -> Result<Response<SetDohConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("set_doh_config");
        info!("DoH config set: {:?}", req.config);
        Ok(Response::new(SetDohConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_doh_config(
        &self,
        request: Request<GetDohConfigRequest>,
    ) -> Result<Response<GetDohConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_doh_config");
        Ok(Response::new(GetDohConfigResponse { config: None }))
    }

    async fn set_doq_config(
        &self,
        request: Request<SetDoqConfigRequest>,
    ) -> Result<Response<SetDoqConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("set_doq_config");
        info!("DoQ config set: {:?}", req.config);
        Ok(Response::new(SetDoqConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_doq_config(
        &self,
        request: Request<GetDoqConfigRequest>,
    ) -> Result<Response<GetDoqConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_doq_config");
        Ok(Response::new(GetDoqConfigResponse { config: None }))
    }

    async fn set_proxy_config(
        &self,
        request: Request<SetProxyConfigRequest>,
    ) -> Result<Response<SetProxyConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("set_proxy_config");

        let proxy = req.config.map(|cfg| crate::doh_proxy::ProxyConfig {
            url: cfg.url,
            auth: if cfg.auth.is_empty() {
                None
            } else {
                Some(cfg.auth)
            },
            mode: crate::doh_proxy::ProxyMode::parse(&cfg.mode),
        });

        self.dns_server.set_proxy_config(proxy);
        info!("Proxy config updated");

        Ok(Response::new(SetProxyConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_proxy_config(
        &self,
        request: Request<GetProxyConfigRequest>,
    ) -> Result<Response<GetProxyConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_proxy_config");

        let config = self
            .dns_server
            .get_proxy_config()
            .map(|p| proto::ProxyConfig {
                url: p.url,
                auth: p.auth.unwrap_or_default(),
                mode: p.mode.as_str().to_string(),
            });

        Ok(Response::new(GetProxyConfigResponse { config }))
    }

    // ================================================================
    // DNSSEC Key Management
    // ================================================================

    async fn generate_dnssec_key(
        &self,
        request: Request<GenerateDnssecKeyRequest>,
    ) -> Result<Response<GenerateDnssecKeyResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("generate_dnssec_key");

        let algorithm = crate::dnssec::DnssecAlgorithm::parse(&req.algorithm).ok_or_else(|| {
            Status::invalid_argument(format!("unsupported algorithm: {}", req.algorithm))
        })?;
        let key_type = crate::dnssec::KeyType::parse(&req.key_type).ok_or_else(|| {
            Status::invalid_argument(format!("invalid key type: {}", req.key_type))
        })?;

        // An algorithm we cannot generate is refused outright. Generating
        // Ed25519 and labelling it as the requested algorithm — the previous
        // behaviour — produced a DNSKEY, a DS and a set of RRSIGs that all
        // disagreed with the key material underneath them, which no validator
        // accepts and nothing local reports.
        if !algorithm.signing_supported() {
            return Err(Status::invalid_argument(format!(
                "algorithm {} is not supported; supported algorithms are Ed25519, ECDSA-P256-SHA256 and ECDSA-P384-SHA384",
                algorithm.as_str()
            )));
        }
        let key_pair = crate::dnssec::generate_key(&req.zone, algorithm, key_type)
            .map_err(|e| Status::internal(format!("key generation failed: {}", e)))?;

        let id = self
            .db
            .store_dnssec_key(&crate::db::DnssecKeyParams {
                zone: &req.zone,
                scope: "",
                algorithm: algorithm.as_str(),
                key_type: key_type.as_str(),
                private_key: &key_pair.private_key,
                public_key: &key_pair.public_key,
                key_tag: key_pair.key_tag,
            })
            .map_err(|e| Status::internal(format!("failed to store key: {}", e)))?;

        info!(
            "Generated DNSSEC {} key for zone {} (tag={})",
            key_type.as_str(),
            req.zone,
            key_pair.key_tag
        );

        Ok(Response::new(GenerateDnssecKeyResponse {
            success: true,
            message: String::new(),
            key: Some(DnssecKey {
                id,
                zone: req.zone,
                scope_name: String::new(),
                algorithm: algorithm.as_str().to_string(),
                key_type: key_type.as_str().to_string(),
                key_tag: key_pair.key_tag as u32,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
                expires_at: 0,
                active: true,
            }),
        }))
    }

    async fn list_dnssec_keys(
        &self,
        request: Request<ListDnssecKeysRequest>,
    ) -> Result<Response<ListDnssecKeysResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_dnssec_keys");

        let keys = self
            .db
            .list_dnssec_keys(&req.zone)
            .map_err(|e| Status::internal(format!("failed to list keys: {}", e)))?;

        let proto_keys = keys
            .iter()
            .map(|k| DnssecKey {
                id: k.id,
                zone: k.zone.clone(),
                scope_name: k.scope_name.clone(),
                algorithm: k.algorithm.clone(),
                key_type: k.key_type.clone(),
                key_tag: k.key_tag as u32,
                created_at: k.created_at,
                expires_at: 0,
                active: k.active,
            })
            .collect();

        Ok(Response::new(ListDnssecKeysResponse { keys: proto_keys }))
    }

    async fn delete_dnssec_key(
        &self,
        request: Request<DeleteDnssecKeyRequest>,
    ) -> Result<Response<DeleteDnssecKeyResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("delete_dnssec_key");

        let deleted = self
            .db
            .delete_dnssec_key(req.key_id)
            .map_err(|e| Status::internal(format!("failed to delete key: {}", e)))?;

        if deleted {
            info!("Deleted DNSSEC key {}", req.key_id);
        }

        Ok(Response::new(DeleteDnssecKeyResponse {
            success: deleted,
            message: if deleted {
                String::new()
            } else {
                "key not found".to_string()
            },
        }))
    }

    async fn get_ds_records(
        &self,
        request: Request<GetDsRecordsRequest>,
    ) -> Result<Response<GetDsRecordsResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_ds_records");

        let keys = self
            .db
            .get_active_keys(&req.zone, "KSK")
            .map_err(|e| Status::internal(format!("failed to get keys: {}", e)))?;

        let ds_records: Vec<String> = keys
            .iter()
            .map(|k| {
                let algo = crate::dnssec::DnssecAlgorithm::parse(&k.algorithm)
                    .unwrap_or(crate::dnssec::DnssecAlgorithm::Ed25519);
                let kt = crate::dnssec::KeyType::parse(&k.key_type)
                    .unwrap_or(crate::dnssec::KeyType::KSK);
                crate::dnssec::compute_ds_sha256(&k.zone, k.key_tag, algo, &k.public_key, kt)
            })
            .collect();

        Ok(Response::new(GetDsRecordsResponse { ds_records }))
    }

    async fn sign_zone(
        &self,
        request: Request<SignZoneRequest>,
    ) -> Result<Response<SignZoneResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("sign_zone");

        let zone = crate::db::normalize_name(&req.zone);

        // Get all active keys for this zone
        let all_keys = self
            .db
            .list_dnssec_keys(&zone)
            .map_err(|e| Status::internal(format!("failed to list keys: {}", e)))?;

        if all_keys.is_empty() {
            return Ok(Response::new(SignZoneResponse {
                success: false,
                message: "no DNSSEC keys found for zone".to_string(),
            }));
        }

        // Load each active key's material. A key whose stored algorithm does not
        // match its bytes is dropped here with a warning rather than signed
        // with: a signature labelled with an algorithm it was not made by is
        // worse than a missing one, because it fails at the validator instead of
        // at the operator.
        let mut warnings: Vec<String> = Vec::new();
        let mut signing_keys: Vec<crate::dnssec::SigningKey> = Vec::new();
        for key in all_keys.iter().filter(|k| k.active) {
            let Some(algo) = crate::dnssec::DnssecAlgorithm::parse(&key.algorithm) else {
                warnings.push(format!(
                    "key {} has unknown algorithm {}",
                    key.id, key.algorithm
                ));
                continue;
            };
            let Some(kt) = crate::dnssec::KeyType::parse(&key.key_type) else {
                warnings.push(format!(
                    "key {} has unknown key type {}",
                    key.id, key.key_type
                ));
                continue;
            };
            match crate::dnssec::SigningKey::from_pkcs8(algo, kt, &key.private_key) {
                Ok(loaded) => signing_keys.push(loaded),
                Err(e) => warnings.push(format!(
                    "key {} ({}) unusable: {}",
                    key.id, key.algorithm, e
                )),
            }
        }

        if signing_keys.is_empty() {
            return Ok(Response::new(SignZoneResponse {
                success: false,
                message: format!("no usable DNSSEC keys for zone: {}", warnings.join("; ")),
            }));
        }

        // Republish the DNSKEY RRset from scratch so a deleted or unusable key
        // does not leave a DNSKEY behind advertising a key nothing signs with.
        self.db
            .remove_records(&zone, Some(RecordKind::DNSKEY), "")
            .map_err(|e| Status::internal(format!("failed to clear DNSKEY RRset: {}", e)))?;
        for key in &signing_keys {
            let dnskey_value = format!(
                "{} 3 {} {}",
                key.key_type.flags(),
                key.algorithm as u8,
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    key.public_key()
                ),
            );
            self.db
                .add_record(&crate::db::DnsRecord {
                    id: None,
                    name: zone.clone(),
                    record_type: RecordKind::DNSKEY,
                    value: dnskey_value,
                    ttl: DNSKEY_TTL,
                    priority: 0,
                })
                .map_err(|e| Status::internal(format!("failed to store DNSKEY: {}", e)))?;
        }

        // Collect the zone's records. The `*.` filter is a SQL LIKE, which also
        // matches names that merely end in the zone's text ("notexample.com."
        // for "example.com."), so the label-boundary check is redone in Rust.
        let candidates = self
            .db
            .list_records(&format!("*.{}", zone), None)
            .map_err(|e| Status::internal(format!("failed to list zone records: {}", e)))?;

        // Group into RRsets: all records sharing an owner name and type.
        let mut rrsets: HashMap<(String, RecordKind), Vec<crate::db::DnsRecord>> = HashMap::new();
        // Every in-zone name that currently holds a signature. Collected from
        // the records themselves rather than from the RRsets about to be signed:
        // a name whose last record was deleted since the previous run still has
        // an RRSIG, and it is exactly the one that must not survive.
        let mut signed_names: HashSet<String> = HashSet::new();
        for record in candidates {
            if !name_in_zone(&record.name, &zone) {
                continue;
            }
            // RFC 4035 §2.2: RRSIG RRsets are not themselves signed. The old
            // signatures are cleared below.
            if record.record_type == RecordKind::RRSIG {
                signed_names.insert(record.name.clone());
                continue;
            }
            signed_names.insert(record.name.clone());
            rrsets
                .entry((record.name.clone(), record.record_type))
                .or_default()
                .push(record);
        }

        let now = crate::dnssec::now_secs()
            .map_err(|e| Status::internal(format!("cannot read the clock: {}", e)))?;
        let inception = now.saturating_sub(crate::dnssec::RRSIG_INCEPTION_BACKDATE_SECS as u32);
        let expiration = now.saturating_add(crate::dnssec::RRSIG_VALIDITY_SECS as u32);

        // Clear every existing RRSIG in the zone before re-signing, so a record
        // that has since been deleted does not keep its signature.
        for name in &signed_names {
            self.db
                .remove_records(name, Some(RecordKind::RRSIG), "")
                .map_err(|e| Status::internal(format!("failed to clear RRSIGs: {}", e)))?;
        }

        let mut signed_rrsets = 0usize;
        let mut skipped: Vec<String> = Vec::new();
        // Sort for a deterministic pass, so two runs over the same zone do the
        // same work in the same order and a failure is reproducible.
        let mut ordered: Vec<((String, RecordKind), Vec<crate::db::DnsRecord>)> =
            rrsets.into_iter().collect();
        ordered.sort_by(|a, b| (&a.0.0, a.0.1.wire_type()).cmp(&(&b.0.0, b.0.1.wire_type())));

        for ((owner, kind), records) in ordered {
            // A type with no canonical wire encoding cannot be signed; say so
            // rather than emitting a signature over an invented format.
            if records
                .iter()
                .any(|r| crate::dnssec::canonical_rdata(r).is_none())
            {
                skipped.push(format!("{} {}", owner, kind.as_str()));
                continue;
            }

            // Every RR in an RRset shares one TTL. Where the stored rows
            // disagree the smallest wins, because that is the only choice that
            // cannot outlive what an operator asked to be cached.
            let original_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(DNSKEY_TTL);

            // RFC 4035 §2.1: the DNSKEY RRset is signed by the KSK; everything
            // else by the ZSK. With only one kind of key present, it does both.
            let is_apex_dnskey = kind == RecordKind::DNSKEY && owner == zone;
            let wanted = if is_apex_dnskey {
                crate::dnssec::KeyType::KSK
            } else {
                crate::dnssec::KeyType::ZSK
            };
            let mut signers: Vec<&crate::dnssec::SigningKey> = signing_keys
                .iter()
                .filter(|k| k.key_type == wanted)
                .collect();
            if signers.is_empty() {
                signers = signing_keys.iter().collect();
            }

            for key in signers {
                let value = crate::dnssec::sign_rrset(
                    key,
                    &crate::dnssec::RrsetToSign {
                        signer_zone: &zone,
                        owner: &owner,
                        type_covered: kind,
                        original_ttl,
                        rrset: &records,
                        inception,
                        expiration,
                    },
                )
                .map_err(|e| {
                    Status::internal(format!("failed to sign {} {}: {}", owner, kind.as_str(), e))
                })?;

                self.db
                    .add_record(&crate::db::DnsRecord {
                        id: None,
                        name: owner.clone(),
                        record_type: RecordKind::RRSIG,
                        value,
                        ttl: original_ttl,
                        priority: 0,
                    })
                    .map_err(|e| Status::internal(format!("failed to store RRSIG: {}", e)))?;
            }
            signed_rrsets += 1;
        }

        // Signing rewrites records, so the answer cache must not keep serving
        // the unsigned versions.
        self.dns_server.flush_cache();

        info!(
            "Signed zone {} ({} keys, {} RRsets, {} skipped)",
            zone,
            signing_keys.len(),
            signed_rrsets,
            skipped.len()
        );

        let mut message = String::new();
        if !skipped.is_empty() {
            message.push_str(&format!(
                "skipped {} RRset(s) with no canonical wire form: {}",
                skipped.len(),
                skipped.join(", ")
            ));
        }
        if !warnings.is_empty() {
            if !message.is_empty() {
                message.push_str("; ");
            }
            message.push_str(&warnings.join("; "));
        }

        Ok(Response::new(SignZoneResponse {
            success: true,
            message,
        }))
    }

    // ================================================================
    // DANE + ACME
    // ================================================================

    async fn generate_tlsa_record(
        &self,
        request: Request<GenerateTlsaRecordRequest>,
    ) -> Result<Response<GenerateTlsaRecordResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("generate_tlsa_record");

        let tlsa_value = crate::dane::generate_tlsa_record(
            &req.cert_pem,
            req.usage as u8,
            req.selector as u8,
            req.matching_type as u8,
        )
        .map_err(|e| Status::internal(format!("TLSA generation failed: {}", e)))?;

        // Store as a TLSA DNS record
        let dns_name = crate::dane::tlsa_dns_name(&req.domain, req.port as u16, &req.protocol);
        self.db
            .add_record(&DnsRecord {
                id: None,
                name: dns_name,
                record_type: RecordKind::TLSA,
                value: tlsa_value.clone(),
                ttl: 3600,
                priority: 0,
            })
            .map_err(|e| Status::internal(format!("failed to store TLSA record: {}", e)))?;

        info!("Generated TLSA record for {}", req.domain);

        Ok(Response::new(GenerateTlsaRecordResponse {
            success: true,
            message: String::new(),
            tlsa_record: tlsa_value,
        }))
    }

    async fn list_tlsa_records(
        &self,
        request: Request<ListTlsaRecordsRequest>,
    ) -> Result<Response<ListTlsaRecordsResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_tlsa_records");

        // Query for TLSA records matching _*._*.{domain} pattern
        let filter = format!("*.{}", req.domain);
        let records = self
            .db
            .list_records(&filter, Some(RecordKind::TLSA))
            .map_err(|e| Status::internal(format!("failed to list TLSA records: {}", e)))?;

        let proto_records = records
            .iter()
            .map(|r| proto::DnsRecord {
                name: r.name.clone(),
                record_type: r.record_type.to_proto_i32(),
                value: r.value.clone(),
                ttl: r.ttl,
                priority: r.priority,
            })
            .collect();

        Ok(Response::new(ListTlsaRecordsResponse {
            records: proto_records,
        }))
    }

    async fn generate_dane_root_ca(
        &self,
        request: Request<GenerateDaneRootCaRequest>,
    ) -> Result<Response<GenerateDaneRootCaResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("generate_dane_root_ca");

        let (cert_pem, key_pem) = crate::dane::generate_dane_root_ca(&req.name)
            .map_err(|e| Status::internal(format!("CA generation failed: {}", e)))?;

        self.db
            .store_dane_root_ca(&req.name, &cert_pem, &key_pem)
            .map_err(|e| Status::internal(format!("failed to store CA: {}", e)))?;

        info!("Generated DANE root CA: {}", req.name);

        Ok(Response::new(GenerateDaneRootCaResponse {
            success: true,
            message: String::new(),
            cert_pem,
        }))
    }

    async fn request_acme_cert(
        &self,
        request: Request<RequestAcmeCertRequest>,
    ) -> Result<Response<RequestAcmeCertResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("request_acme_cert");

        // Set up the DNS-01 challenge TXT record
        // In a full implementation, this would interact with an ACME provider
        // For now, we provision the challenge record so it can be resolved
        let token = format!("acme-challenge-{}", req.domain);
        crate::acme::set_acme_challenge(&self.db, &req.domain, &token)
            .map_err(|e| Status::internal(format!("failed to set ACME challenge: {}", e)))?;

        info!(
            "Set ACME challenge for domain {} (provider: {})",
            req.domain, req.provider_url
        );

        Ok(Response::new(RequestAcmeCertResponse {
            success: true,
            message: format!("DNS-01 challenge provisioned for {}", req.domain),
        }))
    }

    async fn get_acme_status(
        &self,
        request: Request<GetAcmeStatusRequest>,
    ) -> Result<Response<GetAcmeStatusResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_acme_status");

        // Check if there's a certificate in the database
        match self.db.get_acme_certificate(&req.domain) {
            Ok(Some(cert)) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let status = if now > cert.expires_at {
                    "expired"
                } else {
                    "valid"
                };
                Ok(Response::new(GetAcmeStatusResponse {
                    status: status.to_string(),
                    expires_at: cert.expires_at,
                    domain: req.domain,
                }))
            }
            Ok(None) => {
                // Check if there's a pending challenge
                let challenge_name =
                    format!("_acme-challenge.{}", req.domain.trim_end_matches('.'));
                let challenges = self.db.lookup(&challenge_name, Some(RecordKind::TXT));
                let status = if challenges.map(|r| !r.is_empty()).unwrap_or(false) {
                    "pending"
                } else {
                    "not_configured"
                };
                Ok(Response::new(GetAcmeStatusResponse {
                    status: status.to_string(),
                    expires_at: 0,
                    domain: req.domain,
                }))
            }
            Err(e) => Err(Status::internal(format!(
                "failed to get ACME status: {}",
                e
            ))),
        }
    }

    // ================================================================
    // DNS64
    // ================================================================

    async fn set_dns64_config(
        &self,
        request: Request<SetDns64ConfigRequest>,
    ) -> Result<Response<SetDns64ConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("set_dns64_config");
        info!("DNS64 config set: {:?}", req.config);
        Ok(Response::new(SetDns64ConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_dns64_config(
        &self,
        request: Request<GetDns64ConfigRequest>,
    ) -> Result<Response<GetDns64ConfigResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("get_dns64_config");
        Ok(Response::new(GetDns64ConfigResponse {
            config: Some(Dns64Config {
                enabled: false,
                prefix: "64:ff9b::".to_string(),
            }),
        }))
    }

    // ================================================================
    // DHCP Pool Management
    // ================================================================

    async fn add_dhcp_pool(
        &self,
        request: Request<AddDhcpPoolRequest>,
    ) -> Result<Response<AddDhcpPoolResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("add_dhcp_pool");
        let pool = req
            .pool
            .ok_or_else(|| Status::invalid_argument("pool is required"))?;
        let db_pool = crate::db::DhcpPool {
            id: 0,
            scope_name: pool.scope_name,
            range_start: pool.range_start,
            range_end: pool.range_end,
            gateway: if pool.gateway.is_empty() {
                None
            } else {
                Some(pool.gateway)
            },
            subnet_mask: if pool.subnet_mask.is_empty() {
                "255.255.255.0".to_string()
            } else {
                pool.subnet_mask
            },
            dns_servers: if pool.dns_servers.is_empty() {
                None
            } else {
                Some(pool.dns_servers)
            },
        };
        match self.db.add_dhcp_pool(&db_pool) {
            Ok(id) => {
                info!("Added DHCP pool {} for scope {}", id, db_pool.scope_name);
                Ok(Response::new(AddDhcpPoolResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(AddDhcpPoolResponse {
                success: false,
                message: e.to_string(),
            })),
        }
    }

    async fn remove_dhcp_pool(
        &self,
        request: Request<RemoveDhcpPoolRequest>,
    ) -> Result<Response<RemoveDhcpPoolResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("remove_dhcp_pool");
        match self.db.remove_dhcp_pool(req.pool_id) {
            Ok(true) => {
                info!("Removed DHCP pool {}", req.pool_id);
                Ok(Response::new(RemoveDhcpPoolResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(RemoveDhcpPoolResponse {
                success: false,
                message: "pool not found".to_string(),
            })),
            Err(e) => Ok(Response::new(RemoveDhcpPoolResponse {
                success: false,
                message: e.to_string(),
            })),
        }
    }

    async fn list_dhcp_pools(
        &self,
        request: Request<ListDhcpPoolsRequest>,
    ) -> Result<Response<ListDhcpPoolsResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_dhcp_pools");
        let scope_filter = if req.scope_name.is_empty() {
            None
        } else {
            Some(req.scope_name.as_str())
        };
        match self.db.list_dhcp_pools(scope_filter) {
            Ok(pools) => {
                let proto_pools = pools
                    .into_iter()
                    .map(|p| proto::DhcpPool {
                        id: p.id,
                        scope_name: p.scope_name,
                        range_start: p.range_start,
                        range_end: p.range_end,
                        gateway: p.gateway.unwrap_or_default(),
                        subnet_mask: p.subnet_mask,
                        dns_servers: p.dns_servers.unwrap_or_default(),
                    })
                    .collect();
                Ok(Response::new(ListDhcpPoolsResponse { pools: proto_pools }))
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    // ================================================================
    // DHCP Lease Management
    // ================================================================

    async fn list_dhcp_leases(
        &self,
        request: Request<ListDhcpLeasesRequest>,
    ) -> Result<Response<ListDhcpLeasesResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_dhcp_leases");
        let scope_filter = if req.scope_name.is_empty() {
            None
        } else {
            Some(req.scope_name.as_str())
        };
        match self.db.list_leases(scope_filter) {
            Ok(leases) => {
                let proto_leases = leases
                    .into_iter()
                    .map(|l| proto::DhcpLease {
                        mac: l.mac,
                        ip: l.ip,
                        scope_name: l.scope_name,
                        hostname: l.hostname.unwrap_or_default(),
                        lease_start: l.lease_start,
                        lease_duration: l.lease_duration,
                        state: l.state,
                    })
                    .collect();
                Ok(Response::new(ListDhcpLeasesResponse {
                    leases: proto_leases,
                }))
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn delete_dhcp_lease(
        &self,
        request: Request<DeleteDhcpLeaseRequest>,
    ) -> Result<Response<DeleteDhcpLeaseResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("delete_dhcp_lease");
        if req.mac.is_empty() {
            return Err(Status::invalid_argument("mac is required"));
        }
        match self.db.delete_lease(&req.mac) {
            Ok(true) => {
                info!("Deleted DHCP lease for MAC {}", req.mac);
                Ok(Response::new(DeleteDhcpLeaseResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(DeleteDhcpLeaseResponse {
                success: false,
                message: "lease not found".to_string(),
            })),
            Err(e) => Ok(Response::new(DeleteDhcpLeaseResponse {
                success: false,
                message: e.to_string(),
            })),
        }
    }

    // ================================================================
    // Per-Scope RBL Providers
    // ================================================================

    async fn add_scope_rbl_provider(
        &self,
        request: Request<AddScopeRblProviderRequest>,
    ) -> Result<Response<AddScopeRblProviderResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("add_scope_rbl_provider");
        let provider = req
            .provider
            .ok_or_else(|| Status::invalid_argument("provider is required"))?;
        // Validate the codes here rather than at read time: a scope provider is
        // stored and re-read much later, and a code that only fails to parse on
        // the query path would fail silently, on a path where the consequence is
        // reading a refusal as a listing.
        crate::rbl::resolve_refusal_codes(&provider.refusal_codes)
            .map_err(Status::invalid_argument)?;
        let db_provider = crate::db::ScopeRblProvider {
            scope_name: provider.scope_name,
            zone: provider.zone,
            enabled: provider.enabled,
            refusal_codes: provider.refusal_codes,
            refusal_cooldown_secs: u64::from(provider.refusal_cooldown_secs),
        };
        match self.db.add_scope_rbl_provider(&db_provider) {
            Ok(()) => {
                info!(
                    "Added scope RBL provider {} for scope {}",
                    db_provider.zone, db_provider.scope_name
                );
                Ok(Response::new(AddScopeRblProviderResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(AddScopeRblProviderResponse {
                success: false,
                message: e.to_string(),
            })),
        }
    }

    async fn remove_scope_rbl_provider(
        &self,
        request: Request<RemoveScopeRblProviderRequest>,
    ) -> Result<Response<RemoveScopeRblProviderResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("remove_scope_rbl_provider");
        match self
            .db
            .remove_scope_rbl_provider(&req.scope_name, &req.zone)
        {
            Ok(true) => {
                info!(
                    "Removed scope RBL provider {} from scope {}",
                    req.zone, req.scope_name
                );
                Ok(Response::new(RemoveScopeRblProviderResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(RemoveScopeRblProviderResponse {
                success: false,
                message: "provider not found".to_string(),
            })),
            Err(e) => Ok(Response::new(RemoveScopeRblProviderResponse {
                success: false,
                message: e.to_string(),
            })),
        }
    }

    async fn list_scope_rbl_providers(
        &self,
        request: Request<ListScopeRblProvidersRequest>,
    ) -> Result<Response<ListScopeRblProvidersResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_scope_rbl_providers");
        match self.db.list_scope_rbl_providers(&req.scope_name) {
            Ok(providers) => {
                let proto_providers = providers
                    .into_iter()
                    .map(|p| proto::ScopeRblProvider {
                        scope_name: p.scope_name,
                        zone: p.zone,
                        enabled: p.enabled,
                        refusal_codes: p.refusal_codes,
                        refusal_cooldown_secs: p.refusal_cooldown_secs as u32,
                    })
                    .collect();
                Ok(Response::new(ListScopeRblProvidersResponse {
                    providers: proto_providers,
                }))
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    // ================================================================
    // Scope TLDs (per-network owned zones, partitioned across networks)
    // ================================================================

    async fn add_scope_tld(
        &self,
        request: Request<AddScopeTldRequest>,
    ) -> Result<Response<AddScopeTldResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("add_scope_tld");
        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }
        if req.tld.is_empty() {
            return Err(Status::invalid_argument("tld is required"));
        }
        // An optional ingress listener IP. Parse (and reject bad input) before
        // touching the database so a typo does not half-register a TLD.
        let listen_ip = if req.listen_ip.is_empty() {
            None
        } else {
            match req.listen_ip.parse::<std::net::IpAddr>() {
                Ok(ip) => Some(ip),
                Err(e) => {
                    return Ok(Response::new(AddScopeTldResponse {
                        success: false,
                        message: format!("invalid listen_ip '{}': {}", req.listen_ip, e),
                    }));
                }
            }
        };
        match self.db.add_scope_tld(&req.scope_name, &req.tld) {
            Ok(_) => {
                if let Some(ip) = listen_ip {
                    if let Err(e) = self.db.set_tld_listener(&req.scope_name, &req.tld, ip) {
                        return Ok(Response::new(AddScopeTldResponse {
                            success: false,
                            message: e.to_string(),
                        }));
                    }
                    self.dns_server.spawn_ingress_listener(ip);
                }
                self.dns_server.flush_cache();
                match listen_ip {
                    Some(ip) => info!(
                        "Added TLD {} to scope {} with ingress listener {}",
                        req.tld, req.scope_name, ip
                    ),
                    None => info!("Added TLD {} to scope {}", req.tld, req.scope_name),
                }
                Ok(Response::new(AddScopeTldResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(AddScopeTldResponse {
                success: false,
                message: e.to_string(),
            })),
        }
    }

    async fn remove_scope_tld(
        &self,
        request: Request<RemoveScopeTldRequest>,
    ) -> Result<Response<RemoveScopeTldResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("remove_scope_tld");
        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }
        // Note the TLD's ingress IP (if any) before removal so we can tear down
        // its listener afterwards — but only once no other TLD still uses it.
        let ingress_ip = self.db.get_tld_ingress(&req.tld);
        match self.db.remove_scope_tld(&req.scope_name, &req.tld) {
            Ok(true) => {
                if let Some(ip) = ingress_ip
                    && !self.db.list_all_tld_ingress_ips().contains(&ip)
                {
                    self.dns_server.stop_ingress_listener(ip);
                }
                self.dns_server.flush_cache();
                info!("Removed TLD {} from scope {}", req.tld, req.scope_name);
                Ok(Response::new(RemoveScopeTldResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(RemoveScopeTldResponse {
                success: false,
                message: format!("tld '{}' not found in scope '{}'", req.tld, req.scope_name),
            })),
            Err(e) => Ok(Response::new(RemoveScopeTldResponse {
                success: false,
                message: e.to_string(),
            })),
        }
    }

    async fn list_scope_tlds(
        &self,
        request: Request<ListScopeTldsRequest>,
    ) -> Result<Response<ListScopeTldsResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_scope_tlds");
        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }
        match self.db.list_all_owned_tlds(&req.scope_name) {
            Ok(tlds) => Ok(Response::new(ListScopeTldsResponse { tlds })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn set_scope_tld_forwarders(
        &self,
        request: Request<SetScopeTldForwardersRequest>,
    ) -> Result<Response<SetScopeTldForwardersResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("set_scope_tld_forwarders");
        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }
        if req.tld.is_empty() {
            return Err(Status::invalid_argument("tld is required"));
        }
        match self
            .db
            .set_scope_tld_forwarders(&req.scope_name, &req.tld, &req.forwarders)
        {
            Ok(_) => {
                self.dns_server.flush_cache();
                info!(
                    "Set {} peer forwarder(s) for scope {} tld {}",
                    req.forwarders.len(),
                    req.scope_name,
                    req.tld
                );
                Ok(Response::new(SetScopeTldForwardersResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(SetScopeTldForwardersResponse {
                success: false,
                message: e.to_string(),
            })),
        }
    }

    async fn list_scope_tld_forwarders(
        &self,
        request: Request<ListScopeTldForwardersRequest>,
    ) -> Result<Response<ListScopeTldForwardersResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_scope_tld_forwarders");
        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }
        match self.db.list_scope_tld_forwarders(&req.scope_name, &req.tld) {
            Ok(forwarders) => Ok(Response::new(ListScopeTldForwardersResponse { forwarders })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn list_scope_tld_listeners(
        &self,
        request: Request<ListScopeTldListenersRequest>,
    ) -> Result<Response<ListScopeTldListenersResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_scope_tld_listeners");
        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }
        match self.db.list_tld_listeners(&req.scope_name) {
            Ok(rows) => {
                let listeners = rows
                    .into_iter()
                    .map(|(tld, ip)| TldListener {
                        tld,
                        listen_ip: ip.to_string(),
                    })
                    .collect();
                Ok(Response::new(ListScopeTldListenersResponse { listeners }))
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    // ================================================================
    // DHCP Certificate Options
    // ================================================================

    async fn set_dhcp_cert_option(
        &self,
        request: Request<SetDhcpCertOptionRequest>,
    ) -> Result<Response<SetDhcpCertOptionResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("set_dhcp_cert_option");
        let opt = req
            .option
            .ok_or_else(|| Status::invalid_argument("option is required"))?;
        let db_opt = crate::db::DhcpCertOption {
            scope_name: opt.scope_name,
            option_code: opt.option_code,
            cert_data: opt.cert_data,
            description: if opt.description.is_empty() {
                None
            } else {
                Some(opt.description)
            },
        };
        match self.db.set_dhcp_cert_option(&db_opt) {
            Ok(()) => {
                info!(
                    "Set DHCP cert option {} for scope {}",
                    db_opt.option_code, db_opt.scope_name
                );
                Ok(Response::new(SetDhcpCertOptionResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(SetDhcpCertOptionResponse {
                success: false,
                message: e.to_string(),
            })),
        }
    }

    async fn remove_dhcp_cert_option(
        &self,
        request: Request<RemoveDhcpCertOptionRequest>,
    ) -> Result<Response<RemoveDhcpCertOptionResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("remove_dhcp_cert_option");
        match self
            .db
            .remove_dhcp_cert_option(&req.scope_name, req.option_code)
        {
            Ok(true) => {
                info!(
                    "Removed DHCP cert option {} from scope {}",
                    req.option_code, req.scope_name
                );
                Ok(Response::new(RemoveDhcpCertOptionResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(RemoveDhcpCertOptionResponse {
                success: false,
                message: "option not found".to_string(),
            })),
            Err(e) => Ok(Response::new(RemoveDhcpCertOptionResponse {
                success: false,
                message: e.to_string(),
            })),
        }
    }

    async fn list_dhcp_cert_options(
        &self,
        request: Request<ListDhcpCertOptionsRequest>,
    ) -> Result<Response<ListDhcpCertOptionsResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_dhcp_cert_options");
        match self.db.list_dhcp_cert_options(&req.scope_name) {
            Ok(options) => {
                let proto_opts = options
                    .into_iter()
                    .map(|o| proto::DhcpCertOption {
                        scope_name: o.scope_name,
                        option_code: o.option_code,
                        cert_data: o.cert_data,
                        description: o.description.unwrap_or_default(),
                    })
                    .collect();
                Ok(Response::new(ListDhcpCertOptionsResponse {
                    options: proto_opts,
                }))
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    // ================================================================
    // ACME Issuer (CA) Administration
    // ================================================================

    async fn ensure_zone_ca(
        &self,
        request: Request<EnsureZoneCaRequest>,
    ) -> Result<Response<EnsureZoneCaResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("ensure_zone_ca");

        crate::ca::ensure_root_ca(&self.db, &self.acme_root_cn)
            .map_err(|e| Status::internal(format!("failed to ensure root CA: {}", e)))?;
        crate::ca::ensure_zone_intermediate(&self.db, &req.zone)
            .map_err(|e| Status::internal(format!("failed to ensure zone CA: {}", e)))?;
        // ensure_zone_intermediate publishes CA records into DNS.
        self.dns_server.flush_cache();

        let root_ca_pem = crate::ca::root_ca_pem(&self.db)
            .map_err(|e| Status::internal(format!("failed to read root CA: {}", e)))?;
        let intermediate_ca_pem = self
            .db
            .get_zone_ca(&req.zone)
            .map_err(|e| Status::internal(e.to_string()))?
            .map(|(cert, _)| cert)
            .unwrap_or_default();

        info!("Ensured zone CA for {}", req.zone);
        Ok(Response::new(EnsureZoneCaResponse {
            success: true,
            message: String::new(),
            root_ca_pem,
            intermediate_ca_pem,
        }))
    }

    async fn create_eab_credential(
        &self,
        request: Request<CreateEabCredentialRequest>,
    ) -> Result<Response<CreateEabCredentialResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("create_eab_credential");

        // Ensure the per-zone CA exists so issuance against this EAB can succeed.
        crate::ca::ensure_root_ca(&self.db, &self.acme_root_cn)
            .map_err(|e| Status::internal(format!("failed to ensure root CA: {}", e)))?;
        crate::ca::ensure_zone_intermediate(&self.db, &req.zone)
            .map_err(|e| Status::internal(format!("failed to ensure zone CA: {}", e)))?;
        // ensure_zone_intermediate publishes CA records into DNS.
        self.dns_server.flush_cache();

        let (kid, secret) = generate_eab()?;
        let hmac_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &secret);
        self.db
            .create_eab(&kid, &secret, Some(&req.zone))
            .map_err(|e| Status::internal(format!("failed to store EAB: {}", e)))?;

        info!("Created EAB credential {} for zone {}", kid, req.zone);
        Ok(Response::new(CreateEabCredentialResponse {
            success: true,
            message: String::new(),
            kid,
            hmac_key: hmac_b64,
            directory_url: self.acme_directory_url.clone(),
        }))
    }

    async fn remove_eab_credential(
        &self,
        request: Request<RemoveEabCredentialRequest>,
    ) -> Result<Response<RemoveEabCredentialResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("remove_eab_credential");
        match self.db.remove_eab(&req.kid) {
            Ok(removed) => Ok(Response::new(RemoveEabCredentialResponse {
                success: removed,
                message: if removed {
                    String::new()
                } else {
                    "no such EAB credential".to_string()
                },
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn list_acme_accounts(
        &self,
        request: Request<ListAcmeAccountsRequest>,
    ) -> Result<Response<ListAcmeAccountsResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_acme_accounts");
        match self.db.list_acme_accounts() {
            Ok(accounts) => {
                let accounts = accounts
                    .into_iter()
                    .map(|a| proto::AcmeAccountInfo {
                        account_id: a.account_id,
                        status: a.status,
                        zone: a.zone.unwrap_or_default(),
                        eab_kid: a.eab_kid.unwrap_or_default(),
                    })
                    .collect();
                Ok(Response::new(ListAcmeAccountsResponse { accounts }))
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn list_acme_certificates(
        &self,
        request: Request<ListAcmeCertificatesRequest>,
    ) -> Result<Response<ListAcmeCertificatesResponse>, Status> {
        let peer = request.remote_addr();
        let req = request.into_inner();
        self.check_auth(peer, &req.auth_token)?;
        self.count_rpc("list_acme_certificates");
        let zone = if req.zone.is_empty() {
            None
        } else {
            Some(req.zone.as_str())
        };
        match self.db.list_acme_certificates(zone) {
            Ok(certs) => {
                let certificates = certs
                    .into_iter()
                    .map(|c| proto::AcmeCertificateInfo {
                        id: c.id,
                        domain: c.domain,
                        issued_at: c.issued_at,
                        expires_at: c.expires_at,
                    })
                    .collect();
                Ok(Response::new(ListAcmeCertificatesResponse { certificates }))
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }
}

/// Generates an EAB credential: a random kid and a base64url HMAC key.
///
/// Returns `(kid, secret_bytes)`. Errors only if the system RNG fails.
fn generate_eab() -> Result<(String, Vec<u8>), Status> {
    use base64::Engine;
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut kid = [0u8; 16];
    let mut secret = [0u8; 32];
    rng.fill(&mut kid)
        .map_err(|_| Status::internal("secure RNG failure"))?;
    rng.fill(&mut secret)
        .map_err(|_| Status::internal("secure RNG failure"))?;
    Ok((
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kid),
        secret.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbl::{RblAnswer, RblResolver};

    struct NeverListedResolver;

    #[async_trait::async_trait]
    impl RblResolver for NeverListedResolver {
        async fn lookup_rbl(&self, _query: &str) -> Result<Option<RblAnswer>, anyhow::Error> {
            Ok(None)
        }
    }

    fn make_test_service() -> RolodexDnsGrpcService {
        let db = Database::open_memory().unwrap();
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
        RolodexDnsGrpcService::new(db, dns_server, rbl, "secret123".to_string(), false)
    }

    fn make_unix_service() -> RolodexDnsGrpcService {
        let db = Database::open_memory().unwrap();
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
        RolodexDnsGrpcService::new(db, dns_server, rbl, "secret123".to_string(), true)
    }

    /// A stand-in peer address for the auth tests.
    fn peer(addr: &str) -> Option<SocketAddr> {
        Some(SocketAddr::new(addr.parse().unwrap(), 40000))
    }

    #[test]
    fn test_auth_valid_token() {
        let service = make_test_service();
        assert!(service.check_auth(peer("127.0.0.1"), "secret123").is_ok());
    }

    #[test]
    fn test_auth_invalid_token() {
        let service = make_test_service();
        assert!(service.check_auth(peer("127.0.0.1"), "wrong").is_err());
    }

    #[test]
    fn test_auth_unix_socket_bypasses() {
        let service = make_unix_service();
        assert!(service.check_auth(None, "").is_ok());
        assert!(service.check_auth(None, "wrong").is_ok());
    }

    #[test]
    fn test_auth_empty_secret_allows_all() {
        let db = Database::open_memory().unwrap();
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
        let service = RolodexDnsGrpcService::new(db, dns_server, rbl, String::new(), false);
        assert!(service.check_auth(peer("127.0.0.1"), "anything").is_ok());
    }

    #[test]
    fn repeated_failures_lock_a_source_out() {
        let service = make_test_service();
        let src = peer("192.0.2.10");

        // Up to the threshold, a wrong token is simply unauthenticated.
        for i in 1..AUTH_FAILURE_THRESHOLD {
            let err = service.check_auth(src, "wrong").unwrap_err();
            assert_eq!(
                err.code(),
                tonic::Code::Unauthenticated,
                "attempt {} should not be throttled yet",
                i
            );
        }

        // The threshold attempt trips the lockout; the next one is refused
        // without the token being considered at all.
        assert_eq!(
            service.check_auth(src, "wrong").unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            service.check_auth(src, "wrong").unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        // Even the *correct* secret is refused while locked out — otherwise the
        // lockout would be a free oracle for "was that guess right?".
        assert_eq!(
            service.check_auth(src, "secret123").unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
    }

    #[test]
    fn a_lockout_is_confined_to_its_source() {
        let service = make_test_service();
        let attacker = peer("192.0.2.10");
        let operator = peer("192.0.2.11");

        for _ in 0..AUTH_FAILURE_THRESHOLD + 1 {
            assert!(service.check_auth(attacker, "wrong").is_err());
        }
        assert_eq!(
            service.check_auth(attacker, "wrong").unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        // Keyed per source, so an attacker cannot lock the operator out of
        // their own management plane.
        assert!(service.check_auth(operator, "secret123").is_ok());
    }

    #[test]
    fn success_forgets_earlier_failures() {
        let service = make_test_service();
        let src = peer("192.0.2.12");

        // Fail just short of the threshold, then succeed: the counter resets, so
        // a fat-fingered token never accumulates across unrelated sessions.
        for _ in 0..AUTH_FAILURE_THRESHOLD - 1 {
            assert!(service.check_auth(src, "wrong").is_err());
        }
        assert!(service.check_auth(src, "secret123").is_ok());
        for _ in 0..AUTH_FAILURE_THRESHOLD - 1 {
            assert_eq!(
                service.check_auth(src, "wrong").unwrap_err().code(),
                tonic::Code::Unauthenticated
            );
        }
    }

    #[test]
    fn a_correct_token_is_never_throttled() {
        let service = make_test_service();
        let src = peer("192.0.2.13");
        // The throttle counts failures, not requests: legitimate automation
        // calling in a loop must never be locked out.
        for i in 0..AUTH_FAILURE_THRESHOLD * 10 {
            assert!(
                service.check_auth(src, "secret123").is_ok(),
                "correct token rejected on call {}",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_add_record() {
        let service = make_test_service();
        let request = Request::new(AddRecordRequest {
            record: Some(proto::DnsRecord {
                name: "test.example.com".to_string(),
                record_type: 0, // A
                value: "192.168.1.1".to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "secret123".to_string(),
        });

        let response = service.add_record(request).await.unwrap();
        assert!(response.into_inner().success);
    }

    #[tokio::test]
    async fn test_add_record_no_auth() {
        let service = make_test_service();
        let request = Request::new(AddRecordRequest {
            record: Some(proto::DnsRecord {
                name: "test.example.com".to_string(),
                record_type: 0,
                value: "192.168.1.1".to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "wrong".to_string(),
        });

        let result = service.add_record(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_add_and_list_records() {
        let service = make_test_service();

        // Add a record
        let add_req = Request::new(AddRecordRequest {
            record: Some(proto::DnsRecord {
                name: "test.example.com".to_string(),
                record_type: 0,
                value: "192.168.1.1".to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "secret123".to_string(),
        });
        service.add_record(add_req).await.unwrap();

        // List all records
        let list_req = Request::new(ListRecordsRequest {
            name_filter: String::new(),
            record_type_filter: 0,
            filter_by_type: false,
            auth_token: "secret123".to_string(),
        });
        let response = service.list_records(list_req).await.unwrap();
        let records = response.into_inner().records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "192.168.1.1");
    }

    #[tokio::test]
    async fn test_add_and_remove_records() {
        let service = make_test_service();

        // Add a record
        let add_req = Request::new(AddRecordRequest {
            record: Some(proto::DnsRecord {
                name: "remove.example.com".to_string(),
                record_type: 0,
                value: "192.168.1.1".to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "secret123".to_string(),
        });
        service.add_record(add_req).await.unwrap();

        // Remove it
        let remove_req = Request::new(RemoveRecordRequest {
            name: "remove.example.com".to_string(),
            record_type: 0,
            value: String::new(),
            auth_token: "secret123".to_string(),
        });
        let response = service.remove_record(remove_req).await.unwrap();
        let inner = response.into_inner();
        assert!(inner.success);
        assert_eq!(inner.removed_count, 1);

        // Verify it's gone
        let list_req = Request::new(ListRecordsRequest {
            name_filter: String::new(),
            record_type_filter: 0,
            filter_by_type: false,
            auth_token: "secret123".to_string(),
        });
        let response = service.list_records(list_req).await.unwrap();
        assert!(response.into_inner().records.is_empty());
    }

    #[tokio::test]
    async fn test_set_forwarders() {
        let service = make_test_service();

        let req = Request::new(SetForwarderRequest {
            forwarders: vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
            auth_token: "secret123".to_string(),
        });
        let response = service.set_forwarders(req).await.unwrap();
        assert!(response.into_inner().success);
    }

    #[tokio::test]
    async fn test_set_forwarders_invalid() {
        let service = make_test_service();

        let req = Request::new(SetForwarderRequest {
            forwarders: vec!["not-an-address".to_string()],
            auth_token: "secret123".to_string(),
        });
        let result = service.set_forwarders(req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rbl_config() {
        let service = make_test_service();

        // Set config
        let set_req = Request::new(SetRblConfigRequest {
            enabled: true,
            providers: vec![proto::RblConfig {
                zone: "test.rbl".to_string(),
                enabled: true,
                ..Default::default()
            }],
            auth_token: "secret123".to_string(),
            ..Default::default()
        });
        let response = service.set_rbl_config(set_req).await.unwrap();
        assert!(response.into_inner().success);

        // Get config
        let get_req = Request::new(GetRblConfigRequest {
            auth_token: "secret123".to_string(),
        });
        let response = service.get_rbl_config(get_req).await.unwrap();
        let config = response.into_inner();
        assert!(config.enabled);
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].zone, "test.rbl");
    }

    #[tokio::test]
    async fn test_dnsbl_config() {
        let service = make_test_service();

        // Defaults: disabled, no providers.
        let get_req = Request::new(GetDnsblConfigRequest {
            auth_token: "secret123".to_string(),
        });
        let config = service
            .get_dnsbl_config(get_req)
            .await
            .unwrap()
            .into_inner();
        assert!(!config.enabled);
        assert!(config.providers.is_empty());

        // Set config.
        let set_req = Request::new(SetDnsblConfigRequest {
            enabled: true,
            providers: vec![
                proto::DnsblConfig {
                    zone: "dbl.spamhaus.org".to_string(),
                    enabled: true,
                    ..Default::default()
                },
                proto::DnsblConfig {
                    zone: "multi.surbl.org".to_string(),
                    enabled: false,
                    ..Default::default()
                },
            ],
            auth_token: "secret123".to_string(),
            ..Default::default()
        });
        assert!(
            service
                .set_dnsbl_config(set_req)
                .await
                .unwrap()
                .into_inner()
                .success
        );

        // Read it back.
        let get_req = Request::new(GetDnsblConfigRequest {
            auth_token: "secret123".to_string(),
        });
        let config = service
            .get_dnsbl_config(get_req)
            .await
            .unwrap()
            .into_inner();
        assert!(config.enabled);
        assert_eq!(config.providers.len(), 2);
        assert_eq!(config.providers[0].zone, "dbl.spamhaus.org");
        assert!(config.providers[0].enabled);
        assert_eq!(config.providers[1].zone, "multi.surbl.org");
        assert!(!config.providers[1].enabled);

        // Setting DNSBL must not disturb the independent RBL config.
        let rbl = service
            .get_rbl_config(Request::new(GetRblConfigRequest {
                auth_token: "secret123".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!rbl.enabled);
    }

    #[tokio::test]
    async fn test_dnsbl_allowlist_lifecycle() {
        let service = make_test_service();

        // Nothing configured to start with.
        let list_req = Request::new(ListDnsblAllowlistEntriesRequest {
            auth_token: "secret123".to_string(),
        });
        assert!(
            service
                .list_dnsbl_allowlist_entries(list_req)
                .await
                .unwrap()
                .into_inner()
                .entries
                .is_empty()
        );

        // Add an entry.
        let add_req = Request::new(AddDnsblAllowlistEntryRequest {
            entry: Some(DnsblAllowlistEntry {
                name: "Vendor.Example.com".to_string(),
                reason: "false positive".to_string(),
            }),
            auth_token: "secret123".to_string(),
        });
        assert!(
            service
                .add_dnsbl_allowlist_entry(add_req)
                .await
                .unwrap()
                .into_inner()
                .success
        );

        // It comes back normalized, with its reason, and takes effect on lookup.
        let list_req = Request::new(ListDnsblAllowlistEntriesRequest {
            auth_token: "secret123".to_string(),
        });
        let entries = service
            .list_dnsbl_allowlist_entries(list_req)
            .await
            .unwrap()
            .into_inner()
            .entries;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "vendor.example.com.");
        assert_eq!(entries[0].reason, "false positive");
        assert!(service.db.is_dnsbl_allowlisted("cdn.vendor.example.com."));

        // Remove it.
        let remove_req = Request::new(RemoveDnsblAllowlistEntryRequest {
            name: "vendor.example.com".to_string(),
            auth_token: "secret123".to_string(),
        });
        assert!(
            service
                .remove_dnsbl_allowlist_entry(remove_req)
                .await
                .unwrap()
                .into_inner()
                .success
        );
        assert!(!service.db.is_dnsbl_allowlisted("cdn.vendor.example.com."));

        // Removing a name that is not listed reports failure, not an error.
        let remove_req = Request::new(RemoveDnsblAllowlistEntryRequest {
            name: "vendor.example.com".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service
            .remove_dnsbl_allowlist_entry(remove_req)
            .await
            .unwrap()
            .into_inner();
        assert!(!resp.success);
        assert!(resp.message.contains("not found"));
    }

    #[tokio::test]
    async fn test_dnsbl_allowlist_rejects_empty_name() {
        let service = make_test_service();
        let add_req = Request::new(AddDnsblAllowlistEntryRequest {
            entry: Some(DnsblAllowlistEntry {
                name: "   ".to_string(),
                reason: String::new(),
            }),
            auth_token: "secret123".to_string(),
        });
        assert!(service.add_dnsbl_allowlist_entry(add_req).await.is_err());

        let add_req = Request::new(AddDnsblAllowlistEntryRequest {
            entry: None,
            auth_token: "secret123".to_string(),
        });
        assert!(service.add_dnsbl_allowlist_entry(add_req).await.is_err());
    }

    #[tokio::test]
    async fn test_dnsbl_allowlist_requires_auth() {
        let service = make_test_service();
        let add_req = Request::new(AddDnsblAllowlistEntryRequest {
            entry: Some(DnsblAllowlistEntry {
                name: "vendor.example.com".to_string(),
                reason: String::new(),
            }),
            auth_token: "wrong".to_string(),
        });
        assert!(service.add_dnsbl_allowlist_entry(add_req).await.is_err());

        let remove_req = Request::new(RemoveDnsblAllowlistEntryRequest {
            name: "vendor.example.com".to_string(),
            auth_token: "wrong".to_string(),
        });
        assert!(
            service
                .remove_dnsbl_allowlist_entry(remove_req)
                .await
                .is_err()
        );

        let list_req = Request::new(ListDnsblAllowlistEntriesRequest {
            auth_token: "wrong".to_string(),
        });
        assert!(
            service
                .list_dnsbl_allowlist_entries(list_req)
                .await
                .is_err()
        );
    }

    /// The Unix socket transport bypasses authentication, so the allowlist RPCs
    /// are reachable with no token at all.
    #[tokio::test]
    async fn test_dnsbl_allowlist_unix_socket_bypasses_auth() {
        let service = make_unix_service();
        let add_req = Request::new(AddDnsblAllowlistEntryRequest {
            entry: Some(DnsblAllowlistEntry {
                name: "vendor.example.com".to_string(),
                reason: String::new(),
            }),
            auth_token: String::new(),
        });
        assert!(
            service
                .add_dnsbl_allowlist_entry(add_req)
                .await
                .unwrap()
                .into_inner()
                .success
        );
    }

    #[tokio::test]
    async fn test_dnsbl_config_requires_auth() {
        let service = make_test_service();
        let set_req = Request::new(SetDnsblConfigRequest {
            enabled: true,
            providers: vec![],
            auth_token: "wrong".to_string(),
            ..Default::default()
        });
        assert!(service.set_dnsbl_config(set_req).await.is_err());
    }

    #[tokio::test]
    async fn test_flush_cache() {
        let service = make_test_service();

        let req = Request::new(FlushCacheRequest {
            auth_token: "secret123".to_string(),
        });
        let response = service.flush_cache(req).await.unwrap();
        assert!(response.into_inner().success);
    }

    #[tokio::test]
    async fn test_add_record_missing_record() {
        let service = make_test_service();
        let request = Request::new(AddRecordRequest {
            record: None,
            auth_token: "secret123".to_string(),
        });

        let result = service.add_record(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_add_record_default_ttl() {
        let service = make_test_service();
        let request = Request::new(AddRecordRequest {
            record: Some(proto::DnsRecord {
                name: "ttl.example.com".to_string(),
                record_type: 0,
                value: "10.0.0.1".to_string(),
                ttl: 0, // Should default to 300
                priority: 0,
            }),
            auth_token: "secret123".to_string(),
        });

        service.add_record(request).await.unwrap();

        let list_req = Request::new(ListRecordsRequest {
            name_filter: "ttl.example.com".to_string(),
            record_type_filter: 0,
            filter_by_type: false,
            auth_token: "secret123".to_string(),
        });
        let response = service.list_records(list_req).await.unwrap();
        let records = response.into_inner().records;
        assert_eq!(records[0].ttl, 300);
    }

    // ================================================================
    // Network Scope gRPC Tests
    // ================================================================

    #[tokio::test]
    async fn test_create_and_list_network_scopes() {
        let service = make_test_service();

        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "office".to_string(),
                home_domain: "office.home".to_string(),
                tlds: Vec::new(),
            }),
            auth_token: "secret123".to_string(),
        });
        let resp = service.create_network_scope(req).await.unwrap();
        assert!(resp.into_inner().success);

        let list_req = Request::new(ListNetworkScopesRequest {
            auth_token: "secret123".to_string(),
        });
        let resp = service.list_network_scopes(list_req).await.unwrap();
        let scopes = resp.into_inner().scopes;
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].name, "office");
    }

    #[tokio::test]
    async fn test_create_scope_default_home_domain() {
        let service = make_test_service();

        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "lab".to_string(),
                home_domain: String::new(), // Should default to lab.home
                tlds: Vec::new(),
            }),
            auth_token: "secret123".to_string(),
        });
        let resp = service.create_network_scope(req).await.unwrap();
        assert!(resp.into_inner().success);

        let list_req = Request::new(ListNetworkScopesRequest {
            auth_token: "secret123".to_string(),
        });
        let resp = service.list_network_scopes(list_req).await.unwrap();
        let scopes = resp.into_inner().scopes;
        assert_eq!(scopes[0].home_domain, "lab.home.");
    }

    #[tokio::test]
    async fn test_delete_network_scope() {
        let service = make_test_service();

        // Create scope
        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "temp".to_string(),
                home_domain: "temp.home".to_string(),
                tlds: Vec::new(),
            }),
            auth_token: "secret123".to_string(),
        });
        service.create_network_scope(req).await.unwrap();

        // Delete it
        let del_req = Request::new(DeleteNetworkScopeRequest {
            name: "temp".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.delete_network_scope(del_req).await.unwrap();
        assert!(resp.into_inner().success);

        // Verify it's gone
        let list_req = Request::new(ListNetworkScopesRequest {
            auth_token: "secret123".to_string(),
        });
        let resp = service.list_network_scopes(list_req).await.unwrap();
        assert!(resp.into_inner().scopes.is_empty());
    }

    #[tokio::test]
    async fn test_join_and_leave_network() {
        let service = make_test_service();

        // Create scope
        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "mynet".to_string(),
                home_domain: "mynet.home".to_string(),
                tlds: Vec::new(),
            }),
            auth_token: "secret123".to_string(),
        });
        service.create_network_scope(req).await.unwrap();

        // Join
        let join_req = Request::new(JoinNetworkRequest {
            ip_address: "192.168.1.100".to_string(),
            scope_name: "mynet".to_string(),
            ttl_seconds: 3600,
            auth_token: "secret123".to_string(),
        });
        let resp = service.join_network(join_req).await.unwrap();
        assert!(resp.into_inner().success);

        // Check associations
        let assoc_req = Request::new(GetNetworkAssociationsRequest {
            scope_name: "mynet".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.get_network_associations(assoc_req).await.unwrap();
        let assocs = resp.into_inner().associations;
        assert_eq!(assocs.len(), 1);
        assert_eq!(assocs[0].ip_address, "192.168.1.100");

        // Leave
        let leave_req = Request::new(LeaveNetworkRequest {
            ip_address: "192.168.1.100".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.leave_network(leave_req).await.unwrap();
        assert!(resp.into_inner().success);

        // Verify gone
        let assoc_req = Request::new(GetNetworkAssociationsRequest {
            scope_name: "mynet".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.get_network_associations(assoc_req).await.unwrap();
        assert!(resp.into_inner().associations.is_empty());
    }

    #[tokio::test]
    async fn test_add_and_list_scoped_records() {
        let service = make_test_service();

        // Create scope
        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "recscope".to_string(),
                home_domain: "recscope.home".to_string(),
                tlds: Vec::new(),
            }),
            auth_token: "secret123".to_string(),
        });
        service.create_network_scope(req).await.unwrap();

        // Add scoped record
        let add_req = Request::new(AddScopedRecordRequest {
            scope_name: "recscope".to_string(),
            record: Some(proto::DnsRecord {
                name: "host.recscope.home".to_string(),
                record_type: 0,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "secret123".to_string(),
        });
        let resp = service.add_scoped_record(add_req).await.unwrap();
        assert!(resp.into_inner().success);

        // List scoped records
        let list_req = Request::new(ListScopedRecordsRequest {
            scope_name: "recscope".to_string(),
            name_filter: String::new(),
            record_type_filter: 0,
            filter_by_type: false,
            auth_token: "secret123".to_string(),
        });
        let resp = service.list_scoped_records(list_req).await.unwrap();
        let records = resp.into_inner().records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "10.0.0.1");
    }

    #[tokio::test]
    async fn test_remove_scoped_records() {
        let service = make_test_service();

        // Create scope + record
        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "rmscope".to_string(),
                home_domain: "rmscope.home".to_string(),
                tlds: Vec::new(),
            }),
            auth_token: "secret123".to_string(),
        });
        service.create_network_scope(req).await.unwrap();

        let add_req = Request::new(AddScopedRecordRequest {
            scope_name: "rmscope".to_string(),
            record: Some(proto::DnsRecord {
                name: "delete-me.rmscope.home".to_string(),
                record_type: 0,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "secret123".to_string(),
        });
        service.add_scoped_record(add_req).await.unwrap();

        // Remove
        let rm_req = Request::new(RemoveScopedRecordRequest {
            scope_name: "rmscope".to_string(),
            name: "delete-me.rmscope.home".to_string(),
            record_type: 0,
            value: String::new(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.remove_scoped_record(rm_req).await.unwrap();
        let inner = resp.into_inner();
        assert!(inner.success);
        assert_eq!(inner.removed_count, 1);
    }

    #[tokio::test]
    async fn test_get_search_domains() {
        let service = make_test_service();

        // Create scope
        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "searchnet".to_string(),
                home_domain: "searchnet.home".to_string(),
                tlds: Vec::new(),
            }),
            auth_token: "secret123".to_string(),
        });
        service.create_network_scope(req).await.unwrap();

        // Join network
        let join_req = Request::new(JoinNetworkRequest {
            ip_address: "10.0.0.50".to_string(),
            scope_name: "searchnet".to_string(),
            ttl_seconds: 3600,
            auth_token: "secret123".to_string(),
        });
        service.join_network(join_req).await.unwrap();

        // Get search domains
        let sd_req = Request::new(GetSearchDomainsRequest {
            ip_address: "10.0.0.50".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.get_search_domains(sd_req).await.unwrap();
        let domains = resp.into_inner().search_domains;
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "searchnet.home.");
    }

    #[tokio::test]
    async fn test_join_network_default_ttl() {
        let service = make_test_service();

        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "ttlnet".to_string(),
                home_domain: "ttlnet.home".to_string(),
                tlds: Vec::new(),
            }),
            auth_token: "secret123".to_string(),
        });
        service.create_network_scope(req).await.unwrap();

        let join_req = Request::new(JoinNetworkRequest {
            ip_address: "10.0.0.1".to_string(),
            scope_name: "ttlnet".to_string(),
            ttl_seconds: 0, // Should default to 300
            auth_token: "secret123".to_string(),
        });
        let resp = service.join_network(join_req).await.unwrap();
        assert!(resp.into_inner().success);

        let assoc_req = Request::new(GetNetworkAssociationsRequest {
            scope_name: "ttlnet".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.get_network_associations(assoc_req).await.unwrap();
        let assocs = resp.into_inner().associations;
        assert_eq!(assocs[0].ttl_seconds, 300);
    }

    #[tokio::test]
    async fn test_network_scope_auth_required() {
        let service = make_test_service();

        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "auth-test".to_string(),
                home_domain: "auth.home".to_string(),
                tlds: Vec::new(),
            }),
            auth_token: "wrong".to_string(),
        });
        let result = service.create_network_scope(req).await;
        assert!(result.is_err());
    }
}
