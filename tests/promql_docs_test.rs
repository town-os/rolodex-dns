//! The documented PromQL is checked against the real exposition output.
//!
//! Every ```promql block in `README.md` and `CLAUDE.md` is parsed, its metric
//! names and label matchers extracted, and each one resolved against what
//! `Metrics::render` actually emits. A documented query that names a series or a
//! label value which does not exist fails here.
//!
//! This exists because documentation is the one part of a metrics change that
//! nothing else verifies. Renaming a label — `dhcp_messages_total{type}` to
//! `{message_type}`, say — leaves the code compiling, the unit tests green and
//! the integration tests green, and silently turns every dashboard query in the
//! README into one that returns no data. An operator finds out when a panel goes
//! blank during an incident.
//!
//! The parser is hand-rolled rather than pulling in `regex`, matching how the
//! rest of this codebase treats dependencies. It is deliberately *permissive*
//! about PromQL syntax it does not understand and *strict* about the identifiers
//! it does recognize: the job is to check names against the registry, not to be
//! a second PromQL implementation. Whether a query is well-formed as PromQL is a
//! different question, answered by the gated `prometheus_integration_test` which
//! runs these same queries through a real Prometheus.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use rolodex_dns::metrics::{AnswerSource, Metrics, Proto, QueryObservation, TLD_OTHER};

/// Documentation files scanned for PromQL.
const DOC_FILES: &[&str] = &["README.md", "CLAUDE.md"];

/// The metric-name prefix every series here shares. Identifiers not starting
/// with it are PromQL functions, grouping labels or literals, and are skipped.
const PREFIX: &str = "rolodex_dns_";

// ---------------------------------------------------------------------------
// Rendering a registry with every series present
// ---------------------------------------------------------------------------

/// Renders a registry primed so that the *runtime-labelled* families have series
/// too.
///
/// The fixed-label families pre-allocate every series at construction, so they
/// appear in a fresh registry at zero. The dynamic ones (`queries_by_tld_total`,
/// `upstream_queries_total`, …) are empty until something is recorded, and a
/// documented query naming one would otherwise fail for the wrong reason — the
/// metric exists, the sample just has not happened yet.
fn rendered() -> String {
    let m = Metrics::new();

    // Two TLD samples: one tracked, one not. `tld` is the only dimension whose
    // *values* are deployment-specific, so the assertions can only reasonably
    // cover the catch-all, which is the one value guaranteed to exist anywhere.
    m.set_tracked_tlds(["lab.internal"]);
    for tld in [TLD_OTHER, "lab.internal."] {
        m.observe_query(QueryObservation {
            proto: Proto::Udp,
            rcode_index: 0,
            qtype_index: 0,
            tld,
            source: AnswerSource::Local,
            query_bytes: 32,
            response_bytes: 64,
            answer_records: 1,
            truncated: false,
            elapsed: Duration::from_micros(120),
        });
    }

    m.upstream_queries.inc("8.8.8.8:53");
    m.grpc_requests.inc("add_record");
    m.resolver_latency_ms.set_scaled("198.41.0.4:53", 12_500);

    m.render()
}

/// One emitted sample: its labels, keyed by name.
type Labels = BTreeMap<String, String>;

/// Parses an exposition body into `metric name -> [label set, …]`.
///
/// A metric with no labels maps to a single empty label set, so "does this
/// metric exist" and "does it carry this label" are the same lookup.
fn parse_exposition(body: &str) -> BTreeMap<String, Vec<Labels>> {
    let mut out: BTreeMap<String, Vec<Labels>> = BTreeMap::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, labels) = match line.find('{') {
            Some(brace) => {
                let name = &line[..brace];
                let close = match line.rfind('}') {
                    Some(c) if c > brace => c,
                    _ => continue,
                };
                (name, parse_labels(&line[brace + 1..close]))
            }
            None => match line.split_once(' ') {
                Some((name, _)) => (name, Labels::new()),
                None => continue,
            },
        };
        out.entry(name.to_string()).or_default().push(labels);
    }
    out
}

/// Parses `a="1",b="2"` into a map. Values here are produced by this crate's own
/// renderer, so the only escape that occurs in practice is `\"`.
fn parse_labels(s: &str) -> Labels {
    let mut out = Labels::new();
    let mut rest = s;
    while let Some(eq) = rest.find('=') {
        let key = rest[..eq].trim_start_matches(',').trim().to_string();
        let after = &rest[eq + 1..];
        if !after.starts_with('"') {
            break;
        }
        let mut value = String::new();
        let mut chars = after[1..].char_indices();
        let mut end = None;
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => {
                    if let Some((_, esc)) = chars.next() {
                        value.push(esc);
                    }
                }
                '"' => {
                    end = Some(i);
                    break;
                }
                _ => value.push(c),
            }
        }
        let Some(end) = end else { break };
        out.insert(key, value);
        rest = &after[end + 2..];
    }
    out
}

// ---------------------------------------------------------------------------
// Extracting PromQL from the docs
// ---------------------------------------------------------------------------

/// One metric reference found in a documented query.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MetricRef {
    name: String,
    /// `(label, value)` for `=` matchers only.
    equals: Vec<(String, String)>,
    /// Label names used with any other operator (`!=`, `=~`, `!~`), where only
    /// the label's existence on the metric can be checked.
    mentioned: Vec<String>,
}

/// Pulls the contents of every ```promql fenced block out of a markdown file.
fn promql_blocks(md: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in md.lines() {
        let trimmed = line.trim();
        match current {
            None => {
                if trimmed == "```promql" {
                    current = Some(String::new());
                }
            }
            Some(ref mut buf) => {
                if trimmed == "```" {
                    blocks.push(std::mem::take(buf));
                    current = None;
                } else {
                    buf.push_str(line);
                    buf.push('\n');
                }
            }
        }
    }
    blocks
}

/// Finds every `rolodex_dns_*` selector in a query, with its label matchers.
///
/// Comment lines are dropped first: the prose in a `#` comment is explanation,
/// not a selector, and a metric named there is not one Prometheus would resolve.
fn metric_refs(query: &str) -> Vec<MetricRef> {
    let code: String = query
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");

    let bytes = code.as_bytes();
    let mut refs = Vec::new();
    let mut i = 0;
    while let Some(found) = code[i..].find(PREFIX) {
        let start = i + found;
        // Must begin an identifier: a match mid-word is not a metric name.
        if start > 0 && is_ident_byte(bytes[start - 1]) {
            i = start + PREFIX.len();
            continue;
        }
        let mut end = start;
        while end < bytes.len() && is_ident_byte(bytes[end]) {
            end += 1;
        }
        let name = code[start..end].to_string();

        let mut equals = Vec::new();
        let mut mentioned = Vec::new();
        // A `{` immediately after the name (whitespace tolerated) opens matchers.
        let after = code[end..].trim_start();
        if after.starts_with('{')
            && let Some(close) = after.find('}')
        {
            for matcher in split_matchers(&after[1..close]) {
                if let Some((label, value)) = parse_matcher(&matcher) {
                    match value {
                        Some(v) => equals.push((label, v)),
                        None => mentioned.push(label),
                    }
                }
            }
        }
        refs.push(MetricRef {
            name,
            equals,
            mentioned,
        });
        i = end;
    }
    refs
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b':'
}

/// Splits a matcher list on commas that are not inside a quoted value.
fn split_matchers(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for c in s.chars() {
        match c {
            _ if escaped => {
                buf.push(c);
                escaped = false;
            }
            '\\' if in_quotes => {
                buf.push(c);
                escaped = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                buf.push(c);
            }
            ',' if !in_quotes => out.push(std::mem::take(&mut buf)),
            _ => buf.push(c),
        }
    }
    if !buf.trim().is_empty() {
        out.push(buf);
    }
    out
}

/// `label="value"` yields `(label, Some(value))`; any other operator yields
/// `(label, None)`, since only the label's existence can be checked then.
fn parse_matcher(m: &str) -> Option<(String, Option<String>)> {
    let m = m.trim();
    let op = m.find(['=', '!'])?;
    let label = m[..op].trim().to_string();
    if label.is_empty() {
        return None;
    }
    let rest = &m[op..];
    let exact = rest.starts_with('=') && !rest.starts_with("=~");
    let value = rest
        .trim_start_matches(['=', '!', '~'])
        .trim()
        .trim_matches('"')
        .to_string();
    Some(if exact {
        (label, Some(value))
    } else {
        (label, None)
    })
}

/// Reads a documentation file. A missing one is a hard failure.
///
/// Every file in [`DOC_FILES`] is in the crate's `include` list, so all of them
/// are present in a repo checkout *and* in the published package — which is why
/// this can insist rather than tolerate. Skipping a doc that failed to load is
/// how a check quietly starts verifying nothing, and a package that carried the
/// test but not its input would do exactly that.
fn read_doc(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "reading {}: {e}\nEvery file in DOC_FILES must ship — check the \
             `include` list in Cargo.toml",
            path.display()
        )
    })
}

/// Every documentation file, as `(name, contents)`.
fn docs() -> Vec<(&'static str, String)> {
    DOC_FILES.iter().map(|f| (*f, read_doc(f))).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn documented_promql_references_only_real_series() {
    let series = parse_exposition(&rendered());
    let mut checked = 0usize;
    let mut failures = Vec::new();

    for (file, md) in docs() {
        for (n, block) in promql_blocks(&md).iter().enumerate() {
            for r in metric_refs(block) {
                checked += 1;
                let Some(sets) = series.get(&r.name) else {
                    failures.push(format!(
                        "{file} promql block #{n}: no such metric `{}`",
                        r.name
                    ));
                    continue;
                };

                for (label, value) in &r.equals {
                    let matched = sets
                        .iter()
                        .any(|s| s.get(label).is_some_and(|v| v == value));
                    if !matched {
                        let seen: BTreeSet<&str> = sets
                            .iter()
                            .filter_map(|s| s.get(label).map(String::as_str))
                            .collect();
                        failures.push(format!(
                            "{file} promql block #{n}: `{}` has no series with {label}=\"{value}\" \
                             (values present: {seen:?})",
                            r.name
                        ));
                    }
                }

                for label in &r.mentioned {
                    if !sets.iter().any(|s| s.contains_key(label)) {
                        failures.push(format!(
                            "{file} promql block #{n}: `{}` carries no label `{label}`",
                            r.name
                        ));
                    }
                }
            }
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // A parser bug that silently matched nothing would make every assertion
    // above vacuous, and this file would then pass forever while checking
    // nothing at all.
    assert!(
        checked >= 30,
        "only {checked} metric references found across {DOC_FILES:?} — \
         the extractor is probably broken, or the promql blocks lost their fence"
    );
}

#[test]
fn every_documented_label_value_is_reachable() {
    // The inverse of the test above, for the dimension most likely to drift: if
    // the docs claim `{kind}` takes a value the code cannot produce, the query
    // is legal PromQL that always returns nothing.
    let series = parse_exposition(&rendered());
    let dhcp = series
        .get("rolodex_dns_dhcp_messages_total")
        .expect("dhcp message family present");
    assert!(
        dhcp.iter().all(|s| s.contains_key("message_type")),
        "DHCP messages must label `message_type`, not the generic `type`, so an \
         aggregation spanning DNS and DHCP cannot blend the two"
    );
    let leases = series
        .get("rolodex_dns_dhcp_leases")
        .expect("dhcp lease family present");
    assert!(
        leases.iter().all(|s| s.contains_key("lease_state")),
        "DHCP leases must label `lease_state`, not the generic `state`"
    );

    // And the generic names must be gone entirely, on every family: a rename
    // that left one series behind is the case a spot check misses.
    for (name, sets) in &series {
        for s in sets {
            assert!(
                !s.contains_key("type") && !s.contains_key("state"),
                "`{name}` uses a generic label name ({s:?}); use a subsystem-qualified one"
            );
        }
    }
}

#[test]
fn documented_family_count_matches_the_registry() {
    // The count in the docs drifted once already (73 documented, 74 emitted).
    // Pinning it here means the next family added has to be documented in the
    // same change or the suite fails.
    let body = rendered();
    let families: BTreeSet<&str> = body
        .lines()
        .filter_map(|l| l.strip_prefix("# TYPE "))
        .filter_map(|l| l.split_whitespace().next())
        .collect();

    for (file, md) in docs() {
        let documented = md
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(3)
            .find_map(|w| {
                (w[1] == "metric" && w[2].starts_with("families"))
                    .then(|| w[0].parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or_else(|| panic!("{file} does not state an 'N metric families' count"));

        assert_eq!(
            documented,
            families.len(),
            "{file} documents {documented} metric families but the registry emits {}: {:?}",
            families.len(),
            families
        );
    }
}

#[test]
fn promql_extractor_finds_names_and_matchers() {
    // The extractor is the load-bearing part of this file; if it silently
    // matched nothing the tests above would pass while checking nothing.
    let refs = metric_refs(
        r#"
        # rolodex_dns_this_is_a_comment_and_must_be_ignored
        sum by (kind) (rate(rolodex_dns_blocklist_blocks_total{kind="rbl_local"}[5m]))
          / sum(rate(rolodex_dns_queries_total{rcode!="NOERROR"}[5m]))
        "#,
    );
    assert_eq!(refs.len(), 2, "expected two selectors, got {refs:?}");
    assert_eq!(refs[0].name, "rolodex_dns_blocklist_blocks_total");
    assert_eq!(
        refs[0].equals,
        vec![("kind".to_string(), "rbl_local".to_string())]
    );
    assert_eq!(refs[1].name, "rolodex_dns_queries_total");
    assert!(refs[1].equals.is_empty());
    assert_eq!(refs[1].mentioned, vec!["rcode".to_string()]);
}

#[test]
fn promql_blocks_are_actually_present_in_the_docs() {
    // Guards the fence itself: a block relabelled ```bash or ```text would make
    // the whole file silently stop checking anything.
    //
    // README.md carries the cookbook, so it is the floor the whole file rests
    // on and is asserted unconditionally.
    let blocks = promql_blocks(&read_doc("README.md"));
    assert!(
        blocks.len() >= 5,
        "README.md has {} promql blocks; the cookbook should have several",
        blocks.len()
    );
}
