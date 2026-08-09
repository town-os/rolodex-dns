//! The documented PromQL is executed by a real Prometheus.
//!
//! `promql_docs_test` resolves every documented query's metric names and label
//! matchers against the exposition output, which catches the common regression:
//! a renamed label or a series that no longer exists. What it cannot catch is a
//! query that is malformed *as PromQL* — an unbalanced paren, a `rate()` applied
//! to a gauge, a `histogram_quantile` missing its `le` grouping. Those parse
//! fine to a substring scanner and fail the moment an operator pastes them.
//!
//! So this suite scrapes a live server with an actual Prometheus and runs each
//! documented query through its HTTP API. The two layers are complementary: this
//! one is authoritative about syntax, the other about whether the series exist.
//!
//! # The gate
//!
//! `make prometheus-test` runs this, and `make test` depends on that target, so
//! the queries are checked on every full run. But it needs podman and, on a cold
//! image cache, the network, and not every machine has either — so the gate is
//! built to keep `make test` honest in both directions:
//!
//! - **`ROLODEX_PROMETHEUS_TEST=1`** must be set, which the make target does. A
//!   bare `cargo test` therefore does not start containers behind your back.
//! - **podman must be on PATH.** If it is not, the test *skips* rather than
//!   fails, so a developer without a container runtime still gets a green
//!   `make test` — but the skip is announced loudly on stderr (the target passes
//!   `--nocapture`), because a silent skip and a passing check look identical
//!   from the outside, and the second is what a reader assumes.
//! - **`ROLODEX_PROMETHEUS_REQUIRED=1`** turns that skip into a failure. CI has
//!   podman, and "the PromQL was never actually executed" is precisely the thing
//!   a pipeline must not shrug off.
//!
//! Nothing here writes outside a temp dir the test owns, and the container runs
//! with `--rm` under a test-specific name so a killed run leaves nothing behind.

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rolodex_dns::db::{Database, DnsRecord, RecordKind};
use rolodex_dns::dns_cache::DnsCache;
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::metrics::{MetricsState, Proto, build_router};
use rolodex_dns::rbl::{RblChecker, RblResolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Overridable so a deployment mirroring the image elsewhere can point at it.
const DEFAULT_IMAGE: &str = "quay.io/prometheus/prometheus:latest";

/// Container name, fixed so a leaked container from a killed run is replaced
/// rather than accumulating.
const CONTAINER: &str = "rolodex-dns-promql-test";

/// Where the containerised Prometheus listens. Fixed rather than ephemeral: it
/// runs with host networking, so the port has to be known before the process
/// starts, and 9099 avoids the 9090 a developer's own Prometheus would hold.
const PROM_ADDR: &str = "127.0.0.1:9099";

const DOC_FILES: &[&str] = &["README.md", "CLAUDE.md"];

struct NeverListedResolver;

#[async_trait::async_trait]
impl RblResolver for NeverListedResolver {
    async fn lookup_rbl(
        &self,
        _query: &str,
    ) -> Result<Option<rolodex_dns::rbl::RblAnswer>, anyhow::Error> {
        Ok(None)
    }
}

/// `(should_run, reason)` — the gate and why it is closed.
fn gate() -> (bool, String) {
    if std::env::var("ROLODEX_PROMETHEUS_TEST").as_deref() != Ok("1") {
        return (
            false,
            "ROLODEX_PROMETHEUS_TEST=1 not set (run `make prometheus-test`, or `make test`)"
                .to_string(),
        );
    }
    match Command::new("podman").arg("--version").output() {
        Ok(o) if o.status.success() => (true, String::new()),
        _ => (false, "podman is not on PATH".to_string()),
    }
}

/// Announces a skip, or fails if the caller declared the check mandatory.
///
/// Loud on purpose. A skipped check and a passing one are indistinguishable in a
/// test summary, and since this target is part of `make test`, a quiet skip
/// would let "the documented queries are verified" quietly become false on any
/// machine that happens to lack podman.
fn skip(reason: &str) {
    if std::env::var("ROLODEX_PROMETHEUS_REQUIRED").as_deref() == Ok("1") {
        panic!(
            "ROLODEX_PROMETHEUS_REQUIRED=1 but the PromQL execution check could \
             not run: {reason}"
        );
    }
    eprintln!(
        "\n\
         ============================================================\n\
         SKIPPED: the documented PromQL was NOT executed.\n\
           reason: {reason}\n\
           consequence: a query malformed as PromQL would not be caught\n\
                        here (promql_docs_test still checks that every\n\
                        documented series and label value exists).\n\
           to enforce: set ROLODEX_PROMETHEUS_REQUIRED=1\n\
         ============================================================\n"
    );
}

fn image() -> String {
    std::env::var("ROLODEX_PROMETHEUS_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string())
}

/// Serves a metrics endpoint with every family populated, and returns its port.
async fn spawn_populated_metrics() -> u16 {
    let db = Database::open_memory().expect("in-memory database");
    let rbl = Arc::new(RblChecker::with_resolver(
        false,
        vec![],
        Arc::new(NeverListedResolver),
    ));
    let cache = Arc::new(DnsCache::new(db.clone()));
    let dns_server = Arc::new(DnsServer::new_with_options(
        db.clone(),
        rbl.clone(),
        vec![],
        Some(Arc::clone(&cache)),
        None,
        false,
    ));

    db.add_record(&DnsRecord {
        id: None,
        name: "promql.example.com.".to_string(),
        record_type: RecordKind::A,
        value: "192.0.2.99".to_string(),
        ttl: 300,
        priority: 0,
    })
    .expect("add record");

    // Give the runtime-labelled families some series, so a query against them
    // returns data rather than an empty result. An empty result is still a
    // syntactically valid query, but a populated one makes a failure legible.
    rolodex_dns::metrics::metrics().set_tracked_tlds(["common"]);
    for name in ["promql.example.com.", "unknown.invalid."] {
        let mut msg = hickory_proto::op::Message::new();
        msg.set_id(1);
        msg.set_message_type(hickory_proto::op::MessageType::Query);
        msg.set_op_code(hickory_proto::op::OpCode::Query);
        let mut q = hickory_proto::op::Query::new();
        q.set_name(hickory_proto::rr::Name::from_ascii(name).expect("name"));
        q.set_query_type(hickory_proto::rr::RecordType::A);
        q.set_query_class(hickory_proto::rr::DNSClass::IN);
        msg.add_query(q);
        let bytes = msg.to_vec().expect("serialize");
        let _ = dns_server
            .handle_query_proto(&bytes, None, None, Proto::Udp)
            .await;
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let state = MetricsState {
        db,
        dns_server,
        dns_cache: Some(cache),
        rbl,
    };
    tokio::spawn(async move {
        let _ = axum::serve(listener, build_router(state)).await;
    });
    port
}

/// Minimal HTTP GET returning the body, or `None` if the connection failed.
async fn http_get(addr: SocketAddr, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect(addr).await.ok()?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    Some(
        text.split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or(text),
    )
}

/// Percent-encodes a PromQL expression for a query string. Hand-rolled rather
/// than adding a URL crate for one call site.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Extracts every ```promql block, one query per block entry, comments stripped.
fn documented_queries() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for file in DOC_FILES {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        let Ok(md) = std::fs::read_to_string(&path) else {
            continue;
        };
        let mut in_block = false;
        let mut buf = String::new();
        for line in md.lines() {
            let trimmed = line.trim();
            if !in_block {
                if trimmed == "```promql" {
                    in_block = true;
                    buf.clear();
                }
                continue;
            }
            if trimmed == "```" {
                in_block = false;
                // Blocks hold several queries separated by blank lines; a
                // comment line introduces the query that follows it.
                for chunk in buf.split("\n\n") {
                    let q: String = chunk
                        .lines()
                        .filter(|l| !l.trim_start().starts_with('#'))
                        .collect::<Vec<_>>()
                        .join(" ");
                    if !q.trim().is_empty() {
                        out.push((file.to_string(), q.trim().to_string()));
                    }
                }
                continue;
            }
            buf.push_str(line);
            buf.push('\n');
        }
    }
    out
}

/// Stops any container left over from a previous run.
fn stop_container() {
    let _ = Command::new("podman")
        .args(["rm", "-f", "-i", CONTAINER])
        .output();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn documented_promql_executes_against_a_real_prometheus() {
    let (run, why) = gate();
    if !run {
        skip(&why);
        return;
    }

    let metrics_port = spawn_populated_metrics().await;
    let queries = documented_queries();
    assert!(
        queries.len() >= 15,
        "only {} documented queries found — the extractor or the fences are broken",
        queries.len()
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let cfg = format!(
        "global:\n  scrape_interval: 1s\n  evaluation_interval: 1s\n\
         scrape_configs:\n  - job_name: rolodex\n    static_configs:\n      \
         - targets: ['127.0.0.1:{metrics_port}']\n"
    );
    let cfg_path = dir.path().join("prometheus.yml");
    std::fs::write(&cfg_path, cfg).expect("write prometheus.yml");
    // The container runs as a non-root user; the config must be world-readable
    // regardless of the caller's umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod config");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("chmod dir");
    }

    stop_container();
    // Host networking so the container reaches the loopback-bound exposition
    // endpoint without publishing a port.
    let spawned = Command::new("podman")
        .args([
            "run",
            "--rm",
            "--name",
            CONTAINER,
            "--network=host",
            "-v",
            &format!("{}:/etc/prometheus:ro,Z", dir.path().display()),
            &image(),
            "--config.file=/etc/prometheus/prometheus.yml",
            &format!("--web.listen-address={PROM_ADDR}"),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            skip(&format!("podman run failed: {e}"));
            return;
        }
    };

    let prom: SocketAddr = PROM_ADDR.parse().expect("prom addr");

    // Wait for Prometheus to come up and complete one scrape.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut ready = false;
    while Instant::now() < deadline {
        if let Some(body) = http_get(prom, "/api/v1/query?query=up").await
            && body.contains("\"status\":\"success\"")
            && body.contains("\"value\"")
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    if !ready {
        let _ = child.kill();
        stop_container();
        panic!(
            "prometheus did not become ready within 90s (image: {})",
            image()
        );
    }

    let mut failures = Vec::new();
    for (file, q) in &queries {
        let path = format!("/api/v1/query?query={}", percent_encode(q));
        match http_get(prom, &path).await {
            Some(body) if body.contains("\"status\":\"success\"") => {}
            Some(body) => failures.push(format!("{file}: {q}\n  -> {}", body.trim())),
            None => failures.push(format!("{file}: {q}\n  -> no response from prometheus")),
        }
    }

    let _ = child.kill();
    stop_container();

    assert!(
        failures.is_empty(),
        "{} of {} documented queries were rejected by prometheus:\n{}",
        failures.len(),
        queries.len(),
        failures.join("\n")
    );
}

#[test]
fn every_documented_query_is_extracted_individually() {
    // Runs unconditionally: if the splitter merged the cookbook into one blob,
    // the gated test above would send Prometheus a single nonsense expression
    // and its failure would be unreadable.
    let queries = documented_queries();
    assert!(
        queries.len() >= 15,
        "expected the cookbook to yield many separate queries, got {}: {:?}",
        queries.len(),
        queries
    );
    for (file, q) in &queries {
        assert!(!q.contains('#'), "{file}: comment leaked into query: {q}");
        assert!(
            q.matches('(').count() == q.matches(')').count(),
            "{file}: unbalanced parens, so the block was split mid-query: {q}"
        );
    }
}
