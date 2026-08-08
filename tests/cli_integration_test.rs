use assert_cmd::Command;
use assert_cmd::cargo;
use predicates::prelude::*;
use rolodex_dns::db::Database;
use rolodex_dns::dns_server::DnsServer;
use rolodex_dns::grpc_service::RolodexDnsGrpcService;
use rolodex_dns::grpc_service::proto::rolodex_dns_service_server::RolodexDnsServiceServer;
use rolodex_dns::rbl::{RblChecker, RblResolver};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::net::UnixListener;
use tonic::transport::Server;

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

struct TestServer {
    tcp_addr: String,
    unix_path: String,
    _tmpdir: tempfile::TempDir,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl TestServer {
    async fn start(shared_secret: &str) -> Self {
        let tmpdir = tempfile::tempdir().unwrap();
        let socket_path = tmpdir.path().join("rolodex-dns-test.sock");
        let socket_path_str = socket_path.to_str().unwrap().to_string();

        let db = Database::open_memory().unwrap();
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));

        // Start TCP server
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap().to_string();
        let tcp_incoming = tokio_stream::wrappers::TcpListenerStream::new(tcp_listener);

        let tcp_service = RolodexDnsGrpcService::new(
            db.clone(),
            dns_server.clone(),
            rbl.clone(),
            shared_secret.to_string(),
            false,
        );

        // Start Unix socket server
        let uds = UnixListener::bind(&socket_path).unwrap();
        let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds);

        let unix_service = RolodexDnsGrpcService::new(
            db.clone(),
            dns_server.clone(),
            rbl.clone(),
            shared_secret.to_string(),
            true,
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let tcp_server = Server::builder()
                .add_service(RolodexDnsServiceServer::new(tcp_service))
                .serve_with_incoming(tcp_incoming);

            let unix_server = Server::builder()
                .add_service(RolodexDnsServiceServer::new(unix_service))
                .serve_with_incoming(uds_stream);

            tokio::select! {
                _ = tcp_server => {},
                _ = unix_server => {},
                _ = shutdown_rx => {},
            }
        });

        // Give the server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        TestServer {
            tcp_addr,
            unix_path: socket_path_str,
            _tmpdir: tmpdir,
            shutdown_tx,
        }
    }

    fn cli_tcp(&self) -> Command {
        let mut cmd = Command::new(cargo::cargo_bin!("rolodex-dns-cli"));
        cmd.args(["-a", &self.tcp_addr, "-t", "test-secret"]);
        cmd.timeout(std::time::Duration::from_secs(10));
        cmd
    }

    fn cli_unix(&self) -> Command {
        let mut cmd = Command::new(cargo::cargo_bin!("rolodex-dns-cli"));
        cmd.args(["-u", &self.unix_path]);
        cmd.timeout(std::time::Duration::from_secs(10));
        cmd
    }

    fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// Run a blocking assert_cmd operation without blocking the tokio runtime.
async fn run_cmd(mut cmd: Command) -> assert_cmd::assert::Assert {
    tokio::task::spawn_blocking(move || cmd.assert())
        .await
        .unwrap()
}

// ========================================================
// TCP transport tests
// ========================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_add_record_tcp() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "cli-test.example.com.",
            "-r",
            "a",
            "-v",
            "10.0.0.1",
            "--ttl",
            "600",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Added record"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_add_and_list_records_tcp() {
    let server = TestServer::start("test-secret").await;

    // Add a record
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "list-test.example.com.",
            "-r",
            "a",
            "-v",
            "10.0.0.1",
        ]);
        cmd
    })
    .await
    .success();

    // List all records
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-records"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("list-test.example.com."))
    .stdout(predicate::str::contains("10.0.0.1"))
    .stdout(predicate::str::contains("1 record(s) found"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_add_and_remove_record_tcp() {
    let server = TestServer::start("test-secret").await;

    // Add a record
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "remove-test.example.com.",
            "-r",
            "a",
            "-v",
            "10.0.0.2",
        ]);
        cmd
    })
    .await
    .success();

    // Remove it
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["remove-record", "-n", "remove-test.example.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Removed 1 record(s)"));

    // Verify it's gone
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-records"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No records found"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_remove_record_with_type_filter_tcp() {
    let server = TestServer::start("test-secret").await;

    // Add A and AAAA records
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "multi.example.com.",
            "-r",
            "a",
            "-v",
            "10.0.0.1",
        ]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "multi.example.com.",
            "-r",
            "aaaa",
            "-v",
            "::1",
        ]);
        cmd
    })
    .await
    .success();

    // Remove only A records
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["remove-record", "-n", "multi.example.com.", "-r", "a"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Removed 1 record(s)"));

    // AAAA should still be there
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-records"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("AAAA"))
    .stdout(predicate::str::contains("::1"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_list_records_with_name_filter_tcp() {
    let server = TestServer::start("test-secret").await;

    for (name, value) in &[
        ("host1.filter.com.", "10.0.0.1"),
        ("host2.filter.com.", "10.0.0.2"),
        ("other.test.com.", "10.0.0.3"),
    ] {
        run_cmd({
            let mut cmd = server.cli_tcp();
            cmd.args(["add-record", "-n", name, "-r", "a", "-v", value]);
            cmd
        })
        .await
        .success();
    }

    // List with wildcard filter
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-records", "-n", "*.filter.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("2 record(s) found"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_list_records_with_type_filter_tcp() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "typed.example.com.",
            "-r",
            "a",
            "-v",
            "10.0.0.1",
        ]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "typed.example.com.",
            "-r",
            "aaaa",
            "-v",
            "::1",
        ]);
        cmd
    })
    .await
    .success();

    // Filter by type AAAA
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-records", "-r", "aaaa"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("AAAA"))
    .stdout(predicate::str::contains("1 record(s) found"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_set_forwarders_tcp() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["set-forwarders", "-f", "8.8.8.8:53", "1.1.1.1:53"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Forwarders updated"))
    .stdout(predicate::str::contains("8.8.8.8:53"))
    .stdout(predicate::str::contains("1.1.1.1:53"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_set_and_get_rbl_config_tcp() {
    let server = TestServer::start("test-secret").await;

    // Set RBL config
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "set-rbl-config",
            "-e",
            "-p",
            "zen.spamhaus.org:true",
            "bl.spamcop.net:false",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains(
        "RBL config updated (enabled: true)",
    ));

    // Get RBL config
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["get-rbl-config"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("RBL enabled: true"))
    .stdout(predicate::str::contains("zen.spamhaus.org"))
    .stdout(predicate::str::contains("bl.spamcop.net"));

    server.shutdown();
}

/// Refusal codes and the rotate-out duration are reachable from the CLI, and
/// `get-rbl-config` shows what is actually in effect. An operator who cannot
/// see which codes a provider is using cannot tell a misconfigured blocklist
/// from a working one until it starts NXDOMAINing everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_set_and_get_rbl_refusal_codes_tcp() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "set-rbl-config",
            "-e",
            "-p",
            "zen.spamhaus.org:true",
            "private.rbl:true",
            "--refusal-codes",
            "zen.spamhaus.org=127.255.255.0/24,127.0.0.1",
            "private.rbl=none",
            "--provider-cooldown",
            "zen.spamhaus.org=1800",
            "--refusal-cooldown",
            "900",
        ]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["get-rbl-config"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Refusal rotate-out: 900s"))
    .stdout(predicate::str::contains("127.255.255.0/24"))
    .stdout(predicate::str::contains("1800s"))
    // A provider with detection off reads back as `none`, not as blank —
    // blank means "the defaults" on the way back in.
    .stdout(predicate::str::contains("none"));

    // A zone named in --refusal-codes but absent from --providers is an error
    // rather than a silently dropped flag: the operator would otherwise believe
    // they had configured codes that were never sent.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "set-rbl-config",
            "-e",
            "-p",
            "zen.spamhaus.org:true",
            "--refusal-codes",
            "typo.spamhaus.org=127.0.0.1",
        ]);
        cmd
    })
    .await
    .failure()
    .stderr(predicate::str::contains("not in --providers"));

    // A malformed code is refused by the server.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "set-rbl-config",
            "-e",
            "-p",
            "zen.spamhaus.org:true",
            "--refusal-codes",
            "zen.spamhaus.org=not-an-ip",
        ]);
        cmd
    })
    .await
    .failure();

    server.shutdown();
}

/// The per-scope provider carries the same knobs, over the Unix socket path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_add_scope_rbl_with_refusal_codes_unix() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["create-scope", "--name", "refusal-scope"]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args([
            "add-scope-rbl",
            "--scope",
            "refusal-scope",
            "--zone",
            "scope.rbl",
            "--refusal-code",
            "127.255.255.0/24",
            "--refusal-code",
            "127.0.1.255",
            "--refusal-cooldown",
            "300",
        ]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-scope-rbl", "--scope", "refusal-scope"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("scope.rbl"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_set_and_get_dnsbl_config_tcp() {
    let server = TestServer::start("test-secret").await;

    // DNSBL starts disabled with no providers.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["get-dnsbl-config"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("DNSBL enabled: false"))
    .stdout(predicate::str::contains("No DNSBL providers configured"));

    // Set DNSBL config.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "set-dnsbl-config",
            "-e",
            "-p",
            "dbl.spamhaus.org:true",
            "multi.surbl.org:false",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains(
        "DNSBL config updated (enabled: true)",
    ));

    // Get DNSBL config.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["get-dnsbl-config"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("DNSBL enabled: true"))
    .stdout(predicate::str::contains("dbl.spamhaus.org"))
    .stdout(predicate::str::contains("multi.surbl.org"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_dnsbl_allowlist_lifecycle_tcp() {
    let server = TestServer::start("test-secret").await;

    // The allowlist starts empty.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-dnsbl-allow"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains(
        "No DNSBL allowlist entries configured",
    ));

    // Add an entry.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-dnsbl-allow",
            "-n",
            "vendor.example.com",
            "-r",
            "false positive",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains(
        "Added DNSBL allowlist entry: vendor.example.com",
    ));

    // It lists back normalized, with its reason.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-dnsbl-allow"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("vendor.example.com."))
    .stdout(predicate::str::contains("false positive"))
    .stdout(predicate::str::contains("1 entry(ies) found"));

    // Remove it.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["remove-dnsbl-allow", "-n", "vendor.example.com"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains(
        "Removed DNSBL allowlist entry: vendor.example.com",
    ));

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-dnsbl-allow"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains(
        "No DNSBL allowlist entries configured",
    ));

    // Removing an entry that is not there fails with a message.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["remove-dnsbl-allow", "-n", "vendor.example.com"]);
        cmd
    })
    .await
    .failure()
    .stderr(predicate::str::contains("not found"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_dnsbl_allowlist_unix() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["add-dnsbl-allow", "-n", "cdn.example.net", "-r", "vendor"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Added DNSBL allowlist entry"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-dnsbl-allow"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("cdn.example.net."))
    .stdout(predicate::str::contains("vendor"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_get_rbl_config_default_tcp() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["get-rbl-config"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("RBL enabled: false"))
    .stdout(predicate::str::contains("No RBL providers configured"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_flush_cache_tcp() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["flush-cache"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Cache flushed successfully"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_auth_failure_tcp() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = Command::new(cargo::cargo_bin!("rolodex-dns-cli"));
        cmd.args(["-a", &server.tcp_addr, "-t", "wrong-secret"]);
        cmd.args(["list-records"]);
        cmd.timeout(std::time::Duration::from_secs(10));
        cmd
    })
    .await
    .failure();

    server.shutdown();
}

// ========================================================
// Unix socket transport tests
// ========================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_add_record_unix() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args([
            "add-record",
            "-n",
            "unix-test.example.com.",
            "-r",
            "a",
            "-v",
            "10.0.0.5",
            "--ttl",
            "900",
            "-p",
            "0",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Added record"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_add_and_list_records_unix() {
    let server = TestServer::start("test-secret").await;

    // Add a record via Unix socket (no auth needed)
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args([
            "add-record",
            "-n",
            "unix-list.example.com.",
            "-r",
            "txt",
            "-v",
            "hello world",
        ]);
        cmd
    })
    .await
    .success();

    // List via Unix socket
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-records"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("unix-list.example.com."))
    .stdout(predicate::str::contains("hello world"))
    .stdout(predicate::str::contains("TXT"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_unix_bypasses_auth() {
    let server = TestServer::start("test-secret").await;

    // Unix socket should work without any auth token
    run_cmd({
        let mut cmd = Command::new(cargo::cargo_bin!("rolodex-dns-cli"));
        cmd.args(["-u", &server.unix_path]);
        cmd.args(["list-records"]);
        cmd.timeout(std::time::Duration::from_secs(10));
        cmd
    })
    .await
    .success();

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_full_crud_unix() {
    let server = TestServer::start("test-secret").await;

    // Create
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args([
            "add-record",
            "-n",
            "crud.example.com.",
            "-r",
            "a",
            "-v",
            "192.168.1.1",
        ]);
        cmd
    })
    .await
    .success();

    // Read
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-records", "-n", "crud.example.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("192.168.1.1"))
    .stdout(predicate::str::contains("1 record(s) found"));

    // Delete
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args([
            "remove-record",
            "-n",
            "crud.example.com.",
            "-v",
            "192.168.1.1",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Removed 1 record(s)"));

    // Verify deleted
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-records", "-n", "crud.example.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No records found"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_set_forwarders_unix() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["set-forwarders", "-f", "9.9.9.9:53"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Forwarders updated"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_rbl_config_roundtrip_unix() {
    let server = TestServer::start("test-secret").await;

    // Set
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["set-rbl-config", "-e", "-p", "zen.spamhaus.org:true"]);
        cmd
    })
    .await
    .success();

    // Get
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["get-rbl-config"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("RBL enabled: true"))
    .stdout(predicate::str::contains("zen.spamhaus.org"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_flush_cache_unix() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["flush-cache"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Cache flushed"));

    server.shutdown();
}

// ========================================================
// Record type tests
// ========================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_add_mx_record() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "example.com.",
            "-r",
            "mx",
            "-v",
            "mail.example.com.",
            "-p",
            "10",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Added record"))
    .stdout(predicate::str::contains("MX"))
    .stdout(predicate::str::contains("Priority: 10"));

    // Verify in list output
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-records", "-r", "mx"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("MX"))
    .stdout(predicate::str::contains("mail.example.com."));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_add_cname_record() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "www.example.com.",
            "-r",
            "cname",
            "-v",
            "example.com.",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("CNAME"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_add_srv_record() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "_sip._tcp.example.com.",
            "-r",
            "srv",
            "-v",
            "5 5060 sip.example.com.",
            "-p",
            "10",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("SRV"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_add_ns_record() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "example.com.",
            "-r",
            "ns",
            "-v",
            "ns1.example.com.",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("NS"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_add_ptr_record() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "1.168.192.in-addr.arpa.",
            "-r",
            "ptr",
            "-v",
            "host.example.com.",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("PTR"));

    server.shutdown();
}

// ========================================================
// Help output tests
// ========================================================

#[test]
fn test_cli_help_output() {
    Command::new(cargo::cargo_bin!("rolodex-dns-cli"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "CLI client for managing a Rolodex",
        ))
        .stdout(predicate::str::contains("add-record"))
        .stdout(predicate::str::contains("remove-record"))
        .stdout(predicate::str::contains("list-records"))
        .stdout(predicate::str::contains("set-forwarders"))
        .stdout(predicate::str::contains("set-rbl-config"))
        .stdout(predicate::str::contains("get-rbl-config"))
        .stdout(predicate::str::contains("set-dnsbl-config"))
        .stdout(predicate::str::contains("get-dnsbl-config"))
        .stdout(predicate::str::contains("flush-cache"));
}

#[test]
fn test_cli_add_record_help() {
    Command::new(cargo::cargo_bin!("rolodex-dns-cli"))
        .args(["add-record", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Add a DNS record"))
        .stdout(predicate::str::contains("--name"))
        .stdout(predicate::str::contains("--record-type"))
        .stdout(predicate::str::contains("--value"))
        .stdout(predicate::str::contains("--ttl"))
        .stdout(predicate::str::contains("--priority"));
}

#[test]
fn test_cli_remove_record_help() {
    Command::new(cargo::cargo_bin!("rolodex-dns-cli"))
        .args(["remove-record", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Remove DNS record"))
        .stdout(predicate::str::contains("--name"));
}

#[test]
fn test_cli_list_records_help() {
    Command::new(cargo::cargo_bin!("rolodex-dns-cli"))
        .args(["list-records", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("List DNS records"))
        .stdout(predicate::str::contains("--name"))
        .stdout(predicate::str::contains("--record-type"));
}

// ========================================================
// Edge cases
// ========================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_empty_auth_server() {
    // Server with empty shared secret allows all tokens
    let server = TestServer::start("").await;

    // Should work with any token
    run_cmd({
        let mut cmd = Command::new(cargo::cargo_bin!("rolodex-dns-cli"));
        cmd.args(["-a", &server.tcp_addr, "-t", "anything"]);
        cmd.args(["list-records"]);
        cmd.timeout(std::time::Duration::from_secs(10));
        cmd
    })
    .await
    .success();

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_set_rbl_config_disabled() {
    let server = TestServer::start("test-secret").await;

    // Set RBL to disabled with no providers
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["set-rbl-config"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains(
        "RBL config updated (enabled: false)",
    ));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_remove_nonexistent_record() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["remove-record", "-n", "nonexistent.example.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Removed 0 record(s)"));

    server.shutdown();
}

// ========================================================
// Scope TLD subcommands
// ========================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_scope_tld_lifecycle_tcp() {
    let server = TestServer::start("test-secret").await;

    // Create a scope with an additional TLD via the repeatable --tld flag.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "create-scope",
            "-n",
            "office",
            "-d",
            "office.home",
            "--tld",
            "office.",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Created network scope"));

    // Add another TLD.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["add-scope-tld", "-s", "office", "--tld", "corp."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Added TLD"));

    // List TLDs: home_domain plus both additional.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-scope-tlds", "-s", "office"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("office.home."))
    .stdout(predicate::str::contains("office."))
    .stdout(predicate::str::contains("corp."));

    // list-scopes shows the TLDs column.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-scopes"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("office"));

    // Remove a TLD.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["remove-scope-tld", "-s", "office", "--tld", "corp."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Removed TLD"));

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_scope_tld_uniqueness_tcp() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["create-scope", "-n", "office", "-d", "office.home"]);
        cmd
    })
    .await
    .success();
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["create-scope", "-n", "lab", "-d", "lab.home"]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["add-scope-tld", "-s", "office", "--tld", "shared."]);
        cmd
    })
    .await
    .success();

    // Claiming the same TLD from another scope fails.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["add-scope-tld", "-s", "lab", "--tld", "shared."]);
        cmd
    })
    .await
    .failure();

    server.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_scope_tld_forwarders_unix() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args([
            "create-scope",
            "-n",
            "office",
            "-d",
            "office.",
            "--tld",
            "office.",
        ]);
        cmd
    })
    .await
    .success();

    // Set two peer forwarders.
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args([
            "set-scope-tld-forwarders",
            "-s",
            "office",
            "--tld",
            "office.",
            "-f",
            "10.90.12.2:53",
            "-f",
            "10.90.12.3:53",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Set 2 forwarder(s)"));

    // List them back.
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args([
            "list-scope-tld-forwarders",
            "-s",
            "office",
            "--tld",
            "office.",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("10.90.12.2:53"))
    .stdout(predicate::str::contains("10.90.12.3:53"));

    server.shutdown();
}
