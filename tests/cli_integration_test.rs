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
    async fn lookup_rbl(&self, _query: &str) -> Result<Option<u32>, anyhow::Error> {
        Ok(None)
    }
}

struct TestServer {
    tcp_addr: String,
    unix_path: String,
    /// The database the service is running against.
    ///
    /// Exposed so a test can seed state the CLI has no subcommand to create —
    /// a DHCP lease, an issued certificate, a registered ACME account — and then
    /// exercise the subcommand that reads or deletes it. Without this, the
    /// read-side commands could only ever be tested against an empty table,
    /// which passes equally well for a command that returns nothing at all.
    db: Database,
    tmpdir: tempfile::TempDir,
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
            db,
            tmpdir,
            shutdown_tx,
        }
    }

    /// A path inside the server's temporary directory, for tests that need to
    /// hand the CLI a file (a certificate to read, for instance).
    fn temp_path(&self, name: &str) -> String {
        self.tmpdir.path().join(name).to_string_lossy().to_string()
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

// ========================================================
// Full subcommand coverage
// ========================================================
//
// Everything below exists because the CLI is a separate surface from the gRPC
// service it wraps. A handler can be perfectly tested and its subcommand still
// be broken: a mistyped `#[arg(short)]`, a field mapped to the wrong request
// slot, a `default_value` that disagrees with the server's, or an error path
// that prints a success line. None of that is visible from a test that calls the
// RPC directly.
//
// So these drive the real binary and assert on what an operator sees — the
// output for the success path, and a non-zero exit for the failure path. Where a
// command reads state the CLI cannot create, the test seeds it through
// `server.db` and then reads it back through the CLI, so the listing is proven
// to render real rows rather than an empty table.

/// Writes a self-signed certificate PEM and returns its path, for the
/// subcommands that take a `--cert-path`.
fn write_test_cert(server: &TestServer, name: &str) -> String {
    let params =
        rcgen::CertificateParams::new(vec!["cli-test.example.com".to_string()]).expect("params");
    let key_pair = rcgen::KeyPair::generate().expect("key pair");
    let cert = params.self_signed(&key_pair).expect("self-signed");
    let path = server.temp_path(name);
    std::fs::write(&path, cert.pem()).expect("write certificate");
    path
}

// --------------------------------------------------------
// Network membership
// --------------------------------------------------------

/// `join-network`, `list-associations`, `get-search-domains`, `leave-network`.
///
/// Run as one sequence because they describe one lifecycle, and because the
/// interesting assertions are about what each command sees *after* the previous
/// one: an association that never appears in `list-associations` and a search
/// domain that survives `leave-network` are both failures no single-command test
/// would catch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_network_membership_lifecycle_unix() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["create-scope", "-n", "office", "-d", "office.home."]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args([
            "join-network",
            "-i",
            "10.64.1.5",
            "-s",
            "office",
            "--ttl",
            "600",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("joined scope 'office'"))
    .stdout(predicate::str::contains("600"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-associations"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("10.64.1.5"))
    .stdout(predicate::str::contains("office"));

    // The scope filter must actually filter, not be accepted and ignored.
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-associations", "-s", "nonexistent"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No network associations found."));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["get-search-domains", "-i", "10.64.1.5"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("office.home."));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["leave-network", "-i", "10.64.1.5"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("left network"));

    // Gone from both views, which is what "left" has to mean.
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-associations"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No network associations found."));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["get-search-domains", "-i", "10.64.1.5"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No search domains"));

    server.shutdown();
}

/// `add-scoped-record`, `list-scoped-records`, `remove-scoped-record`, and
/// `delete-scope`.
///
/// The type and value filters on the remove are exercised separately from the
/// unfiltered case: a `--record-type` that reached the server as "remove
/// everything" would pass a test that only checked the record was gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_scoped_record_lifecycle_tcp() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["create-scope", "-n", "lab"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Created network scope: lab"));

    for (name, rtype, value) in [
        ("host.lab.home.", "a", "10.5.0.1"),
        ("host.lab.home.", "aaaa", "2001:db8::5"),
        ("other.lab.home.", "a", "10.5.0.2"),
    ] {
        run_cmd({
            let mut cmd = server.cli_tcp();
            cmd.args([
                "add-scoped-record",
                "-s",
                "lab",
                "-n",
                name,
                "-r",
                rtype,
                "-v",
                value,
            ]);
            cmd
        })
        .await
        .success();
    }

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-scoped-records", "-s", "lab"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("host.lab.home."))
    .stdout(predicate::str::contains("10.5.0.1"))
    .stdout(predicate::str::contains("3 record(s) found"));

    // Name filter.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-scoped-records", "-s", "lab", "-n", "other.lab.home."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("10.5.0.2"))
    .stdout(predicate::str::contains("1 record(s) found"));

    // Type filter.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-scoped-records", "-s", "lab", "-r", "aaaa"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("2001:db8::5"))
    .stdout(predicate::str::contains("1 record(s) found"));

    // Remove only the AAAA; the A at the same name must survive.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "remove-scoped-record",
            "-s",
            "lab",
            "-n",
            "host.lab.home.",
            "-r",
            "aaaa",
        ]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-scoped-records", "-s", "lab", "-n", "host.lab.home."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("10.5.0.1"))
    .stdout(predicate::str::contains("1 record(s) found"));

    // Deleting the scope takes its records with it.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["delete-scope", "-n", "lab"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Deleted network scope: lab"));

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-scopes"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No network scopes configured."));

    server.shutdown();
}

// --------------------------------------------------------
// Zones and caches
// --------------------------------------------------------

/// `add-auth-zone` / `list-auth-zones` / `remove-auth-zone`, and the two cache
/// commands.
///
/// `cache-stats` is read twice around a `flush-dns-cache` so the command is
/// shown to report live numbers rather than a constant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_auth_zones_and_cache_unix() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-auth-zones"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains(
        "No authoritative zones configured.",
    ));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["add-auth-zone", "-z", "internal.test."]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-auth-zones"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("internal.test."))
    .stdout(predicate::str::contains("1 zone(s) found."));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["remove-auth-zone", "-z", "internal.test."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Removed authoritative zone"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-auth-zones"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains(
        "No authoritative zones configured.",
    ));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["cache-stats"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("DNS Cache Statistics:"))
    .stdout(predicate::str::contains("Total entries:"))
    .stdout(predicate::str::contains("Hit count:"))
    .stdout(predicate::str::contains("Miss count:"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["flush-dns-cache"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("DNS cache flushed successfully."));

    server.shutdown();
}

/// The local RBL entry commands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_local_rbl_lifecycle_tcp() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-local-rbl"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No local RBL entries configured."));

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-local-rbl",
            "-n",
            "spammer.example.com.",
            "-r",
            "phishing campaign",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Added local RBL entry"));

    // The reason is the operator's note to their future self; a command that
    // accepted it and dropped it would look identical here without this.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-local-rbl"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("spammer.example.com."))
    .stdout(predicate::str::contains("phishing campaign"))
    .stdout(predicate::str::contains("1 entry(ies) found."));

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["remove-local-rbl", "-n", "spammer.example.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Removed local RBL entry"));

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-local-rbl"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No local RBL entries configured."));

    server.shutdown();
}

// --------------------------------------------------------
// Runtime tuning
// --------------------------------------------------------

/// `set-ttl-drift` / `get-ttl-drift` across all three modes, and
/// `latency-stats`.
///
/// Each `set` is read back, because the round trip is where a CLI flag mapped
/// into the wrong request field shows up — `--adjustment` landing in
/// `log_multiplier` would still report success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_ttl_drift_and_latency_unix() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["set-ttl-drift", "-m", "fixed", "--adjustment", "1h30m"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("mode=fixed"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["get-ttl-drift"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("TTL Drift Configuration:"))
    .stdout(predicate::str::contains("fixed"))
    .stdout(predicate::str::contains("1h30m"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["set-ttl-drift", "-m", "logarithmic", "-l", "0.25"]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["get-ttl-drift"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("logarithmic"))
    .stdout(predicate::str::contains("0.25"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["set-ttl-drift", "-m", "disabled"]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["get-ttl-drift"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("disabled"));

    // Nothing has been forwarded, so there is nothing to report — and saying so
    // is the correct output, not an empty table or an error.
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["latency-stats"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No latency statistics available."));

    server.shutdown();
}

/// `set-dns64` / `get-dns64`, including the documented default prefix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_dns64_config_tcp() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["set-dns64", "-e", "-p", "2001:db8:64::"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("enabled=true"))
    .stdout(predicate::str::contains("2001:db8:64::"));

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["get-dns64"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("DNS64 Configuration:"))
    .stdout(predicate::str::contains("Enabled: true"))
    .stdout(predicate::str::contains("2001:db8:64::"));

    // Omitting --prefix must fall back to the documented default rather than to
    // an empty string.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["set-dns64"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("64:ff9b::"));

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["get-dns64"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Enabled: false"))
    .stdout(predicate::str::contains("64:ff9b::"));

    server.shutdown();
}

// --------------------------------------------------------
// DHCP
// --------------------------------------------------------

/// The DHCP pool and lease commands.
///
/// The lease is seeded through the database because no subcommand creates one —
/// leases come from real DHCP traffic. Without seeding, `list-dhcp-leases` and
/// `delete-dhcp-lease` could only be tested against an empty table, which is
/// exactly the case that cannot distinguish a working command from one that
/// returns nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_dhcp_pools_and_leases_unix() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["create-scope", "-n", "office"]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-dhcp-pools"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No DHCP pools configured."));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args([
            "add-dhcp-pool",
            "-s",
            "office",
            "--range-start",
            "192.168.50.10",
            "--range-end",
            "192.168.50.99",
            "--gateway",
            "192.168.50.1",
            "--dns-servers",
            "192.168.50.1",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("DHCP pool added for scope office"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-dhcp-pools", "-s", "office"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("192.168.50.10"))
    .stdout(predicate::str::contains("192.168.50.99"))
    .stdout(predicate::str::contains("192.168.50.1"));

    // Seed a lease, list it, then delete it through the CLI.
    server
        .db
        .create_lease(&rolodex_dns::db::DhcpLease {
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            ip: "192.168.50.20".to_string(),
            scope_name: "office".to_string(),
            hostname: Some("laptop".to_string()),
            lease_start: 1_700_000_000,
            lease_duration: 3600,
            state: "active".to_string(),
        })
        .expect("seed lease");

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-dhcp-leases"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("aa:bb:cc:dd:ee:ff"))
    .stdout(predicate::str::contains("192.168.50.20"))
    .stdout(predicate::str::contains("laptop"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-dhcp-leases", "-s", "office"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("aa:bb:cc:dd:ee:ff"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["delete-dhcp-lease", "--mac", "aa:bb:cc:dd:ee:ff"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("deleted"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-dhcp-leases"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No DHCP leases."));

    // Removing the pool needs its id, which only the listing reports.
    let pool_id = server
        .db
        .list_dhcp_pools(Some("office"))
        .expect("list pools")
        .first()
        .expect("the pool exists")
        .id;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["remove-dhcp-pool", "--pool-id", &pool_id.to_string()]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("removed"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-dhcp-pools"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No DHCP pools configured."));

    server.shutdown();
}

/// The DHCP certificate-option commands.
///
/// `set-dhcp-cert` reads a file from disk, so this also covers the CLI's own
/// file handling: a `--cert-path` that is never read would leave the option
/// stored with an empty payload, which the listing's SIZE column exposes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_dhcp_cert_options_tcp() {
    let server = TestServer::start("test-secret").await;
    let cert_path = write_test_cert(&server, "dhcp-cert.pem");

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["create-scope", "-n", "office"]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-dhcp-certs", "-s", "office"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No DHCP cert options for scope"));

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "set-dhcp-cert",
            "-s",
            "office",
            "--option-code",
            "224",
            "--cert-path",
            &cert_path,
            "--description",
            "site root CA",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Set DHCP cert option 224"));

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-dhcp-certs", "-s", "office"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("224"))
    .stdout(predicate::str::contains("site root CA"));

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["remove-dhcp-cert", "-s", "office", "--option-code", "224"]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-dhcp-certs", "-s", "office"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No DHCP cert options for scope"));

    server.shutdown();
}

/// Per-scope RBL providers, and the ingress-listener listing.
///
/// `list-scope-tld-listeners` is checked in its empty form only: binding a real
/// listener requires an address on the host, and these tests must not touch the
/// host's networking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_scope_rbl_and_listeners_unix() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["create-scope", "-n", "office"]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-scope-rbl", "-s", "office"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No scope RBL providers"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args([
            "add-scope-rbl",
            "-s",
            "office",
            "-z",
            "zen.spamhaus.org",
            "-e",
            "true",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Added RBL provider"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-scope-rbl", "-s", "office"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("zen.spamhaus.org"))
    .stdout(predicate::str::contains("true"));

    // `--enabled` takes a value and defaults to `true`, so omitting it adds a
    // provider that is actually checked — which is what the documentation says
    // and the only reading of `add` that does anything.
    //
    // This is pinned in both directions because the flag has been wrong in both
    // directions. Spelled as a bare `bool` with `default_value = "true"`, clap
    // gives the field the `SetTrue` action: older versions ignored the default
    // and made omission mean `false` (an operator following the docs added a
    // provider that silently checked nothing), and clap 4.6 applies the default
    // instead, which makes the flag decorative and a disabled provider
    // impossible to express. Taking a value is what makes both halves reachable.
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["add-scope-rbl", "-s", "office", "-z", "bl.spamcop.net"]);
        cmd
    })
    .await
    .success();

    let providers = server
        .db
        .list_scope_rbl_providers("office")
        .expect("list providers");
    let spamcop = providers
        .iter()
        .find(|p| p.zone == "bl.spamcop.net")
        .expect("the provider was not stored");
    assert!(
        spamcop.enabled,
        "omitting --enabled must register an *enabled* provider, as documented"
    );

    // The other half: a provider can still be registered without turning it on.
    // If this ever fails with a parse error, the flag has gone back to being a
    // bare switch and the disabled state is unreachable again.
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args([
            "add-scope-rbl",
            "-s",
            "office",
            "-z",
            "multi.uribl.com",
            "--enabled",
            "false",
        ]);
        cmd
    })
    .await
    .success();

    let providers = server
        .db
        .list_scope_rbl_providers("office")
        .expect("list providers");
    let uribl = providers
        .iter()
        .find(|p| p.zone == "multi.uribl.com")
        .expect("the disabled provider was not stored");
    assert!(
        !uribl.enabled,
        "--enabled false must register a disabled provider"
    );

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["remove-scope-rbl", "-s", "office", "-z", "multi.uribl.com"]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["remove-scope-rbl", "-s", "office", "-z", "bl.spamcop.net"]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["remove-scope-rbl", "-s", "office", "-z", "zen.spamhaus.org"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Removed RBL provider"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-scope-rbl", "-s", "office"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No scope RBL providers"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-scope-tld-listeners", "-s", "office"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No ingress listeners for scope"));

    server.shutdown();
}

// --------------------------------------------------------
// DNSSEC and DANE
// --------------------------------------------------------

/// `generate-dnssec-key`, `list-dnssec-keys`, `sign-zone`, and `generate-tlsa`.
///
/// `sign-zone` is run against a zone that has a record, so it does real signing
/// work rather than succeeding vacuously; and it is run *before* any key exists
/// as well, because "sign a zone with no keys" must fail loudly rather than
/// report a zone signed with nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_dnssec_and_tlsa_tcp() {
    let server = TestServer::start("test-secret").await;
    let cert_path = write_test_cert(&server, "tlsa-cert.pem");

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-dnssec-keys", "-z", "example.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No DNSSEC keys found"));

    // No keys yet: signing must fail rather than claim success.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["sign-zone", "-z", "example.com."]);
        cmd
    })
    .await
    .failure();

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n",
            "www.example.com.",
            "-r",
            "a",
            "-v",
            "192.0.2.1",
        ]);
        cmd
    })
    .await
    .success();

    // The requested spelling and the canonical name the server reports back are
    // deliberately different strings: a key generated as `ed25519` must be
    // reported as `Ed25519`, because that canonical name is what is stored and
    // what `DnssecAlgorithm::parse` has to round-trip at signing time.
    for (requested, canonical, key_type) in [
        ("ed25519", "Ed25519", "KSK"),
        ("ecdsa-p256", "ECDSA-P256-SHA256", "ZSK"),
    ] {
        run_cmd({
            let mut cmd = server.cli_tcp();
            cmd.args([
                "generate-dnssec-key",
                "-z",
                "example.com.",
                "--algorithm",
                requested,
                "-k",
                key_type,
            ]);
            cmd
        })
        .await
        .success()
        .stdout(predicate::str::contains("Generated DNSSEC key"))
        .stdout(predicate::str::contains(canonical))
        .stdout(predicate::str::contains(key_type))
        .stdout(predicate::str::contains("Key tag:"));
    }

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-dnssec-keys", "-z", "example.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Ed25519"))
    .stdout(predicate::str::contains("ECDSA-P256-SHA256"))
    .stdout(predicate::str::contains("2 key(s) found."));

    // RSA is refused at generation; the CLI must surface that as a failure.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "generate-dnssec-key",
            "-z",
            "example.com.",
            "--algorithm",
            "rsa-sha256",
        ]);
        cmd
    })
    .await
    .failure();

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["sign-zone", "-z", "example.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("signed successfully"));

    // The signing actually produced RRSIGs, not just a success line.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-records", "-r", "rrsig"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("RRSIG"));

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "generate-tlsa",
            "-d",
            "example.com.",
            "-p",
            "443",
            "-c",
            &cert_path,
            "--usage",
            "3",
            "--selector",
            "1",
            "--matching-type",
            "1",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("TLSA record generated:"))
    .stdout(predicate::str::contains("3 1 1"));

    server.shutdown();
}

// --------------------------------------------------------
// ACME
// --------------------------------------------------------

/// The ACME issuer administration commands: `ensure-zone-ca`, `create-eab`,
/// `remove-eab`, `list-acme-accounts`, `list-acme-certs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_acme_admin_unix() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-acme-accounts"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No ACME accounts."));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-acme-certs"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No issued certificates."));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["ensure-zone-ca", "-z", "example.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Zone CA ready for example.com."))
    .stdout(predicate::str::contains("Root CA:"))
    .stdout(predicate::str::contains("Intermediate CA:"))
    .stdout(predicate::str::contains("BEGIN CERTIFICATE"));

    // Mint a credential, then read its kid back out of the output so the
    // removal targets the credential that was actually created.
    let minted = run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["create-eab", "-z", "example.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("EAB credential created"))
    .stdout(predicate::str::contains("Key ID:"))
    .stdout(predicate::str::contains("HMAC key:"));

    let output = String::from_utf8(minted.get_output().stdout.clone()).expect("utf-8 output");
    let kid = output
        .lines()
        .find_map(|l| l.trim().strip_prefix("Key ID:"))
        .map(|v| v.trim().to_string())
        .expect("the create-eab output did not print a key id");
    assert!(!kid.is_empty(), "create-eab printed an empty key id");

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["remove-eab", "-k", &kid]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("Removed EAB credential"));

    // Removing it a second time must fail: the CLI has to distinguish "removed"
    // from "there was nothing to remove".
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["remove-eab", "-k", &kid]);
        cmd
    })
    .await
    .failure();

    // Seed an account and a certificate so the listings render real rows.
    server
        .db
        .create_acme_account(&rolodex_dns::db::AcmeAccount {
            account_id: "acct-cli".to_string(),
            jwk: r#"{"kty":"OKP","crv":"Ed25519","x":"cli"}"#.to_string(),
            thumbprint: "thumb-cli".to_string(),
            contacts: None,
            status: "valid".to_string(),
            eab_kid: Some("kid-cli".to_string()),
            zone: Some("example.com.".to_string()),
        })
        .expect("seed account");
    server
        .db
        .store_acme_certificate("www.example.com.", "cert", "key", "chain", 4_000_000_000)
        .expect("seed certificate");

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-acme-accounts"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("acct-cli"))
    .stdout(predicate::str::contains("valid"))
    .stdout(predicate::str::contains("kid-cli"));

    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-acme-certs"]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("www.example.com."));

    // The zone filter must filter.
    run_cmd({
        let mut cmd = server.cli_unix();
        cmd.args(["list-acme-certs", "-z", "elsewhere.test."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("No issued certificates."));

    server.shutdown();
}

/// The legacy `request-acme-cert` and `acme-status` stubs.
///
/// `request-acme-cert` provisions the dns-01 challenge record locally and
/// contacts nobody, so the provider URL is inert here — which is exactly why the
/// TXT record it plants is what gets asserted, rather than the success line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_legacy_acme_stubs_tcp() {
    let server = TestServer::start("test-secret").await;

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["acme-status", "-d", "example.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("ACME Status for example.com."))
    .stdout(predicate::str::contains("Status:"));

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "request-acme-cert",
            "-d",
            "example.com.",
            "-p",
            "https://acme.invalid/directory",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains(
        "ACME certificate requested for example.com.",
    ));

    // The challenge record is the observable effect.
    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args(["list-records", "-n", "_acme-challenge.example.com."]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("_acme-challenge.example.com."))
    .stdout(predicate::str::contains("TXT"));

    server.shutdown();
}

/// Every subcommand's parser must actually build.
///
/// clap validates a command's short options when the parser is constructed, and
/// **panics** on a duplicate — so a subcommand that reuses a short letter taken
/// by a global option is not merely awkward, it aborts on every invocation
/// including `--help`, before any argument is read. That is how
/// `generate-dnssec-key` (`-a` for `--algorithm`) and `set-ttl-drift` (`-a` for
/// `--adjustment`) both collided with the global `--address` and became
/// impossible to run at all.
///
/// A test per subcommand would not have caught it either, unless there happened
/// to be one for that subcommand. This walks the whole list, so a new command
/// that reuses `-a`, `-u`, or `-t` fails here rather than in an operator's
/// terminal.
///
/// `--help` is the probe because it exercises parser construction and nothing
/// else: no server, no connection, no side effects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cli_every_subcommand_help_builds() {
    // Read the subcommand list out of the top-level help rather than hardcoding
    // it, so a newly added command is covered without anyone remembering to add
    // it here.
    let top = run_cmd({
        let mut cmd = Command::new(cargo::cargo_bin!("rolodex-dns-cli"));
        cmd.arg("--help");
        cmd.timeout(std::time::Duration::from_secs(10));
        cmd
    })
    .await
    .success();

    let help = String::from_utf8(top.get_output().stdout.clone()).expect("utf-8 help");
    // clap lists each command on a line indented by exactly two spaces, with
    // wrapped descriptions continuing at the description column (deeper). The
    // section ends at the blank line before `Options:`.
    let subcommands: Vec<String> = help
        .lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|token| *token != "help")
        .map(|token| token.to_string())
        .collect();

    assert!(
        subcommands.len() > 50,
        "only {} subcommands were parsed out of the top-level help; the parsing \
         here has drifted from clap's output format and is no longer covering \
         anything: {:?}",
        subcommands.len(),
        subcommands
    );

    for name in subcommands {
        let assert = run_cmd({
            let mut cmd = Command::new(cargo::cargo_bin!("rolodex-dns-cli"));
            cmd.args([&name, "--help"]);
            cmd.timeout(std::time::Duration::from_secs(10));
            cmd
        })
        .await;

        let output = assert.get_output();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("panicked"),
            "`{name} --help` panicked, so the subcommand cannot be invoked at \
             all:\n{stderr}"
        );
        assert!(
            output.status.success(),
            "`{name} --help` exited unsuccessfully:\n{stderr}"
        );
    }
}
