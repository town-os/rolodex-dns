use assert_cmd::cargo;
use assert_cmd::Command;
use predicates::prelude::*;
use rolodex::db::Database;
use rolodex::dns_server::DnsServer;
use rolodex::grpc_service::proto::rolodex_service_server::RolodexServiceServer;
use rolodex::grpc_service::RolodexGrpcService;
use rolodex::rbl::{RblChecker, RblResolver};
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
    _tmpdir: tempfile::TempDir,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl TestServer {
    async fn start(shared_secret: &str) -> Self {
        let tmpdir = tempfile::tempdir().unwrap();
        let socket_path = tmpdir.path().join("rolodex-test.sock");
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

        let tcp_service = RolodexGrpcService::new(
            db.clone(),
            dns_server.clone(),
            rbl.clone(),
            shared_secret.to_string(),
            false,
        );

        // Start Unix socket server
        let uds = UnixListener::bind(&socket_path).unwrap();
        let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds);

        let unix_service = RolodexGrpcService::new(
            db.clone(),
            dns_server.clone(),
            rbl.clone(),
            shared_secret.to_string(),
            true,
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let tcp_server = Server::builder()
                .add_service(RolodexServiceServer::new(tcp_service))
                .serve_with_incoming(tcp_incoming);

            let unix_server = Server::builder()
                .add_service(RolodexServiceServer::new(unix_service))
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
        let mut cmd = Command::new(cargo::cargo_bin!("rolodex-cli"));
        cmd.args(["-a", &self.tcp_addr, "-t", "test-secret"]);
        cmd.timeout(std::time::Duration::from_secs(10));
        cmd
    }

    fn cli_unix(&self) -> Command {
        let mut cmd = Command::new(cargo::cargo_bin!("rolodex-cli"));
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

    run_cmd(
        {
            let mut cmd = server.cli_tcp();
            cmd.args([
                "add-record",
                "-n", "cli-test.example.com.",
                "-r", "a",
                "-v", "10.0.0.1",
                "--ttl", "600",
            ]);
            cmd
        },
    )
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
            "-n", "list-test.example.com.",
            "-r", "a",
            "-v", "10.0.0.1",
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
            "-n", "remove-test.example.com.",
            "-r", "a",
            "-v", "10.0.0.2",
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
            "-n", "multi.example.com.",
            "-r", "a",
            "-v", "10.0.0.1",
        ]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n", "multi.example.com.",
            "-r", "aaaa",
            "-v", "::1",
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
            "-n", "typed.example.com.",
            "-r", "a",
            "-v", "10.0.0.1",
        ]);
        cmd
    })
    .await
    .success();

    run_cmd({
        let mut cmd = server.cli_tcp();
        cmd.args([
            "add-record",
            "-n", "typed.example.com.",
            "-r", "aaaa",
            "-v", "::1",
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
            "-p", "zen.spamhaus.org:true", "bl.spamcop.net:false",
        ]);
        cmd
    })
    .await
    .success()
    .stdout(predicate::str::contains("RBL config updated (enabled: true)"));

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
        let mut cmd = Command::new(cargo::cargo_bin!("rolodex-cli"));
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
            "-n", "unix-test.example.com.",
            "-r", "a",
            "-v", "10.0.0.5",
            "--ttl", "900",
            "-p", "0",
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
            "-n", "unix-list.example.com.",
            "-r", "txt",
            "-v", "hello world",
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
        let mut cmd = Command::new(cargo::cargo_bin!("rolodex-cli"));
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
            "-n", "crud.example.com.",
            "-r", "a",
            "-v", "192.168.1.1",
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
            "-n", "crud.example.com.",
            "-v", "192.168.1.1",
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
            "-n", "example.com.",
            "-r", "mx",
            "-v", "mail.example.com.",
            "-p", "10",
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
            "-n", "www.example.com.",
            "-r", "cname",
            "-v", "example.com.",
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
            "-n", "_sip._tcp.example.com.",
            "-r", "srv",
            "-v", "5 5060 sip.example.com.",
            "-p", "10",
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
            "-n", "example.com.",
            "-r", "ns",
            "-v", "ns1.example.com.",
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
            "-n", "1.168.192.in-addr.arpa.",
            "-r", "ptr",
            "-v", "host.example.com.",
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
    Command::new(cargo::cargo_bin!("rolodex-cli"))
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("CLI client for managing a Rolodex"))
        .stdout(predicate::str::contains("add-record"))
        .stdout(predicate::str::contains("remove-record"))
        .stdout(predicate::str::contains("list-records"))
        .stdout(predicate::str::contains("set-forwarders"))
        .stdout(predicate::str::contains("set-rbl-config"))
        .stdout(predicate::str::contains("get-rbl-config"))
        .stdout(predicate::str::contains("flush-cache"));
}

#[test]
fn test_cli_add_record_help() {
    Command::new(cargo::cargo_bin!("rolodex-cli"))
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
    Command::new(cargo::cargo_bin!("rolodex-cli"))
        .args(["remove-record", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Remove DNS record"))
        .stdout(predicate::str::contains("--name"));
}

#[test]
fn test_cli_list_records_help() {
    Command::new(cargo::cargo_bin!("rolodex-cli"))
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
        let mut cmd = Command::new(cargo::cargo_bin!("rolodex-cli"));
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
    .stdout(predicate::str::contains("RBL config updated (enabled: false)"));

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
