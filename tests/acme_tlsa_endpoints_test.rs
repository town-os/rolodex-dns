//! `acme.tlsa_endpoints` as a deployed configuration, out of process.
//!
//! A TLSA record names a service *endpoint* rather than a certificate, and one
//! certificate serving encrypted DNS covers two of them: DoT at `853/tcp` and
//! DoQ at `853/udp`. `acme.tlsa_port`/`acme.tlsa_proto` are a single scalar
//! pair, so issuance published exactly one record and the other transport had
//! none. A DANE-checking client that finds no record for the transport it chose
//! fails closed, so the missing half reads as "this server's DoQ is broken"
//! rather than "this server has no DANE".
//!
//! `tests/acme_issuer_test.rs` covers what gets published, against a real
//! issuance flow. This file covers the half that only exists once a config file
//! meets the real binary: that a malformed entry stops the server instead of
//! being skipped.
//!
//! That distinction is the whole reason the parse is strict. A skipped entry is
//! a TLSA record that silently never appears, and to a DANE client an absent
//! record and a server that never had DANE are the same thing — so a typo would
//! turn a security feature off with nothing to show for it. Refusing to start is
//! loud; publishing three records out of four is not.
//!
//! Nothing here touches the host: loopback only, ephemeral ports, a temporary
//! directory, and the process is killed on drop whatever the test does.

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn server_binary() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("rolodex-dns").to_path_buf()
}

/// An ephemeral port, so two concurrent runs of the suite cannot collide.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// A spawned server, killed and reaped on drop however the test exits.
struct Server {
    child: Child,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _unused = self.child.kill();
        let _unused = self.child.wait();
    }
}

impl Server {
    fn spawn(config_path: &Path) -> Self {
        let child = Command::new(server_binary())
            .arg("-c")
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn rolodex-dns");
        Self { child }
    }

    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().expect("try_wait")
    }

    /// Waits up to 15s for the process to exit, returning its status if it did.
    ///
    /// Long enough that a server which is going to fail has failed, short enough
    /// that a server which came up cleanly is still identifiable as running.
    fn wait_for_exit(&mut self) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if let Some(status) = self.exited() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        None
    }
}

/// Writes a config whose only interesting content is `acme.tlsa_endpoints`.
///
/// Everything else is the smallest thing that starts: loopback DNS on an
/// ephemeral port, the management socket in the temp dir, no TCP gRPC listener
/// (which would need a shared secret), and `forward` mode with no forwarders so
/// the process cannot reach the network even if something asked it to.
fn write_config(dir: &Path, endpoints: &str) -> PathBuf {
    let config_path = dir.join("rolodex-dns.yml");
    let config = format!(
        r#"database_path: "{db}"
forwarders: []
resolution:
  mode: forward
dns:
  bind:
    - udp: "127.0.0.1:{dns}"
    - tcp: "127.0.0.1:{dns}"
grpc:
  tcp_bind: ""
  unix_socket: "{sock}"
  shared_secret: ""
acme:
  bind: "127.0.0.1:{acme}"
  portal_bind: "127.0.0.1:{portal}"
  tlsa_endpoints: {endpoints}
"#,
        db = dir.join("rolodex-dns.db").display(),
        sock = dir.join("rolodex-dns.sock").display(),
        dns = free_port(),
        acme = free_port(),
        portal = free_port(),
        endpoints = endpoints,
    );
    let mut f = std::fs::File::create(&config_path).expect("create config");
    f.write_all(config.as_bytes()).expect("write config");
    config_path
}

/// A malformed entry must stop the server, not be dropped on the floor.
///
/// Each of these is a different way to be wrong — no protocol, a protocol that
/// is not a TLSA protocol, a port outside the range, a port that is not a
/// number, and the zero port that names no endpoint — because a parser that
/// rejected only the shapes it happened to think of would still let the others
/// through as silently-missing records.
#[test]
fn a_malformed_tlsa_endpoint_refuses_to_start() {
    for bad in [
        r#"["853"]"#,
        r#"["853/sctp"]"#,
        r#"["70000/tcp"]"#,
        r#"["eight53/tcp"]"#,
        r#"["0/tcp"]"#,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(dir.path(), bad);
        let mut server = Server::spawn(&config);

        match server.wait_for_exit() {
            Some(status) => assert!(
                !status.success(),
                "server exited successfully with acme.tlsa_endpoints: {bad}"
            ),
            None => panic!(
                "server started with acme.tlsa_endpoints: {bad}. A malformed \
                 endpoint must be refused at startup — skipping it publishes \
                 fewer TLSA records than the operator asked for, and a DANE \
                 client cannot tell a missing record from a server with no DANE."
            ),
        }
    }
}

/// The control, and the reason the test above proves anything.
///
/// The same config shape with well-formed entries — including the `853/udp`
/// that the scalar `tlsa_port`/`tlsa_proto` pair could not express — has to
/// start and stay up. Without this, a server that failed to start for any
/// unrelated reason (a bad path, a port already held, a parse error elsewhere in
/// the file) would satisfy every assertion above.
#[test]
fn wellformed_tlsa_endpoints_start_normally() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), r#"["853/tcp", "853/udp"]"#);
    let mut server = Server::spawn(&config);

    if let Some(status) = server.wait_for_exit() {
        panic!(
            "server refused to start with well-formed tlsa_endpoints \
             (exit {status:?}); the rejection test above proves nothing if a \
             valid list is refused too"
        );
    }
}

/// Omitting the key entirely is every configuration written before this feature
/// existed, and it has to keep starting: the scalar pair alone remains a
/// complete configuration.
#[test]
fn an_absent_tlsa_endpoints_key_still_starts() {
    let dir = tempfile::tempdir().unwrap();

    // Written without the key at all rather than as an empty list — an absent
    // key and `[]` take different paths through serde's defaulting, and it is
    // the absent one that every existing deployment has.
    let config_path = dir.path().join("rolodex-dns.yml");
    let config = format!(
        r#"database_path: "{db}"
forwarders: []
resolution:
  mode: forward
dns:
  bind:
    - udp: "127.0.0.1:{dns}"
    - tcp: "127.0.0.1:{dns}"
grpc:
  tcp_bind: ""
  unix_socket: "{sock}"
  shared_secret: ""
acme:
  bind: "127.0.0.1:{acme}"
  portal_bind: "127.0.0.1:{portal}"
"#,
        db = dir.path().join("rolodex-dns.db").display(),
        sock = dir.path().join("rolodex-dns.sock").display(),
        dns = free_port(),
        acme = free_port(),
        portal = free_port(),
    );
    std::fs::write(&config_path, config).expect("write config");

    let mut server = Server::spawn(&config_path);
    if let Some(status) = server.wait_for_exit() {
        panic!("server refused to start with no acme.tlsa_endpoints key (exit {status:?})");
    }
}
