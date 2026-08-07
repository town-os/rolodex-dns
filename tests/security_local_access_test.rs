//! Security regression tests for local access to the management plane.
//!
//! These assert behaviour the server *should* have and are expected to FAIL
//! against the current implementation. Do not weaken an assertion to make one
//! pass.
//!
//! Two of the three pin filesystem permissions, which is why they spawn the real
//! `rolodex-dns` binary rather than building a server in-process: the permission
//! decision belongs to the startup path in `main.rs`, so an in-process harness
//! would test the wrong thing.
//!
//! | Test | Issue |
//! | ---- | ----- |
//! | `unix_socket_is_not_world_accessible` | `check_auth` returns `Ok(())` unconditionally for Unix connections, and `main.rs` never chmods the socket after `UnixListener::bind` — so it lands world-connectable under the default umask and any local user has unauthenticated admin. |
//! | `database_file_is_not_world_readable` | The database holds the root CA private key, every per-zone intermediate key, DNSSEC private keys, and EAB HMAC secrets. Nothing in the tree calls `set_permissions`, so it is created 0644 under a typical umask. |
//! | `public_grpc_bind_with_empty_secret_is_refused` | An empty `grpc.shared_secret` disables TCP authentication entirely (`check_auth` early-returns). Combined with a routable `tcp_bind` that is a silent, total exposure of the management plane. |
//!
//! Everything happens inside a `tempfile::TempDir` on loopback and ephemeral
//! ports; no host state is modified and the spawned process is always reaped.

use std::io::Write;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Path to the compiled server binary.
fn server_binary() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("rolodex-dns").to_path_buf()
}

/// Reserves an ephemeral TCP port by binding and immediately dropping it. Good
/// enough for a test: nothing else on the box is racing for it.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// A spawned server that is killed and reaped on drop, whatever the test does.
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
    /// Spawns the server against `config_path`.
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

    /// Returns the exit status if the process has already exited.
    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().expect("try_wait")
    }
}

/// Writes a minimal server config into `dir` and returns its path along with the
/// socket and database paths it names. `grpc_tcp_bind` is written verbatim.
fn write_config(
    dir: &Path,
    grpc_tcp_bind: &str,
    shared_secret: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    let socket_path = dir.join("rolodex-dns.sock");
    let db_path = dir.join("rolodex-dns.db");
    let config_path = dir.join("rolodex-dns.yml");
    let dns_port = free_port();

    let config = format!(
        "database_path: {db}\n\
         forwarders: []\n\
         dns:\n\
         \x20 bind:\n\
         \x20   - udp: \"127.0.0.1:{dns_port}\"\n\
         \x20   - tcp: \"127.0.0.1:{dns_port}\"\n\
         resolution:\n\
         \x20 mode: forward\n\
         grpc:\n\
         \x20 tcp_bind: \"{tcp}\"\n\
         \x20 unix_socket: {sock}\n\
         \x20 shared_secret: \"{secret}\"\n\
         rbl:\n\
         \x20 enabled: false\n\
         \x20 providers: []\n\
         address_family:\n\
         \x20 mode: off\n",
        db = db_path.display(),
        dns_port = dns_port,
        tcp = grpc_tcp_bind,
        sock = socket_path.display(),
        secret = shared_secret,
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config.as_bytes()).unwrap();
    (config_path, socket_path, db_path)
}

/// Waits up to `timeout` for `path` to exist. Returns whether it appeared.
fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// ============================================================================
// Unix socket permissions
// ============================================================================

/// A connection over the Unix socket bypasses authentication entirely, so the
/// socket's file mode *is* the access control. Created with a bare
/// `UnixListener::bind` and never chmodded, it inherits the process umask —
/// typically 0755 — and every local user on the box gets unauthenticated
/// administrative control: rewrite any DNS record, mint EAB credentials, ensure
/// zone CAs.
///
/// The socket must not be accessible to other users. 0660 with a dedicated group
/// (or 0600) is the shape of the fix; this asserts only that no permission bits
/// are granted to "other".
#[test]
fn unix_socket_is_not_world_accessible() {
    let dir = tempfile::tempdir().unwrap();
    let (config, socket_path, _db) = write_config(dir.path(), "", "");
    let _server = Server::spawn(&config);

    assert!(
        wait_for_path(&socket_path, Duration::from_secs(15)),
        "server did not create its Unix socket"
    );
    // The socket is bound before the mode is set; give startup a moment to
    // settle so this measures the steady state rather than a race.
    std::thread::sleep(Duration::from_millis(300));

    let mode = mode_of(&socket_path);
    assert_eq!(
        mode & 0o007,
        0,
        "the gRPC Unix socket is mode {:04o}: it grants access to other users, \
         and a Unix connection bypasses authentication entirely",
        mode
    );
}

// ============================================================================
// Database permissions
// ============================================================================

/// The database is the keystore: the root CA private key (`dane_root_cas`),
/// every per-zone intermediate key (`zone_cas`), DNSSEC private keys, and EAB
/// HMAC secrets all live in it as plain rows. A local user who can read the file
/// holds the root CA key and can forge a certificate for any name that every
/// enrolled client will trust.
///
/// Nothing in the tree calls `set_permissions`, so the file is created under the
/// bare umask. It must not be readable by other users. The WAL and shared-memory
/// sidecars carry the same content and are checked alongside it.
#[test]
fn database_file_is_not_world_readable() {
    let dir = tempfile::tempdir().unwrap();
    let (config, socket_path, db_path) = write_config(dir.path(), "", "");
    let _server = Server::spawn(&config);

    assert!(
        wait_for_path(&socket_path, Duration::from_secs(15)),
        "server did not finish starting"
    );
    assert!(db_path.exists(), "server did not create its database");
    std::thread::sleep(Duration::from_millis(300));

    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{}", db_path.display(), suffix));
        if !path.exists() {
            continue;
        }
        let mode = mode_of(&path);
        assert_eq!(
            mode & 0o007,
            0,
            "{} is mode {:04o}: it is readable by other users and contains the \
             root CA private key, the per-zone intermediate keys, the DNSSEC \
             private keys, and the EAB HMAC secrets",
            path.display(),
            mode
        );
    }
}

// ============================================================================
// Fail-open TCP authentication
// ============================================================================

/// `check_auth` early-returns `Ok(())` when the shared secret is empty, so an
/// empty `grpc.shared_secret` disables TCP authentication for every RPC. That is
/// defensible on a loopback bind and indefensible on a routable one, and the
/// combination is silent today — the server starts and logs nothing unusual.
///
/// Binding the management plane to a non-loopback address with no secret must be
/// a startup error, not a running configuration. (The DNS listeners here stay on
/// loopback; only the gRPC listener is exercised, on an ephemeral port, and the
/// process is killed either way.)
#[test]
fn public_grpc_bind_with_empty_secret_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let (config, _socket, _db) = write_config(dir.path(), &format!("0.0.0.0:{}", port), "");
    let mut server = Server::spawn(&config);

    // Give the process time to either fail fast or come up.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut status = None;
    while Instant::now() < deadline {
        if let Some(s) = server.exited() {
            status = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    match status {
        Some(s) => assert!(
            !s.success(),
            "server exited successfully instead of reporting a configuration error"
        ),
        None => panic!(
            "server started with grpc.tcp_bind=0.0.0.0:{} and an empty \
             shared_secret: the management plane is exposed with authentication \
             disabled. This combination must be rejected at startup.",
            port
        ),
    }
}

/// The counterpart: the same empty secret on a loopback bind is the documented
/// development configuration and must keep working, so the fix rejects the
/// routable case specifically rather than banning empty secrets outright.
#[test]
fn loopback_grpc_bind_with_empty_secret_still_starts() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let (config, socket_path, _db) = write_config(dir.path(), &format!("127.0.0.1:{}", port), "");
    let mut server = Server::spawn(&config);

    assert!(
        wait_for_path(&socket_path, Duration::from_secs(15)),
        "server with a loopback gRPC bind and no secret should start normally"
    );
    assert!(
        server.exited().is_none(),
        "server exited unexpectedly on a loopback bind with an empty secret"
    );
}
