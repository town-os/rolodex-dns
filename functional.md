# Rolodex Functional Specification

Rolodex is a split-horizon DNS server and forwarding resolver with remote management via gRPC. It is written in Rust and licensed under AGPL-3.0-only.

## DNS Resolution

Rolodex serves DNS queries over both UDP and TCP on configurable bind addresses (default `0.0.0.0:53`). TCP uses the standard 2-byte length prefix framing. Maximum UDP message size is 4096 bytes; maximum TCP message size is 65535 bytes.

### Supported Record Types

A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR.

### Split-Horizon Behavior

DNS queries are resolved in the following order:

1. **RBL check** — If the query is a reverse DNS lookup (`in-addr.arpa` or `ip6.arpa`), the extracted IP is checked against enabled RBL providers. If listed, NXDOMAIN is returned.
2. **Local database lookup** — The local database is queried for the requested name and type. If records exist, they are returned immediately.
3. **CNAME chain** — If no exact type match is found locally, a CNAME lookup is attempted for the queried name. If a CNAME exists, it is returned.
4. **Managed zone authority** — If the queried name falls under a zone that has records in the local database (determined by the last two labels of any stored FQDN), but the specific name was not found, an authoritative NXDOMAIN is returned. This prevents forwarding queries for names that should be resolved internally.
5. **Upstream forwarding** — Unmatched queries are forwarded via UDP to the configured upstream resolvers, tried in order with a 5-second timeout per attempt. If all forwarders fail or none are configured, SERVFAIL is returned.

This ordering ensures the inside representation always takes priority over external DNS, allowing TLD-level and domain-level overlays that update in real time as the gRPC control plane modifies records.

## Local Record Database

Records are stored in SQLite with WAL mode enabled for concurrent read performance. The database path is configurable (default `rolodex.db`). An in-memory mode is available for testing.

Domain names are normalized to lowercase with a trailing dot on storage and lookup, providing case-insensitive matching. The database has indices on `name` and `(name, record_type)`.

Records consist of: name, record type, value, TTL (default 300 seconds), and priority (used by MX and SRV).

SOA values are stored as `"mname rname serial refresh retry expire minimum"`. SRV values are stored as `"weight port target"`.

## Realtime Blackhole Lists (RBL)

Rolodex checks IPs against DNS-based blackhole lists using the standard reversed-IP lookup format:

- **IPv4**: Octets are reversed and appended to the RBL zone (e.g., `192.168.1.100` becomes `100.1.168.192.zen.spamhaus.org`).
- **IPv6**: Nibbles are expanded, reversed, and appended to the RBL zone.

RBL checking is globally togglable and disabled by default. Individual providers can also be enabled or disabled independently.

### Default Providers

These match the standard DNSBL zones used by unbound:

- `zen.spamhaus.org` — Combined Spamhaus blocklist (SBL + XBL + PBL + CSS)
- `bl.spamcop.net` — SpamCop blocklist
- `b.barracudacentral.org` — Barracuda Reputation Block List
- `dnsbl.sorbs.net` — SORBS aggregate zone
- `dbl.spamhaus.org` — Spamhaus Domain Block List

### Caching

RBL results are cached in memory using a concurrent hash map (keyed by `<ip>/<zone>`):

- **Positive results** (listed): Cached for the TTL returned by the RBL provider (default 300 seconds if no TTL provided).
- **Negative results** (not listed): Cached for 5 minutes.
- **Lookup errors**: Not cached; treated as not-listed to avoid false positives.

The cache can be flushed via gRPC.

## gRPC Management Interface

The management API is defined in `proto/rolodex.proto` under the `RolodexService` service. It can listen on TCP (default `127.0.0.1:50051`) and/or a Unix socket (default `/var/run/rolodex.sock`). Either transport can be disabled by setting its bind address to an empty string.

### Authentication

- **TCP connections** require a shared secret passed as `auth_token` in each request. If the server's shared secret is empty, all connections are allowed without authentication.
- **Unix socket connections** bypass authentication entirely.

### Operations

| RPC | Description |
|---|---|
| `AddRecord` | Adds a DNS record to the local database. TTL defaults to 300 if set to 0. |
| `RemoveRecord` | Removes records by name, with optional type and value filters. Returns the count of records removed. |
| `ListRecords` | Queries the local database with optional name filter (supports `*.` wildcard prefix for subdomain matching) and optional record type filter. |
| `SetForwarders` | Replaces the upstream DNS forwarder list at runtime without restart. |
| `SetRblConfig` | Replaces the RBL configuration (global enable flag and provider list) at runtime. |
| `GetRblConfig` | Returns the current RBL configuration. |
| `FlushCache` | Clears the RBL result cache. |

All changes made via gRPC (record additions/removals, forwarder updates, RBL configuration) take effect immediately and are reflected in subsequent DNS resolution.

## CLI Client

The `rolodex-cli` binary is a command-line client for the gRPC management interface. It supports all gRPC operations as subcommands and can connect over TCP or Unix socket.

### Global Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--address` | `-a` | `127.0.0.1:50051` | gRPC server address (host:port). Ignored when `--unix-socket` is specified. |
| `--unix-socket` | `-u` | — | Path to Unix domain socket. Overrides `--address`. |
| `--auth-token` | `-t` | (empty) | Authentication token for TCP connections. Ignored for Unix socket. |

### Subcommands

| Command | Description |
|---|---|
| `add-record` | Add a DNS record. Takes `--name` (required), `--record-type` (default `a`), `--value` (required), `--ttl` (default 300), and `--priority` (default 0, used for MX/SRV). |
| `remove-record` | Remove DNS record(s). Takes `--name` (required), with optional `--record-type` and `--value` filters. |
| `list-records` | List DNS records. Takes optional `--name` (supports `*.` wildcard prefix) and `--record-type` filters. |
| `set-forwarders` | Set upstream DNS forwarders. Takes `--forwarders` (one or more `host:port` addresses). |
| `set-rbl-config` | Configure RBL settings. Takes `--enabled` flag and optional `--providers` in `zone:enabled` format. |
| `get-rbl-config` | Display current RBL configuration. |
| `flush-cache` | Clear the RBL result cache. |

The `list-records` subcommand displays results in a tabular format with columns for name, type, value, TTL, and priority. The `get-rbl-config` subcommand displays the global enabled state and a table of providers.

## Go Client Library

A Go client library is provided in the `go/` directory, importable as `github.com/erikh/rolodex/go`. It wraps the gRPC API with idiomatic Go types and supports the same transport and authentication modes as the CLI.

### Connection

The `Dial` function establishes a connection and returns a `Client`:

- **TCP**: `Dial(ctx, "host:port", WithAuthToken("secret"))` — connects via TCP with shared-secret authentication.
- **Unix socket**: `Dial(ctx, "/path/to/socket", WithUnixSocket())` — connects via Unix domain socket, bypassing server-side authentication.

An additional `WithGRPCDialOption` option allows passing custom `grpc.DialOption` values for TLS or interceptor configuration.

### Client Methods

| Method | Description |
|---|---|
| `AddRecord(ctx, record)` | Adds a DNS record. |
| `RemoveRecord(ctx, name, opts)` | Removes records by name with optional `RemoveRecordOptions` (type and value filters). Returns removed count. |
| `ListRecords(ctx, opts)` | Queries records with optional `ListRecordsOptions` (name filter with `*.` wildcard support, type filter). |
| `SetForwarders(ctx, forwarders)` | Replaces the upstream forwarder list. |
| `SetRblConfig(ctx, enabled, providers)` | Replaces the RBL configuration. |
| `GetRblConfig(ctx)` | Returns an `RblStatus` with the current RBL configuration. |
| `FlushCache(ctx)` | Clears the RBL result cache. |
| `Close()` | Releases the underlying gRPC connection. |

The client automatically includes the auth token in every RPC call. All methods accept `context.Context` for cancellation and deadlines.

### Exported Types

- `RecordType` — DNS record type enum (constants: `RecordTypeA`, `RecordTypeAAAA`, `RecordTypeCNAME`, `RecordTypeMX`, `RecordTypeTXT`, `RecordTypeNS`, `RecordTypeSOA`, `RecordTypeSRV`, `RecordTypePTR`).
- `DnsRecord` — DNS record with name, record type, value, TTL, and priority.
- `RblConfig` — RBL provider configuration (zone and enabled flag).
- `RblStatus` — RBL state returned by `GetRblConfig` (global enabled flag and provider list).
- `RemoveRecordOptions` — Optional filters for `RemoveRecord` (record type, value).
- `ListRecordsOptions` — Optional filters for `ListRecords` (name filter, record type).
- `Option` — Functional option for configuring `Dial`.

### Generated Protobuf Code

Generated Go protobuf and gRPC bindings are in `go/rolodexpb/`, produced from `proto/rolodex.proto`. The client library re-exports the key types so consumers do not need to import the generated package directly.

## Configuration

Configuration is loaded from a YAML file (default path `rolodex.yml`, overridable via `-c`/`--config` CLI flag). If the file does not exist, sensible defaults are used.

### Configuration Fields

| Field | Default | Description |
|---|---|---|
| `dns.udp_bind` | `0.0.0.0:53` | DNS UDP listener address |
| `dns.tcp_bind` | `0.0.0.0:53` | DNS TCP listener address |
| `grpc.tcp_bind` | `127.0.0.1:50051` | gRPC TCP listener address |
| `grpc.unix_socket` | `/var/run/rolodex.sock` | gRPC Unix socket path |
| `grpc.shared_secret` | (empty) | Shared secret for TCP gRPC auth |
| `forwarders` | `["8.8.8.8:53", "8.8.4.4:53"]` | Upstream DNS resolvers |
| `database_path` | `rolodex.db` | SQLite database file path |
| `rbl.enabled` | `false` | Global RBL enable flag |
| `rbl.providers` | 5 default zones (see above) | RBL provider list |

## Build System

The project uses a top-level Makefile with the following targets:

| Target | Description |
|---|---|
| `build` | Compile the Rust project in debug mode (`cargo build`). Produces the `rolodex` server and `rolodex-cli` client binaries. |
| `test` | Run all tests: Go integration tests, Go unit tests, and Rust tests (`cargo test`). |
| `clean` | Clean build artifacts (`cargo clean`). |
| `go-test` | Run Go unit tests (depends on `go-integration-test`). |
| `go-integration-test` | Build the Rust binaries, then run Go integration tests with the `integration` build tag, passing the compiled server binary path via `ROLODEX_BINARY`. |
| `install` | Install the Rust binaries to the Cargo bin directory (`cargo install --path .`). |
| `dev` | Build the Rust project in debug mode, then start a development server using `dev.yml`. |
| `dev-release` | Build the Rust project in release mode, then start a development server using `dev.yml`. |

The Makefile is designed to be extended for non-cargo scenarios. Protocol buffer bindings are generated at build time via `build.rs` using `tonic-prost-build`.

### Development Server

The `make dev` target starts a local development instance configured via `dev.yml`:

- DNS listeners on `127.0.0.1:5300` (UDP and TCP) — a non-privileged port that does not require root.
- gRPC management via Unix socket at `/tmp/rolodex.sock` only (TCP gRPC disabled).
- Database at `/tmp/rolodex-dev.db`.
- No authentication (empty shared secret).
- RBL disabled.
- Google DNS forwarders (`8.8.8.8:53`, `8.8.4.4:53`).

The `make dev-release` target does the same but builds with `--release` for optimized performance.

## Testing

### Rust Tests

Rust tests (`cargo test`) include unit tests and integration tests covering gRPC operations, DNS resolution (UDP and TCP), split-horizon behavior, authentication enforcement, Unix socket auth bypass, database persistence, and configuration serialization.

### CLI Integration Tests

The `rolodex-cli` binary has integration tests that spawn a test gRPC server and execute the CLI binary against it. Tests cover all subcommands over both TCP and Unix socket transports, authentication (success, failure, and Unix socket bypass), all record types (A, AAAA, CNAME, MX, TXT, NS, SRV, PTR), wildcard filtering, and help output validation.

### Go Client Tests

The Go client has two test layers:

- **Unit tests** — Use an in-process mock gRPC server via `bufconn` to test all client methods, authentication token propagation, transport modes, error handling, and edge cases (idempotent close, lazy dial, custom dial options).
- **Integration tests** — Gated behind the `integration` build tag. Each test starts a real Rolodex server subprocess with a unique temporary directory, random ports, and isolated database. Tests cover record CRUD, wildcard filtering, forwarder configuration, RBL round-trip, cache flushing, Unix socket transport, authentication failure, default TTL behavior, and concurrent clients (5 simultaneous).

The `make test` target runs the full test suite: Go integration tests, Go unit tests, and Rust tests, in that order.

## Key Dependencies

### Rust

- **domain** / **hickory-resolver** / **hickory-proto** — DNS protocol parsing, record types, and upstream resolution
- **tonic** / **prost** — gRPC framework and protocol buffer serialization
- **rusqlite** (bundled) — SQLite database with WAL mode
- **tokio** — Async runtime
- **dashmap** — Lock-free concurrent hash map/set for caching
- **arc-swap** — Lock-free atomic swapping of `Arc` pointers for RBL providers and TTL drift config
- **clap** — CLI argument parsing (server and client)
- **tracing** — Structured logging (configurable via `RUST_LOG` environment variable)
- **hyper-util** / **tower** — HTTP/2 transport for Unix socket gRPC connections in the CLI client

### Go

- **google.golang.org/grpc** — gRPC framework
- **google.golang.org/protobuf** — Protocol buffer runtime

## Concurrency Model

The server runs on the tokio multi-threaded async runtime. DNS UDP queries are handled sequentially on a single task. DNS TCP connections spawn a new task per connection. gRPC servers (TCP and Unix socket) run as separate tasks. Upstream forwarder configuration is protected by `RwLock` for concurrent read access. RBL state uses lock-free primitives: the enabled flag is an `AtomicBool` and the provider list uses `ArcSwap` for zero-contention reads. The RBL cache and DNS response cache use lock-free `DashMap`. The SQLite database is protected by a `Mutex` with `prepare_cached` for statement reuse.

At boot, in-memory caches are populated from the database: scope count (`AtomicUsize`), local RBL entries (`DashSet`), authoritative zones (`DashSet`), and managed zones (`DashSet`). These caches avoid SQL queries on the hot path and are updated incrementally as records are added or removed via gRPC.

Upstream DNS forwarding uses a pool of UDP sockets, allowing concurrent forwarding without contention on a single socket.

The in-memory DNS cache is automatically flushed when records are mutated via gRPC (add, remove, or scoped variants) to ensure consistency between the database and cached responses. Local database records are cached with a `local` flag that prevents TTL decay and SQLite persistence, since they are authoritative.
