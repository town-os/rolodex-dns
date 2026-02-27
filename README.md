# Rolodex

A split-horizon DNS server and forwarding resolver with gRPC management, written in Rust.

Rolodex provides DNS over UDP and TCP with a local record database that takes priority over forwarded queries. Records are managed remotely via gRPC (shared secret authentication over TCP, or unauthenticated over Unix socket). It supports TLD-level resolution with domain overlay, so internal DNS representations are always preferred.

Rolodex also supports Realtime Blackhole Lists (RBLs) for DNS-based spam/malware filtering.

## Features

- **Split-horizon DNS**: Local database records always take priority over forwarded upstream results
- **DNS over UDP and TCP**: Full protocol support for both transport layers
- **Forwarding resolver**: Configurable upstream DNS forwarders for non-local queries
- **TLD/domain overlay**: Add records at any level (including TLDs) to override public DNS
- **gRPC management**: Remote record management via gRPC with shared secret or Unix socket auth
- **RBL support**: Realtime Blackhole List checking with in-memory caching
- **SQLite persistence**: DNS records persist across restarts
- **Performance**: Built on Rust with tokio async runtime, hickory-dns protocol handling, and DashMap concurrent caching

## Building

```
make build
```

## Testing

```
make test
```

## Development

Start a local dev server for testing and development:

```
make dev
```

This will:
1. Build the project (`cargo build`)
2. Install the `rolodex` binary to your Cargo bin directory (`cargo install --path .`)
3. Start the server using `dev.yml` with the following settings:
   - DNS listeners on `127.0.0.1:5300` (UDP and TCP)
   - gRPC Unix socket at `/tmp/rolodex.sock` (no TCP gRPC listener)
   - SQLite database at `/tmp/rolodex-dev.db`
   - No authentication required
   - RBL checking disabled
   - Default upstream forwarders (`8.8.8.8:53`, `8.8.4.4:53`)

After `make dev` is running, you can manage the server using the installed `rolodex` binary or the Go client library connected to `/tmp/rolodex.sock`. Press Ctrl+C to stop the server.

## Configuration

Rolodex reads configuration from a YAML file (default: `rolodex.yml`).

```yaml
# Database file path
database_path: rolodex.db

# Upstream DNS forwarders (address:port format)
forwarders:
  - "8.8.8.8:53"
  - "8.8.4.4:53"

dns:
  # UDP listener bind address
  udp_bind: "0.0.0.0:53"
  # TCP listener bind address
  tcp_bind: "0.0.0.0:53"

grpc:
  # TCP gRPC listener (empty string to disable)
  tcp_bind: "127.0.0.1:50051"
  # Unix socket path (empty string to disable)
  unix_socket: /var/run/rolodex.sock
  # Shared secret for TCP gRPC authentication (not required for Unix socket)
  shared_secret: your-secret-here

rbl:
  # Enable/disable RBL checking globally (default: false)
  enabled: false
  # RBL providers
  providers:
    - zone: zen.spamhaus.org
      enabled: true
    - zone: bl.spamcop.net
      enabled: true
    - zone: b.barracudacentral.org
      enabled: true
    - zone: dnsbl.sorbs.net
      enabled: true
    - zone: dbl.spamhaus.org
      enabled: true
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `database_path` | `"rolodex.db"` | Path to the SQLite database file |
| `forwarders` | `["8.8.8.8:53", "8.8.4.4:53"]` | Upstream DNS resolver addresses |
| `dns.udp_bind` | `"0.0.0.0:53"` | UDP DNS listener bind address |
| `dns.tcp_bind` | `"0.0.0.0:53"` | TCP DNS listener bind address |
| `grpc.tcp_bind` | `"127.0.0.1:50051"` | TCP gRPC listener address (empty to disable) |
| `grpc.unix_socket` | `"/var/run/rolodex.sock"` | Unix socket path (empty to disable) |
| `grpc.shared_secret` | `""` | Shared secret for TCP gRPC auth (empty = no auth) |
| `rbl.enabled` | `false` | Enable RBL checking globally |
| `rbl.providers[].zone` | — | DNSBL zone to query |
| `rbl.providers[].enabled` | `true` | Enable/disable individual provider |

## Usage

### Server

```
rolodex [OPTIONS]

Options:
  -c, --config <CONFIG>  Path to configuration file [default: rolodex.yml]
  -h, --help             Print help
```

### CLI Client

`rolodex-cli` is a command-line client for managing a running Rolodex server via its gRPC management interface. It supports both TCP and Unix socket transports.

```
rolodex-cli [OPTIONS] <COMMAND>
```

#### Global Options

| Option | Default | Description |
|--------|---------|-------------|
| `-a, --address <ADDRESS>` | `127.0.0.1:50051` | gRPC server address for TCP connections (host:port). Ignored when `--unix-socket` is set. |
| `-u, --unix-socket <PATH>` | — | Path to Unix domain socket. Overrides `--address`. Unix socket connections bypass authentication. |
| `-t, --auth-token <TOKEN>` | `""` | Authentication token for TCP connections. Required when the server has a shared secret configured. Ignored for Unix socket connections. |
| `-h, --help` | — | Print help |
| `-V, --version` | — | Print version |

#### Commands

##### `add-record`

Add a DNS record to the local database.
**gRPC path:** `/rolodex.RolodexService/AddRecord`

```
rolodex-cli add-record -n <NAME> -v <VALUE> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-n, --name <NAME>` | — | Fully qualified domain name (e.g. `"example.com."` — trailing dot recommended) |
| `-r, --record-type <TYPE>` | `a` | DNS record type: `a`, `aaaa`, `cname`, `mx`, `txt`, `ns`, `soa`, `srv`, `ptr` |
| `-v, --value <VALUE>` | — | Record data. Format depends on record type (see Record Types section) |
| `--ttl <TTL>` | `300` | Time-to-live in seconds. If set to 0, the server defaults to 300 |
| `-p, --priority <PRIORITY>` | `0` | Priority for MX and SRV records. Lower values = higher priority. Ignored for other types |

Examples:
```bash
# Add an A record via TCP
rolodex-cli -a 127.0.0.1:50051 -t my-secret add-record \
  -n example.com. -r a -v 10.0.0.1 --ttl 600

# Add an MX record via Unix socket
rolodex-cli -u /var/run/rolodex.sock add-record \
  -n example.com. -r mx -v mail.example.com. -p 10

# Add a CNAME record
rolodex-cli add-record -n www.example.com. -r cname -v example.com.

# Add an SRV record
rolodex-cli add-record -n _sip._tcp.example.com. -r srv \
  -v "5 5060 sip.example.com." -p 10
```

##### `remove-record`

Remove DNS record(s) from the local database. Removes by name, with optional type and value filters.
**gRPC path:** `/rolodex.RolodexService/RemoveRecord`

```
rolodex-cli remove-record -n <NAME> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-n, --name <NAME>` | — | Fully qualified domain name of records to remove |
| `-r, --record-type <TYPE>` | — | If specified, only remove records of this type. If omitted, removes all types for the name |
| `-v, --value <VALUE>` | — | If specified, only remove the record with this exact value |

Examples:
```bash
# Remove all records for a name
rolodex-cli remove-record -n old.example.com.

# Remove only A records for a name
rolodex-cli remove-record -n example.com. -r a

# Remove a specific record by value
rolodex-cli remove-record -n example.com. -r a -v 10.0.0.1
```

##### `list-records`

List DNS records from the local database with optional filters.
**gRPC path:** `/rolodex.RolodexService/ListRecords`

```
rolodex-cli list-records [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-n, --name <NAME>` | — | Filter by domain name. Supports wildcard prefix `"*."` to match all subdomains (e.g. `"*.example.com."`) |
| `-r, --record-type <TYPE>` | — | Filter by record type. If omitted, returns all record types |

Examples:
```bash
# List all records
rolodex-cli list-records

# List records for a specific name
rolodex-cli list-records -n example.com.

# List all subdomains
rolodex-cli list-records -n "*.example.com."

# List only AAAA records
rolodex-cli list-records -r aaaa
```

##### `set-forwarders`

Set upstream DNS forwarders at runtime. Replaces the entire forwarder list.
**gRPC path:** `/rolodex.RolodexService/SetForwarders`

```
rolodex-cli set-forwarders -f <ADDR>...
```

| Option | Default | Description |
|--------|---------|-------------|
| `-f, --forwarders <ADDR>...` | — | Upstream DNS server addresses in `"host:port"` format. Multiple addresses separated by spaces |

Examples:
```bash
# Set Google and Cloudflare DNS
rolodex-cli set-forwarders -f 8.8.8.8:53 1.1.1.1:53

# Set a single forwarder
rolodex-cli set-forwarders -f 9.9.9.9:53
```

##### `set-rbl-config`

Configure RBL (Realtime Blackhole List) settings at runtime. Replaces the entire RBL configuration.
**gRPC path:** `/rolodex.RolodexService/SetRblConfig`

```
rolodex-cli set-rbl-config [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-e, --enabled` | `false` | Enable RBL checking globally. If flag is absent, RBL is disabled |
| `-p, --providers <SPEC>...` | — | RBL provider specifications in `"zone:enabled"` format (e.g. `"zen.spamhaus.org:true"`) |

Examples:
```bash
# Enable RBL with Spamhaus
rolodex-cli set-rbl-config -e -p "zen.spamhaus.org:true"

# Enable RBL with multiple providers (some disabled)
rolodex-cli set-rbl-config -e \
  -p "zen.spamhaus.org:true" \
  -p "bl.spamcop.net:false" \
  -p "dnsbl.sorbs.net:true"

# Disable RBL entirely
rolodex-cli set-rbl-config
```

##### `get-rbl-config`

Retrieve the current RBL configuration.
**gRPC path:** `/rolodex.RolodexService/GetRblConfig`

```
rolodex-cli get-rbl-config
```

Example output:
```
RBL enabled: true

Providers:
ZONE                                     ENABLED
--------------------------------------------------
zen.spamhaus.org                         true
bl.spamcop.net                           false
```

##### `flush-cache`

Flush the RBL result cache. Forces fresh lookups for subsequent reverse DNS queries.
**gRPC path:** `/rolodex.RolodexService/FlushCache`

```
rolodex-cli flush-cache
```

## gRPC API

The management API is defined in `proto/rolodex.proto`. All methods accept an `auth_token` field for shared-secret authentication when connecting over TCP. Unix socket connections bypass authentication.

### Service: `rolodex.RolodexService`

#### `AddRecord`

**Path:** `/rolodex.RolodexService/AddRecord`

Adds a DNS record to the local database.

**Parameters:**
- `record` (DnsRecord, required): The DNS record to add
  - `name` (string): Fully qualified domain name (e.g. `"example.com."`)
  - `record_type` (RecordType): Type of DNS record (see Record Types below)
  - `value` (string): Record data (e.g. IP address, hostname)
  - `ttl` (uint32): Time-to-live in seconds. Default: 300 if set to 0
  - `priority` (uint32): Priority for MX/SRV records (ignored for other types). Default: 0
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `RemoveRecord`

**Path:** `/rolodex.RolodexService/RemoveRecord`

Removes DNS record(s) from the local database.

**Parameters:**
- `name` (string, required): Fully qualified domain name
- `record_type` (RecordType): If set, only remove records of this type. If unset (A/0), removes all records for the name
- `value` (string): If non-empty, only remove the record with this exact value
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `removed_count` (uint32): Number of records removed
- `message` (string): Error message if `success` is false

#### `ListRecords`

**Path:** `/rolodex.RolodexService/ListRecords`

Queries the local DNS database with optional filters.

**Parameters:**
- `name_filter` (string): Filter by domain name. Supports wildcard prefix `"*."` to match all subdomains (e.g. `"*.example.com."`)
- `record_type_filter` (RecordType): Filter by record type (only applied when `filter_by_type` is true)
- `filter_by_type` (bool): Whether to apply the `record_type_filter`. Default: false
- `auth_token` (string): Shared secret for authentication

**Response:**
- `records` (repeated DnsRecord): Matching DNS records

#### `SetForwarders`

**Path:** `/rolodex.RolodexService/SetForwarders`

Configures upstream DNS forwarders at runtime.

**Parameters:**
- `forwarders` (repeated string): List of upstream DNS server addresses in `"host:port"` format (e.g. `"8.8.8.8:53"`)
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `SetRblConfig`

**Path:** `/rolodex.RolodexService/SetRblConfig`

Configures Realtime Blackhole List settings at runtime.

**Parameters:**
- `enabled` (bool): Whether RBL checking is globally enabled. Default: false
- `providers` (repeated RblConfig): List of RBL providers
  - `zone` (string): The DNSBL zone to query (e.g. `"zen.spamhaus.org"`)
  - `enabled` (bool): Whether this specific provider is enabled. Default: true
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `GetRblConfig`

**Path:** `/rolodex.RolodexService/GetRblConfig`

Retrieves the current RBL configuration.

**Parameters:**
- `auth_token` (string): Shared secret for authentication

**Response:**
- `enabled` (bool): Whether RBL checking is globally enabled
- `providers` (repeated RblConfig): Current RBL providers

#### `FlushCache`

**Path:** `/rolodex.RolodexService/FlushCache`

Clears the RBL lookup cache.

**Parameters:**
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

### Record Types

| Enum Value | Name | Description |
|-----------|------|-------------|
| 0 | `A` | IPv4 address mapping. Value: IPv4 address (e.g. `"192.168.1.1"`) |
| 1 | `AAAA` | IPv6 address mapping. Value: IPv6 address (e.g. `"::1"`) |
| 2 | `CNAME` | Canonical name alias. Value: target FQDN (e.g. `"target.example.com."`) |
| 3 | `MX` | Mail exchange. Value: mail server FQDN. Uses `priority` field |
| 4 | `TXT` | Text record. Value: text content |
| 5 | `NS` | Name server. Value: nameserver FQDN |
| 6 | `SOA` | Start of authority. Value: `"mname rname serial refresh retry expire minimum"` (space-separated) |
| 7 | `SRV` | Service locator. Value: `"weight port target"` (space-separated). Uses `priority` field |
| 8 | `PTR` | Pointer for reverse DNS. Value: target FQDN |

## RBL (Realtime Blackhole List)

When RBL is enabled, rolodex checks IP addresses found in reverse DNS queries against configured DNSBL providers. If an IP is listed in any enabled provider, the query receives an `NXDOMAIN` response.

### Default Providers

These match the common providers used by unbound and other DNS resolvers:

| Zone | Description |
|------|-------------|
| `zen.spamhaus.org` | Combined Spamhaus blocklist (SBL + XBL + PBL + CSS) |
| `bl.spamcop.net` | SpamCop blocklist |
| `b.barracudacentral.org` | Barracuda Reputation Block List |
| `dnsbl.sorbs.net` | SORBS aggregate zone |
| `dbl.spamhaus.org` | Spamhaus Domain Block List |

### How RBL Works

1. A reverse DNS query arrives (e.g. `100.1.168.192.in-addr.arpa.`)
2. The IP is extracted from the query name (`192.168.1.100`)
3. For each enabled RBL provider, rolodex constructs a query: `<reversed-ip>.<rbl-zone>`
4. If any RBL responds with an A record, the IP is considered listed
5. Results are cached in memory for the TTL returned by the RBL
6. Listed IPs receive `NXDOMAIN` for the original query

### Caching

- Positive results (IP is listed) are cached for the TTL returned by the RBL provider
- Negative results (IP is not listed) are cached for 5 minutes
- The cache can be flushed via the `FlushCache` gRPC method

## Go Client

A Go client library is included at `go/` for programmatic access to the Rolodex gRPC API. It can be imported as a Go module dependency.

### Installation

```
go get github.com/erikh/rolodex/go
```

### Connecting

The client supports two transports:

**TCP** (with shared-secret authentication):

```go
client, err := rolodex.Dial(ctx, "localhost:50051",
    rolodex.WithAuthToken("my-secret"),
)
defer client.Close()
```

**Unix socket** (authentication bypassed server-side):

```go
client, err := rolodex.Dial(ctx, "/var/run/rolodex.sock",
    rolodex.WithUnixSocket(),
)
defer client.Close()
```

### Client Options

| Option | Description |
|--------|-------------|
| `WithAuthToken(token)` | Sets the shared secret sent with every RPC for TCP authentication. Ignored by the server on Unix socket connections. Default: empty (succeeds if server has no secret configured) |
| `WithUnixSocket()` | Marks the address as a Unix domain socket path instead of a TCP address. Server bypasses authentication for Unix socket connections |
| `WithGRPCDialOption(opt)` | Appends a low-level `grpc.DialOption` (e.g. for TLS, interceptors) |

### Client Methods

All methods accept a `context.Context` for cancellation and deadlines.

#### `AddRecord(ctx, record) error`

Adds a DNS record to the server's local database.

**Path:** `/rolodex.RolodexService/AddRecord`

**Parameters:**
- `record` (`*DnsRecord`): The record to add. Fields:
  - `Name` (string): Fully qualified domain name (e.g. `"example.com."`)
  - `RecordType` (`RecordType`): One of `RecordTypeA` (0, default), `RecordTypeAAAA` (1), `RecordTypeCNAME` (2), `RecordTypeMX` (3), `RecordTypeTXT` (4), `RecordTypeNS` (5), `RecordTypeSOA` (6), `RecordTypeSRV` (7), `RecordTypePTR` (8)
  - `Value` (string): Record data (e.g. IP address, hostname)
  - `Ttl` (uint32): Time-to-live in seconds. Default: 300 if set to 0
  - `Priority` (uint32): Priority for MX/SRV records (ignored for other types). Default: 0

#### `RemoveRecord(ctx, name, opts) (uint32, error)`

Removes DNS records from the server's local database.

**Path:** `/rolodex.RolodexService/RemoveRecord`

**Parameters:**
- `name` (string): Fully qualified domain name to remove records for
- `opts` (`*RemoveRecordOptions`, optional): If nil, removes all records for the name
  - `RecordType` (`*RecordType`): If set, only remove records of this type
  - `Value` (string): If non-empty, only remove the record with this exact value

**Returns:** Number of records removed.

#### `ListRecords(ctx, opts) ([]*DnsRecord, error)`

Queries the server's local DNS database.

**Path:** `/rolodex.RolodexService/ListRecords`

**Parameters:**
- `opts` (`*ListRecordsOptions`, optional): If nil, returns all records
  - `NameFilter` (string): Filter by domain name. Supports wildcard prefix `"*."` (e.g. `"*.example.com."`)
  - `RecordType` (`*RecordType`): If set, only return records of this type

#### `SetForwarders(ctx, forwarders) error`

Configures upstream DNS forwarders. Replaces the entire forwarder list.

**Path:** `/rolodex.RolodexService/SetForwarders`

**Parameters:**
- `forwarders` (`[]string`): Upstream DNS server addresses in `"host:port"` format (e.g. `"8.8.8.8:53"`)

#### `SetRblConfig(ctx, enabled, providers) error`

Configures Realtime Blackhole List settings. Replaces the entire RBL configuration.

**Path:** `/rolodex.RolodexService/SetRblConfig`

**Parameters:**
- `enabled` (bool): Whether RBL checking is globally enabled. Default: false
- `providers` (`[]*RblConfig`): List of RBL providers
  - `Zone` (string): The DNSBL zone to query (e.g. `"zen.spamhaus.org"`)
  - `Enabled` (bool): Whether this provider is enabled. Default: true when added

#### `GetRblConfig(ctx) (*RblStatus, error)`

Retrieves the current RBL configuration.

**Path:** `/rolodex.RolodexService/GetRblConfig`

**Returns:** `*RblStatus` with fields:
- `Enabled` (bool): Whether RBL checking is globally enabled
- `Providers` (`[]*RblConfig`): Configured RBL providers

#### `FlushCache(ctx) error`

Clears the RBL lookup cache on the server.

**Path:** `/rolodex.RolodexService/FlushCache`

#### `Close() error`

Closes the underlying gRPC connection. Should be called when the client is no longer needed.

### Record Types

| Constant | Value | Description |
|----------|-------|-------------|
| `RecordTypeA` | 0 | IPv4 address (default) |
| `RecordTypeAAAA` | 1 | IPv6 address |
| `RecordTypeCNAME` | 2 | Canonical name alias |
| `RecordTypeMX` | 3 | Mail exchange (uses Priority) |
| `RecordTypeTXT` | 4 | Text record |
| `RecordTypeNS` | 5 | Name server |
| `RecordTypeSOA` | 6 | Start of authority |
| `RecordTypeSRV` | 7 | Service locator (uses Priority) |
| `RecordTypePTR` | 8 | Pointer for reverse DNS |

## Architecture

```
                    ┌──────────────┐
                    │   DNS Client  │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  DNS Server   │
                    │  (UDP + TCP)  │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼────┐ ┌────▼────┐ ┌────▼─────┐
        │  Local DB │ │  RBL    │ │ Forwarder │
        │ (SQLite)  │ │ Checker │ │ (Upstream)│
        └──────────┘ └─────────┘ └──────────┘
              │
        ┌─────▼──────┐
        │ gRPC Mgmt   │
        │ (TCP/Unix)  │
        └─────────────┘
```

Resolution order:
1. Check RBL (for reverse DNS queries, if enabled)
2. Check local database (split-horizon, always preferred)
3. Check for CNAME records in local database
4. If name is under a managed zone but not found, return authoritative NXDOMAIN
5. Forward to upstream resolvers

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See the [LICENSE](LICENSE) file for the full license text.
