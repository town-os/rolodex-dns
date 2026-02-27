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
- **Network scoping**: Split-horizon DNS views with per-scope records and IP-based access control
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

##### `create-scope`

Create a new network scope with a reserved `.home` domain.
**gRPC path:** `/rolodex.RolodexService/CreateNetworkScope`

```
rolodex-cli create-scope -n <NAME> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-n, --name <NAME>` | — | Unique name for the network scope (e.g. `"office"`, `"lab"`) |
| `-d, --home-domain <DOMAIN>` | `"<name>.home."` | Reserved `.home` domain for this scope. If omitted, defaults to `"<name>.home."` |

Examples:
```bash
# Create a scope with default home domain
rolodex-cli create-scope -n office
# Creates scope "office" with home domain "office.home."

# Create a scope with custom home domain
rolodex-cli create-scope -n lab -d lab.internal.
```

##### `delete-scope`

Delete a network scope and all its records and associations.
**gRPC path:** `/rolodex.RolodexService/DeleteNetworkScope`

```
rolodex-cli delete-scope -n <NAME>
```

| Option | Default | Description |
|--------|---------|-------------|
| `-n, --name <NAME>` | — | Name of the scope to delete |

##### `list-scopes`

List all configured network scopes.
**gRPC path:** `/rolodex.RolodexService/ListNetworkScopes`

```
rolodex-cli list-scopes
```

##### `join-network`

Associate an IP address with a network scope. The association has a TTL and must be refreshed regularly.
**gRPC path:** `/rolodex.RolodexService/JoinNetwork`

```
rolodex-cli join-network -i <IP> -s <SCOPE> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i, --ip <IP>` | — | Client IP address to associate (e.g. `"192.168.1.100"`) |
| `-s, --scope <SCOPE>` | — | Network scope name to join |
| `--ttl <TTL>` | `300` | TTL in seconds for the association. Must be refreshed before expiry. If 0, defaults to 300 |

Examples:
```bash
# Join with default TTL
rolodex-cli join-network -i 192.168.1.100 -s office

# Join with custom TTL
rolodex-cli join-network -i 10.0.0.5 -s lab --ttl 600
```

##### `leave-network`

Remove an IP address's association with its network scope.
**gRPC path:** `/rolodex.RolodexService/LeaveNetwork`

```
rolodex-cli leave-network -i <IP>
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i, --ip <IP>` | — | Client IP address to disassociate |

##### `list-associations`

List IP-to-scope associations, optionally filtered by scope.
**gRPC path:** `/rolodex.RolodexService/GetNetworkAssociations`

```
rolodex-cli list-associations [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | — | Filter by scope name. If omitted, lists all associations |

##### `add-scoped-record`

Add a DNS record within a specific network scope. Scoped records are only visible to IPs associated with that scope.
**gRPC path:** `/rolodex.RolodexService/AddScopedRecord`

```
rolodex-cli add-scoped-record -s <SCOPE> -n <NAME> -v <VALUE> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | — | Network scope to add the record to |
| `-n, --name <NAME>` | — | Fully qualified domain name |
| `-r, --record-type <TYPE>` | `a` | DNS record type |
| `-v, --value <VALUE>` | — | Record data |
| `--ttl <TTL>` | `300` | Time-to-live in seconds |
| `-p, --priority <PRIORITY>` | `0` | Priority for MX and SRV records |

Examples:
```bash
# Add a scoped A record
rolodex-cli add-scoped-record -s office -n printer.office.home. -v 192.168.1.50

# Add a scoped CNAME
rolodex-cli add-scoped-record -s lab -n app.lab.home. -r cname -v server.lab.home.
```

##### `remove-scoped-record`

Remove DNS records from a specific network scope.
**gRPC path:** `/rolodex.RolodexService/RemoveScopedRecord`

```
rolodex-cli remove-scoped-record -s <SCOPE> -n <NAME> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | — | Network scope to remove records from |
| `-n, --name <NAME>` | — | Fully qualified domain name |
| `-r, --record-type <TYPE>` | — | Filter by record type |
| `-v, --value <VALUE>` | — | Filter by exact value |

##### `list-scoped-records`

List DNS records within a network scope.
**gRPC path:** `/rolodex.RolodexService/ListScopedRecords`

```
rolodex-cli list-scoped-records -s <SCOPE> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-s, --scope <SCOPE>` | — | Network scope to query |
| `-n, --name <NAME>` | — | Filter by domain name (supports wildcard `"*."` prefix) |
| `-r, --record-type <TYPE>` | — | Filter by record type |

##### `get-search-domains`

Retrieve the search domains for a client IP address.
**gRPC path:** `/rolodex.RolodexService/GetSearchDomains`

```
rolodex-cli get-search-domains -i <IP>
```

| Option | Default | Description |
|--------|---------|-------------|
| `-i, --ip <IP>` | — | Client IP address to look up |

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

#### `CreateNetworkScope`

**Path:** `/rolodex.RolodexService/CreateNetworkScope`

Creates a new network scope with a reserved `.home` domain.

**Parameters:**
- `scope` (NetworkScope, required): The scope to create
  - `name` (string): Unique name for the scope (e.g. `"office"`, `"lab"`)
  - `home_domain` (string): Reserved `.home` domain. Default: `"<name>.home."` if empty
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `DeleteNetworkScope`

**Path:** `/rolodex.RolodexService/DeleteNetworkScope`

Deletes a network scope and all its records and associations.

**Parameters:**
- `name` (string, required): Name of the scope to delete
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `ListNetworkScopes`

**Path:** `/rolodex.RolodexService/ListNetworkScopes`

Retrieves all configured network scopes.

**Parameters:**
- `auth_token` (string): Shared secret for authentication

**Response:**
- `scopes` (repeated NetworkScope): All configured scopes

#### `JoinNetwork`

**Path:** `/rolodex.RolodexService/JoinNetwork`

Associates a client IP address with a network scope. The association has a TTL that must be refreshed regularly to maintain DNS resolution.

**Parameters:**
- `ip_address` (string, required): Client IP to associate (e.g. `"192.168.1.100"`)
- `scope_name` (string, required): Network scope name to join
- `ttl_seconds` (uint64): TTL in seconds. Default: 300 if set to 0. Must be refreshed before expiry.
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `LeaveNetwork`

**Path:** `/rolodex.RolodexService/LeaveNetwork`

Removes an IP address's association with its network scope.

**Parameters:**
- `ip_address` (string, required): Client IP to disassociate
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `GetNetworkAssociations`

**Path:** `/rolodex.RolodexService/GetNetworkAssociations`

Retrieves IP-to-scope associations.

**Parameters:**
- `scope_name` (string): Filter by scope name. Empty returns all associations.
- `auth_token` (string): Shared secret for authentication

**Response:**
- `associations` (repeated NetworkAssociation): Matching associations
  - `ip_address` (string): The associated IP
  - `scope_name` (string): The scope name
  - `ttl_seconds` (uint64): TTL for the association

#### `AddScopedRecord`

**Path:** `/rolodex.RolodexService/AddScopedRecord`

Adds a DNS record within a specific network scope. Scoped records are only visible to IPs associated with that scope.

**Parameters:**
- `scope_name` (string, required): The scope to add the record to
- `record` (DnsRecord, required): The DNS record to add
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `message` (string): Error message if `success` is false

#### `RemoveScopedRecord`

**Path:** `/rolodex.RolodexService/RemoveScopedRecord`

Removes DNS records from a specific network scope.

**Parameters:**
- `scope_name` (string, required): The scope to remove records from
- `name` (string, required): FQDN to remove records for
- `record_type` (RecordType): Optional type filter
- `value` (string): Optional exact value filter
- `auth_token` (string): Shared secret for authentication

**Response:**
- `success` (bool): Whether the operation succeeded
- `removed_count` (uint32): Number of records removed
- `message` (string): Error message if `success` is false

#### `ListScopedRecords`

**Path:** `/rolodex.RolodexService/ListScopedRecords`

Queries DNS records within a network scope.

**Parameters:**
- `scope_name` (string, required): The scope to query
- `name_filter` (string): Filter by domain name (supports wildcard `"*."` prefix)
- `record_type_filter` (RecordType): Filter by record type (only applied when `filter_by_type` is true)
- `filter_by_type` (bool): Whether to apply `record_type_filter`. Default: false
- `auth_token` (string): Shared secret for authentication

**Response:**
- `records` (repeated DnsRecord): Matching scoped records

#### `GetSearchDomains`

**Path:** `/rolodex.RolodexService/GetSearchDomains`

Retrieves the search domains for a client IP address. Returns the `.home` domain of the scope the IP is associated with.

**Parameters:**
- `ip_address` (string, required): Client IP to look up
- `auth_token` (string): Shared secret for authentication

**Response:**
- `search_domains` (repeated string): Search domains for the IP (typically the scope's `.home` domain)

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

## Network Scoping

Network scoping provides split-horizon DNS views, allowing different DNS responses based on which network scope a client IP is associated with.

### Concepts

- **Network Scope**: A named DNS view with its own set of DNS records and a reserved `.home` domain (e.g. `office.home.`). The `.home` domain is used as the default search domain for DHCP clients.
- **Network Association**: A mapping from a client IP to a scope, with a TTL that must be refreshed regularly. When the TTL expires, the IP loses its scope association and DNS queries are refused.
- **Scoped Records**: DNS records that belong to a specific scope and are only visible to IPs associated with that scope.

### How It Works

1. Create a network scope (e.g. `"office"` with domain `"office.home."`)
2. Add scoped DNS records to the scope
3. Client IPs join the network by associating with a scope (with a TTL)
4. When a DNS query arrives:
   - If scopes exist and the source IP is not associated with any scope: **REFUSED**
   - If the IP is associated with a scope: check scoped records first, then fall through to global records, then forward upstream
   - If no scopes exist at all: legacy behavior (all queries served from global records)
5. Search domains (via `GetSearchDomains`) return the `.home` domain for DHCP integration

### Resolution Order (Scoped)

1. Check RBL (for reverse DNS queries, if enabled)
2. Check scoped records for the client's scope
3. Check scoped CNAME records
4. Check if name is under a scoped managed zone (authoritative NXDOMAIN)
5. Check global database records
6. Check global CNAME records
7. Check if name is under a global managed zone (authoritative NXDOMAIN)
8. Forward to upstream resolvers

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

#### `CreateNetworkScope(ctx, scope) error`

Creates a new network scope.

**Path:** `/rolodex.RolodexService/CreateNetworkScope`

**Parameters:**
- `scope` (`*NetworkScope`): The scope to create. Fields:
  - `Name` (string): Unique name for the scope
  - `HomeDomain` (string): Reserved `.home` domain. Default: `"<name>.home."` if empty

#### `DeleteNetworkScope(ctx, name) error`

Deletes a network scope and all its records and associations.

**Path:** `/rolodex.RolodexService/DeleteNetworkScope`

**Parameters:**
- `name` (string): Name of the scope to delete

#### `ListNetworkScopes(ctx) ([]*NetworkScope, error)`

Retrieves all configured network scopes.

**Path:** `/rolodex.RolodexService/ListNetworkScopes`

#### `JoinNetwork(ctx, ipAddress, scopeName, ttlSeconds) error`

Associates a client IP with a network scope. The association must be refreshed before the TTL expires.

**Path:** `/rolodex.RolodexService/JoinNetwork`

**Parameters:**
- `ipAddress` (string): Client IP to associate (e.g. `"192.168.1.100"`)
- `scopeName` (string): Network scope name to join
- `ttlSeconds` (uint64): TTL in seconds (0 defaults to 300)

#### `LeaveNetwork(ctx, ipAddress) error`

Removes an IP's association with its network scope.

**Path:** `/rolodex.RolodexService/LeaveNetwork`

**Parameters:**
- `ipAddress` (string): Client IP to disassociate

#### `GetNetworkAssociations(ctx, scopeName) ([]*NetworkAssociation, error)`

Retrieves IP-to-scope associations.

**Path:** `/rolodex.RolodexService/GetNetworkAssociations`

**Parameters:**
- `scopeName` (string): Filter by scope name. Empty returns all associations.

#### `AddScopedRecord(ctx, scopeName, record) error`

Adds a DNS record within a specific network scope. Only visible to IPs associated with that scope.

**Path:** `/rolodex.RolodexService/AddScopedRecord`

**Parameters:**
- `scopeName` (string): The scope to add the record to
- `record` (`*DnsRecord`): The DNS record to add

#### `RemoveScopedRecord(ctx, scopeName, name, opts) (uint32, error)`

Removes DNS records from a specific network scope.

**Path:** `/rolodex.RolodexService/RemoveScopedRecord`

**Parameters:**
- `scopeName` (string): The scope to remove records from
- `name` (string): FQDN to remove records for
- `opts` (`*RemoveScopedRecordOptions`, optional): If nil, removes all records for the name
  - `RecordType` (`*RecordType`): Filter by record type
  - `Value` (string): Filter by exact value

**Returns:** Number of records removed.

#### `ListScopedRecords(ctx, scopeName, opts) ([]*DnsRecord, error)`

Queries DNS records within a network scope.

**Path:** `/rolodex.RolodexService/ListScopedRecords`

**Parameters:**
- `scopeName` (string): The scope to query
- `opts` (`*ListScopedRecordsOptions`, optional): If nil, returns all records in the scope
  - `NameFilter` (string): Filter by domain name (supports wildcard `"*."`)
  - `RecordType` (`*RecordType`): Filter by record type

#### `GetSearchDomains(ctx, ipAddress) ([]string, error)`

Retrieves the search domains for a client IP. Returns the `.home` domain of the associated scope.

**Path:** `/rolodex.RolodexService/GetSearchDomains`

**Parameters:**
- `ipAddress` (string): Client IP to look up

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

Resolution order (when no network scopes are configured):
1. Check RBL (for reverse DNS queries, if enabled)
2. Check local database (split-horizon, always preferred)
3. Check for CNAME records in local database
4. If name is under a managed zone but not found, return authoritative NXDOMAIN
5. Forward to upstream resolvers

When network scopes are configured, see [Network Scoping](#network-scoping) for the extended resolution order.

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See the [LICENSE](LICENSE) file for the full license text.
