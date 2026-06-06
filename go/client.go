// Package rolodexdns provides a Go client for the Rolodex DNS split-horizon DNS server's
// gRPC management API.
//
// The client supports two transport modes:
//   - TCP: connects to a "host:port" address with optional shared-secret authentication
//   - Unix socket: connects to a filesystem path, which bypasses server-side authentication
//
// # Usage
//
// Connect over TCP with authentication:
//
//	client, err := rolodexdns.Dial(ctx, "localhost:50051",
//	    rolodexdns.WithAuthToken("my-secret"),
//	)
//
// Connect over a Unix socket (authentication is bypassed server-side):
//
//	client, err := rolodexdns.Dial(ctx, "/var/run/rolodex-dns.sock",
//	    rolodexdns.WithUnixSocket(),
//	)
//
// All RPC methods accept a context.Context for cancellation and deadlines.
// Call [Client.Close] when finished to release the underlying gRPC connection.
package rolodexdns

import (
	"context"
	"fmt"
	"net"

	pb "gitea.com/town-os/rolodex-dns/go/rolodexdnspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// RecordType enumerates supported DNS record types.
// The zero value is RecordTypeA.
type RecordType = pb.RecordType

const (
	// RecordTypeA represents an IPv4 address record.
	RecordTypeA RecordType = pb.RecordType_A
	// RecordTypeAAAA represents an IPv6 address record.
	RecordTypeAAAA RecordType = pb.RecordType_AAAA
	// RecordTypeCNAME represents a canonical name alias record.
	RecordTypeCNAME RecordType = pb.RecordType_CNAME
	// RecordTypeMX represents a mail exchange record.
	RecordTypeMX RecordType = pb.RecordType_MX
	// RecordTypeTXT represents a text record.
	RecordTypeTXT RecordType = pb.RecordType_TXT
	// RecordTypeNS represents a name server record.
	RecordTypeNS RecordType = pb.RecordType_NS
	// RecordTypeSOA represents a start of authority record.
	RecordTypeSOA RecordType = pb.RecordType_SOA
	// RecordTypeSRV represents a service locator record.
	RecordTypeSRV RecordType = pb.RecordType_SRV
	// RecordTypePTR represents a pointer record for reverse DNS.
	RecordTypePTR RecordType = pb.RecordType_PTR
	// RecordTypeURI represents a URI resource record.
	RecordTypeURI RecordType = pb.RecordType_URI
	// RecordTypeSSHFP represents an SSH fingerprint record.
	RecordTypeSSHFP RecordType = pb.RecordType_SSHFP
	// RecordTypeDNAME represents a delegation name record.
	RecordTypeDNAME RecordType = pb.RecordType_DNAME
	// RecordTypeANAME represents an alias name record (auto-resolved CNAME at zone apex).
	RecordTypeANAME RecordType = pb.RecordType_ANAME
	// RecordTypeZONEMD represents a zone message digest record.
	RecordTypeZONEMD RecordType = pb.RecordType_ZONEMD
	// RecordTypeTLSA represents a TLSA certificate association record.
	RecordTypeTLSA RecordType = pb.RecordType_TLSA
	// RecordTypeDNSKEY represents a DNSSEC public key record.
	RecordTypeDNSKEY RecordType = pb.RecordType_DNSKEY
	// RecordTypeDS represents a DNSSEC delegation signer record.
	RecordTypeDS RecordType = pb.RecordType_DS
	// RecordTypeRRSIG represents a DNSSEC resource record signature.
	RecordTypeRRSIG RecordType = pb.RecordType_RRSIG
	// RecordTypeNSEC represents a DNSSEC next secure record.
	RecordTypeNSEC RecordType = pb.RecordType_NSEC
	// RecordTypeNSEC3 represents a DNSSEC next secure record version 3.
	RecordTypeNSEC3 RecordType = pb.RecordType_NSEC3
	// RecordTypeNSEC3PARAM represents a DNSSEC NSEC3 parameters record.
	RecordTypeNSEC3PARAM RecordType = pb.RecordType_NSEC3PARAM
)

// DnsRecord represents a DNS record managed by the Rolodex DNS server.
type DnsRecord = pb.DnsRecord

// RblConfig represents a single RBL (Realtime Blackhole List) provider configuration.
type RblConfig = pb.RblConfig

// CacheStats represents DNS cache statistics.
type CacheStats = pb.GetCacheStatsResponse

// TtlDriftConfig represents the TTL drift configuration.
type TtlDriftConfig = pb.TtlDriftConfig

// QueryLatencyStats represents per-server query latency statistics.
type QueryLatencyStats = pb.QueryLatencyStat

// LocalRblEntry represents a local RBL blocklist entry.
type LocalRblEntry = pb.LocalRblEntry

// DotConfig represents DNS-over-TLS configuration.
type DotConfig = pb.DotConfig

// DohConfig represents DNS-over-HTTPS configuration.
type DohConfig = pb.DohConfig

// DoqConfig represents DNS-over-QUIC configuration.
type DoqConfig = pb.DoqConfig

// TlsConfig represents TLS certificate configuration used by transport protocols.
type TlsConfig = pb.TlsConfig

// ProxyConfig represents DNS proxy transport configuration.
type ProxyConfig = pb.ProxyConfig

// DnssecKey represents a DNSSEC signing key.
type DnssecKey = pb.DnssecKey

// DsRecord is a string representation of a DS record for parent-zone delegation.
// Use [Client.GetDsRecords] to retrieve DS records for a zone.
type DsRecord = string

// TlsaRecord is a string representation of a TLSA record.
// Use [Client.GenerateTlsaRecord] to generate one.
type TlsaRecord = string

// DaneRootCa is a PEM-encoded root CA certificate generated for DANE.
// Use [Client.GenerateDaneRootCa] to generate one.
type DaneRootCa = string

// AcmeStatus represents the status of an ACME certificate.
type AcmeStatus = pb.GetAcmeStatusResponse

// Dns64Config represents DNS64 synthesis configuration.
type Dns64Config = pb.Dns64Config

// DhcpPool represents a DHCP address pool.
type DhcpPool = pb.DhcpPool

// DhcpLease represents a DHCP lease.
type DhcpLease = pb.DhcpLease

// ScopeRblProvider represents a per-scope RBL provider.
type ScopeRblProvider = pb.ScopeRblProvider

// DhcpCertOption represents a DHCP certificate option.
type DhcpCertOption = pb.DhcpCertOption

// Option configures a [Client] during [Dial].
type Option func(*clientConfig)

type clientConfig struct {
	authToken  string
	unixSocket bool
	dialOpts   []grpc.DialOption
}

// WithAuthToken sets the shared secret used for authentication on TCP connections.
// This token is sent with every RPC call. It is ignored by the server for Unix socket
// connections. If not set, an empty token is sent (which succeeds if the server has
// no shared secret configured).
func WithAuthToken(token string) Option {
	return func(c *clientConfig) {
		c.authToken = token
	}
}

// WithUnixSocket marks the target address as a Unix domain socket path.
// When set, the client connects via Unix socket instead of TCP.
// The server bypasses authentication for Unix socket connections.
func WithUnixSocket() Option {
	return func(c *clientConfig) {
		c.unixSocket = true
	}
}

// WithGRPCDialOption appends additional [grpc.DialOption] values to the
// underlying gRPC dial call. This can be used to configure TLS, interceptors,
// or other low-level gRPC settings.
func WithGRPCDialOption(opt grpc.DialOption) Option {
	return func(c *clientConfig) {
		c.dialOpts = append(c.dialOpts, opt)
	}
}

// Client provides high-level access to the Rolodex DNS gRPC management API.
// Create one with [Dial] and close it with [Client.Close] when finished.
type Client struct {
	conn      *grpc.ClientConn
	rpc       pb.RolodexDnsServiceClient
	authToken string
}

// Dial establishes a gRPC connection to a Rolodex DNS server and returns a [Client].
//
// The addr parameter specifies either:
//   - A TCP address in "host:port" format (e.g. "localhost:50051")
//   - A Unix socket path (e.g. "/var/run/rolodex-dns.sock") when [WithUnixSocket] is used
//
// Supported options:
//   - [WithAuthToken]: set the shared secret for TCP authentication
//   - [WithUnixSocket]: connect via Unix domain socket
//   - [WithGRPCDialOption]: pass additional gRPC dial options
//
// The returned Client must be closed with [Client.Close] when no longer needed.
func Dial(ctx context.Context, addr string, opts ...Option) (*Client, error) {
	cfg := &clientConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	dialOpts = append(dialOpts, cfg.dialOpts...)

	target := addr
	if cfg.unixSocket {
		dialOpts = append(dialOpts, grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", addr)
		}))
		target = "passthrough:///unix"
	}

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: dial %s: %w", addr, err)
	}

	return &Client{
		conn:      conn,
		rpc:       pb.NewRolodexDnsServiceClient(conn),
		authToken: cfg.authToken,
	}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// AddRecord adds a DNS record to the Rolodex DNS server's local database.
//
// Parameters:
//   - record: the DNS record to add (name, record_type, value are required;
//     ttl defaults to 300 if zero; priority is used only for MX and SRV records)
//
// Returns an error if the RPC fails or the server reports a failure.
//
// Remote API path: /rolodex_dns.RolodexDnsService/AddRecord
func (c *Client) AddRecord(ctx context.Context, record *DnsRecord) error {
	resp, err := c.rpc.AddRecord(ctx, &pb.AddRecordRequest{
		Record:    record,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: add record: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: add record: %s", resp.Message)
	}
	return nil
}

// RemoveRecordOptions configures which records to remove in [Client.RemoveRecord].
type RemoveRecordOptions struct {
	// RecordType filters removal to records of this type only.
	// If nil, all record types for the given name are removed.
	RecordType *RecordType
	// Value filters removal to the record with this exact value.
	// If empty, all matching records are removed.
	Value string
}

// RemoveRecord removes DNS records from the Rolodex DNS server's local database.
//
// Parameters:
//   - name: the fully qualified domain name to remove records for (e.g. "example.com.")
//   - opts: optional filters to narrow which records are removed. If nil, all records
//     for the given name are removed.
//
// Returns the number of records removed and any error.
//
// Remote API path: /rolodex_dns.RolodexDnsService/RemoveRecord
func (c *Client) RemoveRecord(ctx context.Context, name string, opts *RemoveRecordOptions) (uint32, error) {
	req := &pb.RemoveRecordRequest{
		Name:      name,
		AuthToken: c.authToken,
	}
	if opts != nil {
		if opts.RecordType != nil {
			req.RecordType = *opts.RecordType
		}
		req.Value = opts.Value
	}

	resp, err := c.rpc.RemoveRecord(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("rolodex-dns: remove record: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("rolodex-dns: remove record: %s", resp.Message)
	}
	return resp.RemovedCount, nil
}

// ListRecordsOptions configures filtering for [Client.ListRecords].
type ListRecordsOptions struct {
	// NameFilter filters results by domain name. Supports wildcard prefix "*."
	// to match all subdomains (e.g. "*.example.com."). If empty, no name filter
	// is applied.
	NameFilter string
	// RecordType filters results to records of this type only.
	// If nil, all record types are returned.
	RecordType *RecordType
}

// ListRecords queries the Rolodex DNS server's local DNS database.
//
// Parameters:
//   - opts: optional filters for name and/or record type. If nil, all records
//     are returned.
//
// Returns the matching DNS records and any error.
//
// Remote API path: /rolodex_dns.RolodexDnsService/ListRecords
func (c *Client) ListRecords(ctx context.Context, opts *ListRecordsOptions) ([]*DnsRecord, error) {
	req := &pb.ListRecordsRequest{
		AuthToken: c.authToken,
	}
	if opts != nil {
		req.NameFilter = opts.NameFilter
		if opts.RecordType != nil {
			req.RecordTypeFilter = *opts.RecordType
			req.FilterByType = true
		}
	}

	resp, err := c.rpc.ListRecords(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list records: %w", err)
	}
	return resp.Records, nil
}

// SetForwarders configures the upstream DNS forwarders on the Rolodex DNS server.
// Forwarders are specified as "host:port" strings (e.g. "8.8.8.8:53").
// This replaces the entire forwarder list.
//
// Parameters:
//   - forwarders: list of upstream DNS server addresses in "host:port" format
//
// Remote API path: /rolodex_dns.RolodexDnsService/SetForwarders
func (c *Client) SetForwarders(ctx context.Context, forwarders []string) error {
	resp, err := c.rpc.SetForwarders(ctx, &pb.SetForwarderRequest{
		Forwarders: forwarders,
		AuthToken:  c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: set forwarders: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: set forwarders: %s", resp.Message)
	}
	return nil
}

// SetRblConfig configures Realtime Blackhole List settings on the Rolodex DNS server.
// This replaces the entire RBL configuration.
//
// Parameters:
//   - enabled: whether RBL checking is globally enabled (default: false when first configured)
//   - providers: list of RBL provider configurations, each with a zone name and enabled flag
//
// Remote API path: /rolodex_dns.RolodexDnsService/SetRblConfig
func (c *Client) SetRblConfig(ctx context.Context, enabled bool, providers []*RblConfig) error {
	resp, err := c.rpc.SetRblConfig(ctx, &pb.SetRblConfigRequest{
		Enabled:   enabled,
		Providers: providers,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: set rbl config: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: set rbl config: %s", resp.Message)
	}
	return nil
}

// RblStatus holds the current RBL configuration returned by [Client.GetRblConfig].
type RblStatus struct {
	// Enabled indicates whether RBL checking is globally enabled.
	Enabled bool
	// Providers lists the configured RBL providers.
	Providers []*RblConfig
}

// GetRblConfig retrieves the current RBL configuration from the Rolodex DNS server.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetRblConfig
func (c *Client) GetRblConfig(ctx context.Context) (*RblStatus, error) {
	resp, err := c.rpc.GetRblConfig(ctx, &pb.GetRblConfigRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get rbl config: %w", err)
	}
	return &RblStatus{
		Enabled:   resp.Enabled,
		Providers: resp.Providers,
	}, nil
}

// FlushCache clears the RBL lookup cache on the Rolodex DNS server.
//
// Remote API path: /rolodex_dns.RolodexDnsService/FlushCache
func (c *Client) FlushCache(ctx context.Context) error {
	resp, err := c.rpc.FlushCache(ctx, &pb.FlushCacheRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: flush cache: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: flush cache: %s", resp.Message)
	}
	return nil
}

// NetworkScope represents a DNS view that groups records and IP associations.
type NetworkScope = pb.NetworkScope

// NetworkAssociation represents a client IP's membership in a network scope.
type NetworkAssociation = pb.NetworkAssociation

// CreateNetworkScope creates a new network scope on the Rolodex DNS server.
//
// Each scope has a unique name and a reserved .home domain that serves
// as the default search domain for DNS clients in that network.
//
// Parameters:
//   - scope: the network scope to create. If HomeDomain is empty, it defaults
//     to "<name>.home" (e.g. "office" becomes "office.home").
//
// Remote API path: /rolodex_dns.RolodexDnsService/CreateNetworkScope
func (c *Client) CreateNetworkScope(ctx context.Context, scope *NetworkScope) error {
	resp, err := c.rpc.CreateNetworkScope(ctx, &pb.CreateNetworkScopeRequest{
		Scope:     scope,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: create network scope: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: create network scope: %s", resp.Message)
	}
	return nil
}

// DeleteNetworkScope removes a network scope and all its records and associations.
//
// Parameters:
//   - name: the unique name of the scope to delete
//
// Remote API path: /rolodex_dns.RolodexDnsService/DeleteNetworkScope
func (c *Client) DeleteNetworkScope(ctx context.Context, name string) error {
	resp, err := c.rpc.DeleteNetworkScope(ctx, &pb.DeleteNetworkScopeRequest{
		Name:      name,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: delete network scope: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: delete network scope: %s", resp.Message)
	}
	return nil
}

// ListNetworkScopes retrieves all configured network scopes.
//
// Remote API path: /rolodex_dns.RolodexDnsService/ListNetworkScopes
func (c *Client) ListNetworkScopes(ctx context.Context) ([]*NetworkScope, error) {
	resp, err := c.rpc.ListNetworkScopes(ctx, &pb.ListNetworkScopesRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list network scopes: %w", err)
	}
	return resp.Scopes, nil
}

// JoinNetwork associates a client IP address with a network scope.
//
// The association has a TTL that must be refreshed regularly to maintain
// DNS resolution capability. If the TTL expires, the DNS server stops
// resolving queries from this IP.
//
// Parameters:
//   - ipAddress: the client IP to associate (e.g. "192.168.1.100")
//   - scopeName: the network scope name to join
//   - ttlSeconds: TTL in seconds for this association (0 defaults to 300)
//
// Remote API path: /rolodex_dns.RolodexDnsService/JoinNetwork
func (c *Client) JoinNetwork(ctx context.Context, ipAddress, scopeName string, ttlSeconds uint64) error {
	resp, err := c.rpc.JoinNetwork(ctx, &pb.JoinNetworkRequest{
		IpAddress:  ipAddress,
		ScopeName:  scopeName,
		TtlSeconds: ttlSeconds,
		AuthToken:  c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: join network: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: join network: %s", resp.Message)
	}
	return nil
}

// LeaveNetwork removes an IP address's association with its network scope.
//
// Parameters:
//   - ipAddress: the client IP to disassociate
//
// Remote API path: /rolodex_dns.RolodexDnsService/LeaveNetwork
func (c *Client) LeaveNetwork(ctx context.Context, ipAddress string) error {
	resp, err := c.rpc.LeaveNetwork(ctx, &pb.LeaveNetworkRequest{
		IpAddress: ipAddress,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: leave network: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: leave network: %s", resp.Message)
	}
	return nil
}

// GetNetworkAssociations retrieves IP-to-scope associations.
//
// Parameters:
//   - scopeName: if non-empty, only return associations for this scope.
//     If empty, returns all associations.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetNetworkAssociations
func (c *Client) GetNetworkAssociations(ctx context.Context, scopeName string) ([]*NetworkAssociation, error) {
	resp, err := c.rpc.GetNetworkAssociations(ctx, &pb.GetNetworkAssociationsRequest{
		ScopeName: scopeName,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get network associations: %w", err)
	}
	return resp.Associations, nil
}

// AddScopedRecord adds a DNS record within a specific network scope.
// Scoped records are only visible to IPs associated with that scope.
//
// Parameters:
//   - scopeName: the network scope to add the record to
//   - record: the DNS record to add
//
// Remote API path: /rolodex_dns.RolodexDnsService/AddScopedRecord
func (c *Client) AddScopedRecord(ctx context.Context, scopeName string, record *DnsRecord) error {
	resp, err := c.rpc.AddScopedRecord(ctx, &pb.AddScopedRecordRequest{
		ScopeName: scopeName,
		Record:    record,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: add scoped record: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: add scoped record: %s", resp.Message)
	}
	return nil
}

// RemoveScopedRecordOptions configures which scoped records to remove.
type RemoveScopedRecordOptions struct {
	// RecordType filters removal to records of this type only.
	// If nil, all record types for the given name are removed.
	RecordType *RecordType
	// Value filters removal to the record with this exact value.
	// If empty, all matching records are removed.
	Value string
}

// RemoveScopedRecord removes DNS records from a specific network scope.
//
// Parameters:
//   - scopeName: the network scope to remove records from
//   - name: the FQDN to remove records for
//   - opts: optional filters. If nil, all records for the name are removed.
//
// Returns the number of records removed and any error.
//
// Remote API path: /rolodex_dns.RolodexDnsService/RemoveScopedRecord
func (c *Client) RemoveScopedRecord(ctx context.Context, scopeName, name string, opts *RemoveScopedRecordOptions) (uint32, error) {
	req := &pb.RemoveScopedRecordRequest{
		ScopeName: scopeName,
		Name:      name,
		AuthToken: c.authToken,
	}
	if opts != nil {
		if opts.RecordType != nil {
			req.RecordType = *opts.RecordType
		}
		req.Value = opts.Value
	}

	resp, err := c.rpc.RemoveScopedRecord(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("rolodex-dns: remove scoped record: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("rolodex-dns: remove scoped record: %s", resp.Message)
	}
	return resp.RemovedCount, nil
}

// ListScopedRecordsOptions configures filtering for scoped record queries.
type ListScopedRecordsOptions struct {
	// NameFilter filters by domain name. Supports wildcard prefix "*.".
	NameFilter string
	// RecordType filters to records of this type only.
	RecordType *RecordType
}

// ListScopedRecords queries DNS records within a network scope.
//
// Parameters:
//   - scopeName: the network scope to query
//   - opts: optional filters. If nil, all records in the scope are returned.
//
// Remote API path: /rolodex_dns.RolodexDnsService/ListScopedRecords
func (c *Client) ListScopedRecords(ctx context.Context, scopeName string, opts *ListScopedRecordsOptions) ([]*DnsRecord, error) {
	req := &pb.ListScopedRecordsRequest{
		ScopeName: scopeName,
		AuthToken: c.authToken,
	}
	if opts != nil {
		req.NameFilter = opts.NameFilter
		if opts.RecordType != nil {
			req.RecordTypeFilter = *opts.RecordType
			req.FilterByType = true
		}
	}

	resp, err := c.rpc.ListScopedRecords(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list scoped records: %w", err)
	}
	return resp.Records, nil
}

// GetSearchDomains retrieves the search domains for a client IP address.
// Returns the .home domain of the scope the IP is associated with, which
// can be used as the default search domain for DHCP clients.
//
// Parameters:
//   - ipAddress: the client IP to look up search domains for
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetSearchDomains
func (c *Client) GetSearchDomains(ctx context.Context, ipAddress string) ([]string, error) {
	resp, err := c.rpc.GetSearchDomains(ctx, &pb.GetSearchDomainsRequest{
		IpAddress: ipAddress,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get search domains: %w", err)
	}
	return resp.SearchDomains, nil
}

// AddAuthoritativeZone registers a zone as authoritative on the Rolodex DNS server.
// Queries for names within authoritative zones will not be forwarded upstream.
//
// Parameters:
//   - zone: the zone name (e.g. "example.com.")
//
// Remote API path: /rolodex_dns.RolodexDnsService/AddAuthoritativeZone
func (c *Client) AddAuthoritativeZone(ctx context.Context, zone string) error {
	resp, err := c.rpc.AddAuthoritativeZone(ctx, &pb.AddAuthoritativeZoneRequest{
		Zone:      zone,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: add authoritative zone: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: add authoritative zone: %s", resp.Message)
	}
	return nil
}

// RemoveAuthoritativeZone removes a zone from the authoritative zone list.
//
// Parameters:
//   - zone: the zone name to remove (e.g. "example.com.")
//
// Remote API path: /rolodex_dns.RolodexDnsService/RemoveAuthoritativeZone
func (c *Client) RemoveAuthoritativeZone(ctx context.Context, zone string) error {
	resp, err := c.rpc.RemoveAuthoritativeZone(ctx, &pb.RemoveAuthoritativeZoneRequest{
		Zone:      zone,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: remove authoritative zone: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: remove authoritative zone: %s", resp.Message)
	}
	return nil
}

// ListAuthoritativeZones retrieves all authoritative zone names.
//
// Remote API path: /rolodex_dns.RolodexDnsService/ListAuthoritativeZones
func (c *Client) ListAuthoritativeZones(ctx context.Context) ([]string, error) {
	resp, err := c.rpc.ListAuthoritativeZones(ctx, &pb.ListAuthoritativeZonesRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list authoritative zones: %w", err)
	}
	return resp.Zones, nil
}

// GetCacheStats retrieves DNS cache statistics from the Rolodex DNS server.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetCacheStats
func (c *Client) GetCacheStats(ctx context.Context) (*CacheStats, error) {
	resp, err := c.rpc.GetCacheStats(ctx, &pb.GetCacheStatsRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get cache stats: %w", err)
	}
	return resp, nil
}

// FlushDnsCache clears the DNS record cache on the Rolodex DNS server.
//
// Remote API path: /rolodex_dns.RolodexDnsService/FlushDnsCache
func (c *Client) FlushDnsCache(ctx context.Context) error {
	resp, err := c.rpc.FlushDnsCache(ctx, &pb.FlushDnsCacheRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: flush dns cache: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: flush dns cache: %s", resp.Message)
	}
	return nil
}

// SetTtlDriftConfig configures TTL drift adjustment on the Rolodex DNS server.
// TTL drift modifies cached record TTLs to reduce thundering-herd cache
// expiration storms.
//
// Parameters:
//   - config: the TTL drift configuration (mode, fixed_adjustment, log_multiplier)
//
// Remote API path: /rolodex_dns.RolodexDnsService/SetTtlDriftConfig
func (c *Client) SetTtlDriftConfig(ctx context.Context, config *TtlDriftConfig) error {
	resp, err := c.rpc.SetTtlDriftConfig(ctx, &pb.SetTtlDriftConfigRequest{
		Config:    config,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: set ttl drift config: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: set ttl drift config: %s", resp.Message)
	}
	return nil
}

// GetTtlDriftConfig retrieves the current TTL drift configuration.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetTtlDriftConfig
func (c *Client) GetTtlDriftConfig(ctx context.Context) (*TtlDriftConfig, error) {
	resp, err := c.rpc.GetTtlDriftConfig(ctx, &pb.GetTtlDriftConfigRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get ttl drift config: %w", err)
	}
	return resp.Config, nil
}

// GetQueryLatencyStats retrieves per-server query latency statistics.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetQueryLatencyStats
func (c *Client) GetQueryLatencyStats(ctx context.Context) ([]*QueryLatencyStats, error) {
	resp, err := c.rpc.GetQueryLatencyStats(ctx, &pb.GetQueryLatencyStatsRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get query latency stats: %w", err)
	}
	return resp.Stats, nil
}

// AddLocalRblEntry adds an entry to the local RBL blocklist.
//
// Parameters:
//   - entry: the local RBL entry to add (name and reason)
//
// Remote API path: /rolodex_dns.RolodexDnsService/AddLocalRblEntry
func (c *Client) AddLocalRblEntry(ctx context.Context, entry *LocalRblEntry) error {
	resp, err := c.rpc.AddLocalRblEntry(ctx, &pb.AddLocalRblEntryRequest{
		Entry:     entry,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: add local rbl entry: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: add local rbl entry: %s", resp.Message)
	}
	return nil
}

// RemoveLocalRblEntry removes an entry from the local RBL blocklist.
//
// Parameters:
//   - name: the name or IP to unblock
//
// Remote API path: /rolodex_dns.RolodexDnsService/RemoveLocalRblEntry
func (c *Client) RemoveLocalRblEntry(ctx context.Context, name string) error {
	resp, err := c.rpc.RemoveLocalRblEntry(ctx, &pb.RemoveLocalRblEntryRequest{
		Name:      name,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: remove local rbl entry: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: remove local rbl entry: %s", resp.Message)
	}
	return nil
}

// ListLocalRblEntries retrieves all entries in the local RBL blocklist.
//
// Remote API path: /rolodex_dns.RolodexDnsService/ListLocalRblEntries
func (c *Client) ListLocalRblEntries(ctx context.Context) ([]*LocalRblEntry, error) {
	resp, err := c.rpc.ListLocalRblEntries(ctx, &pb.ListLocalRblEntriesRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list local rbl entries: %w", err)
	}
	return resp.Entries, nil
}

// SetDotConfig configures DNS-over-TLS settings on the Rolodex DNS server.
//
// Parameters:
//   - config: the DoT configuration (bind address and TLS settings)
//
// Remote API path: /rolodex_dns.RolodexDnsService/SetDotConfig
func (c *Client) SetDotConfig(ctx context.Context, config *DotConfig) error {
	resp, err := c.rpc.SetDotConfig(ctx, &pb.SetDotConfigRequest{
		Config:    config,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: set dot config: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: set dot config: %s", resp.Message)
	}
	return nil
}

// GetDotConfig retrieves the current DNS-over-TLS configuration.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetDotConfig
func (c *Client) GetDotConfig(ctx context.Context) (*DotConfig, error) {
	resp, err := c.rpc.GetDotConfig(ctx, &pb.GetDotConfigRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get dot config: %w", err)
	}
	return resp.Config, nil
}

// SetDohConfig configures DNS-over-HTTPS settings on the Rolodex DNS server.
//
// Parameters:
//   - config: the DoH configuration (bind address, TLS settings, HTTP/3 support)
//
// Remote API path: /rolodex_dns.RolodexDnsService/SetDohConfig
func (c *Client) SetDohConfig(ctx context.Context, config *DohConfig) error {
	resp, err := c.rpc.SetDohConfig(ctx, &pb.SetDohConfigRequest{
		Config:    config,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: set doh config: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: set doh config: %s", resp.Message)
	}
	return nil
}

// GetDohConfig retrieves the current DNS-over-HTTPS configuration.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetDohConfig
func (c *Client) GetDohConfig(ctx context.Context) (*DohConfig, error) {
	resp, err := c.rpc.GetDohConfig(ctx, &pb.GetDohConfigRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get doh config: %w", err)
	}
	return resp.Config, nil
}

// SetDoqConfig configures DNS-over-QUIC settings on the Rolodex DNS server.
//
// Parameters:
//   - config: the DoQ configuration (bind address and TLS settings)
//
// Remote API path: /rolodex_dns.RolodexDnsService/SetDoqConfig
func (c *Client) SetDoqConfig(ctx context.Context, config *DoqConfig) error {
	resp, err := c.rpc.SetDoqConfig(ctx, &pb.SetDoqConfigRequest{
		Config:    config,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: set doq config: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: set doq config: %s", resp.Message)
	}
	return nil
}

// GetDoqConfig retrieves the current DNS-over-QUIC configuration.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetDoqConfig
func (c *Client) GetDoqConfig(ctx context.Context) (*DoqConfig, error) {
	resp, err := c.rpc.GetDoqConfig(ctx, &pb.GetDoqConfigRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get doq config: %w", err)
	}
	return resp.Config, nil
}

// SetProxyConfig configures DNS proxy transport settings on the Rolodex DNS server.
//
// Parameters:
//   - config: the proxy configuration (URL, authentication, mode)
//
// Remote API path: /rolodex_dns.RolodexDnsService/SetProxyConfig
func (c *Client) SetProxyConfig(ctx context.Context, config *ProxyConfig) error {
	resp, err := c.rpc.SetProxyConfig(ctx, &pb.SetProxyConfigRequest{
		Config:    config,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: set proxy config: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: set proxy config: %s", resp.Message)
	}
	return nil
}

// GetProxyConfig retrieves the current DNS proxy transport configuration.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetProxyConfig
func (c *Client) GetProxyConfig(ctx context.Context) (*ProxyConfig, error) {
	resp, err := c.rpc.GetProxyConfig(ctx, &pb.GetProxyConfigRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get proxy config: %w", err)
	}
	return resp.Config, nil
}

// GenerateDnssecKey generates a new DNSSEC signing key for a zone.
//
// Parameters:
//   - zone: the zone to generate the key for (e.g. "example.com.")
//   - algorithm: the DNSSEC algorithm (e.g. "ECDSAP256SHA256")
//   - keyType: the key type ("KSK" or "ZSK")
//
// Returns the generated key and any error.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GenerateDnssecKey
func (c *Client) GenerateDnssecKey(ctx context.Context, zone, algorithm, keyType string) (*DnssecKey, error) {
	resp, err := c.rpc.GenerateDnssecKey(ctx, &pb.GenerateDnssecKeyRequest{
		Zone:      zone,
		Algorithm: algorithm,
		KeyType:   keyType,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: generate dnssec key: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("rolodex-dns: generate dnssec key: %s", resp.Message)
	}
	return resp.Key, nil
}

// ListDnssecKeys retrieves all DNSSEC keys for a zone.
//
// Parameters:
//   - zone: the zone to list keys for (e.g. "example.com.")
//
// Remote API path: /rolodex_dns.RolodexDnsService/ListDnssecKeys
func (c *Client) ListDnssecKeys(ctx context.Context, zone string) ([]*DnssecKey, error) {
	resp, err := c.rpc.ListDnssecKeys(ctx, &pb.ListDnssecKeysRequest{
		Zone:      zone,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list dnssec keys: %w", err)
	}
	return resp.Keys, nil
}

// DeleteDnssecKey removes a DNSSEC key by its ID.
//
// Parameters:
//   - keyID: the numeric ID of the key to delete
//
// Remote API path: /rolodex_dns.RolodexDnsService/DeleteDnssecKey
func (c *Client) DeleteDnssecKey(ctx context.Context, keyID int64) error {
	resp, err := c.rpc.DeleteDnssecKey(ctx, &pb.DeleteDnssecKeyRequest{
		KeyId:     keyID,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: delete dnssec key: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: delete dnssec key: %s", resp.Message)
	}
	return nil
}

// GetDsRecords retrieves the DS (Delegation Signer) records for a zone.
// These records are submitted to the parent zone registrar for DNSSEC chain of trust.
//
// Parameters:
//   - zone: the zone to get DS records for (e.g. "example.com.")
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetDsRecords
func (c *Client) GetDsRecords(ctx context.Context, zone string) ([]string, error) {
	resp, err := c.rpc.GetDsRecords(ctx, &pb.GetDsRecordsRequest{
		Zone:      zone,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get ds records: %w", err)
	}
	return resp.DsRecords, nil
}

// SignZone signs (or re-signs) all records in a zone with its DNSSEC keys.
//
// Parameters:
//   - zone: the zone to sign (e.g. "example.com.")
//
// Remote API path: /rolodex_dns.RolodexDnsService/SignZone
func (c *Client) SignZone(ctx context.Context, zone string) error {
	resp, err := c.rpc.SignZone(ctx, &pb.SignZoneRequest{
		Zone:      zone,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: sign zone: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: sign zone: %s", resp.Message)
	}
	return nil
}

// GenerateTlsaRecordOptions configures TLSA record generation parameters.
type GenerateTlsaRecordOptions struct {
	// Domain is the FQDN for the TLSA record.
	Domain string
	// Port is the TCP/UDP port number.
	Port uint32
	// Protocol is the transport protocol (e.g. "tcp").
	Protocol string
	// Usage is the TLSA certificate usage field (0-3).
	Usage uint32
	// Selector is the TLSA selector field (0-1).
	Selector uint32
	// MatchingType is the TLSA matching type field (0-2).
	MatchingType uint32
	// CertPem is the PEM-encoded certificate to generate the TLSA record from.
	CertPem string
}

// GenerateTlsaRecord generates a TLSA record for DANE certificate association.
//
// Parameters:
//   - opts: the TLSA record generation parameters
//
// Returns the generated TLSA record string and any error.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GenerateTlsaRecord
func (c *Client) GenerateTlsaRecord(ctx context.Context, opts *GenerateTlsaRecordOptions) (string, error) {
	resp, err := c.rpc.GenerateTlsaRecord(ctx, &pb.GenerateTlsaRecordRequest{
		Domain:       opts.Domain,
		Port:         opts.Port,
		Protocol:     opts.Protocol,
		Usage:        opts.Usage,
		Selector:     opts.Selector,
		MatchingType: opts.MatchingType,
		CertPem:      opts.CertPem,
		AuthToken:    c.authToken,
	})
	if err != nil {
		return "", fmt.Errorf("rolodex-dns: generate tlsa record: %w", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("rolodex-dns: generate tlsa record: %s", resp.Message)
	}
	return resp.TlsaRecord, nil
}

// ListTlsaRecords retrieves all TLSA DNS records for a domain.
//
// Parameters:
//   - domain: the domain to list TLSA records for
//
// Remote API path: /rolodex_dns.RolodexDnsService/ListTlsaRecords
func (c *Client) ListTlsaRecords(ctx context.Context, domain string) ([]*DnsRecord, error) {
	resp, err := c.rpc.ListTlsaRecords(ctx, &pb.ListTlsaRecordsRequest{
		Domain:    domain,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list tlsa records: %w", err)
	}
	return resp.Records, nil
}

// GenerateDaneRootCa generates a root CA certificate for DANE usage.
//
// Parameters:
//   - name: the common name for the root CA certificate
//
// Returns the PEM-encoded root CA certificate and any error.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GenerateDaneRootCa
func (c *Client) GenerateDaneRootCa(ctx context.Context, name string) (string, error) {
	resp, err := c.rpc.GenerateDaneRootCa(ctx, &pb.GenerateDaneRootCaRequest{
		Name:      name,
		AuthToken: c.authToken,
	})
	if err != nil {
		return "", fmt.Errorf("rolodex-dns: generate dane root ca: %w", err)
	}
	if !resp.Success {
		return "", fmt.Errorf("rolodex-dns: generate dane root ca: %s", resp.Message)
	}
	return resp.CertPem, nil
}

// RequestAcmeCert requests an ACME certificate for a domain using DNS-01 validation.
//
// Parameters:
//   - domain: the domain to request a certificate for
//   - providerURL: the ACME provider URL (e.g. Let's Encrypt directory URL)
//
// Remote API path: /rolodex_dns.RolodexDnsService/RequestAcmeCert
func (c *Client) RequestAcmeCert(ctx context.Context, domain, providerURL string) error {
	resp, err := c.rpc.RequestAcmeCert(ctx, &pb.RequestAcmeCertRequest{
		Domain:      domain,
		ProviderUrl: providerURL,
		AuthToken:   c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: request acme cert: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: request acme cert: %s", resp.Message)
	}
	return nil
}

// GetAcmeStatus retrieves the ACME certificate status for a domain.
//
// Parameters:
//   - domain: the domain to check ACME status for
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetAcmeStatus
func (c *Client) GetAcmeStatus(ctx context.Context, domain string) (*AcmeStatus, error) {
	resp, err := c.rpc.GetAcmeStatus(ctx, &pb.GetAcmeStatusRequest{
		Domain:    domain,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get acme status: %w", err)
	}
	return resp, nil
}

// SetDns64Config configures DNS64 synthesis on the Rolodex DNS server.
// DNS64 synthesizes AAAA records from A records for IPv6-only clients.
//
// Parameters:
//   - config: the DNS64 configuration (enabled flag and IPv6 prefix)
//
// Remote API path: /rolodex_dns.RolodexDnsService/SetDns64Config
func (c *Client) SetDns64Config(ctx context.Context, config *Dns64Config) error {
	resp, err := c.rpc.SetDns64Config(ctx, &pb.SetDns64ConfigRequest{
		Config:    config,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: set dns64 config: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: set dns64 config: %s", resp.Message)
	}
	return nil
}

// GetDns64Config retrieves the current DNS64 configuration.
//
// Remote API path: /rolodex_dns.RolodexDnsService/GetDns64Config
func (c *Client) GetDns64Config(ctx context.Context) (*Dns64Config, error) {
	resp, err := c.rpc.GetDns64Config(ctx, &pb.GetDns64ConfigRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: get dns64 config: %w", err)
	}
	return resp.Config, nil
}

// AddDhcpPool adds an IP address pool for DHCP allocation within a scope.
//
// Parameters:
//   - pool: the DHCP pool to add
//
// Remote API path: /rolodex_dns.RolodexDnsService/AddDhcpPool
func (c *Client) AddDhcpPool(ctx context.Context, pool *DhcpPool) error {
	resp, err := c.rpc.AddDhcpPool(ctx, &pb.AddDhcpPoolRequest{
		Pool:      pool,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: add dhcp pool: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: add dhcp pool: %s", resp.Message)
	}
	return nil
}

// RemoveDhcpPool removes a DHCP address pool by ID.
//
// Parameters:
//   - poolID: the numeric ID of the pool to remove
//
// Remote API path: /rolodex_dns.RolodexDnsService/RemoveDhcpPool
func (c *Client) RemoveDhcpPool(ctx context.Context, poolID int64) error {
	resp, err := c.rpc.RemoveDhcpPool(ctx, &pb.RemoveDhcpPoolRequest{
		PoolId:    poolID,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: remove dhcp pool: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: remove dhcp pool: %s", resp.Message)
	}
	return nil
}

// ListDhcpPools lists DHCP address pools, optionally filtered by scope.
//
// Parameters:
//   - scopeName: if non-empty, only return pools for this scope.
//     If empty, returns all pools.
//
// Remote API path: /rolodex_dns.RolodexDnsService/ListDhcpPools
func (c *Client) ListDhcpPools(ctx context.Context, scopeName string) ([]*DhcpPool, error) {
	resp, err := c.rpc.ListDhcpPools(ctx, &pb.ListDhcpPoolsRequest{
		ScopeName: scopeName,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list dhcp pools: %w", err)
	}
	return resp.Pools, nil
}

// ListDhcpLeases lists DHCP leases, optionally filtered by scope.
//
// Parameters:
//   - scopeName: if non-empty, only return leases for this scope.
//     If empty, returns all leases.
//
// Remote API path: /rolodex_dns.RolodexDnsService/ListDhcpLeases
func (c *Client) ListDhcpLeases(ctx context.Context, scopeName string) ([]*DhcpLease, error) {
	resp, err := c.rpc.ListDhcpLeases(ctx, &pb.ListDhcpLeasesRequest{
		ScopeName: scopeName,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list dhcp leases: %w", err)
	}
	return resp.Leases, nil
}

// DeleteDhcpLease deletes a DHCP lease by MAC address.
//
// Parameters:
//   - mac: the MAC address of the lease to delete
//
// Remote API path: /rolodex_dns.RolodexDnsService/DeleteDhcpLease
func (c *Client) DeleteDhcpLease(ctx context.Context, mac string) error {
	resp, err := c.rpc.DeleteDhcpLease(ctx, &pb.DeleteDhcpLeaseRequest{
		Mac:       mac,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: delete dhcp lease: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: delete dhcp lease: %s", resp.Message)
	}
	return nil
}

// AddScopeRblProvider adds an additional RBL provider for a specific scope.
//
// Parameters:
//   - scopeName: the network scope name
//   - zone: the RBL zone (e.g. "zen.spamhaus.org")
//   - enabled: whether the provider is enabled
//
// Remote API path: /rolodex_dns.RolodexDnsService/AddScopeRblProvider
func (c *Client) AddScopeRblProvider(ctx context.Context, scopeName, zone string, enabled bool) error {
	resp, err := c.rpc.AddScopeRblProvider(ctx, &pb.AddScopeRblProviderRequest{
		Provider: &pb.ScopeRblProvider{
			ScopeName: scopeName,
			Zone:      zone,
			Enabled:   enabled,
		},
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: add scope rbl provider: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: add scope rbl provider: %s", resp.Message)
	}
	return nil
}

// RemoveScopeRblProvider removes a scope-specific RBL provider.
//
// Parameters:
//   - scopeName: the network scope name
//   - zone: the RBL zone to remove
//
// Remote API path: /rolodex_dns.RolodexDnsService/RemoveScopeRblProvider
func (c *Client) RemoveScopeRblProvider(ctx context.Context, scopeName, zone string) error {
	resp, err := c.rpc.RemoveScopeRblProvider(ctx, &pb.RemoveScopeRblProviderRequest{
		ScopeName: scopeName,
		Zone:      zone,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: remove scope rbl provider: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: remove scope rbl provider: %s", resp.Message)
	}
	return nil
}

// ListScopeRblProviders lists RBL providers for a specific scope.
//
// Parameters:
//   - scopeName: the network scope name to list providers for
//
// Remote API path: /rolodex_dns.RolodexDnsService/ListScopeRblProviders
func (c *Client) ListScopeRblProviders(ctx context.Context, scopeName string) ([]*ScopeRblProvider, error) {
	resp, err := c.rpc.ListScopeRblProviders(ctx, &pb.ListScopeRblProvidersRequest{
		ScopeName: scopeName,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list scope rbl providers: %w", err)
	}
	return resp.Providers, nil
}

// SetDhcpCertOption sets a certificate to be delivered via DHCP for a scope.
//
// Parameters:
//   - opt: the DHCP certificate option to set
//
// Remote API path: /rolodex_dns.RolodexDnsService/SetDhcpCertOption
func (c *Client) SetDhcpCertOption(ctx context.Context, opt *DhcpCertOption) error {
	resp, err := c.rpc.SetDhcpCertOption(ctx, &pb.SetDhcpCertOptionRequest{
		Option:    opt,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: set dhcp cert option: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: set dhcp cert option: %s", resp.Message)
	}
	return nil
}

// RemoveDhcpCertOption removes a DHCP certificate option for a scope.
//
// Parameters:
//   - scopeName: the network scope name
//   - optionCode: the DHCP option code to remove
//
// Remote API path: /rolodex_dns.RolodexDnsService/RemoveDhcpCertOption
func (c *Client) RemoveDhcpCertOption(ctx context.Context, scopeName string, optionCode uint32) error {
	resp, err := c.rpc.RemoveDhcpCertOption(ctx, &pb.RemoveDhcpCertOptionRequest{
		ScopeName:  scopeName,
		OptionCode: optionCode,
		AuthToken:  c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: remove dhcp cert option: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: remove dhcp cert option: %s", resp.Message)
	}
	return nil
}

// ListDhcpCertOptions lists DHCP certificate options for a scope.
//
// Parameters:
//   - scopeName: the network scope name to list options for
//
// Remote API path: /rolodex_dns.RolodexDnsService/ListDhcpCertOptions
func (c *Client) ListDhcpCertOptions(ctx context.Context, scopeName string) ([]*DhcpCertOption, error) {
	resp, err := c.rpc.ListDhcpCertOptions(ctx, &pb.ListDhcpCertOptionsRequest{
		ScopeName: scopeName,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list dhcp cert options: %w", err)
	}
	return resp.Options, nil
}

// ============================================================================
// ACME Issuer (CA) Administration
// ============================================================================

// ZoneCa holds the root and intermediate CA certificates for a zone.
type ZoneCa struct {
	RootCAPEM         string
	IntermediateCAPEM string
}

// EabCredential is an External Account Binding credential for ACME clients.
type EabCredential struct {
	Kid          string
	HmacKey      string // base64url-encoded
	DirectoryURL string
}

// AcmeAccount describes a registered ACME server account.
type AcmeAccount struct {
	AccountID string
	Status    string
	Zone      string
	EabKid    string
}

// AcmeCertificate describes an issued ACME certificate.
type AcmeCertificate struct {
	ID        int64
	Domain    string
	IssuedAt  int64
	ExpiresAt int64
}

// EnsureZoneCa creates the per-zone intermediate CA if absent and returns the
// root + intermediate certificates.
func (c *Client) EnsureZoneCa(ctx context.Context, zone string) (*ZoneCa, error) {
	resp, err := c.rpc.EnsureZoneCa(ctx, &pb.EnsureZoneCaRequest{
		Zone:      zone,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: ensure zone ca: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("rolodex-dns: ensure zone ca: %s", resp.Message)
	}
	return &ZoneCa{RootCAPEM: resp.RootCaPem, IntermediateCAPEM: resp.IntermediateCaPem}, nil
}

// CreateEabCredential mints an EAB credential scoped to a zone.
func (c *Client) CreateEabCredential(ctx context.Context, zone string) (*EabCredential, error) {
	resp, err := c.rpc.CreateEabCredential(ctx, &pb.CreateEabCredentialRequest{
		Zone:      zone,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: create eab credential: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("rolodex-dns: create eab credential: %s", resp.Message)
	}
	return &EabCredential{Kid: resp.Kid, HmacKey: resp.HmacKey, DirectoryURL: resp.DirectoryUrl}, nil
}

// RemoveEabCredential removes an EAB credential by key id.
func (c *Client) RemoveEabCredential(ctx context.Context, kid string) error {
	resp, err := c.rpc.RemoveEabCredential(ctx, &pb.RemoveEabCredentialRequest{
		Kid:       kid,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex-dns: remove eab credential: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex-dns: remove eab credential: %s", resp.Message)
	}
	return nil
}

// ListAcmeAccounts lists registered ACME server accounts.
func (c *Client) ListAcmeAccounts(ctx context.Context) ([]*AcmeAccount, error) {
	resp, err := c.rpc.ListAcmeAccounts(ctx, &pb.ListAcmeAccountsRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list acme accounts: %w", err)
	}
	out := make([]*AcmeAccount, 0, len(resp.Accounts))
	for _, a := range resp.Accounts {
		out = append(out, &AcmeAccount{
			AccountID: a.AccountId,
			Status:    a.Status,
			Zone:      a.Zone,
			EabKid:    a.EabKid,
		})
	}
	return out, nil
}

// ListAcmeCertificates lists issued certificates, optionally filtered by zone.
func (c *Client) ListAcmeCertificates(ctx context.Context, zone string) ([]*AcmeCertificate, error) {
	resp, err := c.rpc.ListAcmeCertificates(ctx, &pb.ListAcmeCertificatesRequest{
		Zone:      zone,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex-dns: list acme certificates: %w", err)
	}
	out := make([]*AcmeCertificate, 0, len(resp.Certificates))
	for _, cert := range resp.Certificates {
		out = append(out, &AcmeCertificate{
			ID:        cert.Id,
			Domain:    cert.Domain,
			IssuedAt:  cert.IssuedAt,
			ExpiresAt: cert.ExpiresAt,
		})
	}
	return out, nil
}
