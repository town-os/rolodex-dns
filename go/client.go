// Package rolodex provides a Go client for the Rolodex split-horizon DNS server's
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
//	client, err := rolodex.Dial(ctx, "localhost:50051",
//	    rolodex.WithAuthToken("my-secret"),
//	)
//
// Connect over a Unix socket (authentication is bypassed server-side):
//
//	client, err := rolodex.Dial(ctx, "/var/run/rolodex.sock",
//	    rolodex.WithUnixSocket(),
//	)
//
// All RPC methods accept a context.Context for cancellation and deadlines.
// Call [Client.Close] when finished to release the underlying gRPC connection.
package rolodex

import (
	"context"
	"fmt"
	"net"

	pb "github.com/erikh/rolodex/go/rolodexpb"
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
)

// DnsRecord represents a DNS record managed by the Rolodex server.
type DnsRecord = pb.DnsRecord

// RblConfig represents a single RBL (Realtime Blackhole List) provider configuration.
type RblConfig = pb.RblConfig

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

// Client provides high-level access to the Rolodex gRPC management API.
// Create one with [Dial] and close it with [Client.Close] when finished.
type Client struct {
	conn      *grpc.ClientConn
	rpc       pb.RolodexServiceClient
	authToken string
}

// Dial establishes a gRPC connection to a Rolodex server and returns a [Client].
//
// The addr parameter specifies either:
//   - A TCP address in "host:port" format (e.g. "localhost:50051")
//   - A Unix socket path (e.g. "/var/run/rolodex.sock") when [WithUnixSocket] is used
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
		return nil, fmt.Errorf("rolodex: dial %s: %w", addr, err)
	}

	return &Client{
		conn:      conn,
		rpc:       pb.NewRolodexServiceClient(conn),
		authToken: cfg.authToken,
	}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// AddRecord adds a DNS record to the Rolodex server's local database.
//
// Parameters:
//   - record: the DNS record to add (name, record_type, value are required;
//     ttl defaults to 300 if zero; priority is used only for MX and SRV records)
//
// Returns an error if the RPC fails or the server reports a failure.
//
// Remote API path: /rolodex.RolodexService/AddRecord
func (c *Client) AddRecord(ctx context.Context, record *DnsRecord) error {
	resp, err := c.rpc.AddRecord(ctx, &pb.AddRecordRequest{
		Record:    record,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex: add record: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex: add record: %s", resp.Message)
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

// RemoveRecord removes DNS records from the Rolodex server's local database.
//
// Parameters:
//   - name: the fully qualified domain name to remove records for (e.g. "example.com.")
//   - opts: optional filters to narrow which records are removed. If nil, all records
//     for the given name are removed.
//
// Returns the number of records removed and any error.
//
// Remote API path: /rolodex.RolodexService/RemoveRecord
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
		return 0, fmt.Errorf("rolodex: remove record: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("rolodex: remove record: %s", resp.Message)
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

// ListRecords queries the Rolodex server's local DNS database.
//
// Parameters:
//   - opts: optional filters for name and/or record type. If nil, all records
//     are returned.
//
// Returns the matching DNS records and any error.
//
// Remote API path: /rolodex.RolodexService/ListRecords
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
		return nil, fmt.Errorf("rolodex: list records: %w", err)
	}
	return resp.Records, nil
}

// SetForwarders configures the upstream DNS forwarders on the Rolodex server.
// Forwarders are specified as "host:port" strings (e.g. "8.8.8.8:53").
// This replaces the entire forwarder list.
//
// Parameters:
//   - forwarders: list of upstream DNS server addresses in "host:port" format
//
// Remote API path: /rolodex.RolodexService/SetForwarders
func (c *Client) SetForwarders(ctx context.Context, forwarders []string) error {
	resp, err := c.rpc.SetForwarders(ctx, &pb.SetForwarderRequest{
		Forwarders: forwarders,
		AuthToken:  c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex: set forwarders: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex: set forwarders: %s", resp.Message)
	}
	return nil
}

// SetRblConfig configures Realtime Blackhole List settings on the Rolodex server.
// This replaces the entire RBL configuration.
//
// Parameters:
//   - enabled: whether RBL checking is globally enabled (default: false when first configured)
//   - providers: list of RBL provider configurations, each with a zone name and enabled flag
//
// Remote API path: /rolodex.RolodexService/SetRblConfig
func (c *Client) SetRblConfig(ctx context.Context, enabled bool, providers []*RblConfig) error {
	resp, err := c.rpc.SetRblConfig(ctx, &pb.SetRblConfigRequest{
		Enabled:   enabled,
		Providers: providers,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex: set rbl config: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex: set rbl config: %s", resp.Message)
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

// GetRblConfig retrieves the current RBL configuration from the Rolodex server.
//
// Remote API path: /rolodex.RolodexService/GetRblConfig
func (c *Client) GetRblConfig(ctx context.Context) (*RblStatus, error) {
	resp, err := c.rpc.GetRblConfig(ctx, &pb.GetRblConfigRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex: get rbl config: %w", err)
	}
	return &RblStatus{
		Enabled:   resp.Enabled,
		Providers: resp.Providers,
	}, nil
}

// FlushCache clears the RBL lookup cache on the Rolodex server.
//
// Remote API path: /rolodex.RolodexService/FlushCache
func (c *Client) FlushCache(ctx context.Context) error {
	resp, err := c.rpc.FlushCache(ctx, &pb.FlushCacheRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex: flush cache: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex: flush cache: %s", resp.Message)
	}
	return nil
}

// NetworkScope represents a DNS view that groups records and IP associations.
type NetworkScope = pb.NetworkScope

// NetworkAssociation represents a client IP's membership in a network scope.
type NetworkAssociation = pb.NetworkAssociation

// CreateNetworkScope creates a new network scope on the Rolodex server.
//
// Each scope has a unique name and a reserved .home domain that serves
// as the default search domain for DNS clients in that network.
//
// Parameters:
//   - scope: the network scope to create. If HomeDomain is empty, it defaults
//     to "<name>.home" (e.g. "office" becomes "office.home").
//
// Remote API path: /rolodex.RolodexService/CreateNetworkScope
func (c *Client) CreateNetworkScope(ctx context.Context, scope *NetworkScope) error {
	resp, err := c.rpc.CreateNetworkScope(ctx, &pb.CreateNetworkScopeRequest{
		Scope:     scope,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex: create network scope: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex: create network scope: %s", resp.Message)
	}
	return nil
}

// DeleteNetworkScope removes a network scope and all its records and associations.
//
// Parameters:
//   - name: the unique name of the scope to delete
//
// Remote API path: /rolodex.RolodexService/DeleteNetworkScope
func (c *Client) DeleteNetworkScope(ctx context.Context, name string) error {
	resp, err := c.rpc.DeleteNetworkScope(ctx, &pb.DeleteNetworkScopeRequest{
		Name:      name,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex: delete network scope: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex: delete network scope: %s", resp.Message)
	}
	return nil
}

// ListNetworkScopes retrieves all configured network scopes.
//
// Remote API path: /rolodex.RolodexService/ListNetworkScopes
func (c *Client) ListNetworkScopes(ctx context.Context) ([]*NetworkScope, error) {
	resp, err := c.rpc.ListNetworkScopes(ctx, &pb.ListNetworkScopesRequest{
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex: list network scopes: %w", err)
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
// Remote API path: /rolodex.RolodexService/JoinNetwork
func (c *Client) JoinNetwork(ctx context.Context, ipAddress, scopeName string, ttlSeconds uint64) error {
	resp, err := c.rpc.JoinNetwork(ctx, &pb.JoinNetworkRequest{
		IpAddress:  ipAddress,
		ScopeName:  scopeName,
		TtlSeconds: ttlSeconds,
		AuthToken:  c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex: join network: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex: join network: %s", resp.Message)
	}
	return nil
}

// LeaveNetwork removes an IP address's association with its network scope.
//
// Parameters:
//   - ipAddress: the client IP to disassociate
//
// Remote API path: /rolodex.RolodexService/LeaveNetwork
func (c *Client) LeaveNetwork(ctx context.Context, ipAddress string) error {
	resp, err := c.rpc.LeaveNetwork(ctx, &pb.LeaveNetworkRequest{
		IpAddress: ipAddress,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex: leave network: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex: leave network: %s", resp.Message)
	}
	return nil
}

// GetNetworkAssociations retrieves IP-to-scope associations.
//
// Parameters:
//   - scopeName: if non-empty, only return associations for this scope.
//     If empty, returns all associations.
//
// Remote API path: /rolodex.RolodexService/GetNetworkAssociations
func (c *Client) GetNetworkAssociations(ctx context.Context, scopeName string) ([]*NetworkAssociation, error) {
	resp, err := c.rpc.GetNetworkAssociations(ctx, &pb.GetNetworkAssociationsRequest{
		ScopeName: scopeName,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex: get network associations: %w", err)
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
// Remote API path: /rolodex.RolodexService/AddScopedRecord
func (c *Client) AddScopedRecord(ctx context.Context, scopeName string, record *DnsRecord) error {
	resp, err := c.rpc.AddScopedRecord(ctx, &pb.AddScopedRecordRequest{
		ScopeName: scopeName,
		Record:    record,
		AuthToken: c.authToken,
	})
	if err != nil {
		return fmt.Errorf("rolodex: add scoped record: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rolodex: add scoped record: %s", resp.Message)
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
// Remote API path: /rolodex.RolodexService/RemoveScopedRecord
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
		return 0, fmt.Errorf("rolodex: remove scoped record: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("rolodex: remove scoped record: %s", resp.Message)
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
// Remote API path: /rolodex.RolodexService/ListScopedRecords
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
		return nil, fmt.Errorf("rolodex: list scoped records: %w", err)
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
// Remote API path: /rolodex.RolodexService/GetSearchDomains
func (c *Client) GetSearchDomains(ctx context.Context, ipAddress string) ([]string, error) {
	resp, err := c.rpc.GetSearchDomains(ctx, &pb.GetSearchDomainsRequest{
		IpAddress: ipAddress,
		AuthToken: c.authToken,
	})
	if err != nil {
		return nil, fmt.Errorf("rolodex: get search domains: %w", err)
	}
	return resp.SearchDomains, nil
}
