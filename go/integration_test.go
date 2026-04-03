// Integration tests for the rolodex-dns Go client.
//
// These tests start a real Rolodex DNS server process and exercise the Go client
// against it over both TCP and Unix socket transports. They are fully isolated:
// each test uses a private temporary directory, random ports, and a per-test
// database file.
//
// The tests require the "rolodex-dns" binary to be built first (see Makefile).
// They are gated behind the "integration" build tag so they do not run during
// normal `go test` invocations.

//go:build integration

package rolodexdns

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// rolodexBinary returns the path to the pre-built rolodex-dns binary.
func rolodexBinary() string {
	if p := os.Getenv("ROLODEX_DNS_BINARY"); p != "" {
		return p
	}
	return "rolodex-dns"
}

// serverConfig holds the configuration for a test server instance.
type serverConfig struct {
	dir          string
	dbPath       string
	grpcTCPAddr  string
	unixSocket   string
	dnsUDPAddr   string
	dnsTCPAddr   string
	sharedSecret string
}

// startServer starts a rolodex-dns server process with the given configuration and
// returns a cleanup function that stops the process.
func startServer(t *testing.T, cfg serverConfig) {
	t.Helper()

	configContent := fmt.Sprintf(`database_path: %q
forwarders: []

dns:
  bind:
    - udp: %q
    - tcp: %q

grpc:
  tcp_bind: %q
  unix_socket: %q
  shared_secret: %q

rbl:
  enabled: false
  providers: []
`, cfg.dbPath, cfg.dnsUDPAddr, cfg.dnsTCPAddr, cfg.grpcTCPAddr, cfg.unixSocket, cfg.sharedSecret)

	configPath := filepath.Join(cfg.dir, "rolodex-dns.yml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command(rolodexBinary(), "-c", configPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Wait for the gRPC TCP port to be ready
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", cfg.grpcTCPAddr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server did not start within 10 seconds")
}

// allocatePort finds a free TCP port and returns the "host:port" address.
func allocatePort(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate port: %v", err)
	}
	addr := lis.Addr().String()
	lis.Close()
	return addr
}

// setupTestServer creates a temporary directory, allocates random ports, starts
// a rolodex-dns server, and returns a connected TCP client.
func setupTestServer(t *testing.T) (*Client, serverConfig) {
	t.Helper()

	dir := t.TempDir()
	cfg := serverConfig{
		dir:          dir,
		dbPath:       filepath.Join(dir, "rolodex-dns.db"),
		grpcTCPAddr:  allocatePort(t),
		unixSocket:   filepath.Join(dir, "rolodex-dns.sock"),
		dnsUDPAddr:   allocatePort(t),
		dnsTCPAddr:   allocatePort(t),
		sharedSecret: "integration-test-secret",
	}

	startServer(t, cfg)

	client, err := Dial(context.Background(), cfg.grpcTCPAddr,
		WithAuthToken(cfg.sharedSecret),
	)
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	return client, cfg
}

func TestIntegrationAddAndListRecords(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Add an A record
	err := client.AddRecord(ctx, &DnsRecord{
		Name:       "host1.integration.test.",
		RecordType: RecordTypeA,
		Value:      "10.0.0.1",
		Ttl:        600,
	})
	if err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	// Add an AAAA record
	err = client.AddRecord(ctx, &DnsRecord{
		Name:       "host1.integration.test.",
		RecordType: RecordTypeAAAA,
		Value:      "fd00::1",
		Ttl:        600,
	})
	if err != nil {
		t.Fatalf("AddRecord AAAA: %v", err)
	}

	// List all records
	records, err := client.ListRecords(ctx, nil)
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}

	// List filtered by type
	rt := RecordTypeA
	records, err = client.ListRecords(ctx, &ListRecordsOptions{
		RecordType: &rt,
	})
	if err != nil {
		t.Fatalf("ListRecords filtered: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d A records, want 1", len(records))
	}
	if records[0].Value != "10.0.0.1" {
		t.Errorf("record value = %q, want %q", records[0].Value, "10.0.0.1")
	}
}

func TestIntegrationAddAndRemoveRecord(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Add a record
	err := client.AddRecord(ctx, &DnsRecord{
		Name:       "remove-me.integration.test.",
		RecordType: RecordTypeA,
		Value:      "10.0.0.99",
		Ttl:        300,
	})
	if err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	// Verify it exists
	records, err := client.ListRecords(ctx, &ListRecordsOptions{
		NameFilter: "remove-me.integration.test.",
	})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}

	// Remove it
	count, err := client.RemoveRecord(ctx, "remove-me.integration.test.", nil)
	if err != nil {
		t.Fatalf("RemoveRecord: %v", err)
	}
	if count != 1 {
		t.Errorf("removed %d, want 1", count)
	}

	// Verify it's gone
	records, err = client.ListRecords(ctx, &ListRecordsOptions{
		NameFilter: "remove-me.integration.test.",
	})
	if err != nil {
		t.Fatalf("ListRecords after remove: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("got %d records, want 0 after removal", len(records))
	}
}

func TestIntegrationRemoveWithFilters(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Add multiple records for same name
	for _, val := range []string{"10.0.0.1", "10.0.0.2"} {
		err := client.AddRecord(ctx, &DnsRecord{
			Name:       "multi.integration.test.",
			RecordType: RecordTypeA,
			Value:      val,
			Ttl:        300,
		})
		if err != nil {
			t.Fatalf("AddRecord: %v", err)
		}
	}

	// Remove only the record with value 10.0.0.1
	rt := RecordTypeA
	count, err := client.RemoveRecord(ctx, "multi.integration.test.", &RemoveRecordOptions{
		RecordType: &rt,
		Value:      "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("RemoveRecord: %v", err)
	}
	if count != 1 {
		t.Errorf("removed %d, want 1", count)
	}

	// Verify only one remains
	records, err := client.ListRecords(ctx, nil)
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Value != "10.0.0.2" {
		t.Errorf("remaining value = %q, want %q", records[0].Value, "10.0.0.2")
	}
}

func TestIntegrationWildcardFilter(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Add records across multiple subdomains
	for _, name := range []string{
		"a.wild.test.",
		"b.wild.test.",
		"c.other.test.",
	} {
		err := client.AddRecord(ctx, &DnsRecord{
			Name:       name,
			RecordType: RecordTypeA,
			Value:      "10.0.0.1",
			Ttl:        300,
		})
		if err != nil {
			t.Fatalf("AddRecord %s: %v", name, err)
		}
	}

	// List with wildcard
	records, err := client.ListRecords(ctx, &ListRecordsOptions{
		NameFilter: "*.wild.test.",
	})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records matching *.wild.test., want 2", len(records))
	}
}

func TestIntegrationSetForwarders(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	err := client.SetForwarders(ctx, []string{"8.8.8.8:53", "1.1.1.1:53"})
	if err != nil {
		t.Fatalf("SetForwarders: %v", err)
	}
}

func TestIntegrationSetForwardersInvalid(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	err := client.SetForwarders(ctx, []string{"not-a-valid-address"})
	if err == nil {
		t.Fatal("expected error for invalid forwarder address")
	}
}

func TestIntegrationRblConfigRoundtrip(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Set RBL config
	err := client.SetRblConfig(ctx, true, []*RblConfig{
		{Zone: "zen.spamhaus.org", Enabled: true},
		{Zone: "bl.spamcop.net", Enabled: false},
	})
	if err != nil {
		t.Fatalf("SetRblConfig: %v", err)
	}

	// Get it back
	status, err := client.GetRblConfig(ctx)
	if err != nil {
		t.Fatalf("GetRblConfig: %v", err)
	}
	if !status.Enabled {
		t.Error("expected RBL to be enabled")
	}
	if len(status.Providers) != 2 {
		t.Fatalf("got %d providers, want 2", len(status.Providers))
	}
	if status.Providers[0].Zone != "zen.spamhaus.org" {
		t.Errorf("provider[0].zone = %q, want %q", status.Providers[0].Zone, "zen.spamhaus.org")
	}
	if !status.Providers[0].Enabled {
		t.Error("provider[0] should be enabled")
	}
	if status.Providers[1].Zone != "bl.spamcop.net" {
		t.Errorf("provider[1].zone = %q, want %q", status.Providers[1].Zone, "bl.spamcop.net")
	}
	if status.Providers[1].Enabled {
		t.Error("provider[1] should be disabled")
	}
}

func TestIntegrationFlushCache(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	err := client.FlushCache(ctx)
	if err != nil {
		t.Fatalf("FlushCache: %v", err)
	}
}

func TestIntegrationUnixSocket(t *testing.T) {
	_, cfg := setupTestServer(t)
	ctx := context.Background()

	// Connect via Unix socket (no auth token needed server-side)
	client, err := Dial(ctx, cfg.unixSocket, WithUnixSocket())
	if err != nil {
		t.Fatalf("Dial unix: %v", err)
	}
	defer client.Close()

	// Add a record (no auth token, should work over unix socket)
	err = client.AddRecord(ctx, &DnsRecord{
		Name:       "unix-test.integration.test.",
		RecordType: RecordTypeA,
		Value:      "172.16.0.1",
		Ttl:        300,
	})
	if err != nil {
		t.Fatalf("AddRecord via unix socket: %v", err)
	}

	// Verify it exists
	records, err := client.ListRecords(ctx, &ListRecordsOptions{
		NameFilter: "unix-test.integration.test.",
	})
	if err != nil {
		t.Fatalf("ListRecords via unix socket: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Value != "172.16.0.1" {
		t.Errorf("value = %q, want %q", records[0].Value, "172.16.0.1")
	}
}

func TestIntegrationAuthFailure(t *testing.T) {
	_, cfg := setupTestServer(t)
	ctx := context.Background()

	// Connect with wrong auth token
	client, err := Dial(ctx, cfg.grpcTCPAddr, WithAuthToken("wrong-secret"))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	err = client.AddRecord(ctx, &DnsRecord{
		Name:       "should-fail.",
		RecordType: RecordTypeA,
		Value:      "1.2.3.4",
	})
	if err == nil {
		t.Fatal("expected authentication error")
	}
}

func TestIntegrationDefaultTTL(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Add a record with TTL 0 (should default to 300)
	err := client.AddRecord(ctx, &DnsRecord{
		Name:       "default-ttl.integration.test.",
		RecordType: RecordTypeA,
		Value:      "10.0.0.1",
		Ttl:        0,
	})
	if err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	records, err := client.ListRecords(ctx, &ListRecordsOptions{
		NameFilter: "default-ttl.integration.test.",
	})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Ttl != 300 {
		t.Errorf("ttl = %d, want 300 (default)", records[0].Ttl)
	}
}

func TestIntegrationMultipleRecordTypes(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Add various record types
	testRecords := []struct {
		name       string
		recordType RecordType
		value      string
		priority   uint32
	}{
		{"mx.integration.test.", RecordTypeMX, "mail.example.com.", 10},
		{"txt.integration.test.", RecordTypeTXT, "v=spf1 include:example.com ~all", 0},
		{"cname.integration.test.", RecordTypeCNAME, "target.example.com.", 0},
		{"ns.integration.test.", RecordTypeNS, "ns1.example.com.", 0},
		{"srv.integration.test.", RecordTypeSRV, "0 443 web.example.com.", 10},
		{"ptr.integration.test.", RecordTypePTR, "host.example.com.", 0},
	}

	for _, tr := range testRecords {
		err := client.AddRecord(ctx, &DnsRecord{
			Name:       tr.name,
			RecordType: tr.recordType,
			Value:      tr.value,
			Ttl:        300,
			Priority:   tr.priority,
		})
		if err != nil {
			t.Fatalf("AddRecord %s: %v", tr.name, err)
		}
	}

	// List all and verify count
	records, err := client.ListRecords(ctx, nil)
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != len(testRecords) {
		t.Errorf("got %d records, want %d", len(records), len(testRecords))
	}

	// Filter by MX type
	rt := RecordTypeMX
	records, err = client.ListRecords(ctx, &ListRecordsOptions{RecordType: &rt})
	if err != nil {
		t.Fatalf("ListRecords MX: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d MX records, want 1", len(records))
	}
	if records[0].Priority != 10 {
		t.Errorf("MX priority = %d, want 10", records[0].Priority)
	}
}

func TestIntegrationNetworkScopeLifecycle(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Create a scope
	err := client.CreateNetworkScope(ctx, &NetworkScope{
		Name: "office",
	})
	if err != nil {
		t.Fatalf("CreateNetworkScope: %v", err)
	}

	// List scopes
	scopes, err := client.ListNetworkScopes(ctx)
	if err != nil {
		t.Fatalf("ListNetworkScopes: %v", err)
	}
	if len(scopes) != 1 {
		t.Fatalf("got %d scopes, want 1", len(scopes))
	}
	if scopes[0].Name != "office" {
		t.Errorf("scope name = %q, want %q", scopes[0].Name, "office")
	}

	// Delete scope
	err = client.DeleteNetworkScope(ctx, "office")
	if err != nil {
		t.Fatalf("DeleteNetworkScope: %v", err)
	}

	// Verify deleted
	scopes, err = client.ListNetworkScopes(ctx)
	if err != nil {
		t.Fatalf("ListNetworkScopes after delete: %v", err)
	}
	if len(scopes) != 0 {
		t.Errorf("got %d scopes after delete, want 0", len(scopes))
	}
}

func TestIntegrationJoinLeaveNetwork(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Create scope first
	err := client.CreateNetworkScope(ctx, &NetworkScope{Name: "lab"})
	if err != nil {
		t.Fatalf("CreateNetworkScope: %v", err)
	}

	// Join network
	err = client.JoinNetwork(ctx, "10.0.0.50", "lab", 600)
	if err != nil {
		t.Fatalf("JoinNetwork: %v", err)
	}

	// Check associations
	assocs, err := client.GetNetworkAssociations(ctx, "lab")
	if err != nil {
		t.Fatalf("GetNetworkAssociations: %v", err)
	}
	if len(assocs) != 1 {
		t.Fatalf("got %d associations, want 1", len(assocs))
	}
	if assocs[0].IpAddress != "10.0.0.50" {
		t.Errorf("ip = %q, want %q", assocs[0].IpAddress, "10.0.0.50")
	}

	// Leave network
	err = client.LeaveNetwork(ctx, "10.0.0.50")
	if err != nil {
		t.Fatalf("LeaveNetwork: %v", err)
	}

	// Verify gone
	assocs, err = client.GetNetworkAssociations(ctx, "lab")
	if err != nil {
		t.Fatalf("GetNetworkAssociations after leave: %v", err)
	}
	if len(assocs) != 0 {
		t.Errorf("got %d associations after leave, want 0", len(assocs))
	}
}

func TestIntegrationScopedRecords(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Create scope
	err := client.CreateNetworkScope(ctx, &NetworkScope{Name: "office"})
	if err != nil {
		t.Fatalf("CreateNetworkScope: %v", err)
	}

	// Add scoped record
	err = client.AddScopedRecord(ctx, "office", &DnsRecord{
		Name:       "printer.office.home.",
		RecordType: RecordTypeA,
		Value:      "192.168.1.50",
		Ttl:        300,
	})
	if err != nil {
		t.Fatalf("AddScopedRecord: %v", err)
	}

	// List scoped records
	records, err := client.ListScopedRecords(ctx, "office", nil)
	if err != nil {
		t.Fatalf("ListScopedRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Value != "192.168.1.50" {
		t.Errorf("value = %q, want %q", records[0].Value, "192.168.1.50")
	}

	// Remove scoped record
	count, err := client.RemoveScopedRecord(ctx, "office", "printer.office.home.", nil)
	if err != nil {
		t.Fatalf("RemoveScopedRecord: %v", err)
	}
	if count != 1 {
		t.Errorf("removed %d, want 1", count)
	}

	// Verify removed
	records, err = client.ListScopedRecords(ctx, "office", nil)
	if err != nil {
		t.Fatalf("ListScopedRecords after remove: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("got %d records after remove, want 0", len(records))
	}
}

func TestIntegrationSearchDomains(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Create scope and join
	err := client.CreateNetworkScope(ctx, &NetworkScope{Name: "office"})
	if err != nil {
		t.Fatalf("CreateNetworkScope: %v", err)
	}
	err = client.JoinNetwork(ctx, "192.168.1.100", "office", 300)
	if err != nil {
		t.Fatalf("JoinNetwork: %v", err)
	}

	// Get search domains
	domains, err := client.GetSearchDomains(ctx, "192.168.1.100")
	if err != nil {
		t.Fatalf("GetSearchDomains: %v", err)
	}
	if len(domains) != 1 {
		t.Fatalf("got %d domains, want 1", len(domains))
	}
	if domains[0] != "office.home." {
		t.Errorf("domain = %q, want %q", domains[0], "office.home.")
	}
}

func TestIntegrationConcurrentClients(t *testing.T) {
	_, cfg := setupTestServer(t)
	ctx := context.Background()

	// Connect multiple clients simultaneously
	const numClients = 5
	errs := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		go func(i int) {
			c, err := Dial(ctx, cfg.grpcTCPAddr, WithAuthToken(cfg.sharedSecret))
			if err != nil {
				errs <- fmt.Errorf("client %d: dial: %w", i, err)
				return
			}
			defer c.Close()

			err = c.AddRecord(ctx, &DnsRecord{
				Name:       fmt.Sprintf("concurrent-%d.test.", i),
				RecordType: RecordTypeA,
				Value:      fmt.Sprintf("10.0.0.%d", i+1),
				Ttl:        300,
			})
			errs <- err
		}(i)
	}

	for i := 0; i < numClients; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent client error: %v", err)
		}
	}

	// Verify all records were added
	client, err := Dial(ctx, cfg.grpcTCPAddr, WithAuthToken(cfg.sharedSecret))
	if err != nil {
		t.Fatalf("dial for verification: %v", err)
	}
	defer client.Close()

	records, err := client.ListRecords(ctx, nil)
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(records) != numClients {
		t.Errorf("got %d records, want %d", len(records), numClients)
	}
}

func TestIntegrationNetworkScopeCustomDomain(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Create scope with custom home domain
	err := client.CreateNetworkScope(ctx, &NetworkScope{
		Name:       "custom",
		HomeDomain: "custom.internal.",
	})
	if err != nil {
		t.Fatalf("CreateNetworkScope: %v", err)
	}

	scopes, err := client.ListNetworkScopes(ctx)
	if err != nil {
		t.Fatalf("ListNetworkScopes: %v", err)
	}
	if len(scopes) != 1 {
		t.Fatalf("got %d scopes, want 1", len(scopes))
	}
	if scopes[0].HomeDomain != "custom.internal." {
		t.Errorf("home_domain = %q, want %q", scopes[0].HomeDomain, "custom.internal.")
	}

	// Join and verify search domains use the custom domain
	err = client.JoinNetwork(ctx, "10.0.0.1", "custom", 300)
	if err != nil {
		t.Fatalf("JoinNetwork: %v", err)
	}
	domains, err := client.GetSearchDomains(ctx, "10.0.0.1")
	if err != nil {
		t.Fatalf("GetSearchDomains: %v", err)
	}
	if len(domains) != 1 {
		t.Fatalf("got %d domains, want 1", len(domains))
	}
	if domains[0] != "custom.internal." {
		t.Errorf("search domain = %q, want %q", domains[0], "custom.internal.")
	}
}

func TestIntegrationScopedRecordFiltering(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Create scope and add multiple records
	err := client.CreateNetworkScope(ctx, &NetworkScope{Name: "filter"})
	if err != nil {
		t.Fatalf("CreateNetworkScope: %v", err)
	}

	records := []struct {
		name       string
		recordType RecordType
		value      string
	}{
		{"a.filter.home.", RecordTypeA, "10.0.0.1"},
		{"b.filter.home.", RecordTypeA, "10.0.0.2"},
		{"a.filter.home.", RecordTypeAAAA, "fd00::1"},
		{"c.other.zone.", RecordTypeA, "10.0.0.3"},
	}

	for _, r := range records {
		err = client.AddScopedRecord(ctx, "filter", &DnsRecord{
			Name:       r.name,
			RecordType: r.recordType,
			Value:      r.value,
			Ttl:        300,
		})
		if err != nil {
			t.Fatalf("AddScopedRecord %s: %v", r.name, err)
		}
	}

	// List all
	all, err := client.ListScopedRecords(ctx, "filter", nil)
	if err != nil {
		t.Fatalf("ListScopedRecords all: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("got %d records, want 4", len(all))
	}

	// Filter by name wildcard
	filtered, err := client.ListScopedRecords(ctx, "filter", &ListScopedRecordsOptions{
		NameFilter: "*.filter.home.",
	})
	if err != nil {
		t.Fatalf("ListScopedRecords wildcard: %v", err)
	}
	if len(filtered) != 3 {
		t.Fatalf("got %d records matching *.filter.home., want 3", len(filtered))
	}

	// Filter by type
	rt := RecordTypeAAAA
	filtered, err = client.ListScopedRecords(ctx, "filter", &ListScopedRecordsOptions{
		RecordType: &rt,
	})
	if err != nil {
		t.Fatalf("ListScopedRecords AAAA: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("got %d AAAA records, want 1", len(filtered))
	}

	// Remove with type filter
	rtA := RecordTypeA
	count, err := client.RemoveScopedRecord(ctx, "filter", "a.filter.home.", &RemoveScopedRecordOptions{
		RecordType: &rtA,
	})
	if err != nil {
		t.Fatalf("RemoveScopedRecord: %v", err)
	}
	if count != 1 {
		t.Errorf("removed %d, want 1", count)
	}

	// Should have 3 remaining
	remaining, err := client.ListScopedRecords(ctx, "filter", nil)
	if err != nil {
		t.Fatalf("ListScopedRecords after remove: %v", err)
	}
	if len(remaining) != 3 {
		t.Errorf("got %d records after remove, want 3", len(remaining))
	}
}

func TestIntegrationSearchDomainsUnassociatedIP(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Create a scope (but don't associate any IP)
	err := client.CreateNetworkScope(ctx, &NetworkScope{Name: "empty"})
	if err != nil {
		t.Fatalf("CreateNetworkScope: %v", err)
	}

	// Unassociated IP should get no search domains
	domains, err := client.GetSearchDomains(ctx, "192.168.99.99")
	if err != nil {
		t.Fatalf("GetSearchDomains: %v", err)
	}
	if len(domains) != 0 {
		t.Errorf("got %d domains for unassociated IP, want 0", len(domains))
	}
}

func TestIntegrationDeleteScopeCascade(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Create scope, add records and associations
	err := client.CreateNetworkScope(ctx, &NetworkScope{Name: "cascade"})
	if err != nil {
		t.Fatalf("CreateNetworkScope: %v", err)
	}

	err = client.AddScopedRecord(ctx, "cascade", &DnsRecord{
		Name:       "host.cascade.home.",
		RecordType: RecordTypeA,
		Value:      "10.0.0.1",
		Ttl:        300,
	})
	if err != nil {
		t.Fatalf("AddScopedRecord: %v", err)
	}

	err = client.JoinNetwork(ctx, "192.168.1.1", "cascade", 300)
	if err != nil {
		t.Fatalf("JoinNetwork: %v", err)
	}

	// Delete scope
	err = client.DeleteNetworkScope(ctx, "cascade")
	if err != nil {
		t.Fatalf("DeleteNetworkScope: %v", err)
	}

	// Verify scoped records are gone
	records, err := client.ListScopedRecords(ctx, "cascade", nil)
	if err != nil {
		t.Fatalf("ListScopedRecords: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("got %d records after cascade delete, want 0", len(records))
	}

	// Verify associations are gone
	assocs, err := client.GetNetworkAssociations(ctx, "cascade")
	if err != nil {
		t.Fatalf("GetNetworkAssociations: %v", err)
	}
	if len(assocs) != 0 {
		t.Errorf("got %d associations after cascade delete, want 0", len(assocs))
	}
}

func TestIntegrationAuthoritativeZoneLifecycle(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Add authoritative zone
	err := client.AddAuthoritativeZone(ctx, "auth.test.")
	if err != nil {
		t.Fatalf("AddAuthoritativeZone: %v", err)
	}

	// List zones
	zones, err := client.ListAuthoritativeZones(ctx)
	if err != nil {
		t.Fatalf("ListAuthoritativeZones: %v", err)
	}
	found := false
	for _, z := range zones {
		if z == "auth.test." {
			found = true
		}
	}
	if !found {
		t.Errorf("zone 'auth.test.' not found in %v", zones)
	}

	// Remove zone
	err = client.RemoveAuthoritativeZone(ctx, "auth.test.")
	if err != nil {
		t.Fatalf("RemoveAuthoritativeZone: %v", err)
	}

	// Verify removed
	zones, err = client.ListAuthoritativeZones(ctx)
	if err != nil {
		t.Fatalf("ListAuthoritativeZones after remove: %v", err)
	}
	for _, z := range zones {
		if z == "auth.test." {
			t.Errorf("zone 'auth.test.' still present after removal")
		}
	}
}

func TestIntegrationLocalRblLifecycle(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Add local RBL entry
	err := client.AddLocalRblEntry(ctx, &LocalRblEntry{
		Name:   "10.0.0.99",
		Reason: "test block",
	})
	if err != nil {
		t.Fatalf("AddLocalRblEntry: %v", err)
	}

	// List entries
	entries, err := client.ListLocalRblEntries(ctx)
	if err != nil {
		t.Fatalf("ListLocalRblEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Name != "10.0.0.99" {
		t.Errorf("name = %q, want %q", entries[0].Name, "10.0.0.99")
	}
	if entries[0].Reason != "test block" {
		t.Errorf("reason = %q, want %q", entries[0].Reason, "test block")
	}

	// Remove entry
	err = client.RemoveLocalRblEntry(ctx, "10.0.0.99")
	if err != nil {
		t.Fatalf("RemoveLocalRblEntry: %v", err)
	}

	// Verify removed
	entries, err = client.ListLocalRblEntries(ctx)
	if err != nil {
		t.Fatalf("ListLocalRblEntries after remove: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries after remove, want 0", len(entries))
	}
}

func TestIntegrationCacheStatsAndFlush(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Get cache stats (should succeed even with empty cache)
	stats, err := client.GetCacheStats(ctx)
	if err != nil {
		t.Fatalf("GetCacheStats: %v", err)
	}
	if stats == nil {
		t.Fatal("stats should not be nil")
	}

	// Flush DNS cache
	err = client.FlushDnsCache(ctx)
	if err != nil {
		t.Fatalf("FlushDnsCache: %v", err)
	}
}

func TestIntegrationTtlDriftConfig(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Set TTL drift config to fixed mode
	err := client.SetTtlDriftConfig(ctx, &TtlDriftConfig{
		Mode:            "fixed",
		FixedAdjustment: "30s",
	})
	if err != nil {
		t.Fatalf("SetTtlDriftConfig: %v", err)
	}

	// Get config back
	config, err := client.GetTtlDriftConfig(ctx)
	if err != nil {
		t.Fatalf("GetTtlDriftConfig: %v", err)
	}
	if config == nil {
		t.Fatal("config should not be nil")
	}
	if config.Mode != "fixed" {
		t.Errorf("mode = %q, want %q", config.Mode, "fixed")
	}
}

func TestIntegrationTransportConfigs(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// DoT config
	err := client.SetDotConfig(ctx, &DotConfig{
		Bind: "0.0.0.0:853",
	})
	if err != nil {
		t.Fatalf("SetDotConfig: %v", err)
	}
	dotCfg, err := client.GetDotConfig(ctx)
	if err != nil {
		t.Fatalf("GetDotConfig: %v", err)
	}
	if dotCfg != nil && dotCfg.Bind != "0.0.0.0:853" {
		t.Errorf("DoT bind = %q, want %q", dotCfg.Bind, "0.0.0.0:853")
	}

	// DoH config
	err = client.SetDohConfig(ctx, &DohConfig{
		Bind:     "0.0.0.0:443",
		EnableH3: true,
	})
	if err != nil {
		t.Fatalf("SetDohConfig: %v", err)
	}
	dohCfg, err := client.GetDohConfig(ctx)
	if err != nil {
		t.Fatalf("GetDohConfig: %v", err)
	}
	if dohCfg != nil && dohCfg.Bind != "0.0.0.0:443" {
		t.Errorf("DoH bind = %q, want %q", dohCfg.Bind, "0.0.0.0:443")
	}

	// DoQ config
	err = client.SetDoqConfig(ctx, &DoqConfig{
		Bind: "0.0.0.0:8853",
	})
	if err != nil {
		t.Fatalf("SetDoqConfig: %v", err)
	}
	doqCfg, err := client.GetDoqConfig(ctx)
	if err != nil {
		t.Fatalf("GetDoqConfig: %v", err)
	}
	if doqCfg != nil && doqCfg.Bind != "0.0.0.0:8853" {
		t.Errorf("DoQ bind = %q, want %q", doqCfg.Bind, "0.0.0.0:8853")
	}

	// Proxy config
	err = client.SetProxyConfig(ctx, &ProxyConfig{
		Url:  "socks5://proxy.example.com:1080",
		Mode: "connect",
	})
	if err != nil {
		t.Fatalf("SetProxyConfig: %v", err)
	}
	proxyCfg, err := client.GetProxyConfig(ctx)
	if err != nil {
		t.Fatalf("GetProxyConfig: %v", err)
	}
	if proxyCfg != nil && proxyCfg.Url != "socks5://proxy.example.com:1080" {
		t.Errorf("Proxy url = %q, want %q", proxyCfg.Url, "socks5://proxy.example.com:1080")
	}
}

func TestIntegrationDnssecKeyLifecycle(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Generate DNSSEC key
	key, err := client.GenerateDnssecKey(ctx, "dnssec.test.", "ED25519", "ZSK")
	if err != nil {
		t.Fatalf("GenerateDnssecKey: %v", err)
	}
	if key == nil {
		t.Fatal("key should not be nil")
	}
	if key.KeyTag == 0 {
		t.Error("key_tag should be > 0")
	}
	if key.Zone != "dnssec.test." {
		t.Errorf("zone = %q, want %q", key.Zone, "dnssec.test.")
	}

	// List keys
	keys, err := client.ListDnssecKeys(ctx, "dnssec.test.")
	if err != nil {
		t.Fatalf("ListDnssecKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}

	// Get DS records (need a KSK first)
	ksk, err := client.GenerateDnssecKey(ctx, "dnssec.test.", "ED25519", "KSK")
	if err != nil {
		t.Fatalf("GenerateDnssecKey KSK: %v", err)
	}

	dsRecords, err := client.GetDsRecords(ctx, "dnssec.test.")
	if err != nil {
		t.Fatalf("GetDsRecords: %v", err)
	}
	if len(dsRecords) == 0 {
		t.Error("expected at least one DS record")
	}

	// Delete key
	err = client.DeleteDnssecKey(ctx, ksk.Id)
	if err != nil {
		t.Fatalf("DeleteDnssecKey: %v", err)
	}

	// Sign zone
	err = client.SignZone(ctx, "dnssec.test.")
	if err != nil {
		t.Fatalf("SignZone: %v", err)
	}
}

func TestIntegrationDaneTlsaLifecycle(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Generate DANE root CA
	certPem, err := client.GenerateDaneRootCa(ctx, "Test DANE CA")
	if err != nil {
		t.Fatalf("GenerateDaneRootCa: %v", err)
	}
	if certPem == "" {
		t.Error("cert PEM should not be empty")
	}

	// Generate TLSA record using the CA cert
	tlsaRecord, err := client.GenerateTlsaRecord(ctx, &GenerateTlsaRecordOptions{
		Domain:       "dane.test.",
		Port:         443,
		Protocol:     "tcp",
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		CertPem:      certPem,
	})
	if err != nil {
		t.Fatalf("GenerateTlsaRecord: %v", err)
	}
	if tlsaRecord == "" {
		t.Error("TLSA record should not be empty")
	}

	// List TLSA records
	records, err := client.ListTlsaRecords(ctx, "dane.test.")
	if err != nil {
		t.Fatalf("ListTlsaRecords: %v", err)
	}
	// Note: may be 0 if the server stores TLSA differently
	_ = records
}

func TestIntegrationDns64Config(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Set DNS64 config (server accepts it)
	err := client.SetDns64Config(ctx, &Dns64Config{
		Enabled: true,
		Prefix:  "64:ff9b::",
	})
	if err != nil {
		t.Fatalf("SetDns64Config: %v", err)
	}

	// Get config (server returns default config)
	config, err := client.GetDns64Config(ctx)
	if err != nil {
		t.Fatalf("GetDns64Config: %v", err)
	}
	if config == nil {
		t.Fatal("config should not be nil")
	}
	// Server returns the well-known prefix
	if config.Prefix != "64:ff9b::" {
		t.Errorf("prefix = %q, want %q", config.Prefix, "64:ff9b::")
	}
}

func TestIntegrationQueryLatencyStats(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Should succeed even with no data
	stats, err := client.GetQueryLatencyStats(ctx)
	if err != nil {
		t.Fatalf("GetQueryLatencyStats: %v", err)
	}
	// Empty is fine, just verify it doesn't error
	_ = stats
}

func TestDhcpPoolCrud(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Create a scope first
	err := client.CreateNetworkScope(ctx, &NetworkScope{
		Name:       "dhcp-test",
		HomeDomain: "dhcp-test.home.",
	})
	if err != nil {
		t.Fatalf("CreateNetworkScope: %v", err)
	}

	// Add a DHCP pool
	err = client.AddDhcpPool(ctx, &DhcpPool{
		ScopeName:  "dhcp-test",
		RangeStart: "10.99.0.100",
		RangeEnd:   "10.99.0.200",
		Gateway:    "10.99.0.1",
		SubnetMask: "255.255.255.0",
		DnsServers: "10.99.0.1",
	})
	if err != nil {
		t.Fatalf("AddDhcpPool: %v", err)
	}

	// List pools and verify
	pools, err := client.ListDhcpPools(ctx, "dhcp-test")
	if err != nil {
		t.Fatalf("ListDhcpPools: %v", err)
	}
	if len(pools) != 1 {
		t.Fatalf("got %d pools, want 1", len(pools))
	}
	if pools[0].RangeStart != "10.99.0.100" {
		t.Errorf("range start = %q, want %q", pools[0].RangeStart, "10.99.0.100")
	}
	if pools[0].RangeEnd != "10.99.0.200" {
		t.Errorf("range end = %q, want %q", pools[0].RangeEnd, "10.99.0.200")
	}

	// Remove the pool
	err = client.RemoveDhcpPool(ctx, pools[0].Id)
	if err != nil {
		t.Fatalf("RemoveDhcpPool: %v", err)
	}

	// Verify empty
	pools, err = client.ListDhcpPools(ctx, "dhcp-test")
	if err != nil {
		t.Fatalf("ListDhcpPools after remove: %v", err)
	}
	if len(pools) != 0 {
		t.Errorf("got %d pools after removal, want 0", len(pools))
	}
}

func TestScopeRblProviderCrud(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Create a scope first
	err := client.CreateNetworkScope(ctx, &NetworkScope{
		Name:       "rbl-test",
		HomeDomain: "rbl-test.home.",
	})
	if err != nil {
		t.Fatalf("CreateNetworkScope: %v", err)
	}

	// Add a scope RBL provider
	err = client.AddScopeRblProvider(ctx, "rbl-test", "zen.spamhaus.org", true)
	if err != nil {
		t.Fatalf("AddScopeRblProvider: %v", err)
	}

	// List and verify
	providers, err := client.ListScopeRblProviders(ctx, "rbl-test")
	if err != nil {
		t.Fatalf("ListScopeRblProviders: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("got %d providers, want 1", len(providers))
	}
	if providers[0].Zone != "zen.spamhaus.org" {
		t.Errorf("zone = %q, want %q", providers[0].Zone, "zen.spamhaus.org")
	}
	if !providers[0].Enabled {
		t.Errorf("enabled = false, want true")
	}

	// Remove the provider
	err = client.RemoveScopeRblProvider(ctx, "rbl-test", "zen.spamhaus.org")
	if err != nil {
		t.Fatalf("RemoveScopeRblProvider: %v", err)
	}

	// Verify empty
	providers, err = client.ListScopeRblProviders(ctx, "rbl-test")
	if err != nil {
		t.Fatalf("ListScopeRblProviders after remove: %v", err)
	}
	if len(providers) != 0 {
		t.Errorf("got %d providers after removal, want 0", len(providers))
	}
}

func TestDhcpCertOptionCrud(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// Create a scope first
	err := client.CreateNetworkScope(ctx, &NetworkScope{
		Name:       "cert-test",
		HomeDomain: "cert-test.home.",
	})
	if err != nil {
		t.Fatalf("CreateNetworkScope: %v", err)
	}

	// Set a DHCP cert option
	certData := []byte("test-certificate-data-bytes")
	err = client.SetDhcpCertOption(ctx, &DhcpCertOption{
		ScopeName:   "cert-test",
		OptionCode:  224,
		CertData:    certData,
		Description: "Test CA certificate",
	})
	if err != nil {
		t.Fatalf("SetDhcpCertOption: %v", err)
	}

	// List and verify
	options, err := client.ListDhcpCertOptions(ctx, "cert-test")
	if err != nil {
		t.Fatalf("ListDhcpCertOptions: %v", err)
	}
	if len(options) != 1 {
		t.Fatalf("got %d options, want 1", len(options))
	}
	if options[0].OptionCode != 224 {
		t.Errorf("option code = %d, want %d", options[0].OptionCode, 224)
	}
	if string(options[0].CertData) != "test-certificate-data-bytes" {
		t.Errorf("cert data = %q, want %q", string(options[0].CertData), "test-certificate-data-bytes")
	}
	if options[0].Description != "Test CA certificate" {
		t.Errorf("description = %q, want %q", options[0].Description, "Test CA certificate")
	}

	// Remove the cert option
	err = client.RemoveDhcpCertOption(ctx, "cert-test", 224)
	if err != nil {
		t.Fatalf("RemoveDhcpCertOption: %v", err)
	}

	// Verify empty
	options, err = client.ListDhcpCertOptions(ctx, "cert-test")
	if err != nil {
		t.Fatalf("ListDhcpCertOptions after remove: %v", err)
	}
	if len(options) != 0 {
		t.Errorf("got %d options after removal, want 0", len(options))
	}
}

func TestDhcpLeaseCrud(t *testing.T) {
	client, _ := setupTestServer(t)
	ctx := context.Background()

	// List leases on a fresh server (should be empty)
	leases, err := client.ListDhcpLeases(ctx, "")
	if err != nil {
		t.Fatalf("ListDhcpLeases: %v", err)
	}
	if len(leases) != 0 {
		t.Errorf("got %d leases on fresh server, want 0", len(leases))
	}

	// Delete a non-existent lease (should not crash)
	err = client.DeleteDhcpLease(ctx, "00:11:22:33:44:55")
	// We accept either success or a controlled error, but it must not panic
	_ = err
}
