// Integration tests for the rolodex Go client.
//
// These tests start a real Rolodex server process and exercise the Go client
// against it over both TCP and Unix socket transports. They are fully isolated:
// each test uses a private temporary directory, random ports, and a per-test
// database file.
//
// The tests require the "rolodex" binary to be built first (see Makefile).
// They are gated behind the "integration" build tag so they do not run during
// normal `go test` invocations.

//go:build integration

package rolodex

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

// rolodexBinary returns the path to the pre-built rolodex binary.
func rolodexBinary() string {
	if p := os.Getenv("ROLODEX_BINARY"); p != "" {
		return p
	}
	return "rolodex"
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

// startServer starts a rolodex server process with the given configuration and
// returns a cleanup function that stops the process.
func startServer(t *testing.T, cfg serverConfig) {
	t.Helper()

	configContent := fmt.Sprintf(`
database_path = %q
forwarders = []

[dns]
udp_bind = %q
tcp_bind = %q

[grpc]
tcp_bind = %q
unix_socket = %q
shared_secret = %q

[rbl]
enabled = false
providers = []
`, cfg.dbPath, cfg.dnsUDPAddr, cfg.dnsTCPAddr, cfg.grpcTCPAddr, cfg.unixSocket, cfg.sharedSecret)

	configPath := filepath.Join(cfg.dir, "rolodex.toml")
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
// a rolodex server, and returns a connected TCP client.
func setupTestServer(t *testing.T) (*Client, serverConfig) {
	t.Helper()

	dir := t.TempDir()
	cfg := serverConfig{
		dir:          dir,
		dbPath:       filepath.Join(dir, "rolodex.db"),
		grpcTCPAddr:  allocatePort(t),
		unixSocket:   filepath.Join(dir, "rolodex.sock"),
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
