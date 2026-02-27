package rolodex

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/erikh/rolodex/go/rolodexpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// mockRolodexService is a configurable mock implementation of the gRPC service.
// Each field is a function that, if set, handles the corresponding RPC. If nil,
// the RPC returns an Unimplemented error.
type mockRolodexService struct {
	pb.UnimplementedRolodexServiceServer

	addRecordFn    func(ctx context.Context, req *pb.AddRecordRequest) (*pb.AddRecordResponse, error)
	removeRecordFn func(ctx context.Context, req *pb.RemoveRecordRequest) (*pb.RemoveRecordResponse, error)
	listRecordsFn  func(ctx context.Context, req *pb.ListRecordsRequest) (*pb.ListRecordsResponse, error)
	setForwarderFn func(ctx context.Context, req *pb.SetForwarderRequest) (*pb.SetForwarderResponse, error)
	setRblConfigFn func(ctx context.Context, req *pb.SetRblConfigRequest) (*pb.SetRblConfigResponse, error)
	getRblConfigFn func(ctx context.Context, req *pb.GetRblConfigRequest) (*pb.GetRblConfigResponse, error)
	flushCacheFn   func(ctx context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error)
}

func (m *mockRolodexService) AddRecord(ctx context.Context, req *pb.AddRecordRequest) (*pb.AddRecordResponse, error) {
	if m.addRecordFn != nil {
		return m.addRecordFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) RemoveRecord(ctx context.Context, req *pb.RemoveRecordRequest) (*pb.RemoveRecordResponse, error) {
	if m.removeRecordFn != nil {
		return m.removeRecordFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) ListRecords(ctx context.Context, req *pb.ListRecordsRequest) (*pb.ListRecordsResponse, error) {
	if m.listRecordsFn != nil {
		return m.listRecordsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) SetForwarders(ctx context.Context, req *pb.SetForwarderRequest) (*pb.SetForwarderResponse, error) {
	if m.setForwarderFn != nil {
		return m.setForwarderFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) SetRblConfig(ctx context.Context, req *pb.SetRblConfigRequest) (*pb.SetRblConfigResponse, error) {
	if m.setRblConfigFn != nil {
		return m.setRblConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) GetRblConfig(ctx context.Context, req *pb.GetRblConfigRequest) (*pb.GetRblConfigResponse, error) {
	if m.getRblConfigFn != nil {
		return m.getRblConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) FlushCache(ctx context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
	if m.flushCacheFn != nil {
		return m.flushCacheFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// startMockServer starts an in-process gRPC server using a bufconn listener and
// returns a connected Client. The server is stopped when the test finishes.
func startMockServer(t *testing.T, mock *mockRolodexService, opts ...Option) *Client {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	pb.RegisterRolodexServiceServer(srv, mock)
	t.Cleanup(func() { srv.Stop() })

	go func() {
		if err := srv.Serve(lis); err != nil {
			// Server stopped, expected during cleanup
		}
	}()

	allOpts := append([]Option{
		WithGRPCDialOption(grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		})),
	}, opts...)

	client, err := Dial(context.Background(), "passthrough:///bufconn", allOpts...)
	if err != nil {
		t.Fatalf("failed to dial mock server: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	return client
}

func TestAddRecord(t *testing.T) {
	var captured *pb.AddRecordRequest
	mock := &mockRolodexService{
		addRecordFn: func(_ context.Context, req *pb.AddRecordRequest) (*pb.AddRecordResponse, error) {
			captured = req
			return &pb.AddRecordResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("test-token"))

	err := client.AddRecord(context.Background(), &DnsRecord{
		Name:       "test.example.com.",
		RecordType: RecordTypeA,
		Value:      "192.168.1.1",
		Ttl:        600,
		Priority:   0,
	})
	if err != nil {
		t.Fatalf("AddRecord returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.AuthToken != "test-token" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "test-token")
	}
	if captured.Record.Name != "test.example.com." {
		t.Errorf("record name = %q, want %q", captured.Record.Name, "test.example.com.")
	}
	if captured.Record.Value != "192.168.1.1" {
		t.Errorf("record value = %q, want %q", captured.Record.Value, "192.168.1.1")
	}
	if captured.Record.Ttl != 600 {
		t.Errorf("record ttl = %d, want %d", captured.Record.Ttl, 600)
	}
}

func TestAddRecordServerFailure(t *testing.T) {
	mock := &mockRolodexService{
		addRecordFn: func(_ context.Context, req *pb.AddRecordRequest) (*pb.AddRecordResponse, error) {
			return &pb.AddRecordResponse{Success: false, Message: "db error"}, nil
		},
	}
	client := startMockServer(t, mock)

	err := client.AddRecord(context.Background(), &DnsRecord{
		Name:       "test.example.com.",
		RecordType: RecordTypeA,
		Value:      "192.168.1.1",
	})
	if err == nil {
		t.Fatal("expected error from server failure")
	}
}

func TestAddRecordRPCError(t *testing.T) {
	mock := &mockRolodexService{
		addRecordFn: func(_ context.Context, req *pb.AddRecordRequest) (*pb.AddRecordResponse, error) {
			return nil, status.Error(codes.Unauthenticated, "invalid auth token")
		},
	}
	client := startMockServer(t, mock)

	err := client.AddRecord(context.Background(), &DnsRecord{
		Name:       "test.example.com.",
		RecordType: RecordTypeA,
		Value:      "192.168.1.1",
	})
	if err == nil {
		t.Fatal("expected error from RPC failure")
	}
}

func TestRemoveRecord(t *testing.T) {
	var captured *pb.RemoveRecordRequest
	mock := &mockRolodexService{
		removeRecordFn: func(_ context.Context, req *pb.RemoveRecordRequest) (*pb.RemoveRecordResponse, error) {
			captured = req
			return &pb.RemoveRecordResponse{Success: true, RemovedCount: 2}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("secret"))

	count, err := client.RemoveRecord(context.Background(), "test.example.com.", nil)
	if err != nil {
		t.Fatalf("RemoveRecord returned error: %v", err)
	}
	if count != 2 {
		t.Errorf("removed count = %d, want %d", count, 2)
	}
	if captured.Name != "test.example.com." {
		t.Errorf("name = %q, want %q", captured.Name, "test.example.com.")
	}
	if captured.AuthToken != "secret" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "secret")
	}
}

func TestRemoveRecordWithOptions(t *testing.T) {
	var captured *pb.RemoveRecordRequest
	mock := &mockRolodexService{
		removeRecordFn: func(_ context.Context, req *pb.RemoveRecordRequest) (*pb.RemoveRecordResponse, error) {
			captured = req
			return &pb.RemoveRecordResponse{Success: true, RemovedCount: 1}, nil
		},
	}
	client := startMockServer(t, mock)

	rt := RecordTypeAAAA
	count, err := client.RemoveRecord(context.Background(), "test.example.com.", &RemoveRecordOptions{
		RecordType: &rt,
		Value:      "::1",
	})
	if err != nil {
		t.Fatalf("RemoveRecord returned error: %v", err)
	}
	if count != 1 {
		t.Errorf("removed count = %d, want %d", count, 1)
	}
	if captured.RecordType != pb.RecordType_AAAA {
		t.Errorf("record type = %v, want AAAA", captured.RecordType)
	}
	if captured.Value != "::1" {
		t.Errorf("value = %q, want %q", captured.Value, "::1")
	}
}

func TestRemoveRecordServerFailure(t *testing.T) {
	mock := &mockRolodexService{
		removeRecordFn: func(_ context.Context, req *pb.RemoveRecordRequest) (*pb.RemoveRecordResponse, error) {
			return &pb.RemoveRecordResponse{Success: false, Message: "not found"}, nil
		},
	}
	client := startMockServer(t, mock)

	_, err := client.RemoveRecord(context.Background(), "test.example.com.", nil)
	if err == nil {
		t.Fatal("expected error from server failure")
	}
}

func TestListRecords(t *testing.T) {
	mock := &mockRolodexService{
		listRecordsFn: func(_ context.Context, req *pb.ListRecordsRequest) (*pb.ListRecordsResponse, error) {
			return &pb.ListRecordsResponse{
				Records: []*pb.DnsRecord{
					{Name: "a.example.com.", RecordType: pb.RecordType_A, Value: "10.0.0.1", Ttl: 300},
					{Name: "b.example.com.", RecordType: pb.RecordType_A, Value: "10.0.0.2", Ttl: 300},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock)

	records, err := client.ListRecords(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListRecords returned error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0].Name != "a.example.com." {
		t.Errorf("record[0].Name = %q, want %q", records[0].Name, "a.example.com.")
	}
}

func TestListRecordsWithFilters(t *testing.T) {
	var captured *pb.ListRecordsRequest
	mock := &mockRolodexService{
		listRecordsFn: func(_ context.Context, req *pb.ListRecordsRequest) (*pb.ListRecordsResponse, error) {
			captured = req
			return &pb.ListRecordsResponse{}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tk"))

	rt := RecordTypeMX
	_, err := client.ListRecords(context.Background(), &ListRecordsOptions{
		NameFilter: "*.example.com.",
		RecordType: &rt,
	})
	if err != nil {
		t.Fatalf("ListRecords returned error: %v", err)
	}
	if captured.NameFilter != "*.example.com." {
		t.Errorf("name filter = %q, want %q", captured.NameFilter, "*.example.com.")
	}
	if !captured.FilterByType {
		t.Error("filter_by_type should be true")
	}
	if captured.RecordTypeFilter != pb.RecordType_MX {
		t.Errorf("record type filter = %v, want MX", captured.RecordTypeFilter)
	}
	if captured.AuthToken != "tk" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tk")
	}
}

func TestSetForwarders(t *testing.T) {
	var captured *pb.SetForwarderRequest
	mock := &mockRolodexService{
		setForwarderFn: func(_ context.Context, req *pb.SetForwarderRequest) (*pb.SetForwarderResponse, error) {
			captured = req
			return &pb.SetForwarderResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock)

	err := client.SetForwarders(context.Background(), []string{"8.8.8.8:53", "1.1.1.1:53"})
	if err != nil {
		t.Fatalf("SetForwarders returned error: %v", err)
	}
	if len(captured.Forwarders) != 2 {
		t.Fatalf("got %d forwarders, want 2", len(captured.Forwarders))
	}
	if captured.Forwarders[0] != "8.8.8.8:53" {
		t.Errorf("forwarder[0] = %q, want %q", captured.Forwarders[0], "8.8.8.8:53")
	}
}

func TestSetForwardersServerFailure(t *testing.T) {
	mock := &mockRolodexService{
		setForwarderFn: func(_ context.Context, req *pb.SetForwarderRequest) (*pb.SetForwarderResponse, error) {
			return &pb.SetForwarderResponse{Success: false, Message: "bad address"}, nil
		},
	}
	client := startMockServer(t, mock)

	err := client.SetForwarders(context.Background(), []string{"invalid"})
	if err == nil {
		t.Fatal("expected error from server failure")
	}
}

func TestSetRblConfig(t *testing.T) {
	var captured *pb.SetRblConfigRequest
	mock := &mockRolodexService{
		setRblConfigFn: func(_ context.Context, req *pb.SetRblConfigRequest) (*pb.SetRblConfigResponse, error) {
			captured = req
			return &pb.SetRblConfigResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock)

	err := client.SetRblConfig(context.Background(), true, []*RblConfig{
		{Zone: "zen.spamhaus.org", Enabled: true},
		{Zone: "bl.spamcop.net", Enabled: false},
	})
	if err != nil {
		t.Fatalf("SetRblConfig returned error: %v", err)
	}
	if !captured.Enabled {
		t.Error("enabled should be true")
	}
	if len(captured.Providers) != 2 {
		t.Fatalf("got %d providers, want 2", len(captured.Providers))
	}
	if captured.Providers[0].Zone != "zen.spamhaus.org" {
		t.Errorf("provider[0].zone = %q, want %q", captured.Providers[0].Zone, "zen.spamhaus.org")
	}
	if !captured.Providers[0].Enabled {
		t.Error("provider[0].enabled should be true")
	}
	if captured.Providers[1].Enabled {
		t.Error("provider[1].enabled should be false")
	}
}

func TestGetRblConfig(t *testing.T) {
	mock := &mockRolodexService{
		getRblConfigFn: func(_ context.Context, req *pb.GetRblConfigRequest) (*pb.GetRblConfigResponse, error) {
			return &pb.GetRblConfigResponse{
				Enabled: true,
				Providers: []*pb.RblConfig{
					{Zone: "zen.spamhaus.org", Enabled: true},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock)

	rblStatus, err := client.GetRblConfig(context.Background())
	if err != nil {
		t.Fatalf("GetRblConfig returned error: %v", err)
	}
	if !rblStatus.Enabled {
		t.Error("enabled should be true")
	}
	if len(rblStatus.Providers) != 1 {
		t.Fatalf("got %d providers, want 1", len(rblStatus.Providers))
	}
	if rblStatus.Providers[0].Zone != "zen.spamhaus.org" {
		t.Errorf("provider zone = %q, want %q", rblStatus.Providers[0].Zone, "zen.spamhaus.org")
	}
}

func TestFlushCache(t *testing.T) {
	var captured *pb.FlushCacheRequest
	mock := &mockRolodexService{
		flushCacheFn: func(_ context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
			captured = req
			return &pb.FlushCacheResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("s"))

	err := client.FlushCache(context.Background())
	if err != nil {
		t.Fatalf("FlushCache returned error: %v", err)
	}
	if captured.AuthToken != "s" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "s")
	}
}

func TestFlushCacheServerFailure(t *testing.T) {
	mock := &mockRolodexService{
		flushCacheFn: func(_ context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
			return &pb.FlushCacheResponse{Success: false, Message: "cache error"}, nil
		},
	}
	client := startMockServer(t, mock)

	err := client.FlushCache(context.Background())
	if err == nil {
		t.Fatal("expected error from server failure")
	}
}

func TestDialUnixSocket(t *testing.T) {
	// Create a temporary directory for the socket
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	// Start a gRPC server on the Unix socket
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}

	mock := &mockRolodexService{
		flushCacheFn: func(_ context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
			return &pb.FlushCacheResponse{Success: true}, nil
		},
	}
	srv := grpc.NewServer()
	pb.RegisterRolodexServiceServer(srv, mock)
	t.Cleanup(func() { srv.Stop() })

	go func() {
		if err := srv.Serve(lis); err != nil {
			// expected during cleanup
		}
	}()

	// Connect via Unix socket
	client, err := Dial(context.Background(), socketPath, WithUnixSocket())
	if err != nil {
		t.Fatalf("Dial unix socket failed: %v", err)
	}
	defer client.Close()

	err = client.FlushCache(context.Background())
	if err != nil {
		t.Fatalf("FlushCache over unix socket failed: %v", err)
	}
}

func TestDialTCP(t *testing.T) {
	// Start a gRPC server on a random TCP port
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	mock := &mockRolodexService{
		listRecordsFn: func(_ context.Context, req *pb.ListRecordsRequest) (*pb.ListRecordsResponse, error) {
			if req.AuthToken != "my-secret" {
				return nil, status.Error(codes.Unauthenticated, "bad token")
			}
			return &pb.ListRecordsResponse{}, nil
		},
	}
	srv := grpc.NewServer()
	pb.RegisterRolodexServiceServer(srv, mock)
	t.Cleanup(func() { srv.Stop() })

	go func() {
		if err := srv.Serve(lis); err != nil {
			// expected during cleanup
		}
	}()

	// Connect via TCP
	client, err := Dial(context.Background(), lis.Addr().String(), WithAuthToken("my-secret"))
	if err != nil {
		t.Fatalf("Dial TCP failed: %v", err)
	}
	defer client.Close()

	records, err := client.ListRecords(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListRecords over TCP failed: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("got %d records, want 0", len(records))
	}
}

func TestAuthTokenSentWithAllRPCs(t *testing.T) {
	// Verify the auth token is propagated for each RPC method
	tokens := make(map[string]string)
	mock := &mockRolodexService{
		addRecordFn: func(_ context.Context, req *pb.AddRecordRequest) (*pb.AddRecordResponse, error) {
			tokens["add"] = req.AuthToken
			return &pb.AddRecordResponse{Success: true}, nil
		},
		removeRecordFn: func(_ context.Context, req *pb.RemoveRecordRequest) (*pb.RemoveRecordResponse, error) {
			tokens["remove"] = req.AuthToken
			return &pb.RemoveRecordResponse{Success: true}, nil
		},
		listRecordsFn: func(_ context.Context, req *pb.ListRecordsRequest) (*pb.ListRecordsResponse, error) {
			tokens["list"] = req.AuthToken
			return &pb.ListRecordsResponse{}, nil
		},
		setForwarderFn: func(_ context.Context, req *pb.SetForwarderRequest) (*pb.SetForwarderResponse, error) {
			tokens["forwarders"] = req.AuthToken
			return &pb.SetForwarderResponse{Success: true}, nil
		},
		setRblConfigFn: func(_ context.Context, req *pb.SetRblConfigRequest) (*pb.SetRblConfigResponse, error) {
			tokens["setrbl"] = req.AuthToken
			return &pb.SetRblConfigResponse{Success: true}, nil
		},
		getRblConfigFn: func(_ context.Context, req *pb.GetRblConfigRequest) (*pb.GetRblConfigResponse, error) {
			tokens["getrbl"] = req.AuthToken
			return &pb.GetRblConfigResponse{}, nil
		},
		flushCacheFn: func(_ context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
			tokens["flush"] = req.AuthToken
			return &pb.FlushCacheResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("shared"))
	ctx := context.Background()

	if err := client.AddRecord(ctx, &DnsRecord{Name: "x.", RecordType: RecordTypeA, Value: "1.2.3.4"}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	if _, err := client.RemoveRecord(ctx, "x.", nil); err != nil {
		t.Fatalf("RemoveRecord: %v", err)
	}
	if _, err := client.ListRecords(ctx, nil); err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if err := client.SetForwarders(ctx, []string{"8.8.8.8:53"}); err != nil {
		t.Fatalf("SetForwarders: %v", err)
	}
	if err := client.SetRblConfig(ctx, false, nil); err != nil {
		t.Fatalf("SetRblConfig: %v", err)
	}
	if _, err := client.GetRblConfig(ctx); err != nil {
		t.Fatalf("GetRblConfig: %v", err)
	}
	if err := client.FlushCache(ctx); err != nil {
		t.Fatalf("FlushCache: %v", err)
	}

	for method, tok := range tokens {
		if tok != "shared" {
			t.Errorf("%s: auth token = %q, want %q", method, tok, "shared")
		}
	}
	if len(tokens) != 7 {
		t.Errorf("expected 7 RPCs, got %d", len(tokens))
	}
}

func TestNoAuthToken(t *testing.T) {
	var captured string
	mock := &mockRolodexService{
		flushCacheFn: func(_ context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
			captured = req.AuthToken
			return &pb.FlushCacheResponse{Success: true}, nil
		},
	}
	// No WithAuthToken - should send empty string
	client := startMockServer(t, mock)

	_ = client.FlushCache(context.Background())
	if captured != "" {
		t.Errorf("auth token = %q, want empty", captured)
	}
}

func TestRecordTypeConstants(t *testing.T) {
	// Verify our constants match proto values
	tests := []struct {
		name string
		got  RecordType
		want int32
	}{
		{"A", RecordTypeA, 0},
		{"AAAA", RecordTypeAAAA, 1},
		{"CNAME", RecordTypeCNAME, 2},
		{"MX", RecordTypeMX, 3},
		{"TXT", RecordTypeTXT, 4},
		{"NS", RecordTypeNS, 5},
		{"SOA", RecordTypeSOA, 6},
		{"SRV", RecordTypeSRV, 7},
		{"PTR", RecordTypePTR, 8},
	}
	for _, tt := range tests {
		if int32(tt.got) != tt.want {
			t.Errorf("RecordType%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func TestCloseIdempotent(t *testing.T) {
	mock := &mockRolodexService{}
	client := startMockServer(t, mock)
	// startMockServer already registers Close via t.Cleanup, but we explicitly call it
	// here to ensure it doesn't panic. The second close from cleanup should also not panic.
	if err := client.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestDialInvalidAddress(t *testing.T) {
	// Dial with an invalid address should not error at dial time (lazy connection)
	// but should fail on actual RPC call
	client, err := Dial(context.Background(), "localhost:0")
	if err != nil {
		t.Fatalf("Dial returned unexpected error: %v", err)
	}
	defer client.Close()

	// Attempt an RPC - this should fail
	err = client.FlushCache(context.Background())
	if err == nil {
		t.Fatal("expected error from RPC to invalid address")
	}
}

func TestWithGRPCDialOption(t *testing.T) {
	// Test that custom gRPC dial options are passed through
	mock := &mockRolodexService{
		flushCacheFn: func(_ context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
			return &pb.FlushCacheResponse{Success: true}, nil
		},
	}

	// Start a real TCP server
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterRolodexServiceServer(srv, mock)
	t.Cleanup(func() { srv.Stop() })
	go func() { _ = srv.Serve(lis) }()

	// Use WithGRPCDialOption to set a custom option
	client, err := Dial(context.Background(), lis.Addr().String(),
		WithGRPCDialOption(grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024*1024))),
	)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer client.Close()

	err = client.FlushCache(context.Background())
	if err != nil {
		t.Fatalf("FlushCache failed: %v", err)
	}
}

func TestUnixSocketEnvFile(t *testing.T) {
	// Test that WithUnixSocket uses the unix dialer path
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "rolodex.sock")

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	var capturedToken string
	mock := &mockRolodexService{
		flushCacheFn: func(_ context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
			capturedToken = req.AuthToken
			return &pb.FlushCacheResponse{Success: true}, nil
		},
	}
	srv := grpc.NewServer()
	pb.RegisterRolodexServiceServer(srv, mock)
	t.Cleanup(func() { srv.Stop() })
	go func() { _ = srv.Serve(lis) }()

	// Connect with auth token over unix socket
	// Server-side would ignore the token, but client should still send it
	client, err := Dial(context.Background(), socketPath,
		WithUnixSocket(),
		WithAuthToken("should-be-sent"),
	)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer client.Close()

	err = client.FlushCache(context.Background())
	if err != nil {
		t.Fatalf("FlushCache failed: %v", err)
	}
	if capturedToken != "should-be-sent" {
		t.Errorf("token = %q, want %q", capturedToken, "should-be-sent")
	}

	// Verify socket file exists
	if _, err := os.Stat(socketPath); err != nil {
		t.Errorf("socket file should exist: %v", err)
	}
}
