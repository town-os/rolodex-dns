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

	addRecordFn              func(ctx context.Context, req *pb.AddRecordRequest) (*pb.AddRecordResponse, error)
	removeRecordFn           func(ctx context.Context, req *pb.RemoveRecordRequest) (*pb.RemoveRecordResponse, error)
	listRecordsFn            func(ctx context.Context, req *pb.ListRecordsRequest) (*pb.ListRecordsResponse, error)
	setForwarderFn           func(ctx context.Context, req *pb.SetForwarderRequest) (*pb.SetForwarderResponse, error)
	setRblConfigFn           func(ctx context.Context, req *pb.SetRblConfigRequest) (*pb.SetRblConfigResponse, error)
	getRblConfigFn           func(ctx context.Context, req *pb.GetRblConfigRequest) (*pb.GetRblConfigResponse, error)
	flushCacheFn             func(ctx context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error)
	createNetworkScopeFn     func(ctx context.Context, req *pb.CreateNetworkScopeRequest) (*pb.CreateNetworkScopeResponse, error)
	deleteNetworkScopeFn     func(ctx context.Context, req *pb.DeleteNetworkScopeRequest) (*pb.DeleteNetworkScopeResponse, error)
	listNetworkScopesFn      func(ctx context.Context, req *pb.ListNetworkScopesRequest) (*pb.ListNetworkScopesResponse, error)
	joinNetworkFn            func(ctx context.Context, req *pb.JoinNetworkRequest) (*pb.JoinNetworkResponse, error)
	leaveNetworkFn           func(ctx context.Context, req *pb.LeaveNetworkRequest) (*pb.LeaveNetworkResponse, error)
	getNetworkAssociationsFn func(ctx context.Context, req *pb.GetNetworkAssociationsRequest) (*pb.GetNetworkAssociationsResponse, error)
	addScopedRecordFn        func(ctx context.Context, req *pb.AddScopedRecordRequest) (*pb.AddScopedRecordResponse, error)
	removeScopedRecordFn     func(ctx context.Context, req *pb.RemoveScopedRecordRequest) (*pb.RemoveScopedRecordResponse, error)
	listScopedRecordsFn      func(ctx context.Context, req *pb.ListScopedRecordsRequest) (*pb.ListScopedRecordsResponse, error)
	getSearchDomainsFn       func(ctx context.Context, req *pb.GetSearchDomainsRequest) (*pb.GetSearchDomainsResponse, error)
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

func (m *mockRolodexService) CreateNetworkScope(ctx context.Context, req *pb.CreateNetworkScopeRequest) (*pb.CreateNetworkScopeResponse, error) {
	if m.createNetworkScopeFn != nil {
		return m.createNetworkScopeFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) DeleteNetworkScope(ctx context.Context, req *pb.DeleteNetworkScopeRequest) (*pb.DeleteNetworkScopeResponse, error) {
	if m.deleteNetworkScopeFn != nil {
		return m.deleteNetworkScopeFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) ListNetworkScopes(ctx context.Context, req *pb.ListNetworkScopesRequest) (*pb.ListNetworkScopesResponse, error) {
	if m.listNetworkScopesFn != nil {
		return m.listNetworkScopesFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) JoinNetwork(ctx context.Context, req *pb.JoinNetworkRequest) (*pb.JoinNetworkResponse, error) {
	if m.joinNetworkFn != nil {
		return m.joinNetworkFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) LeaveNetwork(ctx context.Context, req *pb.LeaveNetworkRequest) (*pb.LeaveNetworkResponse, error) {
	if m.leaveNetworkFn != nil {
		return m.leaveNetworkFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) GetNetworkAssociations(ctx context.Context, req *pb.GetNetworkAssociationsRequest) (*pb.GetNetworkAssociationsResponse, error) {
	if m.getNetworkAssociationsFn != nil {
		return m.getNetworkAssociationsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) AddScopedRecord(ctx context.Context, req *pb.AddScopedRecordRequest) (*pb.AddScopedRecordResponse, error) {
	if m.addScopedRecordFn != nil {
		return m.addScopedRecordFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) RemoveScopedRecord(ctx context.Context, req *pb.RemoveScopedRecordRequest) (*pb.RemoveScopedRecordResponse, error) {
	if m.removeScopedRecordFn != nil {
		return m.removeScopedRecordFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) ListScopedRecords(ctx context.Context, req *pb.ListScopedRecordsRequest) (*pb.ListScopedRecordsResponse, error) {
	if m.listScopedRecordsFn != nil {
		return m.listScopedRecordsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexService) GetSearchDomains(ctx context.Context, req *pb.GetSearchDomainsRequest) (*pb.GetSearchDomainsResponse, error) {
	if m.getSearchDomainsFn != nil {
		return m.getSearchDomainsFn(ctx, req)
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

func TestCreateNetworkScope(t *testing.T) {
	var captured *pb.CreateNetworkScopeRequest
	mock := &mockRolodexService{
		createNetworkScopeFn: func(_ context.Context, req *pb.CreateNetworkScopeRequest) (*pb.CreateNetworkScopeResponse, error) {
			captured = req
			return &pb.CreateNetworkScopeResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tk"))

	err := client.CreateNetworkScope(context.Background(), &NetworkScope{
		Name:       "office",
		HomeDomain: "office.home.",
	})
	if err != nil {
		t.Fatalf("CreateNetworkScope returned error: %v", err)
	}
	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.AuthToken != "tk" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tk")
	}
	if captured.Scope.Name != "office" {
		t.Errorf("scope name = %q, want %q", captured.Scope.Name, "office")
	}
	if captured.Scope.HomeDomain != "office.home." {
		t.Errorf("home domain = %q, want %q", captured.Scope.HomeDomain, "office.home.")
	}
}

func TestCreateNetworkScopeServerFailure(t *testing.T) {
	mock := &mockRolodexService{
		createNetworkScopeFn: func(_ context.Context, req *pb.CreateNetworkScopeRequest) (*pb.CreateNetworkScopeResponse, error) {
			return &pb.CreateNetworkScopeResponse{Success: false, Message: "already exists"}, nil
		},
	}
	client := startMockServer(t, mock)

	err := client.CreateNetworkScope(context.Background(), &NetworkScope{Name: "office"})
	if err == nil {
		t.Fatal("expected error from server failure")
	}
}

func TestDeleteNetworkScope(t *testing.T) {
	var captured *pb.DeleteNetworkScopeRequest
	mock := &mockRolodexService{
		deleteNetworkScopeFn: func(_ context.Context, req *pb.DeleteNetworkScopeRequest) (*pb.DeleteNetworkScopeResponse, error) {
			captured = req
			return &pb.DeleteNetworkScopeResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tk"))

	err := client.DeleteNetworkScope(context.Background(), "office")
	if err != nil {
		t.Fatalf("DeleteNetworkScope returned error: %v", err)
	}
	if captured.Name != "office" {
		t.Errorf("name = %q, want %q", captured.Name, "office")
	}
	if captured.AuthToken != "tk" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tk")
	}
}

func TestListNetworkScopes(t *testing.T) {
	mock := &mockRolodexService{
		listNetworkScopesFn: func(_ context.Context, req *pb.ListNetworkScopesRequest) (*pb.ListNetworkScopesResponse, error) {
			return &pb.ListNetworkScopesResponse{
				Scopes: []*pb.NetworkScope{
					{Name: "office", HomeDomain: "office.home."},
					{Name: "lab", HomeDomain: "lab.home."},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock)

	scopes, err := client.ListNetworkScopes(context.Background())
	if err != nil {
		t.Fatalf("ListNetworkScopes returned error: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("got %d scopes, want 2", len(scopes))
	}
	if scopes[0].Name != "office" {
		t.Errorf("scope[0].Name = %q, want %q", scopes[0].Name, "office")
	}
	if scopes[1].Name != "lab" {
		t.Errorf("scope[1].Name = %q, want %q", scopes[1].Name, "lab")
	}
}

func TestJoinNetwork(t *testing.T) {
	var captured *pb.JoinNetworkRequest
	mock := &mockRolodexService{
		joinNetworkFn: func(_ context.Context, req *pb.JoinNetworkRequest) (*pb.JoinNetworkResponse, error) {
			captured = req
			return &pb.JoinNetworkResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tk"))

	err := client.JoinNetwork(context.Background(), "192.168.1.100", "office", 600)
	if err != nil {
		t.Fatalf("JoinNetwork returned error: %v", err)
	}
	if captured.IpAddress != "192.168.1.100" {
		t.Errorf("ip = %q, want %q", captured.IpAddress, "192.168.1.100")
	}
	if captured.ScopeName != "office" {
		t.Errorf("scope = %q, want %q", captured.ScopeName, "office")
	}
	if captured.TtlSeconds != 600 {
		t.Errorf("ttl = %d, want %d", captured.TtlSeconds, 600)
	}
	if captured.AuthToken != "tk" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tk")
	}
}

func TestJoinNetworkServerFailure(t *testing.T) {
	mock := &mockRolodexService{
		joinNetworkFn: func(_ context.Context, req *pb.JoinNetworkRequest) (*pb.JoinNetworkResponse, error) {
			return &pb.JoinNetworkResponse{Success: false, Message: "scope not found"}, nil
		},
	}
	client := startMockServer(t, mock)

	err := client.JoinNetwork(context.Background(), "192.168.1.100", "nonexistent", 300)
	if err == nil {
		t.Fatal("expected error from server failure")
	}
}

func TestLeaveNetwork(t *testing.T) {
	var captured *pb.LeaveNetworkRequest
	mock := &mockRolodexService{
		leaveNetworkFn: func(_ context.Context, req *pb.LeaveNetworkRequest) (*pb.LeaveNetworkResponse, error) {
			captured = req
			return &pb.LeaveNetworkResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tk"))

	err := client.LeaveNetwork(context.Background(), "192.168.1.100")
	if err != nil {
		t.Fatalf("LeaveNetwork returned error: %v", err)
	}
	if captured.IpAddress != "192.168.1.100" {
		t.Errorf("ip = %q, want %q", captured.IpAddress, "192.168.1.100")
	}
	if captured.AuthToken != "tk" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tk")
	}
}

func TestGetNetworkAssociations(t *testing.T) {
	mock := &mockRolodexService{
		getNetworkAssociationsFn: func(_ context.Context, req *pb.GetNetworkAssociationsRequest) (*pb.GetNetworkAssociationsResponse, error) {
			return &pb.GetNetworkAssociationsResponse{
				Associations: []*pb.NetworkAssociation{
					{IpAddress: "192.168.1.100", ScopeName: "office", TtlSeconds: 300},
					{IpAddress: "10.0.0.5", ScopeName: "lab", TtlSeconds: 600},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock)

	assocs, err := client.GetNetworkAssociations(context.Background(), "")
	if err != nil {
		t.Fatalf("GetNetworkAssociations returned error: %v", err)
	}
	if len(assocs) != 2 {
		t.Fatalf("got %d associations, want 2", len(assocs))
	}
	if assocs[0].IpAddress != "192.168.1.100" {
		t.Errorf("assoc[0].IpAddress = %q, want %q", assocs[0].IpAddress, "192.168.1.100")
	}
	if assocs[0].ScopeName != "office" {
		t.Errorf("assoc[0].ScopeName = %q, want %q", assocs[0].ScopeName, "office")
	}
}

func TestGetNetworkAssociationsFiltered(t *testing.T) {
	var captured *pb.GetNetworkAssociationsRequest
	mock := &mockRolodexService{
		getNetworkAssociationsFn: func(_ context.Context, req *pb.GetNetworkAssociationsRequest) (*pb.GetNetworkAssociationsResponse, error) {
			captured = req
			return &pb.GetNetworkAssociationsResponse{}, nil
		},
	}
	client := startMockServer(t, mock)

	_, err := client.GetNetworkAssociations(context.Background(), "office")
	if err != nil {
		t.Fatalf("GetNetworkAssociations returned error: %v", err)
	}
	if captured.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.ScopeName, "office")
	}
}

func TestAddScopedRecord(t *testing.T) {
	var captured *pb.AddScopedRecordRequest
	mock := &mockRolodexService{
		addScopedRecordFn: func(_ context.Context, req *pb.AddScopedRecordRequest) (*pb.AddScopedRecordResponse, error) {
			captured = req
			return &pb.AddScopedRecordResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tk"))

	err := client.AddScopedRecord(context.Background(), "office", &DnsRecord{
		Name:       "host1.office.home.",
		RecordType: RecordTypeA,
		Value:      "192.168.1.10",
		Ttl:        600,
	})
	if err != nil {
		t.Fatalf("AddScopedRecord returned error: %v", err)
	}
	if captured.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.ScopeName, "office")
	}
	if captured.Record.Name != "host1.office.home." {
		t.Errorf("record name = %q, want %q", captured.Record.Name, "host1.office.home.")
	}
	if captured.Record.Value != "192.168.1.10" {
		t.Errorf("record value = %q, want %q", captured.Record.Value, "192.168.1.10")
	}
	if captured.AuthToken != "tk" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tk")
	}
}

func TestAddScopedRecordServerFailure(t *testing.T) {
	mock := &mockRolodexService{
		addScopedRecordFn: func(_ context.Context, req *pb.AddScopedRecordRequest) (*pb.AddScopedRecordResponse, error) {
			return &pb.AddScopedRecordResponse{Success: false, Message: "scope not found"}, nil
		},
	}
	client := startMockServer(t, mock)

	err := client.AddScopedRecord(context.Background(), "nonexistent", &DnsRecord{
		Name: "x.", RecordType: RecordTypeA, Value: "1.2.3.4",
	})
	if err == nil {
		t.Fatal("expected error from server failure")
	}
}

func TestRemoveScopedRecord(t *testing.T) {
	var captured *pb.RemoveScopedRecordRequest
	mock := &mockRolodexService{
		removeScopedRecordFn: func(_ context.Context, req *pb.RemoveScopedRecordRequest) (*pb.RemoveScopedRecordResponse, error) {
			captured = req
			return &pb.RemoveScopedRecordResponse{Success: true, RemovedCount: 1}, nil
		},
	}
	client := startMockServer(t, mock)

	count, err := client.RemoveScopedRecord(context.Background(), "office", "host1.office.home.", nil)
	if err != nil {
		t.Fatalf("RemoveScopedRecord returned error: %v", err)
	}
	if count != 1 {
		t.Errorf("removed count = %d, want 1", count)
	}
	if captured.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.ScopeName, "office")
	}
	if captured.Name != "host1.office.home." {
		t.Errorf("name = %q, want %q", captured.Name, "host1.office.home.")
	}
}

func TestRemoveScopedRecordWithOptions(t *testing.T) {
	var captured *pb.RemoveScopedRecordRequest
	mock := &mockRolodexService{
		removeScopedRecordFn: func(_ context.Context, req *pb.RemoveScopedRecordRequest) (*pb.RemoveScopedRecordResponse, error) {
			captured = req
			return &pb.RemoveScopedRecordResponse{Success: true, RemovedCount: 1}, nil
		},
	}
	client := startMockServer(t, mock)

	rt := RecordTypeA
	count, err := client.RemoveScopedRecord(context.Background(), "office", "host1.office.home.", &RemoveScopedRecordOptions{
		RecordType: &rt,
		Value:      "192.168.1.10",
	})
	if err != nil {
		t.Fatalf("RemoveScopedRecord returned error: %v", err)
	}
	if count != 1 {
		t.Errorf("removed count = %d, want 1", count)
	}
	if captured.RecordType != pb.RecordType_A {
		t.Errorf("record type = %v, want A", captured.RecordType)
	}
	if captured.Value != "192.168.1.10" {
		t.Errorf("value = %q, want %q", captured.Value, "192.168.1.10")
	}
}

func TestListScopedRecords(t *testing.T) {
	mock := &mockRolodexService{
		listScopedRecordsFn: func(_ context.Context, req *pb.ListScopedRecordsRequest) (*pb.ListScopedRecordsResponse, error) {
			return &pb.ListScopedRecordsResponse{
				Records: []*pb.DnsRecord{
					{Name: "host1.office.home.", RecordType: pb.RecordType_A, Value: "192.168.1.10", Ttl: 300},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock)

	records, err := client.ListScopedRecords(context.Background(), "office", nil)
	if err != nil {
		t.Fatalf("ListScopedRecords returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Name != "host1.office.home." {
		t.Errorf("record name = %q, want %q", records[0].Name, "host1.office.home.")
	}
}

func TestListScopedRecordsWithFilters(t *testing.T) {
	var captured *pb.ListScopedRecordsRequest
	mock := &mockRolodexService{
		listScopedRecordsFn: func(_ context.Context, req *pb.ListScopedRecordsRequest) (*pb.ListScopedRecordsResponse, error) {
			captured = req
			return &pb.ListScopedRecordsResponse{}, nil
		},
	}
	client := startMockServer(t, mock)

	rt := RecordTypeAAAA
	_, err := client.ListScopedRecords(context.Background(), "office", &ListScopedRecordsOptions{
		NameFilter: "*.office.home.",
		RecordType: &rt,
	})
	if err != nil {
		t.Fatalf("ListScopedRecords returned error: %v", err)
	}
	if captured.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.ScopeName, "office")
	}
	if captured.NameFilter != "*.office.home." {
		t.Errorf("name filter = %q, want %q", captured.NameFilter, "*.office.home.")
	}
	if !captured.FilterByType {
		t.Error("filter_by_type should be true")
	}
	if captured.RecordTypeFilter != pb.RecordType_AAAA {
		t.Errorf("record type filter = %v, want AAAA", captured.RecordTypeFilter)
	}
}

func TestGetSearchDomains(t *testing.T) {
	mock := &mockRolodexService{
		getSearchDomainsFn: func(_ context.Context, req *pb.GetSearchDomainsRequest) (*pb.GetSearchDomainsResponse, error) {
			return &pb.GetSearchDomainsResponse{
				SearchDomains: []string{"office.home."},
			}, nil
		},
	}
	client := startMockServer(t, mock)

	domains, err := client.GetSearchDomains(context.Background(), "192.168.1.100")
	if err != nil {
		t.Fatalf("GetSearchDomains returned error: %v", err)
	}
	if len(domains) != 1 {
		t.Fatalf("got %d domains, want 1", len(domains))
	}
	if domains[0] != "office.home." {
		t.Errorf("domain = %q, want %q", domains[0], "office.home.")
	}
}

func TestGetSearchDomainsAuthToken(t *testing.T) {
	var captured *pb.GetSearchDomainsRequest
	mock := &mockRolodexService{
		getSearchDomainsFn: func(_ context.Context, req *pb.GetSearchDomainsRequest) (*pb.GetSearchDomainsResponse, error) {
			captured = req
			return &pb.GetSearchDomainsResponse{}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("secret"))

	_, err := client.GetSearchDomains(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("GetSearchDomains returned error: %v", err)
	}
	if captured.AuthToken != "secret" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "secret")
	}
	if captured.IpAddress != "10.0.0.1" {
		t.Errorf("ip = %q, want %q", captured.IpAddress, "10.0.0.1")
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
		createNetworkScopeFn: func(_ context.Context, req *pb.CreateNetworkScopeRequest) (*pb.CreateNetworkScopeResponse, error) {
			tokens["createScope"] = req.AuthToken
			return &pb.CreateNetworkScopeResponse{Success: true}, nil
		},
		deleteNetworkScopeFn: func(_ context.Context, req *pb.DeleteNetworkScopeRequest) (*pb.DeleteNetworkScopeResponse, error) {
			tokens["deleteScope"] = req.AuthToken
			return &pb.DeleteNetworkScopeResponse{Success: true}, nil
		},
		listNetworkScopesFn: func(_ context.Context, req *pb.ListNetworkScopesRequest) (*pb.ListNetworkScopesResponse, error) {
			tokens["listScopes"] = req.AuthToken
			return &pb.ListNetworkScopesResponse{}, nil
		},
		joinNetworkFn: func(_ context.Context, req *pb.JoinNetworkRequest) (*pb.JoinNetworkResponse, error) {
			tokens["join"] = req.AuthToken
			return &pb.JoinNetworkResponse{Success: true}, nil
		},
		leaveNetworkFn: func(_ context.Context, req *pb.LeaveNetworkRequest) (*pb.LeaveNetworkResponse, error) {
			tokens["leave"] = req.AuthToken
			return &pb.LeaveNetworkResponse{Success: true}, nil
		},
		getNetworkAssociationsFn: func(_ context.Context, req *pb.GetNetworkAssociationsRequest) (*pb.GetNetworkAssociationsResponse, error) {
			tokens["assocs"] = req.AuthToken
			return &pb.GetNetworkAssociationsResponse{}, nil
		},
		addScopedRecordFn: func(_ context.Context, req *pb.AddScopedRecordRequest) (*pb.AddScopedRecordResponse, error) {
			tokens["addScoped"] = req.AuthToken
			return &pb.AddScopedRecordResponse{Success: true}, nil
		},
		removeScopedRecordFn: func(_ context.Context, req *pb.RemoveScopedRecordRequest) (*pb.RemoveScopedRecordResponse, error) {
			tokens["removeScoped"] = req.AuthToken
			return &pb.RemoveScopedRecordResponse{Success: true}, nil
		},
		listScopedRecordsFn: func(_ context.Context, req *pb.ListScopedRecordsRequest) (*pb.ListScopedRecordsResponse, error) {
			tokens["listScoped"] = req.AuthToken
			return &pb.ListScopedRecordsResponse{}, nil
		},
		getSearchDomainsFn: func(_ context.Context, req *pb.GetSearchDomainsRequest) (*pb.GetSearchDomainsResponse, error) {
			tokens["searchDomains"] = req.AuthToken
			return &pb.GetSearchDomainsResponse{}, nil
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
	if err := client.CreateNetworkScope(ctx, &NetworkScope{Name: "test"}); err != nil {
		t.Fatalf("CreateNetworkScope: %v", err)
	}
	if err := client.DeleteNetworkScope(ctx, "test"); err != nil {
		t.Fatalf("DeleteNetworkScope: %v", err)
	}
	if _, err := client.ListNetworkScopes(ctx); err != nil {
		t.Fatalf("ListNetworkScopes: %v", err)
	}
	if err := client.JoinNetwork(ctx, "1.2.3.4", "test", 300); err != nil {
		t.Fatalf("JoinNetwork: %v", err)
	}
	if err := client.LeaveNetwork(ctx, "1.2.3.4"); err != nil {
		t.Fatalf("LeaveNetwork: %v", err)
	}
	if _, err := client.GetNetworkAssociations(ctx, ""); err != nil {
		t.Fatalf("GetNetworkAssociations: %v", err)
	}
	if err := client.AddScopedRecord(ctx, "test", &DnsRecord{Name: "x.", RecordType: RecordTypeA, Value: "1.2.3.4"}); err != nil {
		t.Fatalf("AddScopedRecord: %v", err)
	}
	if _, err := client.RemoveScopedRecord(ctx, "test", "x.", nil); err != nil {
		t.Fatalf("RemoveScopedRecord: %v", err)
	}
	if _, err := client.ListScopedRecords(ctx, "test", nil); err != nil {
		t.Fatalf("ListScopedRecords: %v", err)
	}
	if _, err := client.GetSearchDomains(ctx, "1.2.3.4"); err != nil {
		t.Fatalf("GetSearchDomains: %v", err)
	}

	for method, tok := range tokens {
		if tok != "shared" {
			t.Errorf("%s: auth token = %q, want %q", method, tok, "shared")
		}
	}
	if len(tokens) != 17 {
		t.Errorf("expected 17 RPCs, got %d", len(tokens))
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
