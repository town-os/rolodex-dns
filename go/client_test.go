package rolodexdns

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	pb "gitea.com/town-os/rolodex-dns/go/rolodexdnspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// mockRolodexDnsService is a configurable mock implementation of the gRPC service.
// Each field is a function that, if set, handles the corresponding RPC. If nil,
// the RPC returns an Unimplemented error.
type mockRolodexDnsService struct {
	pb.UnimplementedRolodexDnsServiceServer

	addRecordFn              func(ctx context.Context, req *pb.AddRecordRequest) (*pb.AddRecordResponse, error)
	removeRecordFn           func(ctx context.Context, req *pb.RemoveRecordRequest) (*pb.RemoveRecordResponse, error)
	listRecordsFn            func(ctx context.Context, req *pb.ListRecordsRequest) (*pb.ListRecordsResponse, error)
	setForwarderFn           func(ctx context.Context, req *pb.SetForwarderRequest) (*pb.SetForwarderResponse, error)
	setRblConfigFn           func(ctx context.Context, req *pb.SetRblConfigRequest) (*pb.SetRblConfigResponse, error)
	getRblConfigFn           func(ctx context.Context, req *pb.GetRblConfigRequest) (*pb.GetRblConfigResponse, error)
	setDnsblConfigFn         func(ctx context.Context, req *pb.SetDnsblConfigRequest) (*pb.SetDnsblConfigResponse, error)
	getDnsblConfigFn         func(ctx context.Context, req *pb.GetDnsblConfigRequest) (*pb.GetDnsblConfigResponse, error)
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
	addAuthoritativeZoneFn   func(ctx context.Context, req *pb.AddAuthoritativeZoneRequest) (*pb.AddAuthoritativeZoneResponse, error)
	removeAuthoritativeZoneFn func(ctx context.Context, req *pb.RemoveAuthoritativeZoneRequest) (*pb.RemoveAuthoritativeZoneResponse, error)
	listAuthoritativeZonesFn func(ctx context.Context, req *pb.ListAuthoritativeZonesRequest) (*pb.ListAuthoritativeZonesResponse, error)
	getCacheStatsFn          func(ctx context.Context, req *pb.GetCacheStatsRequest) (*pb.GetCacheStatsResponse, error)
	flushDnsCacheFn          func(ctx context.Context, req *pb.FlushDnsCacheRequest) (*pb.FlushDnsCacheResponse, error)
	setTtlDriftConfigFn      func(ctx context.Context, req *pb.SetTtlDriftConfigRequest) (*pb.SetTtlDriftConfigResponse, error)
	getTtlDriftConfigFn      func(ctx context.Context, req *pb.GetTtlDriftConfigRequest) (*pb.GetTtlDriftConfigResponse, error)
	getQueryLatencyStatsFn   func(ctx context.Context, req *pb.GetQueryLatencyStatsRequest) (*pb.GetQueryLatencyStatsResponse, error)
	addLocalRblEntryFn       func(ctx context.Context, req *pb.AddLocalRblEntryRequest) (*pb.AddLocalRblEntryResponse, error)
	removeLocalRblEntryFn    func(ctx context.Context, req *pb.RemoveLocalRblEntryRequest) (*pb.RemoveLocalRblEntryResponse, error)
	listLocalRblEntriesFn    func(ctx context.Context, req *pb.ListLocalRblEntriesRequest) (*pb.ListLocalRblEntriesResponse, error)
	setDotConfigFn           func(ctx context.Context, req *pb.SetDotConfigRequest) (*pb.SetDotConfigResponse, error)
	getDotConfigFn           func(ctx context.Context, req *pb.GetDotConfigRequest) (*pb.GetDotConfigResponse, error)
	setDohConfigFn           func(ctx context.Context, req *pb.SetDohConfigRequest) (*pb.SetDohConfigResponse, error)
	getDohConfigFn           func(ctx context.Context, req *pb.GetDohConfigRequest) (*pb.GetDohConfigResponse, error)
	setDoqConfigFn           func(ctx context.Context, req *pb.SetDoqConfigRequest) (*pb.SetDoqConfigResponse, error)
	getDoqConfigFn           func(ctx context.Context, req *pb.GetDoqConfigRequest) (*pb.GetDoqConfigResponse, error)
	setProxyConfigFn         func(ctx context.Context, req *pb.SetProxyConfigRequest) (*pb.SetProxyConfigResponse, error)
	getProxyConfigFn         func(ctx context.Context, req *pb.GetProxyConfigRequest) (*pb.GetProxyConfigResponse, error)
	generateDnssecKeyFn      func(ctx context.Context, req *pb.GenerateDnssecKeyRequest) (*pb.GenerateDnssecKeyResponse, error)
	listDnssecKeysFn         func(ctx context.Context, req *pb.ListDnssecKeysRequest) (*pb.ListDnssecKeysResponse, error)
	deleteDnssecKeyFn        func(ctx context.Context, req *pb.DeleteDnssecKeyRequest) (*pb.DeleteDnssecKeyResponse, error)
	getDsRecordsFn           func(ctx context.Context, req *pb.GetDsRecordsRequest) (*pb.GetDsRecordsResponse, error)
	signZoneFn               func(ctx context.Context, req *pb.SignZoneRequest) (*pb.SignZoneResponse, error)
	generateTlsaRecordFn     func(ctx context.Context, req *pb.GenerateTlsaRecordRequest) (*pb.GenerateTlsaRecordResponse, error)
	listTlsaRecordsFn        func(ctx context.Context, req *pb.ListTlsaRecordsRequest) (*pb.ListTlsaRecordsResponse, error)
	generateDaneRootCaFn     func(ctx context.Context, req *pb.GenerateDaneRootCaRequest) (*pb.GenerateDaneRootCaResponse, error)
	requestAcmeCertFn        func(ctx context.Context, req *pb.RequestAcmeCertRequest) (*pb.RequestAcmeCertResponse, error)
	getAcmeStatusFn          func(ctx context.Context, req *pb.GetAcmeStatusRequest) (*pb.GetAcmeStatusResponse, error)
	setDns64ConfigFn         func(ctx context.Context, req *pb.SetDns64ConfigRequest) (*pb.SetDns64ConfigResponse, error)
	getDns64ConfigFn         func(ctx context.Context, req *pb.GetDns64ConfigRequest) (*pb.GetDns64ConfigResponse, error)
	addDhcpPoolFn            func(ctx context.Context, req *pb.AddDhcpPoolRequest) (*pb.AddDhcpPoolResponse, error)
	removeDhcpPoolFn         func(ctx context.Context, req *pb.RemoveDhcpPoolRequest) (*pb.RemoveDhcpPoolResponse, error)
	listDhcpPoolsFn          func(ctx context.Context, req *pb.ListDhcpPoolsRequest) (*pb.ListDhcpPoolsResponse, error)
	listDhcpLeasesFn         func(ctx context.Context, req *pb.ListDhcpLeasesRequest) (*pb.ListDhcpLeasesResponse, error)
	deleteDhcpLeaseFn        func(ctx context.Context, req *pb.DeleteDhcpLeaseRequest) (*pb.DeleteDhcpLeaseResponse, error)
	addScopeRblProviderFn    func(ctx context.Context, req *pb.AddScopeRblProviderRequest) (*pb.AddScopeRblProviderResponse, error)
	removeScopeRblProviderFn func(ctx context.Context, req *pb.RemoveScopeRblProviderRequest) (*pb.RemoveScopeRblProviderResponse, error)
	listScopeRblProvidersFn  func(ctx context.Context, req *pb.ListScopeRblProvidersRequest) (*pb.ListScopeRblProvidersResponse, error)
	setDhcpCertOptionFn      func(ctx context.Context, req *pb.SetDhcpCertOptionRequest) (*pb.SetDhcpCertOptionResponse, error)
	removeDhcpCertOptionFn   func(ctx context.Context, req *pb.RemoveDhcpCertOptionRequest) (*pb.RemoveDhcpCertOptionResponse, error)
	listDhcpCertOptionsFn    func(ctx context.Context, req *pb.ListDhcpCertOptionsRequest) (*pb.ListDhcpCertOptionsResponse, error)
}

func (m *mockRolodexDnsService) AddRecord(ctx context.Context, req *pb.AddRecordRequest) (*pb.AddRecordResponse, error) {
	if m.addRecordFn != nil {
		return m.addRecordFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) RemoveRecord(ctx context.Context, req *pb.RemoveRecordRequest) (*pb.RemoveRecordResponse, error) {
	if m.removeRecordFn != nil {
		return m.removeRecordFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) ListRecords(ctx context.Context, req *pb.ListRecordsRequest) (*pb.ListRecordsResponse, error) {
	if m.listRecordsFn != nil {
		return m.listRecordsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) SetForwarders(ctx context.Context, req *pb.SetForwarderRequest) (*pb.SetForwarderResponse, error) {
	if m.setForwarderFn != nil {
		return m.setForwarderFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) SetRblConfig(ctx context.Context, req *pb.SetRblConfigRequest) (*pb.SetRblConfigResponse, error) {
	if m.setRblConfigFn != nil {
		return m.setRblConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetRblConfig(ctx context.Context, req *pb.GetRblConfigRequest) (*pb.GetRblConfigResponse, error) {
	if m.getRblConfigFn != nil {
		return m.getRblConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) SetDnsblConfig(ctx context.Context, req *pb.SetDnsblConfigRequest) (*pb.SetDnsblConfigResponse, error) {
	if m.setDnsblConfigFn != nil {
		return m.setDnsblConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetDnsblConfig(ctx context.Context, req *pb.GetDnsblConfigRequest) (*pb.GetDnsblConfigResponse, error) {
	if m.getDnsblConfigFn != nil {
		return m.getDnsblConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) FlushCache(ctx context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
	if m.flushCacheFn != nil {
		return m.flushCacheFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) CreateNetworkScope(ctx context.Context, req *pb.CreateNetworkScopeRequest) (*pb.CreateNetworkScopeResponse, error) {
	if m.createNetworkScopeFn != nil {
		return m.createNetworkScopeFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) DeleteNetworkScope(ctx context.Context, req *pb.DeleteNetworkScopeRequest) (*pb.DeleteNetworkScopeResponse, error) {
	if m.deleteNetworkScopeFn != nil {
		return m.deleteNetworkScopeFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) ListNetworkScopes(ctx context.Context, req *pb.ListNetworkScopesRequest) (*pb.ListNetworkScopesResponse, error) {
	if m.listNetworkScopesFn != nil {
		return m.listNetworkScopesFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) JoinNetwork(ctx context.Context, req *pb.JoinNetworkRequest) (*pb.JoinNetworkResponse, error) {
	if m.joinNetworkFn != nil {
		return m.joinNetworkFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) LeaveNetwork(ctx context.Context, req *pb.LeaveNetworkRequest) (*pb.LeaveNetworkResponse, error) {
	if m.leaveNetworkFn != nil {
		return m.leaveNetworkFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetNetworkAssociations(ctx context.Context, req *pb.GetNetworkAssociationsRequest) (*pb.GetNetworkAssociationsResponse, error) {
	if m.getNetworkAssociationsFn != nil {
		return m.getNetworkAssociationsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) AddScopedRecord(ctx context.Context, req *pb.AddScopedRecordRequest) (*pb.AddScopedRecordResponse, error) {
	if m.addScopedRecordFn != nil {
		return m.addScopedRecordFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) RemoveScopedRecord(ctx context.Context, req *pb.RemoveScopedRecordRequest) (*pb.RemoveScopedRecordResponse, error) {
	if m.removeScopedRecordFn != nil {
		return m.removeScopedRecordFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) ListScopedRecords(ctx context.Context, req *pb.ListScopedRecordsRequest) (*pb.ListScopedRecordsResponse, error) {
	if m.listScopedRecordsFn != nil {
		return m.listScopedRecordsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetSearchDomains(ctx context.Context, req *pb.GetSearchDomainsRequest) (*pb.GetSearchDomainsResponse, error) {
	if m.getSearchDomainsFn != nil {
		return m.getSearchDomainsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) AddAuthoritativeZone(ctx context.Context, req *pb.AddAuthoritativeZoneRequest) (*pb.AddAuthoritativeZoneResponse, error) {
	if m.addAuthoritativeZoneFn != nil {
		return m.addAuthoritativeZoneFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) RemoveAuthoritativeZone(ctx context.Context, req *pb.RemoveAuthoritativeZoneRequest) (*pb.RemoveAuthoritativeZoneResponse, error) {
	if m.removeAuthoritativeZoneFn != nil {
		return m.removeAuthoritativeZoneFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) ListAuthoritativeZones(ctx context.Context, req *pb.ListAuthoritativeZonesRequest) (*pb.ListAuthoritativeZonesResponse, error) {
	if m.listAuthoritativeZonesFn != nil {
		return m.listAuthoritativeZonesFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetCacheStats(ctx context.Context, req *pb.GetCacheStatsRequest) (*pb.GetCacheStatsResponse, error) {
	if m.getCacheStatsFn != nil {
		return m.getCacheStatsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) FlushDnsCache(ctx context.Context, req *pb.FlushDnsCacheRequest) (*pb.FlushDnsCacheResponse, error) {
	if m.flushDnsCacheFn != nil {
		return m.flushDnsCacheFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) SetTtlDriftConfig(ctx context.Context, req *pb.SetTtlDriftConfigRequest) (*pb.SetTtlDriftConfigResponse, error) {
	if m.setTtlDriftConfigFn != nil {
		return m.setTtlDriftConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetTtlDriftConfig(ctx context.Context, req *pb.GetTtlDriftConfigRequest) (*pb.GetTtlDriftConfigResponse, error) {
	if m.getTtlDriftConfigFn != nil {
		return m.getTtlDriftConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetQueryLatencyStats(ctx context.Context, req *pb.GetQueryLatencyStatsRequest) (*pb.GetQueryLatencyStatsResponse, error) {
	if m.getQueryLatencyStatsFn != nil {
		return m.getQueryLatencyStatsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) AddLocalRblEntry(ctx context.Context, req *pb.AddLocalRblEntryRequest) (*pb.AddLocalRblEntryResponse, error) {
	if m.addLocalRblEntryFn != nil {
		return m.addLocalRblEntryFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) RemoveLocalRblEntry(ctx context.Context, req *pb.RemoveLocalRblEntryRequest) (*pb.RemoveLocalRblEntryResponse, error) {
	if m.removeLocalRblEntryFn != nil {
		return m.removeLocalRblEntryFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) ListLocalRblEntries(ctx context.Context, req *pb.ListLocalRblEntriesRequest) (*pb.ListLocalRblEntriesResponse, error) {
	if m.listLocalRblEntriesFn != nil {
		return m.listLocalRblEntriesFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) SetDotConfig(ctx context.Context, req *pb.SetDotConfigRequest) (*pb.SetDotConfigResponse, error) {
	if m.setDotConfigFn != nil {
		return m.setDotConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetDotConfig(ctx context.Context, req *pb.GetDotConfigRequest) (*pb.GetDotConfigResponse, error) {
	if m.getDotConfigFn != nil {
		return m.getDotConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) SetDohConfig(ctx context.Context, req *pb.SetDohConfigRequest) (*pb.SetDohConfigResponse, error) {
	if m.setDohConfigFn != nil {
		return m.setDohConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetDohConfig(ctx context.Context, req *pb.GetDohConfigRequest) (*pb.GetDohConfigResponse, error) {
	if m.getDohConfigFn != nil {
		return m.getDohConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) SetDoqConfig(ctx context.Context, req *pb.SetDoqConfigRequest) (*pb.SetDoqConfigResponse, error) {
	if m.setDoqConfigFn != nil {
		return m.setDoqConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetDoqConfig(ctx context.Context, req *pb.GetDoqConfigRequest) (*pb.GetDoqConfigResponse, error) {
	if m.getDoqConfigFn != nil {
		return m.getDoqConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) SetProxyConfig(ctx context.Context, req *pb.SetProxyConfigRequest) (*pb.SetProxyConfigResponse, error) {
	if m.setProxyConfigFn != nil {
		return m.setProxyConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetProxyConfig(ctx context.Context, req *pb.GetProxyConfigRequest) (*pb.GetProxyConfigResponse, error) {
	if m.getProxyConfigFn != nil {
		return m.getProxyConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GenerateDnssecKey(ctx context.Context, req *pb.GenerateDnssecKeyRequest) (*pb.GenerateDnssecKeyResponse, error) {
	if m.generateDnssecKeyFn != nil {
		return m.generateDnssecKeyFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) ListDnssecKeys(ctx context.Context, req *pb.ListDnssecKeysRequest) (*pb.ListDnssecKeysResponse, error) {
	if m.listDnssecKeysFn != nil {
		return m.listDnssecKeysFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) DeleteDnssecKey(ctx context.Context, req *pb.DeleteDnssecKeyRequest) (*pb.DeleteDnssecKeyResponse, error) {
	if m.deleteDnssecKeyFn != nil {
		return m.deleteDnssecKeyFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetDsRecords(ctx context.Context, req *pb.GetDsRecordsRequest) (*pb.GetDsRecordsResponse, error) {
	if m.getDsRecordsFn != nil {
		return m.getDsRecordsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) SignZone(ctx context.Context, req *pb.SignZoneRequest) (*pb.SignZoneResponse, error) {
	if m.signZoneFn != nil {
		return m.signZoneFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GenerateTlsaRecord(ctx context.Context, req *pb.GenerateTlsaRecordRequest) (*pb.GenerateTlsaRecordResponse, error) {
	if m.generateTlsaRecordFn != nil {
		return m.generateTlsaRecordFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) ListTlsaRecords(ctx context.Context, req *pb.ListTlsaRecordsRequest) (*pb.ListTlsaRecordsResponse, error) {
	if m.listTlsaRecordsFn != nil {
		return m.listTlsaRecordsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GenerateDaneRootCa(ctx context.Context, req *pb.GenerateDaneRootCaRequest) (*pb.GenerateDaneRootCaResponse, error) {
	if m.generateDaneRootCaFn != nil {
		return m.generateDaneRootCaFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) RequestAcmeCert(ctx context.Context, req *pb.RequestAcmeCertRequest) (*pb.RequestAcmeCertResponse, error) {
	if m.requestAcmeCertFn != nil {
		return m.requestAcmeCertFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetAcmeStatus(ctx context.Context, req *pb.GetAcmeStatusRequest) (*pb.GetAcmeStatusResponse, error) {
	if m.getAcmeStatusFn != nil {
		return m.getAcmeStatusFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) SetDns64Config(ctx context.Context, req *pb.SetDns64ConfigRequest) (*pb.SetDns64ConfigResponse, error) {
	if m.setDns64ConfigFn != nil {
		return m.setDns64ConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) GetDns64Config(ctx context.Context, req *pb.GetDns64ConfigRequest) (*pb.GetDns64ConfigResponse, error) {
	if m.getDns64ConfigFn != nil {
		return m.getDns64ConfigFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) AddDhcpPool(ctx context.Context, req *pb.AddDhcpPoolRequest) (*pb.AddDhcpPoolResponse, error) {
	if m.addDhcpPoolFn != nil {
		return m.addDhcpPoolFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) RemoveDhcpPool(ctx context.Context, req *pb.RemoveDhcpPoolRequest) (*pb.RemoveDhcpPoolResponse, error) {
	if m.removeDhcpPoolFn != nil {
		return m.removeDhcpPoolFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) ListDhcpPools(ctx context.Context, req *pb.ListDhcpPoolsRequest) (*pb.ListDhcpPoolsResponse, error) {
	if m.listDhcpPoolsFn != nil {
		return m.listDhcpPoolsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) ListDhcpLeases(ctx context.Context, req *pb.ListDhcpLeasesRequest) (*pb.ListDhcpLeasesResponse, error) {
	if m.listDhcpLeasesFn != nil {
		return m.listDhcpLeasesFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) DeleteDhcpLease(ctx context.Context, req *pb.DeleteDhcpLeaseRequest) (*pb.DeleteDhcpLeaseResponse, error) {
	if m.deleteDhcpLeaseFn != nil {
		return m.deleteDhcpLeaseFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) AddScopeRblProvider(ctx context.Context, req *pb.AddScopeRblProviderRequest) (*pb.AddScopeRblProviderResponse, error) {
	if m.addScopeRblProviderFn != nil {
		return m.addScopeRblProviderFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) RemoveScopeRblProvider(ctx context.Context, req *pb.RemoveScopeRblProviderRequest) (*pb.RemoveScopeRblProviderResponse, error) {
	if m.removeScopeRblProviderFn != nil {
		return m.removeScopeRblProviderFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) ListScopeRblProviders(ctx context.Context, req *pb.ListScopeRblProvidersRequest) (*pb.ListScopeRblProvidersResponse, error) {
	if m.listScopeRblProvidersFn != nil {
		return m.listScopeRblProvidersFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) SetDhcpCertOption(ctx context.Context, req *pb.SetDhcpCertOptionRequest) (*pb.SetDhcpCertOptionResponse, error) {
	if m.setDhcpCertOptionFn != nil {
		return m.setDhcpCertOptionFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) RemoveDhcpCertOption(ctx context.Context, req *pb.RemoveDhcpCertOptionRequest) (*pb.RemoveDhcpCertOptionResponse, error) {
	if m.removeDhcpCertOptionFn != nil {
		return m.removeDhcpCertOptionFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockRolodexDnsService) ListDhcpCertOptions(ctx context.Context, req *pb.ListDhcpCertOptionsRequest) (*pb.ListDhcpCertOptionsResponse, error) {
	if m.listDhcpCertOptionsFn != nil {
		return m.listDhcpCertOptionsFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// startMockServer starts an in-process gRPC server using a bufconn listener and
// returns a connected Client. The server is stopped when the test finishes.
func startMockServer(t *testing.T, mock *mockRolodexDnsService, opts ...Option) *Client {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	pb.RegisterRolodexDnsServiceServer(srv, mock)
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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

func TestSetDnsblConfig(t *testing.T) {
	var captured *pb.SetDnsblConfigRequest
	mock := &mockRolodexDnsService{
		setDnsblConfigFn: func(_ context.Context, req *pb.SetDnsblConfigRequest) (*pb.SetDnsblConfigResponse, error) {
			captured = req
			return &pb.SetDnsblConfigResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock)

	err := client.SetDnsblConfig(context.Background(), true, []*DnsblConfig{
		{Zone: "dbl.spamhaus.org", Enabled: true},
		{Zone: "multi.surbl.org", Enabled: false},
	})
	if err != nil {
		t.Fatalf("SetDnsblConfig returned error: %v", err)
	}
	if !captured.Enabled {
		t.Error("enabled should be true")
	}
	if len(captured.Providers) != 2 {
		t.Fatalf("got %d providers, want 2", len(captured.Providers))
	}
	if captured.Providers[0].Zone != "dbl.spamhaus.org" {
		t.Errorf("provider[0].zone = %q, want %q", captured.Providers[0].Zone, "dbl.spamhaus.org")
	}
	if !captured.Providers[0].Enabled {
		t.Error("provider[0].enabled should be true")
	}
	if captured.Providers[1].Enabled {
		t.Error("provider[1].enabled should be false")
	}
}

func TestGetDnsblConfig(t *testing.T) {
	mock := &mockRolodexDnsService{
		getDnsblConfigFn: func(_ context.Context, req *pb.GetDnsblConfigRequest) (*pb.GetDnsblConfigResponse, error) {
			return &pb.GetDnsblConfigResponse{
				Enabled: true,
				Providers: []*pb.DnsblConfig{
					{Zone: "dbl.spamhaus.org", Enabled: true},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock)

	dnsblStatus, err := client.GetDnsblConfig(context.Background())
	if err != nil {
		t.Fatalf("GetDnsblConfig returned error: %v", err)
	}
	if !dnsblStatus.Enabled {
		t.Error("enabled should be true")
	}
	if len(dnsblStatus.Providers) != 1 {
		t.Fatalf("got %d providers, want 1", len(dnsblStatus.Providers))
	}
	if dnsblStatus.Providers[0].Zone != "dbl.spamhaus.org" {
		t.Errorf("provider zone = %q, want %q", dnsblStatus.Providers[0].Zone, "dbl.spamhaus.org")
	}
}

func TestFlushCache(t *testing.T) {
	var captured *pb.FlushCacheRequest
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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

	mock := &mockRolodexDnsService{
		flushCacheFn: func(_ context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
			return &pb.FlushCacheResponse{Success: true}, nil
		},
	}
	srv := grpc.NewServer()
	pb.RegisterRolodexDnsServiceServer(srv, mock)
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

	mock := &mockRolodexDnsService{
		listRecordsFn: func(_ context.Context, req *pb.ListRecordsRequest) (*pb.ListRecordsResponse, error) {
			if req.AuthToken != "my-secret" {
				return nil, status.Error(codes.Unauthenticated, "bad token")
			}
			return &pb.ListRecordsResponse{}, nil
		},
	}
	srv := grpc.NewServer()
	pb.RegisterRolodexDnsServiceServer(srv, mock)
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{
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
	mock := &mockRolodexDnsService{}
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
	mock := &mockRolodexDnsService{
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
	pb.RegisterRolodexDnsServiceServer(srv, mock)
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
	socketPath := filepath.Join(dir, "rolodex-dns.sock")

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	var capturedToken string
	mock := &mockRolodexDnsService{
		flushCacheFn: func(_ context.Context, req *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
			capturedToken = req.AuthToken
			return &pb.FlushCacheResponse{Success: true}, nil
		},
	}
	srv := grpc.NewServer()
	pb.RegisterRolodexDnsServiceServer(srv, mock)
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

func TestAddAuthoritativeZone(t *testing.T) {
	var captured *pb.AddAuthoritativeZoneRequest
	mock := &mockRolodexDnsService{
		addAuthoritativeZoneFn: func(_ context.Context, req *pb.AddAuthoritativeZoneRequest) (*pb.AddAuthoritativeZoneResponse, error) {
			captured = req
			return &pb.AddAuthoritativeZoneResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	err := client.AddAuthoritativeZone(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("AddAuthoritativeZone: %v", err)
	}
	if captured.Zone != "example.com." {
		t.Errorf("zone = %q, want %q", captured.Zone, "example.com.")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestRemoveAuthoritativeZone(t *testing.T) {
	var captured *pb.RemoveAuthoritativeZoneRequest
	mock := &mockRolodexDnsService{
		removeAuthoritativeZoneFn: func(_ context.Context, req *pb.RemoveAuthoritativeZoneRequest) (*pb.RemoveAuthoritativeZoneResponse, error) {
			captured = req
			return &pb.RemoveAuthoritativeZoneResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	err := client.RemoveAuthoritativeZone(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("RemoveAuthoritativeZone: %v", err)
	}
	if captured.Zone != "example.com." {
		t.Errorf("zone = %q, want %q", captured.Zone, "example.com.")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestListAuthoritativeZones(t *testing.T) {
	mock := &mockRolodexDnsService{
		listAuthoritativeZonesFn: func(_ context.Context, req *pb.ListAuthoritativeZonesRequest) (*pb.ListAuthoritativeZonesResponse, error) {
			return &pb.ListAuthoritativeZonesResponse{
				Zones: []string{"example.com.", "test.org."},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	zones, err := client.ListAuthoritativeZones(context.Background())
	if err != nil {
		t.Fatalf("ListAuthoritativeZones: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("got %d zones, want 2", len(zones))
	}
	if zones[0] != "example.com." {
		t.Errorf("zones[0] = %q, want %q", zones[0], "example.com.")
	}
	if zones[1] != "test.org." {
		t.Errorf("zones[1] = %q, want %q", zones[1], "test.org.")
	}
}

func TestGetCacheStats(t *testing.T) {
	mock := &mockRolodexDnsService{
		getCacheStatsFn: func(_ context.Context, req *pb.GetCacheStatsRequest) (*pb.GetCacheStatsResponse, error) {
			return &pb.GetCacheStatsResponse{
				TotalEntries: 100,
				HitCount:     80,
				MissCount:    20,
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	stats, err := client.GetCacheStats(context.Background())
	if err != nil {
		t.Fatalf("GetCacheStats: %v", err)
	}
	if stats.TotalEntries != 100 {
		t.Errorf("TotalEntries = %d, want 100", stats.TotalEntries)
	}
	if stats.HitCount != 80 {
		t.Errorf("HitCount = %d, want 80", stats.HitCount)
	}
	if stats.MissCount != 20 {
		t.Errorf("MissCount = %d, want 20", stats.MissCount)
	}
}

func TestFlushDnsCache(t *testing.T) {
	var captured *pb.FlushDnsCacheRequest
	mock := &mockRolodexDnsService{
		flushDnsCacheFn: func(_ context.Context, req *pb.FlushDnsCacheRequest) (*pb.FlushDnsCacheResponse, error) {
			captured = req
			return &pb.FlushDnsCacheResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	err := client.FlushDnsCache(context.Background())
	if err != nil {
		t.Fatalf("FlushDnsCache: %v", err)
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestSetTtlDriftConfig(t *testing.T) {
	var captured *pb.SetTtlDriftConfigRequest
	mock := &mockRolodexDnsService{
		setTtlDriftConfigFn: func(_ context.Context, req *pb.SetTtlDriftConfigRequest) (*pb.SetTtlDriftConfigResponse, error) {
			captured = req
			return &pb.SetTtlDriftConfigResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	cfg := &TtlDriftConfig{
		Mode:            "fixed",
		FixedAdjustment: "5m",
		LogMultiplier:   0,
	}
	err := client.SetTtlDriftConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("SetTtlDriftConfig: %v", err)
	}
	if captured.Config.Mode != "fixed" {
		t.Errorf("mode = %q, want %q", captured.Config.Mode, "fixed")
	}
	if captured.Config.FixedAdjustment != "5m" {
		t.Errorf("fixed_adjustment = %q, want %q", captured.Config.FixedAdjustment, "5m")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestGetTtlDriftConfig(t *testing.T) {
	mock := &mockRolodexDnsService{
		getTtlDriftConfigFn: func(_ context.Context, req *pb.GetTtlDriftConfigRequest) (*pb.GetTtlDriftConfigResponse, error) {
			return &pb.GetTtlDriftConfigResponse{
				Config: &pb.TtlDriftConfig{
					Mode:          "logarithmic",
					LogMultiplier: 1.5,
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	cfg, err := client.GetTtlDriftConfig(context.Background())
	if err != nil {
		t.Fatalf("GetTtlDriftConfig: %v", err)
	}
	if cfg.Mode != "logarithmic" {
		t.Errorf("mode = %q, want %q", cfg.Mode, "logarithmic")
	}
	if cfg.LogMultiplier != 1.5 {
		t.Errorf("log_multiplier = %f, want 1.5", cfg.LogMultiplier)
	}
}

func TestGetQueryLatencyStats(t *testing.T) {
	mock := &mockRolodexDnsService{
		getQueryLatencyStatsFn: func(_ context.Context, req *pb.GetQueryLatencyStatsRequest) (*pb.GetQueryLatencyStatsResponse, error) {
			return &pb.GetQueryLatencyStatsResponse{
				Stats: []*pb.QueryLatencyStat{
					{Server: "8.8.8.8:53", AvgLatencyMs: 12.5, QueryCount: 100},
					{Server: "1.1.1.1:53", AvgLatencyMs: 8.3, QueryCount: 200},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	stats, err := client.GetQueryLatencyStats(context.Background())
	if err != nil {
		t.Fatalf("GetQueryLatencyStats: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("got %d stats, want 2", len(stats))
	}
	if stats[0].Server != "8.8.8.8:53" {
		t.Errorf("stats[0].Server = %q, want %q", stats[0].Server, "8.8.8.8:53")
	}
	if stats[0].AvgLatencyMs != 12.5 {
		t.Errorf("stats[0].AvgLatencyMs = %f, want 12.5", stats[0].AvgLatencyMs)
	}
	if stats[0].QueryCount != 100 {
		t.Errorf("stats[0].QueryCount = %d, want 100", stats[0].QueryCount)
	}
}

func TestAddLocalRblEntry(t *testing.T) {
	var captured *pb.AddLocalRblEntryRequest
	mock := &mockRolodexDnsService{
		addLocalRblEntryFn: func(_ context.Context, req *pb.AddLocalRblEntryRequest) (*pb.AddLocalRblEntryResponse, error) {
			captured = req
			return &pb.AddLocalRblEntryResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	entry := &LocalRblEntry{
		Name:   "malware.example.com",
		Reason: "known malware domain",
	}
	err := client.AddLocalRblEntry(context.Background(), entry)
	if err != nil {
		t.Fatalf("AddLocalRblEntry: %v", err)
	}
	if captured.Entry.Name != "malware.example.com" {
		t.Errorf("name = %q, want %q", captured.Entry.Name, "malware.example.com")
	}
	if captured.Entry.Reason != "known malware domain" {
		t.Errorf("reason = %q, want %q", captured.Entry.Reason, "known malware domain")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestRemoveLocalRblEntry(t *testing.T) {
	var captured *pb.RemoveLocalRblEntryRequest
	mock := &mockRolodexDnsService{
		removeLocalRblEntryFn: func(_ context.Context, req *pb.RemoveLocalRblEntryRequest) (*pb.RemoveLocalRblEntryResponse, error) {
			captured = req
			return &pb.RemoveLocalRblEntryResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	err := client.RemoveLocalRblEntry(context.Background(), "malware.example.com")
	if err != nil {
		t.Fatalf("RemoveLocalRblEntry: %v", err)
	}
	if captured.Name != "malware.example.com" {
		t.Errorf("name = %q, want %q", captured.Name, "malware.example.com")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestListLocalRblEntries(t *testing.T) {
	mock := &mockRolodexDnsService{
		listLocalRblEntriesFn: func(_ context.Context, req *pb.ListLocalRblEntriesRequest) (*pb.ListLocalRblEntriesResponse, error) {
			return &pb.ListLocalRblEntriesResponse{
				Entries: []*pb.LocalRblEntry{
					{Name: "bad.example.com", Reason: "spam"},
					{Name: "evil.example.com", Reason: "phishing"},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	entries, err := client.ListLocalRblEntries(context.Background())
	if err != nil {
		t.Fatalf("ListLocalRblEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Name != "bad.example.com" {
		t.Errorf("entries[0].Name = %q, want %q", entries[0].Name, "bad.example.com")
	}
	if entries[1].Reason != "phishing" {
		t.Errorf("entries[1].Reason = %q, want %q", entries[1].Reason, "phishing")
	}
}

func TestSetDotConfig(t *testing.T) {
	var captured *pb.SetDotConfigRequest
	mock := &mockRolodexDnsService{
		setDotConfigFn: func(_ context.Context, req *pb.SetDotConfigRequest) (*pb.SetDotConfigResponse, error) {
			captured = req
			return &pb.SetDotConfigResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	cfg := &DotConfig{
		Bind: "0.0.0.0:853",
		Tls: &pb.TlsConfig{
			CertPath: "/etc/ssl/cert.pem",
			KeyPath:  "/etc/ssl/key.pem",
		},
	}
	err := client.SetDotConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("SetDotConfig: %v", err)
	}
	if captured.Config.Bind != "0.0.0.0:853" {
		t.Errorf("bind = %q, want %q", captured.Config.Bind, "0.0.0.0:853")
	}
	if captured.Config.Tls.CertPath != "/etc/ssl/cert.pem" {
		t.Errorf("cert_path = %q, want %q", captured.Config.Tls.CertPath, "/etc/ssl/cert.pem")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestGetDotConfig(t *testing.T) {
	mock := &mockRolodexDnsService{
		getDotConfigFn: func(_ context.Context, req *pb.GetDotConfigRequest) (*pb.GetDotConfigResponse, error) {
			return &pb.GetDotConfigResponse{
				Config: &pb.DotConfig{
					Bind: "0.0.0.0:853",
					Tls: &pb.TlsConfig{
						CertPath:       "/etc/ssl/cert.pem",
						KeyPath:        "/etc/ssl/key.pem",
						AutoSelfSigned: true,
					},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	cfg, err := client.GetDotConfig(context.Background())
	if err != nil {
		t.Fatalf("GetDotConfig: %v", err)
	}
	if cfg.Bind != "0.0.0.0:853" {
		t.Errorf("bind = %q, want %q", cfg.Bind, "0.0.0.0:853")
	}
	if !cfg.Tls.AutoSelfSigned {
		t.Errorf("auto_self_signed = false, want true")
	}
}

func TestSetDohConfig(t *testing.T) {
	var captured *pb.SetDohConfigRequest
	mock := &mockRolodexDnsService{
		setDohConfigFn: func(_ context.Context, req *pb.SetDohConfigRequest) (*pb.SetDohConfigResponse, error) {
			captured = req
			return &pb.SetDohConfigResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	cfg := &DohConfig{
		Bind: "0.0.0.0:443",
		Tls: &pb.TlsConfig{
			CertPath: "/etc/ssl/cert.pem",
			KeyPath:  "/etc/ssl/key.pem",
		},
		EnableH3: true,
	}
	err := client.SetDohConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("SetDohConfig: %v", err)
	}
	if captured.Config.Bind != "0.0.0.0:443" {
		t.Errorf("bind = %q, want %q", captured.Config.Bind, "0.0.0.0:443")
	}
	if !captured.Config.EnableH3 {
		t.Errorf("enable_h3 = false, want true")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestGetDohConfig(t *testing.T) {
	mock := &mockRolodexDnsService{
		getDohConfigFn: func(_ context.Context, req *pb.GetDohConfigRequest) (*pb.GetDohConfigResponse, error) {
			return &pb.GetDohConfigResponse{
				Config: &pb.DohConfig{
					Bind: "0.0.0.0:443",
					Tls: &pb.TlsConfig{
						CertPath: "/etc/ssl/cert.pem",
						KeyPath:  "/etc/ssl/key.pem",
					},
					EnableH3: true,
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	cfg, err := client.GetDohConfig(context.Background())
	if err != nil {
		t.Fatalf("GetDohConfig: %v", err)
	}
	if cfg.Bind != "0.0.0.0:443" {
		t.Errorf("bind = %q, want %q", cfg.Bind, "0.0.0.0:443")
	}
	if !cfg.EnableH3 {
		t.Errorf("enable_h3 = false, want true")
	}
}

func TestSetDoqConfig(t *testing.T) {
	var captured *pb.SetDoqConfigRequest
	mock := &mockRolodexDnsService{
		setDoqConfigFn: func(_ context.Context, req *pb.SetDoqConfigRequest) (*pb.SetDoqConfigResponse, error) {
			captured = req
			return &pb.SetDoqConfigResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	cfg := &DoqConfig{
		Bind: "0.0.0.0:8853",
		Tls: &pb.TlsConfig{
			CertPath: "/etc/ssl/cert.pem",
			KeyPath:  "/etc/ssl/key.pem",
		},
	}
	err := client.SetDoqConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("SetDoqConfig: %v", err)
	}
	if captured.Config.Bind != "0.0.0.0:8853" {
		t.Errorf("bind = %q, want %q", captured.Config.Bind, "0.0.0.0:8853")
	}
	if captured.Config.Tls.CertPath != "/etc/ssl/cert.pem" {
		t.Errorf("cert_path = %q, want %q", captured.Config.Tls.CertPath, "/etc/ssl/cert.pem")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestGetDoqConfig(t *testing.T) {
	mock := &mockRolodexDnsService{
		getDoqConfigFn: func(_ context.Context, req *pb.GetDoqConfigRequest) (*pb.GetDoqConfigResponse, error) {
			return &pb.GetDoqConfigResponse{
				Config: &pb.DoqConfig{
					Bind: "0.0.0.0:8853",
					Tls: &pb.TlsConfig{
						CertPath: "/etc/ssl/cert.pem",
						KeyPath:  "/etc/ssl/key.pem",
					},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	cfg, err := client.GetDoqConfig(context.Background())
	if err != nil {
		t.Fatalf("GetDoqConfig: %v", err)
	}
	if cfg.Bind != "0.0.0.0:8853" {
		t.Errorf("bind = %q, want %q", cfg.Bind, "0.0.0.0:8853")
	}
	if cfg.Tls.KeyPath != "/etc/ssl/key.pem" {
		t.Errorf("key_path = %q, want %q", cfg.Tls.KeyPath, "/etc/ssl/key.pem")
	}
}

func TestSetProxyConfig(t *testing.T) {
	var captured *pb.SetProxyConfigRequest
	mock := &mockRolodexDnsService{
		setProxyConfigFn: func(_ context.Context, req *pb.SetProxyConfigRequest) (*pb.SetProxyConfigResponse, error) {
			captured = req
			return &pb.SetProxyConfigResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	cfg := &ProxyConfig{
		Url:  "http://proxy.example.com:8080",
		Auth: "user:pass",
		Mode: "connect",
	}
	err := client.SetProxyConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("SetProxyConfig: %v", err)
	}
	if captured.Config.Url != "http://proxy.example.com:8080" {
		t.Errorf("url = %q, want %q", captured.Config.Url, "http://proxy.example.com:8080")
	}
	if captured.Config.Auth != "user:pass" {
		t.Errorf("auth = %q, want %q", captured.Config.Auth, "user:pass")
	}
	if captured.Config.Mode != "connect" {
		t.Errorf("mode = %q, want %q", captured.Config.Mode, "connect")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestGetProxyConfig(t *testing.T) {
	mock := &mockRolodexDnsService{
		getProxyConfigFn: func(_ context.Context, req *pb.GetProxyConfigRequest) (*pb.GetProxyConfigResponse, error) {
			return &pb.GetProxyConfigResponse{
				Config: &pb.ProxyConfig{
					Url:  "http://proxy.example.com:8080",
					Auth: "user:pass",
					Mode: "doh",
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	cfg, err := client.GetProxyConfig(context.Background())
	if err != nil {
		t.Fatalf("GetProxyConfig: %v", err)
	}
	if cfg.Url != "http://proxy.example.com:8080" {
		t.Errorf("url = %q, want %q", cfg.Url, "http://proxy.example.com:8080")
	}
	if cfg.Mode != "doh" {
		t.Errorf("mode = %q, want %q", cfg.Mode, "doh")
	}
}

func TestGenerateDnssecKey(t *testing.T) {
	var captured *pb.GenerateDnssecKeyRequest
	mock := &mockRolodexDnsService{
		generateDnssecKeyFn: func(_ context.Context, req *pb.GenerateDnssecKeyRequest) (*pb.GenerateDnssecKeyResponse, error) {
			captured = req
			return &pb.GenerateDnssecKeyResponse{
				Success: true,
				Key: &pb.DnssecKey{
					Id:        1,
					Zone:      "example.com.",
					Algorithm: "ECDSAP256SHA256",
					KeyType:   "KSK",
					KeyTag:    12345,
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	key, err := client.GenerateDnssecKey(context.Background(), "example.com.", "ECDSAP256SHA256", "KSK")
	if err != nil {
		t.Fatalf("GenerateDnssecKey: %v", err)
	}
	if captured.Zone != "example.com." {
		t.Errorf("zone = %q, want %q", captured.Zone, "example.com.")
	}
	if captured.Algorithm != "ECDSAP256SHA256" {
		t.Errorf("algorithm = %q, want %q", captured.Algorithm, "ECDSAP256SHA256")
	}
	if captured.KeyType != "KSK" {
		t.Errorf("key_type = %q, want %q", captured.KeyType, "KSK")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
	if key.Id != 1 {
		t.Errorf("key.Id = %d, want 1", key.Id)
	}
	if key.KeyTag != 12345 {
		t.Errorf("key.KeyTag = %d, want 12345", key.KeyTag)
	}
}

func TestListDnssecKeys(t *testing.T) {
	mock := &mockRolodexDnsService{
		listDnssecKeysFn: func(_ context.Context, req *pb.ListDnssecKeysRequest) (*pb.ListDnssecKeysResponse, error) {
			return &pb.ListDnssecKeysResponse{
				Keys: []*pb.DnssecKey{
					{Id: 1, Zone: "example.com.", Algorithm: "ECDSAP256SHA256", KeyType: "KSK", KeyTag: 12345},
					{Id: 2, Zone: "example.com.", Algorithm: "ECDSAP256SHA256", KeyType: "ZSK", KeyTag: 67890},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	keys, err := client.ListDnssecKeys(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("ListDnssecKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	if keys[0].KeyType != "KSK" {
		t.Errorf("keys[0].KeyType = %q, want %q", keys[0].KeyType, "KSK")
	}
	if keys[1].KeyType != "ZSK" {
		t.Errorf("keys[1].KeyType = %q, want %q", keys[1].KeyType, "ZSK")
	}
}

func TestDeleteDnssecKey(t *testing.T) {
	var captured *pb.DeleteDnssecKeyRequest
	mock := &mockRolodexDnsService{
		deleteDnssecKeyFn: func(_ context.Context, req *pb.DeleteDnssecKeyRequest) (*pb.DeleteDnssecKeyResponse, error) {
			captured = req
			return &pb.DeleteDnssecKeyResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	err := client.DeleteDnssecKey(context.Background(), 42)
	if err != nil {
		t.Fatalf("DeleteDnssecKey: %v", err)
	}
	if captured.KeyId != 42 {
		t.Errorf("key_id = %d, want 42", captured.KeyId)
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestGetDsRecords(t *testing.T) {
	mock := &mockRolodexDnsService{
		getDsRecordsFn: func(_ context.Context, req *pb.GetDsRecordsRequest) (*pb.GetDsRecordsResponse, error) {
			return &pb.GetDsRecordsResponse{
				DsRecords: []string{
					"example.com. IN DS 12345 13 2 AABB...",
					"example.com. IN DS 67890 13 2 CCDD...",
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	records, err := client.GetDsRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetDsRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0] != "example.com. IN DS 12345 13 2 AABB..." {
		t.Errorf("records[0] = %q, want %q", records[0], "example.com. IN DS 12345 13 2 AABB...")
	}
}

func TestSignZone(t *testing.T) {
	var captured *pb.SignZoneRequest
	mock := &mockRolodexDnsService{
		signZoneFn: func(_ context.Context, req *pb.SignZoneRequest) (*pb.SignZoneResponse, error) {
			captured = req
			return &pb.SignZoneResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	err := client.SignZone(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	if captured.Zone != "example.com." {
		t.Errorf("zone = %q, want %q", captured.Zone, "example.com.")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestGenerateTlsaRecord(t *testing.T) {
	var captured *pb.GenerateTlsaRecordRequest
	mock := &mockRolodexDnsService{
		generateTlsaRecordFn: func(_ context.Context, req *pb.GenerateTlsaRecordRequest) (*pb.GenerateTlsaRecordResponse, error) {
			captured = req
			return &pb.GenerateTlsaRecordResponse{
				Success:    true,
				TlsaRecord: "_443._tcp.example.com. IN TLSA 3 1 1 AABBCCDD...",
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	record, err := client.GenerateTlsaRecord(context.Background(), &GenerateTlsaRecordOptions{
		Domain:       "example.com.",
		Port:         443,
		Protocol:     "tcp",
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		CertPem:      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	})
	if err != nil {
		t.Fatalf("GenerateTlsaRecord: %v", err)
	}
	if captured.Domain != "example.com." {
		t.Errorf("domain = %q, want %q", captured.Domain, "example.com.")
	}
	if captured.Port != 443 {
		t.Errorf("port = %d, want 443", captured.Port)
	}
	if captured.Protocol != "tcp" {
		t.Errorf("protocol = %q, want %q", captured.Protocol, "tcp")
	}
	if captured.Usage != 3 {
		t.Errorf("usage = %d, want 3", captured.Usage)
	}
	if captured.Selector != 1 {
		t.Errorf("selector = %d, want 1", captured.Selector)
	}
	if captured.MatchingType != 1 {
		t.Errorf("matching_type = %d, want 1", captured.MatchingType)
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
	if record != "_443._tcp.example.com. IN TLSA 3 1 1 AABBCCDD..." {
		t.Errorf("record = %q, want %q", record, "_443._tcp.example.com. IN TLSA 3 1 1 AABBCCDD...")
	}
}

func TestListTlsaRecords(t *testing.T) {
	mock := &mockRolodexDnsService{
		listTlsaRecordsFn: func(_ context.Context, req *pb.ListTlsaRecordsRequest) (*pb.ListTlsaRecordsResponse, error) {
			return &pb.ListTlsaRecordsResponse{
				Records: []*pb.DnsRecord{
					{Name: "_443._tcp.example.com.", RecordType: pb.RecordType_TLSA, Value: "3 1 1 AABBCCDD"},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	records, err := client.ListTlsaRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("ListTlsaRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Name != "_443._tcp.example.com." {
		t.Errorf("records[0].Name = %q, want %q", records[0].Name, "_443._tcp.example.com.")
	}
	if records[0].RecordType != pb.RecordType_TLSA {
		t.Errorf("records[0].RecordType = %v, want TLSA", records[0].RecordType)
	}
}

func TestGenerateDaneRootCa(t *testing.T) {
	var captured *pb.GenerateDaneRootCaRequest
	mock := &mockRolodexDnsService{
		generateDaneRootCaFn: func(_ context.Context, req *pb.GenerateDaneRootCaRequest) (*pb.GenerateDaneRootCaResponse, error) {
			captured = req
			return &pb.GenerateDaneRootCaResponse{
				Success: true,
				CertPem: "-----BEGIN CERTIFICATE-----\nROOTCA\n-----END CERTIFICATE-----",
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	certPem, err := client.GenerateDaneRootCa(context.Background(), "My DANE Root CA")
	if err != nil {
		t.Fatalf("GenerateDaneRootCa: %v", err)
	}
	if captured.Name != "My DANE Root CA" {
		t.Errorf("name = %q, want %q", captured.Name, "My DANE Root CA")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
	if certPem != "-----BEGIN CERTIFICATE-----\nROOTCA\n-----END CERTIFICATE-----" {
		t.Errorf("cert_pem = %q, want PEM certificate", certPem)
	}
}

func TestRequestAcmeCert(t *testing.T) {
	var captured *pb.RequestAcmeCertRequest
	mock := &mockRolodexDnsService{
		requestAcmeCertFn: func(_ context.Context, req *pb.RequestAcmeCertRequest) (*pb.RequestAcmeCertResponse, error) {
			captured = req
			return &pb.RequestAcmeCertResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	err := client.RequestAcmeCert(context.Background(), "example.com", "https://acme-v02.api.letsencrypt.org/directory")
	if err != nil {
		t.Fatalf("RequestAcmeCert: %v", err)
	}
	if captured.Domain != "example.com" {
		t.Errorf("domain = %q, want %q", captured.Domain, "example.com")
	}
	if captured.ProviderUrl != "https://acme-v02.api.letsencrypt.org/directory" {
		t.Errorf("provider_url = %q, want %q", captured.ProviderUrl, "https://acme-v02.api.letsencrypt.org/directory")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestGetAcmeStatus(t *testing.T) {
	mock := &mockRolodexDnsService{
		getAcmeStatusFn: func(_ context.Context, req *pb.GetAcmeStatusRequest) (*pb.GetAcmeStatusResponse, error) {
			return &pb.GetAcmeStatusResponse{
				Status:    "valid",
				ExpiresAt: 1700000000,
				Domain:    "example.com",
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	acmeStatus, err := client.GetAcmeStatus(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("GetAcmeStatus: %v", err)
	}
	if acmeStatus.Status != "valid" {
		t.Errorf("status = %q, want %q", acmeStatus.Status, "valid")
	}
	if acmeStatus.ExpiresAt != 1700000000 {
		t.Errorf("expires_at = %d, want 1700000000", acmeStatus.ExpiresAt)
	}
	if acmeStatus.Domain != "example.com" {
		t.Errorf("domain = %q, want %q", acmeStatus.Domain, "example.com")
	}
}

func TestSetDns64Config(t *testing.T) {
	var captured *pb.SetDns64ConfigRequest
	mock := &mockRolodexDnsService{
		setDns64ConfigFn: func(_ context.Context, req *pb.SetDns64ConfigRequest) (*pb.SetDns64ConfigResponse, error) {
			captured = req
			return &pb.SetDns64ConfigResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	cfg := &Dns64Config{
		Enabled: true,
		Prefix:  "64:ff9b::",
	}
	err := client.SetDns64Config(context.Background(), cfg)
	if err != nil {
		t.Fatalf("SetDns64Config: %v", err)
	}
	if !captured.Config.Enabled {
		t.Errorf("enabled = false, want true")
	}
	if captured.Config.Prefix != "64:ff9b::" {
		t.Errorf("prefix = %q, want %q", captured.Config.Prefix, "64:ff9b::")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
}

func TestGetDns64Config(t *testing.T) {
	mock := &mockRolodexDnsService{
		getDns64ConfigFn: func(_ context.Context, req *pb.GetDns64ConfigRequest) (*pb.GetDns64ConfigResponse, error) {
			return &pb.GetDns64ConfigResponse{
				Config: &pb.Dns64Config{
					Enabled: true,
					Prefix:  "64:ff9b::",
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))
	cfg, err := client.GetDns64Config(context.Background())
	if err != nil {
		t.Fatalf("GetDns64Config: %v", err)
	}
	if !cfg.Enabled {
		t.Errorf("enabled = false, want true")
	}
	if cfg.Prefix != "64:ff9b::" {
		t.Errorf("prefix = %q, want %q", cfg.Prefix, "64:ff9b::")
	}
}

func TestAddDhcpPool(t *testing.T) {
	var captured *pb.AddDhcpPoolRequest
	mock := &mockRolodexDnsService{
		addDhcpPoolFn: func(_ context.Context, req *pb.AddDhcpPoolRequest) (*pb.AddDhcpPoolResponse, error) {
			captured = req
			return &pb.AddDhcpPoolResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("test-token"))

	err := client.AddDhcpPool(context.Background(), &DhcpPool{
		ScopeName:  "office",
		RangeStart: "10.0.0.100",
		RangeEnd:   "10.0.0.200",
		Gateway:    "10.0.0.1",
		SubnetMask: "255.255.255.0",
		DnsServers: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("AddDhcpPool returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.AuthToken != "test-token" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "test-token")
	}
	if captured.Pool.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.Pool.ScopeName, "office")
	}
	if captured.Pool.RangeStart != "10.0.0.100" {
		t.Errorf("range start = %q, want %q", captured.Pool.RangeStart, "10.0.0.100")
	}
	if captured.Pool.RangeEnd != "10.0.0.200" {
		t.Errorf("range end = %q, want %q", captured.Pool.RangeEnd, "10.0.0.200")
	}
	if captured.Pool.Gateway != "10.0.0.1" {
		t.Errorf("gateway = %q, want %q", captured.Pool.Gateway, "10.0.0.1")
	}
	if captured.Pool.SubnetMask != "255.255.255.0" {
		t.Errorf("subnet mask = %q, want %q", captured.Pool.SubnetMask, "255.255.255.0")
	}
	if captured.Pool.DnsServers != "10.0.0.1" {
		t.Errorf("dns servers = %q, want %q", captured.Pool.DnsServers, "10.0.0.1")
	}
}

func TestRemoveDhcpPool(t *testing.T) {
	var captured *pb.RemoveDhcpPoolRequest
	mock := &mockRolodexDnsService{
		removeDhcpPoolFn: func(_ context.Context, req *pb.RemoveDhcpPoolRequest) (*pb.RemoveDhcpPoolResponse, error) {
			captured = req
			return &pb.RemoveDhcpPoolResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("test-token"))

	err := client.RemoveDhcpPool(context.Background(), 42)
	if err != nil {
		t.Fatalf("RemoveDhcpPool returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.PoolId != 42 {
		t.Errorf("pool id = %d, want %d", captured.PoolId, 42)
	}
	if captured.AuthToken != "test-token" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "test-token")
	}
}

func TestListDhcpPools(t *testing.T) {
	var captured *pb.ListDhcpPoolsRequest
	mock := &mockRolodexDnsService{
		listDhcpPoolsFn: func(_ context.Context, req *pb.ListDhcpPoolsRequest) (*pb.ListDhcpPoolsResponse, error) {
			captured = req
			return &pb.ListDhcpPoolsResponse{
				Pools: []*pb.DhcpPool{
					{Id: 1, ScopeName: "office", RangeStart: "10.0.0.100", RangeEnd: "10.0.0.200", Gateway: "10.0.0.1", SubnetMask: "255.255.255.0"},
					{Id: 2, ScopeName: "office", RangeStart: "10.0.1.100", RangeEnd: "10.0.1.200", Gateway: "10.0.1.1", SubnetMask: "255.255.255.0"},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))

	pools, err := client.ListDhcpPools(context.Background(), "office")
	if err != nil {
		t.Fatalf("ListDhcpPools returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.ScopeName, "office")
	}
	if captured.AuthToken != "tok" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "tok")
	}
	if len(pools) != 2 {
		t.Fatalf("got %d pools, want 2", len(pools))
	}
	if pools[0].RangeStart != "10.0.0.100" {
		t.Errorf("pool[0] range start = %q, want %q", pools[0].RangeStart, "10.0.0.100")
	}
}

func TestListDhcpLeases(t *testing.T) {
	var captured *pb.ListDhcpLeasesRequest
	mock := &mockRolodexDnsService{
		listDhcpLeasesFn: func(_ context.Context, req *pb.ListDhcpLeasesRequest) (*pb.ListDhcpLeasesResponse, error) {
			captured = req
			return &pb.ListDhcpLeasesResponse{
				Leases: []*pb.DhcpLease{
					{Mac: "aa:bb:cc:dd:ee:ff", Ip: "10.0.0.101", ScopeName: "office", Hostname: "workstation1", LeaseStart: 1000, LeaseDuration: 3600, State: "active"},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))

	leases, err := client.ListDhcpLeases(context.Background(), "office")
	if err != nil {
		t.Fatalf("ListDhcpLeases returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.ScopeName, "office")
	}
	if len(leases) != 1 {
		t.Fatalf("got %d leases, want 1", len(leases))
	}
	if leases[0].Mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("lease mac = %q, want %q", leases[0].Mac, "aa:bb:cc:dd:ee:ff")
	}
	if leases[0].Ip != "10.0.0.101" {
		t.Errorf("lease ip = %q, want %q", leases[0].Ip, "10.0.0.101")
	}
	if leases[0].State != "active" {
		t.Errorf("lease state = %q, want %q", leases[0].State, "active")
	}
}

func TestDeleteDhcpLease(t *testing.T) {
	var captured *pb.DeleteDhcpLeaseRequest
	mock := &mockRolodexDnsService{
		deleteDhcpLeaseFn: func(_ context.Context, req *pb.DeleteDhcpLeaseRequest) (*pb.DeleteDhcpLeaseResponse, error) {
			captured = req
			return &pb.DeleteDhcpLeaseResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("test-token"))

	err := client.DeleteDhcpLease(context.Background(), "aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("DeleteDhcpLease returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.Mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac = %q, want %q", captured.Mac, "aa:bb:cc:dd:ee:ff")
	}
	if captured.AuthToken != "test-token" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "test-token")
	}
}

func TestAddScopeRblProvider(t *testing.T) {
	var captured *pb.AddScopeRblProviderRequest
	mock := &mockRolodexDnsService{
		addScopeRblProviderFn: func(_ context.Context, req *pb.AddScopeRblProviderRequest) (*pb.AddScopeRblProviderResponse, error) {
			captured = req
			return &pb.AddScopeRblProviderResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("test-token"))

	err := client.AddScopeRblProvider(context.Background(), "office", "zen.spamhaus.org", true)
	if err != nil {
		t.Fatalf("AddScopeRblProvider returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.AuthToken != "test-token" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "test-token")
	}
	if captured.Provider.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.Provider.ScopeName, "office")
	}
	if captured.Provider.Zone != "zen.spamhaus.org" {
		t.Errorf("zone = %q, want %q", captured.Provider.Zone, "zen.spamhaus.org")
	}
	if !captured.Provider.Enabled {
		t.Errorf("enabled = false, want true")
	}
}

func TestRemoveScopeRblProvider(t *testing.T) {
	var captured *pb.RemoveScopeRblProviderRequest
	mock := &mockRolodexDnsService{
		removeScopeRblProviderFn: func(_ context.Context, req *pb.RemoveScopeRblProviderRequest) (*pb.RemoveScopeRblProviderResponse, error) {
			captured = req
			return &pb.RemoveScopeRblProviderResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("test-token"))

	err := client.RemoveScopeRblProvider(context.Background(), "office", "zen.spamhaus.org")
	if err != nil {
		t.Fatalf("RemoveScopeRblProvider returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.ScopeName, "office")
	}
	if captured.Zone != "zen.spamhaus.org" {
		t.Errorf("zone = %q, want %q", captured.Zone, "zen.spamhaus.org")
	}
	if captured.AuthToken != "test-token" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "test-token")
	}
}

func TestListScopeRblProviders(t *testing.T) {
	var captured *pb.ListScopeRblProvidersRequest
	mock := &mockRolodexDnsService{
		listScopeRblProvidersFn: func(_ context.Context, req *pb.ListScopeRblProvidersRequest) (*pb.ListScopeRblProvidersResponse, error) {
			captured = req
			return &pb.ListScopeRblProvidersResponse{
				Providers: []*pb.ScopeRblProvider{
					{ScopeName: "office", Zone: "zen.spamhaus.org", Enabled: true},
					{ScopeName: "office", Zone: "bl.spamcop.net", Enabled: false},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))

	providers, err := client.ListScopeRblProviders(context.Background(), "office")
	if err != nil {
		t.Fatalf("ListScopeRblProviders returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.ScopeName, "office")
	}
	if len(providers) != 2 {
		t.Fatalf("got %d providers, want 2", len(providers))
	}
	if providers[0].Zone != "zen.spamhaus.org" {
		t.Errorf("provider[0] zone = %q, want %q", providers[0].Zone, "zen.spamhaus.org")
	}
	if !providers[0].Enabled {
		t.Errorf("provider[0] enabled = false, want true")
	}
	if providers[1].Enabled {
		t.Errorf("provider[1] enabled = true, want false")
	}
}

func TestSetDhcpCertOption(t *testing.T) {
	var captured *pb.SetDhcpCertOptionRequest
	mock := &mockRolodexDnsService{
		setDhcpCertOptionFn: func(_ context.Context, req *pb.SetDhcpCertOptionRequest) (*pb.SetDhcpCertOptionResponse, error) {
			captured = req
			return &pb.SetDhcpCertOptionResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("test-token"))

	certData := []byte("fake-cert-data")
	err := client.SetDhcpCertOption(context.Background(), &DhcpCertOption{
		ScopeName:   "office",
		OptionCode:  224,
		CertData:    certData,
		Description: "Test CA cert",
	})
	if err != nil {
		t.Fatalf("SetDhcpCertOption returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.AuthToken != "test-token" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "test-token")
	}
	if captured.Option.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.Option.ScopeName, "office")
	}
	if captured.Option.OptionCode != 224 {
		t.Errorf("option code = %d, want %d", captured.Option.OptionCode, 224)
	}
	if string(captured.Option.CertData) != "fake-cert-data" {
		t.Errorf("cert data = %q, want %q", string(captured.Option.CertData), "fake-cert-data")
	}
	if captured.Option.Description != "Test CA cert" {
		t.Errorf("description = %q, want %q", captured.Option.Description, "Test CA cert")
	}
}

func TestRemoveDhcpCertOption(t *testing.T) {
	var captured *pb.RemoveDhcpCertOptionRequest
	mock := &mockRolodexDnsService{
		removeDhcpCertOptionFn: func(_ context.Context, req *pb.RemoveDhcpCertOptionRequest) (*pb.RemoveDhcpCertOptionResponse, error) {
			captured = req
			return &pb.RemoveDhcpCertOptionResponse{Success: true}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("test-token"))

	err := client.RemoveDhcpCertOption(context.Background(), "office", 224)
	if err != nil {
		t.Fatalf("RemoveDhcpCertOption returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.ScopeName, "office")
	}
	if captured.OptionCode != 224 {
		t.Errorf("option code = %d, want %d", captured.OptionCode, 224)
	}
	if captured.AuthToken != "test-token" {
		t.Errorf("auth token = %q, want %q", captured.AuthToken, "test-token")
	}
}

func TestListDhcpCertOptions(t *testing.T) {
	var captured *pb.ListDhcpCertOptionsRequest
	mock := &mockRolodexDnsService{
		listDhcpCertOptionsFn: func(_ context.Context, req *pb.ListDhcpCertOptionsRequest) (*pb.ListDhcpCertOptionsResponse, error) {
			captured = req
			return &pb.ListDhcpCertOptionsResponse{
				Options: []*pb.DhcpCertOption{
					{ScopeName: "office", OptionCode: 224, CertData: []byte("cert-1"), Description: "CA cert"},
					{ScopeName: "office", OptionCode: 225, CertData: []byte("cert-2"), Description: "Intermediate cert"},
				},
			}, nil
		},
	}
	client := startMockServer(t, mock, WithAuthToken("tok"))

	options, err := client.ListDhcpCertOptions(context.Background(), "office")
	if err != nil {
		t.Fatalf("ListDhcpCertOptions returned error: %v", err)
	}

	if captured == nil {
		t.Fatal("server did not receive request")
	}
	if captured.ScopeName != "office" {
		t.Errorf("scope name = %q, want %q", captured.ScopeName, "office")
	}
	if len(options) != 2 {
		t.Fatalf("got %d options, want 2", len(options))
	}
	if options[0].OptionCode != 224 {
		t.Errorf("option[0] code = %d, want %d", options[0].OptionCode, 224)
	}
	if options[0].Description != "CA cert" {
		t.Errorf("option[0] description = %q, want %q", options[0].Description, "CA cert")
	}
	if string(options[1].CertData) != "cert-2" {
		t.Errorf("option[1] cert data = %q, want %q", string(options[1].CertData), "cert-2")
	}
}
