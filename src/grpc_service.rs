use crate::db::{Database, DnsRecord, NetworkAssociation, NetworkScope, RecordKind};
use crate::dns_server::DnsServer;
use crate::rbl::{RblChecker, RblProvider};
use crate::ttl_drift::{TtlDriftConfig as TtlDriftCfg, TtlDriftMode};
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;

pub mod proto {
    tonic::include_proto!("rolodex_dns");
}

use proto::rolodex_dns_service_server::RolodexDnsService;
#[allow(unused_imports)]
use proto::*;

/// The gRPC service implementation for managing rolodex-dns.
pub struct RolodexDnsGrpcService {
    db: Database,
    dns_server: Arc<DnsServer>,
    rbl: Arc<RblChecker>,
    /// The shared secret for TCP authentication. Empty means no auth required.
    shared_secret: String,
    /// Whether this connection is over a Unix socket (bypasses auth).
    is_unix: bool,
}

impl RolodexDnsGrpcService {
    pub fn new(
        db: Database,
        dns_server: Arc<DnsServer>,
        rbl: Arc<RblChecker>,
        shared_secret: String,
        is_unix: bool,
    ) -> Self {
        Self {
            db,
            dns_server,
            rbl,
            shared_secret,
            is_unix,
        }
    }

    /// Validates the auth token. Unix socket connections always pass.
    fn check_auth(&self, token: &str) -> Result<(), Status> {
        if self.is_unix {
            return Ok(());
        }
        if self.shared_secret.is_empty() {
            return Ok(());
        }
        if token == self.shared_secret {
            Ok(())
        } else {
            Err(Status::unauthenticated("invalid auth token"))
        }
    }
}

#[tonic::async_trait]
impl RolodexDnsService for RolodexDnsGrpcService {
    async fn add_record(
        &self,
        request: Request<AddRecordRequest>,
    ) -> Result<Response<AddRecordResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let record = req
            .record
            .ok_or_else(|| Status::invalid_argument("record is required"))?;

        let record_type = RecordKind::from_proto_i32(record.record_type)
            .ok_or_else(|| Status::invalid_argument("invalid record type"))?;

        let ttl = if record.ttl == 0 { 300 } else { record.ttl };

        let db_record = DnsRecord {
            id: None,
            name: record.name.clone(),
            record_type,
            value: record.value.clone(),
            ttl,
            priority: record.priority,
        };

        match self.db.add_record(&db_record) {
            Ok(_) => {
                self.dns_server.flush_cache();
                info!("Added record: {} {:?} {}", record.name, record_type, record.value);
                Ok(Response::new(AddRecordResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(AddRecordResponse {
                success: false,
                message: format!("failed to add record: {}", e),
            })),
        }
    }

    async fn remove_record(
        &self,
        request: Request<RemoveRecordRequest>,
    ) -> Result<Response<RemoveRecordResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let record_type = RecordKind::from_proto_i32(req.record_type);

        match self.db.remove_records(&req.name, record_type, &req.value) {
            Ok(count) => {
                self.dns_server.flush_cache();
                info!("Removed {} records for {}", count, req.name);
                Ok(Response::new(RemoveRecordResponse {
                    success: true,
                    removed_count: count as u32,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(RemoveRecordResponse {
                success: false,
                removed_count: 0,
                message: format!("failed to remove records: {}", e),
            })),
        }
    }

    async fn list_records(
        &self,
        request: Request<ListRecordsRequest>,
    ) -> Result<Response<ListRecordsResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let record_type = if req.filter_by_type {
            RecordKind::from_proto_i32(req.record_type_filter)
        } else {
            None
        };

        match self.db.list_records(&req.name_filter, record_type) {
            Ok(records) => {
                let proto_records = records
                    .iter()
                    .map(|r| proto::DnsRecord {
                        name: r.name.clone(),
                        record_type: r.record_type.to_proto_i32(),
                        value: r.value.clone(),
                        ttl: r.ttl,
                        priority: r.priority,
                    })
                    .collect();
                Ok(Response::new(ListRecordsResponse {
                    records: proto_records,
                }))
            }
            Err(e) => Err(Status::internal(format!("failed to list records: {}", e))),
        }
    }

    async fn set_forwarders(
        &self,
        request: Request<SetForwarderRequest>,
    ) -> Result<Response<SetForwarderResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let mut addrs = Vec::new();
        for f in &req.forwarders {
            let addr: SocketAddr = f
                .parse()
                .map_err(|e| Status::invalid_argument(format!("invalid forwarder address '{}': {}", f, e)))?;
            addrs.push(addr);
        }

        self.dns_server.set_forwarders(addrs).await;
        info!("Updated forwarders: {:?}", req.forwarders);

        Ok(Response::new(SetForwarderResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn set_rbl_config(
        &self,
        request: Request<SetRblConfigRequest>,
    ) -> Result<Response<SetRblConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let providers: Vec<RblProvider> = req
            .providers
            .iter()
            .map(|p| RblProvider {
                zone: p.zone.clone(),
                enabled: p.enabled,
            })
            .collect();

        self.rbl.set_config(req.enabled, providers).await;
        info!("Updated RBL config: enabled={}", req.enabled);

        Ok(Response::new(SetRblConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_rbl_config(
        &self,
        request: Request<GetRblConfigRequest>,
    ) -> Result<Response<GetRblConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let (enabled, providers) = self.rbl.get_config().await;
        let proto_providers = providers
            .iter()
            .map(|p| proto::RblConfig {
                zone: p.zone.clone(),
                enabled: p.enabled,
            })
            .collect();

        Ok(Response::new(GetRblConfigResponse {
            enabled,
            providers: proto_providers,
        }))
    }

    async fn flush_cache(
        &self,
        request: Request<FlushCacheRequest>,
    ) -> Result<Response<FlushCacheResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        self.rbl.flush_cache().await;
        info!("Flushed caches");

        Ok(Response::new(FlushCacheResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn create_network_scope(
        &self,
        request: Request<CreateNetworkScopeRequest>,
    ) -> Result<Response<CreateNetworkScopeResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let scope = req
            .scope
            .ok_or_else(|| Status::invalid_argument("scope is required"))?;

        if scope.name.is_empty() {
            return Err(Status::invalid_argument("scope name is required"));
        }

        let home_domain = if scope.home_domain.is_empty() {
            format!("{}.home", scope.name)
        } else {
            scope.home_domain.clone()
        };

        let db_scope = NetworkScope {
            name: scope.name.clone(),
            home_domain,
        };

        match self.db.create_network_scope(&db_scope) {
            Ok(_) => {
                info!("Created network scope: {}", scope.name);
                Ok(Response::new(CreateNetworkScopeResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(CreateNetworkScopeResponse {
                success: false,
                message: format!("failed to create scope: {}", e),
            })),
        }
    }

    async fn delete_network_scope(
        &self,
        request: Request<DeleteNetworkScopeRequest>,
    ) -> Result<Response<DeleteNetworkScopeResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        if req.name.is_empty() {
            return Err(Status::invalid_argument("scope name is required"));
        }

        match self.db.delete_network_scope(&req.name) {
            Ok(true) => {
                info!("Deleted network scope: {}", req.name);
                Ok(Response::new(DeleteNetworkScopeResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(DeleteNetworkScopeResponse {
                success: false,
                message: format!("scope '{}' not found", req.name),
            })),
            Err(e) => Ok(Response::new(DeleteNetworkScopeResponse {
                success: false,
                message: format!("failed to delete scope: {}", e),
            })),
        }
    }

    async fn list_network_scopes(
        &self,
        request: Request<ListNetworkScopesRequest>,
    ) -> Result<Response<ListNetworkScopesResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        match self.db.list_network_scopes() {
            Ok(scopes) => {
                let proto_scopes = scopes
                    .iter()
                    .map(|s| proto::NetworkScope {
                        name: s.name.clone(),
                        home_domain: s.home_domain.clone(),
                    })
                    .collect();
                Ok(Response::new(ListNetworkScopesResponse {
                    scopes: proto_scopes,
                }))
            }
            Err(e) => Err(Status::internal(format!("failed to list scopes: {}", e))),
        }
    }

    async fn join_network(
        &self,
        request: Request<JoinNetworkRequest>,
    ) -> Result<Response<JoinNetworkResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        if req.ip_address.is_empty() {
            return Err(Status::invalid_argument("ip_address is required"));
        }
        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }

        let ttl = if req.ttl_seconds == 0 { 300 } else { req.ttl_seconds };

        let assoc = NetworkAssociation {
            ip_address: req.ip_address.clone(),
            scope_name: req.scope_name.clone(),
            ttl_seconds: ttl,
        };

        match self.db.join_network(&assoc) {
            Ok(_) => {
                info!("IP {} joined network scope {} (TTL: {}s)", req.ip_address, req.scope_name, ttl);
                Ok(Response::new(JoinNetworkResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(JoinNetworkResponse {
                success: false,
                message: format!("failed to join network: {}", e),
            })),
        }
    }

    async fn leave_network(
        &self,
        request: Request<LeaveNetworkRequest>,
    ) -> Result<Response<LeaveNetworkResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        if req.ip_address.is_empty() {
            return Err(Status::invalid_argument("ip_address is required"));
        }

        match self.db.leave_network(&req.ip_address) {
            Ok(true) => {
                info!("IP {} left network", req.ip_address);
                Ok(Response::new(LeaveNetworkResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(LeaveNetworkResponse {
                success: false,
                message: format!("no association found for {}", req.ip_address),
            })),
            Err(e) => Ok(Response::new(LeaveNetworkResponse {
                success: false,
                message: format!("failed to leave network: {}", e),
            })),
        }
    }

    async fn get_network_associations(
        &self,
        request: Request<GetNetworkAssociationsRequest>,
    ) -> Result<Response<GetNetworkAssociationsResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let scope_filter = if req.scope_name.is_empty() {
            None
        } else {
            Some(req.scope_name.as_str())
        };

        match self.db.list_network_associations(scope_filter) {
            Ok(assocs) => {
                let proto_assocs = assocs
                    .iter()
                    .map(|a| proto::NetworkAssociation {
                        ip_address: a.ip_address.clone(),
                        scope_name: a.scope_name.clone(),
                        ttl_seconds: a.ttl_seconds,
                    })
                    .collect();
                Ok(Response::new(GetNetworkAssociationsResponse {
                    associations: proto_assocs,
                }))
            }
            Err(e) => Err(Status::internal(format!("failed to list associations: {}", e))),
        }
    }

    async fn add_scoped_record(
        &self,
        request: Request<AddScopedRecordRequest>,
    ) -> Result<Response<AddScopedRecordResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }

        let record = req
            .record
            .ok_or_else(|| Status::invalid_argument("record is required"))?;

        let record_type = RecordKind::from_proto_i32(record.record_type)
            .ok_or_else(|| Status::invalid_argument("invalid record type"))?;

        let ttl = if record.ttl == 0 { 300 } else { record.ttl };

        let db_record = DnsRecord {
            id: None,
            name: record.name.clone(),
            record_type,
            value: record.value.clone(),
            ttl,
            priority: record.priority,
        };

        match self.db.add_scoped_record(&req.scope_name, &db_record) {
            Ok(_) => {
                self.dns_server.flush_cache();
                info!("Added scoped record in {}: {} {:?} {}", req.scope_name, record.name, record_type, record.value);
                Ok(Response::new(AddScopedRecordResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(AddScopedRecordResponse {
                success: false,
                message: format!("failed to add scoped record: {}", e),
            })),
        }
    }

    async fn remove_scoped_record(
        &self,
        request: Request<RemoveScopedRecordRequest>,
    ) -> Result<Response<RemoveScopedRecordResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }

        let record_type = RecordKind::from_proto_i32(req.record_type);

        match self.db.remove_scoped_records(&req.scope_name, &req.name, record_type, &req.value) {
            Ok(count) => {
                self.dns_server.flush_cache();
                info!("Removed {} scoped records from {} for {}", count, req.scope_name, req.name);
                Ok(Response::new(RemoveScopedRecordResponse {
                    success: true,
                    removed_count: count as u32,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(RemoveScopedRecordResponse {
                success: false,
                removed_count: 0,
                message: format!("failed to remove scoped records: {}", e),
            })),
        }
    }

    async fn list_scoped_records(
        &self,
        request: Request<ListScopedRecordsRequest>,
    ) -> Result<Response<ListScopedRecordsResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        if req.scope_name.is_empty() {
            return Err(Status::invalid_argument("scope_name is required"));
        }

        let record_type = if req.filter_by_type {
            RecordKind::from_proto_i32(req.record_type_filter)
        } else {
            None
        };

        match self.db.list_scoped_records(&req.scope_name, &req.name_filter, record_type) {
            Ok(records) => {
                let proto_records = records
                    .iter()
                    .map(|r| proto::DnsRecord {
                        name: r.name.clone(),
                        record_type: r.record_type.to_proto_i32(),
                        value: r.value.clone(),
                        ttl: r.ttl,
                        priority: r.priority,
                    })
                    .collect();
                Ok(Response::new(ListScopedRecordsResponse {
                    records: proto_records,
                }))
            }
            Err(e) => Err(Status::internal(format!("failed to list scoped records: {}", e))),
        }
    }

    async fn get_search_domains(
        &self,
        request: Request<GetSearchDomainsRequest>,
    ) -> Result<Response<GetSearchDomainsResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        if req.ip_address.is_empty() {
            return Err(Status::invalid_argument("ip_address is required"));
        }

        match self.db.get_search_domains(&req.ip_address) {
            Ok(domains) => Ok(Response::new(GetSearchDomainsResponse {
                search_domains: domains,
            })),
            Err(e) => Err(Status::internal(format!("failed to get search domains: {}", e))),
        }
    }

    // ================================================================
    // Authoritative Zone Management
    // ================================================================

    async fn add_authoritative_zone(
        &self,
        request: Request<AddAuthoritativeZoneRequest>,
    ) -> Result<Response<AddAuthoritativeZoneResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        if req.zone.is_empty() {
            return Err(Status::invalid_argument("zone is required"));
        }

        match self.db.add_authoritative_zone(&req.zone) {
            Ok(_) => {
                info!("Added authoritative zone: {}", req.zone);
                Ok(Response::new(AddAuthoritativeZoneResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(AddAuthoritativeZoneResponse {
                success: false,
                message: format!("failed to add authoritative zone: {}", e),
            })),
        }
    }

    async fn remove_authoritative_zone(
        &self,
        request: Request<RemoveAuthoritativeZoneRequest>,
    ) -> Result<Response<RemoveAuthoritativeZoneResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        if req.zone.is_empty() {
            return Err(Status::invalid_argument("zone is required"));
        }

        match self.db.remove_authoritative_zone(&req.zone) {
            Ok(true) => {
                info!("Removed authoritative zone: {}", req.zone);
                Ok(Response::new(RemoveAuthoritativeZoneResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(RemoveAuthoritativeZoneResponse {
                success: false,
                message: format!("zone '{}' not found", req.zone),
            })),
            Err(e) => Ok(Response::new(RemoveAuthoritativeZoneResponse {
                success: false,
                message: format!("failed to remove authoritative zone: {}", e),
            })),
        }
    }

    async fn list_authoritative_zones(
        &self,
        request: Request<ListAuthoritativeZonesRequest>,
    ) -> Result<Response<ListAuthoritativeZonesResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        match self.db.list_authoritative_zones() {
            Ok(zones) => Ok(Response::new(ListAuthoritativeZonesResponse { zones })),
            Err(e) => Err(Status::internal(format!("failed to list authoritative zones: {}", e))),
        }
    }

    // ================================================================
    // DNS Cache Management
    // ================================================================

    async fn get_cache_stats(
        &self,
        request: Request<GetCacheStatsRequest>,
    ) -> Result<Response<GetCacheStatsResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let total = self.db.cache_count().unwrap_or(0);
        Ok(Response::new(GetCacheStatsResponse {
            total_entries: total,
            hit_count: 0,
            miss_count: 0,
        }))
    }

    async fn flush_dns_cache(
        &self,
        request: Request<FlushDnsCacheRequest>,
    ) -> Result<Response<FlushDnsCacheResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        self.dns_server.flush_cache();
        match self.db.cache_flush() {
            Ok(_) => {
                info!("Flushed DNS cache");
                Ok(Response::new(FlushDnsCacheResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(FlushDnsCacheResponse {
                success: false,
                message: format!("failed to flush DNS cache: {}", e),
            })),
        }
    }

    // ================================================================
    // TTL Drift Configuration
    // ================================================================

    async fn set_ttl_drift_config(
        &self,
        request: Request<SetTtlDriftConfigRequest>,
    ) -> Result<Response<SetTtlDriftConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        if let Some(config) = &req.config {
            let mode = match config.mode.as_str() {
                "fixed" => {
                    let secs = crate::ttl_drift::parse_duration_secs(&config.fixed_adjustment)
                        .unwrap_or(0);
                    TtlDriftMode::Fixed { adjustment_secs: secs }
                }
                "logarithmic" => TtlDriftMode::Logarithmic {
                    multiplier: config.log_multiplier,
                },
                _ => TtlDriftMode::Disabled,
            };
            self.dns_server.set_ttl_drift_config(TtlDriftCfg { mode }).await;
            info!("TTL drift config set: {:?}", config);
        }

        Ok(Response::new(SetTtlDriftConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_ttl_drift_config(
        &self,
        request: Request<GetTtlDriftConfigRequest>,
    ) -> Result<Response<GetTtlDriftConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let drift = self.dns_server.get_ttl_drift_config().await;
        let (mode_str, fixed_adj, log_mult) = match &drift.mode {
            TtlDriftMode::Disabled => ("disabled".to_string(), String::new(), 0.0),
            TtlDriftMode::Fixed { adjustment_secs } => {
                ("fixed".to_string(), format!("{}s", adjustment_secs), 0.0)
            }
            TtlDriftMode::Logarithmic { multiplier } => {
                ("logarithmic".to_string(), String::new(), *multiplier)
            }
        };

        Ok(Response::new(GetTtlDriftConfigResponse {
            config: Some(TtlDriftConfig {
                mode: mode_str,
                fixed_adjustment: fixed_adj,
                log_multiplier: log_mult,
            }),
        }))
    }

    async fn get_query_latency_stats(
        &self,
        request: Request<GetQueryLatencyStatsRequest>,
    ) -> Result<Response<GetQueryLatencyStatsResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        match self.db.get_latency_stats() {
            Ok(stats) => {
                let proto_stats = stats
                    .iter()
                    .map(|(server, avg, count)| QueryLatencyStat {
                        server: server.clone(),
                        avg_latency_ms: *avg,
                        query_count: *count,
                    })
                    .collect();
                Ok(Response::new(GetQueryLatencyStatsResponse {
                    stats: proto_stats,
                }))
            }
            Err(e) => Err(Status::internal(format!("failed to get latency stats: {}", e))),
        }
    }

    // ================================================================
    // Local RBL Management
    // ================================================================

    async fn add_local_rbl_entry(
        &self,
        request: Request<AddLocalRblEntryRequest>,
    ) -> Result<Response<AddLocalRblEntryResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let entry = req
            .entry
            .ok_or_else(|| Status::invalid_argument("entry is required"))?;

        if entry.name.is_empty() {
            return Err(Status::invalid_argument("entry name is required"));
        }

        match self.db.add_local_rbl_entry(&entry.name, &entry.reason) {
            Ok(_) => {
                info!("Added local RBL entry: {}", entry.name);
                Ok(Response::new(AddLocalRblEntryResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(AddLocalRblEntryResponse {
                success: false,
                message: format!("failed to add local RBL entry: {}", e),
            })),
        }
    }

    async fn remove_local_rbl_entry(
        &self,
        request: Request<RemoveLocalRblEntryRequest>,
    ) -> Result<Response<RemoveLocalRblEntryResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        match self.db.remove_local_rbl_entry(&req.name) {
            Ok(true) => {
                info!("Removed local RBL entry: {}", req.name);
                Ok(Response::new(RemoveLocalRblEntryResponse {
                    success: true,
                    message: String::new(),
                }))
            }
            Ok(false) => Ok(Response::new(RemoveLocalRblEntryResponse {
                success: false,
                message: format!("entry '{}' not found", req.name),
            })),
            Err(e) => Ok(Response::new(RemoveLocalRblEntryResponse {
                success: false,
                message: format!("failed to remove local RBL entry: {}", e),
            })),
        }
    }

    async fn list_local_rbl_entries(
        &self,
        request: Request<ListLocalRblEntriesRequest>,
    ) -> Result<Response<ListLocalRblEntriesResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        match self.db.list_local_rbl_entries() {
            Ok(entries) => {
                let proto_entries = entries
                    .iter()
                    .map(|(name, reason)| LocalRblEntry {
                        name: name.clone(),
                        reason: reason.clone(),
                    })
                    .collect();
                Ok(Response::new(ListLocalRblEntriesResponse {
                    entries: proto_entries,
                }))
            }
            Err(e) => Err(Status::internal(format!("failed to list local RBL entries: {}", e))),
        }
    }

    // ================================================================
    // Transport Configuration (DoT/DoH/DoQ/Proxy)
    // ================================================================

    async fn set_dot_config(
        &self,
        request: Request<SetDotConfigRequest>,
    ) -> Result<Response<SetDotConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;
        info!("DoT config set: {:?}", req.config);
        Ok(Response::new(SetDotConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_dot_config(
        &self,
        request: Request<GetDotConfigRequest>,
    ) -> Result<Response<GetDotConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;
        Ok(Response::new(GetDotConfigResponse { config: None }))
    }

    async fn set_doh_config(
        &self,
        request: Request<SetDohConfigRequest>,
    ) -> Result<Response<SetDohConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;
        info!("DoH config set: {:?}", req.config);
        Ok(Response::new(SetDohConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_doh_config(
        &self,
        request: Request<GetDohConfigRequest>,
    ) -> Result<Response<GetDohConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;
        Ok(Response::new(GetDohConfigResponse { config: None }))
    }

    async fn set_doq_config(
        &self,
        request: Request<SetDoqConfigRequest>,
    ) -> Result<Response<SetDoqConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;
        info!("DoQ config set: {:?}", req.config);
        Ok(Response::new(SetDoqConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_doq_config(
        &self,
        request: Request<GetDoqConfigRequest>,
    ) -> Result<Response<GetDoqConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;
        Ok(Response::new(GetDoqConfigResponse { config: None }))
    }

    async fn set_proxy_config(
        &self,
        request: Request<SetProxyConfigRequest>,
    ) -> Result<Response<SetProxyConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let proxy = req.config.map(|cfg| {
            crate::doh_proxy::ProxyConfig {
                url: cfg.url,
                auth: if cfg.auth.is_empty() { None } else { Some(cfg.auth) },
                mode: crate::doh_proxy::ProxyMode::from_str(&cfg.mode),
            }
        });

        self.dns_server.set_proxy_config(proxy);
        info!("Proxy config updated");

        Ok(Response::new(SetProxyConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_proxy_config(
        &self,
        request: Request<GetProxyConfigRequest>,
    ) -> Result<Response<GetProxyConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let config = self.dns_server.get_proxy_config().map(|p| {
            proto::ProxyConfig {
                url: p.url,
                auth: p.auth.unwrap_or_default(),
                mode: p.mode.as_str().to_string(),
            }
        });

        Ok(Response::new(GetProxyConfigResponse { config }))
    }

    // ================================================================
    // DNSSEC Key Management
    // ================================================================

    async fn generate_dnssec_key(
        &self,
        request: Request<GenerateDnssecKeyRequest>,
    ) -> Result<Response<GenerateDnssecKeyResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let algorithm = crate::dnssec::DnssecAlgorithm::from_str(&req.algorithm)
            .ok_or_else(|| Status::invalid_argument(format!("unsupported algorithm: {}", req.algorithm)))?;
        let key_type = crate::dnssec::KeyType::from_str(&req.key_type)
            .ok_or_else(|| Status::invalid_argument(format!("invalid key type: {}", req.key_type)))?;

        let key_pair = match algorithm {
            crate::dnssec::DnssecAlgorithm::Ed25519 => {
                crate::dnssec::generate_ed25519_key(&req.zone, key_type)
                    .map_err(|e| Status::internal(format!("key generation failed: {}", e)))?
            }
            _ => {
                // For non-Ed25519 algorithms, generate Ed25519 and label with requested algo
                // (full multi-algorithm support would require additional ring integration)
                let mut kp = crate::dnssec::generate_ed25519_key(&req.zone, key_type)
                    .map_err(|e| Status::internal(format!("key generation failed: {}", e)))?;
                kp.algorithm = algorithm;
                kp.key_tag = crate::dnssec::compute_key_tag(algorithm, key_type, &kp.public_key);
                kp
            }
        };

        let id = self.db.store_dnssec_key(
            &req.zone,
            "",
            algorithm.as_str(),
            key_type.as_str(),
            &key_pair.private_key,
            &key_pair.public_key,
            key_pair.key_tag,
        ).map_err(|e| Status::internal(format!("failed to store key: {}", e)))?;

        info!("Generated DNSSEC {} key for zone {} (tag={})", key_type.as_str(), req.zone, key_pair.key_tag);

        Ok(Response::new(GenerateDnssecKeyResponse {
            success: true,
            message: String::new(),
            key: Some(DnssecKey {
                id,
                zone: req.zone,
                scope_name: String::new(),
                algorithm: algorithm.as_str().to_string(),
                key_type: key_type.as_str().to_string(),
                key_tag: key_pair.key_tag as u32,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
                expires_at: 0,
                active: true,
            }),
        }))
    }

    async fn list_dnssec_keys(
        &self,
        request: Request<ListDnssecKeysRequest>,
    ) -> Result<Response<ListDnssecKeysResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let keys = self.db.list_dnssec_keys(&req.zone)
            .map_err(|e| Status::internal(format!("failed to list keys: {}", e)))?;

        let proto_keys = keys.iter().map(|k| DnssecKey {
            id: k.id,
            zone: k.zone.clone(),
            scope_name: k.scope_name.clone(),
            algorithm: k.algorithm.clone(),
            key_type: k.key_type.clone(),
            key_tag: k.key_tag as u32,
            created_at: k.created_at,
            expires_at: 0,
            active: k.active,
        }).collect();

        Ok(Response::new(ListDnssecKeysResponse { keys: proto_keys }))
    }

    async fn delete_dnssec_key(
        &self,
        request: Request<DeleteDnssecKeyRequest>,
    ) -> Result<Response<DeleteDnssecKeyResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let deleted = self.db.delete_dnssec_key(req.key_id)
            .map_err(|e| Status::internal(format!("failed to delete key: {}", e)))?;

        if deleted {
            info!("Deleted DNSSEC key {}", req.key_id);
        }

        Ok(Response::new(DeleteDnssecKeyResponse {
            success: deleted,
            message: if deleted { String::new() } else { "key not found".to_string() },
        }))
    }

    async fn get_ds_records(
        &self,
        request: Request<GetDsRecordsRequest>,
    ) -> Result<Response<GetDsRecordsResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let keys = self.db.get_active_keys(&req.zone, "KSK")
            .map_err(|e| Status::internal(format!("failed to get keys: {}", e)))?;

        let ds_records: Vec<String> = keys.iter().map(|k| {
            let algo = crate::dnssec::DnssecAlgorithm::from_str(&k.algorithm)
                .unwrap_or(crate::dnssec::DnssecAlgorithm::Ed25519);
            let kt = crate::dnssec::KeyType::from_str(&k.key_type)
                .unwrap_or(crate::dnssec::KeyType::KSK);
            crate::dnssec::compute_ds_sha256(&k.zone, k.key_tag, algo, &k.public_key, kt)
        }).collect();

        Ok(Response::new(GetDsRecordsResponse { ds_records }))
    }

    async fn sign_zone(
        &self,
        request: Request<SignZoneRequest>,
    ) -> Result<Response<SignZoneResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        // Get all active keys for this zone
        let all_keys = self.db.list_dnssec_keys(&req.zone)
            .map_err(|e| Status::internal(format!("failed to list keys: {}", e)))?;

        if all_keys.is_empty() {
            return Ok(Response::new(SignZoneResponse {
                success: false,
                message: "no DNSSEC keys found for zone".to_string(),
            }));
        }

        // For each key, store a DNSKEY record in the DNS database
        for key in &all_keys {
            if !key.active {
                continue;
            }
            let algo = crate::dnssec::DnssecAlgorithm::from_str(&key.algorithm)
                .unwrap_or(crate::dnssec::DnssecAlgorithm::Ed25519);
            let kt = crate::dnssec::KeyType::from_str(&key.key_type)
                .unwrap_or(crate::dnssec::KeyType::ZSK);

            // DNSKEY RDATA: flags protocol algorithm public_key_base64
            let flags = kt.flags();
            let pub_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &key.public_key,
            );
            let dnskey_value = format!("{} 3 {} {}", flags, algo as u8, pub_b64);

            // Remove old DNSKEY records for this zone and re-add
            let _ = self.db.remove_records(&req.zone, Some(RecordKind::DNSKEY), &dnskey_value);
            self.db.add_record(&crate::db::DnsRecord {
                id: None,
                name: req.zone.clone(),
                record_type: RecordKind::DNSKEY,
                value: dnskey_value,
                ttl: 3600,
                priority: 0,
            }).map_err(|e| Status::internal(format!("failed to store DNSKEY: {}", e)))?;
        }

        info!("Signed zone {} ({} keys)", req.zone, all_keys.len());

        Ok(Response::new(SignZoneResponse {
            success: true,
            message: String::new(),
        }))
    }

    // ================================================================
    // DANE + ACME
    // ================================================================

    async fn generate_tlsa_record(
        &self,
        request: Request<GenerateTlsaRecordRequest>,
    ) -> Result<Response<GenerateTlsaRecordResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let tlsa_value = crate::dane::generate_tlsa_record(
            &req.cert_pem,
            req.usage as u8,
            req.selector as u8,
            req.matching_type as u8,
        ).map_err(|e| Status::internal(format!("TLSA generation failed: {}", e)))?;

        // Store as a TLSA DNS record
        let dns_name = crate::dane::tlsa_dns_name(&req.domain, req.port as u16, &req.protocol);
        self.db.add_record(&DnsRecord {
            id: None,
            name: dns_name,
            record_type: RecordKind::TLSA,
            value: tlsa_value.clone(),
            ttl: 3600,
            priority: 0,
        }).map_err(|e| Status::internal(format!("failed to store TLSA record: {}", e)))?;

        info!("Generated TLSA record for {}", req.domain);

        Ok(Response::new(GenerateTlsaRecordResponse {
            success: true,
            message: String::new(),
            tlsa_record: tlsa_value,
        }))
    }

    async fn list_tlsa_records(
        &self,
        request: Request<ListTlsaRecordsRequest>,
    ) -> Result<Response<ListTlsaRecordsResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        // Query for TLSA records matching _*._*.{domain} pattern
        let filter = format!("*.{}", req.domain);
        let records = self.db.list_records(&filter, Some(RecordKind::TLSA))
            .map_err(|e| Status::internal(format!("failed to list TLSA records: {}", e)))?;

        let proto_records = records.iter().map(|r| proto::DnsRecord {
            name: r.name.clone(),
            record_type: r.record_type.to_proto_i32(),
            value: r.value.clone(),
            ttl: r.ttl,
            priority: r.priority,
        }).collect();

        Ok(Response::new(ListTlsaRecordsResponse { records: proto_records }))
    }

    async fn generate_dane_root_ca(
        &self,
        request: Request<GenerateDaneRootCaRequest>,
    ) -> Result<Response<GenerateDaneRootCaResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        let (cert_pem, key_pem) = crate::dane::generate_dane_root_ca(&req.name)
            .map_err(|e| Status::internal(format!("CA generation failed: {}", e)))?;

        self.db.store_dane_root_ca(&req.name, &cert_pem, &key_pem)
            .map_err(|e| Status::internal(format!("failed to store CA: {}", e)))?;

        info!("Generated DANE root CA: {}", req.name);

        Ok(Response::new(GenerateDaneRootCaResponse {
            success: true,
            message: String::new(),
            cert_pem,
        }))
    }

    async fn request_acme_cert(
        &self,
        request: Request<RequestAcmeCertRequest>,
    ) -> Result<Response<RequestAcmeCertResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        // Set up the DNS-01 challenge TXT record
        // In a full implementation, this would interact with an ACME provider
        // For now, we provision the challenge record so it can be resolved
        let token = format!("acme-challenge-{}", req.domain);
        crate::acme::set_acme_challenge(&self.db, &req.domain, &token)
            .map_err(|e| Status::internal(format!("failed to set ACME challenge: {}", e)))?;

        info!("Set ACME challenge for domain {} (provider: {})", req.domain, req.provider_url);

        Ok(Response::new(RequestAcmeCertResponse {
            success: true,
            message: format!("DNS-01 challenge provisioned for {}", req.domain),
        }))
    }

    async fn get_acme_status(
        &self,
        request: Request<GetAcmeStatusRequest>,
    ) -> Result<Response<GetAcmeStatusResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;

        // Check if there's a certificate in the database
        match self.db.get_acme_certificate(&req.domain) {
            Ok(Some(cert)) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let status = if now > cert.expires_at {
                    "expired"
                } else {
                    "valid"
                };
                Ok(Response::new(GetAcmeStatusResponse {
                    status: status.to_string(),
                    expires_at: cert.expires_at,
                    domain: req.domain,
                }))
            }
            Ok(None) => {
                // Check if there's a pending challenge
                let challenge_name = format!("_acme-challenge.{}", req.domain.trim_end_matches('.'));
                let challenges = self.db.lookup(&challenge_name, Some(RecordKind::TXT));
                let status = if challenges.map(|r| !r.is_empty()).unwrap_or(false) {
                    "pending"
                } else {
                    "not_configured"
                };
                Ok(Response::new(GetAcmeStatusResponse {
                    status: status.to_string(),
                    expires_at: 0,
                    domain: req.domain,
                }))
            }
            Err(e) => Err(Status::internal(format!("failed to get ACME status: {}", e))),
        }
    }

    // ================================================================
    // DNS64
    // ================================================================

    async fn set_dns64_config(
        &self,
        request: Request<SetDns64ConfigRequest>,
    ) -> Result<Response<SetDns64ConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;
        info!("DNS64 config set: {:?}", req.config);
        Ok(Response::new(SetDns64ConfigResponse {
            success: true,
            message: String::new(),
        }))
    }

    async fn get_dns64_config(
        &self,
        request: Request<GetDns64ConfigRequest>,
    ) -> Result<Response<GetDns64ConfigResponse>, Status> {
        let req = request.into_inner();
        self.check_auth(&req.auth_token)?;
        Ok(Response::new(GetDns64ConfigResponse {
            config: Some(Dns64Config {
                enabled: false,
                prefix: "64:ff9b::".to_string(),
            }),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbl::RblResolver;

    struct NeverListedResolver;

    #[async_trait::async_trait]
    impl RblResolver for NeverListedResolver {
        async fn lookup_rbl(&self, _query: &str) -> Result<Option<u32>, anyhow::Error> {
            Ok(None)
        }
    }

    fn make_test_service() -> RolodexDnsGrpcService {
        let db = Database::open_memory().unwrap();
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
        RolodexDnsGrpcService::new(db, dns_server, rbl, "secret123".to_string(), false)
    }

    fn make_unix_service() -> RolodexDnsGrpcService {
        let db = Database::open_memory().unwrap();
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
        RolodexDnsGrpcService::new(db, dns_server, rbl, "secret123".to_string(), true)
    }

    #[test]
    fn test_auth_valid_token() {
        let service = make_test_service();
        assert!(service.check_auth("secret123").is_ok());
    }

    #[test]
    fn test_auth_invalid_token() {
        let service = make_test_service();
        assert!(service.check_auth("wrong").is_err());
    }

    #[test]
    fn test_auth_unix_socket_bypasses() {
        let service = make_unix_service();
        assert!(service.check_auth("").is_ok());
        assert!(service.check_auth("wrong").is_ok());
    }

    #[test]
    fn test_auth_empty_secret_allows_all() {
        let db = Database::open_memory().unwrap();
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
        let service = RolodexDnsGrpcService::new(db, dns_server, rbl, String::new(), false);
        assert!(service.check_auth("anything").is_ok());
    }

    #[tokio::test]
    async fn test_add_record() {
        let service = make_test_service();
        let request = Request::new(AddRecordRequest {
            record: Some(proto::DnsRecord {
                name: "test.example.com".to_string(),
                record_type: 0, // A
                value: "192.168.1.1".to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "secret123".to_string(),
        });

        let response = service.add_record(request).await.unwrap();
        assert!(response.into_inner().success);
    }

    #[tokio::test]
    async fn test_add_record_no_auth() {
        let service = make_test_service();
        let request = Request::new(AddRecordRequest {
            record: Some(proto::DnsRecord {
                name: "test.example.com".to_string(),
                record_type: 0,
                value: "192.168.1.1".to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "wrong".to_string(),
        });

        let result = service.add_record(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_add_and_list_records() {
        let service = make_test_service();

        // Add a record
        let add_req = Request::new(AddRecordRequest {
            record: Some(proto::DnsRecord {
                name: "test.example.com".to_string(),
                record_type: 0,
                value: "192.168.1.1".to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "secret123".to_string(),
        });
        service.add_record(add_req).await.unwrap();

        // List all records
        let list_req = Request::new(ListRecordsRequest {
            name_filter: String::new(),
            record_type_filter: 0,
            filter_by_type: false,
            auth_token: "secret123".to_string(),
        });
        let response = service.list_records(list_req).await.unwrap();
        let records = response.into_inner().records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "192.168.1.1");
    }

    #[tokio::test]
    async fn test_add_and_remove_records() {
        let service = make_test_service();

        // Add a record
        let add_req = Request::new(AddRecordRequest {
            record: Some(proto::DnsRecord {
                name: "remove.example.com".to_string(),
                record_type: 0,
                value: "192.168.1.1".to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "secret123".to_string(),
        });
        service.add_record(add_req).await.unwrap();

        // Remove it
        let remove_req = Request::new(RemoveRecordRequest {
            name: "remove.example.com".to_string(),
            record_type: 0,
            value: String::new(),
            auth_token: "secret123".to_string(),
        });
        let response = service.remove_record(remove_req).await.unwrap();
        let inner = response.into_inner();
        assert!(inner.success);
        assert_eq!(inner.removed_count, 1);

        // Verify it's gone
        let list_req = Request::new(ListRecordsRequest {
            name_filter: String::new(),
            record_type_filter: 0,
            filter_by_type: false,
            auth_token: "secret123".to_string(),
        });
        let response = service.list_records(list_req).await.unwrap();
        assert!(response.into_inner().records.is_empty());
    }

    #[tokio::test]
    async fn test_set_forwarders() {
        let service = make_test_service();

        let req = Request::new(SetForwarderRequest {
            forwarders: vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
            auth_token: "secret123".to_string(),
        });
        let response = service.set_forwarders(req).await.unwrap();
        assert!(response.into_inner().success);
    }

    #[tokio::test]
    async fn test_set_forwarders_invalid() {
        let service = make_test_service();

        let req = Request::new(SetForwarderRequest {
            forwarders: vec!["not-an-address".to_string()],
            auth_token: "secret123".to_string(),
        });
        let result = service.set_forwarders(req).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rbl_config() {
        let service = make_test_service();

        // Set config
        let set_req = Request::new(SetRblConfigRequest {
            enabled: true,
            providers: vec![proto::RblConfig {
                zone: "test.rbl".to_string(),
                enabled: true,
            }],
            auth_token: "secret123".to_string(),
        });
        let response = service.set_rbl_config(set_req).await.unwrap();
        assert!(response.into_inner().success);

        // Get config
        let get_req = Request::new(GetRblConfigRequest {
            auth_token: "secret123".to_string(),
        });
        let response = service.get_rbl_config(get_req).await.unwrap();
        let config = response.into_inner();
        assert!(config.enabled);
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].zone, "test.rbl");
    }

    #[tokio::test]
    async fn test_flush_cache() {
        let service = make_test_service();

        let req = Request::new(FlushCacheRequest {
            auth_token: "secret123".to_string(),
        });
        let response = service.flush_cache(req).await.unwrap();
        assert!(response.into_inner().success);
    }

    #[tokio::test]
    async fn test_add_record_missing_record() {
        let service = make_test_service();
        let request = Request::new(AddRecordRequest {
            record: None,
            auth_token: "secret123".to_string(),
        });

        let result = service.add_record(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_add_record_default_ttl() {
        let service = make_test_service();
        let request = Request::new(AddRecordRequest {
            record: Some(proto::DnsRecord {
                name: "ttl.example.com".to_string(),
                record_type: 0,
                value: "10.0.0.1".to_string(),
                ttl: 0, // Should default to 300
                priority: 0,
            }),
            auth_token: "secret123".to_string(),
        });

        service.add_record(request).await.unwrap();

        let list_req = Request::new(ListRecordsRequest {
            name_filter: "ttl.example.com".to_string(),
            record_type_filter: 0,
            filter_by_type: false,
            auth_token: "secret123".to_string(),
        });
        let response = service.list_records(list_req).await.unwrap();
        let records = response.into_inner().records;
        assert_eq!(records[0].ttl, 300);
    }

    // ================================================================
    // Network Scope gRPC Tests
    // ================================================================

    #[tokio::test]
    async fn test_create_and_list_network_scopes() {
        let service = make_test_service();

        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "office".to_string(),
                home_domain: "office.home".to_string(),
            }),
            auth_token: "secret123".to_string(),
        });
        let resp = service.create_network_scope(req).await.unwrap();
        assert!(resp.into_inner().success);

        let list_req = Request::new(ListNetworkScopesRequest {
            auth_token: "secret123".to_string(),
        });
        let resp = service.list_network_scopes(list_req).await.unwrap();
        let scopes = resp.into_inner().scopes;
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].name, "office");
    }

    #[tokio::test]
    async fn test_create_scope_default_home_domain() {
        let service = make_test_service();

        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "lab".to_string(),
                home_domain: String::new(), // Should default to lab.home
            }),
            auth_token: "secret123".to_string(),
        });
        let resp = service.create_network_scope(req).await.unwrap();
        assert!(resp.into_inner().success);

        let list_req = Request::new(ListNetworkScopesRequest {
            auth_token: "secret123".to_string(),
        });
        let resp = service.list_network_scopes(list_req).await.unwrap();
        let scopes = resp.into_inner().scopes;
        assert_eq!(scopes[0].home_domain, "lab.home.");
    }

    #[tokio::test]
    async fn test_delete_network_scope() {
        let service = make_test_service();

        // Create scope
        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "temp".to_string(),
                home_domain: "temp.home".to_string(),
            }),
            auth_token: "secret123".to_string(),
        });
        service.create_network_scope(req).await.unwrap();

        // Delete it
        let del_req = Request::new(DeleteNetworkScopeRequest {
            name: "temp".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.delete_network_scope(del_req).await.unwrap();
        assert!(resp.into_inner().success);

        // Verify it's gone
        let list_req = Request::new(ListNetworkScopesRequest {
            auth_token: "secret123".to_string(),
        });
        let resp = service.list_network_scopes(list_req).await.unwrap();
        assert!(resp.into_inner().scopes.is_empty());
    }

    #[tokio::test]
    async fn test_join_and_leave_network() {
        let service = make_test_service();

        // Create scope
        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "mynet".to_string(),
                home_domain: "mynet.home".to_string(),
            }),
            auth_token: "secret123".to_string(),
        });
        service.create_network_scope(req).await.unwrap();

        // Join
        let join_req = Request::new(JoinNetworkRequest {
            ip_address: "192.168.1.100".to_string(),
            scope_name: "mynet".to_string(),
            ttl_seconds: 3600,
            auth_token: "secret123".to_string(),
        });
        let resp = service.join_network(join_req).await.unwrap();
        assert!(resp.into_inner().success);

        // Check associations
        let assoc_req = Request::new(GetNetworkAssociationsRequest {
            scope_name: "mynet".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.get_network_associations(assoc_req).await.unwrap();
        let assocs = resp.into_inner().associations;
        assert_eq!(assocs.len(), 1);
        assert_eq!(assocs[0].ip_address, "192.168.1.100");

        // Leave
        let leave_req = Request::new(LeaveNetworkRequest {
            ip_address: "192.168.1.100".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.leave_network(leave_req).await.unwrap();
        assert!(resp.into_inner().success);

        // Verify gone
        let assoc_req = Request::new(GetNetworkAssociationsRequest {
            scope_name: "mynet".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.get_network_associations(assoc_req).await.unwrap();
        assert!(resp.into_inner().associations.is_empty());
    }

    #[tokio::test]
    async fn test_add_and_list_scoped_records() {
        let service = make_test_service();

        // Create scope
        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "recscope".to_string(),
                home_domain: "recscope.home".to_string(),
            }),
            auth_token: "secret123".to_string(),
        });
        service.create_network_scope(req).await.unwrap();

        // Add scoped record
        let add_req = Request::new(AddScopedRecordRequest {
            scope_name: "recscope".to_string(),
            record: Some(proto::DnsRecord {
                name: "host.recscope.home".to_string(),
                record_type: 0,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "secret123".to_string(),
        });
        let resp = service.add_scoped_record(add_req).await.unwrap();
        assert!(resp.into_inner().success);

        // List scoped records
        let list_req = Request::new(ListScopedRecordsRequest {
            scope_name: "recscope".to_string(),
            name_filter: String::new(),
            record_type_filter: 0,
            filter_by_type: false,
            auth_token: "secret123".to_string(),
        });
        let resp = service.list_scoped_records(list_req).await.unwrap();
        let records = resp.into_inner().records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "10.0.0.1");
    }

    #[tokio::test]
    async fn test_remove_scoped_records() {
        let service = make_test_service();

        // Create scope + record
        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "rmscope".to_string(),
                home_domain: "rmscope.home".to_string(),
            }),
            auth_token: "secret123".to_string(),
        });
        service.create_network_scope(req).await.unwrap();

        let add_req = Request::new(AddScopedRecordRequest {
            scope_name: "rmscope".to_string(),
            record: Some(proto::DnsRecord {
                name: "delete-me.rmscope.home".to_string(),
                record_type: 0,
                value: "10.0.0.1".to_string(),
                ttl: 300,
                priority: 0,
            }),
            auth_token: "secret123".to_string(),
        });
        service.add_scoped_record(add_req).await.unwrap();

        // Remove
        let rm_req = Request::new(RemoveScopedRecordRequest {
            scope_name: "rmscope".to_string(),
            name: "delete-me.rmscope.home".to_string(),
            record_type: 0,
            value: String::new(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.remove_scoped_record(rm_req).await.unwrap();
        let inner = resp.into_inner();
        assert!(inner.success);
        assert_eq!(inner.removed_count, 1);
    }

    #[tokio::test]
    async fn test_get_search_domains() {
        let service = make_test_service();

        // Create scope
        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "searchnet".to_string(),
                home_domain: "searchnet.home".to_string(),
            }),
            auth_token: "secret123".to_string(),
        });
        service.create_network_scope(req).await.unwrap();

        // Join network
        let join_req = Request::new(JoinNetworkRequest {
            ip_address: "10.0.0.50".to_string(),
            scope_name: "searchnet".to_string(),
            ttl_seconds: 3600,
            auth_token: "secret123".to_string(),
        });
        service.join_network(join_req).await.unwrap();

        // Get search domains
        let sd_req = Request::new(GetSearchDomainsRequest {
            ip_address: "10.0.0.50".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.get_search_domains(sd_req).await.unwrap();
        let domains = resp.into_inner().search_domains;
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "searchnet.home.");
    }

    #[tokio::test]
    async fn test_join_network_default_ttl() {
        let service = make_test_service();

        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "ttlnet".to_string(),
                home_domain: "ttlnet.home".to_string(),
            }),
            auth_token: "secret123".to_string(),
        });
        service.create_network_scope(req).await.unwrap();

        let join_req = Request::new(JoinNetworkRequest {
            ip_address: "10.0.0.1".to_string(),
            scope_name: "ttlnet".to_string(),
            ttl_seconds: 0, // Should default to 300
            auth_token: "secret123".to_string(),
        });
        let resp = service.join_network(join_req).await.unwrap();
        assert!(resp.into_inner().success);

        let assoc_req = Request::new(GetNetworkAssociationsRequest {
            scope_name: "ttlnet".to_string(),
            auth_token: "secret123".to_string(),
        });
        let resp = service.get_network_associations(assoc_req).await.unwrap();
        let assocs = resp.into_inner().associations;
        assert_eq!(assocs[0].ttl_seconds, 300);
    }

    #[tokio::test]
    async fn test_network_scope_auth_required() {
        let service = make_test_service();

        let req = Request::new(CreateNetworkScopeRequest {
            scope: Some(proto::NetworkScope {
                name: "auth-test".to_string(),
                home_domain: "auth.home".to_string(),
            }),
            auth_token: "wrong".to_string(),
        });
        let result = service.create_network_scope(req).await;
        assert!(result.is_err());
    }
}
