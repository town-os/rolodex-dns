use crate::db::{Database, DnsRecord, RecordKind};
use crate::dns_server::DnsServer;
use crate::rbl::{RblChecker, RblProvider};
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;

pub mod proto {
    tonic::include_proto!("rolodex");
}

use proto::rolodex_service_server::RolodexService;
use proto::{
    AddRecordRequest, AddRecordResponse, FlushCacheRequest, FlushCacheResponse,
    GetRblConfigRequest, GetRblConfigResponse, ListRecordsRequest, ListRecordsResponse,
    RemoveRecordRequest, RemoveRecordResponse, SetForwarderRequest, SetForwarderResponse,
    SetRblConfigRequest, SetRblConfigResponse,
};

/// The gRPC service implementation for managing rolodex.
pub struct RolodexGrpcService {
    db: Database,
    dns_server: Arc<DnsServer>,
    rbl: Arc<RblChecker>,
    /// The shared secret for TCP authentication. Empty means no auth required.
    shared_secret: String,
    /// Whether this connection is over a Unix socket (bypasses auth).
    is_unix: bool,
}

impl RolodexGrpcService {
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
impl RolodexService for RolodexGrpcService {
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

    fn make_test_service() -> RolodexGrpcService {
        let db = Database::open_memory().unwrap();
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
        RolodexGrpcService::new(db, dns_server, rbl, "secret123".to_string(), false)
    }

    fn make_unix_service() -> RolodexGrpcService {
        let db = Database::open_memory().unwrap();
        let rbl = Arc::new(RblChecker::with_resolver(
            false,
            vec![],
            Arc::new(NeverListedResolver),
        ));
        let dns_server = Arc::new(DnsServer::new(db.clone(), rbl.clone(), vec![]));
        RolodexGrpcService::new(db, dns_server, rbl, "secret123".to_string(), true)
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
        let service = RolodexGrpcService::new(db, dns_server, rbl, String::new(), false);
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
}
