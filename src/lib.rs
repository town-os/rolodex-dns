#![deny(dead_code)]
#![deny(unsafe_code)]

pub mod acme;
pub mod acme_jose;
pub mod acme_server;
pub mod ca;
pub mod cidr;
pub mod config;
pub mod dane;
pub mod db;
pub mod delegation_cache;
pub mod dhcp;
pub mod dns_cache;
pub mod dns_server;
pub mod dnsbl;
pub mod dnssec;
pub mod dnssec_validate;
pub mod doh_h3_server;
pub mod doh_proxy;
pub mod doh_server;
pub mod doq_server;
pub mod dot_server;
pub mod edns;
pub mod forwarder;
pub mod grpc_service;
pub mod key_cache;
pub mod metrics;
pub mod portal;
pub mod probe;
pub mod record_cache;
pub mod resolver;
pub mod secure_client;
pub mod svcb;
pub mod tls;
pub mod transports;
pub mod ttl_drift;
pub mod zone_signer;
