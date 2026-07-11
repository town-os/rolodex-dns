//! Resolver-side record cache: the parts of a recursion that were being thrown away.
//!
//! [`crate::dns_cache::DnsCache`] sits *above* the resolver and only ever sees the
//! final answer, so it structurally cannot hold anything learned mid-walk. And the
//! resolver was written as a stateless walker whose only output is a
//! [`crate::resolver::Resolution`] — so everything it saw on the way down was used
//! once and dropped, despite arriving with a TTL that says exactly how long it is
//! good for:
//!
//! - **Glue.** `collect_glue` reduces the additional-section records to bare
//!   `Vec<IpAddr>`; the TTLs never leave that function.
//! - **Glueless NS lookups.** `resolve_ns_addresses` runs an entire sub-recursion
//!   to resolve an NS hostname, returns the addresses, and discards them.
//! - **CNAME hops.** Chased targets are accumulated into the answer and forgotten.
//!
//! This cache gives the resolver somewhere to put them. TTLs are honoured exactly
//! as sent; `default_ttl` applies only where a record carries no usable TTL of its
//! own (a zero TTL).

use dashmap::DashMap;
use hickory_proto::rr::{Name, Record, RecordType};
use std::time::{Duration, Instant};
use tracing::debug;

/// Absurdity cap. A record is honoured for as long as it asks, up to a week.
pub const MAX_RECORD_TTL: u32 = 604_800;
/// Bound on the number of distinct (name, type) keys held.
pub const MAX_RECORD_ENTRIES: usize = 50_000;

#[derive(Debug, Clone)]
struct CachedRecords {
    records: Vec<Record>,
    expires_at: Instant,
}

/// `(name, type)` -> records, TTL-respecting, in memory.
#[derive(Debug, Default)]
pub struct RecordCache {
    entries: DashMap<String, CachedRecords>,
    default_ttl: u32,
}

impl RecordCache {
    pub fn new(default_ttl: u32) -> Self {
        Self {
            entries: DashMap::new(),
            default_ttl,
        }
    }

    fn key(name: &Name, rtype: RecordType) -> String {
        format!("{}:{}", name.to_ascii().to_lowercase(), rtype)
    }

    /// The lifetime to honour for a record set: the shortest TTL present, or
    /// [`Self::default_ttl`] when none of them carry one.
    fn lifetime(&self, records: &[Record]) -> u32 {
        let ttl = records.iter().map(|r| r.ttl()).filter(|t| *t > 0).min();
        match ttl {
            Some(t) => t.min(MAX_RECORD_TTL),
            // No usable TTL anywhere in the set — fall back rather than either
            // caching forever or refusing to cache at all.
            None => self.default_ttl,
        }
    }

    /// Caches `records` under `(name, rtype)`, honouring their TTL.
    pub fn insert(&self, name: &Name, rtype: RecordType, records: Vec<Record>) {
        if records.is_empty() {
            return;
        }
        let ttl = self.lifetime(&records);
        if ttl == 0 {
            return;
        }
        self.reap_if_full();
        self.entries.insert(
            Self::key(name, rtype),
            CachedRecords {
                records,
                expires_at: Instant::now() + Duration::from_secs(ttl as u64),
            },
        );
    }

    /// Returns the live records for `(name, rtype)`, dropping the entry if it has
    /// expired.
    ///
    /// TTLs are rewritten to the entry's *remaining* lifetime. Without that decay a
    /// cached record would be handed back with its original TTL, re-cached upstream
    /// for the full duration again, and so on — a record with a 1h TTL would never
    /// actually expire.
    pub fn get(&self, name: &Name, rtype: RecordType) -> Option<Vec<Record>> {
        let key = Self::key(name, rtype);
        let entry = self.entries.get(&key).map(|e| e.value().clone())?;

        let now = Instant::now();
        if entry.expires_at <= now {
            self.entries.remove(&key);
            return None;
        }

        let remaining = entry.expires_at.duration_since(now).as_secs() as u32;
        Some(
            entry
                .records
                .into_iter()
                .map(|mut r| {
                    r.set_ttl(remaining.max(1));
                    r
                })
                .collect(),
        )
    }

    /// Clears everything.
    ///
    /// Called on an `auto` tier switch (via `DnsServer::flush_upstream_state`), and
    /// deliberately **not** from `DnsServer::flush_cache`, which every local
    /// zone/record mutation calls — wiring upstream state into that would mean
    /// adding one package discards the whole recursion cache.
    pub fn flush(&self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn reap_if_full(&self) {
        if self.entries.len() < MAX_RECORD_ENTRIES {
            return;
        }
        let now = Instant::now();
        self.entries.retain(|_, v| v.expires_at > now);
        while self.entries.len() >= MAX_RECORD_ENTRIES {
            let victim = self.entries.iter().next().map(|e| e.key().clone());
            match victim {
                Some(k) => {
                    self.entries.remove(&k);
                }
                None => break,
            }
        }
        debug!("record cache reaped to {} entries", self.entries.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::DEFAULT_TTL;
    use hickory_proto::rr::RData;
    use hickory_proto::rr::rdata::A;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    fn a_rec(owner: &str, ttl: u32, last: u8) -> Record {
        Record::from_rdata(
            name(owner),
            ttl,
            RData::A(A(Ipv4Addr::new(192, 0, 2, last))),
        )
    }

    #[test]
    fn records_round_trip() {
        let cache = RecordCache::new(DEFAULT_TTL);
        cache.insert(
            &name("ns1.example.net."),
            RecordType::A,
            vec![a_rec("ns1.example.net.", 3600, 1)],
        );
        let got = cache
            .get(&name("ns1.example.net."), RecordType::A)
            .expect("hit");
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let cache = RecordCache::new(DEFAULT_TTL);
        cache.insert(
            &name("NS1.Example.NET."),
            RecordType::A,
            vec![a_rec("ns1.example.net.", 3600, 1)],
        );
        assert!(
            cache
                .get(&name("ns1.example.net."), RecordType::A)
                .is_some()
        );
    }

    #[test]
    fn record_type_is_part_of_the_key() {
        let cache = RecordCache::new(DEFAULT_TTL);
        cache.insert(
            &name("ns1.example.net."),
            RecordType::A,
            vec![a_rec("ns1.example.net.", 3600, 1)],
        );
        assert!(
            cache
                .get(&name("ns1.example.net."), RecordType::AAAA)
                .is_none()
        );
    }

    #[test]
    fn a_zero_ttl_record_falls_back_to_the_default() {
        let cache = RecordCache::new(DEFAULT_TTL);
        // TTL 0 carries no usable lifetime — the default applies rather than the
        // record being dropped or cached forever.
        let records = vec![a_rec("ns1.example.net.", 0, 1)];
        assert_eq!(cache.lifetime(&records), DEFAULT_TTL);

        cache.insert(&name("ns1.example.net."), RecordType::A, records);
        assert!(
            cache
                .get(&name("ns1.example.net."), RecordType::A)
                .is_some()
        );
    }

    #[test]
    fn present_ttl_is_honoured_as_sent() {
        let cache = RecordCache::new(DEFAULT_TTL);
        // Well below the default: honoured, not raised.
        assert_eq!(cache.lifetime(&[a_rec("x.", 30, 1)]), 30);
        // Well above: honoured, not lowered.
        assert_eq!(cache.lifetime(&[a_rec("x.", 86_400, 1)]), 86_400);
    }

    #[test]
    fn the_shortest_ttl_in_the_set_wins() {
        let cache = RecordCache::new(DEFAULT_TTL);
        let records = vec![a_rec("x.", 3600, 1), a_rec("x.", 60, 2)];
        assert_eq!(cache.lifetime(&records), 60);
    }

    #[test]
    fn absurd_ttls_are_capped() {
        let cache = RecordCache::new(DEFAULT_TTL);
        assert_eq!(cache.lifetime(&[a_rec("x.", u32::MAX, 1)]), MAX_RECORD_TTL);
    }

    #[test]
    fn expired_records_are_not_served() {
        let cache = RecordCache::new(DEFAULT_TTL);
        cache.entries.insert(
            RecordCache::key(&name("gone.example.net."), RecordType::A),
            CachedRecords {
                records: vec![a_rec("gone.example.net.", 30, 1)],
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
        assert!(
            cache
                .get(&name("gone.example.net."), RecordType::A)
                .is_none()
        );
        assert_eq!(cache.len(), 0, "expired entry is evicted on lookup");
    }

    #[test]
    fn flush_clears_everything() {
        let cache = RecordCache::new(DEFAULT_TTL);
        cache.insert(
            &name("a.net."),
            RecordType::A,
            vec![a_rec("a.net.", 300, 1)],
        );
        cache.insert(
            &name("b.net."),
            RecordType::A,
            vec![a_rec("b.net.", 300, 2)],
        );
        cache.flush();
        assert!(cache.is_empty());
    }

    #[test]
    fn empty_record_sets_are_not_cached() {
        let cache = RecordCache::new(DEFAULT_TTL);
        cache.insert(&name("a.net."), RecordType::A, vec![]);
        assert!(cache.is_empty());
    }
}
