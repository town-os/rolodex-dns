//! Validated DNSSEC trust state, cached per zone.
//!
//! Validation is top-down: the root's DNSKEY set is anchored by the configured
//! trust anchors, each delegation's DS is signed by the parent, and the child's
//! DNSKEY set is anchored by that DS. A resolver that re-derived that chain for
//! every query would send three or four extra round trips per name and start
//! every one of them at a root server — which is exactly the cold-start problem
//! [`crate::delegation_cache`] exists to avoid, reintroduced one layer up.
//!
//! So the chain is cached. An entry says one of two things about a zone, and the
//! difference between them is the whole security property:
//!
//! - [`TrustState::Secure`] — these DNSKEYs are chained to the anchor, and
//!   anything in this zone must verify against one of them.
//! - [`TrustState::Insecure`] — the delegation to this zone provably carries no
//!   DS, so the zone is unsigned and its data is served without signatures.
//!
//! `Insecure` is cached deliberately, not as an optimisation but because the
//! alternative is worse: re-proving the missing DS on every query to every
//! unsigned zone would put an NSEC/NSEC3 round trip in front of most of the
//! internet. It is safe to cache because the proof it records was itself signed
//! by the parent — an attacker cannot manufacture an `Insecure` entry without
//! the parent's key, which is the same bar as manufacturing a `Secure` one.
//!
//! Entries live for the TTL of the records that produced them, so a zone that
//! signs itself tomorrow stops being cached as insecure when the parent's NSEC
//! expires, not later. This cache is flushed by `flush_upstream_state()` (an
//! `auto`-mode tier switch) and **not** by `flush_cache()`, for the same reason
//! the delegation cache is not: hanging it off record mutations would mean every
//! `AddRecord` re-walks the trust chain for every name.

use dashmap::DashMap;
use hickory_proto::dnssec::rdata::DNSKEY;
use hickory_proto::rr::Name;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// Absurdity cap on how long a trust decision is honoured, matching the
/// delegation and record caches. A DNSKEY RRset with a week-long TTL is honoured
/// for a week; nothing is honoured for longer.
pub const MAX_TRUST_TTL: u32 = 604_800;

/// Floor on how long a trust decision is honoured.
///
/// A zone is free to publish a 0-TTL DNSKEY RRset, and honouring that literally
/// would mean re-fetching and re-validating the key set for every single query
/// in the zone — an amplifier a hostile zone could point at us and at its own
/// parent. One minute is short enough that a real rollover is picked up promptly
/// and long enough that a query burst costs one validation.
pub const MIN_TRUST_TTL: u32 = 60;

/// Bound on the number of zones held. Well above the number of zones any real
/// query mix touches; it exists so a walk over a hostile namespace cannot grow
/// the map without limit.
pub const MAX_TRUST_ENTRIES: usize = 10_000;

/// What is known about a zone's position in the chain of trust.
#[derive(Debug, Clone)]
pub enum TrustState {
    /// The zone is signed and these keys are chained to the trust anchor.
    Secure(Arc<Vec<DNSKEY>>),
    /// The delegation to this zone provably has no DS: the zone is unsigned and
    /// legitimately so.
    Insecure,
}

impl TrustState {
    /// The keys, if this zone is secure.
    pub fn keys(&self) -> Option<&[DNSKEY]> {
        match self {
            Self::Secure(keys) => Some(keys),
            Self::Insecure => None,
        }
    }

    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Secure(_))
    }
}

#[derive(Debug, Clone)]
struct Entry {
    state: TrustState,
    expires_at: Instant,
}

/// Zone -> validated trust state.
#[derive(Debug, Default)]
pub struct KeyCache {
    entries: DashMap<String, Entry>,
}

impl KeyCache {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    fn key(zone: &Name) -> String {
        zone.to_ascii().to_lowercase()
    }

    /// Records a zone's trust state for `ttl` seconds.
    pub fn insert(&self, zone: &Name, state: TrustState, ttl: u32) {
        let ttl = ttl.clamp(MIN_TRUST_TTL, MAX_TRUST_TTL);
        self.reap_if_full();
        self.entries.insert(
            Self::key(zone),
            Entry {
                state,
                expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    /// The live trust state for `zone`, dropping the entry if it has expired.
    ///
    /// This is an exact-name lookup, never a suffix match. A parent's keys say
    /// nothing about a child's — that is what the DS record is for — so walking
    /// suffixes here would hand `example.com`'s key set to `evil.example.com`
    /// and let a delegated subzone be validated with its parent's key.
    pub fn get(&self, zone: &Name) -> Option<TrustState> {
        let key = Self::key(zone);
        let entry = self.entries.get(&key).map(|e| e.value().clone())?;
        if entry.expires_at <= Instant::now() {
            self.entries.remove(&key);
            return None;
        }
        Some(entry.state)
    }

    /// Drops a zone's entry, used when its keys turn out not to validate the data
    /// they were supposed to (a rollover we cached across, most likely).
    pub fn invalidate(&self, zone: &Name) {
        self.entries.remove(&Self::key(zone));
    }

    /// Clears everything. Called on an `auto` tier switch, where the answers a
    /// zone gives may come from a different upstream entirely.
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
        if self.entries.len() < MAX_TRUST_ENTRIES {
            return;
        }
        let now = Instant::now();
        self.entries.retain(|_, v| v.expires_at > now);
        while self.entries.len() >= MAX_TRUST_ENTRIES {
            let victim = self.entries.iter().next().map(|e| e.key().clone());
            match victim {
                Some(k) => {
                    self.entries.remove(&k);
                }
                None => break,
            }
        }
        debug!("key cache reaped to {} entries", self.entries.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::{Algorithm, PublicKeyBuf};
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    fn key() -> DNSKEY {
        DNSKEY::new(
            true,
            false,
            false,
            PublicKeyBuf::new(vec![0u8; 32], Algorithm::ED25519),
        )
    }

    #[test]
    fn secure_state_round_trips() {
        let cache = KeyCache::new();
        cache.insert(
            &name("example.com."),
            TrustState::Secure(Arc::new(vec![key()])),
            300,
        );
        let state = cache.get(&name("example.com.")).expect("cached");
        assert!(state.is_secure());
        assert_eq!(state.keys().map(<[DNSKEY]>::len), Some(1));
    }

    #[test]
    fn insecure_state_round_trips() {
        let cache = KeyCache::new();
        cache.insert(&name("unsigned.test."), TrustState::Insecure, 300);
        let state = cache.get(&name("unsigned.test.")).expect("cached");
        assert!(!state.is_secure());
        assert!(state.keys().is_none());
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let cache = KeyCache::new();
        cache.insert(&name("Example.COM."), TrustState::Insecure, 300);
        assert!(cache.get(&name("example.com.")).is_some());
    }

    /// A child's trust state must never be answered from its parent's entry. If
    /// this ever became a suffix match, a delegated subzone would validate
    /// against its parent's keys and a compromised parent key would silently
    /// cover every zone beneath it without a DS.
    #[test]
    fn lookup_does_not_match_suffixes() {
        let cache = KeyCache::new();
        cache.insert(
            &name("example.com."),
            TrustState::Secure(Arc::new(vec![key()])),
            300,
        );
        assert!(
            cache.get(&name("sub.example.com.")).is_none(),
            "a subzone must not inherit its parent's key set"
        );
        assert!(cache.get(&name("com.")).is_none());
    }

    /// A zone publishing a 0-TTL DNSKEY set must not turn every query into a
    /// fresh key fetch and re-validation.
    #[test]
    fn zero_ttl_is_floored_not_honoured() {
        let cache = KeyCache::new();
        cache.insert(&name("flappy.test."), TrustState::Insecure, 0);
        assert!(
            cache.get(&name("flappy.test.")).is_some(),
            "a 0-TTL entry must still be cached for the floor"
        );
    }

    #[test]
    fn invalidate_and_flush_remove_entries() {
        let cache = KeyCache::new();
        cache.insert(&name("a.test."), TrustState::Insecure, 300);
        cache.insert(&name("b.test."), TrustState::Insecure, 300);
        cache.invalidate(&name("a.test."));
        assert!(cache.get(&name("a.test.")).is_none());
        assert!(cache.get(&name("b.test.")).is_some());
        cache.flush();
        assert!(cache.is_empty());
    }
}
