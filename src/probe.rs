//! Address-family routability probe.
//!
//! Networks routinely advertise an IPv6 default route (via RA) yet silently drop
//! all v6 traffic; the mirror case happens on v4-only NAT. When rolodex hands a
//! client an address in a family the host cannot route, the client
//! (podman/getaddrinfo, curl, …) stalls on the dead family instead of falling
//! back to the one that works — the exact failure that wedges `docker.io` pulls
//! on a broken-v6 link.
//!
//! This probe periodically tests *actual* internet reachability per family with a
//! plain TCP connect to public anycast resolvers on **:443** — :443 because it is
//! the port real traffic uses and it survives the :53/:853 filtering some
//! networks impose, and TCP-connect because it needs no raw-socket privilege
//! (unlike ICMP). It then tells the [`DnsServer`] which families to answer via
//! [`DnsServer::set_answer_families`]; the answer filter in `dns_server` drops
//! A/AAAA records of a suppressed family, turning them into NODATA so clients
//! fall back.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::config::AddressFamilyConfig;
use crate::dns_server::DnsServer;

/// Probe parameters, parsed from config once.
struct ProbeParams {
    interval: Duration,
    timeout: Duration,
    fail_threshold: u32,
    targets_v4: Vec<String>,
    targets_v6: Vec<String>,
}

/// Applies the address-family mode to `server` and, in `auto` mode, spawns the
/// background routability probe.
///
/// `auto` runs one probe **synchronously** before returning, so the very first
/// query already reflects reachability (a boot onto a dead-v6 link suppresses
/// AAAA immediately, not one interval later); the recurring probe then runs
/// detached. `off`/`force4`/`force6` set a fixed state and spawn nothing.
pub async fn start(server: Arc<DnsServer>, cfg: &AddressFamilyConfig) {
    match cfg.mode.to_ascii_lowercase().as_str() {
        "off" | "" => {
            server.set_answer_families(true, true);
            info!("address_family=off: answering both A and AAAA");
            return;
        }
        "force4" => {
            server.set_answer_families(true, false);
            info!("address_family=force4: suppressing AAAA answers");
            return;
        }
        "force6" => {
            server.set_answer_families(false, true);
            info!("address_family=force6: suppressing A answers");
            return;
        }
        "auto" => {}
        other => warn!("unknown address_family mode '{}', using auto", other),
    }

    let params = ProbeParams {
        interval: Duration::from_secs(cfg.probe_interval_secs.max(1)),
        timeout: Duration::from_secs(cfg.probe_timeout_secs.max(1)),
        fail_threshold: cfg.fail_threshold.max(1),
        targets_v4: cfg.targets_v4.clone(),
        targets_v6: cfg.targets_v6.clone(),
    };
    info!(
        "address_family=auto: probing v4 {:?} / v6 {:?} every {}s (fail_threshold={})",
        params.targets_v4, params.targets_v6, cfg.probe_interval_secs, params.fail_threshold
    );

    let mut state = ProbeState::new();
    // Decisive first probe, then hand off to the recurring loop.
    state.tick(&server, &params).await;

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(params.interval).await;
            state.tick(&server, &params).await;
        }
    });
}

/// Debounced per-family reachability state.
struct ProbeState {
    v4_ok: bool,
    v6_ok: bool,
    v4_fails: u32,
    v6_fails: u32,
    /// Whether the first (decisive) probe has run.
    seeded: bool,
    /// Last `(v4, v6)` state pushed to the server — avoids redundant stores/logs.
    applied: (bool, bool),
}

impl ProbeState {
    fn new() -> Self {
        Self {
            v4_ok: true,
            v6_ok: true,
            v4_fails: 0,
            v6_fails: 0,
            seeded: false,
            // Mirrors the DnsServer default (both families answered), so an
            // all-reachable first probe applies nothing.
            applied: (true, true),
        }
    }

    /// Runs one probe cycle and pushes any change to `server`.
    async fn tick(&mut self, server: &DnsServer, p: &ProbeParams) {
        let v4_reachable = probe_family(&p.targets_v4, p.timeout).await;
        let v6_reachable = probe_family(&p.targets_v6, p.timeout).await;

        let (mut v4, mut v6) = if !self.seeded {
            // First probe is authoritative (no grace) so a boot onto a dead
            // family suppresses it from the first query rather than after
            // `fail_threshold` cycles.
            self.v4_ok = v4_reachable;
            self.v6_ok = v6_reachable;
            self.v4_fails = if v4_reachable { 0 } else { p.fail_threshold };
            self.v6_fails = if v6_reachable { 0 } else { p.fail_threshold };
            self.seeded = true;
            (self.v4_ok, self.v6_ok)
        } else {
            let v4 = debounce(
                &mut self.v4_ok,
                &mut self.v4_fails,
                v4_reachable,
                p.fail_threshold,
            );
            let v6 = debounce(
                &mut self.v6_ok,
                &mut self.v6_fails,
                v6_reachable,
                p.fail_threshold,
            );
            (v4, v6)
        };

        // Never suppress BOTH families: if neither target set answered, the box
        // is likely fully offline or the probe egress itself is blocked — not a
        // genuine dual-stack outage. Answering both is the safe status quo and
        // lets clients fail on their own terms instead of getting empty answers.
        if !v4 && !v6 {
            debug!(
                "routability probe: neither family reachable — answering both (assuming probe failure, not a real outage)"
            );
            v4 = true;
            v6 = true;
        }

        if (v4, v6) != self.applied {
            server.set_answer_families(v4, v6);
            info!("routability probe: answering A={} AAAA={}", v4, v6);
            self.applied = (v4, v6);
        }
    }
}

/// Advances a single family's debounced state and returns the committed value.
/// Up on the first success (reset the failure streak); down only after
/// `fail_threshold` consecutive failures.
fn debounce(ok: &mut bool, fails: &mut u32, reachable: bool, fail_threshold: u32) -> bool {
    if reachable {
        *fails = 0;
        *ok = true;
    } else {
        *fails = fails.saturating_add(1);
        if *fails >= fail_threshold {
            *ok = false;
        }
    }
    *ok
}

/// Returns true if any target accepts a TCP connection within `timeout`
/// (i.e. that address family can reach the internet). Targets should be literal
/// `ip:port` / `[ip]:port` so the connect uses the intended family.
async fn probe_family(targets: &[String], timeout: Duration) -> bool {
    for t in targets {
        match tokio::time::timeout(timeout, TcpStream::connect(t.as_str())).await {
            Ok(Ok(_stream)) => return true,
            Ok(Err(e)) => debug!("routability probe: connect {} failed: {}", t, e),
            Err(_) => debug!("routability probe: connect {} timed out", t),
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debounce_marks_down_only_after_threshold() {
        let mut ok = true;
        let mut fails = 0;
        // One failure with threshold 2 keeps it up.
        assert!(debounce(&mut ok, &mut fails, false, 2));
        // Second consecutive failure trips it down.
        assert!(!debounce(&mut ok, &mut fails, false, 2));
    }

    #[test]
    fn debounce_recovers_on_first_success() {
        let mut ok = false;
        let mut fails = 5;
        assert!(debounce(&mut ok, &mut fails, true, 2));
        assert_eq!(fails, 0);
    }

    #[tokio::test]
    async fn probe_family_false_when_unreachable() {
        // 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — guaranteed unroutable.
        let targets = vec!["203.0.113.1:443".to_string()];
        assert!(!probe_family(&targets, Duration::from_millis(300)).await);
    }
}
