/// TTL drift adjustment for cached DNS records.
///
/// Two modes:
/// - **Fixed**: Add/subtract a fixed duration from TTLs (stable)
/// - **Logarithmic**: Adjust TTLs based on upstream server latency (experimental)
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// TTL drift mode.
#[derive(Debug, Clone)]
pub enum TtlDriftMode {
    /// No drift adjustment.
    Disabled,
    /// Fixed adjustment: add/subtract seconds from TTL.
    Fixed {
        /// Adjustment in seconds (positive = longer TTL, negative = shorter).
        adjustment_secs: i64,
    },
    /// Logarithmic adjustment based on upstream latency.
    Logarithmic {
        /// Sensitivity multiplier. Higher = more aggressive adjustment.
        multiplier: f64,
    },
}

/// Configuration for TTL drift.
#[derive(Debug, Clone)]
pub struct TtlDriftConfig {
    pub mode: TtlDriftMode,
}

impl Default for TtlDriftConfig {
    fn default() -> Self {
        Self {
            mode: TtlDriftMode::Disabled,
        }
    }
}

/// Applies fixed drift to a TTL value.
/// Clamps result to minimum of 1 second.
pub fn apply_fixed_drift(original_ttl: u32, adjustment_secs: i64) -> u32 {
    let adjusted = original_ttl as i64 + adjustment_secs;
    adjusted.max(1) as u32
}

/// Applies logarithmic drift based on upstream server latency.
///
/// Formula: adjusted_ttl = original_ttl * (1 + multiplier * ln(avg_latency_ms / 50.0))
///
/// - Baseline: 50ms. When latency=50ms, no change.
/// - Higher latency → longer TTLs (fewer upstream queries).
/// - Lower latency → shorter TTLs (fresher data).
pub fn apply_logarithmic_drift(original_ttl: u32, avg_latency_ms: f64, multiplier: f64) -> u32 {
    if avg_latency_ms <= 0.0 || multiplier == 0.0 {
        return original_ttl;
    }

    let baseline = 50.0_f64;
    let ratio = avg_latency_ms / baseline;
    let factor = 1.0 + multiplier * ratio.ln();
    let adjusted = (original_ttl as f64 * factor).round();
    adjusted.max(1.0) as u32
}

/// Parses a duration string into seconds.
///
/// Supports compound durations via `fancy_duration` (e.g. "1h30m", "2d12h"),
/// and falls back to simple format ("5m", "30s", "-2m", "+1h") for backward
/// compatibility.
pub fn parse_duration_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (sign, rest) = if s.starts_with('-') {
        (-1i64, &s[1..])
    } else if s.starts_with('+') {
        (1i64, &s[1..])
    } else {
        (1i64, s)
    };

    // Try fancy_duration first for compound durations like "1h30m".
    // Only use it when the string contains at least one letter (to avoid
    // fancy_duration misinterpreting bare numbers or garbage strings).
    if rest.chars().any(|c| c.is_alphabetic()) && rest.contains(|c: char| c.is_alphabetic()) {
        // Only use fancy_duration when there are multiple duration components
        // (e.g. "1h30m") to avoid interfering with simple "5m" / "30s" parsing.
        let alpha_count = rest.chars().filter(|c| c.is_alphabetic()).count();
        if alpha_count >= 2 {
            if let Ok(fd) = rest.parse::<fancy_duration::FancyDuration<std::time::Duration>>() {
                let secs = fd.duration().as_secs() as i64;
                if secs > 0 {
                    return Some(sign * secs);
                }
            }
        }
    }

    // Fallback to simple parser
    let (num_str, unit) = if rest.ends_with('s') {
        (&rest[..rest.len() - 1], 1i64)
    } else if rest.ends_with('m') {
        (&rest[..rest.len() - 1], 60i64)
    } else if rest.ends_with('h') {
        (&rest[..rest.len() - 1], 3600i64)
    } else if rest.ends_with('d') {
        (&rest[..rest.len() - 1], 86400i64)
    } else {
        // Assume seconds if no unit
        (rest, 1i64)
    };

    let num: i64 = num_str.parse().ok()?;
    Some(sign * num * unit)
}

/// Tracks per-server latency using exponential moving average (EMA).
pub struct LatencyTracker {
    /// Per-server EMA latency in milliseconds.
    latencies: Arc<DashMap<SocketAddr, f64>>,
    /// Per-server query counts.
    counts: Arc<DashMap<SocketAddr, u64>>,
    /// EMA smoothing factor (0 < alpha <= 1). Higher = more weight to recent.
    alpha: f64,
}

impl LatencyTracker {
    pub fn new(alpha: f64) -> Self {
        Self {
            latencies: Arc::new(DashMap::new()),
            counts: Arc::new(DashMap::new()),
            alpha: alpha.clamp(0.01, 1.0),
        }
    }

    /// Records a latency measurement for a server.
    pub fn record(&self, server: SocketAddr, latency_ms: f64) {
        self.latencies
            .entry(server)
            .and_modify(|ema| {
                *ema = self.alpha * latency_ms + (1.0 - self.alpha) * *ema;
            })
            .or_insert(latency_ms);

        self.counts
            .entry(server)
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    /// Gets the average latency for a server.
    pub fn get_latency(&self, server: &SocketAddr) -> Option<f64> {
        self.latencies.get(server).map(|v| *v)
    }

    /// Gets all latency stats.
    pub fn all_stats(&self) -> Vec<(SocketAddr, f64, u64)> {
        self.latencies
            .iter()
            .map(|entry| {
                let count = self.counts.get(entry.key()).map(|c| *c).unwrap_or(0);
                (*entry.key(), *entry.value(), count)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_drift_positive() {
        assert_eq!(apply_fixed_drift(300, 60), 360);
    }

    #[test]
    fn test_fixed_drift_negative() {
        assert_eq!(apply_fixed_drift(300, -60), 240);
    }

    #[test]
    fn test_fixed_drift_clamp_to_min() {
        assert_eq!(apply_fixed_drift(10, -100), 1);
    }

    #[test]
    fn test_logarithmic_baseline_no_change() {
        // At baseline (50ms), ln(1) = 0, so no change
        let result = apply_logarithmic_drift(300, 50.0, 0.5);
        assert_eq!(result, 300);
    }

    #[test]
    fn test_logarithmic_high_latency_increases_ttl() {
        // Higher latency should increase TTL
        let result = apply_logarithmic_drift(300, 200.0, 0.5);
        assert!(result > 300, "Expected TTL > 300, got {}", result);
    }

    #[test]
    fn test_logarithmic_low_latency_decreases_ttl() {
        // Lower latency should decrease TTL
        let result = apply_logarithmic_drift(300, 10.0, 0.5);
        assert!(result < 300, "Expected TTL < 300, got {}", result);
    }

    #[test]
    fn test_logarithmic_clamp_to_min() {
        let result = apply_logarithmic_drift(1, 0.1, 10.0);
        assert!(result >= 1);
    }

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("30"), Some(30));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration_secs("5m"), Some(300));
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration_secs("1h"), Some(3600));
    }

    #[test]
    fn test_parse_duration_negative() {
        assert_eq!(parse_duration_secs("-30s"), Some(-30));
        assert_eq!(parse_duration_secs("-5m"), Some(-300));
    }

    #[test]
    fn test_parse_duration_positive_prefix() {
        assert_eq!(parse_duration_secs("+2m"), Some(120));
    }

    #[test]
    fn test_parse_duration_days() {
        assert_eq!(parse_duration_secs("1d"), Some(86400));
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration_secs("").is_none());
        assert!(parse_duration_secs("abc").is_none());
    }

    #[test]
    fn test_latency_tracker() {
        let tracker = LatencyTracker::new(0.5);
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

        tracker.record(addr, 100.0);
        assert_eq!(tracker.get_latency(&addr), Some(100.0));

        tracker.record(addr, 50.0);
        // EMA: 0.5 * 50 + 0.5 * 100 = 75
        let latency = tracker.get_latency(&addr).unwrap();
        assert!((latency - 75.0).abs() < 0.01);
    }

    #[test]
    fn test_latency_tracker_convergence() {
        let tracker = LatencyTracker::new(0.3);
        let addr: SocketAddr = "1.1.1.1:53".parse().unwrap();

        // Record 10 measurements of 50ms - should converge toward 50
        for _ in 0..10 {
            tracker.record(addr, 50.0);
        }
        let latency = tracker.get_latency(&addr).unwrap();
        assert!((latency - 50.0).abs() < 1.0);
    }

    #[test]
    fn test_latency_tracker_multiple_servers() {
        let tracker = LatencyTracker::new(1.0); // alpha=1 means latest value only
        let addr1: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let addr2: SocketAddr = "1.1.1.1:53".parse().unwrap();

        tracker.record(addr1, 100.0);
        tracker.record(addr2, 200.0);

        assert_eq!(tracker.get_latency(&addr1), Some(100.0));
        assert_eq!(tracker.get_latency(&addr2), Some(200.0));

        let stats = tracker.all_stats();
        assert_eq!(stats.len(), 2);
    }
}
