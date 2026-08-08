//! Prometheus metrics: a hand-rolled registry plus a text-exposition renderer.
//!
//! There is no metrics crate dependency. Everything here is built from the same
//! lock-free primitives the rest of the server already uses — `AtomicU64` for
//! counters and gauges, `DashMap` for the label dimensions whose values are only
//! known at runtime — and rendered to the Prometheus text format by hand. That
//! keeps the hot path allocation-free (a counter bump is one relaxed
//! `fetch_add`) and keeps the dependency tree unchanged.
//!
//! # The global registry
//!
//! Instrumentation points are spread across nearly every module (the query
//! path, both caches, the resolver, the blocklists, DHCP, the ACME issuer, the
//! gRPC service). Threading an `Arc<Metrics>` into all of them would mean
//! changing every constructor and every test call site, so the registry is a
//! process-global instead: [`metrics()`]. This is the same shape the `prometheus`
//! crate arrives at with its `lazy_static!` registry.
//!
//! Because it is global, counters accumulate across a test binary's whole run.
//! Unit tests that assert on counter values therefore construct a private
//! [`Metrics`] with [`Metrics::new`], or assert on *deltas* around the code under
//! test rather than absolute values.
//!
//! # Cardinality
//!
//! Every label dimension is either a fixed enum ([`Proto`], [`RCODES`],
//! [`AnswerSource`], …) or bounded by configuration (upstream server addresses).
//! The one dimension a client could otherwise blow up — the query type — is
//! folded through [`qtype_index`] into a known set with an `OTHER` catch-all, so
//! a flood of queries for random `TYPE1234` values cannot mint unbounded series.
//! Query *names* are never used as labels.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

/// The process-global metrics registry.
///
/// Instrumentation calls this rather than holding a handle; see the module docs
/// for why the registry is global.
pub fn metrics() -> &'static Metrics {
    static METRICS: LazyLock<Metrics> = LazyLock::new(Metrics::new);
    &METRICS
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// A monotonically increasing counter.
#[derive(Debug)]
pub struct Counter {
    name: &'static str,
    help: &'static str,
    value: AtomicU64,
}

impl Counter {
    fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            value: AtomicU64::new(0),
        }
    }

    /// Increments by one.
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments by `n`.
    pub fn add(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    fn encode(&self, out: &mut String) {
        write_meta(out, self.name, self.help, "counter");
        write_sample(out, self.name, &[], self.get());
    }
}

/// A gauge: a value that goes up and down. Written either by the code that owns
/// the underlying state or by the scrape-time collector in [`collect`].
#[derive(Debug)]
pub struct Gauge {
    name: &'static str,
    help: &'static str,
    value: AtomicU64,
}

impl Gauge {
    fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            value: AtomicU64::new(0),
        }
    }

    /// Replaces the value.
    pub fn set(&self, v: u64) {
        self.value.store(v, Ordering::Relaxed);
    }

    /// Current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    fn encode(&self, out: &mut String) {
        write_meta(out, self.name, self.help, "gauge");
        write_sample(out, self.name, &[], self.get());
    }
}

/// A counter family over a single fixed-cardinality label dimension.
///
/// Series are pre-allocated at construction, so an increment is an array index
/// plus one relaxed `fetch_add` — no hashing and no allocation.
#[derive(Debug)]
pub struct CounterVec {
    name: &'static str,
    help: &'static str,
    label: &'static str,
    values: &'static [&'static str],
    counters: Box<[AtomicU64]>,
}

impl CounterVec {
    fn new(
        name: &'static str,
        help: &'static str,
        label: &'static str,
        values: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            help,
            label,
            values,
            counters: (0..values.len()).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// Increments the series for label index `idx`. An out-of-range index is
    /// ignored rather than panicking: a metric is never worth killing a query
    /// over.
    pub fn inc(&self, idx: usize) {
        if let Some(c) = self.counters.get(idx) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Adds `n` to the series for label index `idx`. Out-of-range is ignored.
    pub fn add(&self, idx: usize, n: u64) {
        if let Some(c) = self.counters.get(idx) {
            c.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Value of the series at label index `idx`.
    pub fn get(&self, idx: usize) -> u64 {
        self.counters
            .get(idx)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn encode(&self, out: &mut String) {
        write_meta(out, self.name, self.help, "counter");
        for (i, value) in self.values.iter().enumerate() {
            write_sample(out, self.name, &[(self.label, value)], self.get(i));
        }
    }
}

/// A gauge family over a single fixed-cardinality label dimension.
#[derive(Debug)]
pub struct GaugeVec {
    name: &'static str,
    help: &'static str,
    label: &'static str,
    values: &'static [&'static str],
    gauges: Box<[AtomicU64]>,
}

impl GaugeVec {
    fn new(
        name: &'static str,
        help: &'static str,
        label: &'static str,
        values: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            help,
            label,
            values,
            gauges: (0..values.len()).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    /// Sets the series for label index `idx`. An out-of-range index is ignored.
    pub fn set(&self, idx: usize, v: u64) {
        if let Some(g) = self.gauges.get(idx) {
            g.store(v, Ordering::Relaxed);
        }
    }

    /// Value of the series at label index `idx`.
    pub fn get(&self, idx: usize) -> u64 {
        self.gauges
            .get(idx)
            .map(|g| g.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn encode(&self, out: &mut String) {
        write_meta(out, self.name, self.help, "gauge");
        for (i, value) in self.values.iter().enumerate() {
            write_sample(out, self.name, &[(self.label, value)], self.get(i));
        }
    }
}

/// A counter family over two fixed-cardinality label dimensions, stored as a
/// pre-allocated row-major matrix.
#[derive(Debug)]
pub struct CounterVec2 {
    name: &'static str,
    help: &'static str,
    labels: [&'static str; 2],
    rows: &'static [&'static str],
    cols: &'static [&'static str],
    counters: Box<[AtomicU64]>,
}

impl CounterVec2 {
    fn new(
        name: &'static str,
        help: &'static str,
        labels: [&'static str; 2],
        rows: &'static [&'static str],
        cols: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            help,
            labels,
            rows,
            cols,
            counters: (0..rows.len() * cols.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
        }
    }

    /// Increments the series at (`row`, `col`). Out-of-range indices are ignored.
    pub fn inc(&self, row: usize, col: usize) {
        if row < self.rows.len()
            && col < self.cols.len()
            && let Some(c) = self.counters.get(row * self.cols.len() + col)
        {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Value of the series at (`row`, `col`).
    pub fn get(&self, row: usize, col: usize) -> u64 {
        self.counters
            .get(row * self.cols.len() + col)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn encode(&self, out: &mut String) {
        write_meta(out, self.name, self.help, "counter");
        for (r, row) in self.rows.iter().enumerate() {
            for (c, col) in self.cols.iter().enumerate() {
                write_sample(
                    out,
                    self.name,
                    &[(self.labels[0], row), (self.labels[1], col)],
                    self.get(r, c),
                );
            }
        }
    }
}

/// A counter family whose single label's values are discovered at runtime —
/// upstream server addresses, for instance. Bounded by configuration rather than
/// by client input; nothing derived from a query name may be used as a key.
#[derive(Debug)]
pub struct DynCounterVec {
    name: &'static str,
    help: &'static str,
    label: &'static str,
    series: DashMap<String, AtomicU64>,
}

impl DynCounterVec {
    fn new(name: &'static str, help: &'static str, label: &'static str) -> Self {
        Self {
            name,
            help,
            label,
            series: DashMap::new(),
        }
    }

    /// Increments the series for `value`, creating it on first use. The lookup
    /// borrows `value`, so only the very first increment for a given label
    /// allocates.
    pub fn inc(&self, value: &str) {
        if let Some(c) = self.series.get(value) {
            c.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.series
            .entry(value.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    fn encode(&self, out: &mut String) {
        write_meta(out, self.name, self.help, "counter");
        for entry in self.series.iter() {
            write_sample(
                out,
                self.name,
                &[(self.label, entry.key())],
                entry.value().load(Ordering::Relaxed),
            );
        }
    }
}

/// A gauge family whose label values are discovered at runtime, holding a
/// fixed-point value (see [`DynGaugeVec::set_scaled`]). Used for per-server
/// state sampled at scrape time, such as the resolver's EMA latencies.
#[derive(Debug)]
pub struct DynGaugeVec {
    name: &'static str,
    help: &'static str,
    label: &'static str,
    /// Divisor applied when rendering, so a fractional gauge can be stored in an
    /// integer atomic (1000 => the stored value is thousandths).
    scale: f64,
    series: DashMap<String, AtomicU64>,
}

impl DynGaugeVec {
    fn new(name: &'static str, help: &'static str, label: &'static str, scale: f64) -> Self {
        Self {
            name,
            help,
            label,
            scale,
            series: DashMap::new(),
        }
    }

    /// Sets the series for `value` to `scaled`, which is interpreted as
    /// `scaled / scale` when rendered.
    pub fn set_scaled(&self, value: &str, scaled: u64) {
        if let Some(g) = self.series.get(value) {
            g.store(scaled, Ordering::Relaxed);
            return;
        }
        self.series
            .entry(value.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .store(scaled, Ordering::Relaxed);
    }

    /// Drops every series. The scrape-time collector clears before repopulating
    /// so a server removed from the configuration stops being reported instead
    /// of freezing at its last value forever.
    pub fn clear(&self) {
        self.series.clear();
    }

    fn encode(&self, out: &mut String) {
        write_meta(out, self.name, self.help, "gauge");
        for entry in self.series.iter() {
            let v = entry.value().load(Ordering::Relaxed) as f64 / self.scale;
            write_float_sample(out, self.name, &[(self.label, entry.key())], v);
        }
    }
}

/// A histogram with fixed bucket bounds.
///
/// Bounds and observations are in the metric's native *integer* unit —
/// nanoseconds for durations, bytes for sizes — so the running sum can live in a
/// plain `AtomicU64` with no float CAS loop. Both are divided by `scale` when
/// rendered, which is how nanosecond observations come out as the
/// `_seconds` histogram Prometheus expects.
///
/// Bucket counts are stored per-bucket and accumulated at render time into the
/// cumulative `le` form the exposition format requires.
#[derive(Debug)]
pub struct Histogram {
    name: &'static str,
    help: &'static str,
    /// Ascending inclusive upper bounds, in the native integer unit.
    bounds: &'static [u64],
    /// One counter per bound, plus a final `+Inf` overflow bucket.
    counts: Box<[AtomicU64]>,
    sum: AtomicU64,
    count: AtomicU64,
    scale: f64,
}

impl Histogram {
    fn new(name: &'static str, help: &'static str, bounds: &'static [u64], scale: f64) -> Self {
        Self {
            name,
            help,
            bounds,
            counts: (0..bounds.len() + 1).map(|_| AtomicU64::new(0)).collect(),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
            scale,
        }
    }

    /// Records one observation in the histogram's native unit.
    pub fn observe(&self, v: u64) {
        let idx = match self.bounds.iter().position(|&b| v <= b) {
            Some(i) => i,
            None => self.bounds.len(),
        };
        if let Some(c) = self.counts.get(idx) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        self.sum.fetch_add(v, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Total number of observations.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    fn encode(&self, out: &mut String) {
        write_meta(out, self.name, self.help, "histogram");
        let mut cumulative = 0u64;
        for (i, bound) in self.bounds.iter().enumerate() {
            cumulative += self
                .counts
                .get(i)
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0);
            let le = format_float(*bound as f64 / self.scale);
            out.push_str(self.name);
            out.push_str("_bucket{le=\"");
            out.push_str(&le);
            out.push_str("\"} ");
            out.push_str(&cumulative.to_string());
            out.push('\n');
        }
        let total = self.count();
        out.push_str(self.name);
        out.push_str("_bucket{le=\"+Inf\"} ");
        out.push_str(&total.to_string());
        out.push('\n');

        let sum = self.sum.load(Ordering::Relaxed) as f64 / self.scale;
        out.push_str(self.name);
        out.push_str("_sum ");
        out.push_str(&format_float(sum));
        out.push('\n');
        out.push_str(self.name);
        out.push_str("_count ");
        out.push_str(&total.to_string());
        out.push('\n');
    }
}

/// A histogram family over one fixed-cardinality label dimension.
#[derive(Debug)]
pub struct HistogramVec {
    name: &'static str,
    help: &'static str,
    label: &'static str,
    values: &'static [&'static str],
    bounds: &'static [u64],
    /// Row-major: `values.len()` rows of `bounds.len() + 1` bucket counters.
    counts: Box<[AtomicU64]>,
    sums: Box<[AtomicU64]>,
    totals: Box<[AtomicU64]>,
    scale: f64,
}

impl HistogramVec {
    fn new(
        name: &'static str,
        help: &'static str,
        label: &'static str,
        values: &'static [&'static str],
        bounds: &'static [u64],
        scale: f64,
    ) -> Self {
        let width = bounds.len() + 1;
        Self {
            name,
            help,
            label,
            values,
            bounds,
            counts: (0..values.len() * width)
                .map(|_| AtomicU64::new(0))
                .collect(),
            sums: (0..values.len()).map(|_| AtomicU64::new(0)).collect(),
            totals: (0..values.len()).map(|_| AtomicU64::new(0)).collect(),
            scale,
        }
    }

    /// Records one observation against label index `idx`, in the native unit.
    pub fn observe(&self, idx: usize, v: u64) {
        if idx >= self.values.len() {
            return;
        }
        let width = self.bounds.len() + 1;
        let bucket = match self.bounds.iter().position(|&b| v <= b) {
            Some(i) => i,
            None => self.bounds.len(),
        };
        if let Some(c) = self.counts.get(idx * width + bucket) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(s) = self.sums.get(idx) {
            s.fetch_add(v, Ordering::Relaxed);
        }
        if let Some(t) = self.totals.get(idx) {
            t.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn encode(&self, out: &mut String) {
        write_meta(out, self.name, self.help, "histogram");
        let width = self.bounds.len() + 1;
        for (i, value) in self.values.iter().enumerate() {
            let mut cumulative = 0u64;
            for (b, bound) in self.bounds.iter().enumerate() {
                cumulative += self
                    .counts
                    .get(i * width + b)
                    .map(|c| c.load(Ordering::Relaxed))
                    .unwrap_or(0);
                let le = format_float(*bound as f64 / self.scale);
                write_sample(
                    out,
                    &format!("{}_bucket", self.name),
                    &[(self.label, value), ("le", &le)],
                    cumulative,
                );
            }
            let total = self
                .totals
                .get(i)
                .map(|t| t.load(Ordering::Relaxed))
                .unwrap_or(0);
            write_sample(
                out,
                &format!("{}_bucket", self.name),
                &[(self.label, value), ("le", "+Inf")],
                total,
            );
            let sum = self
                .sums
                .get(i)
                .map(|s| s.load(Ordering::Relaxed))
                .unwrap_or(0) as f64
                / self.scale;
            write_float_sample(
                out,
                &format!("{}_sum", self.name),
                &[(self.label, value)],
                sum,
            );
            write_sample(
                out,
                &format!("{}_count", self.name),
                &[(self.label, value)],
                total,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Label dimensions
// ---------------------------------------------------------------------------

/// The transport a query arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp,
    Dot,
    Doh,
    Doq,
}

/// Label values for [`Proto`], indexed by [`Proto::index`].
pub const PROTOS: &[&str] = &["udp", "tcp", "dot", "doh", "doq"];

impl Proto {
    /// Index into [`PROTOS`].
    pub fn index(self) -> usize {
        match self {
            Proto::Udp => 0,
            Proto::Tcp => 1,
            Proto::Dot => 2,
            Proto::Doh => 3,
            Proto::Doq => 4,
        }
    }
}

/// Response-code label values. Anything outside this set folds into `OTHER`
/// rather than minting a new series.
pub const RCODES: &[&str] = &[
    "NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR", "NOTIMP", "OTHER",
];

/// Folds a response code into an index into [`RCODES`].
pub fn rcode_index(rcode: ResponseCode) -> usize {
    match rcode {
        ResponseCode::NoError => 0,
        ResponseCode::NXDomain => 1,
        ResponseCode::ServFail => 2,
        ResponseCode::Refused => 3,
        ResponseCode::FormErr => 4,
        ResponseCode::NotImp => 5,
        _ => 6,
    }
}

/// Folds a raw wire rcode nibble into an index into [`RCODES`].
pub fn rcode_index_from_wire(rcode: u8) -> usize {
    match rcode {
        0 => 0,
        3 => 1,
        2 => 2,
        5 => 3,
        1 => 4,
        4 => 5,
        _ => 6,
    }
}

/// Query-type label values. The `OTHER` catch-all is what keeps a client from
/// minting unbounded series by asking for arbitrary numeric types.
pub const QTYPES: &[&str] = &[
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "TXT",
    "NS",
    "SOA",
    "SRV",
    "PTR",
    "CAA",
    "TLSA",
    "SSHFP",
    "ANAME",
    "NAPTR",
    "DNSKEY",
    "DS",
    "RRSIG",
    "NSEC",
    "NSEC3",
    "NSEC3PARAM",
    "HTTPS",
    "SVCB",
    "ANY",
    "OTHER",
];

/// Folds a record type into an index into [`QTYPES`].
pub fn qtype_index(rt: RecordType) -> usize {
    match rt {
        RecordType::A => 0,
        RecordType::AAAA => 1,
        RecordType::CNAME => 2,
        RecordType::MX => 3,
        RecordType::TXT => 4,
        RecordType::NS => 5,
        RecordType::SOA => 6,
        RecordType::SRV => 7,
        RecordType::PTR => 8,
        RecordType::CAA => 9,
        RecordType::TLSA => 10,
        RecordType::SSHFP => 11,
        RecordType::ANAME => 12,
        RecordType::NAPTR => 13,
        RecordType::DNSKEY => 14,
        RecordType::DS => 15,
        RecordType::RRSIG => 16,
        RecordType::NSEC => 17,
        RecordType::NSEC3 => 18,
        RecordType::NSEC3PARAM => 19,
        RecordType::HTTPS => 20,
        RecordType::SVCB => 21,
        RecordType::ANY => 22,
        _ => 23,
    }
}

/// Which stage of the resolution order produced the answer. This is the metric
/// that makes the split-horizon pipeline legible from outside: it says whether a
/// name was served from a scope, from the global database, from the blocklist,
/// or from upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerSource {
    /// Served from the DNS response cache.
    Cache,
    /// A global record in the local database.
    Local,
    /// A record inside the query's network scope.
    Scoped,
    /// A trusted local source resolving a name from its TLD's owning scope
    /// (resolution step 5).
    ScopeFallback,
    /// Forwarded to an owned TLD's peer forwarders.
    TldPeer,
    /// NXDOMAIN from the name-based blocklist (local RBL or DNSBL).
    Blocklist,
    /// NXDOMAIN from an IP-based RBL on a reverse lookup.
    Rbl,
    /// A synthesized DNS64 AAAA.
    Dns64,
    /// Resolved upstream (any tier).
    Upstream,
    /// Authoritative NXDOMAIN from a managed, authoritative, or owned zone.
    AuthoritativeNxdomain,
    /// REFUSED — an overlay peer that has joined no network.
    Refused,
    /// SERVFAIL, FORMERR, NOTIMP, BADVERS: the query never reached a lookup.
    Error,
}

/// Label values for `dnssec_validate::Verdict`, in the order its `index()`
/// returns. The two live next to each other on purpose: an index that drifts
/// from this list relabels every DNSSEC series silently.
pub const DNSSEC_VERDICTS: &[&str] = &["secure", "insecure", "bogus", "indeterminate"];

/// Label values for [`AnswerSource`].
pub const ANSWER_SOURCES: &[&str] = &[
    "cache",
    "local",
    "scoped",
    "scope_fallback",
    "tld_peer",
    "blocklist",
    "rbl",
    "dns64",
    "upstream",
    "authoritative_nxdomain",
    "refused",
    "error",
];

impl AnswerSource {
    /// Index into [`ANSWER_SOURCES`].
    pub fn index(self) -> usize {
        match self {
            AnswerSource::Cache => 0,
            AnswerSource::Local => 1,
            AnswerSource::Scoped => 2,
            AnswerSource::ScopeFallback => 3,
            AnswerSource::TldPeer => 4,
            AnswerSource::Blocklist => 5,
            AnswerSource::Rbl => 6,
            AnswerSource::Dns64 => 7,
            AnswerSource::Upstream => 8,
            AnswerSource::AuthoritativeNxdomain => 9,
            AnswerSource::Refused => 10,
            AnswerSource::Error => 11,
        }
    }

    /// Inverse of [`Self::index`]. An unrecognized index yields
    /// [`AnswerSource::Error`] rather than panicking — this only ever reads back
    /// a value this same enum wrote.
    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => AnswerSource::Cache,
            1 => AnswerSource::Local,
            2 => AnswerSource::Scoped,
            3 => AnswerSource::ScopeFallback,
            4 => AnswerSource::TldPeer,
            5 => AnswerSource::Blocklist,
            6 => AnswerSource::Rbl,
            7 => AnswerSource::Dns64,
            8 => AnswerSource::Upstream,
            9 => AnswerSource::AuthoritativeNxdomain,
            10 => AnswerSource::Refused,
            _ => AnswerSource::Error,
        }
    }
}

/// The four `auto`-mode resolution tiers, in trust order. Indices match the
/// `TIER_*` constants in [`crate::dns_server`].
pub const TIERS: &[&str] = &["roots", "secure", "local", "public"];

/// Outcome of a single upstream exchange.
pub const UPSTREAM_RESULTS: &[&str] = &["definitive", "indefinite", "error"];

/// Address families, for the routability probe and the answer filter.
pub const FAMILIES: &[&str] = &["ipv4", "ipv6"];

/// Which blocklist produced a block.
pub const BLOCK_KINDS: &[&str] = &["rbl_provider", "rbl_local", "dnsbl_provider"];

/// Reasons the response cache is cleared.
pub const FLUSH_REASONS: &[&str] = &["mutation", "explicit", "tier_switch"];

/// DHCP message types the server acts on. `nak` is absent deliberately: this
/// server never sends one, and a series pinned at zero forever reads like a
/// signal when it is only an unimplemented branch.
pub const DHCP_MESSAGES: &[&str] = &[
    "discover", "offer", "request", "ack", "release", "decline", "inform",
];

/// Lease states reported by the lease gauge.
pub const LEASE_STATES: &[&str] = &["active", "expired", "released", "reclaimable"];

// ---------------------------------------------------------------------------
// Bucket bounds
// ---------------------------------------------------------------------------

/// Duration buckets in **nanoseconds**, spanning a local cache hit (tens of
/// microseconds) through a full iterative resolution that times out (seconds).
const DURATION_BOUNDS_NANOS: &[u64] = &[
    50_000,        // 50µs — cache hit
    100_000,       // 100µs
    250_000,       // 250µs
    500_000,       // 500µs — local database hit
    1_000_000,     // 1ms
    2_500_000,     // 2.5ms
    5_000_000,     // 5ms
    10_000_000,    // 10ms — warm forwarder
    25_000_000,    // 25ms
    50_000_000,    // 50ms
    100_000_000,   // 100ms — cold iterative resolution
    250_000_000,   // 250ms
    500_000_000,   // 500ms
    1_000_000_000, // 1s
    2_500_000_000, // 2.5s — past the 1.5s per-nameserver timeout
    5_000_000_000, // 5s
];

/// Message-size buckets in bytes. `512` is the pre-EDNS limit, `1232` the
/// conventional EDNS payload that avoids fragmentation, `4096` the server's UDP
/// ceiling, and `65535` the TCP ceiling.
const SIZE_BOUNDS_BYTES: &[u64] = &[
    32, 64, 128, 256, 512, 1024, 1232, 2048, 4096, 8192, 16384, 65535,
];

/// Nanoseconds per second — the scale that turns nanosecond observations into a
/// `_seconds` histogram.
const NANOS_PER_SEC: f64 = 1_000_000_000.0;

/// Thousandths, for gauges holding a fractional value in an integer atomic.
const MILLI_SCALE: f64 = 1000.0;

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// Every metric the server exposes.
///
/// Fields are grouped by subsystem in the same order [`Metrics::render`] emits
/// them, so the exposition output reads top-to-bottom like this struct.
#[derive(Debug)]
pub struct Metrics {
    // --- process ---
    /// Wall-clock start time, for `rolodex_dns_start_time_seconds`.
    start_unix: u64,
    /// Monotonic start instant, for the uptime gauge (immune to clock steps).
    start_instant: Instant,
    /// Number of times `/metrics` has been scraped.
    pub scrapes: Counter,

    // --- query path ---
    /// Queries answered, by transport and response code.
    pub queries: CounterVec2,
    /// Queries by (folded) query type.
    pub queries_by_type: CounterVec,
    /// Which resolution stage produced the answer.
    pub answer_source: CounterVec,
    /// End-to-end handling time, by transport.
    pub query_duration: HistogramVec,
    /// Received query sizes.
    pub query_size: Histogram,
    /// Emitted response sizes.
    pub response_size: Histogram,
    /// Responses that set TC.
    pub responses_truncated: Counter,
    /// Queries that could not be parsed or were malformed.
    pub malformed_queries: Counter,
    /// Queries carrying an EDNS version the server does not implement.
    pub edns_unsupported_version: Counter,
    /// Queries with the EDNS DO bit set.
    pub edns_do_queries: Counter,
    /// Per-TLD ingress rewrites applied to an A/AAAA answer.
    pub ingress_rewrites: Counter,
    /// A/AAAA records dropped because the host cannot route that family.
    pub answers_family_filtered: CounterVec,

    // --- response cache ---
    /// Response-cache lookups that hit.
    pub cache_hits: Counter,
    /// Response-cache lookups that missed.
    pub cache_misses: Counter,
    /// Cached negative answers served.
    pub cache_negative_hits: Counter,
    /// Entries dropped because their TTL had elapsed when they were read.
    pub cache_expired: Counter,
    /// Cache clears, by what triggered them.
    pub cache_flushes: CounterVec,
    /// Live positive entries (sampled at scrape).
    pub cache_entries: Gauge,
    /// Live cached negative answers (sampled at scrape).
    pub cache_negative_entries: Gauge,

    // --- blocklists ---
    /// Queries answered NXDOMAIN by a blocklist, by which list matched.
    pub blocklist_blocks: CounterVec,
    /// Names that skipped the blocklist check via the DNSBL allowlist.
    pub blocklist_allowlisted: Counter,
    /// Blocklist provider lookups, by list kind and outcome.
    pub blocklist_lookups: CounterVec2,
    /// Provider lookups skipped because plaintext `:53` is unusable.
    pub blocklist_skipped: Counter,
    /// Entries in the shared RBL/DNSBL result cache (sampled at scrape).
    pub blocklist_cache_entries: Gauge,

    // --- upstream resolution ---
    /// The committed `auto` tier (0=roots … 3=public).
    pub active_tier: Gauge,
    /// Tiers tried.
    pub tier_attempts: CounterVec,
    /// Tiers that returned a definitive answer.
    pub tier_wins: CounterVec,
    /// Tiers that failed or answered indefinitely and fell through.
    pub tier_failures: CounterVec,
    /// Committed tier changes, by direction.
    pub tier_switches: CounterVec,
    /// Recovery probes that restarted the chain at the top.
    pub recovery_probes: Counter,
    /// Time spent in the winning upstream tier.
    pub upstream_duration: HistogramVec,
    /// Upstream exchanges by server address and outcome.
    pub upstream_queries: DynCounterVec,
    /// Queries that exhausted every tier and became SERVFAIL.
    pub upstream_exhausted: Counter,

    // --- iterative resolver ---
    /// Client lookups that entered the iterative resolver.
    pub resolver_lookups: Counter,
    /// Delegation referrals followed.
    pub resolver_referrals: Counter,
    /// Referrals and glue records discarded for being out of bailiwick.
    pub resolver_out_of_bailiwick: Counter,
    /// CNAME hops followed.
    pub resolver_cname_hops: Counter,
    /// Lookups aborted by the 64-query budget.
    pub resolver_budget_exhausted: Counter,
    /// Truncated UDP responses retried over TCP.
    pub resolver_tcp_retries: Counter,
    /// Root priming attempts, by outcome.
    pub resolver_priming: CounterVec,
    /// Per-nameserver EMA latency in milliseconds (sampled at scrape).
    pub resolver_latency_ms: DynGaugeVec,
    /// Zones in the delegation cache (sampled at scrape).
    pub delegation_cache_entries: Gauge,
    /// Keys in the resolver's record cache (sampled at scrape).
    pub record_cache_entries: Gauge,

    // --- DNSSEC validation ---
    /// Resolutions by DNSSEC verdict.
    ///
    /// `bogus` is the series to alert on: it is data that claimed to be signed
    /// and was not, which is either an attack or a zone that has broken its own
    /// signing. `indeterminate` is kept separate because it means we could not
    /// obtain what we needed — a network fault, not a forgery.
    pub dnssec_verdicts: CounterVec,
    /// Answers withheld and turned into SERVFAIL because validation failed.
    pub dnssec_servfail: Counter,
    /// DNSKEY RRsets fetched and validated while walking a chain of trust.
    pub dnssec_dnskey_lookups: Counter,
    /// Delegations proven to carry no DS, i.e. legitimately unsigned zones.
    pub dnssec_insecure_delegations: Counter,
    /// Zones held in the validated-key cache (sampled at scrape).
    pub key_cache_entries: Gauge,

    // --- split-horizon state ---
    /// Records in the global database (sampled at scrape).
    pub records: Gauge,
    /// Scoped records across all scopes (sampled at scrape).
    pub scoped_records: Gauge,
    /// Configured network scopes (sampled at scrape).
    pub scopes: Gauge,
    /// Live IP-to-scope associations (sampled at scrape).
    pub scope_associations: Gauge,
    /// Zones declared authoritative (sampled at scrape).
    pub authoritative_zones: Gauge,
    /// Zones with records, hence implicitly managed (sampled at scrape).
    pub managed_zones: Gauge,
    /// Per-network owned TLDs (sampled at scrape).
    pub owned_tlds: Gauge,
    /// Live per-TLD ingress listeners (sampled at scrape).
    pub ingress_listeners: Gauge,
    /// Whether each address family is currently routable (sampled at scrape).
    pub family_reachable: GaugeVec,

    // --- DHCP ---
    /// DHCP messages handled, by type.
    pub dhcp_messages: CounterVec,
    /// Leases by state (sampled at scrape).
    pub dhcp_leases: GaugeVec,
    /// Configured address pools (sampled at scrape).
    pub dhcp_pools: Gauge,
    /// Requests that found no free address in the pool.
    pub dhcp_allocation_failures: Counter,
    /// Background lease-sweep passes.
    pub dhcp_sweeps: Counter,

    // --- ACME issuer ---
    /// Registered ACME accounts (sampled at scrape).
    pub acme_accounts: Gauge,
    /// Issued certificates on record (sampled at scrape).
    pub acme_certificates: Gauge,
    /// Certificates signed by the issuer since boot.
    pub acme_issued: Counter,
    /// dns-01 challenge validations, by outcome.
    pub acme_validations: CounterVec,

    // --- gRPC control plane ---
    /// gRPC calls served, by method.
    pub grpc_requests: DynCounterVec,
    /// gRPC calls rejected for a bad or missing shared secret.
    pub grpc_auth_failures: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// Builds a fresh, empty registry.
    ///
    /// Production code uses the global [`metrics()`] instead; this is public so
    /// unit tests can exercise the primitives and the exposition format against
    /// an isolated instance.
    pub fn new() -> Self {
        Self {
            start_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs(),
            start_instant: Instant::now(),
            scrapes: Counter::new(
                "rolodex_dns_metrics_scrapes_total",
                "Number of times the /metrics endpoint has been scraped.",
            ),

            queries: CounterVec2::new(
                "rolodex_dns_queries_total",
                "DNS queries answered, by transport and response code.",
                ["proto", "rcode"],
                PROTOS,
                RCODES,
            ),
            queries_by_type: CounterVec::new(
                "rolodex_dns_queries_by_type_total",
                "DNS queries answered, by query type. Unrecognized types fold into OTHER.",
                "qtype",
                QTYPES,
            ),
            answer_source: CounterVec::new(
                "rolodex_dns_answers_total",
                "Answers by the resolution stage that produced them.",
                "source",
                ANSWER_SOURCES,
            ),
            query_duration: HistogramVec::new(
                "rolodex_dns_query_duration_seconds",
                "End-to-end query handling time, by transport.",
                "proto",
                PROTOS,
                DURATION_BOUNDS_NANOS,
                NANOS_PER_SEC,
            ),
            query_size: Histogram::new(
                "rolodex_dns_query_size_bytes",
                "Size of received DNS queries.",
                SIZE_BOUNDS_BYTES,
                1.0,
            ),
            response_size: Histogram::new(
                "rolodex_dns_response_size_bytes",
                "Size of emitted DNS responses.",
                SIZE_BOUNDS_BYTES,
                1.0,
            ),
            responses_truncated: Counter::new(
                "rolodex_dns_responses_truncated_total",
                "Responses returned with the TC bit set.",
            ),
            malformed_queries: Counter::new(
                "rolodex_dns_malformed_queries_total",
                "Queries rejected as unparseable or structurally invalid.",
            ),
            edns_unsupported_version: Counter::new(
                "rolodex_dns_edns_unsupported_version_total",
                "Queries rejected with BADVERS for an EDNS version above 0.",
            ),
            edns_do_queries: Counter::new(
                "rolodex_dns_edns_do_queries_total",
                "Queries received with the EDNS DNSSEC-OK bit set.",
            ),
            ingress_rewrites: Counter::new(
                "rolodex_dns_ingress_rewrites_total",
                "A/AAAA answers rewritten to a per-TLD ingress listener address.",
            ),
            answers_family_filtered: CounterVec::new(
                "rolodex_dns_answers_family_filtered_total",
                "Address records dropped because the host cannot route that family.",
                "family",
                FAMILIES,
            ),

            cache_hits: Counter::new(
                "rolodex_dns_cache_hits_total",
                "Response-cache lookups served from cache.",
            ),
            cache_misses: Counter::new(
                "rolodex_dns_cache_misses_total",
                "Response-cache lookups that found nothing live.",
            ),
            cache_negative_hits: Counter::new(
                "rolodex_dns_cache_negative_hits_total",
                "Cached negative answers (NXDOMAIN/NODATA) served from cache.",
            ),
            cache_expired: Counter::new(
                "rolodex_dns_cache_expired_total",
                "Cache entries evicted on access because their TTL had elapsed.",
            ),
            cache_flushes: CounterVec::new(
                "rolodex_dns_cache_flushes_total",
                "Response-cache clears, by what triggered them.",
                "reason",
                FLUSH_REASONS,
            ),
            cache_entries: Gauge::new(
                "rolodex_dns_cache_entries",
                "Live positive entries in the response cache.",
            ),
            cache_negative_entries: Gauge::new(
                "rolodex_dns_cache_negative_entries",
                "Live cached negative answers (NXDOMAIN/NODATA) in the response cache.",
            ),

            blocklist_blocks: CounterVec::new(
                "rolodex_dns_blocklist_blocks_total",
                "Queries answered NXDOMAIN by a blocklist, by which list matched.",
                "kind",
                BLOCK_KINDS,
            ),
            blocklist_allowlisted: Counter::new(
                "rolodex_dns_blocklist_allowlisted_total",
                "Queries that skipped the blocklist check via the DNSBL allowlist.",
            ),
            blocklist_lookups: CounterVec2::new(
                "rolodex_dns_blocklist_lookups_total",
                "Blocklist provider lookups, by list kind and outcome.",
                ["kind", "result"],
                BLOCK_KINDS,
                &["listed", "not_listed", "error"],
            ),
            blocklist_skipped: Counter::new(
                "rolodex_dns_blocklist_skipped_total",
                "Provider lookups skipped because plaintext :53 is unusable.",
            ),
            blocklist_cache_entries: Gauge::new(
                "rolodex_dns_blocklist_cache_entries",
                "Entries in the shared RBL/DNSBL result cache.",
            ),

            active_tier: Gauge::new(
                "rolodex_dns_upstream_active_tier",
                "Committed auto-mode resolution tier: 0=roots, 1=secure, 2=local, 3=public.",
            ),
            tier_attempts: CounterVec::new(
                "rolodex_dns_upstream_tier_attempts_total",
                "Upstream tiers tried.",
                "tier",
                TIERS,
            ),
            tier_wins: CounterVec::new(
                "rolodex_dns_upstream_tier_wins_total",
                "Upstream tiers that returned a definitive answer.",
                "tier",
                TIERS,
            ),
            tier_failures: CounterVec::new(
                "rolodex_dns_upstream_tier_failures_total",
                "Upstream tiers that failed or answered indefinitely and fell through.",
                "tier",
                TIERS,
            ),
            tier_switches: CounterVec::new(
                "rolodex_dns_upstream_tier_switches_total",
                "Committed tier changes: a recovery moves to a more-trusted tier, a degrade to a less-trusted one.",
                "direction",
                &["recover", "degrade"],
            ),
            recovery_probes: Counter::new(
                "rolodex_dns_upstream_recovery_probes_total",
                "Queries that restarted the tier chain at the top to reclaim a recovered tier.",
            ),
            upstream_duration: HistogramVec::new(
                "rolodex_dns_upstream_duration_seconds",
                "Time spent resolving upstream, by the tier that answered.",
                "tier",
                TIERS,
                DURATION_BOUNDS_NANOS,
                NANOS_PER_SEC,
            ),
            upstream_queries: DynCounterVec::new(
                "rolodex_dns_upstream_queries_total",
                "Upstream exchanges by server address.",
                "server",
            ),
            upstream_exhausted: Counter::new(
                "rolodex_dns_upstream_exhausted_total",
                "Queries that exhausted every upstream tier and became SERVFAIL.",
            ),

            resolver_lookups: Counter::new(
                "rolodex_dns_resolver_lookups_total",
                "Client lookups that entered the iterative resolver.",
            ),
            resolver_referrals: Counter::new(
                "rolodex_dns_resolver_referrals_total",
                "Delegation referrals followed while walking down from the roots.",
            ),
            resolver_out_of_bailiwick: Counter::new(
                "rolodex_dns_resolver_out_of_bailiwick_total",
                "Referrals and glue records discarded for delegating or naming \
                 something outside the zone that answered.",
            ),
            resolver_cname_hops: Counter::new(
                "rolodex_dns_resolver_cname_hops_total",
                "CNAME hops followed during iterative resolution.",
            ),
            resolver_budget_exhausted: Counter::new(
                "rolodex_dns_resolver_budget_exhausted_total",
                "Lookups aborted by the per-lookup upstream query budget.",
            ),
            resolver_tcp_retries: Counter::new(
                "rolodex_dns_resolver_tcp_retries_total",
                "Truncated UDP responses retried over TCP.",
            ),
            resolver_priming: CounterVec::new(
                "rolodex_dns_resolver_priming_total",
                "Root priming attempts, by outcome.",
                "result",
                &["success", "failure"],
            ),
            resolver_latency_ms: DynGaugeVec::new(
                "rolodex_dns_resolver_nameserver_latency_milliseconds",
                "Per-nameserver EMA latency used for server selection.",
                "server",
                MILLI_SCALE,
            ),
            delegation_cache_entries: Gauge::new(
                "rolodex_dns_delegation_cache_entries",
                "Zones held in the resolver's delegation cache.",
            ),
            record_cache_entries: Gauge::new(
                "rolodex_dns_record_cache_entries",
                "Keys held in the resolver's record cache.",
            ),

            dnssec_verdicts: CounterVec::new(
                "rolodex_dns_dnssec_verdicts_total",
                "Upstream resolutions by DNSSEC validation verdict.",
                "verdict",
                DNSSEC_VERDICTS,
            ),
            dnssec_servfail: Counter::new(
                "rolodex_dns_dnssec_servfail_total",
                "Answers withheld as SERVFAIL because DNSSEC validation failed.",
            ),
            dnssec_dnskey_lookups: Counter::new(
                "rolodex_dns_dnssec_dnskey_lookups_total",
                "DNSKEY RRsets fetched and validated while building a chain of trust.",
            ),
            dnssec_insecure_delegations: Counter::new(
                "rolodex_dns_dnssec_insecure_delegations_total",
                "Delegations proven to carry no DS record.",
            ),
            key_cache_entries: Gauge::new(
                "rolodex_dns_key_cache_entries",
                "Zones held in the resolver's validated-key cache.",
            ),

            records: Gauge::new(
                "rolodex_dns_records",
                "Records in the global (unscoped) database.",
            ),
            scoped_records: Gauge::new(
                "rolodex_dns_scoped_records",
                "Records across all network scopes.",
            ),
            scopes: Gauge::new("rolodex_dns_scopes", "Configured network scopes."),
            scope_associations: Gauge::new(
                "rolodex_dns_scope_associations",
                "Live IP-to-scope associations.",
            ),
            authoritative_zones: Gauge::new(
                "rolodex_dns_authoritative_zones",
                "Zones explicitly declared authoritative.",
            ),
            managed_zones: Gauge::new(
                "rolodex_dns_managed_zones",
                "Zones with local records, and therefore implicitly managed.",
            ),
            owned_tlds: Gauge::new("rolodex_dns_owned_tlds", "TLDs owned by a network scope."),
            ingress_listeners: Gauge::new(
                "rolodex_dns_ingress_listeners",
                "Live per-TLD ingress DNS listeners.",
            ),
            family_reachable: GaugeVec::new(
                "rolodex_dns_address_family_reachable",
                "Whether the host can currently reach the internet over each address family.",
                "family",
                FAMILIES,
            ),

            dhcp_messages: CounterVec::new(
                "rolodex_dns_dhcp_messages_total",
                "DHCP messages handled, by type.",
                "type",
                DHCP_MESSAGES,
            ),
            dhcp_leases: GaugeVec::new(
                "rolodex_dns_dhcp_leases",
                "DHCP leases by state.",
                "state",
                LEASE_STATES,
            ),
            dhcp_pools: Gauge::new("rolodex_dns_dhcp_pools", "Configured DHCP address pools."),
            dhcp_allocation_failures: Counter::new(
                "rolodex_dns_dhcp_allocation_failures_total",
                "Requests that found no free address in the matching pool.",
            ),
            dhcp_sweeps: Counter::new(
                "rolodex_dns_dhcp_sweeps_total",
                "Background lease-sweep passes.",
            ),

            acme_accounts: Gauge::new("rolodex_dns_acme_accounts", "Registered ACME accounts."),
            acme_certificates: Gauge::new(
                "rolodex_dns_acme_certificates",
                "Issued certificates on record.",
            ),
            acme_issued: Counter::new(
                "rolodex_dns_acme_issued_total",
                "Certificates signed by the issuer since boot.",
            ),
            acme_validations: CounterVec::new(
                "rolodex_dns_acme_validations_total",
                "dns-01 challenge validations, by outcome.",
                "result",
                &["valid", "invalid"],
            ),

            grpc_requests: DynCounterVec::new(
                "rolodex_dns_grpc_requests_total",
                "gRPC control-plane calls served, by method.",
                "method",
            ),
            grpc_auth_failures: Counter::new(
                "rolodex_dns_grpc_auth_failures_total",
                "gRPC calls rejected for a missing or incorrect shared secret.",
            ),
        }
    }

    /// Renders the whole registry in the Prometheus text exposition format.
    ///
    /// The order here is the order the fields are declared in, so the scrape
    /// output reads like the struct.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(16 * 1024);

        write_meta(
            &mut out,
            "rolodex_dns_build_info",
            "Build information; the value is always 1.",
            "gauge",
        );
        write_sample(
            &mut out,
            "rolodex_dns_build_info",
            &[("version", env!("CARGO_PKG_VERSION"))],
            1,
        );

        write_meta(
            &mut out,
            "rolodex_dns_start_time_seconds",
            "Unix timestamp at which the process started.",
            "gauge",
        );
        write_sample(
            &mut out,
            "rolodex_dns_start_time_seconds",
            &[],
            self.start_unix,
        );

        write_meta(
            &mut out,
            "rolodex_dns_uptime_seconds",
            "Seconds since the process started, measured monotonically.",
            "gauge",
        );
        write_sample(
            &mut out,
            "rolodex_dns_uptime_seconds",
            &[],
            self.start_instant.elapsed().as_secs(),
        );

        self.scrapes.encode(&mut out);

        self.queries.encode(&mut out);
        self.queries_by_type.encode(&mut out);
        self.answer_source.encode(&mut out);
        self.query_duration.encode(&mut out);
        self.query_size.encode(&mut out);
        self.response_size.encode(&mut out);
        self.responses_truncated.encode(&mut out);
        self.malformed_queries.encode(&mut out);
        self.edns_unsupported_version.encode(&mut out);
        self.edns_do_queries.encode(&mut out);
        self.ingress_rewrites.encode(&mut out);
        self.answers_family_filtered.encode(&mut out);

        self.cache_hits.encode(&mut out);
        self.cache_misses.encode(&mut out);
        self.cache_negative_hits.encode(&mut out);
        self.cache_expired.encode(&mut out);
        self.cache_flushes.encode(&mut out);
        self.cache_entries.encode(&mut out);
        self.cache_negative_entries.encode(&mut out);

        self.blocklist_blocks.encode(&mut out);
        self.blocklist_allowlisted.encode(&mut out);
        self.blocklist_lookups.encode(&mut out);
        self.blocklist_skipped.encode(&mut out);
        self.blocklist_cache_entries.encode(&mut out);

        self.active_tier.encode(&mut out);
        self.tier_attempts.encode(&mut out);
        self.tier_wins.encode(&mut out);
        self.tier_failures.encode(&mut out);
        self.tier_switches.encode(&mut out);
        self.recovery_probes.encode(&mut out);
        self.upstream_duration.encode(&mut out);
        self.upstream_queries.encode(&mut out);
        self.upstream_exhausted.encode(&mut out);

        self.resolver_lookups.encode(&mut out);
        self.resolver_referrals.encode(&mut out);
        self.resolver_out_of_bailiwick.encode(&mut out);
        self.resolver_cname_hops.encode(&mut out);
        self.resolver_budget_exhausted.encode(&mut out);
        self.resolver_tcp_retries.encode(&mut out);
        self.resolver_priming.encode(&mut out);
        self.resolver_latency_ms.encode(&mut out);
        self.delegation_cache_entries.encode(&mut out);
        self.record_cache_entries.encode(&mut out);

        self.dnssec_verdicts.encode(&mut out);
        self.dnssec_servfail.encode(&mut out);
        self.dnssec_dnskey_lookups.encode(&mut out);
        self.dnssec_insecure_delegations.encode(&mut out);
        self.key_cache_entries.encode(&mut out);

        self.records.encode(&mut out);
        self.scoped_records.encode(&mut out);
        self.scopes.encode(&mut out);
        self.scope_associations.encode(&mut out);
        self.authoritative_zones.encode(&mut out);
        self.managed_zones.encode(&mut out);
        self.owned_tlds.encode(&mut out);
        self.ingress_listeners.encode(&mut out);
        self.family_reachable.encode(&mut out);

        self.dhcp_messages.encode(&mut out);
        self.dhcp_leases.encode(&mut out);
        self.dhcp_pools.encode(&mut out);
        self.dhcp_allocation_failures.encode(&mut out);
        self.dhcp_sweeps.encode(&mut out);

        self.acme_accounts.encode(&mut out);
        self.acme_certificates.encode(&mut out);
        self.acme_issued.encode(&mut out);
        self.acme_validations.encode(&mut out);

        self.grpc_requests.encode(&mut out);
        self.grpc_auth_failures.encode(&mut out);

        out
    }

    /// Records a completed query: the transport, the answer's response code and
    /// query type, the sizes of both messages, and how long it took.
    ///
    /// Called from one place — the single exit through which every transport's
    /// responses pass — so a new early return in the resolution pipeline cannot
    /// silently escape instrumentation.
    pub fn observe_query(&self, obs: QueryObservation) {
        self.queries.inc(obs.proto.index(), obs.rcode_index);
        self.queries_by_type.inc(obs.qtype_index);
        self.answer_source.inc(obs.source.index());
        self.query_duration.observe(
            obs.proto.index(),
            obs.elapsed.as_nanos().min(u64::MAX as u128) as u64,
        );
        self.query_size.observe(obs.query_bytes as u64);
        self.response_size.observe(obs.response_bytes as u64);
        if obs.truncated {
            self.responses_truncated.inc();
        }
    }
}

/// One completed query, as handed to [`Metrics::observe_query`].
#[derive(Debug, Clone, Copy)]
pub struct QueryObservation {
    /// Transport the query arrived on.
    pub proto: Proto,
    /// Index into [`RCODES`] for the response code sent.
    pub rcode_index: usize,
    /// Index into [`QTYPES`] for the question's type.
    pub qtype_index: usize,
    /// Which resolution stage produced the answer.
    pub source: AnswerSource,
    /// Bytes received.
    pub query_bytes: usize,
    /// Bytes sent.
    pub response_bytes: usize,
    /// Whether the response set TC.
    pub truncated: bool,
    /// End-to-end handling time.
    pub elapsed: Duration,
}

// ---------------------------------------------------------------------------
// Scrape-time collection
// ---------------------------------------------------------------------------

/// The live state a scrape samples gauges from.
///
/// Counters are pushed by the code that does the work, but a gauge — how many
/// records exist, how large the caches are, which tier is committed — has no
/// natural push point, and keeping one in sync from every mutation site would
/// be a standing invitation to drift. Those are pulled here instead, once per
/// scrape.
#[derive(Clone)]
pub struct MetricsState {
    /// Record database, for the row counts.
    pub db: crate::db::Database,
    /// The DNS server, for tier, ingress and address-family state.
    pub dns_server: std::sync::Arc<crate::dns_server::DnsServer>,
    /// The response cache, when one is configured.
    pub dns_cache: Option<std::sync::Arc<crate::dns_cache::DnsCache>>,
    /// The blocklist checker, for its result-cache size.
    pub rbl: std::sync::Arc<crate::rbl::RblChecker>,
}

/// Samples every pull-based gauge into the global registry.
///
/// A failure to read the database is logged and skipped rather than failing the
/// scrape: the counters are still worth serving, and a metrics endpoint that
/// returns 500 because SQLite was briefly locked would page someone about the
/// wrong thing.
pub fn collect(state: &MetricsState) {
    let m = metrics();

    match state.db.metrics_counts() {
        Ok(counts) => {
            m.records.set(counts.records);
            m.scoped_records.set(counts.scoped_records);
            m.scopes.set(counts.scopes);
            m.scope_associations.set(counts.associations);
            m.authoritative_zones.set(counts.authoritative_zones);
            m.owned_tlds.set(counts.owned_tlds);
            m.dhcp_pools.set(counts.dhcp_pools);
            m.acme_accounts.set(counts.acme_accounts);
            m.acme_certificates.set(counts.acme_certificates);

            // Zero every state first: a state that drops to no rows disappears
            // from the GROUP BY, and without this its gauge would stay frozen at
            // its last non-zero value forever.
            for i in 0..LEASE_STATES.len() {
                m.dhcp_leases.set(i, 0);
            }
            for (state_name, n) in &counts.leases_by_state {
                if let Some(i) = LEASE_STATES.iter().position(|s| *s == state_name) {
                    m.dhcp_leases.set(i, *n);
                }
            }
        }
        Err(e) => tracing::warn!("metrics: database counts unavailable: {}", e),
    }

    m.managed_zones.set(state.db.managed_zone_count() as u64);

    if let Some(ref cache) = state.dns_cache {
        m.cache_entries.set(cache.stats().total_entries);
        m.cache_negative_entries
            .set(cache.negative_entries() as u64);
    }

    m.blocklist_cache_entries
        .set(state.rbl.cache_entries() as u64);

    m.active_tier.set(state.dns_server.active_tier() as u64);
    m.ingress_listeners
        .set(state.dns_server.ingress_listener_count() as u64);

    let (v4, v6) = state.dns_server.answer_families();
    m.family_reachable.set(0, u64::from(v4));
    m.family_reachable.set(1, u64::from(v6));

    let resolver = state.dns_server.resolver();
    m.delegation_cache_entries
        .set(resolver.delegations().len() as u64);
    m.record_cache_entries.set(resolver.records().len() as u64);
    m.key_cache_entries.set(resolver.keys().len() as u64);

    // Replace rather than update: a nameserver that has aged out of the
    // resolver's stats should stop being reported, not freeze.
    m.resolver_latency_ms.clear();
    for (server, latency_ms, _hits) in resolver.latency_stats() {
        let scaled = (latency_ms * MILLI_SCALE).max(0.0).min(u64::MAX as f64) as u64;
        m.resolver_latency_ms
            .set_scaled(&server.to_string(), scaled);
    }
}

// ---------------------------------------------------------------------------
// The /metrics listener
// ---------------------------------------------------------------------------

/// Serves the Prometheus scrape endpoint on `bind`, over plain HTTP.
///
/// Plain HTTP, deliberately: Prometheus scrapes are an internal, trusted-network
/// concern and the endpoint carries no secrets — no query names, no record
/// values, only aggregate counts. Terminating TLS here would mean either
/// shipping the self-signed certificate to every scraper or standing up a real
/// one for an endpoint that should be bound to a private address anyway. The
/// default bind is loopback for exactly that reason.
pub async fn serve_metrics(bind: &str, state: MetricsState) -> anyhow::Result<()> {
    use anyhow::Context;

    let app = build_router(state);

    let addr: std::net::SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid metrics bind address: {bind}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding metrics listener on {addr}"))?;
    tracing::info!("Prometheus metrics listening on http://{}/metrics", addr);
    axum::serve(listener, app)
        .await
        .context("metrics server error")?;
    Ok(())
}

/// Builds the metrics router.
///
/// Split out of [`serve_metrics`] so tests can serve it on an
/// already-bound ephemeral port: `serve_metrics` resolves and binds the address
/// itself, which leaves a test with no way to learn which port it got short of
/// binding one first and racing to hand it over.
pub fn build_router(state: MetricsState) -> axum::Router {
    axum::Router::new()
        .route("/metrics", axum::routing::get(scrape))
        .route("/", axum::routing::get(index))
        .with_state(state)
}

async fn scrape(
    axum::extract::State(state): axum::extract::State<MetricsState>,
) -> impl axum::response::IntoResponse {
    let m = metrics();
    m.scrapes.inc();
    collect(&state);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        m.render(),
    )
}

/// A landing page, so hitting the port in a browser says what it is instead of
/// returning a bare 404.
async fn index() -> axum::response::Html<&'static str> {
    axum::response::Html(
        "<!doctype html><title>rolodex-dns metrics</title>\
         <h1>rolodex-dns</h1><p><a href=\"/metrics\">Metrics</a></p>",
    )
}

// ---------------------------------------------------------------------------
// Exposition-format helpers
// ---------------------------------------------------------------------------

fn write_meta(out: &mut String, name: &str, help: &str, kind: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
}

fn write_labels(out: &mut String, labels: &[(&str, &str)]) {
    if labels.is_empty() {
        return;
    }
    out.push('{');
    for (i, (k, v)) in labels.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(k);
        out.push_str("=\"");
        escape_label_value(out, v);
        out.push('"');
    }
    out.push('}');
}

fn write_sample(out: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
    out.push_str(name);
    write_labels(out, labels);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

fn write_float_sample(out: &mut String, name: &str, labels: &[(&str, &str)], value: f64) {
    out.push_str(name);
    write_labels(out, labels);
    out.push(' ');
    out.push_str(&format_float(value));
    out.push('\n');
}

/// Escapes a label value per the exposition format: backslash, double quote and
/// newline. Our label values are addresses and fixed identifiers, but escaping
/// unconditionally means a future dynamic label cannot corrupt the output.
fn escape_label_value(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

/// Formats a float for the exposition format, avoiding scientific notation for
/// the small bucket bounds (`1e-4` is legal but `0.0001` is what every other
/// exporter emits, and it keeps bucket labels stable and greppable).
fn format_float(v: f64) -> String {
    if v == v.trunc() && v.abs() < 1e15 {
        return format!("{}", v as i64);
    }
    let s = format!("{v:.9}");
    let trimmed = s.trim_end_matches('0');
    let trimmed = trimmed.trim_end_matches('.');
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_counts() {
        let m = Metrics::new();
        m.cache_hits.inc();
        m.cache_hits.add(4);
        assert_eq!(m.cache_hits.get(), 5);
    }

    #[test]
    fn gauge_sets_and_overwrites() {
        let m = Metrics::new();
        m.cache_entries.set(7);
        m.cache_entries.set(3);
        assert_eq!(m.cache_entries.get(), 3);
    }

    #[test]
    fn counter_vec_is_per_label() {
        let m = Metrics::new();
        m.tier_attempts.inc(0);
        m.tier_attempts.inc(0);
        m.tier_attempts.inc(2);
        assert_eq!(m.tier_attempts.get(0), 2);
        assert_eq!(m.tier_attempts.get(1), 0);
        assert_eq!(m.tier_attempts.get(2), 1);
    }

    #[test]
    fn counter_vec_ignores_out_of_range_index() {
        // A bad index must never panic on the query path.
        let m = Metrics::new();
        m.tier_attempts.inc(99);
        assert_eq!(m.tier_attempts.get(99), 0);
    }

    #[test]
    fn counter_vec2_indexes_row_major() {
        let m = Metrics::new();
        m.queries.inc(Proto::Udp.index(), 0);
        m.queries.inc(Proto::Doh.index(), 1);
        m.queries.inc(Proto::Doh.index(), 1);
        assert_eq!(m.queries.get(Proto::Udp.index(), 0), 1);
        assert_eq!(m.queries.get(Proto::Doh.index(), 1), 2);
        assert_eq!(m.queries.get(Proto::Udp.index(), 1), 0);
    }

    #[test]
    fn dyn_counter_vec_creates_series_on_demand() {
        let m = Metrics::new();
        m.upstream_queries.inc("8.8.8.8:53");
        m.upstream_queries.inc("8.8.8.8:53");
        m.upstream_queries.inc("1.1.1.1:53");
        let out = m.render();
        assert!(out.contains("rolodex_dns_upstream_queries_total{server=\"8.8.8.8:53\"} 2"));
        assert!(out.contains("rolodex_dns_upstream_queries_total{server=\"1.1.1.1:53\"} 1"));
    }

    #[test]
    fn dyn_gauge_vec_scales_and_clears() {
        let m = Metrics::new();
        m.resolver_latency_ms.set_scaled("198.41.0.4:53", 12_500);
        let out = m.render();
        assert!(
            out.contains(
                "rolodex_dns_resolver_nameserver_latency_milliseconds{server=\"198.41.0.4:53\"} 12.5"
            ),
            "unexpected output:\n{out}"
        );
        m.resolver_latency_ms.clear();
        assert!(
            !m.render()
                .contains("rolodex_dns_resolver_nameserver_latency_milliseconds{server=")
        );
    }

    #[test]
    fn histogram_buckets_are_cumulative() {
        let m = Metrics::new();
        // 100 bytes, 300 bytes, 100_000 bytes (past the last bound).
        m.response_size.observe(100);
        m.response_size.observe(300);
        m.response_size.observe(100_000);
        let out = m.render();
        // 100 lands in le=128; 300 in le=512; the huge one only in +Inf.
        assert!(out.contains("rolodex_dns_response_size_bytes_bucket{le=\"64\"} 0"));
        assert!(out.contains("rolodex_dns_response_size_bytes_bucket{le=\"128\"} 1"));
        assert!(out.contains("rolodex_dns_response_size_bytes_bucket{le=\"512\"} 2"));
        assert!(out.contains("rolodex_dns_response_size_bytes_bucket{le=\"65535\"} 2"));
        assert!(out.contains("rolodex_dns_response_size_bytes_bucket{le=\"+Inf\"} 3"));
        assert!(out.contains("rolodex_dns_response_size_bytes_sum 100400"));
        assert!(out.contains("rolodex_dns_response_size_bytes_count 3"));
    }

    #[test]
    fn duration_histogram_renders_as_seconds() {
        let m = Metrics::new();
        // 1.5ms, expressed in nanoseconds.
        m.query_duration.observe(Proto::Udp.index(), 1_500_000);
        let out = m.render();
        assert!(
            out.contains("rolodex_dns_query_duration_seconds_bucket{proto=\"udp\",le=\"0.001\"} 0"),
            "unexpected output:\n{out}"
        );
        assert!(
            out.contains(
                "rolodex_dns_query_duration_seconds_bucket{proto=\"udp\",le=\"0.0025\"} 1"
            )
        );
        assert!(out.contains("rolodex_dns_query_duration_seconds_sum{proto=\"udp\"} 0.0015"));
        assert!(out.contains("rolodex_dns_query_duration_seconds_count{proto=\"udp\"} 1"));
        // Another transport's series must be untouched.
        assert!(out.contains("rolodex_dns_query_duration_seconds_count{proto=\"doh\"} 0"));
    }

    #[test]
    fn histogram_vec_ignores_out_of_range_index() {
        let m = Metrics::new();
        m.query_duration.observe(99, 1_000);
        assert!(
            m.render()
                .contains("rolodex_dns_query_duration_seconds_count{proto=\"udp\"} 0")
        );
    }

    #[test]
    fn observe_query_updates_every_dimension() {
        let m = Metrics::new();
        m.observe_query(QueryObservation {
            proto: Proto::Tcp,
            rcode_index: rcode_index(ResponseCode::NXDomain),
            qtype_index: qtype_index(RecordType::AAAA),
            source: AnswerSource::AuthoritativeNxdomain,
            query_bytes: 40,
            response_bytes: 90,
            truncated: true,
            elapsed: Duration::from_micros(600),
        });
        let out = m.render();
        assert!(out.contains("rolodex_dns_queries_total{proto=\"tcp\",rcode=\"NXDOMAIN\"} 1"));
        assert!(out.contains("rolodex_dns_queries_by_type_total{qtype=\"AAAA\"} 1"));
        assert!(out.contains("rolodex_dns_answers_total{source=\"authoritative_nxdomain\"} 1"));
        assert!(out.contains("rolodex_dns_responses_truncated_total 1"));
        assert!(out.contains("rolodex_dns_query_duration_seconds_count{proto=\"tcp\"} 1"));
        assert_eq!(m.query_size.count(), 1);
    }

    #[test]
    fn every_metric_declares_help_and_type() {
        // Guards against adding a series to `render` without its metadata: each
        // distinct metric family name must be preceded by a HELP and a TYPE.
        let out = Metrics::new().render();
        let mut declared = std::collections::HashSet::new();
        for line in out.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                if let Some(name) = rest.split(' ').next() {
                    declared.insert(name.to_string());
                }
                continue;
            }
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let name = line
                .split(['{', ' '])
                .next()
                .unwrap_or_default()
                .to_string();
            // Histogram and summary series carry generated suffixes.
            let family = ["_bucket", "_sum", "_count"]
                .iter()
                .find_map(|s| name.strip_suffix(s))
                .unwrap_or(&name)
                .to_string();
            assert!(
                declared.contains(&family) || declared.contains(&name),
                "series {name} has no # TYPE declaration"
            );
        }
        assert!(!declared.is_empty());
    }

    #[test]
    fn rcode_and_qtype_fold_unknowns() {
        assert_eq!(RCODES[rcode_index(ResponseCode::NoError)], "NOERROR");
        assert_eq!(RCODES[rcode_index(ResponseCode::Refused)], "REFUSED");
        assert_eq!(RCODES[rcode_index(ResponseCode::BADVERS)], "OTHER");
        assert_eq!(RCODES[rcode_index_from_wire(0)], "NOERROR");
        assert_eq!(RCODES[rcode_index_from_wire(3)], "NXDOMAIN");
        assert_eq!(RCODES[rcode_index_from_wire(9)], "OTHER");
        assert_eq!(QTYPES[qtype_index(RecordType::A)], "A");
        assert_eq!(QTYPES[qtype_index(RecordType::HINFO)], "OTHER");
    }

    #[test]
    fn label_values_are_escaped() {
        let mut out = String::new();
        write_sample(&mut out, "m", &[("l", "a\"b\\c\nd")], 1);
        assert_eq!(out, "m{l=\"a\\\"b\\\\c\\nd\"} 1\n");
    }

    #[test]
    fn floats_avoid_scientific_notation() {
        assert_eq!(format_float(0.0001), "0.0001");
        assert_eq!(format_float(0.00005), "0.00005");
        assert_eq!(format_float(1.0), "1");
        assert_eq!(format_float(65535.0), "65535");
        assert_eq!(format_float(12.5), "12.5");
    }

    #[test]
    fn render_includes_build_info_and_uptime() {
        let out = Metrics::new().render();
        assert!(out.contains(&format!(
            "rolodex_dns_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(out.contains("rolodex_dns_uptime_seconds "));
        assert!(out.contains("rolodex_dns_start_time_seconds "));
    }
}
