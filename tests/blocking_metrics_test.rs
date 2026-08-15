//! Blocking-region instrumentation: `rolodex_dns_blocking_duration_seconds` and
//! `rolodex_dns_blocking_stalls_total`.
//!
//! The server is `async` throughout, but several things it has to do are not:
//! SQLite sits behind a single `std::sync::Mutex<Connection>`, certificate files
//! are read off disk, signatures are arithmetic. Each occupies the thread it
//! runs on, and on a Tokio worker that is a thread not polling anything else.
//! These two families exist to make that visible; this file exists to make sure
//! they actually see it.
//!
//! **An assertion without its control proves nothing.** A timer wired to fire on
//! every call satisfies "the database path is instrumented"; one wired to fire
//! on none satisfies "the cache path allocates no samples". So each test here
//! comes in a pair: a path that must be counted next to a path that must not,
//! measured across the same interval.
//!
//! Two of the tests deliberately avoid the process-wide registry. The threshold
//! rule and the exposition format are checked against a private `Metrics`,
//! because every other test in this binary writes to the global one and an
//! absolute-value assertion against it is a race. The database test does use the
//! global — a `Database` has no way to be handed a registry — so it asserts on
//! deltas, and it is the only test in this file that touches SQLite at all,
//! which is what makes those deltas attributable.

use std::time::Duration;

use rolodex_dns::db::{Database, DnsRecord, RecordKind};
use rolodex_dns::metrics::{
    BLOCK_SITE_CONFIG_LOAD, BLOCK_SITE_DB_LOCK_WAIT, BLOCK_SITE_DB_LOCKED, BLOCK_SITE_DB_OPEN,
    BLOCK_SITE_DNSSEC_SIGN, BLOCK_SITE_DNSSEC_VERIFY, BLOCK_SITE_METRICS_COLLECT,
    BLOCK_SITE_TLS_RELOAD, BLOCKING_SITES, BLOCKING_STALL_NANOS, Metrics, metrics, time_blocking,
};

/// The `BLOCK_SITE_*` constants are positions in a pre-allocated array, exactly
/// like the `BLOCK_*` blocklist constants. Inserting a value rather than
/// appending one silently relabels every sample already recorded against the
/// sites after it — a Prometheus series that changes meaning mid-history without
/// changing name, which is worse than losing it.
///
/// Pinning name-to-index here is what turns that from a review comment into a
/// failing test.
#[test]
fn site_indices_are_fixed_positions() {
    assert_eq!(BLOCKING_SITES[BLOCK_SITE_DB_LOCK_WAIT], "db_lock_wait");
    assert_eq!(BLOCKING_SITES[BLOCK_SITE_DB_LOCKED], "db_locked");
    assert_eq!(BLOCKING_SITES[BLOCK_SITE_DB_OPEN], "db_open");
    assert_eq!(
        BLOCKING_SITES[BLOCK_SITE_METRICS_COLLECT],
        "metrics_collect"
    );
    assert_eq!(BLOCKING_SITES[BLOCK_SITE_TLS_RELOAD], "tls_reload");
    assert_eq!(BLOCKING_SITES[BLOCK_SITE_DNSSEC_SIGN], "dnssec_sign");
    assert_eq!(BLOCKING_SITES[BLOCK_SITE_DNSSEC_VERIFY], "dnssec_verify");
    assert_eq!(BLOCKING_SITES[BLOCK_SITE_CONFIG_LOAD], "config_load");

    // And nothing beyond them: a site added without a constant is a series
    // nobody can record against, which is the mirror of the insertion bug.
    assert_eq!(
        BLOCKING_SITES.len(),
        8,
        "a site was added without pinning its index here: {BLOCKING_SITES:?}"
    );
}

/// The histogram takes every observation; the counter takes only the ones at or
/// above the threshold. Both halves are asserted, because a counter that
/// incremented on everything and a counter that incremented on nothing each pass
/// half of this on their own.
///
/// The boundary is checked from both sides — one nanosecond under, and exactly
/// on — since `>=` and `>` differ by precisely the case an alert written against
/// a 10ms bucket boundary would hit.
#[test]
fn the_stall_counter_fires_only_at_the_threshold() {
    let m = Metrics::new();
    let site = BLOCK_SITE_DNSSEC_VERIFY;

    m.observe_blocking(site, Duration::from_nanos(BLOCKING_STALL_NANOS - 1));
    assert_eq!(
        m.blocking_duration.count(site),
        1,
        "a fast region is still an observation"
    );
    assert_eq!(
        m.blocking_stalls.get(site),
        0,
        "one nanosecond under the threshold is not a stall"
    );

    m.observe_blocking(site, Duration::from_nanos(BLOCKING_STALL_NANOS));
    assert_eq!(m.blocking_duration.count(site), 2);
    assert_eq!(
        m.blocking_stalls.get(site),
        1,
        "exactly at the threshold is a stall: the rule is >=, not >"
    );

    m.observe_blocking(site, Duration::from_secs(1));
    assert_eq!(m.blocking_duration.count(site), 3);
    assert_eq!(m.blocking_stalls.get(site), 2);

    // The sum is in nanoseconds internally and divided by 1e9 at render time.
    // Checked against arithmetic done here rather than against the renderer's
    // own output, so this is not the encoder compared with itself.
    assert_eq!(
        m.blocking_duration.sum(site),
        (BLOCKING_STALL_NANOS - 1) + BLOCKING_STALL_NANOS + 1_000_000_000
    );

    // The control on the *label* dimension: an observation against one site must
    // not land on any other. A `HistogramVec` indexed row-major is exactly the
    // shape that gets this wrong by one row.
    for (i, name) in BLOCKING_SITES.iter().enumerate() {
        if i == site {
            continue;
        }
        assert_eq!(
            m.blocking_duration.count(i),
            0,
            "site `{name}` picked up an observation meant for dnssec_verify"
        );
        assert_eq!(m.blocking_stalls.get(i), 0, "site `{name}` counted a stall");
    }
}

/// `time_blocking` must measure the closure whether it returns or fails. A timer
/// that only records the success path hides the 200ms lookup that then errored,
/// which is the sample worth having.
///
/// This one uses the global registry — `time_blocking` is a free function over
/// it — so it asserts deltas rather than absolutes, and picks `config_load`,
/// a boot-only site nothing else in this binary touches.
#[test]
fn time_blocking_measures_the_error_path_too() {
    let site = BLOCK_SITE_CONFIG_LOAD;
    let before = metrics().blocking_duration.count(site);

    let ok: Result<u32, &str> = time_blocking(site, || Ok(7));
    assert_eq!(ok, Ok(7), "the closure's value is passed through unchanged");

    let failed: Result<u32, &str> = time_blocking(site, || Err("no config file"));
    assert_eq!(failed, Err("no config file"));

    assert_eq!(
        metrics().blocking_duration.count(site) - before,
        2,
        "both the returning and the erroring closure must be observed"
    );
}

/// Every site must appear in the exposition output with both `_bucket`/`_sum`/
/// `_count` and a `_total` counter, at zero, before anything has been recorded.
///
/// A Prometheus histogram that only materialises its label values once they are
/// non-zero makes `rate()` over a newly restarted process silently empty, and
/// makes "we have never blocked here" indistinguishable from "this site does not
/// exist".
#[test]
fn every_site_is_exported_before_it_is_ever_used() {
    let out = Metrics::new().render();

    assert!(
        out.contains("# TYPE rolodex_dns_blocking_duration_seconds histogram"),
        "the duration family is missing from the exposition output"
    );
    assert!(
        out.contains("# TYPE rolodex_dns_blocking_stalls_total counter"),
        "the stall family is missing from the exposition output"
    );

    for site in BLOCKING_SITES {
        assert!(
            out.contains(&format!(
                "rolodex_dns_blocking_duration_seconds_count{{site=\"{site}\"}} 0"
            )),
            "site `{site}` has no zero-valued duration count in:\n{out}"
        );
        assert!(
            out.contains(&format!(
                "rolodex_dns_blocking_stalls_total{{site=\"{site}\"}} 0"
            )),
            "site `{site}` has no zero-valued stall counter in:\n{out}"
        );
    }

    // Buckets are rendered in the cumulative `le` form, and the smallest bound
    // has to be far below a query's floor or `db_lock_wait` has nowhere to move
    // from: an uncontended mutex acquisition is tens of nanoseconds, and a first
    // bucket that already holds every healthy sample cannot show it stop being
    // healthy. Written out longhand rather than derived from the bounds array.
    assert!(
        out.contains(
            "rolodex_dns_blocking_duration_seconds_bucket{site=\"db_lock_wait\",le=\"0.0000001\"} 0"
        ),
        "the 100ns bucket is missing or misscaled in:\n{out}"
    );
    assert!(
        out.contains(
            "rolodex_dns_blocking_duration_seconds_bucket{site=\"db_lock_wait\",le=\"0.01\"} 0"
        ),
        "the 10ms bucket — BLOCKING_STALL_NANOS — has no bound of its own in:\n{out}"
    );
    assert!(
        out.contains(
            "rolodex_dns_blocking_duration_seconds_bucket{site=\"db_lock_wait\",le=\"+Inf\"} 0"
        ),
        "the overflow bucket is missing in:\n{out}"
    );
}

/// The database instrumentation, driven through the real `Database` rather than
/// by calling the metrics helpers directly: the point is that `Database::lock`
/// is the choke point, so a method added later is measured without anyone
/// remembering to measure it.
///
/// The control is the other half of the same object. `Database` serves several
/// hot-path reads out of in-memory `DashMap`s and never touches SQLite for them;
/// those must record nothing, or the series would report contention that is not
/// happening and an operator would go looking for a lock that was never taken.
///
/// Deltas, not absolutes: the registry is process-wide. `Database::open_memory`
/// is used rather than `open`, so this leaves nothing on the host — the file
/// under test is the instrumentation, not SQLite.
#[test]
fn the_database_lock_is_measured_and_the_cache_path_is_not() {
    let db = Database::open_memory().expect("in-memory database");

    // Everything above happened before the baseline is taken, so table creation
    // is not what is being counted here.
    let locked_before = metrics().blocking_duration.count(BLOCK_SITE_DB_LOCKED);
    let waited_before = metrics().blocking_duration.count(BLOCK_SITE_DB_LOCK_WAIT);

    // A real statement, through a real method, in both directions.
    db.add_record(&DnsRecord {
        id: None,
        name: "timed.example.com.".to_string(),
        record_type: RecordKind::A,
        value: "10.0.0.1".to_string(),
        ttl: 300,
        priority: 0,
    })
    .expect("insert");
    let found = db
        .lookup("timed.example.com.", Some(RecordKind::A))
        .expect("lookup succeeds");
    assert_eq!(found.len(), 1, "the record is actually there");

    let locked_after = metrics().blocking_duration.count(BLOCK_SITE_DB_LOCKED);
    let waited_after = metrics().blocking_duration.count(BLOCK_SITE_DB_LOCK_WAIT);

    assert!(
        locked_after > locked_before,
        "SQLite work through Database::lock recorded no held time \
         ({locked_before} -> {locked_after})"
    );
    assert_eq!(
        waited_after - waited_before,
        locked_after - locked_before,
        "every acquisition must record both a wait and a hold: they are taken \
         from the same choke point and one without the other means a path is \
         bypassing it"
    );

    // The control: a lookup served entirely from the in-memory association cache
    // takes no lock, so neither series may move. If this ever starts failing,
    // the cache stopped being a cache — which is itself worth knowing.
    let locked_baseline = metrics().blocking_duration.count(BLOCK_SITE_DB_LOCKED);
    let waited_baseline = metrics().blocking_duration.count(BLOCK_SITE_DB_LOCK_WAIT);

    assert_eq!(
        db.get_scope_for_ip("192.0.2.1"),
        None,
        "no association was registered, so this is a pure cache miss"
    );

    assert_eq!(
        metrics().blocking_duration.count(BLOCK_SITE_DB_LOCKED),
        locked_baseline,
        "a cache-served read recorded held time it never held"
    );
    assert_eq!(
        metrics().blocking_duration.count(BLOCK_SITE_DB_LOCK_WAIT),
        waited_baseline,
        "a cache-served read recorded a wait it never waited"
    );
}

/// `Database::open` is timed as a whole, and it is the one site whose cost is
/// paid in startup latency rather than query latency. It runs once per process,
/// so this asserts it ran once — and, as the control, that opening a *second*
/// database records a second observation rather than the timer being armed only
/// on some first-call path.
#[test]
fn opening_a_database_is_measured_each_time() {
    let before = metrics().blocking_duration.count(BLOCK_SITE_DB_OPEN);

    let dir = tempfile::tempdir().expect("tempdir");
    let first = dir.path().join("first.db");
    let second = dir.path().join("second.db");

    Database::open(&first).expect("first open");
    let after_one = metrics().blocking_duration.count(BLOCK_SITE_DB_OPEN);
    assert_eq!(after_one - before, 1, "the first open was not measured");

    Database::open(&second).expect("second open");
    assert_eq!(
        metrics().blocking_duration.count(BLOCK_SITE_DB_OPEN) - after_one,
        1,
        "the second open was not measured"
    );

    // Boot-time opens load every cached table, so this is never free; a sum of
    // zero nanoseconds would mean the timer is being read before the work.
    assert!(
        metrics().blocking_duration.sum(BLOCK_SITE_DB_OPEN) > 0,
        "db_open recorded observations with no elapsed time at all"
    );
}
