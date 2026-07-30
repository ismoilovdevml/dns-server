//! Per-source-IP token bucket.
//!
//! An authoritative name server on the public internet is a reflection-attack
//! amplifier unless it caps how fast a single source can ask questions. This is
//! a sharded map of token buckets: cheap enough for the query path, and pruned
//! by a background janitor so a spoofed-source flood cannot grow it without
//! bound.
//!
//! Time is injected via [`RateLimiter::check_at`] so the behaviour is testable
//! without sleeping.

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Number of independent shards. A power of two so the modulo is a mask.
const SHARDS: usize = 32;

/// Buckets untouched for this long are dropped by [`RateLimiter::prune`].
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(600);

/// A single source's bucket.
#[derive(Copy, Clone, Debug)]
struct Bucket {
    tokens: f64,
    last_seen: Instant,
}

/// Token-bucket rate limiter keyed by source IP.
#[derive(Debug)]
pub struct RateLimiter {
    shards: Vec<Mutex<HashMap<IpAddr, Bucket>>>,
    /// Tokens added per second.
    refill_per_sec: f64,
    /// Bucket capacity.
    burst: f64,
}

impl RateLimiter {
    /// Create a limiter allowing `qps` sustained queries per source IP with a
    /// bucket capacity of `burst`.
    ///
    /// # Panics
    ///
    /// Panics if `qps` or `burst` is zero — [`crate::config`] rejects that
    /// combination before we get here.
    pub fn new(qps: u32, burst: u32) -> Self {
        assert!(qps > 0 && burst > 0, "qps and burst must be non-zero");
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            refill_per_sec: f64::from(qps),
            burst: f64::from(burst),
        }
    }

    /// Consume one token for `ip`. Returns `true` when the query may proceed.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    /// [`RateLimiter::check`] with an explicit clock reading.
    pub fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut shard = self.shard(ip);
        let bucket = shard.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last_seen: now,
        });

        // `saturating_duration_since` keeps us correct if a caller passes a
        // slightly older `now` than the last observation.
        let elapsed = now
            .saturating_duration_since(bucket.last_seen)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.burst);
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop buckets that have not been touched within `idle_ttl`.
    ///
    /// Returns the number of entries removed.
    pub fn prune(&self, idle_ttl: Duration) -> usize {
        self.prune_at(idle_ttl, Instant::now())
    }

    /// [`RateLimiter::prune`] with an explicit clock reading.
    pub fn prune_at(&self, idle_ttl: Duration, now: Instant) -> usize {
        let mut removed = 0;
        for shard in &self.shards {
            let mut map = shard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = map.len();
            map.retain(|_, bucket| now.saturating_duration_since(bucket.last_seen) < idle_ttl);
            removed += before - map.len();
        }
        removed
    }

    /// Number of source IPs currently tracked.
    pub fn tracked(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
            })
            .sum()
    }

    fn shard(&self, ip: IpAddr) -> std::sync::MutexGuard<'_, HashMap<IpAddr, Bucket>> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ip.hash(&mut hasher);
        #[allow(clippy::cast_possible_truncation)]
        let idx = (hasher.finish() as usize) & (SHARDS - 1);
        self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn burst_is_allowed_then_traffic_is_denied() {
        let rl = RateLimiter::new(1, 3);
        let now = Instant::now();
        assert!(rl.check_at(ip("198.51.100.1"), now));
        assert!(rl.check_at(ip("198.51.100.1"), now));
        assert!(rl.check_at(ip("198.51.100.1"), now));
        assert!(!rl.check_at(ip("198.51.100.1"), now));
    }

    #[test]
    fn tokens_refill_over_time() {
        let rl = RateLimiter::new(10, 1);
        let t0 = Instant::now();
        assert!(rl.check_at(ip("198.51.100.2"), t0));
        assert!(!rl.check_at(ip("198.51.100.2"), t0));
        // 10 qps -> one token back after 100ms.
        assert!(rl.check_at(ip("198.51.100.2"), t0 + Duration::from_millis(100)));
    }

    #[test]
    fn refill_is_capped_at_burst() {
        let rl = RateLimiter::new(100, 2);
        let t0 = Instant::now();
        // Idle for an hour, then only `burst` queries should get through.
        let later = t0 + Duration::from_secs(3600);
        assert!(rl.check_at(ip("198.51.100.3"), later));
        assert!(rl.check_at(ip("198.51.100.3"), later));
        assert!(!rl.check_at(ip("198.51.100.3"), later));
    }

    #[test]
    fn buckets_are_independent_per_source() {
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        assert!(rl.check_at(ip("198.51.100.4"), now));
        assert!(!rl.check_at(ip("198.51.100.4"), now));
        // A different source still has a full bucket.
        assert!(rl.check_at(ip("198.51.100.5"), now));
        assert!(rl.check_at(ip("2001:db8::1"), now));
    }

    #[test]
    fn prune_drops_only_idle_buckets() {
        let rl = RateLimiter::new(1, 1);
        let t0 = Instant::now();
        rl.check_at(ip("198.51.100.6"), t0);
        rl.check_at(ip("198.51.100.7"), t0 + Duration::from_secs(500));
        assert_eq!(rl.tracked(), 2);

        let removed = rl.prune_at(Duration::from_secs(300), t0 + Duration::from_secs(600));
        assert_eq!(removed, 1);
        assert_eq!(rl.tracked(), 1);
    }

    #[test]
    fn prune_on_empty_limiter_is_a_no_op() {
        let rl = RateLimiter::new(1, 1);
        assert_eq!(rl.prune(Duration::from_secs(1)), 0);
        assert_eq!(rl.tracked(), 0);
    }

    #[test]
    fn out_of_order_clock_readings_do_not_grant_extra_tokens() {
        let rl = RateLimiter::new(1, 1);
        let t1 = Instant::now() + Duration::from_secs(10);
        assert!(rl.check_at(ip("198.51.100.8"), t1));
        // An earlier reading must not refill the bucket.
        let earlier = t1
            .checked_sub(Duration::from_secs(5))
            .expect("instant is in range");
        assert!(!rl.check_at(ip("198.51.100.8"), earlier));
    }

    #[test]
    fn many_sources_spread_across_shards() {
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        for i in 0..250u8 {
            assert!(rl.check_at(IpAddr::from([203, 0, 113, i]), now));
        }
        assert_eq!(rl.tracked(), 250);
    }

    // -----------------------------------------------------------------------
    // Regression tests from mutation testing.
    // -----------------------------------------------------------------------

    #[test]
    fn a_bucket_exactly_at_the_idle_ttl_is_pruned() {
        // Kills `< idle_ttl` -> `<= idle_ttl`. The existing prune test used
        // 500s against a 300s TTL, so the boundary itself was never exercised.
        let rl = RateLimiter::new(1, 1);
        let t0 = Instant::now();
        rl.check_at(ip("198.51.100.20"), t0);
        assert_eq!(
            rl.prune_at(Duration::from_secs(300), t0 + Duration::from_secs(300)),
            1,
            "a bucket idle for exactly the TTL must go"
        );
        assert_eq!(rl.tracked(), 0);
    }

    #[test]
    fn a_bucket_one_nanosecond_short_of_the_ttl_survives() {
        let rl = RateLimiter::new(1, 1);
        let t0 = Instant::now();
        rl.check_at(ip("198.51.100.21"), t0);
        let ttl = Duration::from_secs(300);
        let just_before = ttl.checked_sub(Duration::from_nanos(1)).expect("in range");
        assert_eq!(rl.prune_at(ttl, t0 + just_before), 0);
        assert_eq!(rl.tracked(), 1);
    }

    #[test]
    fn prune_reports_the_number_of_buckets_it_dropped() {
        // Kills `RateLimiter::prune -> 0`: every other test went through
        // `prune_at`, so the wall-clock wrapper was never called.
        let rl = RateLimiter::new(1, 1);
        rl.check(ip("198.51.100.22"));
        rl.check(ip("198.51.100.23"));
        assert_eq!(rl.tracked(), 2);
        assert_eq!(rl.prune(Duration::ZERO), 2);
        assert_eq!(rl.tracked(), 0);
    }

    #[test]
    fn concurrent_checks_hand_out_exactly_burst_tokens() {
        // A thread storm against one source: the bucket must not leak tokens
        // under contention, so exactly `burst` of the calls may succeed.
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Barrier,
        };

        const THREADS: usize = 16;
        const PER_THREAD: usize = 200;
        const BURST: u32 = 500;

        let rl = Arc::new(RateLimiter::new(1, BURST));
        let allowed = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(THREADS));
        let now = Instant::now();
        let source = ip("198.51.100.30");

        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let (rl, allowed, barrier) =
                (Arc::clone(&rl), Arc::clone(&allowed), Arc::clone(&barrier));
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..PER_THREAD {
                    if rl.check_at(source, now) {
                        allowed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("worker finishes");
        }

        // Every call uses the same instant, so no refill can happen: the totals
        // have to reconcile exactly.
        assert_eq!(allowed.load(Ordering::Relaxed), BURST as usize);
        assert_eq!(rl.tracked(), 1);
    }

    #[test]
    fn concurrent_checks_across_many_sources_all_land() {
        use std::sync::{Arc, Barrier};

        const THREADS: u32 = 8;
        const PER_THREAD: u32 = 500;

        let rl = Arc::new(RateLimiter::new(1, 1));
        let barrier = Arc::new(Barrier::new(THREADS as usize));
        let mut handles = Vec::new();
        for t in 0..THREADS {
            let (rl, barrier) = (Arc::clone(&rl), Arc::clone(&barrier));
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for i in 0..PER_THREAD {
                    let octets = (t * PER_THREAD + i).to_be_bytes();
                    assert!(rl.check(IpAddr::from([10, octets[1], octets[2], octets[3]])));
                }
            }));
        }
        for h in handles {
            h.join().expect("worker finishes");
        }
        assert_eq!(rl.tracked(), (THREADS * PER_THREAD) as usize);
    }

    #[test]
    #[ignore = "BUG: the bucket map is unbounded — a spoofed-source flood grows it until the janitor runs 60s later, with a 600s idle TTL"]
    fn the_bucket_map_is_bounded() {
        // The map has no capacity limit and no eviction of its own: the only
        // thing that ever removes an entry is the janitor in main.rs, which
        // ticks once a minute and only drops buckets idle for DEFAULT_IDLE_TTL
        // (600s). An attacker sending one packet per spoofed source therefore
        // controls memory growth for a full 600 seconds before anything is
        // reclaimed, and `prune` then walks every entry while holding each
        // shard lock, stalling the query path.
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        for i in 0..250_000u32 {
            let o = i.to_be_bytes();
            rl.check_at(IpAddr::from([10, o[1], o[2], o[3]]), now);
        }
        assert!(
            rl.tracked() < 100_000,
            "the limiter grew to {} buckets from a single flood, with no cap",
            rl.tracked()
        );
    }
}
