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
}
