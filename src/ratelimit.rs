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
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The `.1` host inside the `i`th /24, so `i` doubles as the prefix index.
    fn v4_prefix(i: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from((i << 8) | 1))
    }

    /// The `::1` host inside the `i`th /56, so `i` doubles as the prefix index.
    fn v6_prefix(i: u64) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from((u128::from(i) << 72) | 1))
    }

    /// Drain one prefix's bucket. At `burst == 1` a single call is enough: the
    /// slot ends up empty whether this call consumed the token or a colliding
    /// prefix had already taken it.
    fn drain(rl: &RateLimiter, prefix: IpAddr, now: Instant) {
        let _ = rl.check_at(prefix, now);
    }

    /// Resident set size of this process in KiB.
    ///
    /// The whole of VEGA-003 is a claim about memory, so a platform where this
    /// cannot be measured must fail loudly rather than quietly skip the test.
    fn resident_kib() -> u64 {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    if let Some(Ok(kib)) = rest.split_whitespace().next().map(str::parse) {
                        return kib;
                    }
                }
            }
        }
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .expect("measuring RSS needs /proc/self/status or `ps`; VEGA-003 is a memory bound and this test must not silently pass");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("`ps -o rss=` printed something that is not a number of KiB")
    }

    /// Deterministic xorshift64. A dependency-free stand-in for `rand`, seeded
    /// per test so a failure reproduces exactly.
    struct Xorshift(u64);

    impl Xorshift {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    // -----------------------------------------------------------------------
    // Bucket semantics
    // -----------------------------------------------------------------------

    /// Scenario: A full burst is allowed before any traffic is denied
    /// features/rate-limiting.feature:177
    #[test]
    fn burst_is_allowed_then_traffic_is_denied() {
        let rl = RateLimiter::new(1, 3);
        let now = Instant::now();
        assert!(rl.check_at(ip("198.51.100.1"), now));
        assert!(rl.check_at(ip("198.51.100.1"), now));
        assert!(rl.check_at(ip("198.51.100.1"), now));
        assert!(!rl.check_at(ip("198.51.100.1"), now));
    }

    /// Scenario: Tokens are restored as time passes
    /// features/rate-limiting.feature:184
    #[test]
    fn tokens_refill_over_time() {
        let rl = RateLimiter::new(10, 1);
        let t0 = Instant::now();
        assert!(rl.check_at(ip("198.51.100.2"), t0));
        assert!(!rl.check_at(ip("198.51.100.2"), t0));
        // 10 qps -> one token back after 100ms.
        assert!(rl.check_at(ip("198.51.100.2"), t0 + Duration::from_millis(100)));
    }

    /// Scenario: Refill is capped at the burst size no matter how long the source was idle
    /// features/rate-limiting.feature:191
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

    /// Scenario: A clock reading that moves backwards does not grant extra tokens
    /// features/rate-limiting.feature:218
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

    // -----------------------------------------------------------------------
    // The key: IPv4 /24, IPv6 /56, IPv4-mapped folded first (ruling §2)
    // -----------------------------------------------------------------------

    /// Scenario: Two addresses in the same /24 share one bucket
    /// features/rate-limiting.feature:46
    ///
    /// SUPERSEDES `buckets_are_independent_per_source`, which asserted exactly
    /// the opposite. Authorised by ruling §13 A1: per-address buckets are the
    /// defect, not the contract — they are what an attacker mints memory with,
    /// and what lets an IPv6 /64 walk past the limiter untouched.
    #[test]
    fn two_addresses_in_one_slash_24_share_a_bucket() {
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        assert!(rl.check_at(ip("198.51.100.1"), now));
        assert!(
            !rl.check_at(ip("198.51.100.2"), now),
            "198.51.100.2 is in the same /24 as the address that just spent the \
             token; keying on the full address is what makes the map unbounded"
        );
    }

    /// Scenario: Two addresses in different /24s do not share a bucket
    /// features/rate-limiting.feature:55
    #[test]
    fn two_addresses_in_different_slash_24s_keep_separate_buckets() {
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        assert!(rl.check_at(ip("198.51.100.1"), now));
        assert!(
            rl.check_at(ip("198.51.101.1"), now),
            "a /24 away is a different network and must not be collateral"
        );
    }

    /// Scenario: The first and last address of a /24 share one bucket
    /// features/rate-limiting.feature:61
    #[test]
    fn the_first_and_last_address_of_a_slash_24_share_a_bucket() {
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        assert!(rl.check_at(ip("203.0.113.0"), now));
        assert!(!rl.check_at(ip("203.0.113.255"), now));
    }

    /// Scenario: Addresses one apart across a /24 boundary do not share
    /// features/rate-limiting.feature:67
    ///
    /// The other side of the same boundary. A mask of /23 or /16 — an off-by-one
    /// in the shift — passes the test above and fails this one.
    #[test]
    fn addresses_either_side_of_a_slash_24_boundary_do_not_share() {
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        assert!(rl.check_at(ip("203.0.113.255"), now));
        assert!(rl.check_at(ip("203.0.114.0"), now));
    }

    /// Scenario: Two addresses in the same /56 share one bucket
    /// features/rate-limiting.feature:73
    #[test]
    fn two_addresses_in_one_slash_56_share_a_bucket() {
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        assert!(rl.check_at(ip("2001:db8:0:0::1"), now));
        assert!(
            !rl.check_at(ip("2001:db8:0:00ff:ffff:ffff:ffff:ffff"), now),
            "byte 8 differs, which is inside the /56"
        );
    }

    /// Scenario: Addresses across a /56 boundary do not share
    /// features/rate-limiting.feature:80
    #[test]
    fn addresses_either_side_of_a_slash_56_boundary_do_not_share() {
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        assert!(rl.check_at(ip("2001:db8:0:0000::1"), now));
        assert!(
            rl.check_at(ip("2001:db8:0:0100::1"), now),
            "byte 7 differs, which is outside the /56: a /48 mask would wrongly \
             collapse these two end sites into one bucket"
        );
    }

    /// Scenario: An IPv4-mapped IPv6 source shares the bucket of its bare IPv4 form
    /// features/rate-limiting.feature:87
    #[test]
    fn an_ipv4_mapped_source_shares_the_bucket_of_its_bare_ipv4_form() {
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        assert!(rl.check_at(ip("198.51.100.1"), now));
        assert!(
            !rl.check_at(ip("::ffff:198.51.100.1"), now),
            "a [::]-bound socket hands us IPv4 peers in mapped form; if the two \
             forms key differently an attacker gets two buckets per address"
        );
    }

    /// Scenario: Two IPv4-mapped sources in different /24s stay in different buckets
    /// features/rate-limiting.feature:96
    ///
    /// THE ASSERTION THAT FAILS WITHOUT `to_ipv4_mapped()`. It passes against
    /// today's per-address key and against a correct fold; it fails against the
    /// obvious wrong implementation of the new design, where `::ffff:a.b.c.d`
    /// reaches the /56 mask unfolded, its top 56 bits are zero for every IPv4
    /// client alive, and the whole IPv4 internet lands in one token bucket.
    /// Ruling §2.4 and failure mode F6; same shape as VEGA-016.
    #[test]
    fn two_ipv4_mapped_sources_in_different_slash_24s_do_not_share() {
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        assert!(rl.check_at(ip("::ffff:198.51.100.1"), now));
        assert!(
            rl.check_at(ip("::ffff:203.0.113.1"), now),
            "unfolded, ::ffff:a.b.c.d has 56 constant leading bits, so masking to \
             /56 puts every IPv4 client on earth in one bucket — a self-inflicted \
             total outage for IPv4 on any server listening on [::]"
        );
    }

    /// Scenario: An IPv6 /56 never aliases the IPv4 /24 with the same payload
    /// features/rate-limiting.feature:106
    ///
    /// The canonical key carries a two-bit family tag (ruling §2.5). Without it
    /// the /24 `k` and the /56 whose 56-bit payload is also `k` are one bucket,
    /// so an IPv6 attacker can deny an unrelated IPv4 network by arithmetic.
    /// The bound is "a handful" rather than zero because two prefixes may also
    /// share a slot by hash collision: 256 probes against ~256 drained slots in
    /// a 2^18-slot table expect 0.25 collisions, so 8 is ~30 standard
    /// deviations out while a missing tag gives all 256.
    #[test]
    fn an_ipv6_prefix_never_aliases_the_ipv4_prefix_with_the_same_payload() {
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        let mut shared = 0;
        for k in 0..256u32 {
            drain(&rl, v4_prefix(k), now);
            if !rl.check_at(v6_prefix(u64::from(k)), now) {
                shared += 1;
            }
        }
        assert!(
            shared <= 8,
            "{shared} of 256 IPv6 /56s shared a bucket with the IPv4 /24 carrying \
             the same payload; the family tag in the canonical key is missing"
        );
    }

    /// Scenario: A flood spread across one /64 is rate-limited as a single source
    /// features/rate-limiting.feature:115
    ///
    /// The issue's headline criterion (ruling §13 A8). 65,536 forged addresses
    /// inside one /64 — the smallest allocation any LAN gets — one query each.
    /// Today every one of them is allowed and every one of them is remembered,
    /// which is the limiter failing to fire and the memory exhaustion at once,
    /// from one attacker holding one prefix. No sockets are opened: this mints
    /// addresses, not connections.
    #[test]
    fn a_flood_across_one_slash_64_is_limited_as_a_single_source() {
        const FLOOD: u128 = 65_536;

        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        let base: u128 = 0x2001_0db8_0000_0000 << 64;
        let mut allowed = 0u32;
        for host in 0..FLOOD {
            if rl.check_at(IpAddr::V6(Ipv6Addr::from(base | host)), now) {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, 1,
            "an attacker inside 2001:db8::/64 must be one bucket, not 65,536; \
             {allowed} of 65,536 queries were allowed"
        );
    }

    // -----------------------------------------------------------------------
    // The bound (ruling §3)
    // -----------------------------------------------------------------------

    /// Scenario: A flood of two million distinct spoofed prefixes does not grow the process
    /// features/rate-limiting.feature:128
    ///
    /// REPLACES the `#[ignore]`d `the_bucket_map_is_bounded`, un-ignored and with
    /// a real bound rather than the placeholder `< 100_000`. This is the issue's
    /// evidence table inverted: 186 bytes per tracked source, 356 MiB at
    /// 2,000,000 sources, OOM under the 128 MiB k8s limit at ~723,000 sources in
    /// 7.2 seconds. The ceiling after the change is a compile-time constant of
    /// 2,097,152 bytes, so 32 MiB is two orders of magnitude of headroom and
    /// still a decisive verdict; it is deliberately loose because the test
    /// harness runs tests in parallel threads and RSS is process-wide. If it
    /// ever proves flaky, the remedy is to move it to its own test binary — not
    /// to raise the ceiling, which is the one number this issue is about.
    #[test]
    fn two_million_spoofed_prefixes_do_not_grow_the_process() {
        const FLOOD: u32 = 2_000_000;
        const CEILING_KIB: u64 = 32 * 1024;

        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        let before = resident_kib();
        let mut allowed = 0u32;
        for i in 0..FLOOD {
            if rl.check_at(v4_prefix(i), now) {
                allowed += 1;
            }
        }
        let growth = resident_kib().saturating_sub(before);

        assert!(
            growth < CEILING_KIB,
            "{FLOOD} spoofed prefixes grew the process by {growth} KiB; the \
             limiter's memory must be a constant, not a function of how many \
             source addresses an attacker chooses to forge"
        );
        // Frozen clock, burst of one: at most one query per slot can be allowed,
        // so a table of 2^18 slots caps this far below the flood size. The bound
        // is loose on purpose — it must not break when SLOTS is retuned — but
        // 2,000,000 allowed means every forged source still got its own bucket.
        assert!(
            allowed <= 300_000,
            "{allowed} of {FLOOD} spoofed queries were allowed; a fixed table \
             cannot admit more than one per slot at a frozen instant"
        );
    }

    /// Scenario: Random addresses of either family never index outside the table
    /// features/rate-limiting.feature:159
    ///
    /// The index is `hash & (SLOTS - 1)` over a power-of-two table. A mutant that
    /// uses `%` against a non-power-of-two, drops the mask, or truncates the hash
    /// to the wrong width panics here on an out-of-bounds slot rather than
    /// quietly reading somebody else's bucket. Pseudo-random rather than
    /// exhaustive so the failure reproduces from the seed.
    #[test]
    fn random_addresses_of_both_families_never_index_outside_the_table() {
        const CASES: u32 = 1_000_000;

        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        let mut rng = Xorshift(0x5DEE_CE66_D5DE_ECE6);
        for _ in 0..CASES {
            let a = rng.next_u64();
            let b = rng.next_u64();
            let addr = if a & 1 == 0 {
                #[allow(clippy::cast_possible_truncation)]
                IpAddr::V4(Ipv4Addr::from(a as u32))
            } else {
                IpAddr::V6(Ipv6Addr::from((u128::from(a) << 64) | u128::from(b)))
            };
            let _ = rl.check_at(addr, now);
        }
    }

    /// Scenario: A mixed IPv4 and IPv6 flood stays bounded and does not alias
    /// features/rate-limiting.feature:168
    #[test]
    fn a_mixed_family_flood_stays_bounded() {
        const PER_FAMILY: u32 = 500_000;
        const CEILING_KIB: u64 = 32 * 1024;

        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        let before = resident_kib();
        let mut allowed = 0u32;
        for i in 0..PER_FAMILY {
            if rl.check_at(v4_prefix(i), now) {
                allowed += 1;
            }
            if rl.check_at(v6_prefix(u64::from(i)), now) {
                allowed += 1;
            }
        }
        let growth = resident_kib().saturating_sub(before);

        assert!(
            growth < CEILING_KIB,
            "a mixed-family flood grew the process by {growth} KiB; memory must \
             not depend on the address family an attacker picks"
        );
        assert!(
            allowed <= 300_000,
            "{allowed} of 1,000,000 mixed-family queries were allowed"
        );
    }

    // -----------------------------------------------------------------------
    // Bucket semantics under the new encoding (ruling §13 C)
    // -----------------------------------------------------------------------

    /// Scenario: A partial refill below one token does not admit a query
    /// features/rate-limiting.feature:198
    ///
    /// Was `@gap`. Half a token must not round up to an admission; the
    /// milli-token integer arithmetic makes it exact where the old f64 made it a
    /// rounding question.
    #[test]
    fn a_partial_refill_below_one_token_does_not_admit_a_query() {
        let rl = RateLimiter::new(1, 1);
        let t0 = Instant::now();
        assert!(rl.check_at(ip("198.51.100.9"), t0));
        assert!(!rl.check_at(ip("198.51.100.9"), t0 + Duration::from_millis(500)));
    }

    /// Scenario: Exactly one token's worth of elapsed time admits exactly one query
    /// features/rate-limiting.feature:208
    ///
    /// The far side of the same boundary, and the one that catches a refill that
    /// is a factor of 1000 out: 999 ms denies, 1000 ms admits exactly one.
    #[test]
    fn exactly_one_token_of_elapsed_time_admits_exactly_one_query() {
        let rl = RateLimiter::new(1, 1);
        let t0 = Instant::now();
        assert!(rl.check_at(ip("198.51.100.10"), t0));
        assert!(!rl.check_at(ip("198.51.100.10"), t0 + Duration::from_millis(999)));
        // from_secs(1) is exactly the 1000 ms that buys one token at 1 qps.
        assert!(rl.check_at(ip("198.51.100.10"), t0 + Duration::from_secs(1)));
        assert!(!rl.check_at(ip("198.51.100.10"), t0 + Duration::from_secs(1)));
    }

    /// Scenario: An untouched slot means a full bucket, not an empty one
    /// features/rate-limiting.feature:227
    ///
    /// Pins the deficit encoding (ruling §3.2). The table is one calloc, so the
    /// all-zero word has to mean "full bucket, never touched"; storing tokens
    /// instead would make it mean "empty at time zero" and every untouched slot
    /// would deny for the first burst/qps seconds of process life — a
    /// self-inflicted outage at every restart and every zone reload.
    ///
    /// The clock reading is taken BEFORE the limiter exists, so it cannot be
    /// later than the limiter's epoch and the elapsed time is exactly zero. No
    /// refill can paper over the encoding.
    #[test]
    fn a_never_touched_slot_starts_full_rather_than_empty() {
        let at_or_before_epoch = Instant::now();
        let rl = RateLimiter::new(1, 5);
        for i in 0..5 {
            assert!(
                rl.check_at(ip("198.51.100.11"), at_or_before_epoch),
                "query {i} of a fresh limiter's burst was denied at its own epoch"
            );
        }
        assert!(!rl.check_at(ip("198.51.100.11"), at_or_before_epoch));
    }

    /// Scenario: Two prefixes that land on the same slot share the bucket and never reset it
    /// features/rate-limiting.feature:240
    ///
    /// The table never fills, so collisions SHARE silently — always conservative,
    /// never looser (ruling §3.5). Detect-and-reset was rejected because an
    /// attacker alternating two colliding prefixes would reset the bucket to full
    /// on every packet and never be limited; a mutant that resets on key mismatch
    /// allows every probe below and fails here.
    ///
    /// Found by birthday search rather than by injecting a seed, so no test-only
    /// constructor is needed: 4096 drained prefixes against 4096 fresh probes in
    /// a 2^18-slot table expect ~63 shared slots, and the probability of seeing
    /// none is e^-63, about 1 in 10^27. Cost is 12k in-process checks and no
    /// sockets.
    #[test]
    fn two_prefixes_on_one_slot_share_the_bucket_without_resetting_it() {
        const VICTIMS: u32 = 4096;
        const PROBES: u32 = 4096;

        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        for i in 0..VICTIMS {
            drain(&rl, v4_prefix(i), now);
        }

        let mut denied_on_first_sight = 0;
        for i in 0..PROBES {
            if !rl.check_at(v4_prefix(1_000_000 + i), now) {
                denied_on_first_sight += 1;
            }
        }

        assert!(
            denied_on_first_sight >= 1,
            "not one of {PROBES} previously unseen prefixes was denied on its \
             first query, so no two prefixes share a bucket — the table is not \
             fixed-size, and memory is still a function of source diversity"
        );
    }

    /// Scenario: Which prefixes share a slot differs between processes
    /// features/rate-limiting.feature:253
    ///
    /// VEGA-020's acceptance criterion, moved here by ruling §5.2. DefaultHasher
    /// has a documented fixed zero seed: 62,664 addresses landing in one shard
    /// were found offline in 8.7 ms, identically in every process. Under a fixed
    /// table that stops being a contention bug and becomes targeted denial —
    /// compute a prefix that collides with a victim's slot and drain the victim's
    /// bucket without ever sending the victim a packet. The per-process seed is
    /// what makes silent collision sharing safe rather than exploitable.
    ///
    /// Expressed on the observable consequence rather than on the index, so it
    /// needs no test-only accessor: the set of prefixes that collide with a fixed
    /// victim set must not carry over to a second limiter. With independent seeds
    /// each carried-over probe re-collides with probability ~1.5%, so ~1 of ~63
    /// survives; with a fixed seed all 63 survive.
    #[test]
    fn the_set_of_colliding_prefixes_differs_between_limiters() {
        const VICTIMS: u32 = 4096;
        const PROBES: u32 = 4096;

        let now = Instant::now();
        let first = RateLimiter::new(1, 1);
        for i in 0..VICTIMS {
            drain(&first, v4_prefix(i), now);
        }
        let colliding: Vec<u32> = (0..PROBES)
            .filter(|i| !first.check_at(v4_prefix(1_000_000 + i), now))
            .collect();

        assert!(
            colliding.len() >= 10,
            "only {} of {PROBES} probes collided with the {VICTIMS} drained \
             prefixes; with no fixed-size table there is nothing to collide in \
             and the seed cannot be observed",
            colliding.len()
        );

        let second = RateLimiter::new(1, 1);
        for i in 0..VICTIMS {
            drain(&second, v4_prefix(i), now);
        }
        let carried = colliding
            .iter()
            .filter(|i| !second.check_at(v4_prefix(1_000_000 + **i), now))
            .count();

        assert!(
            carried * 3 < colliding.len(),
            "{carried} of {} colliding prefixes collided again in a second \
             limiter; the hash seed is shared between instances, so an attacker \
             can compute a victim's slot mates offline",
            colliding.len()
        );
    }

    /// Scenario: A gap longer than the wrap guard grants no refill
    /// features/rate-limiting.feature:277
    ///
    /// `last_ms` is 32 bits of milliseconds and wraps every 49.71 days, so a gap
    /// past the wrap computes garbage. One guard covers it: an elapsed of 2^31 ms
    /// (24.86 days) or more is treated as zero. The answer is conservative — a
    /// slot that cannot prove how long it has been idle is not handed a refill.
    #[test]
    fn a_gap_past_the_wrap_guard_grants_no_refill() {
        let rl = RateLimiter::new(1, 1);
        let t0 = Instant::now();
        assert!(rl.check_at(ip("198.51.100.12"), t0));
        let after_wrap_guard = t0 + Duration::from_secs(25 * 24 * 60 * 60);
        assert!(
            !rl.check_at(ip("198.51.100.12"), after_wrap_guard),
            "25 days is past the 24.86-day wrap guard: the elapsed time cannot be \
             trusted, so the refill must not be granted"
        );
    }

    /// Scenario: A gap just short of the wrap guard still refills normally
    /// features/rate-limiting.feature:288
    ///
    /// The other side of the guard. A mutant that clamps too eagerly — at 2^30,
    /// say — denies a legitimate resolver that went quiet over a long weekend.
    #[test]
    fn a_gap_just_short_of_the_wrap_guard_still_refills() {
        let rl = RateLimiter::new(1, 1);
        let t0 = Instant::now();
        assert!(rl.check_at(ip("198.51.100.13"), t0));
        let inside_guard = t0 + Duration::from_secs(24 * 24 * 60 * 60);
        assert!(
            rl.check_at(ip("198.51.100.13"), inside_guard),
            "24 days is inside the 24.86-day guard and the bucket must have \
             refilled to the burst"
        );
    }

    /// Scenario: A zero qps and a zero burst are clamped rather than panicking
    /// features/rate-limiting.feature:297
    ///
    /// `assert!(qps > 0 && burst > 0)` is unreachable today because config.rs
    /// rejects the combination — but `panic = "abort"` in release turns one
    /// slipped invariant into a full outage, and CLAUDE.md forbids a panic on any
    /// path reachable from a network packet. Construction gains no failure mode:
    /// zero clamps to one (ruling §5.6).
    #[test]
    fn a_zero_qps_and_burst_are_clamped_instead_of_panicking() {
        let rl = RateLimiter::new(0, 0);
        let now = Instant::now();
        assert!(
            rl.check_at(ip("198.51.100.14"), now),
            "a zero burst must clamp to one, not deny everything for ever"
        );
        assert!(!rl.check_at(ip("198.51.100.14"), now));
    }

    /// Scenario: A qps and burst of u32::MAX are clamped rather than overflowing
    /// features/rate-limiting.feature:309
    ///
    /// `capacity_milli` has to stay inside the 30-bit field with bits 63..62
    /// reserved zero for VEGA-041's SLIP counter, so both are clamped to
    /// MAX_RATE = 1,000,000 and burst*1000 stays under 2^30.
    #[test]
    fn a_u32_max_qps_and_burst_are_clamped_instead_of_overflowing() {
        let rl = RateLimiter::new(u32::MAX, u32::MAX);
        let now = Instant::now();
        for i in 0..1000 {
            assert!(
                rl.check_at(ip("198.51.100.15"), now),
                "query {i} was denied by a limiter configured with the largest \
                 legal qps and burst"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Concurrency (ruling §13 D)
    // -----------------------------------------------------------------------

    /// Scenario: Concurrent checks never hand out more than the burst
    /// features/rate-limiting.feature:320
    ///
    /// RELAXED from `== burst` to `<= burst`, authorised by ruling §13 D1: the
    /// CAS loop is bounded at 8 attempts and fails CLOSED, so extreme contention
    /// may legitimately admit fewer than the burst. Failing open would hand an
    /// attacker an off-switch — manufacture contention, get admitted.
    ///
    /// On its own this relaxation would hollow the test out, so it is only sound
    /// paired with `a_single_threaded_run_hands_out_exactly_the_burst` and
    /// `two_threads_at_a_barrier_still_hand_out_exactly_the_burst`, which pin the
    /// exact count where the CAS bound cannot be reached. Do not delete either
    /// without restoring `==` here.
    #[test]
    fn concurrent_checks_never_hand_out_more_than_burst_tokens() {
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

        let allowed = allowed.load(Ordering::Relaxed);
        assert!(
            allowed <= BURST as usize,
            "{allowed} queries were admitted from one prefix against a burst of \
             {BURST}: tokens leaked under contention"
        );
        assert!(
            allowed >= 1,
            "not one of {} concurrent queries was admitted; the limiter denies \
             everything rather than limiting anything",
            THREADS * PER_THREAD
        );
    }

    /// Scenario: A single-threaded run hands out exactly the burst
    /// features/rate-limiting.feature:333
    ///
    /// Half of the pair that keeps the relaxation above honest. This is where the
    /// token arithmetic is pinned; the concurrent test only pins the direction.
    #[test]
    fn a_single_threaded_run_hands_out_exactly_the_burst() {
        const BURST: u32 = 500;

        let rl = RateLimiter::new(1, BURST);
        let now = Instant::now();
        let source = ip("198.51.100.31");
        let allowed = (0..700).filter(|_| rl.check_at(source, now)).count();
        assert_eq!(allowed, BURST as usize);
    }

    /// Scenario: Two threads at a barrier still hand out exactly the burst
    /// features/rate-limiting.feature:341
    ///
    /// The other half. Two writers exercise the CAS retry and cannot exhaust an
    /// 8-attempt bound, so the exact count must survive contention.
    #[test]
    fn two_threads_at_a_barrier_still_hand_out_exactly_the_burst() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Barrier,
        };

        const THREADS: usize = 2;
        const PER_THREAD: usize = 400;
        const BURST: u32 = 500;

        let rl = Arc::new(RateLimiter::new(1, BURST));
        let allowed = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(THREADS));
        let now = Instant::now();
        let source = ip("198.51.100.32");

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
        assert_eq!(allowed.load(Ordering::Relaxed), BURST as usize);
    }

    /// Scenario: A sustained storm against a single slot completes in bounded time
    /// features/rate-limiting.feature:349
    ///
    /// CLAUDE.md bounds every loop on the query path, and a CAS loop is the
    /// classic place that rule is broken. Run off-thread behind a channel
    /// timeout so a mutant that removes the 8-attempt cap fails this test instead
    /// of hanging the whole binary. 800,000 in-process checks, no sockets, no
    /// sleeping.
    #[test]
    fn a_storm_against_a_single_slot_completes_in_bounded_time() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc, Barrier,
        };

        const THREADS: usize = 8;
        const PER_THREAD: usize = 100_000;

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rl = Arc::new(RateLimiter::new(1, 1));
            let allowed = Arc::new(AtomicUsize::new(0));
            let barrier = Arc::new(Barrier::new(THREADS));
            let now = Instant::now();
            let source = ip("198.51.100.33");

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
            let _ = tx.send(allowed.load(Ordering::Relaxed));
        });

        let allowed = rx
            .recv_timeout(Duration::from_secs(60))
            .expect("a storm on one slot must terminate: the CAS loop is bounded at 8 attempts");
        assert_eq!(
            allowed, 1,
            "a frozen clock and a burst of one admit exactly one query however \
             many threads race for it"
        );
    }

    /// Scenario: Concurrent checks across many distinct prefixes all land
    /// features/rate-limiting.feature:359
    ///
    /// SUPERSEDES `concurrent_checks_across_many_sources_all_land`, which counted
    /// `tracked()` — an accessor VEGA-003 deletes — over 4000 addresses that all
    /// shared a single /24 under the new key. Rewritten onto distinct /24s and
    /// onto the observable outcome. The tolerance is for hash collisions: 4000
    /// prefixes in a 2^18-slot table expect ~30 shared slots, and 100 is well
    /// past any plausible run, while a lost update loses far more.
    #[test]
    fn concurrent_checks_across_many_prefixes_all_land() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Barrier,
        };

        const THREADS: u32 = 8;
        const PER_THREAD: u32 = 500;

        let rl = Arc::new(RateLimiter::new(1, 1));
        let allowed = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(THREADS as usize));
        let now = Instant::now();

        let mut handles = Vec::new();
        for t in 0..THREADS {
            let (rl, allowed, barrier) =
                (Arc::clone(&rl), Arc::clone(&allowed), Arc::clone(&barrier));
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for i in 0..PER_THREAD {
                    if rl.check_at(v4_prefix(t * PER_THREAD + i), now) {
                        allowed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("worker finishes");
        }

        let allowed = allowed.load(Ordering::Relaxed);
        assert!(
            allowed >= (THREADS * PER_THREAD) as usize - 100,
            "only {allowed} of {} distinct prefixes were admitted; concurrent \
             updates to different slots are being lost",
            THREADS * PER_THREAD
        );
    }

    // -----------------------------------------------------------------------
    // The operational breaking change (ruling §7)
    // -----------------------------------------------------------------------

    /// Scenario: The configured qps applies to a whole /24, not to each host inside it
    /// features/rate-limiting.feature:477
    ///
    /// `qps` changes meaning from per source ADDRESS to per /24 or /56. An
    /// operator running qps = 50 whose traffic comes from a resolver farm of 200
    /// hosts inside one /24 is granting that farm 10,000 qps today and will be
    /// granting it 50. It will look like an outage and it is not a bug, so it is
    /// asserted here as well as written in the CHANGELOG, the README and
    /// vega.example.toml: size qps for the busiest single /24 you serve, not for
    /// a single resolver.
    #[test]
    fn the_configured_qps_covers_a_whole_slash_24_not_each_host_in_it() {
        const HOSTS: u32 = 200;
        const BURST: u32 = 50;

        let rl = RateLimiter::new(50, BURST);
        let now = Instant::now();
        let allowed = (1..=HOSTS)
            .filter(|host| {
                #[allow(clippy::cast_possible_truncation)]
                let addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, *host as u8));
                rl.check_at(addr, now)
            })
            .count();

        assert_eq!(
            allowed, BURST as usize,
            "a 200-host resolver farm inside one /24 now shares one bucket: {allowed} \
             of {HOSTS} hosts got through against a burst of {BURST}"
        );
    }
}
