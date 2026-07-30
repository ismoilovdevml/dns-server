//! Per-source-prefix token buckets in a fixed table of slots.
//!
//! An authoritative name server on the public internet is a reflection-attack
//! amplifier unless it caps how fast a single source can ask questions. The
//! danger is that the *key* is chosen by the attacker, one packet at a time:
//! DNS over UDP has no transaction-level proof of source (RFC 1035 §4.2.1) and
//! ingress filtering (BCP 38 / RFC 2827) is not ours to deploy. Anything this
//! module remembers per key is therefore memory an attacker mints for free —
//! which is what a map keyed on the full address did, at a measured 186 bytes
//! per forged source, reaching a 128 MiB container limit in 7.2 seconds.
//! Turning rate limiting on was what made the process killable (VEGA-003).
//!
//! What replaced it, and what it guarantees:
//!
//! * **Memory is a compile-time constant.** One `Box<[AtomicU64]>` of 2^18
//!   eight-byte slots — 2 MiB — allocated once in [`RateLimiter::new`] and never
//!   grown, shrunk or pruned. [`RateLimiter::memory_bytes`] reports the same
//!   number after one query and after 2^64, whatever the traffic looks like.
//! * **The key is a network prefix, not an address:** IPv4 /24 and IPv6 /56,
//!   with IPv4-mapped IPv6 folded to its IPv4 form first. An attacker holding a
//!   single IPv6 /64 — the smallest allocation any LAN gets — is one bucket
//!   rather than 2^64 of them, so the bucket actually fires.
//! * **Source cardinality is deliberately not retained.** There are no entries,
//!   so there is nothing to count, nothing to reclaim and no sweeper task. Two
//!   prefixes whose hashes land on one slot share that bucket silently, which is
//!   always *stricter* than giving each its own and never looser.
//! * **The hash seed is per process**, which is what keeps that sharing
//!   unexploitable: an attacker cannot compute offline which prefix collides
//!   with a victim's and drain the victim's bucket from somewhere else
//!   (VEGA-020).
//!
//! The price, stated plainly because an operator will meet it: `qps` now applies
//! to a whole /24 or /56, so every host inside one shares a bucket, and under a
//! maximally diverse flood the table degrades towards a global limit. Degraded
//! service under attack beats a process the attacker can OOM-kill, after which
//! there is no service at all until a human intervenes.
//!
//! Time is injected via [`RateLimiter::check_at`] so the behaviour is testable
//! without sleeping.

use std::{
    collections::hash_map::RandomState,
    hash::BuildHasher,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

/// Index width of the slot table, so `2^SLOT_BITS` slots of 8 bytes = 2 MiB.
///
/// Sized against the number of *prefixes* a single-zone authoritative server
/// sees at once, not the number of addresses. The fraction of active prefixes
/// sharing a slot is `1 - e^(-M/SLOTS)`: at 10,000 active prefixes that is 3.7%
/// here against 14% at 2^16, while 2^20 would buy another 4× for 8 MiB — 6% of
/// a 128 MiB container limit — at a cardinality this server will not see. It
/// sits between NSD's fixed 1,000,000 entries and Knot DNS's 393,241, at a
/// fraction of their per-bucket cost.
const SLOT_BITS: u32 = 18;

/// Number of slots. A power of two, so the index is a mask rather than a modulo.
const SLOTS: usize = 1 << SLOT_BITS;

/// Mask that turns a hash into a slot index.
const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;

/// Significant bits of an IPv4 source address.
///
/// A /24 is the smallest routable unit in the global table and the conventional
/// customer allocation; it is also BIND 9's `ipv4-prefix-length` default. There
/// is no RFC for response rate limiting — this is operational practice, from
/// Vixie and Schryver, *DNS Response Rate Limiting*, ISC-TN-2012-1.
const IPV4_PREFIX_BITS: u32 = 24;

/// Significant bits of an IPv6 source address.
///
/// A /56 is an end site: RFC 6177 (BCP 157) recommends end sites receive a /48,
/// /56 or /64 rather than a single address, and it is BIND 9's
/// `ipv6-prefix-length` default. Aggregating at /64 (NSD's choice) lets one home
/// site present 256 independent buckets; /48 would collapse unrelated
/// enterprises together.
const IPV6_PREFIX_BITS: u32 = 56;

/// Family tag in bits 63..62 of the canonical key: IPv4.
///
/// Without a tag the IPv4 /24 whose payload is `k` and the IPv6 /56 whose
/// payload is also `k` are one bucket, and an IPv6 attacker could deny an
/// unrelated IPv4 network by arithmetic.
const KEY_TAG_V4: u64 = 0;

/// Family tag in bits 63..62 of the canonical key: IPv6.
const KEY_TAG_V6: u64 = 1 << 62;

/// Upper bound on `qps` and `burst`.
///
/// Keeps `capacity_milli` below 2^30 (1,000,000 × 1000 = 1.0e9 < 1.074e9), so
/// the deficit fits its 30-bit field and slot bits 63..62 stay zero.
const MAX_RATE: u32 = 1_000_000;

/// Milli-tokens per token. One query costs exactly one token.
const MILLI: u64 = 1_000;

/// Bit offset of `deficit_milli` within a slot word.
const DEFICIT_SHIFT: u32 = 32;

/// Mask of `deficit_milli` once shifted down: 30 bits.
const DEFICIT_MASK: u64 = (1 << 30) - 1;

/// Apparent elapsed milliseconds at or above which a slot has been idle so long
/// that its bucket must be full.
///
/// `last_ms` is a 32-bit millisecond clock that wraps every 49.71 days, so past
/// that a gap aliases — and the aliasing is not one-sided: "the reading moved
/// backwards by X" and "the slot has been idle for 2^32 - X" are *the same bit
/// pattern*. No rule can tell them apart from the slot alone, so the rule is a
/// choice about which reading to favour. See [`STALE_MAX_MS`].
const WRAP_GUARD_MS: u32 = 1 << 31;

/// The widest apparent backwards step still read as a backwards clock reading.
///
/// A reading that really moved backwards has only two sources, and both are
/// tiny: a thread that sampled `now`, lost its compare-exchange and re-read a
/// slot another thread has since stamped (sub-microsecond, bounded above by
/// preemption at single-digit milliseconds), and a test injecting an `Instant`.
/// One minute is six orders of magnitude above the first and five orders below
/// the 24.86-day boundary, so the band cannot be aimed: landing a slot in it
/// means having touched it at a chosen moment 49.7 days minus under a minute
/// earlier, to buy 60 seconds of over-strict limiting on one prefix.
///
/// Above the band, a long apparent gap is read as what it almost always is — a
/// slot nobody has used for weeks — and its bucket is full. That is not a
/// concession to an attacker: a slot idle for `burst/qps` seconds is already
/// indistinguishable from one never touched, and an untouched slot is full, so
/// the same grant is available for free from any unused prefix. Reading it as
/// "cannot tell, deny" instead is what left an emptied slot denied for up to
/// 24.86 days, because the denied path stores nothing and so never advances
/// `last_ms` out of the ambiguous window.
const STALE_MAX_MS: u32 = 60_000;

/// Apparent elapsed at or above which the reading is treated as backwards:
/// `2^32 - STALE_MAX_MS`.
const BACKWARDS_FLOOR_MS: u32 = u32::MAX - STALE_MAX_MS + 1;

/// Maximum compare-exchange attempts before a query is refused.
///
/// CLAUDE.md bounds every loop on the query path and a CAS loop is the classic
/// place that rule is broken. Eight consecutive failures means eight or more
/// concurrent writers hit one slot within tens of nanoseconds — that prefix is
/// flooding us, so refusing is both the safe answer and the correct one. Failing
/// *open* would hand an attacker an off-switch: manufacture contention, get
/// admitted.
const CAS_ATTEMPTS: u32 = 8;

/// Token-bucket rate limiter keyed by source network prefix.
///
/// See the module documentation for the guarantees. The table's shape is fixed
/// for the process lifetime; only slot contents change, and only through
/// atomics, so there is no lock anywhere on the query path.
pub struct RateLimiter {
    /// One allocation, made in `new`, never resized. Index = `hash(key) & SLOT_MASK`.
    ///
    /// Slots are deliberately **not** padded to a cache line. Padding would make
    /// the table 16 MiB; the attack this defends against is a maximally diverse
    /// flood, where an unpadded 2 MiB table stays resident in L2/L3 and a padded
    /// one thrashes it. Cache residency beats false-sharing avoidance at this
    /// access pattern.
    slots: Box<[AtomicU64]>,
    /// Per-process seed. Without it, collision sets are computable offline and
    /// silent slot sharing becomes a targeted-denial primitive (VEGA-020).
    hasher: RandomState,
    /// Zero point for the 32-bit millisecond timestamps in each slot.
    epoch: Instant,
    /// Milli-tokens added per millisecond, numerically equal to `qps`.
    refill_per_ms: u32,
    /// Bucket capacity in milli-tokens: `burst * 1000`.
    capacity_milli: u32,
}

/// Hand-written so a `{:?}` of the handler cannot dump 262,144 atomics into a
/// log line. The shape is what an operator wants; the contents are the gauges.
impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("slots", &self.slots.len())
            .field("refill_per_ms", &self.refill_per_ms)
            .field("capacity_milli", &self.capacity_milli)
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    /// Create a limiter allowing `qps` sustained queries per source *prefix*
    /// (IPv4 /24, IPv6 /56) with a bucket capacity of `burst`.
    ///
    /// Construction has no failure mode. Zero clamps to one and anything above
    /// [`MAX_RATE`] clamps down to it: [`crate::config`] already rejects a zero
    /// `qps`, but `panic = "abort"` in release turns one slipped invariant into a
    /// full outage, and an assert is not worth that.
    pub fn new(qps: u32, burst: u32) -> Self {
        Self {
            // Zeroed, and the zero word means "full bucket, never touched" — see
            // `check_at`. Built once at startup, off the query path.
            slots: (0..SLOTS)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            hasher: RandomState::new(),
            epoch: Instant::now(),
            refill_per_ms: qps.clamp(1, MAX_RATE),
            capacity_milli: burst.clamp(1, MAX_RATE) * 1000,
        }
    }

    /// Consume one token for `ip`. Returns `true` when the query may proceed.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    /// [`RateLimiter::check`] with an explicit clock reading.
    ///
    /// This runs on every query, before message-type, opcode, EDNS, QDCOUNT,
    /// QCLASS and QTYPE validation, so a 29-byte garbage datagram reaches it: one
    /// masked index, one relaxed load, integer arithmetic, and a compare-exchange
    /// on the *allowed* path only. Nothing is allocated and nothing is locked.
    ///
    /// A refused query performs no store at all. Under a flood the refusal path
    /// is the hot one, so writing back would bounce the cache line between every
    /// core for no semantic gain — and a token bucket that refuses a query has
    /// not consumed anything.
    pub fn check_at(&self, ip: IpAddr, now: Instant) -> bool {
        let slot = &self.slots[self.slot_of(ip)];
        let now_ms = self.millis_since_epoch(now);
        let capacity = u64::from(self.capacity_milli);
        let refill_per_ms = u64::from(self.refill_per_ms);

        let mut observed = slot.load(Ordering::Relaxed);
        for _ in 0..CAS_ATTEMPTS {
            let (refilled, stamp) = settle(observed, now_ms, refill_per_ms);
            let charged = refilled + MILLI;
            if charged > capacity {
                return false;
            }
            match slot.compare_exchange_weak(
                observed,
                pack(charged, stamp),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => observed = actual,
            }
        }
        // Fail closed: see CAS_ATTEMPTS.
        false
    }

    /// Bytes of slot table held by this limiter, for `dns_ratelimit_slots` and
    /// for the tests that pin the ceiling.
    ///
    /// A constant of the binary. It is the same after one query and after two
    /// million forged sources, which is the whole point of VEGA-003.
    pub fn memory_bytes(&self) -> usize {
        self.slots.len() * std::mem::size_of::<AtomicU64>()
    }

    /// Number of slots in the table. Constant for the process lifetime.
    pub fn slots(&self) -> usize {
        self.slots.len()
    }

    /// Slots whose bucket, refilled to `now`, is below full.
    ///
    /// Computed on scrape rather than maintained by a task: 262,144 relaxed loads
    /// over 2 MiB of sequential memory, taking no lock and blocking nothing, so a
    /// scrape landing during a flood cannot stall a query.
    ///
    /// Read against [`RateLimiter::slots`], this is the difference between a
    /// concentrated attack (few active slots) and a maximally diverse one that
    /// has collapsed the table towards a global limit (active approaching
    /// slots), which is the alert an operator actually needs.
    pub fn active_at(&self, now: Instant) -> usize {
        let now_ms = self.millis_since_epoch(now);
        let refill_per_ms = u64::from(self.refill_per_ms);
        self.slots
            .iter()
            .filter(|slot| settle(slot.load(Ordering::Relaxed), now_ms, refill_per_ms).0 > 0)
            .count()
    }

    /// [`RateLimiter::active_at`] with the current clock reading.
    pub fn active(&self) -> usize {
        self.active_at(Instant::now())
    }

    /// Slot index for a source address.
    ///
    /// Kept apart from [`RateLimiter::check_at`] so VEGA-041 can substitute a
    /// response-class key without touching the bucket arithmetic.
    fn slot_of(&self, ip: IpAddr) -> usize {
        // The mask leaves at most 18 bits, so the conversion is exact on any
        // target Rust supports; clippy cannot see that through the mask.
        #[allow(clippy::cast_possible_truncation)]
        let idx = (self.hasher.hash_one(canonical_key(ip)) & SLOT_MASK) as usize;
        idx
    }

    /// Milliseconds from this limiter's epoch, wrapping every 49.71 days.
    fn millis_since_epoch(&self, now: Instant) -> u32 {
        // The truncation IS the 32-bit millisecond clock; `band` is what handles
        // the wrap it creates.
        #[allow(clippy::cast_possible_truncation)]
        let ms = now.saturating_duration_since(self.epoch).as_millis() as u32;
        ms
    }

    /// Raw slot word, for the tests that assert the refusal path writes nothing.
    #[cfg(test)]
    fn slot_word(&self, idx: usize) -> u64 {
        self.slots[idx].load(Ordering::Relaxed)
    }
}

/// The source address reduced to one 8-byte key: a family tag in bits 63..62 and
/// the network prefix, right-aligned, in bits 55..0.
///
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`, RFC 4291 §2.5.5.2) is folded to its IPv4
/// form *before* masking. A socket bound to `[::]` delivers IPv4 peers in that
/// form, and unfolded its top 56 bits are constant for every IPv4 client on
/// earth — masking to /56 would put the entire IPv4 internet in one token
/// bucket. `to_ipv4_mapped` and not `to_ipv4`, because the latter also matches
/// the IPv4-*compatible* form deprecated by RFC 4291 §2.5.5.1 and would fold the
/// legitimate address `::1.2.3.4` into IPv4 space. 6to4 and Teredo are not
/// unwrapped: that is a second parser on the query path for a vanishing traffic
/// class, and BIND does not do it either.
fn canonical_key(ip: IpAddr) -> u64 {
    match ip {
        IpAddr::V4(v4) => v4_key(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(|| v6_key(v6), v4_key),
    }
}

/// The /24 of an IPv4 address, tagged.
fn v4_key(v4: Ipv4Addr) -> u64 {
    KEY_TAG_V4 | u64::from(u32::from(v4) >> (32 - IPV4_PREFIX_BITS))
}

/// The /56 of an IPv6 address, tagged.
fn v6_key(v6: Ipv6Addr) -> u64 {
    // The shift leaves 56 bits, so the cast keeps every one of them and the
    // payload can never reach the tag in bit 62.
    #[allow(clippy::cast_possible_truncation)]
    let prefix = (u128::from(v6) >> (128 - IPV6_PREFIX_BITS)) as u64;
    KEY_TAG_V6 | prefix
}

/// Split a slot word into its milli-token deficit and its timestamp.
fn unpack(word: u64) -> (u64, u32) {
    // Field extraction, not a lossy conversion: `last_ms` is the low 32 bits.
    #[allow(clippy::cast_possible_truncation)]
    let last_ms = word as u32;
    ((word >> DEFICIT_SHIFT) & DEFICIT_MASK, last_ms)
}

/// Build a slot word. Bits 63..62 stay zero, reserved for VEGA-041's SLIP
/// counter; `MAX_RATE` is what guarantees `deficit` cannot reach them.
fn pack(deficit: u64, last_ms: u32) -> u64 {
    ((deficit & DEFICIT_MASK) << DEFICIT_SHIFT) | u64::from(last_ms)
}

/// What an apparent elapsed time means, once the 32-bit wrap is accounted for.
///
/// The three bands of the wrap window. The split between the last two is the
/// only place a judgement is possible at all — see [`STALE_MAX_MS`].
enum Band {
    /// An ordinary gap, in milliseconds. Under 24.86 days.
    Ordinary(u32),
    /// The reading moved backwards. No refill, and the slot's clock must not be
    /// dragged back with it: that is the last-writer-wins hazard, where a thread
    /// holding a stale `now` hands a later reader a longer gap than really
    /// passed. This is precisely the band that does not store.
    Backwards,
    /// Idle so long the bucket must be full.
    LongIdle,
}

/// Classify the apparent gap from `last_ms` to `now_ms`.
fn band(now_ms: u32, last_ms: u32) -> Band {
    let elapsed = now_ms.wrapping_sub(last_ms);
    if elapsed < WRAP_GUARD_MS {
        Band::Ordinary(elapsed)
    } else if elapsed >= BACKWARDS_FLOOR_MS {
        Band::Backwards
    } else {
        Band::LongIdle
    }
}

/// A slot's milli-token deficit brought up to `now_ms`, with the timestamp a
/// store would have to carry.
///
/// Shared by [`RateLimiter::check_at`] and [`RateLimiter::active_at`] so the
/// occupancy gauge can never disagree with the limiter about what a slot holds.
fn settle(word: u64, now_ms: u32, refill_per_ms: u64) -> (u64, u32) {
    let (deficit, last_ms) = unpack(word);
    match band(now_ms, last_ms) {
        Band::Ordinary(elapsed) => (
            deficit.saturating_sub(u64::from(elapsed) * refill_per_ms),
            now_ms,
        ),
        Band::Backwards => (deficit, last_ms),
        Band::LongIdle => (0, now_ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
    /// features/rate-limiting.feature:201
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
    /// features/rate-limiting.feature:208
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
    /// features/rate-limiting.feature:215
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
    /// features/rate-limiting.feature:242
    ///
    /// The five-second step back is deliberate and must stay under a minute.
    /// A 32-bit stored timestamp cannot tell "moved backwards by X" from "idle
    /// for 2^32 - X" — they are the same bit pattern — so the ruling splits the
    /// wrap window at `STALE_MAX` = 60 s (§4.3, criterion C1). "Strengthening"
    /// this to a month-long step would not make the test harder; it would move it
    /// into the long-idle band, where a full bucket is the correct answer, and it
    /// would then pass for the opposite reason.
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
    /// features/rate-limiting.feature:60
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
    /// features/rate-limiting.feature:69
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
    /// features/rate-limiting.feature:75
    #[test]
    fn the_first_and_last_address_of_a_slash_24_share_a_bucket() {
        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        assert!(rl.check_at(ip("203.0.113.0"), now));
        assert!(!rl.check_at(ip("203.0.113.255"), now));
    }

    /// Scenario: Addresses one apart across a /24 boundary do not share
    /// features/rate-limiting.feature:81
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
    /// features/rate-limiting.feature:87
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
    /// features/rate-limiting.feature:94
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
    /// features/rate-limiting.feature:101
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
    /// features/rate-limiting.feature:110
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
    /// features/rate-limiting.feature:120
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
    /// features/rate-limiting.feature:129
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

    /// Scenario: The table size is a compile-time constant, not a function of traffic
    /// features/rate-limiting.feature:154
    ///
    /// REPLACES the structural guard of the same scenario in `tests/ratelimit.rs`,
    /// which could only assert that `const SLOTS` and `fn memory_bytes` appear in
    /// the source text because the accessor did not exist yet. It exists now, so
    /// the ceiling is asserted by equality across a 2,000,000-source flood and
    /// against two limiters configured at opposite extremes — ruling §13 B1, B5.
    #[test]
    fn the_slot_table_is_the_same_size_before_and_after_a_two_million_source_flood() {
        const FLOOD: u32 = 2_000_000;

        let rl = RateLimiter::new(1, 1);
        let now = Instant::now();
        let before = rl.memory_bytes();

        assert_eq!(rl.slots(), SLOTS);
        assert_eq!(
            before,
            SLOTS * 8,
            "the table is one AtomicU64 per slot and nothing else"
        );
        assert_eq!(before, 2_097_152, "2 MiB exactly, and it is a constant");

        for i in 0..FLOOD {
            let _ = rl.check_at(v4_prefix(i), now);
        }

        assert_eq!(
            rl.memory_bytes(),
            before,
            "{FLOOD} distinct forged prefixes changed the limiter's footprint; \
             the ceiling must be a property of the binary, not the outcome of a \
             race between a background sweep and an attacker"
        );
        assert_eq!(
            RateLimiter::new(MAX_RATE, MAX_RATE).memory_bytes(),
            before,
            "a limiter sized for a million qps costs the same as one sized for \
             one: construction is independent of expected load"
        );
    }

    /// Scenario: A flood of two million distinct spoofed prefixes does not grow the process
    /// features/rate-limiting.feature:142
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
    /// features/rate-limiting.feature:183
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
    /// features/rate-limiting.feature:192
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
    /// features/rate-limiting.feature:222
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
    /// features/rate-limiting.feature:232
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
    /// features/rate-limiting.feature:255
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
    /// features/rate-limiting.feature:268
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
    /// features/rate-limiting.feature:281
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

    /// Scenario: A denied query does not write to its slot
    /// features/rate-limiting.feature:294
    ///
    /// REPLACES the structural guard of the same scenario in `tests/ratelimit.rs`,
    /// which could only assert that `check_at` contains no plain store. It could
    /// never be asserted behaviourally through the public API — a store on the
    /// refusal path writes back the same refilled deficit and a later timestamp,
    /// which is semantically identical — so it needs the raw word, and the raw
    /// word needs the `#[cfg(test)]` accessor this commit lands.
    ///
    /// Under a flood the refusal path IS the hot path, so a write-back per
    /// dropped packet is a cache line bounced between every core for no semantic
    /// gain (ruling §5.3 step 6). No timing test catches that reliably. The
    /// second reading is 500 ms later precisely so a write-back would be visible:
    /// it would carry a different timestamp.
    #[test]
    fn a_denied_query_leaves_its_slot_word_byte_identical() {
        let rl = RateLimiter::new(1, 1);
        let t0 = Instant::now();
        let prefix = ip("198.51.100.40");
        let idx = rl.slot_of(prefix);

        assert!(rl.check_at(prefix, t0));
        let before = rl.slot_word(idx);
        assert!(!rl.check_at(prefix, t0 + Duration::from_millis(500)));

        assert_eq!(
            rl.slot_word(idx),
            before,
            "the refused query wrote to its slot: {:#018x} became {:#018x}",
            before,
            rl.slot_word(idx)
        );
    }

    /// Scenario: No write ever touches the two reserved slot bits
    /// features/rate-limiting.feature:305
    ///
    /// The other half of the slot contract, and the one VEGA-041 depends on:
    /// bits 63..62 are reserved for its SLIP counter and MUST be written as zero,
    /// which the MAX_RATE clamp is what guarantees (ruling §12). Asserted at the
    /// largest legal configuration, where the deficit field is closest to
    /// overflowing into them.
    #[test]
    fn no_write_ever_touches_the_two_reserved_slot_bits() {
        const RESERVED: u64 = 0b11 << 62;

        let rl = RateLimiter::new(MAX_RATE, MAX_RATE);
        let t0 = Instant::now();
        let prefix = ip("198.51.100.41");
        let idx = rl.slot_of(prefix);

        // Fill the bucket to the brim: capacity_milli is 1.0e9, one query below
        // 2^30, so this is the largest deficit the field can ever hold.
        for i in 0..MAX_RATE {
            assert!(
                rl.check_at(prefix, t0),
                "query {i} was denied below the configured burst"
            );
            assert_eq!(
                rl.slot_word(idx) & RESERVED,
                0,
                "a slot word reached the two bits reserved for VEGA-041's SLIP \
                 counter after {i} queries"
            );
        }
        assert!(!rl.check_at(prefix, t0), "the burst must still be a bound");
    }

    /// Scenario: A reading that moved backwards grants nothing and stores nothing
    /// features/rate-limiting.feature:316
    ///
    /// REWRITTEN for the ruling's 2026-07-31 amendment to §4.3, which also
    /// rewrote criterion C6. This test used to step 25 days *forward* and assert
    /// a denial, on the superseded rule that any apparent gap past 2^31 ms was
    /// untrustworthy and granted nothing. That rule was wrong, and provably so:
    /// the denied path stores nothing, so a slot it denied never advanced
    /// `last_ms`, recomputed the same out-of-range gap on every subsequent query,
    /// and stayed denied for up to 24.86 days rather than the 2 seconds the
    /// ruling claimed. A 25-day gap is now read as what it almost certainly is —
    /// a long-idle slot — and is granted a full bucket; that half is
    /// `a_long_idle_slot_is_full_rather_than_stuck`.
    ///
    /// What survives is the half that was always sound: a reading inside the
    /// stale window really did move backwards, so it grants no refill AND leaves
    /// the slot word byte-identical. The store is what would drag the slot's
    /// clock backwards and hand the next reader a longer gap than really passed.
    #[test]
    fn a_reading_that_moved_backwards_grants_nothing_and_stores_nothing() {
        let rl = RateLimiter::new(1, 1);
        // Comfortably after the limiter's epoch, so stepping back stays positive.
        let t0 = Instant::now() + Duration::from_secs(120);
        let prefix = ip("198.51.100.12");
        let idx = rl.slot_of(prefix);

        assert!(rl.check_at(prefix, t0));
        let before = rl.slot_word(idx);

        let backwards = t0
            .checked_sub(Duration::from_secs(30))
            .expect("instant is in range");
        assert!(
            !rl.check_at(prefix, backwards),
            "a reading 30 seconds behind the slot's stamp is inside the 60-second \
             stale window and must not refill the bucket"
        );
        assert_eq!(
            rl.slot_word(idx),
            before,
            "the backwards reading was stored: {:#018x} became {:#018x}, which \
             drags the slot's clock back and inflates the next reader's gap",
            before,
            rl.slot_word(idx)
        );
    }

    /// Scenario: A genuinely long idle slot is full, not stuck
    /// features/rate-limiting.feature:338
    ///
    /// Criterion C8, new from the ruling's 2026-07-31 amendment, and the test
    /// that pins the fix. An apparent gap in `[2^31, 2^32 - 60_000)` is read as a
    /// long idle: the bucket is full, the query is allowed, and — because it is
    /// allowed — it stores its new timestamp through the ordinary path, which is
    /// what gets the slot out of the ambiguous window.
    ///
    /// The second and third queries are the ones that matter. Under the
    /// superseded rule the first is denied and so is every one after it, for up
    /// to 24.86 days, because nothing ever advances `last_ms`. The symptom would
    /// be a legitimate resolver's whole /24 dropped in silence — VEGA-004 drops
    /// rather than REFUSEs on UDP — for three and a half weeks, with nothing in
    /// the logs but `dns_rate_limited_total` ticking.
    ///
    /// Reachable, and more so than "seen once": the slot must have been left
    /// within one token of empty, which is what a scanner, a decommissioned
    /// resolver or a throttled attack source does before going quiet.
    #[test]
    fn a_long_idle_slot_is_full_rather_than_stuck() {
        let rl = RateLimiter::new(1, 1);
        let t0 = Instant::now();
        let prefix = ip("198.51.100.42");

        // Leave the bucket empty, which is the state that used to get stuck.
        assert!(rl.check_at(prefix, t0));
        assert!(!rl.check_at(prefix, t0));

        // 30 days: past the 24.86-day guard, short of the 49.7-day stale window.
        let long_idle = t0 + Duration::from_secs(30 * 24 * 60 * 60);
        assert!(
            rl.check_at(prefix, long_idle),
            "a slot idle for 30 days holds no information — it is indistinguishable \
             from one never touched, and an untouched slot is full"
        );
        assert!(
            !rl.check_at(prefix, long_idle),
            "the refilled slot is still a token bucket: the burst is one"
        );
        assert!(
            rl.check_at(prefix, long_idle + Duration::from_secs(1)),
            "the slot is stuck: it did not store a timestamp inside the ordinary \
             band, so it is recomputing the same out-of-range gap and will deny \
             this prefix until the 32-bit clock wraps past it"
        );
    }

    /// Scenario: A backwards step beyond the stale window is read as a long idle
    /// features/rate-limiting.feature:360
    ///
    /// The other side of the split, which pins where it sits. A backwards step of
    /// 30 seconds is denied (above) and one of 90 seconds is granted a full
    /// bucket, because beyond the stale window the reading is by construction
    /// indistinguishable from 49.7 days of idleness and the ruling favours the
    /// overwhelmingly more likely reading. Either test alone leaves `STALE_MAX`
    /// free to drift; together they bracket it between 30 and 90 seconds.
    ///
    /// This is stated in the ruling as the reason a backwards-clock test must
    /// inject a delta under a minute (§4.3, criterion C1) — a later
    /// "strengthening" to a month-long step would start passing for the opposite
    /// reason.
    #[test]
    fn a_backwards_step_beyond_the_stale_window_is_read_as_a_long_idle() {
        let rl = RateLimiter::new(1, 1);
        let t0 = Instant::now() + Duration::from_secs(300);
        let prefix = ip("198.51.100.43");

        assert!(rl.check_at(prefix, t0));
        assert!(!rl.check_at(prefix, t0));

        let far_back = t0
            .checked_sub(Duration::from_secs(90))
            .expect("instant is in range");
        assert!(
            rl.check_at(prefix, far_back),
            "90 seconds back is outside the 60-second stale window, so it reads as \
             a 49.7-day idle slot and the bucket is full"
        );
    }

    /// Scenario: A gap just short of the wrap guard still refills normally
    /// features/rate-limiting.feature:372
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
    /// features/rate-limiting.feature:381
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
    /// features/rate-limiting.feature:393
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
    /// features/rate-limiting.feature:404
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
    /// features/rate-limiting.feature:417
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
    /// features/rate-limiting.feature:425
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
    /// features/rate-limiting.feature:433
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
    /// features/rate-limiting.feature:443
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
    /// features/rate-limiting.feature:570
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
