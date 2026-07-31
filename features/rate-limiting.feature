Feature: Per-source-prefix rate limiting
  # WHY THIS MATTERS
  # An authoritative name server on the public internet with no rate limit is a
  # reflection amplifier waiting to be pointed at somebody. The attacker spoofs
  # the victim's source address, we answer, and the victim absorbs the bandwidth.
  # The token bucket is the only thing between this server and that role.
  # It is also the single most dangerous piece of code to get wrong in the other
  # direction: a bucket that refills too slowly, or one keyed carelessly, takes a
  # legitimate resolver offline for every domain we serve.
  #
  # And the key is chosen by the attacker, one packet at a time. Keying on the
  # full source address means every forged address costs memory, so turning rate
  # limiting on is what makes the process killable: 2,000,000 spoofed sources
  # measured at 356 MiB and climbing, OOM under a 128 MiB limit in 7.2 seconds.
  # VEGA-003 replaces the map with a fixed table of slots keyed on a network
  # PREFIX, so memory is a compile-time constant and an IPv6 attacker holding a
  # /64 is one bucket rather than 2^64 of them.
  #
  # HOW IT IS KEYED (VEGA-003 ruling §2, BIND 9's documented defaults)
  #   IPv4                -> /24
  #   IPv6                -> /56
  #   ::ffff:a.b.c.d      -> folded to the IPv4 /24 BEFORE masking. Unfolded, the
  #                          top 56 bits are constant for every IPv4 client on
  #                          earth and a [::]-bound server puts all of IPv4 in
  #                          one bucket. Same shape of bug as VEGA-016.
  #
  # WHAT WAS DELETED HERE, AND WHY IT IS NOT A @gap
  # VEGA-003 deletes pruning outright: `prune`, `prune_at`, `tracked`,
  # DEFAULT_IDLE_TTL, JANITOR_INTERVAL and `spawn_janitor`. A fixed table makes no
  # per-key allocation, so there is nothing to reclaim, and the ruling proves in
  # §4.2 that the old janitor was semantically a no-op for every entry it was
  # allowed to touch (a slot idle for burst/qps seconds is indistinguishable from
  # an untouched one; the TTL was 600 s against the 2 s that mattered). The four
  # scenarios that described that machinery — two prune, two janitor — were
  # DELETED from this file, not marked @gap: a scenario for machinery that no
  # longer exists is a permanent false debt. Ruling:
  # .claude/backlog/decisions/VEGA-003-bounded-rate-limiter.md §4, §13 E2.
  #
  # THE 32-BIT TIMESTAMP, AND WHY THREE BANDS AND NOT TWO
  # Each slot carries 32 bits of milliseconds, which wrap every 49.71 days, so
  # "the reading moved backwards by X" and "the slot has been idle for 2^32 - X"
  # are the same bit pattern. The ambiguity is irreducible; the only question is
  # which reading to favour and what the residual costs. The ruling's first answer
  # — deny anything past 24.86 days — was wrong, and qa-spec caught it: the denied
  # path stores nothing, so a slot denied that way never advanced its timestamp
  # and stayed denied for up to 24.86 days rather than the 2 seconds claimed. The
  # amended rule splits the window at STALE_MAX = 60 s: under a minute back is a
  # backwards reading (no refill, no store), beyond that is a long idle (full
  # bucket, allowed, and it stores through the ordinary path). Residual: up to
  # 60 s of over-strict limiting for a slot last touched 46.6-49.7 days ago, once
  # per uptime cycle. Ruling §4.3 and §4.3.1, amended 2026-07-31.
  #
  # Implementation: src/ratelimit.rs (prefix key, fixed slot table, token bucket)
  #                 src/handler.rs:331 (dispatch-time check, before opcode validation)
  #                 src/config.rs:494-542 (qps/burst resolution)

  # ------------------------------------------------------- PREFIX KEYING

  @happy @enforced src/ratelimit.rs:554
  Scenario: Two addresses in the same /24 share one bucket
    # SUPERSEDES "Each source IP gets its own bucket". Per-address buckets are
    # the defect: they are what an attacker mints memory with, and what lets a
    # /64 walk past the limiter untouched. Ruling §13 A1.
    Given a rate limiter allowing 1 qps with a burst of 1
    When 198.51.100.1 exhausts its bucket
    Then a query from 198.51.100.2 is denied

  @happy @enforced src/ratelimit.rs:568
  Scenario: Two addresses in different /24s do not share a bucket
    Given a rate limiter allowing 1 qps with a burst of 1
    When 198.51.100.1 exhausts its bucket
    Then a query from 198.51.101.1 is allowed

  @boundary @enforced src/ratelimit.rs:581
  Scenario: The first and last address of a /24 share one bucket
    Given a rate limiter allowing 1 qps with a burst of 1
    When 203.0.113.0 exhausts its bucket
    Then a query from 203.0.113.255 is denied

  @boundary @enforced src/ratelimit.rs:594
  Scenario: Addresses one apart across a /24 boundary do not share
    Given a rate limiter allowing 1 qps with a burst of 1
    When 203.0.113.255 exhausts its bucket
    Then a query from 203.0.114.0 is allowed

  @happy @enforced src/ratelimit.rs:604
  Scenario: Two addresses in the same /56 share one bucket
    # Byte 8 differs, which is inside a /56.
    Given a rate limiter allowing 1 qps with a burst of 1
    When 2001:db8:0:0::1 exhausts its bucket
    Then a query from 2001:db8:0:00ff:ffff:ffff:ffff:ffff is denied

  @boundary @enforced src/ratelimit.rs:617
  Scenario: Addresses across a /56 boundary do not share
    # Byte 7 differs, which is outside a /56.
    Given a rate limiter allowing 1 qps with a burst of 1
    When 2001:db8:0:0000::1 exhausts its bucket
    Then a query from 2001:db8:0:0100::1 is allowed

  @hostile @enforced src/ratelimit.rs:631
  Scenario: An IPv4-mapped IPv6 source shares the bucket of its bare IPv4 form
    # A socket bound to [::] delivers IPv4 peers as ::ffff:a.b.c.d. If the two
    # forms key differently, an attacker gets two buckets per address by
    # switching transport.
    Given a rate limiter allowing 1 qps with a burst of 1
    When 198.51.100.1 exhausts its bucket
    Then a query from ::ffff:198.51.100.1 is denied

  @hostile @enforced src/ratelimit.rs:652
  Scenario: Two IPv4-mapped sources in different /24s stay in different buckets
    # THE ASSERTION THAT FAILS WITHOUT to_ipv4_mapped(). Unfolded, the top 56
    # bits of ::ffff:a.b.c.d are zero for every IPv4 client alive, so a /56 mask
    # collapses the entire IPv4 internet into one token bucket and a
    # [::]-bound server denies all of IPv4 at once. Ruling §2.4, F6.
    Given a rate limiter allowing 1 qps with a burst of 1
    When ::ffff:198.51.100.1 exhausts its bucket
    Then a query from ::ffff:203.0.113.1 is allowed

  @hostile @enforced src/ratelimit.rs:675
  Scenario: An IPv6 /56 never aliases the IPv4 /24 with the same payload
    # The canonical key carries a two-bit family tag. Without it, 198.51.100.0/24
    # and the /56 whose 56-bit payload happens to equal 0xC63364 are one bucket.
    Given a rate limiter allowing 1 qps with a burst of 1
    When 256 IPv4 /24s are each paired with the IPv6 /56 carrying the same payload
    And each IPv4 prefix exhausts its bucket
    Then all but a handful of the paired IPv6 prefixes are still allowed

  @hostile @enforced src/ratelimit.rs:702
  Scenario: A flood spread across one /64 is rate-limited as a single source
    # THE HEADLINE. 65,536 forged addresses inside 2001:db8::/64 — the smallest
    # allocation any LAN gets — one query each. Today all 65,536 are allowed and
    # all 65,536 are remembered, which is both the limiter failing to fire and
    # the memory exhaustion, from one attacker with one prefix. Ruling §13 A8.
    Given a rate limiter allowing 1 qps with a burst of 1
    When 65536 distinct addresses inside 2001:db8::/64 each send one query
    Then exactly 1 query is allowed
    And 65535 queries are denied

  # --------------------------------------------------------- THE BOUND

  @hostile @enforced src/ratelimit.rs:782
  Scenario: A flood of two million distinct spoofed prefixes does not grow the process
    # REPLACES the #[ignore]d `the_bucket_map_is_bounded`, un-ignored and with a
    # real bound instead of the placeholder `< 100_000`. This is the issue's
    # evidence table inverted: 2,000,000 sources measured at 356 MiB and still
    # climbing, OOM under the 128 MiB k8s limit at ~723,000 sources in 7.2 s.
    # The fixed table is 2,097,152 bytes whatever the traffic.
    Given a rate limiter allowing 1 qps with a burst of 1
    When 2000000 distinct /24s each send one query at the same instant
    Then process memory grows by less than 32 MiB
    And far fewer than 2000000 queries are allowed

  @hostile @enforced src/ratelimit.rs:734
  Scenario: The table size is a compile-time constant, not a function of traffic
    # Ruling §3.3: 2^18 slots x 8 bytes = 2,097,152 bytes, allocated once, never
    # grown, never shrunk, never pruned. The accessor must be derived from the
    # constant, so two limiters configured for wildly different loads report the
    # same size. Ruling §13 B1, B5.
    Given a limiter built for 1 qps and a limiter built for 1000000 qps
    When each is asked for its memory footprint
    Then both report the same number of bytes
    And the number is the slot count times eight

  @hostile @enforced tests/ratelimit.rs:69
  Scenario: The check path allocates nothing
    # The mutant this kills is "somebody put a map back". A check that allocates
    # is a check whose cost an attacker controls, at whatever rate they can send.
    # Asserted on ZERO under a counting global allocator, in its own
    # single-test binary because the allocator counts the whole process; a
    # threshold would let a smaller per-packet allocation back in. The
    # instrument is the stats_alloc dev-dependency, which keeps the unsafe impl
    # behind a crate boundary that unsafe_code = "forbid" does not reach, and it
    # clears cargo deny. Ruling §13 B3 as amended 2026-07-31.
    #
    # The source-text guard at tests/ratelimit.rs stays as a tripwire and is
    # still only a partial: it cannot see through a helper and misses format!,
    # to_owned, Box::new, collect and anything allocating inside hash_one.
    Given a limiter and one hundred thousand checks from distinct prefixes
    When the checks run
    Then no allocation is made on the check path

  @hostile @enforced src/ratelimit.rs:823
  Scenario: Random addresses of either family never index outside the table
    # The index is `hash & (SLOTS-1)` with SLOTS a power of two. A mutant using
    # `%` with a non-power-of-two, or an unmasked hash, panics here rather than
    # reading somebody else's slot. Ruling §13 B4.
    Given a rate limiter allowing 1 qps with a burst of 1
    When 1000000 pseudo-random addresses of both families each send one query
    Then no query panics

  @hostile @enforced src/ratelimit.rs:845
  Scenario: A mixed IPv4 and IPv6 flood stays bounded and does not alias
    Given a rate limiter allowing 1 qps with a burst of 1
    When 500000 IPv4 /24s and 500000 IPv6 /56s are interleaved
    Then process memory grows by less than 32 MiB
    And far fewer than 1000000 queries are allowed

  # -------------------------------------------------- BUCKET SEMANTICS

  @happy @enforced src/ratelimit.rs:486
  Scenario: A full burst is allowed before any traffic is denied
    Given a rate limiter allowing 1 qps with a burst of 3
    When one source sends 4 queries in the same instant
    Then the first 3 are allowed
    And the 4th is denied

  @happy @enforced src/ratelimit.rs:498
  Scenario: Tokens are restored as time passes
    Given a rate limiter allowing 10 qps with a burst of 1
    When one source exhausts its bucket
    And 100 milliseconds pass
    Then the next query from that source is allowed

  @boundary @enforced src/ratelimit.rs:510
  Scenario: Refill is capped at the burst size no matter how long the source was idle
    Given a rate limiter allowing 100 qps with a burst of 2
    When a source that has been idle for an hour sends 3 queries in the same instant
    Then the first 2 are allowed
    And the 3rd is denied

  @boundary @enforced src/ratelimit.rs:885
  Scenario: A partial refill below one token does not admit a query
    # Was @gap. 1 qps, 500 ms elapsed => half a token, which must not round up to
    # an admission. The milli-token integer arithmetic makes this exact; the old
    # f64 made it a rounding question. Ruling §13 C1.
    Given a rate limiter allowing 1 qps with a burst of 1
    When one source exhausts its bucket
    And 500 milliseconds pass
    Then the next query from that source is denied

  @boundary @enforced src/ratelimit.rs:898
  Scenario: Exactly one token's worth of elapsed time admits exactly one query
    # The other side of the same boundary: 999 ms denies, 1000 ms admits, and the
    # query after that is denied again.
    Given a rate limiter allowing 1 qps with a burst of 1
    When one source exhausts its bucket
    And exactly 1000 milliseconds pass
    Then the next query from that source is allowed
    And the query after it is denied

  @hostile @enforced src/ratelimit.rs:531
  Scenario: A clock reading that moves backwards does not grant extra tokens
    # The step back must stay under STALE_MAX = 60 s. A 32-bit stored timestamp
    # cannot tell "moved backwards by X" from "idle for 2^32 - X", so beyond that
    # band the reading is correctly granted a full bucket and this scenario would
    # pass for the opposite reason. Ruling §4.3, §13 C1 as amended.
    # A monotonic-clock regression here would hand an attacker a free refill on
    # every query.
    Given a rate limiter allowing 1 qps with a burst of 1
    When a source consumes its token at time T
    And the same source is checked with a clock reading of T minus 5 seconds
    Then the query is denied

  @empty @enforced src/ratelimit.rs:921
  Scenario: An untouched slot means a full bucket, not an empty one
    # Ruling §3.2: the table is one calloc, so the all-zero word must mean "full,
    # never touched". Storing tokens rather than the DEFICIT would make a zero
    # word mean "empty at time zero" and every untouched slot would deny for the
    # first burst/qps seconds of process life — a self-inflicted outage at every
    # restart. Checked at now == epoch exactly, so elapsed is 0 and no refill can
    # paper over the encoding. Ruling §13 C2.
    Given a freshly constructed rate limiter allowing 1 qps with a burst of 5
    When 5 queries arrive at the limiter's own epoch instant
    Then all 5 are allowed
    And the 6th is denied

  @hostile @enforced src/ratelimit.rs:948
  Scenario: Two prefixes that land on the same slot share the bucket and never reset it
    # The table never fills, so "full" is unrepresentable: collisions SHARE,
    # silently, exactly as Knot's fixed table does. Sharing is always
    # conservative — two prefixes drain one bucket, so each is limited tighter,
    # never looser. Detect-and-reset was REJECTED (§3.5): an attacker alternating
    # two colliding prefixes would reset the bucket to full on every packet and
    # never be limited at all. Ruling §13 C3.
    Given a rate limiter allowing 1 qps with a burst of 1
    And 4096 prefixes that have each exhausted their bucket
    When 4096 previously unseen prefixes each send their first query
    Then at least one of them is denied on its very first query

  @hostile @enforced src/ratelimit.rs:990
  Scenario: Which prefixes share a slot differs between processes
    # VEGA-020's acceptance criterion, moved. DefaultHasher has a documented
    # fixed zero seed: 62,664 addresses were found offline in 8.7 ms that all
    # land in the same shard, identically in every process. Under a fixed table
    # that stops being a contention bug and becomes a targeted-denial attack —
    # compute a prefix that collides with your victim's slot and drain their
    # bucket without ever sending them a packet. The per-process seed is what
    # makes silent sharing safe rather than exploitable. Ruling §5.2, §13 C4.
    Given two rate limiters constructed in the same process
    When the set of prefixes that collide with a fixed victim set is measured in each
    Then the two sets are substantially different

  @hostile @enforced src/ratelimit.rs:1045
  Scenario: A denied query does not write to its slot
    # Under a flood the denial path IS the hot path. A write-back per dropped
    # packet is a cache line bounced between every core for no semantic gain,
    # and a token bucket that refuses a query has not consumed anything. No
    # timing test catches this reliably, so it is asserted on the slot word.
    # Ruling §5.3 step 6, §13 C5.
    Given a rate limiter whose bucket for one prefix is empty
    When another query from that prefix is denied
    Then the slot word is byte-identical before and after

  @boundary @enforced src/ratelimit.rs:1073
  Scenario: No write ever touches the two reserved slot bits
    # Bits 63..62 of every slot are reserved for VEGA-041's SLIP counter and MUST
    # be written as zero. What guarantees it is the MAX_RATE clamp: burst is
    # capped at 1,000,000, so capacity_milli is 1.0e9 and the deficit cannot
    # reach 2^30. Asserted at the largest legal configuration, where the field is
    # closest to overflowing. Ruling §3.2, §12.
    Given a rate limiter built with the largest legal qps and burst
    When the bucket is filled to the brim one query at a time
    Then no slot word ever sets either reserved bit

  @hostile @enforced src/ratelimit.rs:1117
  Scenario: A reading that moved backwards grants nothing and stores nothing
    # REWRITTEN with the ruling's 2026-07-31 amendment, which also rewrote C6.
    # This scenario used to say "a gap longer than the wrap guard grants no
    # refill" and stepped 25 days FORWARD. That rule could not work: the denied
    # path stores nothing, so a slot denied by the guard never advanced last_ms,
    # recomputed the same out-of-range gap for ever, and stayed denied for up to
    # 24.86 days — not the 2 seconds the ruling claimed. A forward gap of 25 days
    # is now a long idle and is granted a full bucket; see the next scenario.
    #
    # What survives is the half that was always sound. last_ms is 32 bits of
    # milliseconds and wraps every 49.71 days, so "moved backwards by X" and
    # "idle for 2^32 - X" are the same bit pattern and the ambiguity is
    # irreducible. Inside STALE_MAX = 60 s the backwards reading is the
    # overwhelmingly more likely one: no refill, and no store either, because
    # storing would drag the slot's clock back and inflate the next reader's gap.
    # Ruling §4.3 as amended, §13 C6.
    Given a rate limiter allowing 1 qps with a burst of 1
    When a source exhausts its bucket and a reading 30 seconds earlier arrives
    Then the query is denied
    And the slot word is byte-identical before and after

  @hostile @enforced src/ratelimit.rs:1165
  Scenario: A genuinely long idle slot is full, not stuck
    # THE CRITERION THAT PINS THE AMENDMENT (C8, new 2026-07-31). An apparent gap
    # in [2^31, 2^32 - 60_000) — idle 24.86 to 46.6 days — reads as a long idle,
    # so the bucket is full and the query is ALLOWED. Because it is allowed it
    # stores its timestamp through the ordinary path, which is what gets the slot
    # out of the ambiguous window. Nothing is added to the denied path, so C5
    # stands unchanged and §5.3 step 6's rationale is untouched.
    #
    # Granting a full bucket concedes nothing: §4.2 proves a slot idle past
    # T_full is indistinguishable from one never touched, and an untouched slot
    # is full — the same grant is free from any unused prefix. The second and
    # third queries are what matter: under the superseded rule the first is
    # denied and so is every one after it, for up to 24.86 days, and because
    # VEGA-004 drops rather than REFUSEs on UDP the symptom is a legitimate
    # resolver's whole /24 silently dropped for three and a half weeks with
    # nothing in the logs but dns_rate_limited_total ticking. Ruling §4.3.1.
    Given a rate limiter allowing 1 qps with a burst of 1
    When a source empties its bucket and returns 30 days later
    Then the query is allowed
    And the next query one second later is also allowed

  @boundary @enforced src/ratelimit.rs:1208
  Scenario: A backwards step beyond the stale window is read as a long idle
    # The other side of the split, and what pins where it sits: 30 seconds back
    # is denied, 90 seconds back is granted a full bucket. Either alone leaves
    # STALE_MAX free to drift; together they bracket it. This is also why a
    # backwards-clock test must inject a delta under a minute (C1) — a later
    # "strengthening" to a month-long step would start passing for the opposite
    # reason. Ruling §4.3, §13 C8.
    Given a rate limiter allowing 1 qps with a burst of 1
    When a source empties its bucket and a reading 90 seconds earlier arrives
    Then the query is allowed

  @boundary @enforced src/ratelimit.rs:1232
  Scenario: A gap just short of the wrap guard still refills normally
    # 24 days is under the 24.86-day guard, so the arithmetic is trusted and the
    # bucket refills to the burst. A mutant that clamps too eagerly — say at
    # 2^30 — denies a legitimate resolver that went quiet over a long weekend.
    Given a rate limiter allowing 1 qps with a burst of 1
    When a source exhausts its bucket and returns 24 days later
    Then the query is allowed

  @malformed @enforced src/ratelimit.rs:1253
  Scenario: A zero qps and a zero burst are clamped rather than panicking
    # `assert!(qps > 0 && burst > 0)` is unreachable today because config.rs
    # rejects it — but `panic = "abort"` in release means one slipped invariant
    # is a full outage, and CLAUDE.md forbids a panic on any path reachable from
    # a network packet. Construction gains no failure mode. Ruling §5.6, §13 C7.
    Given a rate limiter constructed with 0 qps and 0 burst
    When one source sends 2 queries in the same instant
    Then the constructor does not panic
    And the first query is allowed
    And the second is denied

  @malformed @enforced src/ratelimit.rs:1270
  Scenario: A qps and burst of u32::MAX are clamped rather than overflowing
    # capacity_milli must stay inside the 30-bit field with bits 63..62 reserved
    # zero for VEGA-041. MAX_RATE = 1,000,000 keeps burst*1000 under 2^30.
    Given a rate limiter constructed with u32::MAX qps and u32::MAX burst
    When 1000 queries arrive from one prefix in the same instant
    Then the constructor does not panic
    And every query is allowed

  # ------------------------------------------------------- CONCURRENCY

  @hostile @enforced src/ratelimit.rs:1300
  Scenario: Concurrent checks never hand out more than the burst
    # RELAXED from "exactly burst" to "at most burst" by ruling §13 D1: the CAS
    # loop is bounded at 8 attempts and FAILS CLOSED, so extreme contention may
    # legitimately admit fewer. Failing open would hand an attacker an off-switch
    # for the limiter — manufacture contention, get admitted. This relaxation is
    # only sound because the scenario below pins the exact count at low
    # concurrency; on its own it would hollow the test out.
    Given a rate limiter allowing 1 qps with a burst of 500
    When 16 threads each send 200 queries from one prefix at one frozen instant
    Then at most 500 queries are allowed
    And at least one query is denied

  @happy @enforced src/ratelimit.rs:1353
  Scenario: A single-threaded run hands out exactly the burst
    # The other half of the pair above. This is where the token arithmetic is
    # pinned; the concurrent test only pins the safety direction.
    Given a rate limiter allowing 1 qps with a burst of 500
    When one prefix sends 700 queries at one frozen instant on one thread
    Then exactly 500 are allowed

  @boundary @enforced src/ratelimit.rs:1369
  Scenario: Two threads at a barrier still hand out exactly the burst
    # Two writers is enough to exercise the CAS retry and not enough to exhaust
    # the 8-attempt bound, so the exact count must survive.
    Given a rate limiter allowing 1 qps with a burst of 500
    When 2 threads each send 400 queries from one prefix at one frozen instant
    Then exactly 500 are allowed

  @hostile @enforced src/ratelimit.rs:1413
  Scenario: A sustained storm against a single slot completes in bounded time
    # CLAUDE.md bounds every loop on the query path, and a CAS loop is the
    # classic place that rule is broken. A mutant that removes the 8-attempt cap
    # hangs here instead of passing review. Ruling §13 D3, G2.
    Given a rate limiter allowing 1 qps with a burst of 1
    When 8 threads each send 100000 queries from the same prefix
    Then the run completes within 60 seconds
    And at most 1 query is allowed

  @hostile @enforced src/ratelimit.rs:1469
  Scenario: Concurrent checks across many distinct prefixes all land
    # SUPERSEDES "Many distinct sources are tracked without loss across shards",
    # which counted `tracked()` — an accessor VEGA-003 deletes, over addresses
    # that all shared one /24 under the new key. A lost update here would
    # silently stop limiting some fraction of sources.
    Given a rate limiter allowing 1 qps with a burst of 1
    When 8 threads each send one query from 500 distinct /24s
    Then no thread panics
    And all but a small fraction of the 4000 queries are allowed

  # ------------------------------------ DELETIONS AND NON-REGRESSIONS

  @hostile @enforced tests/ratelimit.rs:100
  Scenario: Pruning and the janitor cannot come back
    # A structural guard, in the style of VEGA-046's. `prune`, `prune_at`,
    # `tracked`, DEFAULT_IDLE_TTL, JANITOR_INTERVAL and `spawn_janitor` are
    # deleted by this ruling; a mutant or a well-meaning revert that
    # reintroduces a background sweep must fail a test, not merely a review. The
    # janitor was a query-path stall (an O(n) retain under a shard mutex an
    # attacker can concentrate) and it could not win its race: 600 s TTL against
    # a map that reached the 128 MiB limit in 7.2 s. Ruling §1.4, §1.5, §13 E1.
    Given the source tree
    When src/ratelimit.rs and src/main.rs are read
    Then neither mentions prune, tracked, an idle TTL, a janitor interval or a janitor task

  @hostile @enforced tests/integration.rs:357
  Scenario: A rate-limited UDP query is answered with silence
    # VEGA-004, preserved unchanged. Replying REFUSED still delivers a packet to
    # whatever source the attacker forged, so the limiter would have reduced our
    # byte count and not the victim's packet count. Prefix aggregation makes this
    # more important, not less: the set of addresses that get silence is now a
    # whole /24 of forgeable victims. Ruling §6.1 I1, §13 E3.
    Given a running server with a rate limiter allowing 1 qps with a burst of 1
    When the same client sends two UDP queries in quick succession
    Then the first response rcode is NOERROR
    And the second query receives no response at all

  @happy @enforced tests/integration.rs:394
  Scenario: A rate-limited TCP query is refused rather than dropped
    # TCP completed a handshake, so the source is proved and a reply cannot be
    # reflected at a third party. It is also the recovery path for a legitimate
    # resolver aggregated into an attacked /24: REFUSED is a poor answer but it
    # is a signal rather than a timeout. Ruling §6.1 I3.
    Given a running server with a rate limiter allowing 1 qps with a burst of 1
    When the same client sends two TCP queries in quick succession
    Then the first response rcode is NOERROR
    And the second response rcode is REFUSED

  @happy @enforced src/handler.rs:934
  Scenario: The handler consults the limiter before resolving
    Given a handler with a rate limiter allowing 1 qps with a burst of 1
    When the same client is checked twice
    Then the first check is allowed
    And the second check is denied

  @hostile @gap
  Scenario: A rate-limited query is refused before its opcode is even inspected
    # STILL A GAP, and it must stay one until somebody owns tests/integration.rs:
    # the limiter check precedes message-type and opcode validation, so a flood
    # of malformed packets is dropped just as cheaply as valid ones. That
    # ordering is a deliberate DoS property, VEGA-003 must not move it (ruling
    # §6.1 I2, §9), and nothing pins it. Needs the integration harness to build
    # an opcode-UPDATE message; it cannot be written from src/ratelimit.rs.
    Given a handler with a rate limiter whose bucket is empty
    When a message with opcode UPDATE arrives over TCP
    Then the response rcode is REFUSED
    And the opcode is never inspected

  @happy @enforced tests/reload.rs:1086
  Scenario: A reload that changes the rate limit reports it as ignored
    # VEGA-005, preserved. The limiter is constructed once in serve(); a reload
    # that appeared to change it would be a lie to the operator. VEGA-003 must
    # not need to touch these tests — if it does, the ruling was exceeded.
    # Ruling §10, §13 E5.
    Given a running server with rate_limit qps 10
    When a reload raises rate_limit qps to 1000
    Then the reload reports server.rate_limit.qps as ignored
    And the effective limit is still 10 qps

  # ------------------------------------------------------ OBSERVABILITY

  @happy @enforced tests/reload.rs:1086
  Scenario: A rate-limited query is counted in the rate-limited metric
    # Was @gap. It is the one line an operator watches during an attack, and it
    # is already asserted by the reload suite's rate-limit precedence tests.
    # Ruling §13 F4.
    Given a running server with a rate limiter allowing 10 qps
    When a client sends 40 queries in quick succession
    Then dns_rate_limited_total is greater than 0

  @happy @enforced tests/ratelimit.rs:142
  Scenario: The limiter exposes a constant slot count and a live occupancy gauge
    # `dns_ratelimit_tracked` as requested by VEGA-043 is UNIMPLEMENTABLE after
    # this change — nothing is tracked, source cardinality is deliberately not
    # retained, and shipping a plausible number that does not mean what its name
    # says is worse than renaming it. Two gauges replace it, both computed on
    # scrape with relaxed loads, no task and no lock. The pair is what tells an
    # operator whether they are seeing a concentrated attack (total rising,
    # active low) or a maximal-diversity flood collapsing the table into a global
    # limiter (active approaching slots). Ruling §8, §13 F1, F2.
    Given a limiter that has been queried
    When the metrics are rendered
    Then dns_ratelimit_slots is present and constant
    And dns_ratelimit_active is present and no greater than dns_ratelimit_slots

  @empty @enforced tests/ratelimit.rs:212
  Scenario: The limiter gauges are absent when rate limiting is off
    # Rate limiting is off unless configured, and there is then no table. A
    # series reporting 262,144 slots for a limiter that does not exist would have
    # an operator alerting on a saturation that cannot happen. Ruling §8.
    Given a server with no rate limiter configured
    When the metrics are rendered
    Then no dns_ratelimit series is present

  @hostile @gap
  Scenario: A scrape concurrent with sustained queries neither deadlocks nor corrupts the exposition
    # The occupancy walk is 262,144 relaxed loads over 2 MiB on the admin scrape
    # thread — ~100-300 us, taking no lock and blocking nothing. Needs the admin
    # harness, which lives in a file this agent does not own. Ruling §13 F3.
    Given a running server under sustained query load
    When /metrics is scraped repeatedly
    Then every scrape parses as valid Prometheus exposition
    And no query is blocked by a scrape

  # ------------------------------------ OPERATIONAL BREAKING CHANGE

  @hostile @enforced src/ratelimit.rs:1524
  Scenario: The configured qps applies to a whole /24, not to each host inside it
    # THE BREAKING CHANGE, stated so nobody discovers it in production. `qps` used
    # to mean per source ADDRESS; it now means per /24 or per /56. An operator
    # running qps = 50 whose traffic comes from a resolver farm of 200 hosts in
    # one /24 is currently granting that farm 10,000 qps and will be granting it
    # 50. It will look like an outage and it is not a bug. Guidance for the
    # CHANGELOG, README and vega.example.toml: size qps for the busiest single
    # /24 you serve, not for a single resolver. Blast radius is limited by rate
    # limiting being off unless configured, so no default deployment changes.
    # Ruling §7, §11 F1.
    Given a rate limiter allowing 50 qps with a burst of 50
    When 200 hosts inside one /24 each send one query at the same instant
    Then exactly 50 queries are allowed
    And 150 are denied

  # ----------------------------------------------------- CONFIGURATION

  @happy @enforced src/config.rs:821
  Scenario: The burst defaults to twice the configured qps
    Given the configuration sets rate_limit qps to 25 and no burst
    When the configuration is resolved
    Then the effective qps is 25
    And the effective burst is 50

  @boundary @gap
  Scenario: An explicitly configured burst overrides the doubling default
    # `cli.rate_limit_burst.or(file...).unwrap_or(qps*2)`. The explicit branch has
    # no test, so a regression that always doubled would go unnoticed.
    Given the configuration sets rate_limit qps to 25 and burst to 5
    When the configuration is resolved
    Then the effective burst is 5

  @boundary @gap
  Scenario: A burst of one allows exactly one query before denial
    # The tightest legal setting, and the one used by the integration test. The
    # unit tests never exercise burst == 1 at the config layer.
    Given the configuration sets rate_limit qps to 1 and burst to 1
    When the configuration is resolved
    Then the effective burst is 1

  @empty @enforced src/config.rs:829
  Scenario: A qps of zero disables rate limiting entirely
    Given the configuration sets rate_limit qps to 0
    When the configuration is resolved
    Then no rate limiter is configured

  @empty @enforced src/config.rs:781
  Scenario: Rate limiting is off by default
    Given no rate limit is configured
    When the configuration is resolved
    Then no rate limiter is configured

  @empty @gap
  Scenario: With no limiter configured the handler never refuses on rate grounds
    # `if let Some(limiter) = &self.limiter` short-circuits. Nothing asserts a
    # limiter-less handler answers an unbounded number of queries.
    Given a handler with no rate limiter
    When one client sends 100 queries in the same instant
    Then every response rcode is NOERROR

  @malformed @gap
  Scenario: A burst of zero alongside a non-zero qps is rejected at startup
    # src/config.rs bails. The line is uncovered: a config that would deny every
    # single query — a self-inflicted total outage — currently has no test.
    Given the configuration sets rate_limit qps to 10 and burst to 0
    When the configuration is resolved
    Then the configuration is rejected with an error mentioning "burst"

  @malformed @gap
  Scenario: A burst configured without a qps is ignored rather than applied
    # `qps` of None short-circuits the whole match, silently discarding the burst.
    # An operator who sets only the burst gets no limiting and no warning.
    Given the configuration sets rate_limit burst to 5 and no qps
    When the configuration is resolved
    Then no rate limiter is configured
