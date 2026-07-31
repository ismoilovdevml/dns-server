# Traceability key used throughout features/:
#   @enforced <path>:<line>  — a Rust test exists and asserts this behaviour
#   @gap                     — no test enforces this scenario; it is a known hole
#   @wip                     — the behaviour is not reachable from any public
#                              surface yet; the scenario is the obligation and
#                              the commit named in the comment must discharge it
#   @category tags           — happy | boundary | empty | malformed | hostile

Feature: The zone data model — canonical order, the suffix hash, and the node arena
  # WHY THIS MATTERS
  #
  # Every answer this server gives comes out of one data structure, and VEGA-032
  # replaces it. The replacement lands as six commits (S0..S5). This file specs
  # the first two, and only the first two.
  #
  #   S0 — primitives, wired to nothing: a byte key whose sort order is RFC 4034
  #        §6.1 canonical DNS name order, and a one-pass hash of every suffix of
  #        a query name.
  #   S1 — the arena: three flat Box<[T]> plus a hash index, replacing the
  #        parallel maps. NO ENTs, NO closest encloser, NO delegation. Every
  #        answer stays byte-identical.
  #
  # Two different failure modes, and they need two different kinds of scenario.
  #
  # S0's failure is INVISIBLE. Nothing consumes canonical order until DNSSEC
  # signs a zone, and at that point a mis-ordered arena means the NSEC chain
  # does not close and every validating resolver SERVFAILs the entire zone —
  # total, sudden, and traced back to a sort written months earlier. There is no
  # behaviour to observe today, so the order is pinned against the RFC's own
  # printed example vector and against LowerName: Ord, now, before there is a
  # consumer to notice.
  #
  # S1's failure is a WRONG ANSWER. It rewrites the lookup path with no
  # behavioural mandate at all, so the only claim it makes — "nothing observable
  # changes" — has to be mechanised rather than reviewed. A differential against
  # a transcription of today's implementation is that mechanisation: if any
  # generated zone and any generated query disagree by so much as a TTL, S1 is
  # wrong. Reading 700 lines of arena construction is not a substitute and is
  # not what anyone will actually do.
  #
  # WHAT MUST NOT MOVE, and is pinned here on purpose
  #
  #  * VEGA-065: label_count (asterisks counted), MAX_LABELS = 127, the ban on
  #    num_labels in any module that indexes a name by label depth, and the
  #    RFC 4592 §3.3.1 window reasoning. The u128 wildcard_depths bitmap is
  #    SUBSUMED by ancestor closure at S2/S3, not undone — and at S1 it is still
  #    there, recomputed over wildcard nodes. Its measured numbers (88 ns
  #    shallow, 1.657 µs at 123 labels, 9.1 µs per-query budget) are the S1 gate.
  #  * VEGA-083: Zone::exists keeps its signature and its RFC 1034 §4.3.2 step
  #    3(c) contract, coverage stays per-parent and never per-depth, and a
  #    wildcard-covered name answers NODATA for every type the wildcard lacks.
  #  * The three #[ignore]d tests pinning VEGA-006 and VEGA-009 stay RED through
  #    S0 and S1. They go green at S2 and S3. One turning green at S1 means S1
  #    changed behaviour and S1 is wrong.
  #
  # Implementation: src/zone.rs
  # Ruling: .claude/backlog/decisions/VEGA-032-zone-data-model.md §10.2, §13
  # Composes with: VEGA-065 (bounded walk), VEGA-083 (Zone::exists)

  Background:
    Given a zone with origin "example.com"
    And a zone default TTL of 300 seconds
    And an SOA record with minimum 60

  # =========================================================================
  # S0 — CANONICAL ORDER
  # =========================================================================
  # WHY THIS SECTION MATTERS
  #
  # The arena is physically sorted from the first commit, and sorting 100,000
  # names through LowerName: Ord is hundreds of milliseconds of label-by-label
  # comparison on every reload. So the sort runs on a precomputed byte key and
  # the key's order must EQUAL Ord's order — not approximate it, not agree on
  # the names anyone writes. "My key function equals the RFC" is exactly the
  # kind of claim that is wrong once, silently, in the case nobody generated.
  #
  # RFC 2181 §11 permits any octet in a label, including 0x00. A plain 0x00
  # terminator is therefore NOT order-preserving, and the counterexample is two
  # names apart: p.a.root vs q.a\000.root. Measured against hickory 0.26.1,
  # LowerName: Ord says Less and a plain-terminator key says Greater. The escape
  # (0x00 -> 0x00 0x01, separator 0x00 0x00) is load-bearing, not decoration.

  @happy @enforced tests/canonical_order.rs:174
  Scenario: RFC 4034 §6.1's own nine-name example sorts into the order the RFC prints
    # The RFC prints the answer. Transcribing it is the one test that cannot be
    # wrong in the same direction as the implementation, because it was written
    # by the people who defined the ordering, and it deliberately includes
    # "*.z.example" so the asterisk's sort position is pinned by the RFC's text
    # rather than by our reading of it.
    Given the nine names of RFC 4034 §6.1 in a shuffled order
    When they are sorted by the canonical sort key
    Then the result is the order printed in the RFC

  @happy @enforced tests/canonical_order.rs:256
  Scenario: The canonical sort key orders every name exactly as LowerName Ord does
    # hickory's cmp_labels IS RFC 4034 §6.1 — it zips reversed label iterators,
    # compares octets case-insensitively, then label lengths, then label counts.
    # The key exists only to make that comparison cheap. Any input where the two
    # disagree is a defect in the key, and the generator draws the inputs the
    # hand-written cases would not: NUL and 0xff octets, mixed case, names that
    # are proper suffixes of each other, 1 to 127 labels.
    Given any two names built from arbitrary label octets
    When both are compared by the canonical sort key and by LowerName Ord
    Then the two comparisons agree, including on equality

  @boundary @enforced tests/canonical_order.rs:298
  Scenario: A label containing a NUL octet sorts by the escaped key, and a plain terminator inverts it
    # The specific counterexample from the ruling §7.2, measured rather than
    # argued. Without this scenario the escape looks like paranoia and the first
    # person to simplify the key removes it, and nothing in the suite notices
    # until a zone containing a NUL-bearing label is signed.
    Given the names "p.a.root." and "q.a\000.root."
    When they are ordered by LowerName Ord
    Then "p.a.root." sorts first
    And the escaped canonical key agrees
    And a key using a plain 0x00 terminator instead reverses them

  @boundary @enforced tests/canonical_order.rs:338
  Scenario: Two names differing only in case are equal under the canonical key
    # RFC 4034 §6.1 compares octets case-insensitively, and RFC 4343 says the
    # same about matching. A key that lowercases inconsistently would put the
    # same owner name in the arena twice and break the index round trip.
    Given the names "Z.a.EXAMPLE." and "z.a.example."
    When they are compared by the canonical sort key
    Then they compare equal

  @boundary @enforced tests/canonical_order.rs:361
  Scenario: A name sorts before every name that has it as a proper suffix
    # Ancestors precede descendants, which is the property the whole arena rests
    # on: node 0 is the apex, cut propagation is one linear pass because every
    # parent has already been visited, and the NSEC next owner of node i is node
    # i+1. A key that got this backwards would not be caught by any answer.
    Given the names "example.", "a.example." and "b.a.example."
    When they are sorted by the canonical sort key
    Then "example." precedes "a.example." and "a.example." precedes "b.a.example."

  @empty @enforced tests/canonical_order.rs:383
  Scenario: The root name is the smallest key there is
    # The empty case of the key function, and it is reachable: origin = "." is
    # an accepted configuration, so the root really is a node in some zones.
    Given the root name "."
    When it is compared by the canonical sort key against any other name
    Then the root sorts first

  @malformed @enforced tests/canonical_order.rs:412
  Scenario: A label made entirely of 0xff octets is ordered as data, not as a delimiter
    # The other end of the octet range from the NUL case. RFC 2181 §11 permits
    # it; a key that treated any octet as structural rather than as content
    # would misplace it.
    Given a label of 0xff octets and an ordinary label
    When both are compared by the canonical sort key and by LowerName Ord
    Then the two comparisons agree

  @hostile @enforced tests/canonical_order.rs:435
  Scenario: Names chosen to collide under a naive key still sort correctly
    # An operator picks the names in a zone, but a zone file can be generated
    # from attacker-supplied input (a hosting control panel, a DDNS front end).
    # Families of names that agree on a long shared prefix and differ only in a
    # boundary octet are what break a hand-rolled key.
    Given families of names that share every label but one boundary octet
    When they are sorted by the canonical sort key
    Then the order equals sorting them by LowerName Ord

  # =========================================================================
  # S0 — THE SUFFIX HASH
  # =========================================================================
  # WHY THIS SECTION MATTERS
  #
  # Every probe of the arena is "does a node exist at the d rightmost labels of
  # this query name". Today that materialises a name through trim_to, which
  # allocates two Vecs — measured at 1 allocation per negative query in a
  # wildcard zone, 5 for a 123-label miss. The suffix hash removes them: one
  # reverse pass over the name into a [u64; 128] stack array, and h[d] is the
  # hash of the d rightmost labels.
  #
  # The array is indexed by a label count derived from a name an attacker chose.
  # Under panic = "abort" one out-of-range index is a full outage, so the label
  # ceiling is not a tuning knob: RFC 1035 §2.3.4 caps a name at 255 octets and
  # §3.1 spends two octets on a single-octet label plus one terminator, so
  # 2n + 1 <= 255 and n <= 127. Measured against hickory 0.26.1: 127 labels
  # decode, 128 labels are rejected with DomainNameTooLong(257).
  #
  # 127, not 123. 123 is the ceiling for names under "example.com." only, and it
  # is wrong wherever the tests use it as a protocol limit.

  @happy @wip src/zone.rs — S0 commit
  Scenario: The suffix hash at every depth equals hashing that suffix directly
    # The whole correctness claim of the one-pass hash, and it is not observable
    # from outside the crate: the primitive is pub(crate) by the ruling's §10.1,
    # deliberately, because a pub API with no caller is its own defect. The test
    # is a unit test in src/zone.rs and the S0 commit must carry it.
    Given a name of between 1 and 127 labels
    When the suffix hashes are computed in one reverse pass
    Then h[d] equals the hash of that name's d rightmost labels, for every d

  @boundary @wip src/zone.rs — S0 commit
  Scenario: A 127-label name produces 128 suffix hashes and allocates nothing
    # h[0] is the root, so a 127-label name fills 128 entries — the exact width
    # of the stack array. One index past it is an out-of-bounds read on a path
    # an attacker reaches with a single 271-byte packet.
    Given a name with exactly 127 labels
    When the suffix hashes are computed
    Then there are 128 entries and the pass performs no heap allocation

  @boundary @enforced tests/canonical_order.rs:574
  Scenario: A name one label past the ceiling never reaches the zone at all
    # The upstream fact the [u64; 128] array is sized from. If hickory ever
    # accepted a 128-label name, the array would be indexed out of range by a
    # packet. Pinned here so a dependency bump cannot quietly invalidate it.
    Given a name of 128 single-octet labels
    When it is parsed
    Then hickory rejects it as longer than 255 octets

  @hostile @enforced src/zone.rs:1914
  Scenario: A name of maximum-length labels is answered rather than mis-indexed
    # The other shape at the 255-octet limit: three 63-octet labels instead of
    # 127 one-octet ones. A hash pass that walked octets rather than label
    # boundaries, or sized a buffer from octets rather than labels, breaks here
    # and nowhere else in the suite.
    Given a zone holding a wildcard at the apex
    When a client queries a name of three 63-octet labels
    Then the query is answered rather than panicking

  @hostile @enforced tests/canonical_order.rs:482
  Scenario: The banned label-counting function stays out of every module that indexes by depth
    # num_labels() discounts a leading asterisk; trim_to and the suffix hash
    # index the raw count. Mixing them shifts every probe one label off for any
    # name whose leftmost label is "*" — four silent wrong answers on the
    # authoritative path, which is VEGA-065's whole finding. The ban is stated
    # in a doc comment on label_count; this is what makes it a check, and it
    # follows the code into whatever module S0 puts the primitives in rather
    # than naming src/zone.rs.
    Given every source file that indexes a name by label depth
    When they are scanned for the banned function
    Then none of them names it outside a comment explaining the ban

  # =========================================================================
  # S1 — THE ARENA, BEHAVIOUR-PRESERVING
  # =========================================================================
  # WHY THIS SECTION MATTERS
  #
  # S1 is the largest diff in the sequence and the only one whose acceptance
  # criterion is a negative: no input produces a different answer. A reviewer
  # cannot establish that by reading, and the tests that exist today were not
  # written to establish it either — they assert the shapes somebody thought of.
  #
  # So the gate is a differential. Today's implementation is transcribed as an
  # oracle NOW, while it is still the thing being served, and every generated
  # zone and query is put through both. Zero permitted transitions: same Answer
  # variant, same records, same owner names, same TTLs, same rdata, in the same
  # order. The transcription must never be updated to match a new
  # implementation — the moment it is, the property stops testing anything.

  @hostile @enforced tests/arena_differential.rs:686
  Scenario: The arena answers exactly what today's implementation answers, for every zone and every query
    # The only claim S1 makes. Cases are CONSTRUCTED, not filtered: query names
    # are drawn out of the zone that was just generated — its exact owners, its
    # wildcard parents, those parents with a prefix stacked on, names that are
    # ancestors of an owner, CNAME owners and CNAME targets — so every case
    # exercises a real branch. Generating a zone and a name independently and
    # rejecting the pairs that do not interact is how the previous property test
    # in this tree reached 1024 global rejects on CI and passed locally on a
    # luckier seed. A test that depends on the generator being lucky is not a
    # test.
    Given any zone the generator produces
    And any query name constructed from that zone's own structure
    When it is looked up
    Then the Answer variant matches a transcription of today's implementation
    And the records match in owner name, TTL, rdata and order

  @boundary @enforced tests/arena_differential.rs:777
  Scenario: The differential covers ANY, CNAME chasing and the negative paths, not only wildcards
    # The existing differential (VEGA-065's) excludes CNAME and ANY on purpose,
    # because that issue did not touch them. S1 touches every branch of the
    # lookup, so an oracle that skips two of them is not a gate on S1. This is
    # the same property restricted to the branches the older one leaves out, so
    # that a regression there cannot hide behind a green wildcard suite.
    Given a zone containing a CNAME chain, a wildcard and an apex record
    When each name is queried for A, ANY and CNAME
    Then every answer matches the transcription exactly

  @happy @enforced src/zone.rs:1273
  Scenario: VEGA-065's four asterisk-in-the-name behaviours survive the arena unmodified
    # Wildcards stop being a parent-keyed map at S1 and become nodes named
    # "*.x" (RFC 4592 §2.1.1). These four are the cases a wrong label-count
    # index breaks, and they are the ones that caught the rejected VEGA-065
    # patch. They must pass with their assertions untouched — not adapted, not
    # relaxed.
    Given the zone holds a wildcard at the apex and a nested "*.*.dev"
    When each wildcard's own literal name is queried
    Then all four answers are unchanged from today

  @happy @enforced src/zone.rs:1381
  Scenario: The deepest wildcard still wins at S1, because closest-encloser is S3's
    # RFC 4592 §3.3.1's closest-encloser rule would make "*.dev" NOT answer
    # under a name whose closest encloser is deeper. That is the fix, and it is
    # S3's. Landing half of it inside S1 is the failure mode this scenario
    # exists to catch: S1 keeps deepest-wins, byte for byte.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    And the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type A
    Then the answer holds 203.0.113.50

  @boundary @enforced src/zone.rs:1843
  Scenario: Wildcard coverage is still decided per parent and never per depth
    # VEGA-083's AC-5, restated as an obligation on the arena. "*.dev" sits at
    # depth 3 and so does "other.example.com". Reading coverage off a depth
    # bitmap makes almost every name in a wildcard zone exist, and the failure
    # is silent: the server stops saying NXDOMAIN about names it denies.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "q.other.example.com." for type A
    Then the response rcode is NXDOMAIN

  @boundary @enforced src/zone.rs:1760
  Scenario: A wildcard-covered name is still NODATA for every type the wildcard does not carry
    # VEGA-083's ruling is an obligation on this model, not a behaviour the
    # rewrite gets to renegotiate. The arena must satisfy it from the node
    # model rather than from a coverage flag, and the answer must not move.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type AAAA
    Then the lookup result is NoData

  @boundary @enforced src/zone.rs:2047
  Scenario: The three RFC defects VEGA-032 fixes later are still red after S1
    # S2 fixes empty non-terminals, S3 fixes the closest encloser. If one of
    # them turns green at S0 or S1, the commit went outside its fence and the
    # commit is wrong, not the test. The ignore reasons are pinned verbatim by a
    # source-level guard, and that guard may be edited ONLY by the commit that
    # makes the corresponding test pass.
    Given the S0 or S1 commit
    When the ignored RFC tests are run
    Then all three still fail, and their ignore reasons are unchanged

  # ------------------------------------------------------------- MEMORY

  @boundary @enforced tests/zone_memory.rs:326
  Scenario: A 100,000-record zone costs at most 40 MiB of live heap
    # Measured today: 134,227,984 bytes live, 128.0 MiB, 1,342 B/record, in
    # 600,035 allocations. The owner Name is stored once per RECORD; it becomes
    # once per NODE. The TTL moves to the RRset (RFC 2181 §5) and the class to
    # the zone (Vega is IN-only). The arena has no spare capacity anywhere.
    #
    # This is not a vanity number. VEGA-069 measured RSS ratcheting 1,736 ->
    # 2,676 -> 3,095 MiB across three reloads of a 1M-record zone, attributed to
    # freeing and re-allocating a million small blocks. Three allocations
    # instead of 300,000 is what removes that mechanism.
    Given a zone of 100,000 single-value A records
    When it is built
    Then its live heap is at most 40 MiB

  @boundary @enforced tests/zone_memory.rs:326
  Scenario: An answer vector is not over-allocated
    # Measured today: a one-record answer comes back in a Vec of capacity 4 —
    # 816 wasted bytes, per query, on the hot path. Vec's minimum non-zero
    # capacity, paid because the answer is collected without a size hint. The
    # arena knows the rdata range's length before it copies anything.
    Given a zone holding one A record at a name
    When that name is looked up
    Then the answer vector's capacity equals its length

  @boundary @enforced tests/zone_memory.rs:326
  Scenario: A negative answer in a wildcard zone allocates nothing at all
    # Measured today, per query: uncovered NXDOMAIN 1, covered type-miss 1,
    # 123-label miss 5. Every one of them is trim_to materialising a parent name
    # the probe throws away. The negative path is the path an attacker picks,
    # because it is the only one they can drive without knowing the zone, so its
    # allocation count is an attacker-set cost.
    #
    # The assertion is on ZERO, not on a threshold. A threshold lets a smaller
    # allocation back in.
    Given a 100,000-record zone that also holds a wildcard
    When an uncovered name, a covered name of the wrong type and a 123-label
      name are each looked up a thousand times
    Then no allocation is performed on any of them

  # ------------------------------------------------------------ STRUCTURE

  @boundary @wip src/zone.rs — S1 commit
  Scenario: The arena is physically in RFC 4034 §6.1 canonical order
    # Nothing consumes the ordering at S1, which is exactly why it is asserted
    # at S1: an ordering nothing exercises is an ordering nobody notices is
    # wrong until a validating resolver SERVFAILs the zone. Asserted directly on
    # the arena, pairwise under LowerName: Ord, over a zone containing the RFC's
    # own example names. Not reachable from outside the crate — the arena is
    # pub(crate) by §10.1 — so the S1 commit must carry this as a unit test.
    Given a zone whose owner names are RFC 4034 §6.1's example vector
    When the arena is built
    Then every adjacent pair of nodes is strictly increasing under LowerName Ord

  @boundary @wip src/zone.rs — S1 commit
  Scenario: Node 0 is the apex and every node's parent has a lower index
    # The two structural facts the rest of the design reads as given: cut
    # propagation is one linear pass because parents are already visited, and
    # NodeIdx::APEX is a constant rather than a search. Both are consequences of
    # canonical order, and both stop being true silently if the sort changes.
    Given any zone the generator produces
    When the arena is built
    Then node 0 is the zone apex
    And every non-apex node's parent appears at a lower index

  @boundary @wip src/zone.rs — S1 commit
  Scenario: Every node round-trips through the hash index
    # The index and the arena are built in one function from one scratch map and
    # dropped together, so they cannot drift across a reload. The failure this
    # guards is a build-time one: a configured record answering NXDOMAIN with
    # nothing in the log.
    Given any zone the generator produces
    When each node's owner name is probed against the index
    Then the probe returns that node, for every node

  # --------------------------------------------------------------- EMPTY

  @empty @enforced src/zone.rs:1971
  Scenario: A zone holding nothing but its apex answers every shape without panicking
    # The smallest arena that can exist: one node, no RRsets, no wildcards, an
    # empty index bucket for everything else. Every branch of the lookup is
    # reachable on it, and each one is an opportunity to index an empty slice.
    Given the zone contains no records
    When the apex, a name below it, a name above it and the root are queried
    Then each is answered and none panics

  @empty @enforced tests/arena_differential.rs:686
  Scenario: A zone whose config declares no records at all still agrees with the transcription
    # The generator produces empty zones; this pins that they are not skipped.
    # An arena builder that special-cased "no records" and returned early is the
    # kind of thing that passes every populated test.
    Given a config with an empty record list
    When any name is looked up
    Then the answer matches the transcription

  # ----------------------------------------------------------- MALFORMED

  @malformed @enforced src/zone.rs:1009
  Scenario: An owner name outside the zone still fails the build after the rewrite
    # qualify() is the only thing standing between a config and a record for
    # somebody else's namespace. The arena build is a rewrite of everything
    # around it, and a build that materialises ancestors up to the origin is one
    # obvious place to lose the check.
    Given a config declaring record set "www.evil.test." of type "A" with values "203.0.113.99"
    When the zone is built
    Then the build fails with an error mentioning "is not inside zone"

  @malformed @enforced tests/arena_differential.rs:686
  Scenario: A config the transcription refuses is a config the arena refuses
    # Build failure is behaviour too, and S1 must not start accepting a config
    # that fails today — nor start refusing one that loads. The differential
    # compares the build outcome before it compares any answer.
    Given any config the generator produces, valid or not
    When both implementations build it
    Then they agree on whether the build succeeds

  # ------------------------------------------------------------- HOSTILE

  @hostile @enforced src/zone.rs:1525
  Scenario: The deepest name the wire can carry is 127 labels, and it is answered
    # 123 is the ceiling under "example.com." and the suite uses it as though it
    # were the protocol limit in several places. It is not: 127 one-octet labels
    # is 255 octets exactly. This is the input that drives every label-indexed
    # array in the model to its largest reachable index.
    Given a zone whose origin is the root "." with a wildcard at the apex
    When a client queries a name of 127 single-octet labels
    Then it is answered with the owner rewritten to the queried name

  @hostile @enforced src/zone.rs:1914
  Scenario: A query name at exactly 255 octets is answered
    # The octet limit approached from the other direction from the label limit.
    # A name can be at the octet ceiling with very few labels, and a model that
    # bounded work by label count alone would not notice the cost of the octets.
    Given a zone holding a wildcard at the apex
    When a client queries a name whose wire form is exactly 255 octets
    Then it is answered rather than panicking

  @hostile @enforced src/zone.rs:1684
  Scenario: A root-origin zone with a wildcard still terminates on a miss
    # origin = "." drives the probe window's floor to zero, which is where a
    # loop shaped as "count down while depth >= floor" fails to terminate. The
    # closest-encloser binary search S3 installs has the same hazard in a
    # different shape (div_ceil), so this scenario outlives the loop it was
    # written for. Under a process watchdog: a spin must fail the test, not hang
    # the suite.
    Given a zone whose origin is the root "." instead of the Background zone
    And the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "nope.example.com." for type TXT
    Then the lookup returns NoData within the watchdog's deadline

  # --------------------------------------------------------- PERFORMANCE

  @hostile @enforced tests/perf_budget.rs:180
  Scenario: A maximum-length attacker-chosen name still costs no more than a one-label name
    # VEGA-065's acceptance criterion, now S1's regression gate. Measured on the
    # bounded walk: 88 ns shallow, 1.657 µs at 123 labels, ratio 18.8x against a
    # 25x budget, inside a 9.1 µs per-query CPU budget. S1 must hold the ratio;
    # the ruling expects the absolute numbers to improve, because the tuple-key
    # LowerName clone disappears.
    Given a 100,000-record zone containing one wildcard
    When a 123-label name inside the zone is looked up for type A
    Then it costs less than 25 times a 1-label lookup in the same zone

  @hostile @enforced tests/perf_budget.rs:351
  Scenario: The true 127-label ceiling is measured and budgeted, not just the 123-label one
    # The ruling asks for a new baseline at the real boundary, because that is
    # the deepest name an attacker can actually send and the deepest index any
    # label-keyed array in the model will ever see. Ratio-budgeted like its
    # sibling, so a slow machine cannot make it flap.
    Given a root-origin zone containing one wildcard
    When a bare 127-label name is looked up for type A
    Then it costs less than 25 times a 1-label lookup in the same zone

  @hostile @enforced tests/perf_budget.rs:280
  Scenario: An ANY lookup still costs the same on a 100,000-record zone as on a small one
    # VEGA-083 deleted the O(zone) ANY arm. S1 rebuilds the structure that arm
    # scanned, and "iterate the nodes" is a very natural thing to reach for when
    # a node arena is suddenly available. It must stay flat.
    Given a 100,000-record zone
    When an existing name is looked up for type ANY
    Then it costs less than 25 times the same name looked up for type A

  # ------------------------------------------------------- NOT S0'S OR S1'S
  #
  # Written down so nobody mistakes a green S0/S1 for a correct zone model.
  #
  #   * Empty non-terminals are still NXDOMAIN (VEGA-006). S2.
  #   * A wildcard still applies below a name that exists (VEGA-009). S3.
  #   * There is no closest-encloser search, no delegation, no glue, no
  #     occlusion handling, and SOA and apex NS are still optional. S3, S4, S5.
  #   * The u128 wildcard_depths bitmap is still present at S1, recomputed over
  #     wildcard nodes. It is deleted at S3, when ancestor closure makes the set
  #     of populated depths contiguous and a u8 pair carries the same
  #     information. That is VEGA-065's invariant made structural, not undone.
  #
  # A test asserting conformant behaviour on any of those will fail, correctly,
  # and must not be written against S0 or S1.
