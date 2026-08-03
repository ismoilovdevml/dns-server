# Traceability key used throughout features/:
#   @enforced <path>:<line>  — a Rust test exists and asserts this behaviour
#   @gap                     — no test enforces this scenario; it is a known hole
#   @wip                     — the behaviour is not reachable from any public
#                              surface yet; the scenario is the obligation and
#                              the commit named in the comment must discharge it
#   @category tags           — happy | boundary | empty | malformed | hostile

Feature: Empty non-terminals exist (RFC 4592 §2.2.2, RFC 8020 §2)
  # WHY THIS MATTERS
  #
  # A name that exists only because something exists beneath it is still a name
  # in the zone. RFC 4592 §2.2.2 calls it an empty non-terminal and says it
  # exists; RFC 1034 §4.3.2 step 3(c) sets the authoritative name error only when
  # the name does not exist. Today Vega materialises a node for each name the
  # config *writes* and for nothing else, so `_tcp.example.com` — which exists
  # because `_sip._tcp.example.com` holds an SRV — is answered NXDOMAIN.
  #
  # That is not a cosmetic rcode. RFC 8020 §2 licenses a resolver that has cached
  # NXDOMAIN for a name to answer NXDOMAIN for EVERYTHING BENEATH IT, for the
  # SOA MINIMUM (RFC 2308 §5). So one query for the parent takes the child — a
  # record that exists and that the operator configured — out of service for the
  # whole negative-cache lifetime. No attacker is required: a resolver walking
  # down from the apex, or a client asking for the service name before the
  # instance name, is enough. SRV, TLSA, DKIM, ACME and _dmarc all create empty
  # non-terminals, which is to say every zone anyone actually operates.
  #
  # This is VEGA-006, severity blocker, and it is closed by step S2 of VEGA-032's
  # six-commit sequence: materialise every strict ancestor of every owner name,
  # up to the origin, as a node with an empty RRset range. An empty non-terminal
  # is not a special case in the model — it is "a node with no RRsets", which is
  # exactly what RFC 4592 §2.2.2 says it is.
  #
  # WHAT S2 IS NOT
  #
  # S2 does not implement the closest-encloser rule. `*.dev` still applies below
  # `deep.dev` after this step, which is wrong and is VEGA-009's, closed at S3.
  # The test that pins that defect must stay RED through this commit; if it turns
  # green here, S2 went outside its fence and S3 has nothing left to prove. There
  # is no delegation, no glue, no occlusion (S4) and the SOA and apex NS are
  # still optional (S5).
  #
  # WHY ANCESTOR CLOSURE IS LOAD-BEARING BEYOND THIS ISSUE
  #
  # S3's closest-encloser search is a BINARY SEARCH over label depth, and a
  # binary search needs a monotone predicate. "This depth has a node" is monotone
  # only because the node set is closed under ancestry — which is what S2
  # establishes. If ancestor materialisation is ever broken, that search returns
  # a SHALLOWER encloser than the truth, a wildcard synthesises into a subtree an
  # operator carved out, and VEGA-009 reopens silently, with correct-LOOKING
  # answers. The ruling calls this the most dangerous coupling in the design.
  # That is why the invariant is asserted directly here (every node's parent is a
  # node) and not only through the answers it produces.
  #
  # Implementation: src/zone.rs (ZoneBuilder::finish, ancestor materialisation)
  # Spec siblings: features/zone-data-model.feature (S0/S1),
  #                features/wildcards.feature (RFC 4592 §3.3.1),
  #                features/negative-answers.feature (RFC 2308 §2.2 NODATA)
  # Ruling: .claude/backlog/decisions/VEGA-032-zone-data-model.md §3.1, §4.3,
  #         §6.1 I-3, §7.1, §10.2 (S2), §13 (AC-2.1 … AC-2.6)
  # Issues: VEGA-006 (closed here), VEGA-032 S2

  Background:
    Given a zone with origin "example.com"
    And a zone default TTL of 300 seconds
    And an SOA record with minimum 60

  # =========================================================================
  # HAPPY PATH — the name exists, so it is NOERROR
  # =========================================================================

  @happy @enforced src/zone.rs:3676
  Scenario: A name that exists only as an ancestor is NODATA, not NXDOMAIN
    # AC-2.1, and the headline of VEGA-006. The record at the bottom of the chain
    # is configured and must keep answering; the names above it exist because it
    # does.
    Given the zone contains record set "a.b.ent" of type "A" with values "203.0.113.41"
    When a client queries "b.ent.example.com." for type A
    Then the lookup result is NoData

  @happy @enforced src/zone.rs:3781
  Scenario: Every strict ancestor of an owner exists, not just the immediate parent
    # A loop that stops after one level passes the scenario above and leaves
    # every grandparent NXDOMAIN — which is the same RFC 8020 denial one label
    # higher. Each ancestor is asserted separately so the failure names the depth.
    Given the zone contains record set "a.b.c.d" of type "A" with values "203.0.113.41"
    When each of "b.c.d.example.com.", "c.d.example.com." and "d.example.com." is queried for type A
    Then every one of them is NoData

  @happy @enforced src/zone.rs:3807
  Scenario: The record beneath an empty non-terminal still answers
    # The half that makes the fix worth having. A build that materialised
    # ancestors but dropped or shadowed the leaf would satisfy every negative
    # assertion in this file.
    Given the zone contains record set "a.b.ent" of type "A" with values "203.0.113.41"
    When a client queries "a.b.ent.example.com." for type A
    Then the answer holds 1 record with value "203.0.113.41"

  @happy @enforced src/zone.rs:3828
  Scenario: The service-record shapes that created this bug are all NODATA
    # VEGA-006's own evidence, verified live: SRV, TLSA and DKIM are the three
    # shapes that put a record two or three labels below a name nobody writes.
    # A zone using any of them is one cache-fill away from losing the record.
    Given the zone contains record set "_sip._tcp" of type "SRV" with values "10 10 5060 sip.example.com."
    And the zone contains record set "_443._tcp.www" of type "TLSA" with values "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    And the zone contains record set "sel._domainkey" of type "TXT" with values "v=DKIM1; k=rsa; p=MIIB"
    When "_tcp.example.com.", "_tcp.www.example.com." and "_domainkey.example.com." are queried for type A
    Then every one of them is NoData
    And each configured record still answers at its own name

  @happy @enforced src/zone.rs:3722
  Scenario: The parent of a wildcard exists
    # AC-2.2. "*.apps.example.com" is a node whose owner name has a parent, so
    # "apps.example.com" exists for exactly the same reason any other ancestor
    # does. Answering NXDOMAIN here lets an RFC 8020 resolver deny the entire
    # wildcard subtree — including every name the wildcard does answer.
    Given the zone contains record set "*.apps" of type "A" with values "203.0.113.30"
    When a client queries "apps.example.com." for type A
    Then the lookup result is NoData

  @happy @enforced src/zone.rs:2166
  Scenario: A wildcard's parent holds no record of its own
    # AC-2.3, and the rewrite of a_wildcard_never_creates_a_record_at_its_own_parent.
    # That test asserted NXDOMAIN at the parent, which is the exact opposite of
    # the scenario above; it exists to kill an `if is_wildcard` -> `if
    # !is_wildcard` mutant in the build, and that kill is preserved by asserting
    # the two halves that are actually true: the parent exists with NO records,
    # and the wildcard still synthesises below it. A mutant that files the
    # wildcard's records at its parent fails the first half; a mutant that drops
    # the wildcard entirely fails the second.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When "dev.example.com." is queried for type A
    Then the lookup result is NoData
    And "x.dev.example.com." is answered with the synthesised address

  @happy @enforced tests/rfc_conformance.rs:289
  Scenario: An empty non-terminal answers NOERROR with the SOA in the authority section over the wire
    # AC-2.1 end to end. The rcode is the half a resolver caches, and RFC 2308 §3
    # requires the SOA on a NODATA answer exactly as on a name error — without it
    # the negative answer is not cacheable and every miss comes back.
    Given a running server holding record set "a.b.ent" of type "A"
    When a client queries "ent.example.com." for type A over UDP
    Then the response rcode is NOERROR
    And the answer section is empty
    And the authority section holds the zone SOA

  @happy @enforced tests/rfc_conformance.rs:336
  Scenario: Asking for the empty non-terminal first does not deny the record beneath it
    # AC-2.5 — RFC 8020 §2 stated as an experiment rather than as a citation.
    # This is the sequence that takes a configured record out of service today:
    # the parent is asked first, the resolver caches the denial, and the child is
    # never asked again for the SOA MINIMUM. The ORDER is the test.
    Given a running server holding record set "_sip._tcp" of type "SRV"
    When a client queries "_tcp.example.com." for type SRV and then "_sip._tcp.example.com." for type SRV
    Then the first response is NOERROR with an empty answer section
    And the second response carries the SRV record

  # =========================================================================
  # BOUNDARY — where the ancestor walk starts and stops
  # =========================================================================

  @boundary @enforced src/zone.rs:3876
  Scenario: An owner one label below the apex creates no empty non-terminal
    # The discriminating negative for the whole feature. "www.example.com" has
    # exactly one strict ancestor inside the zone — the apex — which already
    # exists, so nothing new is materialised and a sibling name is still a real
    # name error. Without this, "answer NODATA for everything" passes every
    # positive scenario above.
    Given the zone contains record set "www" of type "A" with values "203.0.113.10"
    When a client queries "nope.example.com." for type A
    Then the lookup result is NxDomain

  @boundary @enforced src/zone.rs:3903
  Scenario: The ancestor walk stops at the origin and never materialises a name above it
    # An off-by-one in the other direction: walking past the origin would put
    # "com." and the root in the node set, and a server that believes it holds a
    # node for "com." is one dispatch change away from answering for it. Out-of-
    # zone names are refused before the zone is consulted, so this is asserted
    # against the existence predicate directly, where it is observable.
    Given the zone contains record set "a.b" of type "A" with values "203.0.113.41"
    When the zone is asked whether "com." and "." exist
    Then neither of them exists

  @boundary @enforced src/zone.rs:3932
  Scenario: An empty non-terminal is NODATA for every type, including ANY
    # Existence is a property of the NAME, not of the QTYPE (RFC 1034 §4.3.2 step
    # 3(c)). A fix that materialised ancestors only for the type that created
    # them would answer NXDOMAIN for AAAA at a name that exists, which is the
    # same RFC 8020 denial arriving through a dual-stack client.
    Given the zone contains record set "a.b.ent" of type "A" with values "203.0.113.41"
    When "b.ent.example.com." is queried for A, AAAA, TXT, MX, SRV, CNAME, SOA and ANY
    Then every answer is NoData

  @boundary @enforced src/zone.rs:3968
  Scenario: An empty non-terminal is not counted as a record
    # AC-2.4. `record_count` is the dns_zone_records gauge and an operator's only
    # view of whether a reload truncated the zone. Empty non-terminals are nodes,
    # not records; counting them would move the gauge on upgrade with no config
    # change and make the alert on it worthless.
    Given the zone contains record set "a.b.c.d" of type "A" with values "203.0.113.41"
    When the record count is read
    Then it is 1

  @boundary @enforced src/zone.rs:3999
  Scenario: Every node in the arena has its parent in the arena
    # Invariant I-3, asserted structurally rather than through an answer, because
    # it is what S3's closest-encloser BINARY SEARCH rests on: the predicate "a
    # node exists at this depth" is monotone only under ancestor closure. A hole
    # in the chain makes the search return a shallower encloser than the truth
    # and reopens VEGA-009 with answers that look right. Checked in a release
    # build, not only behind debug_assert, since that is where it will run.
    Given a zone holding owners at several depths, a wildcard and a nested wildcard
    When every node in the arena is examined
    Then each one other than the apex has its immediate parent in the arena
    And every ancestor still precedes its descendant in canonical order

  @boundary @enforced src/zone.rs:4058
  Scenario: An ancestor that is also a declared owner keeps its records
    # The collision case: "b.example.com" is both a configured owner and the
    # strict ancestor of "a.b.example.com". Materialising it twice, or letting
    # the empty ancestor entry win, silently deletes a configured record — and
    # deletes it in the build, where nothing else in the tree would notice.
    Given the zone contains record set "b" of type "A" with values "203.0.113.20"
    And the zone contains record set "a.b" of type "A" with values "203.0.113.41"
    When "b.example.com." is queried for type A
    Then the answer holds 1 record with value "203.0.113.20"

  @boundary @enforced src/zone.rs:4095
  Scenario: An ancestor that is also a declared wildcard keeps its records and stays a wildcard
    # The same collision one step nastier: "*.dev" is a declared wildcard AND the
    # strict ancestor of "x.*.dev" (RFC 4592 §2.1.3 permits further asterisks
    # inside a wildcard's owner name). The node must keep its RRset and its
    # wildcard flag, whichever of the two write sites reaches it first — the
    # build already carries a debug assertion that one name never arrives as both
    # a wildcard and an ordinary node, and ancestor materialisation is a second
    # write site for exactly that field.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "x.*.dev" of type "A" with values "203.0.113.60"
    When "y.dev.example.com." and "x.*.dev.example.com." are queried for type A
    Then the wildcard synthesises for the first
    And the literal name answers with its own record for the second

  # =========================================================================
  # EMPTY — nothing to materialise
  # =========================================================================

  @empty @enforced src/zone.rs:4132
  Scenario: A zone holding no records materialises no empty non-terminals
    # The apex exists on its own account and nothing else does. An ancestor loop
    # that ran over an empty owner set and inserted something — the root, or an
    # empty name — would be invisible to every populated test.
    Given the zone contains no records
    When "x.example.com." is queried for type A
    Then the lookup result is NxDomain
    And the apex is still NoData rather than NXDOMAIN

  @empty @enforced src/zone.rs:4154
  Scenario: An apex-only owner adds nothing to the node set
    # "@" qualifies to the origin, whose only strict ancestors are outside the
    # zone. The walk must produce an empty set here rather than one entry for the
    # origin itself, which would be a node inserted twice.
    Given the zone contains record set "@" of type "A" with values "203.0.113.10"
    When the apex is queried for type A
    Then the answer holds 1 record with value "203.0.113.10"

  # =========================================================================
  # MALFORMED — configs that must still be refused, and answers that must not move
  # =========================================================================

  @malformed @enforced src/zone.rs:1929
  Scenario: An out-of-zone owner name is still refused after ancestors are materialised
    # qualify() is the only thing between a config and a record for somebody
    # else's namespace, and ancestor materialisation is a new loop that walks
    # upwards from every owner — the obvious place to lose the check, or to
    # smuggle a node above the origin in from a name that was rejected.
    Given a config declaring record set "www.evil.test." of type "A" with values "203.0.113.99"
    When the zone is built
    Then the build fails with an error mentioning "is not inside zone"

  @malformed @enforced src/zone.rs:4180
  Scenario: A wildcard whose own owner name exceeds 255 octets materialises no ancestors
    # RFC 1035 §2.3.4 caps a name at 255 octets, so a wildcard whose parent sits
    # within two octets of the ceiling has no representable owner name and is not
    # served — S1 records this, warns, and answers exactly as before. It follows
    # that its parent is NOT an empty non-terminal: no node exists for the
    # wildcard, so nothing implies its parent exists. Pinned because the
    # alternative — materialising ancestors from a record whose owner name could
    # not be built — is a plausible reading of "every strict ancestor of every
    # owner" and it would make a name exist because of a record the zone refused
    # to hold.
    Given the zone contains a wildcard whose parent is 123 labels and 255 octets long
    When that parent name is queried for type A
    Then the lookup result is NxDomain
    And the build emits a warning naming the record

  @malformed @enforced tests/arena_differential.rs:1544
  Scenario: A config the transcription refuses is still a config the arena refuses
    # Ancestor materialisation must not make a config load that fails today, nor
    # fail one that loads. The build outcome is compared before any answer is,
    # and it permits ZERO transitions — S2 changes answers, not which zones can
    # be served.
    Given any config the generator produces, valid or not
    When both implementations build it
    Then they agree on whether the build succeeds

  # =========================================================================
  # HOSTILE — attacker-chosen names and the fence around S3
  # =========================================================================

  @hostile @enforced src/zone.rs:4095
  Scenario: A wildcard that is itself an empty non-terminal covers its names with NODATA
    # The subtlest behaviour S2 introduces, and it must be written down rather
    # than discovered. "x.*.dev" makes "*.dev.example.com" exist as an empty
    # non-terminal — a node whose leftmost label is an asterisk. RFC 4592 §2.1.1
    # says that IS a wildcard, so it becomes a source of synthesis that carries
    # no RRset: RFC 1034 §4.3.2 step 3(c) forbids the name error and the answer
    # for "y.dev.example.com" is NODATA where today it is NXDOMAIN. The flag is a
    # property of the NAME, not of how the node came to exist; deciding it from
    # the config instead would leave a node that the exact-name probe matches and
    # the wildcard probe does not, which is a wildcard nobody can reach.
    Given the zone contains record set "x.*.dev" of type "A" with values "203.0.113.60"
    When "y.dev.example.com." is queried for type A
    Then the lookup result is NoData
    And "x.*.dev.example.com." still answers with its own record

  @hostile
  Scenario: The wildcard no longer applies below a name that exists — S3 discharges the fence
    # DISCHARGED AT VEGA-032 S3, in the commit that closes VEGA-009, which is the
    # only commit allowed to touch this scenario.
    #
    # It used to read "S2 does not fix VEGA-009" and asserted that
    # "a.deep.dev.example.com." was STILL answered from "*.dev", wrongly, with
    # a_wildcard_does_not_apply_below_a_name_that_exists still #[ignore]d and
    # red. That was the right fence for S2: ancestor closure makes the
    # closest-encloser fix look like a two-line change, and making it there would
    # have left S3 with nothing to prove and no differential to prove it against.
    #
    # S3 has landed the rule, so the fence comes down and the assertion INVERTS.
    # It is kept rather than deleted because it is the clearest statement in this
    # file of what S2 was and was not responsible for, and because the two S2
    # behaviours it depends on — "deep.dev" existing, and existing as a node the
    # closest-encloser search can find — are exactly what S3 is built on.
    #
    # Full specification: features/closest-encloser.feature.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "deep.dev" of type "A" with values "203.0.113.51"
    When "a.deep.dev.example.com." is queried for type A
    Then the lookup result is NxDomain
    And a_wildcard_does_not_apply_below_a_name_that_exists is green and not ignored

  @hostile @enforced src/zone.rs:4273
  Scenario: An empty non-terminal chain at the protocol's label ceiling is answered
    # 127 labels is the deepest name the wire can carry (RFC 1035 §3.1:
    # 127 * 2 + 1 = 255) and is reachable only under origin ".". A single owner
    # at that depth materialises 126 ancestors, which drives the label-indexed
    # structures — the [u64; 128] suffix hash and the u128 depth bitmap — to
    # their largest reachable index. With panic = "abort" one index past the end
    # is a full outage from one packet, so every depth in the chain is queried,
    # under the process watchdog.
    Given a zone with origin "." holding one owner 127 labels deep
    When every ancestor of that owner is queried for type A
    Then each one is NoData and none panics
    And the whole sweep completes inside the watchdog

  @hostile @enforced tests/properties.rs:1932
  Scenario: No strict ancestor of any configured owner is ever NXDOMAIN
    # RFC 8020 §2 as a property over generated zones rather than the handful of
    # shapes anyone thinks to write. Cases are CONSTRUCTED, never filtered: the
    # deep owner name is generated FIRST and the queried ancestor is DERIVED from
    # it by dropping labels, so every case is a real ancestor. Generating a zone
    # and a name independently and discarding the pairs that do not interact is
    # what took an earlier property in this tree to 247 successes and 1,024
    # global rejects on CI while it passed locally — and empty non-terminals are
    # rarer than wildcards, so that mistake would bite harder here.
    Given any zone the generator produces
    And any strict ancestor derived from one of its owner names
    When that ancestor is looked up for any type
    Then the answer is never NxDomain

  @hostile @enforced tests/arena_differential.rs:1544
  Scenario: S2 changes the answer at an empty non-terminal and nowhere else
    # The differential, re-armed. Its oracle is the same transcription of the
    # pre-S1 implementation, run over a node set that has been closed under
    # ancestry — the closure computed FROM THE CONFIG, never from the code under
    # test. So the permitted transitions are derived rather than whitelisted, and
    # "any NXDOMAIN may become NODATA" — which would let S3's bug through — is
    # not among them. Three classes are permitted and every difference must be
    # classifiable as one of them:
    #
    #   T1  the queried name is itself an empty non-terminal   => NODATA
    #       (this covers NXDOMAIN -> NODATA *and* the wildcard synthesis that
    #        stops at a name which now exists, RFC 4592 §2.2.2)
    #   T2  the queried name is covered by a wildcard that is itself an empty
    #       non-terminal, and was uncovered before        => NXDOMAIN -> NODATA
    #   T3  a CNAME chase whose target is now an empty non-terminal loses the
    #       chased records from the tail of the answer, and nothing else
    #
    # Anything else fails, including a changed record order, owner name or TTL.
    Given any zone the generator produces
    And any query name constructed from that zone's own structure
    When it is looked up
    Then the answer matches the transcription over the ancestor-closed node set
    And every difference from the pre-S2 transcription is one of the three classes

  @hostile @enforced tests/arena_differential.rs:2032
  Scenario: All three transition classes are actually reached
    # A classification nothing exercises is a classification that permits
    # everything. The deterministic fixture must hit each of the three classes at
    # least once, so that the property above is known to be constraining rather
    # than vacuously satisfied by a generator that never builds an empty
    # non-terminal.
    Given the deterministic branch-sweep fixture
    When every name in it is compared against both transcriptions
    Then each of the three transition classes is observed at least once

  # =========================================================================
  # BUDGETS — what ancestor closure costs
  # =========================================================================

  @boundary @enforced tests/zone_memory.rs:498
  Scenario: An empty non-terminal costs one node and nothing else
    # AC-2.6, and the number the release note owes an operator: RSS grows on
    # upgrade with no config change. MEASURED, not projected, on this machine at
    # e7b8dba: one more node in a 100,000-node zone costs 102 bytes — 96 for the
    # Node itself plus ~6 amortised for its index slot — for any owner name whose
    # labels fit hickory's 32-octet inline buffer, and 174 bytes for one that
    # spills to the heap. The ruling's §7.1 estimate of 112 B per ENT was 10 B
    # high for the common case and 62 B low for long names.
    #
    # The flat 100,000-record fixture the S1 gate uses has NO ancestors to
    # materialise, so it must not move by a single byte — which is itself the
    # check that ancestor materialisation is driven by the config and not by the
    # node count. The SRV fixture is the one that pays: 100,000 records at
    # "_sip._tcp.hN" materialise 200,000 empty non-terminals, and 30,255,464 B
    # becomes ~50.7 MB. That is 48.3 MiB against the ruling's 40 MiB, so the
    # budget is re-baselined PER SHAPE rather than raised globally: a shape with
    # no ancestors keeps the old number exactly, and the ancestor-heavy shape
    # gets a budget stated as bytes-per-empty-non-terminal, where the cost
    # actually lives.
    Given a 100,000-record zone whose owners are flat
    And a 100,000-record zone whose owners each imply two empty non-terminals
    When both are built and their live heap measured
    Then the flat zone still holds at most 40 MiB
    And the ancestor-heavy zone costs at most 110 bytes per empty non-terminal
    And the empty non-terminals it implies all exist

  @boundary @enforced tests/perf_budget.rs:339
  Scenario: An empty non-terminal is answered as cheaply as any other existing name
    # AC-2.6. An empty non-terminal is found by the same single hash probe as any
    # other node and then answers from an empty RRset range, so it must cost no
    # more than an exact hit that returns a record — if it costs more, the lookup
    # is falling through to the wildcard walk after finding the node, which means
    # the node is not being found at all.
    Given a 100,000-record zone with an empty non-terminal in it
    When the empty non-terminal and an ordinary owner are each looked up many times
    Then the empty non-terminal costs no more than twice the ordinary owner

  @boundary @enforced tests/zone_memory.rs:498
  Scenario: A negative answer still allocates nothing after ancestors are materialised
    # S1's zero-allocation guarantee on the three negative shapes is a property
    # of the probe, not of the node set, and it must survive a node set that is
    # three times larger. The negative path is the only query shape an attacker
    # can drive without knowing the zone, so its allocation count is a cost they
    # set — and the budget is zero rather than a threshold, because a threshold
    # lets a smaller allocation back in.
    Given a zone with a wildcard and empty non-terminals
    When an uncovered name, a covered type-miss and a 123-label miss are each looked up 1000 times
    Then no allocation occurs on any of them
