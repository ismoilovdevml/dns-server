Feature: Wildcard record synthesis (RFC 4592)
  # WHY THIS MATTERS
  # A wildcard is the only part of the zone where the server invents a record
  # that the operator never wrote. Get the precedence wrong and a wildcard
  # shadows a real host — traffic for a named production service is answered
  # with the catch-all address. Get the scope wrong and the wildcard leaks into
  # names it was never meant to cover, which is how an operator ends up
  # unintentionally authoritative for every label an attacker can invent. RFC
  # 4592 exists because implementations kept getting exactly these two things
  # wrong.
  #
  # Implementation: src/zone.rs (insert_spec wildcard indexing, Zone::resolve
  #                 wildcard loop at lines 294-312)
  #
  # VEGA-065 replaces that loop with a bounded depth probe. It is a performance
  # fix and must change no answer; see the BOUNDED WALK section at the bottom.
  #
  # NOTE ON THE IMPLEMENTATION MODEL: a config entry "*.dev" is stored under the
  # key ("dev.example.com.", TYPE). A bare "*" is stored under the origin. At
  # lookup time the code walks up from the queried name's parent, stopping at the
  # origin or root.
  #
  # MODEL NOTE, VEGA-032 S1 — LANDED. The paragraph above describes the
  # parent-keyed map and is no longer true. A wildcard is now an ordinary NODE named
  # "*.dev.example.com." (RFC 4592 §2.1.1 — a wildcard is a name whose leftmost
  # label is an asterisk, which is what makes the closest-encloser rule
  # expressible at all), reached through a hash index rather than through a
  # parent key. S1 keeps the depth bitmap, recomputed over wildcard nodes, and
  # keeps deepest-wins; the closest-encloser rule is S3's and the bitmap is
  # subsumed there, by ancestor closure, rather than abandoned.
  #
  # One S1 fidelity point worth knowing before reading any scenario here: a
  # wildcard node is deliberately NOT matched by the exact-name probe, because
  # the map it replaces held wildcards in neither `exact` nor `names`. Without
  # that, a wildcard carrying a CNAME would start substituting it for a query
  # the old model answered NODATA. That exclusion is what S2 and S3 remove, with
  # a ruling, rather than something S1 got to decide.
  #
  # MODEL NOTE, VEGA-032 S2 — LANDED. Every strict ancestor of every owner name
  # is now a node with an empty RRset range, so a name that exists only because
  # something exists beneath it is NODATA and not NXDOMAIN (RFC 4592 §2.2.2, RFC
  # 8020 §2 — features/empty-non-terminals.feature). Two consequences bear on
  # the scenarios in THIS file:
  #
  #   * a wildcard's PARENT now exists. "*.apps" makes "apps.example.com" an
  #     empty non-terminal, so it is NODATA. It still holds no records of its
  #     own, which is the half a_wildcard_never_creates_a_record_at_its_own_
  #     parent was rewritten to assert;
  #   * a wildcard can itself BE an empty non-terminal. "x.*.dev" materialises
  #     "*.dev.example.com" as a node with no RRset, and RFC 4592 §2.1.1 makes
  #     that a source of synthesis, so names under "dev" are NODATA rather than
  #     NXDOMAIN. The flag is a property of the NAME, never of which loop
  #     created the node.
  #
  # Which wildcard answers a covered name is UNCHANGED at S2: deepest-wins, not
  # RFC 4592 §3.3.1's closest encloser. That is VEGA-009 and it is S3's.
  #
  # EVERY SCENARIO IN THIS FILE IS WRITTEN TO HOLD UNDER BOTH MODELS, and that
  # is the S1 acceptance criterion rather than an accident: S1 changes the
  # structure and no answer. The mechanised form of that claim is
  # features/zone-data-model.feature, "The arena answers exactly what today's
  # implementation answers, for every zone and every query". Rewrite this note in
  # the S1 commit, not before — a feature file that describes a model the code
  # does not have yet is worse than one that describes the model it does have.

  Background:
    Given a zone with origin "example.com"
    And an SOA record with minimum 60

  # ---------------------------------------------------------- MATCHING

  @happy @enforced src/zone.rs:529
  Scenario: A wildcard answers a name that does not otherwise exist
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "anything.dev.example.com." for type A
    Then the answer section contains 1 record

  @happy @enforced src/zone.rs:529
  Scenario: A synthesised answer is labelled with the queried name, not the wildcard
    # A resolver that receives an answer owned by "*.dev.example.com." will
    # discard it. The owner must be rewritten to the QNAME.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "anything.dev.example.com." for type A
    Then the answer record owner is "anything.dev.example.com."

  @happy @enforced tests/integration.rs:259
  Scenario: A wildcard answer reaches the client with the queried owner name
    Given the zone contains record set "*.apps" of type "A" with values "203.0.113.30"
    When a client sends a UDP query for "whatever.apps.example.test." type A
    Then the response rcode is NOERROR
    And the answer record owner is "whatever.apps.example.test."

  @happy @gap
  Scenario: A synthesised answer carries the wildcard record's TTL
    # Record::from_rdata(qname, r.ttl, r.data) preserves the TTL. Untested.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50" and TTL 45
    When a client queries "x.dev.example.com." for type A
    Then the answer record TTL is 45

  @happy @gap
  Scenario: A wildcard with multiple values synthesises all of them
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50, 203.0.113.51"
    When a client queries "x.dev.example.com." for type A
    Then the answer section contains 2 records
    And every answer record is owned by "x.dev.example.com."

  # ------------------------------------------------- EXACT BEATS WILDCARD

  @happy @enforced src/zone.rs:543
  Scenario: An exact record wins over a covering wildcard
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "special.dev" of type "A" with values "203.0.113.51"
    When a client queries "special.dev.example.com." for type A
    Then the answer holds 203.0.113.51

  @boundary @gap
  Scenario: A name that exists with another type is NODATA, not a wildcard synthesis
    # RFC 4592 §2.2.1: the wildcard is only consulted when the QNAME does not
    # exist at all. src/zone.rs:260 checks `names.contains` before the wildcard
    # block, so "special.dev" with only a TXT record must yield NODATA for A —
    # NOT the wildcard's A record. This is the single most important wildcard
    # precedence rule and no test covers it.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "special.dev" of type "TXT" with values "\"hi\""
    When a client queries "special.dev.example.com." for type A
    Then the response rcode is NOERROR
    And the answer section is empty

  # ------------------------------------------------------------ WRONG TYPE

  @boundary @enforced src/zone.rs:721
  Scenario: A wildcard does not answer a type it was not configured for, but the name still exists
    # RFC 1034 §4.3.2 step 3(c): the authoritative name error is set ONLY when
    # the `*` node does not exist. It exists here and carries no TXT, so control
    # goes to step 6 — exit with an empty answer section — which is RFC 2308
    # §2.2 NODATA, not a name error. Answering NXDOMAIN instead lets an RFC 8020
    # §2 resolver deny the whole subtree for RFC 2308 §5's SOA MINIMUM
    # (VEGA-083, VEGA-010).
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type TXT
    Then the lookup result is NoData

  @boundary @enforced tests/integration.rs:1040
  Scenario: A wildcard of the wrong type produces NOERROR with the SOA over the wire
    # The unit test asserts the Answer enum only, and the response the client
    # sees is what does the damage: this used to be rcode NXDOMAIN plus a
    # cacheable SOA. The SOA assertion stays — RFC 2308 §3 requires it on a
    # NODATA answer just as on a name error — and only the expectation inverts.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type TXT
    Then the response rcode is NOERROR
    And the answer section is empty
    And the authority record type is SOA
    And the response is authoritative

  @boundary @gap
  Scenario: Wildcards of two types at the same node each answer their own type
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "*.dev" of type "TXT" with values "\"wild\""
    When a client queries "x.dev.example.com." for type TXT
    Then the answer section contains 1 record
    And the answer record type is TXT

  # --------------------------------------------------------------- NESTED

  @boundary @enforced src/zone.rs:694
  Scenario: A wildcard covers a name several labels below it
    # RFC 4592 §2.1.1: "*.dev.example.com" matches "a.b.c.dev.example.com".
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "a.b.c.dev.example.com." for type A
    Then the answer section contains 1 record
    And the answer record owner is "a.b.c.dev.example.com."

  @boundary @gap
  Scenario: The closest enclosing wildcard wins over a higher one
    # With both "*" (at the apex) and "*.dev" configured, a query for
    # "x.dev.example.com" must be answered by "*.dev" because the walk starts at
    # the immediate parent. Untested, and an inverted walk order would silently
    # serve the wrong address.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    And the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type A
    Then the answer holds 203.0.113.50

  @boundary @gap
  Scenario: A bare wildcard at the apex covers a first-level subdomain
    # A config entry of "*" is indexed under the origin itself.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "anything.example.com." for type A
    Then the answer section contains 1 record

  @boundary @gap
  Scenario: A bare apex wildcard does not answer the apex itself
    # RFC 4592 §2.1.2: the wildcard owner name never matches the name it is
    # attached to. The walk starts at name.base_name(), so a query for
    # "example.com." looks under "com." and finds nothing.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "example.com." for type A
    Then the response rcode is NOERROR
    And the answer section is empty

  @boundary @gap
  Scenario: The wildcard walk stops at the zone origin
    # The loop breaks when parent == origin or parent.is_root(). Without that
    # bound, an out-of-zone parent could be consulted. Untested.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "a.b.c.d.example.com." for type A
    Then the answer section contains 1 record

  # ----------------------------------------------------------------- EMPTY

  @empty @gap
  Scenario: A zone with no wildcards skips the wildcard walk entirely
    # `if !self.wildcard.is_empty()` guards the loop. A regression that dropped
    # the guard would be a silent performance cliff on every NXDOMAIN.
    Given the zone contains record set "www" of type "A" with values "203.0.113.20"
    When a client queries "nope.example.com." for type A
    Then the lookup result is NxDomain

  # ------------------------------------------------------------- MALFORMED

  @malformed @gap
  Scenario: A wildcard with an invalid value fails at zone build time
    Given a config declaring record set "*.dev" of type "A" with values "not-an-ip"
    When the zone is built
    Then the build fails with an error mentioning "invalid A record value"

  @malformed @gap
  Scenario: A mid-label wildcard is treated as a literal label, not a wildcard
    # insert_spec() only treats "*" or a "*."-prefix as a wildcard. An entry such
    # as "we*b" is stored as an exact name containing an asterisk, which is what
    # RFC 4592 §2.1.1 requires (a literal, non-synthesising label). Untested, and
    # a looser check would turn a typo into a catch-all.
    Given the zone contains record set "we*b" of type "A" with values "203.0.113.70"
    When a client queries "anything.example.com." for type A
    Then the response rcode is NXDOMAIN

  # --------------------------------------------------------------- HOSTILE

  @hostile @gap
  Scenario: A wildcard does not make the server authoritative outside its zone
    # A wildcard must never cause an out-of-zone name to be answered. The handler
    # refuses before the zone is consulted, but nothing pins that ordering with a
    # wildcard present.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "www.google.com." for type A
    Then the response rcode is REFUSED

  @hostile @vega-065 @gap
  Scenario: A long attacker-chosen name under a wildcard is answered without excessive work
    # Each additional label costs one more base_name() iteration. A 100-label
    # QNAME under a wildcard-bearing zone must still be answered promptly.
    # Quantified by "A maximum-length attacker-chosen name costs no more than a
    # one-label name" in the BOUNDED WALK section below; kept here because this
    # is the end-to-end shape a packet takes.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries a 100-label name inside "example.com." for type A
    Then the server answers with a response rather than terminating

  # =========================================================================
  # BOUNDED WALK (VEGA-065)
  # =========================================================================
  # WHY THIS SECTION MATTERS
  #
  # The wildcard parent walk is the only part of answering a query whose cost
  # is chosen by the client. It calls base_name() once per label, base_name()
  # rebuilds and revalidates the whole remaining name, so a query costs
  # O(labels squared). Measured: 174.7 us to answer one 100-label NXDOMAIN
  # against a 9.1 us per-query CPU budget, from a 229-byte packet. 5,725
  # packets per second — 12.4 Mbit/s, less than a home connection — occupies a
  # core; roughly 12,600 kills the server. The name limit allows 127 labels, so
  # the real worst case is larger still. Only zones that contain at least one
  # wildcard are exposed, which is most of them.
  #
  # VEGA-065 bounds the walk: the zone records, at build time, the set of label
  # depths at which it actually holds a wildcard, and the walk probes only those
  # depths. Cost becomes "how many distinct wildcard depths does this zone
  # have" — one, for every zone anyone writes — and stops being a function of
  # the query name at all.
  #
  # THE POINT OF THESE SCENARIOS IS THAT NOTHING ELSE CHANGES. A performance
  # fix that alters a single answer is not a fix; it has traded a denial of
  # service for silent wrong answers on the authoritative path, which is worse.
  # The first four scenarios are the ones a rejected version of this change got
  # wrong: it counted labels with a function that discounts a leading asterisk
  # while indexing with one that does not, and turned four correct answers into
  # NXDOMAIN. They are load-bearing. A scenario that queries a name with no
  # asterisk in it would have stayed green through that regression.
  #
  # Ruling: .claude/backlog/decisions/VEGA-065-bounded-wildcard-walk.md
  # Out of scope here, by that ruling: closest-encloser blocking (VEGA-009),
  # empty non-terminals (VEGA-006), ANY behaviour (VEGA-002). Today's
  # non-conformant answers on those paths are pinned as-is, deliberately.
  #
  # Wildcard type-mismatch NODATA (VEGA-010) WAS on that list and has since been
  # fixed, by VEGA-083, which found it was the same defect as a wildcard-covered
  # name answering NXDOMAIN for ANY. Two scenarios below therefore now expect
  # NODATA where they used to expect NXDOMAIN. The VEGA-065 property they exist
  # for — the walk's cost, and its termination — is unchanged.

  # ------------------------------------------- HAPPY: asterisks in query names

  @happy @vega-065 @enforced src/zone.rs:885
  Scenario: A query for an apex wildcard's own name is answered from it
    # RFC 4592 §2.3: an asterisk in a query name gets no special processing. It
    # is an ordinary label that matches the existing node "*.example.com.", so
    # the query is answered under RFC 1034 §4.3.2 step 3.a. Reachable with one
    # `dig '*.example.com' A`.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "*.example.com." for type A
    Then the answer section contains 1 record
    And the answer record owner is "*.example.com."
    And the answer holds 203.0.113.1

  @happy @vega-065 @enforced src/zone.rs:906
  Scenario: A query for a wildcard's own name is answered from it
    # The same rule one level down: "*.dev" is stored under "dev.example.com.",
    # and the literal name "*.dev.example.com." walks to that parent.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "*.dev.example.com." for type A
    Then the answer section contains 1 record
    And the answer record owner is "*.dev.example.com."

  @happy @vega-065 @enforced src/zone.rs:927
  Scenario: A wildcard whose own name contains a further asterisk still synthesises
    # RFC 4592 §2.1.3 deleted RFC 1035 §4.3.3's ban on other asterisks inside a
    # wildcard's owner name: "A wildcard domain name can have subdomains."
    # Vega strips only the leftmost asterisk, so "*.*.dev" is keyed under
    # "*.dev.example.com." — a name whose raw depth is 4 and whose
    # asterisk-discounting depth is 3. Recording the wrong one makes this
    # wildcard permanently unreachable.
    Given the zone contains record set "*.*.dev" of type "A" with values "203.0.113.60"
    When a client queries "x.*.dev.example.com." for type A
    Then the answer section contains 1 record
    And the answer record owner is "x.*.dev.example.com."

  @happy @vega-065 @enforced src/zone.rs:949
  Scenario: A query for a nested-asterisk wildcard's own name is answered
    # Both miscounts compounded: the key is one short on the build side and the
    # query name is one short on the query side. Kept separate from the scenario
    # above because it fails through a different pair of errors, and fixing one
    # does not fix the other.
    Given the zone contains record set "*.*.dev" of type "A" with values "203.0.113.60"
    When a client queries "*.*.dev.example.com." for type A
    Then the answer section contains 1 record
    And the answer record owner is "*.*.dev.example.com."

  # ------------------------------------------------ HAPPY: reach and ordering

  @happy @vega-065 @enforced src/zone.rs:971
  Scenario: An apex wildcard covers a name many labels deep
    # The probe must still reach the origin depth from far below it. A window
    # whose floor came from the query name instead of the origin would miss.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "a.b.c.d.e.example.com." for type A
    Then the answer section contains 1 record
    And the answer record owner is "a.b.c.d.e.example.com."

  @boundary @vega-065 @enforced src/zone.rs:988
  Scenario: The closest wildcard answers when several could match
    # Today the walk starts at the query name's parent and descends, so the
    # nearest wildcard wins. The bounded walk must consume its depths deepest
    # first to preserve that; probing shallowest first would serve the apex
    # wildcard's address here, silently, for every name under "dev".
    #
    # Deepest-wins is NOT RFC 4592's closest-encloser rule — that defect is
    # VEGA-009. Preserving today's answer is the whole point of this issue.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    And the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type A
    Then the answer holds 203.0.113.50

  @boundary @vega-065 @enforced src/zone.rs:1012
  Scenario: Two wildcards at non-adjacent depths are both reachable
    # Depths 2 and 8 with five empty depths between them. Recording only the
    # deepest wildcard handles this by probing the whole range; recording the
    # set of populated depths handles it by construction. Neither wildcard may
    # shadow the other.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    And the zone contains record set "*.a.b.c.d.e.f" of type "A" with values "203.0.113.8"
    When a client queries "x.a.b.c.d.e.f.example.com." for type A
    Then the answer holds 203.0.113.8
    And a query for "x.example.com." type A holds 203.0.113.1

  @boundary @vega-065 @enforced src/zone.rs:1035
  Scenario: Every configured wildcard depth stays reachable
    # The worst failure mode of a depth index is that it falls out of step with
    # the record map: a configured wildcard silently answers NXDOMAIN, with
    # nothing in the logs and nothing on a dashboard to see it by. Every
    # populated depth is queried so a missing index update cannot hide.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    And the zone contains record set "*.one" of type "A" with values "203.0.113.2"
    And the zone contains record set "*.one.two" of type "A" with values "203.0.113.3"
    When a client queries "x.example.com.", "x.one.example.com." and "x.one.two.example.com." for type A
    Then each is answered by the wildcard configured at its own depth

  @boundary @vega-065 @enforced src/zone.rs:1058
  Scenario: A wildcard configured thirty labels deep is still reachable
    # The depth index is sized from RFC 1035 §2.3.4's 255-octet name limit and
    # §3.1's length-octet encoding: 2n + 1 <= 255, so 127 depths. Nothing else
    # here would notice that ceiling being set too low — an apex wildcard is
    # reachable under any ceiling above two — while a low one would silently
    # make deep wildcards, which RFC 4592 permits, unreachable.
    Given the zone contains record set "*.a.a. ... .a" (28 labels) of type "A" with values "203.0.113.30"
    When a client queries "x.a.a. ... .a.example.com." for type A
    Then the answer section contains 1 record
    And the answer holds 203.0.113.30

  # ------------------------------------------------------------- BOUNDARY

  @boundary @vega-065 @enforced src/zone.rs:1086
  Scenario: A maximum-length query name is answered
    # 123 labels is the most a name under "example.com." can carry inside RFC
    # 1035 §2.3.4's 255 octets (121*2 + 8 + 4 + 1 = 255). It is NOT the ceiling
    # for the decoder: a bare 127-single-octet-label name is exactly 255 octets
    # and hickory decodes it, which is where the depth index's 128-bit width and
    # its bit 127 come from (2n + 1 <= 255). Both bounds are exercised — this
    # scenario at 123 under a named origin, and src/zone.rs's
    # `the_true_deepest_name_the_wire_can_carry_is_127_labels_and_is_answered`
    # at the real ceiling, where the shift that sets the top bit must not
    # overflow.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries a 123-label name inside "example.com." for type A
    Then the answer section contains 1 record
    And the answer record owner is the queried name

  @boundary @vega-065 @enforced src/zone.rs:1411
  Scenario: A maximum-length query name of a type no wildcard holds is NODATA
    # The type-mismatch path at maximum depth: the walk runs its whole window,
    # hits nothing and must return rather than run off the end of the index.
    # The apex `*` covers this name, so RFC 1034 §4.3.2 step 3(c) makes the
    # answer NODATA (VEGA-083 corrected this from NXDOMAIN, which was VEGA-010's
    # defect pinned as-is while VEGA-065 bounded the walk). The boundary this
    # scenario exists for — the shift at the deepest reachable depth — is
    # unchanged by that.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries a 123-label name inside "example.com." for type TXT
    Then the lookup result is NoData

  @boundary @vega-065 @enforced src/zone.rs:1125
  Scenario: A name above the zone origin is NXDOMAIN even with a wildcard present
    # "com." is an ancestor of the origin, not a descendant, so the probe window
    # is empty — its top is below its floor. A window that forgot that guard
    # would either probe outside the zone or compute a negative width.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "com." for type A
    Then the lookup result is NxDomain

  @boundary @vega-065 @enforced src/zone.rs:1159
  Scenario: A root-origin zone's apex wildcard covers names below it
    # `origin = "."` is accepted, and it drives the walk's floor to zero. Depth
    # zero must still be inside the window or the wildcard is unreachable.
    Given a zone whose origin is the root "." instead of the Background zone
    And the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "nope.example.com." for type A
    Then the answer section contains 1 record
    And the answer record owner is "nope.example.com."

  # ----------------------------------------------------------------- EMPTY

  @empty @vega-065 @enforced src/zone.rs:1111
  Scenario: A zone with no wildcards answers a deep miss at ordinary cost
    # "Are there any wildcards at all" is the guard that keeps the walk off the
    # path of every NXDOMAIN in every wildcard-free zone. This is the 1.13 us
    # control against which the 174.7 us wildcard case was measured; losing the
    # guard is a silent performance cliff on the commonest miss there is.
    Given the zone contains record set "www" of type "A" with values "203.0.113.20"
    When a client queries a 123-label name inside "example.com." for type A
    Then the lookup result is NxDomain

  # ------------------------------------------------------------- MALFORMED

  @malformed @vega-065 @enforced src/zone.rs:1125
  Scenario: The root name queried against a non-root zone is NXDOMAIN
    # "." is neither inside the zone nor a name the walk may probe. A walk whose
    # floor and ceiling were the wrong way round would treat it as in-range.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "." for type A
    Then the lookup result is NxDomain

  # --------------------------------------------------------------- HOSTILE

  @hostile @vega-065 @enforced src/zone.rs:1577
  Scenario: A root-origin zone with a wildcard terminates on a miss
    # `origin = "."` makes the floor zero, which is where a loop shaped as
    # "count down while depth >= floor" fails to terminate: it needs an extra
    # guard at zero that is easy to drop and impossible to notice. A
    # non-terminating walk under `panic = "abort"` is one packet, one wedged
    # worker. Enforced under a process watchdog so a spin fails the test instead
    # of hanging the suite.
    #
    # The answer is NODATA, not NXDOMAIN: with origin `.` the `*` sits at depth
    # 0, which is inside the probe window, so `nope.example.com.` genuinely has
    # a source of synthesis and RFC 1034 §4.3.2 step 3(c) forbids the name error
    # (VEGA-083). Termination — the property this scenario exists for — is
    # unaffected either way.
    Given a zone whose origin is the root "." instead of the Background zone
    And the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "nope.example.com." for type TXT
    Then the lookup returns NoData within the watchdog's deadline

  @hostile @vega-065 @enforced tests/properties.rs:785
  Scenario: The bounded walk agrees with the naive walk on every zone and every name
    # The behaviour-preservation claim, as a property rather than a list of
    # examples. Zones carry up to four wildcards at random depths, including
    # parents that contain asterisks; query names run from 1 to 122 labels and
    # are drawn from in-zone, exact wildcard parent, wildcard parent plus a
    # prefix, asterisk-leading, out-of-zone, the origin and the root. The naive
    # base_name() walk is transcribed as the reference.
    #
    # This is the check that rejects the num_labels() version: run against a
    # transcription of it, this harness shrinks to zone ["*.* AAAA"], query
    # "a.*.example.test." within 86 cases.
    Given any zone with between 0 and 4 wildcards
    And any query name of 1 to 122 labels
    When the name is looked up
    Then the answer matches a naive base_name() walk over the same zone
    And the records match too, owner name, TTL and rdata

  @hostile @vega-065 @enforced tests/properties.rs:839
  Scenario: Stacking labels above a covered name does not uncover it
    # The specific thing a bound derived from the query name gets wrong: it
    # silently stops probing once the query is shallow enough. If a name is
    # covered by a wildcard, prefixing it with up to 40 more labels must leave
    # it covered — the walk's reach is a property of the zone, not the packet.
    Given any zone with between 0 and 4 wildcards
    And a name that a wildcard covers
    When up to 40 further labels are prefixed to it
    Then it is still covered

  @hostile @vega-065 @enforced tests/perf_budget.rs:164
  Scenario: A maximum-length attacker-chosen name costs no more than a one-label name
    # The acceptance criterion. A 123-label NXDOMAIN, measured against a
    # 1-label NXDOMAIN in the same process on the same zone, must be inside 25x.
    # Measured on the unbounded walk: 208 ns shallow, 237.569 us deep, 1142.2x.
    #
    # Live since the commit that landed the depth bitmap: 239.631 µs to 1.657 µs
    # at 123 labels, a 145x cut, ratio 18.8x against a 25x budget.
    Given a 100,000-record zone containing one wildcard
    When a 123-label name inside the zone is looked up for type A
    Then it costs less than 25 times a 1-label lookup in the same zone

  # ------------------------------------------------ THE FENCE, FULLY DISCHARGED
  # src/zone.rs held THREE #[ignore]d tests pinning RFC defects that were live in
  # production. All three are now green:
  #
  #   * an_empty_non_terminal_is_nodata_not_nxdomain        GREEN at S2 (VEGA-006)
  #   * the_parent_of_a_wildcard_is_not_nxdomain            GREEN at S2 (VEGA-006)
  #   * a_wildcard_does_not_apply_below_a_name_that_exists  GREEN at S3 (VEGA-009)
  #
  # ...together with VEGA-009's wire-level twin,
  # tests/rfc_conformance.rs::a_wildcard_does_not_reach_below_a_name_that_exists.
  #
  # AMENDED AT VEGA-032 S3, in the commit that discharges the last of them, which
  # is the only commit allowed to touch this block. The guard in src/zone.rs is
  # renamed for the third and final time -- to
  # every_rfc_bug_this_model_fixes_is_green_and_none_of_them_is_ignored_again --
  # because a guard whose name says something is still ignored while nothing is
  # would be drift wearing a passing test. It now checks ONE direction, in TWO
  # files: none of them may be #[ignore]d again, and neither ignore reason may
  # reappear as a literal.
  #
  # WHAT S3 CHANGED. The walk that climbed to the first wildcard it could find is
  # deleted. The lookup finds the CLOSEST ENCLOSER by binary search over label
  # depth -- monotone because S2 closed the node set under ancestry, at most 8
  # probes for any name the wire can carry -- and then makes exactly ONE probe at
  # *.<closest encloser>. RFC 4592 3.3.1's "there is no search for an alternate"
  # is now a property of the code rather than a comment above a loop.
  #
  # Specced in features/closest-encloser.feature. Two consequences bear on the
  # scenarios in THIS file and both are stated there rather than restated here:
  #
  #   * DEEPEST-WINS IS GONE. "The closest wildcard answers when several could
  #     match" and "Two wildcards at non-adjacent depths are both reachable" are
  #     still green and their assertions are unchanged -- they are now satisfied
  #     by the closest-encloser rule instead of by walk order, which is the
  #     point. Their comments are updated; their assertions are not weakened.
  #   * THE DEPTH BITMAP IS GONE. Ancestor closure makes the populated depths
  #     contiguous, so VEGA-065's u128 carries no information a u8 pair does not.
  #     Its INVARIANT survives verbatim -- raw label counting, MAX_LABELS = 127,
  #     the num_labels ban -- and the ban is now enforced against the RULE rather
  #     than against a filename, with a non-vacuity assertion, because deleting
  #     the bitmap is exactly the change that could empty the guard's scope.
  #
  # VEGA-078 closes with it, and not as a patch: the probe count stops being
  # popcount(wildcard_depths) and becomes a constant.
  #
  # VEGA-098 closes with it too, and it is the part no ruling predicted. A
  # wildcard that is an EMPTY NON-TERMINAL -- "x.*.dev" makes "*.dev" one -- is a
  # name that exists, so RFC 4592 2.2.2 forbids synthesis AT it. The exact-match
  # probe excludes wildcard nodes, an S1 fidelity decision shipped with the note
  # that "that exclusion is what S2 and S3 remove, with a ruling"; S3 removes it.
  # It was found by the very oracle S3 retires, on main, from a seed in neither
  # regressions file.
  #
  # WHAT WAS RETIRED, AND WHAT REPLACED IT. VEGA-065's differential oracle,
  # tests/properties.rs::the_wildcard_walk_agrees_with_a_naive_base_name_walk,
  # compared against a naive base_name() walk -- the deliberately non-conformant
  # rule, which is VEGA-009 written down as a reference implementation. It stayed
  # true only by growing a whitelist: one permitted transition for VEGA-083, two
  # more for VEGA-032 S2, and S3 would have made four. It is RETIRED HERE, in the
  # commit that makes it wrong, and replaced by
  # the_wildcard_answer_agrees_with_a_brute_force_rfc_4592_closest_encloser,
  # which transcribes the RFC and permits ZERO transitions. The generators are
  # kept exactly as VEGA-065 wrote them, asterisk-leading arms included, because
  # those are the shapes a label-count mistake breaks.
  #
  # The commit that discharges the fence must, in the same diff, amend:
  #   * src/zone.rs::every_rfc_bug_this_model_fixes_is_green_and_none_of_them_is_
  #     ignored_again (renamed here)
  #   * the comment block above those tests in src/zone.rs
  #   * this block
  #   * the module doc of tests/rfc_conformance.rs
  # Editing that guard is legitimate ONLY in the commit that makes the
  # corresponding test pass. That is the rule VEGA-005 Amendment 3a set for the
  # reload classification table, and it is what stops "the fence moved" and "the
  # fix landed" from being indistinguishable in the log.
