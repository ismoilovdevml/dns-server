Feature: The closest encloser bounds wildcard synthesis (RFC 4592 3.3.1)
  # WHY THIS MATTERS
  #
  # A wildcard is the only place the server invents a record the operator never
  # wrote. RFC 4592 3.3.1 says exactly one name may do the inventing:
  #
  #   "If the 'closest encloser' ... has a wildcard record, the wildcard record
  #    is the source of synthesis ... If the source of synthesis does not exist
  #    ... there is no wildcard match. There is no search for an alternate."
  #
  # Vega walks up from the query name to the first wildcard it can find. So a
  # zone that says
  #
  #     *.dev    A  203.0.113.50      # catch-all for the dev subtree
  #     deep.dev A  203.0.113.51      # ...except this one, which is carved out
  #
  # answers a.deep.dev.example.com with 203.0.113.50. The operator wrote
  # deep.dev precisely to stop that. deep.dev exists, so it is the closest
  # encloser of a.deep.dev; the only source of synthesis is *.deep.dev; that
  # does not exist; the answer is NXDOMAIN. Vega instead leaks the catch-all
  # into a subtree that was explicitly taken out of its reach.
  #
  # The consequence is not cosmetic and it is not only an operator's problem. A
  # carve-out is how a delegation-shaped subtree, a decommissioned service or a
  # customer-specific name is kept away from a catch-all address. A wildcard
  # that reaches into it makes the server authoritatively assert an address for
  # every label an attacker can invent underneath a name the operator believed
  # was closed. That is VEGA-009.
  #
  # THE OTHER HALF IS COST. Because the walk visits every configured wildcard
  # depth, a zone declaring wildcards at 120 distinct depths spends ~229 us of
  # CPU answering one 276-byte packet that matches none of them -- worse than
  # the 174.7 us that opened VEGA-065, and 24x the 9.1 us per-query budget. The
  # operator supplies the wildcard count; the ATTACKER supplies the query name
  # that makes every probe miss and makes each probe pay its worst case. That is
  # VEGA-078, and it closes here for a structural reason rather than a tuning
  # one: the closest-encloser rule makes exactly ONE wildcard probe, so the
  # probe count stops being a function of the zone at all.
  #
  # HOW IT IS FIXED. VEGA-032 S2 closed the node set under ancestry, so "a node
  # exists at this depth" is monotone in the depth. S3 therefore finds the
  # closest encloser by BINARY SEARCH over label depth -- at most 8 probes for
  # any name the wire can carry -- and then makes exactly one probe at
  # *.<closest encloser>. "There is no search for an alternate" stops being a
  # comment above a loop and becomes a property of the code.
  #
  #   Implementation: src/zone.rs (Zone::resolve step B, Zone::closest_encloser)
  #   Ruling: .claude/backlog/decisions/VEGA-032-zone-data-model.md
  #           4.2 step B, 4.3, 5.4, 10.2 (S3), 13 (AC-3.1 .. AC-3.7)
  #   Closes: VEGA-009 (correctness), VEGA-078 (cost)
  #
  # WHAT THIS FILE DOES NOT COVER. Which names EXIST is
  # features/empty-non-terminals.feature (S2) -- and it is a prerequisite, not
  # background reading: if ancestor materialisation is ever broken the binary
  # search silently returns a SHALLOWER encloser than the truth, which is
  # VEGA-009 reopened with answers that look correct. That is the single most
  # dangerous coupling in the model and the scenario "A closest encloser
  # computed one level short is visible in an answer" below exists to make it
  # visible rather than silent. Delegation is S4's, mandatory SOA is S5's.
  #
  # WHAT IS SUBSUMED, NOT UNDONE. VEGA-065 recorded a u128 bitmap of the label
  # depths carrying a wildcard and probed the set bits. Ancestor closure makes
  # the populated depths contiguous, so that bitmap carries no information a u8
  # pair does not, and it is deleted here. Its INVARIANT survives verbatim and
  # is re-pinned below: label_count counts raw labels including a leading
  # asterisk, MAX_LABELS is 127 because RFC 1035 2.3.4 caps a name at 255
  # octets, and LowerName::num_labels -- which discounts a leading asterisk --
  # stays banned anywhere the raw index space is used. Deleting the bitmap must
  # not delete the reason it was correct.

  Background:
    Given a zone with origin "example.com." and an SOA
    And the zone declares nothing else unless a scenario says so

  # =========================================================================
  # HAPPY -- the rule, working
  # =========================================================================

  @happy
  Scenario: A wildcard synthesises for a name whose closest encloser is its parent
    # The ordinary case, and the control for every negative below. Nothing
    # exists between "dev.example.com." and the query, so "dev.example.com." is
    # the closest encloser, "*.dev.example.com." is the source of synthesis, and
    # it exists.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type A
    Then the answer section contains 1 record
    And the answer holds 203.0.113.50
    And the answer record owner is "x.dev.example.com."

  @happy
  Scenario: A wildcard reaches many labels down when nothing in between exists
    # RFC 4592 2.1.1: "*.dev.example.com" matches "a.b.c.dev.example.com". The
    # closest encloser is still "dev.example.com." because none of
    # "c.dev", "b.c.dev" exists -- reach is not restricted, only overruled by a
    # name that exists.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "a.b.c.dev.example.com." for type A
    Then the answer section contains 1 record
    And the answer record owner is "a.b.c.dev.example.com."

  @happy
  Scenario: The apex is the closest encloser when the zone holds nothing else
    # The floor of the search. Every in-zone name descends from the apex and the
    # apex is always a node, so the search always succeeds and never has to
    # report "none".
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "a.b.c.d.e.example.com." for type A
    Then the answer section contains 1 record
    And the answer holds 203.0.113.1

  # =========================================================================
  # BOUNDARY -- the carve-out, which is the whole defect
  # =========================================================================

  @boundary
  Scenario: A wildcard does not apply below a name that exists
    # VEGA-009's headline, and the test that has been red since the issue was
    # filed. "deep.dev.example.com." exists, so it -- not "dev.example.com." --
    # is the closest encloser of "a.deep.dev.example.com.". The source of
    # synthesis is therefore "*.deep.dev.example.com.", which does not exist, so
    # RFC 4592 3.3.1 forbids looking anywhere else and the answer is NXDOMAIN.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "deep.dev" of type "A" with values "203.0.113.51"
    When a client queries "a.deep.dev.example.com." for type A
    Then the lookup result is NxDomain
    And the answer does not hold 203.0.113.50

  @boundary
  Scenario: The carved-out name itself still answers
    # The anti-vacuity half of the scenario above. A fix that made the whole
    # subtree disappear would pass it. The name the operator carved out must
    # still serve its own record.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "deep.dev" of type "A" with values "203.0.113.51"
    When a client queries "deep.dev.example.com." for type A
    Then the answer holds 203.0.113.51

  @boundary
  Scenario: The sibling of a carved-out name is still synthesised
    # The second anti-vacuity half, and the one that distinguishes "the closest
    # encloser is respected" from "the wildcard was switched off". "other.dev"
    # does not exist, so its closest encloser is still "dev.example.com." and
    # the catch-all still applies to it.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "deep.dev" of type "A" with values "203.0.113.51"
    When a client queries "other.dev.example.com." for type A
    Then the answer holds 203.0.113.50

  @boundary
  Scenario: The nested carve-out holds two levels down
    # AC-3.2. Three names in a chain, so a fix that only compares against the
    # query's immediate parent passes the scenario above and fails this one.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "b.dev" of type "A" with values "203.0.113.51"
    And the zone contains record set "c.b.dev" of type "A" with values "203.0.113.52"
    When a client queries "x.c.b.dev.example.com." for type A
    Then the lookup result is NxDomain
    And a query for "x.dev.example.com." type A holds 203.0.113.50

  @boundary
  Scenario: An empty non-terminal is a closest encloser like any other name
    # The S2/S3 interaction, and the reason S3 could not have been built before
    # S2. "b.deep.dev.example.com." is configured NOWHERE -- it exists only
    # because "a.b.deep.dev" does (RFC 4592 2.2.2). It is still a name that
    # exists, so it is still the closest encloser, and "*.dev" must not reach
    # past it. A model in which only DECLARED names block a wildcard answers
    # 203.0.113.50 here.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "a.b.deep.dev" of type "A" with values "203.0.113.53"
    When a client queries "x.b.deep.dev.example.com." for type A
    Then the lookup result is NxDomain
    And a query for "x.dev.example.com." type A holds 203.0.113.50

  @boundary
  Scenario: There is no search for an alternate wildcard above the closest encloser
    # RFC 4592 3.3.1's last sentence, made observable. The source of synthesis
    # EXISTS here and simply carries no A record. A walk continues past it and
    # serves the apex wildcard's address; the closest-encloser rule stops, and
    # RFC 1034 4.3.2 step 3(c) makes that NODATA because the "*" node exists.
    #
    # This is the scenario that distinguishes "closest encloser" from
    # "deepest wildcard wins": under deepest-wins both rules pick the same
    # SOURCE and differ only on whether the search continues.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    And the zone contains record set "*.dev" of type "TXT" with values "\"only text here\""
    When a client queries "x.dev.example.com." for type A
    Then the response rcode is NOERROR
    And the answer section is empty
    And the answer does not hold 203.0.113.1

  @boundary
  Scenario: A wildcard does not synthesise at a wildcard name that exists
    # VEGA-098, and the one part of S3 that is not about the closest encloser.
    #
    # "*.*.dev" is configured, so ancestor closure materialises
    # "*.dev.example.com" as an empty non-terminal. RFC 4592 2.1.1 makes "is a
    # wildcard" a property of the NAME, never of how the node came to exist, and
    # 2.2.2 says synthesis does not apply at a name that exists. So the apex
    # "* TXT" must not be applied AT "*.dev.example.com" -- that name exists, and
    # the answer is NODATA.
    #
    # The closest-encloser search never runs here: the name is a node and RFC
    # 1034 4.3.2 step 3.a answers it. What has to change is the exact-match
    # probe, which deliberately EXCLUDES wildcard nodes -- an S1 fidelity
    # decision, taken because the map model it replaced held wildcards in
    # neither `exact` nor `names`, and shipped with the note that "that exclusion
    # is what S2 and S3 remove, with a ruling". This is the ruling.
    #
    # Found on main by the very oracle S3 retires, from a seed in neither
    # regressions file. S2 did not introduce it; S2 made VEGA-009 reachable in a
    # shape the oracle could see.
    Given the zone contains record set "*" of type "TXT" with values "\"hello\""
    And the zone contains record set "*.*.dev" of type "A" with values "203.0.113.60"
    When a client queries "*.dev.example.com." for type TXT
    Then the response rcode is NOERROR
    And the answer section is empty
    And the answer does not hold "hello"

  @boundary
  Scenario: A wildcard node still answers a query for its own literal name
    # The other half, and the anti-vacuity control for the scenario above:
    # removing the exact probe's wildcard exclusion must make these names answer
    # MORE precisely, never make them answer nothing. RFC 4592 2.3 -- an asterisk
    # in a QNAME gets no special processing, so this is an ordinary exact match.
    Given the zone contains record set "*" of type "TXT" with values "\"hello\""
    And the zone contains record set "*.*.dev" of type "A" with values "203.0.113.60"
    When a client queries "*.*.dev.example.com." for type A
    Then the answer section contains 1 record
    And the answer holds 203.0.113.60
    And the answer record owner is "*.*.dev.example.com."

  @boundary
  Scenario: The closest encloser's own wildcard wins over a shallower one
    # AC-3.3, restated. "The closest wildcard answers when several could match"
    # was satisfied by walk ORDER; it is now satisfied by the rule. Same
    # assertion, different reason -- which is the point of keeping it.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    And the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type A
    Then the answer holds 203.0.113.50

  @boundary
  Scenario: Wildcards at non-adjacent depths are each reachable from their own names
    # AC-3.3's second half. Under the bitmap this worked because both depths
    # were set; under the closest-encloser rule it works because each query's
    # closest encloser is a different name. Neither may shadow the other.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    And the zone contains record set "*.a.b.c.d.e.f" of type "A" with values "203.0.113.8"
    When a client queries "x.a.b.c.d.e.f.example.com." for type A
    Then the answer holds 203.0.113.8
    And a query for "x.example.com." type A holds 203.0.113.1

  @boundary
  Scenario: A name below a carve-out is NXDOMAIN for every type, not just the configured one
    # The rcode must not depend on the QTYPE. A dual-stack client asks AAAA
    # alongside A and a resolver asks ANY; if any of them answered NOERROR the
    # zone would be reporting two different existence answers for one name.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "deep.dev" of type "A" with values "203.0.113.51"
    When a client queries "a.deep.dev.example.com." for types A, AAAA, TXT and ANY
    Then every answer is NXDOMAIN

  @boundary
  Scenario: A closest encloser computed one level short is visible in an answer
    # The mutant the ruling calls the most dangerous in the model, given a shape
    # that exposes it. Wildcards at two adjacent depths with an existing name
    # between them:
    #
    #   *.dev          -> answers x.dev
    #   x.deep.dev     -> exists, so it encloses q.x.deep.dev
    #   *.x.deep.dev   -> answers q.x.deep.dev
    #   deep.dev       -> exists, and carries NO wildcard
    #
    # A search that stops one level short answers q.x.deep.dev NXDOMAIN (it
    # looks for *.deep.dev) and answers q.deep.dev from *.dev (it looks for
    # *.dev). Both are wrong, in opposite directions, and either alone would be
    # invisible on a fixture without the ladder.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "deep.dev" of type "A" with values "203.0.113.51"
    And the zone contains record set "x.deep.dev" of type "A" with values "203.0.113.52"
    And the zone contains record set "*.x.deep.dev" of type "A" with values "203.0.113.53"
    When a client queries "q.x.deep.dev.example.com." for type A
    Then the answer holds 203.0.113.53
    And a query for "q.deep.dev.example.com." type A is NxDomain
    And a query for "q.dev.example.com." type A holds 203.0.113.50

  @boundary
  Scenario: The closest encloser search costs at most eight probes at the deepest name the wire can carry
    # The bound the binary search is chosen for. 127 labels is RFC 1035 2.3.4's
    # ceiling (127 * 2 + 1 = 255 octets), so ceil(log2(127)) = 7 probes plus the
    # speculative one at the parent. It is stated as a scenario because "at most
    # eight" is what makes the cost independent of both the zone and the query,
    # which is the whole of VEGA-078.
    Given a zone whose origin is the root "." instead of the Background zone
    And the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries a 127-label name for type A
    Then the closest encloser search makes at most 8 probes
    And the source of synthesis is probed exactly once

  # =========================================================================
  # EMPTY -- zones and answers with nothing in them
  # =========================================================================

  @empty
  Scenario: A zone with no wildcards answers NXDOMAIN without probing for one
    # The closest encloser is still computed -- it is where a delegation check
    # will hang at S4 -- but the single source-of-synthesis probe misses and
    # there is nothing else to try.
    Given the zone contains record set "www" of type "A" with values "203.0.113.20"
    When a client queries "nope.example.com." for type A
    Then the lookup result is NxDomain

  @empty
  Scenario: A zone holding only its apex encloses every name at the apex
    # The degenerate zone. Nothing exists below the origin, so the closest
    # encloser of every in-zone name is the apex and the source of synthesis is
    # "*.example.com.", which does not exist.
    Given the zone declares no records at all beyond its SOA
    When a client queries "anything.deep.example.com." for type A
    Then the lookup result is NxDomain
    And the lookup does not panic

  @empty
  Scenario: An empty answer at the source of synthesis is NODATA, not NXDOMAIN
    # RFC 1034 4.3.2 step 3(c) sets the authoritative name error only when the
    # "*" node does not exist. Here it exists and holds no record of the queried
    # type, so control goes to step 6 -- an empty answer section, RFC 2308 2.2
    # NODATA. Answering NXDOMAIN would let an RFC 8020 2 resolver deny the
    # records the wildcard does carry (VEGA-083, preserved).
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type AAAA
    Then the response rcode is NOERROR
    And the answer section is empty
    And the authority section contains the zone SOA

  # =========================================================================
  # MALFORMED -- names the search must refuse to run on
  # =========================================================================

  @malformed
  Scenario: The root name queried against a non-root zone is NXDOMAIN
    # "." is neither in the zone nor a name the search may probe. A window whose
    # floor and ceiling were the wrong way round would treat it as in range and
    # index below the origin.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "." for type A
    Then the lookup result is NxDomain

  @malformed
  Scenario: The apex itself is never covered by its own wildcard
    # RFC 4592 2.1.2: a wildcard's owner name never matches the name it is
    # attached to. The apex is a node, so it is answered by the exact arm and
    # the search never runs -- but a search whose upper bound were the query's
    # OWN depth rather than its parent's would make "*.example.com." the source
    # of synthesis for "example.com.".
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "example.com." for type A
    Then the response rcode is NOERROR
    And the answer section is empty

  @malformed
  Scenario: An out-of-zone name is refused before any encloser is computed
    # The search assumes every name it sees descends from the apex; that is what
    # lets it return the apex as its floor without an Option. A name outside the
    # zone must be rejected before it reaches the search at all.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "www.example.invalid." for type A
    Then the lookup result is NxDomain

  @malformed
  Scenario: An asterisk in the query name gets no special processing
    # RFC 4592 2.3. "x.*.dev.example.com." is an ordinary name whose leftmost
    # labels happen to include an asterisk. Its closest encloser is
    # "*.dev.example.com." -- which exists as an empty non-terminal, because
    # "*.*.dev" was configured -- so the source of synthesis is
    # "*.*.dev.example.com." and it answers.
    #
    # This is the shape LowerName::num_labels miscounts: it discounts a leading
    # asterisk while trim_to does not, and mixing the two indexes one label off
    # for exactly these names. VEGA-065's four asterisk cases stay green here.
    Given the zone contains record set "*.*.dev" of type "A" with values "203.0.113.60"
    When a client queries "x.*.dev.example.com." for type A
    Then the answer section contains 1 record
    And the answer record owner is "x.*.dev.example.com."

  @malformed
  Scenario: A wildcard's own literal name is answered from it, not synthesised
    # "*.dev.example.com." IS a node (RFC 4592 2.1.1), so a query for it is an
    # exact match under RFC 1034 4.3.2 step 3.a and the closest-encloser search
    # never runs. Reachable with one `dig '*.dev.example.com' A`.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "*.dev.example.com." for type A
    Then the answer section contains 1 record
    And the answer record owner is "*.dev.example.com."

  # =========================================================================
  # HOSTILE -- what an attacker chooses
  # =========================================================================

  @hostile
  Scenario: An attacker cannot reach into a carve-out by inventing labels beneath it
    # The security statement of VEGA-009. The operator carved "deep.dev" out of
    # the catch-all; an attacker who can pick any name at all must not be able
    # to make the server assert an address inside it. Every invented name below
    # the carve-out is a name error.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "deep.dev" of type "A" with values "203.0.113.51"
    When a client queries 40 distinct invented names beneath "deep.dev.example.com." for type A
    Then every answer is NXDOMAIN
    And no answer holds 203.0.113.50

  @hostile
  Scenario: A 127-label attacker-chosen name below a carve-out is answered without excessive work
    # The deepest name the wire can carry, aimed at the subtree the operator
    # closed. It must be a name error, it must terminate, and it must cost what
    # a shallow query costs -- the search is at most eight probes whatever the
    # depth.
    Given a zone whose origin is the root "." instead of the Background zone
    And the zone contains record set "*" of type "A" with values "203.0.113.1"
    And the zone contains record set "a.a.example.com." of type "A" with values "203.0.113.2"
    When a client queries a 127-label name ending in "a.a.example.com." for type A
    Then the lookup result is NxDomain within the watchdog's deadline

  @hostile
  Scenario: A root-origin zone terminates on a wildcard miss
    # AC-3.7, kept verbatim from VEGA-065. origin "." drives the search floor to
    # zero, which is where a loop shaped as "count down while depth >= floor"
    # fails to terminate: it needs a guard at zero that is easy to drop and
    # impossible to notice. Under panic = "abort" a non-terminating lookup is one
    # packet and one wedged worker.
    #
    # The answer is NODATA, not NXDOMAIN: with origin "." the "*" sits at depth 0,
    # which is the closest encloser of every name that does not otherwise exist,
    # so the source of synthesis genuinely exists and RFC 1034 4.3.2 step 3(c)
    # forbids the name error (VEGA-083).
    Given a zone whose origin is the root "." instead of the Background zone
    And the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries "nope.example.com." for type TXT
    Then the lookup returns NoData within the watchdog's deadline

  @hostile
  Scenario: A zone with wildcards at 120 depths costs no more than one with a single depth
    # VEGA-078, closed as a consequence rather than as a patch. The bounded walk
    # probes once per DISTINCT configured wildcard depth, so one 276-byte packet
    # against a 120-depth zone bought ~229 us of CPU -- 24x the 9.1 us per-query
    # budget, and worse than the 174.7 us that opened VEGA-065. The operator
    # supplies the depth count; the attacker supplies the query name that makes
    # every probe miss.
    #
    # Under the closest-encloser rule the probe count is a constant. The gate is
    # a RATIO between a 120-depth zone and a 1-depth zone measured back to back
    # in the same process, so a slow or shared runner cannot make it flap, plus
    # the absolute figure the ruling commits to.
    Given a zone declaring wildcards at 120 distinct label depths
    And an otherwise identical zone declaring a wildcard at exactly 1 depth
    When a 123-label name matching no wildcard parent is looked up in each
    Then the 120-depth zone costs no more than 1.5 times the 1-depth zone
    And the 120-depth lookup costs less than 2 microseconds

  @hostile
  Scenario: The lookup allocates nothing on the closest-encloser path
    # The search runs on the suffix hashes computed in one reverse pass before
    # any probe, so no probe materialises a name. VEGA-065 declared "two Vec
    # allocations per trim_to probe" as its residual cost and asked for an issue;
    # it is paid off here because the same primitive is what the search needs.
    # An attacker-chosen allocation count on the negative path is the shape of
    # every allocator-pressure DoS.
    Given a zone containing a wildcard and a carved-out name beneath it
    When 1000 lookups are made on each of the NXDOMAIN, NODATA and covered shapes
    Then no lookup allocates

  # =========================================================================
  # DIFFERENTIAL -- the claim, mechanised
  # =========================================================================
  # The scenarios above are examples. What makes S3 reviewable without reading
  # the arena is that every generated zone and every generated query is run
  # through the pre-S3 model and the RFC and the difference is CLASSIFIED. The
  # classification is derived from the CONFIG, never from the Zone under test,
  # so the implementation gets no vote in which of its own changes are allowed.

  @boundary
  Scenario: Every S3 difference is one of four named classes
    # The transition set, and it is derived rather than whitelisted. A rule of
    # the shape "a synthesised answer may become NXDOMAIN" would also pass a
    # build that had simply stopped synthesising.
    #
    #   W1  a synthesised answer whose source was not *.<closest encloser>
    #       becomes exactly what RFC 4592 3.3.1 says: NXDOMAIN when the closest
    #       encloser holds no wildcard, NODATA when it holds one carrying other
    #       types;
    #   W2  a NODATA that came from coverage above the closest encloser becomes
    #       NXDOMAIN -- the name error is restored, including for ANY;
    #   W3  a CNAME chase whose target was reached only by a synthesis above the
    #       closest encloser loses its tail, and the surviving answer is a strict
    #       prefix ending on the CNAME;
    #   W4  a wildcard is no longer applied AT a wildcard-shaped name that
    #       exists, so that name answers what it actually holds -- its own RRset
    #       of the queried type, or NODATA.
    #
    # W4 IS NOT IN THE RULING, AND WAS NOT IN THE FIRST S3 FIXTURE. It is
    # VEGA-098, and it turned up as an UNCLASSIFIED DIFFERENCE the moment its
    # shape was added -- which is the whole argument for a classification that
    # fails on anything unnamed rather than one that permits a family of
    # transitions. A whitelist of the shape "a synthesised answer may become
    # NXDOMAIN" would have absorbed it in silence.
    Given any zone with wildcards, carved-out names and empty non-terminals
    And any query name constructed from that zone
    When the answer is compared against the pre-S3 model over the same node set
    Then every difference falls into W1, W2, W3 or W4
    And an unclassifiable difference fails the run

  @boundary
  Scenario: The classifier refuses transitions the closest-encloser rule cannot produce
    # The proof the transition set is not too loose, and the assertion that would
    # have to be DELETED rather than weakened for a wrong S3 to pass. Five
    # refusals and two accepts, so it cannot pass by refusing everything.
    Given the S3 fixture zone and its config-derived model
    When the classifier is handed a transition S3 must not produce
    Then it returns no class
    And it still returns a class for the transition S3 must produce

  @boundary
  Scenario: S3 does not undo S2 at an empty non-terminal
    # The specific refusal that matters most. An empty non-terminal is a name
    # that EXISTS, so no wildcard rule applies to it at all; a classifier that
    # permitted NODATA -> NXDOMAIN wherever it appeared would let S3 silently
    # reopen VEGA-006 while closing VEGA-009, and the differential would stay
    # green. S2's own three transition classes are still checked in the same
    # pass, against the same fixture, for the same reason.
    Given a name that exists only because something is configured beneath it
    When the classifier is handed NODATA becoming NXDOMAIN at that name
    Then it returns no class

  @boundary
  Scenario: All four transition classes are actually reached
    # A class nothing exercises is a whitelist entry, not a gate. The fixture is
    # built to produce each one -- a carve-out under a wildcard for W1, a
    # type-only wildcard at the closest encloser for W1's NODATA arm, an ANY
    # query over a carve-out for W2, and a CNAME into a carved-out name for W3 --
    # rather than left to a generator that reaches them at a rate it chooses.
    Given the S3 fixture zone
    When every fixture name is compared across the pre-S3 and RFC models
    Then each of W1, W2, W3 and W4 is observed at least once
    And no difference is left unclassified

  @hostile
  Scenario: The answer agrees with a brute-force transcription of RFC 4592 3.3.1
    # AC-3.4, and the replacement for VEGA-065's retiring oracle. That one
    # compared against a naive base_name() walk -- the DELIBERATELY
    # NON-CONFORMANT rule -- and needed a growing list of permitted transitions
    # to stay true: one for VEGA-083, two for VEGA-032 S2, and it would need
    # three more here. The replacement compares against the RFC itself:
    # enumerate the ancestors, take the deepest that exists, form *.<that>, probe
    # once. It permits ZERO transitions, which is the point of replacing rather
    # than extending.
    Given any zone with between 0 and 4 wildcards and any ordinary names
    And any query name of 1 to 122 labels, including asterisk-leading ones
    When the name is looked up
    Then the answer equals the brute-force closest-encloser answer exactly
    And the records match too, owner name, TTL, rdata and order

  @boundary
  Scenario: Stacking labels above a covered name uncovers it exactly when a name in between exists
    # VEGA-065's second property, AMENDED because the closest-encloser rule makes
    # its old form false. "If a name is covered, prefixing labels leaves it
    # covered" held under a walk; under the RFC it holds only while nothing
    # between the wildcard's parent and the deeper name exists. Stated in both
    # directions so the amendment strengthens it rather than narrowing it: still
    # covered when the path is clear, and a NAME ERROR when it is not.
    Given any zone with between 0 and 4 wildcards
    And a name that a wildcard covers
    When up to 40 further labels are prefixed to it
    Then it is still covered if no prefixed name exists in the zone
    And it is a name error if one does

  # =========================================================================
  # THE BITMAP IS SUBSUMED, NOT UNDONE
  # =========================================================================

  @boundary
  Scenario: The zone carries no wildcard depth bitmap
    # Ancestor closure makes the populated depths contiguous, so the u128 is
    # exactly ((1 << (max_depth + 1)) - 1) & !((1 << origin_depth) - 1) and
    # carries no information a u8 pair does not. Sixteen bytes per zone become
    # one, and -- far more important -- the probe count stops being
    # popcount(wildcard_depths).
    Given the zone module as it stands after S3
    When it is read for the depth bitmap
    Then no field, walk or invariant mentions wildcard_depths

  @boundary
  Scenario: VEGA-065's label index space stays banned where it is dangerous
    # The bitmap goes; the reasoning that made it correct must not. Name::trim_to
    # and the suffix hashes index RAW labels, LowerName::num_labels discounts a
    # leading asterisk, and mixing them shifts every probe one label off for any
    # name whose leftmost label is an asterisk -- four silent wrong answers on
    # the authoritative path.
    #
    # The guard is written against the RULE rather than against a file list: any
    # module that works in the raw index space -- naming trim_to(, label_count,
    # MAX_LABELS or SuffixHashes -- must not also name num_labels. It carries a
    # non-vacuity assertion, because a guard whose scope has quietly emptied
    # passes forever, and the scope is exactly what deleting the bitmap could
    # empty.
    Given every module under src/
    When a module works in the raw label index space
    Then it does not name the asterisk-discounting label count
    And at least one module is in scope, so the guard still bites

  @boundary
  Scenario: MAX_LABELS is still the arithmetic consequence of the 255-octet limit
    # 127, because RFC 1035 3.1 encodes a single-octet label in two octets and
    # terminates the name with one: 2n + 1 <= 255. It is not a tuning knob, and
    # it is the deepest index the suffix hash array will ever see. One past it,
    # under panic = "abort", is a full outage from one packet.
    Given the zone module's label ceiling
    Then it equals 127
    And a 127-label name is answered rather than mis-indexed

  # =========================================================================
  # THE GATES THAT MUST NOT MOVE
  # =========================================================================
  # S3 deletes a u128 per zone and changes the probe strategy. Both are cheap to
  # claim and easy to get wrong in the direction nobody measures, so each is
  # stated as an expectation with a number attached, measured at bd4b397.

  @boundary
  Scenario: The flat 100,000-record fixture does not grow
    # 30,255,464 B (28.8 MiB, 302 B per record), unmoved from S1 to S2 to the
    # byte. It materialises no empty non-terminals and holds one wildcard, so
    # deleting a per-ZONE u128 must move it by 16 bytes at most -- which is below
    # the measurement's own noise. A regression here means the arena grew.
    Given a zone of 100,000 flat A records
    Then its live heap is at most 40 MiB
    And it is within 16 bytes of 30,255,464 B

  @boundary
  Scenario: An empty non-terminal still costs one node and nothing else
    # 105 B measured against a 110 B budget over 200,000 empty non-terminals.
    # S3 touches neither materialisation nor the node layout, so this must not
    # move at all; it is here because a closest-encloser search that memoised
    # anything per node is the obvious wrong way to make the search cheap.
    Given a zone of 100,000 records at names implying two empty non-terminals each
    Then each empty non-terminal costs at most 110 bytes of live heap

  @boundary
  Scenario: The negative paths still allocate nothing
    # 0 allocations per 1,000 lookups on all three shapes at S2. The search must
    # not reintroduce the trim_to allocations VEGA-065 declared as its residual
    # cost -- that is the whole reason the suffix hashes exist.
    Given a zone containing a wildcard
    When 1000 lookups are made on each of the three negative shapes
    Then each shape allocates zero times

  @boundary
  Scenario: The exact-hit and empty-non-terminal costs do not regress
    # shallow 55 ns, deep(123) 324 ns, deep(127) 423 ns, exact hit 125 ns,
    # empty non-terminal 78 ns at bd4b397. The deep figures are expected to
    # IMPROVE, because the search replaces a walk over configured depths with at
    # most eight probes; the shallow ones are expected to be unchanged, because a
    # name that exists never reaches the search at all. A shallow regression
    # means the search is running on the exact-match path.
    Given the perf budget fixtures
    Then the deep/shallow ratio is at most 10x
    And an empty non-terminal still costs no more than an exact hit

  # ---------------------------------------------------- THE FENCE, DISCHARGED
  # src/zone.rs held three #[ignore]d tests pinning RFC defects. Two were
  # discharged at S2 (VEGA-006). The third --
  # a_wildcard_does_not_apply_below_a_name_that_exists -- is VEGA-009's and is
  # discharged HERE, together with its wire-level twin at
  # tests/rfc_conformance.rs::a_wildcard_does_not_reach_below_a_name_that_exists.
  #
  # The commit that discharges it must, in the same diff, amend:
  #
  #   * src/zone.rs::the_rfc_bug_this_step_must_not_touch_is_still_ignored_and_
  #     the_two_it_fixes_are_not -- renamed again, because a guard whose name
  #     says something is still ignored while nothing is is drift wearing a
  #     passing test. It becomes a one-directional guard: all three are green and
  #     none of them may be #[ignore]d again. Re-ignoring a test is the cheapest
  #     way to make a regression disappear, and every one of these was
  #     un-ignored by a ruling.
  #   * the comment block above those tests in src/zone.rs;
  #   * the NOT THIS ISSUE'S block in features/wildcards.feature;
  #   * the module doc of tests/rfc_conformance.rs.
  #
  # Editing that guard is legitimate ONLY in the commit that makes the
  # corresponding test pass -- the rule VEGA-005 Amendment 3a set for the reload
  # classification table. It is what stops "the fence moved" and "the fix
  # landed" from being indistinguishable in the log.

  @happy
  Scenario: The pinned VEGA-009 tests are green and no longer ignored
    Given src/zone.rs and tests/rfc_conformance.rs after S3
    Then a_wildcard_does_not_apply_below_a_name_that_exists carries no #[ignore]
    And a_wildcard_does_not_reach_below_a_name_that_exists carries no #[ignore]
    And neither of VEGA-006's two has been re-ignored

  @happy
  Scenario: The wildcard does not reach below an existing name over the wire
    # The same rule end to end, over UDP, against a running server: the zone
    # layer can be right while the handler turns the resolution into the wrong
    # rcode. This is the test an operator could have run with dig on the day
    # VEGA-009 was filed.
    Given a server serving "*.apps" A and "deep.apps" A
    When a client queries "a.deep.apps.example.test." for type A over UDP
    Then the response rcode is NXDOMAIN
    And the answer section is empty
