Feature: CNAME resolution and chain safety
  # WHY THIS MATTERS
  # CNAME is the only recursive construct in the zone. Recursion driven by
  # attacker-influenced data on the packet path is where name servers die: a
  # two-record loop that nobody notices in review becomes an unbounded recursion,
  # a blown stack, and a process abort — remotely triggerable by a single query,
  # repeatedly, for free. The depth bound is not a nicety, it is the difference
  # between a misconfiguration and an outage. Separately, a CNAME whose target
  # leaves the zone must return only the CNAME: fabricating an answer for a name
  # we are not authoritative for is a lie, and chasing it would make us a
  # resolver, which we are not.
  #
  # Implementation: src/zone.rs (MAX_CNAME_DEPTH = 8, Zone::resolve lines 242-258)

  Background:
    Given a zone with origin "example.com"
    And an SOA record with minimum 60

  # ------------------------------------------------------ IN-ZONE CHASING

  @happy @enforced src/zone.rs:427
  Scenario: A CNAME to an in-zone target returns both the alias and the target record
    Given the zone contains record set "www" of type "CNAME" with values "origin.example.com."
    And the zone contains record set "origin" of type "A" with values "203.0.113.40"
    When a client queries "www.example.com." for type A
    Then the answer section contains 2 records
    And the first answer record type is CNAME
    And the second answer record type is A

  @happy @enforced tests/integration.rs:241
  Scenario: A chased CNAME reaches the client with both records over the wire
    Given the zone contains record set "alias" of type "CNAME" with values "origin.example.test."
    And the zone contains record set "origin" of type "A" with values "203.0.113.20"
    When a client sends a UDP query for "alias.example.test." type A
    Then the answer section contains 2 records
    And the first answer record type is CNAME
    And the second answer record type is A

  @boundary @gap
  Scenario: A two-hop CNAME chain is followed to the final address
    # Only a single hop is tested. The recursive call at src/zone.rs:253 is what
    # makes multi-hop work, and nothing exercises depth > 1 on a valid chain.
    Given the zone contains record set "a" of type "CNAME" with values "b.example.com."
    And the zone contains record set "b" of type "CNAME" with values "c.example.com."
    And the zone contains record set "c" of type "A" with values "203.0.113.40"
    When a client queries "a.example.com." for type A
    Then the answer section contains 3 records
    And the last answer record type is A

  @boundary @gap
  Scenario: A query for the CNAME type itself returns the CNAME without chasing
    # `if record_type != RecordType::CNAME` guards the chase. Querying CNAME
    # directly must return exactly one record. Untested.
    Given the zone contains record set "www" of type "CNAME" with values "origin.example.com."
    And the zone contains record set "origin" of type "A" with values "203.0.113.40"
    When a client queries "www.example.com." for type CNAME
    Then the answer section contains 1 record
    And the answer record type is CNAME

  @boundary @gap
  Scenario: An A record at the same name wins over a CNAME at that name
    # The exact-match lookup runs before the CNAME branch, so a name carrying
    # both (which is illegal per RFC 1034 but accepted by our loader) answers
    # from the A record. Undefined-by-omission today; pinning it makes the
    # loader's permissiveness a deliberate decision rather than an accident.
    Given the zone contains record set "dual" of type "CNAME" with values "origin.example.com."
    And the zone contains record set "dual" of type "A" with values "203.0.113.60"
    When a client queries "dual.example.com." for type A
    Then the answer section contains 1 record
    And the answer record type is A

  # ------------------------------------------------------ EXTERNAL TARGET

  @happy @enforced src/zone.rs:441
  Scenario: A CNAME to an out-of-zone target returns only the CNAME
    Given the zone contains record set "cdn" of type "CNAME" with values "cdn.provider.net."
    When a client queries "cdn.example.com." for type A
    Then the answer section contains 1 record
    And the answer record type is CNAME

  @boundary @gap
  Scenario: A CNAME to an out-of-zone target is still a NOERROR answer
    # The unit test inspects the Answer enum. The rcode the client sees is never
    # asserted, and a resolver treats NOERROR-with-CNAME very differently from
    # NXDOMAIN-with-CNAME.
    Given the zone contains record set "cdn" of type "CNAME" with values "cdn.provider.net."
    When a client queries "cdn.example.com." for type A
    Then the response rcode is NOERROR

  # ----------------------------------------------------- DANGLING TARGET

  @empty @gap
  Scenario: A CNAME to a non-existent in-zone name returns only the CNAME
    # src/zone.rs:253 discards the recursive result with `let _ =`, so a dangling
    # in-zone target yields Found with just the CNAME rather than NXDOMAIN. That
    # deliberate swallow has no test, and inverting it would turn every dangling
    # alias into an NXDOMAIN outage.
    Given the zone contains record set "www" of type "CNAME" with values "ghost.example.com."
    When a client queries "www.example.com." for type A
    Then the answer section contains 1 record
    And the answer record type is CNAME
    And the response rcode is NOERROR

  @empty @gap
  Scenario: A CNAME to an in-zone name that exists with another type returns only the CNAME
    Given the zone contains record set "www" of type "CNAME" with values "other.example.com."
    And the zone contains record set "other" of type "TXT" with values "\"hi\""
    When a client queries "www.example.com." for type A
    Then the answer section contains 1 record
    And the answer record type is CNAME

  # ------------------------------------------------------------- LOOPS

  @hostile @enforced src/zone.rs:451
  Scenario: A two-record CNAME loop terminates instead of recursing forever
    Given the zone contains record set "a" of type "CNAME" with values "b.example.com."
    And the zone contains record set "b" of type "CNAME" with values "a.example.com."
    When a client queries "a.example.com." for type A
    Then the lookup returns rather than overflowing the stack
    And the answer section contains at most 10 records

  @hostile @gap
  Scenario: A self-referential CNAME terminates
    # A record pointing at its own owner name is the tightest possible loop and
    # the easiest one to write by accident. Untested.
    Given the zone contains record set "self" of type "CNAME" with values "self.example.com."
    When a client queries "self.example.com." for type A
    Then the lookup returns rather than overflowing the stack

  @hostile @gap
  Scenario: A long CNAME chain is truncated at the depth bound
    # MAX_CNAME_DEPTH is 8. A 20-link chain must stop, and the existing loop test
    # only asserts "<= MAX_CNAME_DEPTH + 2" on a 2-cycle, which would still pass
    # if the bound were 3 or 30. Nothing pins the bound itself.
    Given the zone contains a CNAME chain of 20 links ending in an A record
    When a client queries the first link for type A
    Then the answer section contains at most 9 records
    And the final A record is absent

  @boundary @gap
  Scenario: A chain exactly at the depth bound still resolves to its address
    # The off-by-one that matters: depth 8 must resolve, depth 9 must truncate.
    # The current assertion cannot distinguish the two.
    Given the zone contains a CNAME chain of 8 links ending in an A record
    When a client queries the first link for type A
    Then the answer section ends with an A record

  @hostile @gap
  Scenario: A CNAME loop does not consume unbounded time under repeated queries
    # A remotely triggerable O(depth) walk per query is acceptable; an unbounded
    # one is a denial of service. Nothing measures it.
    Given the zone contains a two-record CNAME loop
    When 1000 queries are sent for the looping name
    Then every query is answered

  # ------------------------------------------------------------ MALFORMED

  @malformed @gap
  Scenario: A CNAME value that is not a DNS name fails at zone build time
    Given a config declaring record set "www" of type "CNAME" with values "not a name"
    When the zone is built
    Then the build fails with an error mentioning "invalid CNAME record value"

  @empty @gap
  Scenario: A CNAME record set with no values fails at zone build time
    Given a config declaring record set "www" of type "CNAME" with an empty value list
    When the zone is built
    Then the build fails with an error mentioning "has no values"

  # ------------------------------------------------------------- APEX

  @hostile @gap
  Scenario: A CNAME at the zone apex does not shadow the SOA answer
    # RFC 1034 forbids a CNAME alongside other data at the apex; the loader
    # accepts it. The apex SOA special-case in src/handler.rs:195 runs before the
    # record-map lookup, so an SOA query must still be answered from [zone.soa].
    # Untested, and a regression here breaks every secondary and every resolver
    # that needs the negative-caching TTL.
    Given the zone contains record set "@" of type "CNAME" with values "elsewhere.test."
    When a client queries "example.com." for type SOA
    Then the answer record type is SOA
