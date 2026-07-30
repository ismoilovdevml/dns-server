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
  #                 wildcard loop at lines 264-282)
  #
  # NOTE ON THE IMPLEMENTATION MODEL: a config entry "*.dev" is stored under the
  # key ("dev.example.com.", TYPE). A bare "*" is stored under the origin. At
  # lookup time the code walks up from the queried name's parent, stopping at the
  # origin or root.

  Background:
    Given a zone with origin "example.com"
    And an SOA record with minimum 60

  # ---------------------------------------------------------- MATCHING

  @happy @enforced src/zone.rs:464
  Scenario: A wildcard answers a name that does not otherwise exist
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "anything.dev.example.com." for type A
    Then the answer section contains 1 record

  @happy @enforced src/zone.rs:464
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

  @happy @enforced src/zone.rs:478
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

  @boundary @enforced src/zone.rs:494
  Scenario: A wildcard does not answer a type it was not configured for
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type TXT
    Then the lookup result is NxDomain

  @boundary @gap
  Scenario: A wildcard of the wrong type produces NXDOMAIN with the SOA over the wire
    # The unit test asserts the Answer enum only. The response the client sees —
    # rcode NXDOMAIN plus a cacheable SOA — is never asserted.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type TXT
    Then the response rcode is NXDOMAIN
    And the authority record type is SOA

  @boundary @gap
  Scenario: Wildcards of two types at the same node each answer their own type
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    And the zone contains record set "*.dev" of type "TXT" with values "\"wild\""
    When a client queries "x.dev.example.com." for type TXT
    Then the answer section contains 1 record
    And the answer record type is TXT

  # --------------------------------------------------------------- NESTED

  @boundary @gap
  Scenario: A wildcard covers a name several labels below it
    # RFC 4592 §2.1.1: "*.dev.example.com" matches "a.b.c.dev.example.com".
    # The base_name() walk at src/zone.rs:266-281 implements this. Untested.
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

  @hostile @gap
  Scenario: A long attacker-chosen name under a wildcard is answered without excessive work
    # Each additional label costs one more base_name() iteration. A 100-label
    # QNAME under a wildcard-bearing zone must still be answered promptly.
    Given the zone contains record set "*" of type "A" with values "203.0.113.1"
    When a client queries a 100-label name inside "example.com." for type A
    Then the server answers with a response rather than terminating
