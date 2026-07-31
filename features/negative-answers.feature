Feature: Negative answers and out-of-zone refusal
  # WHY THIS MATTERS
  # Getting a negative answer wrong is worse than getting a positive one wrong,
  # because the mistake is cached and multiplied by every resolver downstream.
  # NXDOMAIN for a name that exists poisons a service off the internet for the
  # SOA minimum. NODATA rendered as NXDOMAIN breaks IPv6 fallback and mail
  # routing. A missing SOA in the authority section means resolvers cannot cache
  # the negative at all, turning every miss into repeated load on us — the exact
  # amplification profile a flood wants. And answering NXDOMAIN for a namespace
  # we are not authoritative for is a lie about somebody else's zone; REFUSED is
  # the only honest response.
  #
  # Implementation: src/handler.rs (Resolved::negative / Resolved::refused,
  #                 DnsHandler::resolve), src/zone.rs (Answer::NoData/NxDomain)

  Background:
    Given a zone with origin "example.com"
    And an SOA record with minimum 60

  # ------------------------------------------------- NODATA vs NXDOMAIN

  @happy @enforced src/zone.rs:400
  Scenario: A name that exists with a different type resolves to NODATA
    Given the zone contains record set "www" of type "A" with values "203.0.113.20"
    When the zone is asked for "www.example.com." type AAAA
    Then the lookup result is NoData

  @happy @enforced src/handler.rs:512
  Scenario: NODATA is returned as NOERROR with an empty answer section
    Given the zone contains record set "www" of type "A" with values "203.0.113.20"
    When a client queries "www.example.com." for type AAAA
    Then the response rcode is NOERROR
    And the answer section is empty

  @happy @enforced src/zone.rs:409
  Scenario: A name that does not exist resolves to NXDOMAIN
    Given the zone contains record set "www" of type "A" with values "203.0.113.20"
    When the zone is asked for "nope.example.com." type A
    Then the lookup result is NxDomain

  @happy @enforced src/handler.rs:503
  Scenario: NXDOMAIN is returned with the NXDOMAIN rcode
    Given the zone contains no records
    When a client queries "missing.example.com." for type A
    Then the response rcode is NXDOMAIN

  @happy @enforced tests/integration.rs:214
  Scenario: NODATA over the wire carries NOERROR and no answers
    Given the zone contains record set "www" of type "A" with values "203.0.113.10"
    When a client sends a UDP query for "www.example.test." type AAAA
    Then the response rcode is NOERROR
    And the answer section is empty

  @happy @enforced tests/integration.rs:196
  Scenario: NXDOMAIN over the wire carries the NXDOMAIN rcode
    Given the zone contains no records
    When a client sends a UDP query for "nope.example.test." type A
    Then the response rcode is NXDOMAIN
    And the answer section is empty

  # ------------------------------------------------ SOA IN THE AUTHORITY

  @happy @enforced src/handler.rs:503
  Scenario: An NXDOMAIN response carries the zone SOA in the authority section
    Given the zone contains no records
    When a client queries "missing.example.com." for type A
    Then the authority section contains exactly 1 record
    And the authority record type is SOA

  @happy @enforced src/handler.rs:512
  Scenario: A NODATA response carries the zone SOA in the authority section
    Given the zone contains record set "www" of type "A" with values "203.0.113.20"
    When a client queries "www.example.com." for type AAAA
    Then the authority section contains exactly 1 record

  @happy @enforced tests/integration.rs:196
  Scenario: The SOA reaches the client in the authority section over the wire
    Given the zone contains no records
    When a client sends a UDP query for "nope.example.test." type A
    Then the first authority record type is SOA

  @happy @enforced src/handler.rs:521
  Scenario: An apex SOA query is answered from the zone-level SOA definition
    Given the zone contains no records
    When a client queries "example.com." for type SOA
    Then the response rcode is NOERROR
    And the answer section contains 1 record
    And the answer record type is SOA

  @happy @enforced tests/integration.rs:274
  Scenario: An apex SOA query is answered over the wire
    Given the zone contains no records
    When a client sends a UDP query for "example.test." type SOA
    Then the response rcode is NOERROR
    And the first answer record type is SOA

  @boundary @gap
  Scenario: An SOA declared as a plain record set is promoted to the zone SOA
    # src/zone.rs:85-88 falls back to an exact [[zone.records]] entry of type SOA
    # when [zone.soa] is absent. That fallback has no test.
    Given a zone with no [zone.soa] table
    And the zone contains record set "@" of type "SOA" with a valid SOA value
    When a client queries "missing.example.com." for type A
    Then the authority section contains exactly 1 record
    And the authority record type is SOA

  @empty @gap
  Scenario: A zone with no SOA returns a negative answer with an empty authority section
    # Resolved::negative(code, None) yields an empty authority. Resolvers cannot
    # cache this negative at all — operationally significant, and untested. The
    # `check` command warns about it but nothing asserts the runtime behaviour.
    Given a zone with no SOA record
    When a client queries "missing.example.com." for type A
    Then the response rcode is NXDOMAIN
    And the authority section is empty

  # ----------------------------------------------------- REFUSED

  @happy @enforced src/handler.rs:486
  Scenario: A query for a name outside the zone is refused
    Given the zone contains no records
    When a client queries "google.com." for type A
    Then the response rcode is REFUSED

  @happy @enforced src/handler.rs:486
  Scenario: A refused response is not marked authoritative
    Given the zone contains no records
    When a client queries "google.com." for type A
    Then the response is not marked authoritative

  @happy @enforced tests/integration.rs:231
  Scenario: An out-of-zone query is refused over the wire
    Given the zone contains no records
    When a client sends a UDP query for "www.google.com." type A
    Then the response rcode is REFUSED
    And the AA flag is clear

  @boundary @gap
  Scenario: A refused response carries no SOA
    # Resolved::refused() deliberately leaves the authority section empty: we are
    # not authoritative, so we must not hand out a cacheable negative for a zone
    # that is not ours. Nothing asserts the authority section is empty.
    Given the zone contains no records
    When a client queries "google.com." for type A
    Then the authority section is empty

  @boundary @gap
  Scenario: A query for the parent of our origin is refused, not answered
    # "com." is not inside "example.com.", so zone.contains() is false.
    When a client queries "com." for type NS
    Then the response rcode is REFUSED

  @boundary @gap
  Scenario: A query for the root is refused
    When a client queries "." for type NS
    Then the response rcode is REFUSED

  @boundary @gap
  Scenario: A sibling zone with our origin as a suffix substring is refused
    # "notexample.com" contains "example.com" as a substring but is not inside
    # the zone. A prefix/suffix comparison bug here would make us authoritative
    # for a stranger's domain.
    When a client queries "www.notexample.com." for type A
    Then the response rcode is REFUSED

  # ---------------------------------------------------- REQUEST VALIDATION

  @malformed @gap
  Scenario: A request whose message type is Response is answered FORMERR
    # src/handler.rs:274 returns FormErr. No test constructs such a request.
    When a message with the QR bit set arrives
    Then the response rcode is FORMERR

  @malformed @gap
  Scenario: A request carrying no question is answered FORMERR
    # src/handler.rs:286 requires exactly one query. Untested for zero.
    When a query message with QDCOUNT 0 arrives
    Then the response rcode is FORMERR

  @malformed @gap
  Scenario: A request carrying two questions is answered FORMERR
    # src/handler.rs:286 requires exactly one query. Untested for two.
    When a query message with QDCOUNT 2 arrives
    Then the response rcode is FORMERR

  @hostile @gap
  Scenario: A dynamic UPDATE opcode is answered NOTIMP
    # src/handler.rs:278 refuses non-Query opcodes. We are a static authoritative
    # server; accepting UPDATE would be remote zone modification. Untested.
    When a message with opcode UPDATE arrives
    Then the response rcode is NOTIMP

  @hostile @gap
  Scenario: A NOTIFY opcode is answered NOTIMP
    When a message with opcode NOTIFY arrives
    Then the response rcode is NOTIMP

  @hostile @enforced src/handler.rs:1147
  Scenario: The MAILB meta QTYPE is answered NOTIMP, not with the owner's CNAME
    # RFC 1035 3.2.3 defines MAILB (253) as a QTYPE only, and RFC 973 withdrew
    # the service behind it. hickory has no variant for it, so it arrives as
    # Unknown(253), missed the meta-type arms, and fell into the RFC 1034 3.6.2
    # CNAME substitution rule — which answered NOERROR with a CNAME for a
    # transaction type that names no data at all.
    Given the zone contains record set "alias" of type "CNAME" with values "origin.example.com."
    When a query for "alias.example.com." with QTYPE 253 arrives
    Then the response rcode is NOTIMP
    And the answer section is empty

  @hostile @enforced src/handler.rs:1147
  Scenario: The MAILA meta QTYPE is answered NOTIMP, not with the owner's CNAME
    # RFC 1035 3.2.3, QTYPE 254. Same reasoning as MAILB; note the numbering is
    # not alphabetical, MAILB is 253 and MAILA is 254.
    Given the zone contains record set "alias" of type "CNAME" with values "origin.example.com."
    When a query for "alias.example.com." with QTYPE 254 arrives
    Then the response rcode is NOTIMP
    And the answer section is empty

  @hostile @gap
  Scenario: A truncated or undecodable datagram does not crash the listener
    # Decoding happens inside Hickory before our handler runs. Nothing asserts
    # the process survives a stream of garbage on the UDP socket.
    When 100 random byte strings are sent to the UDP listener
    And a valid query is sent afterwards
    Then the valid query is still answered
