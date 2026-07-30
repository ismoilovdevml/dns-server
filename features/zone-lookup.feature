# Traceability key used throughout features/:
#   @enforced <path>:<line>  — a Rust test exists and asserts this behaviour
#   @gap                     — no test enforces this scenario; it is a known hole
#   @category tags           — happy | boundary | empty | malformed | hostile

Feature: Authoritative zone lookup
  # WHY THIS MATTERS
  # The lookup is the whole product. Every other feature — negative answers,
  # wildcards, CNAME, rate limiting — is a modifier on the answer this code
  # produces. A wrong record here is not a cosmetic bug: it is traffic sent to
  # the wrong host, mail delivered to the wrong server, or a TLS certificate
  # validation that silently succeeds against an attacker's IP. The lookup is
  # also on the packet path, reachable by any host on the internet, so every
  # branch through it is attacker-selectable.
  #
  # Implementation: src/zone.rs (Zone::from_config, Zone::lookup, Zone::resolve)
  #                 src/handler.rs (DnsHandler::resolve)

  Background:
    Given a zone with origin "example.com"
    And a zone default TTL of 300 seconds
    And an SOA record with minimum 60

  # ---------------------------------------------------------------- HAPPY PATH

  @happy @enforced src/zone.rs:369
  Scenario: An apex A record answers a query for the origin
    Given the zone contains record set "@" of type "A" with values "203.0.113.10, 203.0.113.11"
    When a client queries "example.com." for type A
    Then the answer section contains 2 records
    And every answer record is owned by "example.com."

  @happy @enforced src/zone.rs:380
  Scenario: A relative record name is qualified against the origin
    Given the zone contains record set "www" of type "A" with values "203.0.113.20"
    When a client queries "www.example.com." for type A
    Then the answer section contains 1 record

  @happy @enforced tests/integration.rs:168
  Scenario: A configured A record survives the UDP wire round trip
    Given the zone contains record set "www" of type "A" with values "203.0.113.10"
    When a client sends a UDP query for "www.example.test." type A
    Then the response rcode is NOERROR
    And the AA flag is set
    And the response echoes the query id
    And the first answer record holds 203.0.113.10

  @happy @enforced src/zone.rs:524
  Scenario: An MX value is parsed in zone-file presentation format
    Given the zone contains record set "@" of type "MX" with values "10 mail.example.com."
    When a client queries "example.com." for type MX
    Then the answer section contains 1 record

  @happy @enforced tests/integration.rs:290
  Scenario: An MX record keeps its preference and exchange across the wire
    Given the zone contains record set "@" of type "MX" with values "10 mail.example.test."
    When a client sends a UDP query for "example.test." type MX
    Then the answer MX preference is 10
    And the answer MX exchange is "mail.example.test."

  @happy @enforced src/handler.rs:494
  Scenario: An in-zone hit is answered authoritatively
    Given the zone contains record set "www" of type "A" with values "203.0.113.20"
    When a client queries "www.example.com." for type A
    Then the response is marked authoritative

  # ------------------------------------------------------------------- TTL

  @happy @enforced src/zone.rs:369
  Scenario: A record without an explicit TTL inherits the zone default
    Given the zone contains record set "@" of type "A" with values "203.0.113.10"
    When a client queries "example.com." for type A
    Then the answer record TTL is 300

  @boundary @enforced src/zone.rs:389
  Scenario: A per-record TTL overrides the zone default
    Given the zone contains record set "api" of type "A" with values "203.0.113.30" and TTL 30
    When a client queries "api.example.com." for type A
    Then the answer record TTL is 30

  @boundary @gap
  Scenario: A TTL of zero is served as zero rather than falling back to the default
    # `spec.ttl.unwrap_or(default)` treats Some(0) as an explicit 0, which is a
    # legal "do not cache" TTL. Nothing asserts we do not silently rewrite it.
    Given the zone contains record set "flap" of type "A" with values "203.0.113.40" and TTL 0
    When a client queries "flap.example.com." for type A
    Then the answer record TTL is 0

  @boundary @gap
  Scenario: The SOA record is served with the SOA minimum as its TTL
    # build_soa() uses spec.minimum as the record TTL, not default_ttl. Only the
    # zone-level unit test (src/zone.rs:516) checks this, and only via zone.soa(),
    # never through a query.
    When a client queries "example.com." for type SOA
    Then the answer record TTL is 60

  # -------------------------------------------------------- MULTIPLE VALUES

  @happy @enforced tests/integration.rs:429
  Scenario: Every value of a record set is returned in one answer
    Given the zone contains record set "pool" of type "A" with values "203.0.113.1, 203.0.113.2, 203.0.113.3"
    When a client sends a UDP query for "pool.example.test." type A
    Then the answer section contains 3 records

  @boundary @enforced src/zone.rs:566
  Scenario: The record count metric counts values, not record sets
    Given the zone contains record set "@" of type "A" with values "203.0.113.1, 203.0.113.2"
    And the zone contains record set "www" of type "A" with values "203.0.113.3"
    Then the zone reports a record count of 3

  @boundary @gap
  Scenario: Two config entries for the same name and type are merged into one record set
    # insert_spec() uses `entry(key).or_default().extend(records)`, so duplicate
    # [[zone.records]] blocks accumulate rather than the later one winning. That
    # is a deliberate choice with no test pinning it.
    Given the zone contains record set "www" of type "A" with values "203.0.113.1"
    And the zone contains a second record set "www" of type "A" with values "203.0.113.2"
    When a client queries "www.example.com." for type A
    Then the answer section contains 2 records

  # ------------------------------------------------------------- SUBDOMAINS

  @happy @gap
  Scenario: A deeply nested owner name resolves at its exact depth
    # Only single-label subdomains are tested. Nothing pins the behaviour of a
    # multi-label owner such as "a.b.c".
    Given the zone contains record set "a.b.c" of type "A" with values "203.0.113.50"
    When a client queries "a.b.c.example.com." for type A
    Then the answer section contains 1 record

  @boundary @gap
  Scenario: An absolute owner name inside the zone is accepted
    # qualify() accepts a trailing-dot name and checks zone membership. Untested.
    Given the zone contains record set "www.example.com." of type "A" with values "203.0.113.20"
    When a client queries "www.example.com." for type A
    Then the answer section contains 1 record

  @hostile @gap
  Scenario: An absolute owner name outside the zone is rejected at build time
    # qualify() bails with "is not inside zone". A config that smuggles records
    # for someone else's namespace must fail loudly, not load quietly.
    Given a config declaring record set "www.evil.test." of type "A" with values "203.0.113.99"
    When the zone is built
    Then the build fails with an error mentioning "is not inside zone"

  # --------------------------------------------------------------- ANY QUERY

  @happy @enforced src/zone.rs:503
  Scenario: An ANY query returns every type present at the name
    Given the zone contains record set "multi" of type "A" with values "203.0.113.60"
    And the zone contains record set "multi" of type "TXT" with values "\"hello\""
    When a client queries "multi.example.com." for type ANY
    Then the answer section contains 2 records

  @happy @gap
  Scenario: An ANY query at the apex includes the zone SOA
    # src/handler.rs:195-209 special-cases apex ANY to prepend the zone-level SOA
    # and de-duplicate any SOA already in the record map. No test covers it.
    Given the zone contains record set "@" of type "A" with values "203.0.113.10"
    When a client queries "example.com." for type ANY
    Then the answer section contains an SOA record
    And the answer section contains exactly one SOA record

  @empty @gap
  Scenario: An ANY query at an existing name with no records is NODATA
    # Reachable only when a name is in `names` but has no exact entries; the apex
    # of an empty zone is exactly that case.
    Given the zone contains no records
    When a client queries "example.com." for type ANY
    Then the response rcode is NOERROR
    And the answer section is empty

  @boundary @gap
  Scenario: An ANY query does not synthesise a wildcard answer
    # Zone::resolve returns before reaching the wildcard block when the type is
    # ANY, so ANY under a wildcard is NXDOMAIN. This is a real, load-bearing
    # asymmetry with the A-type behaviour and nothing pins it.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type ANY
    Then the response rcode is NXDOMAIN

  @boundary @gap
  Scenario: An ANY query does not chase a CNAME
    # The ANY branch returns the CNAME record itself and never follows it.
    Given the zone contains record set "alias" of type "CNAME" with values "origin.example.com."
    And the zone contains record set "origin" of type "A" with values "203.0.113.40"
    When a client queries "alias.example.com." for type ANY
    Then the answer section contains 1 record
    And the answer record type is CNAME

  # ---------------------------------------------------------------- MALFORMED

  @malformed @enforced src/zone.rs:540
  Scenario: An A record whose value is not an IP address fails at zone build time
    Given a config declaring record set "@" of type "A" with values "not-an-ip"
    When the zone is built
    Then the build fails with an error mentioning "invalid A record value"

  @malformed @enforced src/zone.rs:553
  Scenario: An unrecognised record type fails at zone build time
    Given a config declaring record set "@" of type "NOPE" with values "x"
    When the zone is built
    Then the build fails with an error mentioning "unknown record type"

  @malformed @gap
  Scenario: A record set with no values fails at zone build time
    # src/zone.rs:104 bails with "has no values". No test reaches it.
    Given a config declaring record set "www" of type "A" with an empty value list
    When the zone is built
    Then the build fails with an error mentioning "has no values"

  @malformed @gap
  Scenario: An unparseable zone origin fails at zone build time
    # src/zone.rs:60 wraps the parse error as "invalid zone origin". Untested.
    Given a config with origin "not a hostname"
    When the zone is built
    Then the build fails with an error mentioning "invalid zone origin"

  @malformed @gap
  Scenario: An SOA mname that is not a DNS name fails at zone build time
    # build_soa() contexts the error as "invalid zone.soa.mname". Untested.
    Given a config whose SOA mname is "not a name"
    When the zone is built
    Then the build fails with an error mentioning "invalid zone.soa.mname"

  # ------------------------------------------------------------------ EMPTY

  @empty @gap
  Scenario: A zone with no records still knows its own apex exists
    # from_config() unconditionally inserts the origin into `names` so that an
    # apex query cannot answer NXDOMAIN about our own zone.
    Given the zone contains no records
    When a client queries "example.com." for type TXT
    Then the response rcode is NOERROR
    And the answer section is empty

  @empty @gap
  Scenario: A zone with no SOA still answers positive queries
    # Config allows soa = None. Every existing test configures an SOA.
    Given a zone with no SOA record
    And the zone contains record set "www" of type "A" with values "203.0.113.20"
    When a client queries "www.example.com." for type A
    Then the response rcode is NOERROR
    And the answer section contains 1 record

  # ---------------------------------------------------------------- HOSTILE

  @hostile @enforced tests/integration.rs:446
  Scenario: Concurrent queries are all answered
    Given the zone contains record set "www" of type "A" with values "203.0.113.10"
    When 25 clients query "www.example.test." for type A at the same time
    Then every response rcode is NOERROR

  @hostile @gap
  Scenario: A name with the maximum legal number of labels does not panic the lookup
    # An attacker controls QNAME entirely. base_name() walking in the wildcard
    # loop is bounded by label count, but nothing tests a 127-label name.
    When a client queries a 127-label name inside "example.com." for type A
    Then the server answers with a response rather than terminating

  @hostile @gap
  Scenario: A query name differing only by case matches the record
    # LowerName is used for keys, so matching should be case-insensitive per
    # RFC 4343. Nothing asserts it end to end.
    Given the zone contains record set "www" of type "A" with values "203.0.113.20"
    When a client queries "WwW.ExAmPlE.cOm." for type A
    Then the answer section contains 1 record
