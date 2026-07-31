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
  # RFC 8482 §4.1 and §4.2 change what goes in the ANSWER SECTION and license no
  # change to the rcode or to the existence determination. Everything in this
  # section is therefore about response *content*; what an ANY query's rcode must
  # be lives in the WILDCARD-COVERED NAMES section below, where it is the same
  # rcode every other QTYPE gets.

  @happy @enforced src/handler.rs:1220
  Scenario: An ANY query returns one synthetic HINFO, not the whole node
    # RFC 8482 §4.2. Returning the node made ANY simultaneously the largest
    # response and the most expensive lookup, with the attacker choosing both
    # from a 29-byte packet (VEGA-002).
    Given the zone contains record set "multi" of type "A" with values "203.0.113.60"
    And the zone contains record set "multi" of type "TXT" with values "\"hello\""
    When a client queries "multi.example.com." for type ANY
    Then the response rcode is NOERROR
    And the answer section contains 1 record
    And the answer record type is HINFO
    And the HINFO CPU field is "RFC8482"
    And the answer section does not contain a record of type A
    And the answer section does not contain a record of type TXT

  @happy @enforced src/handler.rs:975
  Scenario: An ANY query at the apex returns the HINFO and not the zone SOA
    # Nothing in RFC 8482 §4.1 or §4.2 licenses adding the SOA to the ANSWER
    # section; RFC 1034 §4.3.2 puts the SOA in AUTHORITY, and only on a negative
    # answer. Prepending it at the apex is the amplification VEGA-002 closed.
    Given the zone contains record set "@" of type "A" with values "203.0.113.10"
    When a client queries "example.com." for type ANY
    Then the response rcode is NOERROR
    And the answer section contains 1 record
    And the answer record type is HINFO
    And the answer section does not contain an SOA record

  @empty @enforced src/handler.rs:1262
  Scenario: An ANY query at an existing name that holds no records still returns the HINFO
    # RFC 8482 §4.2 conditions synthesis on the absence of a CNAME at the QNAME
    # and on nothing else, so the response shape does not depend on what the
    # node holds. Bounded and uniform is the point: taking §4.1's "subset"
    # reading — the empty set for an empty node, i.e. a real NODATA — would make
    # the shape of the answer depend on node contents.
    Given the zone contains no records
    When a client queries "example.com." for type ANY
    Then the response rcode is NOERROR
    And the answer section contains 1 record
    And the answer record type is HINFO

  @boundary @enforced src/handler.rs:779
  Scenario: An ANY query does not chase a CNAME
    # The ANY branch returns the CNAME record itself and never follows it.
    Given the zone contains record set "alias" of type "CNAME" with values "origin.example.com."
    And the zone contains record set "origin" of type "A" with values "203.0.113.40"
    When a client queries "alias.example.com." for type ANY
    Then the answer section contains 1 record
    And the answer record type is CNAME

  @boundary @enforced src/handler.rs:1306
  Scenario: An ANY query at a wildcard-covered CNAME returns the synthesised CNAME
    # RFC 4592 §3.4.3 synthesises a CNAME at a covered name like any other type;
    # RFC 8482 §4.2 forbids the HINFO when a CNAME is present at the QNAME.
    # Before VEGA-083 the existence gate rejected the name before the CNAME
    # probe ran, so this answered NXDOMAIN and never reached the CNAME it owed —
    # even though the probe itself was already wildcard-aware.
    Given the zone contains record set "*.dev" of type "CNAME" with values "origin.example.com."
    When a client queries "x.dev.example.com." for type ANY
    Then the response rcode is NOERROR
    And the answer section contains 1 record
    And the answer record type is CNAME
    And the answer record owner is "x.dev.example.com."

  # ---------------------------------------- WILDCARD-COVERED NAMES (VEGA-083)
  # RFC 1034 §4.3.2 step 3(c): the authoritative name error is set only when the
  # `*` node does not exist. RFC 4592 §3.3.1: `*.dev.example.com` is the source
  # of synthesis for every name under `dev.example.com`, and it exists. So no
  # query for a covered name may be NXDOMAIN, whatever the QTYPE — the answer is
  # RFC 2308 §2.2 NODATA: NOERROR, empty answer section, SOA in authority.
  #
  # RFC 8020 §2 is why the wrong rcode is a subtree-wide denial rather than a
  # cosmetic error: a resolver holding a cached NXDOMAIN for a covered name may
  # answer NXDOMAIN for everything beneath it, for RFC 2308 §5's SOA MINIMUM.
  # And AAAA — not ANY — is what triggers it, because every dual-stack client
  # sends one alongside every A. No attacker is required.

  @happy @enforced src/zone.rs:1633
  Scenario: A wildcard answers the type it carries
    # The positive control. A fix that made every covered name NODATA would
    # satisfy every other scenario here and take the wildcard out of service.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type A
    Then the response rcode is NOERROR
    And the answer section contains 1 record
    And the answer record owner is "x.dev.example.com."

  @boundary @enforced tests/integration.rs:1040
  Scenario Outline: A wildcard-covered name exists for every type, not only the one the wildcard carries
    # AAAA is listed first deliberately: it is the case that fires on ordinary
    # traffic, and it must be the first thing that goes red if the fix regresses.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type <qtype>
    Then the response rcode is NOERROR
    And the answer section is empty
    And the authority section contains the zone SOA

    Examples:
      | qtype |
      | AAAA  |
      | TXT   |
      | MX    |
      | SRV   |

  @boundary @enforced src/handler.rs:1278
  Scenario: An ANY query at a wildcard-covered name is NOERROR with the RFC 8482 HINFO
    # RFC 8482 changes the answer section, not the existence determination
    # (§4.1, §4.2). The rcode here must equal the rcode for AAAA above, and it
    # must be arrived at by the same computation.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.dev.example.com." for type ANY
    Then the response rcode is NOERROR
    And the answer section contains 1 record
    And the answer record type is HINFO

  @boundary @enforced src/zone.rs:1701
  Scenario: A name with no source of synthesis is still NXDOMAIN
    # The negative control. Without it the fix could be "never say NXDOMAIN",
    # which passes every other scenario in this section.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "x.prod.example.com." for type A
    Then the response rcode is NXDOMAIN

  @boundary @enforced src/zone.rs:1736
  Scenario: Coverage is decided by the wildcard's own parent, not by its depth
    # `*.dev` sits at depth 3. So does `other.example.com`. A coverage predicate
    # read off the depth bitmap alone would make `q.other.example.com` — and
    # almost every other name in the zone — exist. The failure is silent: the
    # server stops saying NXDOMAIN about names it is authoritatively denying.
    Given the zone contains record set "*.dev" of type "A" with values "203.0.113.50"
    When a client queries "q.other.example.com." for type A
    Then the response rcode is NXDOMAIN

  @hostile @enforced tests/properties.rs:932
  Scenario: For a name with no CNAME, the rcode is a function of the name alone
    # RFC 1034 §4.3.2 step 3(c) as an executable law, and the strongest single
    # conformance statement in the suite: the name-error branch is not
    # conditioned on QTYPE anywhere. Scoped to CNAME-free names because RFC 1034
    # §3.6.2 chasing legitimately lets the target's status reach the rcode.
    Given any zone the generator produces, with or without wildcards
    And any in-zone name with no CNAME at it and none synthesised for it
    When the name is queried for A, AAAA, TXT, MX, SRV, NS, SOA and ANY
    Then every one of those queries produces the same rcode

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

  @hostile @wip tests/perf_budget.rs:266
  Scenario: An ANY lookup costs the same on a 100,000-record zone as on a small one
    # CLAUDE.md's budget: no O(n) scan over the record map per query, for any
    # query type. The zone layer's ANY arm was one — 219.6 ns / 31.5 µs / 1.83 ms
    # at 1k / 10k / 100k records, 18,239x an A lookup and 201x the 9.1 µs
    # per-query CPU budget. Nothing on the packet path reached it, because RFC
    # 8482 minimal-ANY intercepts first, so it was a landmine in a `pub fn`
    # rather than a live DoS — one routing change, an AXFR path or a SLIP
    # implementation away from being one.
    #
    # VEGA-083 deletes the arm rather than re-keying it: RFC 1035 §3.2.3 makes
    # ANY a QTYPE that can never key the record map, so the zone layer answers
    # existence and the response policy stays with the responder.
    #
    # @wip: `#[ignore]`d and failing until that lands; it must be un-ignored in
    # the same commit.
    Given a 100,000-record zone
    When an existing name is looked up for type ANY
    Then it costs less than 25 times the same name looked up for type A
