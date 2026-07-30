Feature: EDNS0 negotiation and transport behaviour
  # WHY THIS MATTERS
  # EDNS0 is how a resolver tells us how big an answer it can take. Advertise
  # too small and every DNSSEC-sized or multi-value answer is needlessly
  # truncated, forcing a TCP retry and tripling the latency of the whole zone.
  # Advertise too large and we become a reflection amplifier: an attacker spoofs
  # a victim's source address, sends a 60-byte query, and we send the victim a
  # 4096-byte answer. RFC 6891 sets a 512-byte floor for exactly this reason.
  # TCP matters for the same amplification story from the other side — it is the
  # fallback that makes truncation safe — and an unbounded TCP idle timeout is a
  # free file-descriptor exhaustion attack.
  #
  # Implementation: src/handler.rs (handle_request EDNS mirroring, lines 310-315,
  #                 MIN_EDNS_PAYLOAD = 512)
  #                 src/config.rs (tcp_timeout, tcp_response_buffer)
  #                 src/main.rs (register_socket / register_listener)

  Background:
    Given a running server authoritative for "example.test"
    And the zone contains record set "www" of type "A" with values "203.0.113.10"

  # ------------------------------------------------------------- EDNS0

  @happy @enforced tests/integration.rs:399
  Scenario: A query carrying an OPT record gets an OPT record back
    When a client sends a UDP query for "www.example.test." type A advertising a 4096-byte payload
    Then the response carries an EDNS OPT record

  @boundary @enforced tests/integration.rs:399
  Scenario: The advertised payload never drops below the RFC 6891 floor
    When a client sends a UDP query for "www.example.test." type A advertising a 4096-byte payload
    Then the advertised EDNS payload size is at least 512

  @empty @gap
  Scenario: A query with no OPT record gets a response with no OPT record
    # `request.edns.as_ref().map(...)` yields None. Mirroring EDNS onto a
    # non-EDNS client is a protocol violation; nothing asserts we do not.
    When a client sends a plain UDP query for "www.example.test." type A with no OPT record
    Then the response carries no EDNS OPT record

  @boundary @gap
  Scenario: A client advertising less than 512 bytes is answered with 512
    # `req.max_payload().max(MIN_EDNS_PAYLOAD)` raises the floor. The existing
    # test advertises 4096 and asserts ">= 512", which passes whether the floor
    # works or not. The floor itself is unenforced.
    When a client sends a UDP query advertising a 200-byte payload
    Then the advertised EDNS payload size is exactly 512

  @boundary @gap
  Scenario: A client advertising a large payload has it echoed back
    When a client sends a UDP query advertising a 4096-byte payload
    Then the advertised EDNS payload size is exactly 4096

  @boundary @gap
  Scenario: The response OPT record declares EDNS version 0
    # `edns.set_version(0)` is unconditional. Untested.
    When a client sends a UDP query advertising a 4096-byte payload
    Then the response EDNS version is 0

  @malformed @gap
  Scenario: A query advertising EDNS version 1 is handled without a version error
    # RFC 6891 §6.1.3 says an unsupported EDNS version should be answered
    # BADVERS. This server unconditionally replies version 0. That is a known
    # deviation, and pinning it as a scenario makes it a decision rather than an
    # oversight.
    When a client sends a UDP query advertising EDNS version 1
    Then the response EDNS version is 0

  @hostile @gap
  Scenario: A spoofable query does not receive an answer larger than the advertised limit
    # This is the amplification control. Nothing measures response size against
    # the advertised payload for any query, on any transport.
    When a client sends a UDP query advertising a 512-byte payload for a name with many values
    Then the UDP response is no larger than 512 bytes

  # --------------------------------------------------------------- TCP

  @happy @enforced tests/integration.rs:186
  Scenario: A TCP query returns the same answer as the equivalent UDP query
    When a client sends a TCP query for "www.example.test." type A
    Then the response rcode is NOERROR
    And the first answer record holds 203.0.113.10

  @boundary @gap
  Scenario: A TCP response is framed with a two-byte length prefix
    # The test helper reads the prefix but never asserts it matches the body
    # length. A framing bug would desynchronise every TCP client.
    When a client sends a TCP query for "www.example.test." type A
    Then the two-byte length prefix equals the length of the message that follows

  @boundary @gap
  Scenario: Two queries on one TCP connection are both answered
    # register_listener is given a 32-message response buffer, which only matters
    # for pipelined queries. Nothing sends more than one query per connection.
    When a client sends two queries on a single TCP connection
    Then both queries are answered

  # ---------------------------------------------------- TCP IDLE TIMEOUT

  @boundary @gap
  Scenario: A configured TCP idle timeout is applied to the listener
    # config.tcp_timeout is passed to register_listener at src/main.rs:335. No
    # test observes a connection actually being closed after the idle period.
    Given the server is configured with a TCP idle timeout of 1 second
    When a client opens a TCP connection and sends nothing
    Then the connection is closed by the server within a few seconds

  @boundary @gap
  Scenario: The default TCP idle timeout is ten seconds
    # DEFAULT_TCP_TIMEOUT is 10s. Nothing asserts the default survives a refactor.
    Given no TCP idle timeout is configured
    When the configuration is resolved
    Then the effective TCP idle timeout is 10 seconds

  @malformed @gap
  Scenario: A TCP idle timeout of zero is rejected at startup
    # src/config.rs:353-356 bails. The line is uncovered: a config that would
    # leak connections forever currently starts without complaint in any test.
    Given the server is configured with a TCP idle timeout of 0 seconds
    When the configuration is resolved
    Then the configuration is rejected with an error mentioning "tcp_timeout_secs"

  @hostile @gap
  Scenario: Idle TCP connections do not accumulate without bound
    # Slowloris against a name server. The idle timeout is the only defence and
    # nothing exercises it under load.
    When 200 TCP connections are opened and left idle
    Then the connections are reaped and the server still answers UDP queries

  # ---------------------------------------------------------- TRUNCATION

  @boundary @gap
  Scenario: An answer too large for the UDP payload limit sets the TC bit
    # NOT IMPLEMENTED IN OUR CODE. Truncation is delegated entirely to Hickory's
    # response encoder; this repository contains no TC-bit logic and no test.
    # If Hickory's behaviour ever changes, nothing here notices. This scenario is
    # a specification of the contract we depend on, not of code we own.
    Given the zone contains a record set whose encoded answer exceeds 512 bytes
    When a client sends a UDP query advertising a 512-byte payload
    Then the TC bit is set in the response

  @boundary @gap
  Scenario: A truncated UDP answer is served in full over TCP
    # The other half of the same contract: TC must be actionable.
    Given the zone contains a record set whose encoded answer exceeds 512 bytes
    When a client retries the same query over TCP
    Then the TC bit is clear
    And the full record set is present in the answer section

  # ------------------------------------------------------- TRANSPORT METRICS

  @happy @enforced tests/integration.rs:367
  Scenario: UDP and TCP queries are counted under separate transport labels
    When a client sends 2 UDP queries and 1 TCP query
    Then dns_queries_by_transport_total for udp is 2
    And dns_queries_by_transport_total for tcp is 1

  @happy @enforced src/handler.rs:617
  Scenario: The UDP protocol maps to the udp transport label
    When a request arrives over protocol Udp
    Then the recorded transport is udp

  @boundary @gap
  Scenario: A transport that is neither UDP nor TCP is counted as other
    # src/handler.rs:407 is uncovered. DoT/DoH/DoQ would silently vanish from the
    # per-transport counters if this arm regressed.
    When a request arrives over a protocol that is neither Udp nor Tcp
    Then the recorded transport is other
