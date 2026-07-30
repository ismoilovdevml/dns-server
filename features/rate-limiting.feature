Feature: Per-source-IP rate limiting
  # WHY THIS MATTERS
  # An authoritative name server on the public internet with no rate limit is a
  # reflection amplifier waiting to be pointed at somebody. The attacker spoofs
  # the victim's source address, we answer, and the victim absorbs the bandwidth.
  # The per-IP token bucket is the only thing between this server and that role.
  # It is also the single most dangerous piece of code to get wrong in the other
  # direction: a bucket that refills too slowly, or one keyed carelessly, takes a
  # legitimate resolver offline for every domain we serve. And because the map is
  # keyed by an attacker-chosen source address, an unbounded map is itself the
  # attack — memory exhaustion by spoofed source diversity.
  #
  # Implementation: src/ratelimit.rs (token bucket, 32 shards, prune)
  #                 src/handler.rs:266-272 (dispatch-time check)
  #                 src/config.rs:359-372 (qps/burst resolution)
  #                 src/main.rs:446 (janitor, 60s interval, 600s idle TTL)

  # ---------------------------------------------------------- PER-IP BUCKET

  @happy @enforced src/ratelimit.rs:174
  Scenario: Each source IP gets its own bucket
    Given a rate limiter allowing 1 qps with a burst of 1
    When 198.51.100.4 exhausts its bucket
    Then a query from 198.51.100.5 is still allowed

  @happy @enforced src/ratelimit.rs:174
  Scenario: An IPv6 source gets its own bucket independent of IPv4 sources
    Given a rate limiter allowing 1 qps with a burst of 1
    When 198.51.100.4 exhausts its bucket
    Then a query from 2001:db8::1 is still allowed

  @happy @enforced tests/integration.rs:350
  Scenario: A rate-limited client receives REFUSED over the wire
    Given a running server with a rate limiter allowing 1 qps with a burst of 1
    When the same client sends two queries in quick succession
    Then the first response rcode is NOERROR
    And the second response rcode is REFUSED

  @happy @enforced src/handler.rs:623
  Scenario: The handler consults the limiter before resolving
    Given a handler with a rate limiter allowing 1 qps with a burst of 1
    When the same client is checked twice
    Then the first check is allowed
    And the second check is denied

  # ------------------------------------------------------------- BURST

  @happy @enforced src/ratelimit.rs:143
  Scenario: A full burst is allowed before any traffic is denied
    Given a rate limiter allowing 1 qps with a burst of 3
    When one source sends 4 queries in the same instant
    Then the first 3 are allowed
    And the 4th is denied

  @happy @enforced src/config.rs:534
  Scenario: The burst defaults to twice the configured qps
    Given the configuration sets rate_limit qps to 25 and no burst
    When the configuration is resolved
    Then the effective qps is 25
    And the effective burst is 50

  @boundary @gap
  Scenario: An explicitly configured burst overrides the doubling default
    # `cli.rate_limit_burst.or(file...).unwrap_or(qps*2)`. The explicit branch has
    # no test, so a regression that always doubled would go unnoticed.
    Given the configuration sets rate_limit qps to 25 and burst to 5
    When the configuration is resolved
    Then the effective burst is 5

  @boundary @gap
  Scenario: A burst of one allows exactly one query before denial
    # The tightest legal setting, and the one used by the integration test. The
    # unit tests never exercise burst == 1 at the config layer.
    Given the configuration sets rate_limit qps to 1 and burst to 1
    When the configuration is resolved
    Then the effective burst is 1

  # ------------------------------------------------------------ REFILL

  @happy @enforced src/ratelimit.rs:153
  Scenario: Tokens are restored as time passes
    Given a rate limiter allowing 10 qps with a burst of 1
    When one source exhausts its bucket
    And 100 milliseconds pass
    Then the next query from that source is allowed

  @boundary @enforced src/ratelimit.rs:163
  Scenario: Refill is capped at the burst size no matter how long the source was idle
    Given a rate limiter allowing 100 qps with a burst of 2
    When a source that has been idle for an hour sends 3 queries in the same instant
    Then the first 2 are allowed
    And the 3rd is denied

  @hostile @enforced src/ratelimit.rs:205
  Scenario: A clock reading that moves backwards does not grant extra tokens
    # saturating_duration_since. A monotonic-clock regression here would hand an
    # attacker a free refill on every query.
    Given a rate limiter allowing 1 qps with a burst of 1
    When a source consumes its token at time T
    And the same source is checked with a clock reading of T minus 5 seconds
    Then the query is denied

  @boundary @gap
  Scenario: A partial refill below one token does not admit a query
    # 1 qps, 500ms elapsed => 0.5 tokens, which must not round up to an admission.
    Given a rate limiter allowing 1 qps with a burst of 1
    When one source exhausts its bucket
    And 500 milliseconds pass
    Then the next query from that source is denied

  # --------------------------------------------------------- DISABLED

  @empty @enforced src/config.rs:542
  Scenario: A qps of zero disables rate limiting entirely
    Given the configuration sets rate_limit qps to 0
    When the configuration is resolved
    Then no rate limiter is configured

  @empty @enforced src/config.rs:494
  Scenario: Rate limiting is off by default
    Given no rate limit is configured
    When the configuration is resolved
    Then no rate limiter is configured

  @empty @gap
  Scenario: With no limiter configured the handler never refuses on rate grounds
    # `if let Some(limiter) = &self.limiter` short-circuits. Nothing asserts a
    # limiter-less handler answers an unbounded number of queries.
    Given a handler with no rate limiter
    When one client sends 100 queries in the same instant
    Then every response rcode is NOERROR

  @malformed @gap
  Scenario: A burst of zero alongside a non-zero qps is rejected at startup
    # src/config.rs:368 bails. The line is uncovered: a config that would deny
    # every single query — a self-inflicted total outage — currently has no test.
    Given the configuration sets rate_limit qps to 10 and burst to 0
    When the configuration is resolved
    Then the configuration is rejected with an error mentioning "burst"

  @malformed @gap
  Scenario: A burst configured without a qps is ignored rather than applied
    # `qps` of None short-circuits the whole match, silently discarding the burst.
    # An operator who sets only the burst gets no limiting and no warning.
    Given the configuration sets rate_limit burst to 5 and no qps
    When the configuration is resolved
    Then no rate limiter is configured

  # ------------------------------------------------------------ PRUNING

  @happy @enforced src/ratelimit.rs:185
  Scenario: Buckets idle beyond the TTL are pruned and active ones are kept
    Given a rate limiter tracking two sources seen 500 seconds apart
    When buckets idle for more than 300 seconds are pruned
    Then exactly 1 bucket is removed
    And 1 bucket remains

  @empty @enforced src/ratelimit.rs:198
  Scenario: Pruning an empty limiter removes nothing
    Given a rate limiter that has seen no traffic
    When buckets are pruned
    Then 0 buckets are removed

  @hostile @enforced src/ratelimit.rs:217
  Scenario: Many distinct sources are tracked without loss across shards
    # A sharding bug that dropped or collided entries would silently stop
    # limiting some fraction of sources.
    Given a rate limiter allowing 1 qps with a burst of 1
    When 250 distinct source addresses each send one query
    Then all 250 are allowed
    And the limiter reports 250 tracked sources

  @hostile @gap
  Scenario: The janitor prunes idle buckets on its interval
    # src/main.rs:446-462 is entirely uncovered. The janitor is the only thing
    # stopping a spoofed-source flood from growing the bucket map without bound,
    # and no test starts it, ticks it, or observes it removing anything.
    Given a running server with rate limiting enabled
    And a bucket that has been idle beyond the idle TTL
    When the janitor interval elapses
    Then the idle bucket is removed

  @hostile @gap
  Scenario: The janitor stops when the shutdown token is cancelled
    # The select! arm on shutdown.cancelled() is uncovered. A janitor that
    # outlived shutdown would hold the runtime open.
    Given a running janitor
    When the shutdown token is cancelled
    Then the janitor task exits

  @hostile @gap
  Scenario: A rate-limited query is counted in the rate-limited metric
    # src/handler.rs:267-268 calls metrics.rate_limited(). Nothing asserts
    # dns_rate_limited_total moves, so an operator watching for an attack would
    # see a flat line.
    Given a running server with a rate limiter allowing 1 qps with a burst of 1
    When the same client sends two queries in quick succession
    Then dns_rate_limited_total is 1

  @hostile @gap
  Scenario: A rate-limited query is refused before its opcode is even inspected
    # The limiter check precedes message-type and opcode validation, so a flood
    # of malformed packets is dropped just as cheaply as valid ones. That
    # ordering is a deliberate DoS property and nothing pins it.
    Given a handler with a rate limiter whose bucket is empty
    When a message with opcode UPDATE arrives
    Then the response rcode is REFUSED
