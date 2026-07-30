Feature: Admin HTTP API
  # WHY THIS MATTERS
  # The admin listener is the operational control surface: it decides whether an
  # orchestrator restarts the process (/healthz), whether a load balancer sends
  # it traffic (/readyz), whether anyone can see what it is doing (/metrics), and
  # whether a caller can change what it serves (/reload). A /readyz that lies
  # sends traffic to a server that cannot answer. A /healthz that lies leaves a
  # dead process in rotation. And /reload is remote zone modification — if its
  # gate is wrong, an unauthenticated caller repoints your domain. The read-only
  # endpoints are deliberately unauthenticated, which makes it doubly important
  # that the mutating one is not.
  #
  # Implementation: src/admin.rs (router, may_mutate, constant_time_eq)
  #                 src/healthcheck.rs (the container probe client)

  # ------------------------------------------------------------- HEALTHZ

  @happy @enforced src/admin.rs:357
  Scenario: healthz answers 200 as soon as the process is running
    Given an admin server that has not been marked ready
    When a caller gets /healthz
    Then the response status is 200

  @happy @enforced src/healthcheck.rs:65
  Scenario: The container probe succeeds against a live admin server
    Given a real admin server bound to an ephemeral port
    When the healthcheck probe runs
    Then the probe succeeds

  @malformed @enforced src/healthcheck.rs:86
  Scenario: The container probe fails when healthz answers a non-200 status
    Given a server that answers HTTP 503
    When the healthcheck probe runs
    Then the probe fails with an error mentioning "503"

  @empty @enforced src/healthcheck.rs:72
  Scenario: The container probe fails when nothing is listening
    Given no server bound to the probe address
    When the healthcheck probe runs
    Then the probe fails with an error mentioning "connecting to"

  @empty @enforced tests/cli.rs:392
  Scenario: The healthcheck subcommand exits non-zero when nothing is listening
    When `vega healthcheck --admin-listen 127.0.0.1:1` runs
    Then the process exits non-zero

  # -------------------------------------------------------------- READYZ
  #
  # The per-phase status codes of /healthz, /readyz, /metrics, /version and
  # /reload during a shutdown drain are specified in features/shutdown.feature
  # (VEGA-046). Do not re-specify them here: this file owns the endpoints at
  # rest, that one owns them while the process is going away.

  @happy @enforced src/admin.rs:363
  Scenario: readyz answers 503 before the DNS listeners are bound
    Given an admin server that has not been marked ready
    When a caller gets /readyz
    Then the response status is 503

  @happy @enforced src/admin.rs:363
  Scenario: readyz answers 200 once the server is marked ready
    Given an admin server that has been marked ready
    When a caller gets /readyz
    Then the response status is 200

  @boundary @enforced src/admin.rs:363
  Scenario: readyz answers 503 again once the server is marked unready
    # The drain path: mark_unready is called before the sockets close so a load
    # balancer can take us out of rotation first.
    Given an admin server that has been marked ready and then unready
    When a caller gets /readyz
    Then the response status is 503

  @boundary @gap
  Scenario: readyz is flipped to ready only after every listener is bound
    # src/main.rs:380 calls mark_ready after all binds succeed. main.rs's serve()
    # is entirely uncovered, so nothing verifies the ordering that keeps a
    # half-bound server out of rotation.
    Given a server whose UDP bind fails
    When the process starts
    Then readyz never answers 200

  # ------------------------------------------------------------- METRICS

  @happy @enforced src/admin.rs:379
  Scenario: metrics answers 200 with the Prometheus content type
    Given an admin server
    When a caller gets /metrics
    Then the response status is 200
    And the content type is "text/plain; version=0.0.4; charset=utf-8"

  @happy @enforced src/admin.rs:379
  Scenario: metrics reports the query counter
    Given an admin server that has seen 1 UDP query
    When a caller gets /metrics
    Then the body contains "dns_queries_total 1"

  @happy @enforced src/metrics.rs:352
  Scenario: Every exported series declares a HELP line
    # A series without HELP/TYPE is rejected by strict scrapers.
    When the Prometheus exposition is rendered
    Then every sample name has a matching HELP line

  @empty @enforced src/metrics.rs:292
  Scenario: A server that has served nothing exports zeroes rather than omitting series
    # A missing series and a zero series look very different on a dashboard.
    Given a freshly created metrics registry
    When the Prometheus exposition is rendered
    Then the body contains "dns_queries_total 0"

  @happy @enforced src/metrics.rs:330
  Scenario: The latency histogram buckets are cumulative
    Given one observation of 80 microseconds
    When the Prometheus exposition is rendered
    Then the 0.00005 bucket is 0
    And the 0.0001 bucket is 1
    And the +Inf bucket is 1

  @boundary @enforced src/metrics.rs:322
  Scenario: An untracked response code is counted under the other label
    Given a response with rcode NOTAUTH
    When the Prometheus exposition is rendered
    Then dns_responses_total for rcode other is 1

  @boundary @gap
  Scenario: The zone record count gauge reflects the loaded zone
    # src/metrics.rs:87-89 (set_zone_records) is uncovered. dns_zone_records has
    # never been asserted to be anything but zero, so an operator alerting on
    # "zone emptied itself" would be alerting on a constant.
    Given a server that loaded a zone with 3 records
    When the Prometheus exposition is rendered
    Then dns_zone_records is 3

  @boundary @gap
  Scenario: A failure writing a response is counted
    # src/metrics.rs:117-119 (send_error) is uncovered, as is the handler branch
    # that calls it. dns_send_errors_total is dead instrumentation today.
    Given a client that disappears before the response is written
    When the response send fails
    Then dns_send_errors_total is 1

  # ------------------------------------------------------------- VERSION

  @happy @enforced src/admin.rs:397
  Scenario: version reports the build and readiness
    Given an admin server that has been marked ready
    When a caller gets /version
    Then the response status is 200
    And the body contains the crate version
    And the body reports ready true

  @happy @enforced src/admin.rs:497
  Scenario: version reports the same reload count as the reload endpoint
    Given an admin server that has completed 2 reloads
    When a caller gets /version
    Then the body reports 2 reloads

  @boundary @gap
  Scenario: version reports uptime in seconds
    # The uptime_seconds field is rendered but never asserted.
    Given an admin server
    When a caller gets /version
    Then the body carries a numeric uptime_seconds field

  # -------------------------------------------------------- GATED RELOAD

  @happy @enforced src/admin.rs:420
  Scenario: A loopback caller may reload when no token is configured
    Given an admin server with a reload hook and no token
    When a caller from 127.0.0.1 posts to /reload
    Then the response status is 200

  @hostile @enforced src/admin.rs:431
  Scenario: An off-host caller is forbidden when no token is configured
    Given an admin server with a reload hook and no token
    When a caller from 203.0.113.7 posts to /reload
    Then the response status is 403

  @hostile @enforced src/admin.rs:438
  Scenario: A configured token is required even from loopback
    # Configuring a token must not leave a loopback bypass behind it.
    Given an admin server with a reload hook and the token "s3cret"
    When a caller from 127.0.0.1 posts to /reload with no Authorization header
    Then the response status is 403

  @hostile @enforced src/admin.rs:438
  Scenario: A wrong token is rejected
    Given an admin server with a reload hook and the token "s3cret"
    When a caller from 127.0.0.1 posts to /reload with the token "wrong!"
    Then the response status is 403

  @happy @enforced src/admin.rs:438
  Scenario: The correct token is accepted from loopback
    Given an admin server with a reload hook and the token "s3cret"
    When a caller from 127.0.0.1 posts to /reload with the token "s3cret"
    Then the response status is 200

  @happy @enforced src/admin.rs:468
  Scenario: The correct token is accepted from any source address
    Given an admin server with a reload hook and the token "s3cret"
    When a caller from 203.0.113.7 posts to /reload with the token "s3cret"
    Then the response status is 200

  @hostile @enforced src/admin.rs:531
  Scenario: Token comparison is length-checked before byte comparison
    Given the configured token "abc"
    Then a candidate of "abc" compares equal
    And a candidate of "abd" compares unequal
    And a candidate of "abcd" compares unequal

  @malformed @enforced src/admin.rs:519
  Scenario: An Authorization header that is not a Bearer scheme yields no token
    Given an Authorization header of "Basic abc"
    Then no bearer token is extracted

  @empty @enforced src/admin.rs:519
  Scenario: A request with no Authorization header yields no token
    Given no Authorization header
    Then no bearer token is extracted

  @hostile @gap
  Scenario: A token prefix is not accepted as the token
    # constant_time_eq is length-guarded, but nothing tests a *shorter* candidate
    # that is a strict prefix of the real token — the classic early-exit bug.
    Given an admin server with a reload hook and the token "s3cret"
    When a caller from 127.0.0.1 posts to /reload with the token "s3cre"
    Then the response status is 403

  @hostile @gap
  Scenario: A token with different case is rejected
    Given an admin server with a reload hook and the token "s3cret"
    When a caller from 127.0.0.1 posts to /reload with the token "S3CRET"
    Then the response status is 403

  @malformed @gap
  Scenario: An Authorization header with non-UTF-8 bytes is rejected without panicking
    # bearer() uses to_str().ok()?, so it returns None. Untested.
    Given an Authorization header containing invalid UTF-8
    When a caller from 203.0.113.7 posts to /reload
    Then the response status is 403

  @boundary @gap
  Scenario: An IPv6 loopback caller is treated as loopback
    # `peer.ip().is_loopback()` covers ::1. Only 127.0.0.1 is tested, so an
    # operator on an IPv6-only host has no evidence this works.
    Given an admin server with a reload hook and no token
    When a caller from [::1] posts to /reload
    Then the response status is 200

  @hostile @gap
  Scenario: An empty configured token does not admit an empty bearer header
    # constant_time_eq("", "") is true, so `--admin-token ""` would accept
    # `Authorization: Bearer `. Whether that is intended is undecided today.
    Given an admin server with a reload hook and an empty token
    When a caller from 203.0.113.7 posts to /reload with an empty bearer token
    Then the request is rejected

  # ------------------------------------------------------------- ROUTING

  @malformed @enforced src/admin.rs:408
  Scenario: An unknown path is 404
    Given an admin server
    When a caller gets /nope
    Then the response status is 404

  @malformed @enforced src/admin.rs:512
  Scenario: A GET on the reload endpoint is method-not-allowed
    # /reload is POST-only so a stray browser fetch or crawler cannot trigger it.
    Given an admin server with a reload hook
    When a caller gets /reload
    Then the response status is 405

  @boundary @gap
  Scenario: A POST to a read-only endpoint is method-not-allowed
    Given an admin server
    When a caller posts to /metrics
    Then the response status is 405

  # ------------------------------------------------------- CLIENT COMMANDS

  @empty @enforced tests/cli.rs:392
  Scenario: The status subcommand reports an unreachable server as JSON
    When `vega status --json --admin-listen 127.0.0.1:1` runs
    Then the process exits non-zero
    And the JSON reports reachable false

  @empty @enforced tests/cli.rs:392
  Scenario: The reload subcommand reports an unreachable server as JSON
    When `vega reload --json --admin-listen 127.0.0.1:1` runs
    Then the process exits non-zero
    And the JSON reports ok false

  @happy @gap
  Scenario: The status subcommand renders counters from a live server
    # src/commands/inspect.rs is 38.83% covered; the entire status rendering path
    # (lines 139-355) runs only against an unreachable server. Nothing exercises
    # the success path against a real /metrics and /version.
    Given a running admin server with traffic recorded
    When `vega status --json` runs against it
    Then the process exits zero
    And the JSON carries the query counters

  @happy @gap
  Scenario: The reload subcommand reports the new record count from a live server
    Given a running admin server with a reload hook
    When `vega reload --json` runs against it
    Then the process exits zero
    And the JSON reports the record count

  @malformed @gap
  Scenario: A metrics body that is not valid exposition format is handled without panicking
    # The parser at src/commands/inspect.rs:415-453 is tested against our own
    # well-formed output only. A truncated or hostile body from a wrong port has
    # no scenario.
    Given a server answering /metrics with arbitrary bytes
    When `vega status --json` runs against it
    Then the process exits non-zero without panicking
