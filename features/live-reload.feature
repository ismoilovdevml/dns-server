Feature: Live zone reload without restarting
  # WHY THIS MATTERS
  # Reload is the feature that lets an operator change DNS without dropping
  # queries, which means it runs on a production box, under load, driven by a
  # file somebody just edited. Four things must hold or it is worse than a
  # restart. First, the swap must be atomic: a query must never see half of the
  # old zone and half of the new one. Second, a bad edit must be refused with the
  # old zone left serving — a typo in a config file must not take a name server
  # off the internet. Third, queries already in flight must finish against the
  # zone they started with, because a request that resolves against two different
  # zones can produce an answer that neither zone would ever have given. Fourth,
  # a reload must not quietly change what the process *is*: the command line and
  # environment it was started with are its identity, and a reload that discards
  # them serves a different zone than the operator asked for and answers REFUSED
  # to every production query while returning 200 OK to the operator.
  #
  # The fourth is VEGA-005, ruled on in
  # .claude/backlog/decisions/VEGA-005-reload-precedence.md (binding). Its
  # contract in one line: the invocation is frozen for the life of the process,
  # only the file tier is re-read, the origin is fixed for life, and every
  # restart-only setting that drifts is reported rather than silently dropped.
  #
  # Implementation: src/handler.rs (ArcSwap<Active>, replace_zone, resolve loading
  #                 the snapshot once per query at line 179)
  #                 src/main.rs (reload_hook)
  #                 src/admin.rs (POST /reload)

  # ------------------------------------------------------------ ATOMIC SWAP

  @happy @gap
  Scenario: A reload replaces the served zone
    # src/handler.rs:164-167 (replace_zone) is entirely uncovered. The core
    # mechanism of the whole feature has no test at any level.
    Given a running handler serving a zone where "www" is 203.0.113.10
    When the zone is replaced with one where "www" is 198.51.100.1
    When a client queries "www.example.com." for type A
    Then the answer holds 198.51.100.1

  @happy @gap
  Scenario: A record removed by a reload stops being answered
    Given a running handler serving a zone containing "old" of type A
    When the zone is replaced with one that omits "old"
    And a client queries "old.example.com." for type A
    Then the response rcode is NXDOMAIN

  @happy @gap
  Scenario: Replacing the zone with a different origin changes what is refused
    # The handler mechanism only. A *reload* can never do this — see "A reload
    # that would change the origin is refused" below — but replace_zone installs
    # a new Active whose built-ins are derived from the new origin, so zone and
    # built-ins can never disagree about which zone they are.
    Given a running handler serving "example.com"
    When the zone is replaced with one whose origin is "example.net"
    And a client queries "www.example.com." for type A
    Then the response rcode is REFUSED

  @boundary @gap
  Scenario: A reload can turn the diagnostic built-ins off
    # replace_zone takes builtins_enabled from the fresh config, so toggling
    # `builtins` in the file and reloading must take effect without a restart.
    Given a running handler with built-ins enabled
    When the zone is replaced with built-ins disabled
    And a client queries "myip.example.com." for type A
    Then the response rcode is NXDOMAIN

  @boundary @gap
  Scenario: A reload updates the zone record count metric
    # src/main.rs:419 calls metrics.set_zone_records. src/metrics.rs:87-89 is
    # uncovered, so dns_zone_records has never been observed to hold anything but
    # its initial zero.
    Given a running server with 3 records loaded
    When the config file is changed to declare 5 records and a reload is requested
    Then dns_zone_records reports 5

  @happy @enforced src/admin.rs:420
  Scenario: A successful reload reports the new origin and record count
    Given a running admin server with a reload hook that succeeds
    When a loopback caller posts to /reload
    Then the response status is 200
    And the body reports 3 records
    And the body names the origin

  @happy @enforced src/admin.rs:497
  Scenario: Each successful reload increments the reload counter
    Given a running admin server with a reload hook that succeeds
    When a loopback caller posts to /reload twice
    Then the first response reports 1 reload
    And the second response reports 2 reloads

  # ------------------------------------------- INVOCATION SURVIVES A RELOAD
  #
  # VEGA-005 group A. `reload_hook` currently rebuilds GlobalArgs from
  # GlobalArgs::default(), which is not a neutral element: Config::merge treats an
  # absent CLI value as "fall through to the file, then to the hardcoded default"
  # at src/config.rs:338. So substituting default() does not merely lose the
  # flags, it silently substitutes a different zone. Every scenario in this
  # section fails against today's main.

  @hostile @enforced tests/reload.rs:462
  Scenario: A reload keeps the origin given on the command line
    # The outage in the issue: --domain wins at startup, the first reload falls
    # through to "dnsserver.dev", and every production query becomes REFUSED
    # while /reload returns 200 OK.
    Given a server started with --domain "prod.example.test" and a file with no zone origin
    When a loopback caller posts to /reload
    Then the response status is 200
    And the body reports the origin "prod.example.test"
    And a query for "www.prod.example.test." is answered with AA set

  @hostile @enforced tests/reload.rs:486
  Scenario: A reload does not re-enable built-ins the operator turned off
    Given a server started with --no-builtins and a file setting builtins to true
    When a loopback caller posts to /reload
    Then a query for "myip.<origin>" still gets NXDOMAIN

  @boundary @enforced tests/reload.rs:518
  Scenario: A file origin shadowed by --domain still reloads
    # The CLI wins, so this is not a conflict and not a 409: the reload succeeds,
    # the records land, and the origin does not move.
    Given a server started with --domain "example.test" and a file whose origin is "example.test"
    When the file origin is edited to "other.test" and a reload is requested
    Then the response status is 200
    And the served origin is still "example.test"

  @boundary @enforced tests/reload.rs:542
  Scenario: A shadowed file origin is named in the ignored array
    # Silence is the bug being fixed. An operator must never read a 200 and
    # conclude that their edit took effect.
    Given a server started with --domain "example.test" and a file whose origin is "example.test"
    When the file origin is edited to "other.test" and a reload is requested
    Then the ignored array contains "zone.origin"
    And a WARN names "zone.origin"

  @hostile @enforced tests/reload.rs:562
  Scenario: Every flag from the invocation is still in force after a reload
    # Table-driven over every non-N flag in the ruling's partition table. The
    # assertion is on the effective configuration, not on the absence of an error.
    Given a server started with --domain, --no-builtins, --tcp-timeout-secs, --rate-limit-qps, --log-format and --admin-token
    And a config file that sets a different value for every one of them
    When a loopback caller posts to /reload
    Then every effective setting is still the one from the command line

  @boundary @enforced tests/reload.rs:641
  Scenario: Ten successive reloads with no file change are identical
    # Guards against slow drift: a reload that loses one setting per round is a
    # different bug from one that loses them all at once, and just as fatal.
    Given a server started with --domain "prod.example.test" and --no-builtins
    When ten reloads are requested with no file change
    Then the origin, record count and built-ins state are identical after each

  # ------------------------------ THE ORIGIN IS FIXED FOR THE PROCESS LIFETIME
  #
  # VEGA-005 group C. RFC 8499 §7 defines a zone by its apex and RFC 1034 §4.2
  # makes authority a property of a zone, so in a single-zone process the origin
  # is the process's identity, not a field in its data. Moving it puts every
  # in-bailiwick QNAME outside the served zone; RFC 1034 §4.3.1 then makes every
  # answer REFUSED, and because RFC 2308 defines negative caching only for
  # NXDOMAIN and NODATA, REFUSED is not cached — so every resolver retries at
  # full rate against a server that will never answer.

  @hostile @enforced tests/reload.rs:848
  Scenario: A reload that would change the origin is refused
    # 409, not 400 (RFC 9110 §15.5.10): the request is well formed and the
    # conflict is with the identity this process was started with. 400 means "fix
    # the file"; 409 means "this needs a restart". Different runbooks.
    Given a running server whose origin came from the file as "example.test"
    When the file origin is changed to "example.net" and a reload is requested
    Then the response status is 409
    And the body code is "origin_changed"
    And the body status is "unchanged"
    And the body names both the running and the requested origin

  @hostile @enforced tests/reload.rs:869
  Scenario: A refused origin change leaves the previous zone answering
    Given a running server whose origin came from the file as "example.test"
    When the file origin is changed to "example.net" and a reload is requested
    Then a query for "www.example.test." is still answered with AA set
    And the answer holds the pre-reload data

  @hostile @enforced tests/reload.rs:890
  Scenario: A refused origin change moves neither the gauge nor the reload counter
    # VEGA-049 is about to alert on the reload series. A counter that moves on a
    # refusal makes "reloads are succeeding" unfalsifiable.
    Given a running server whose origin came from the file as "example.test"
    When the file origin is changed to "example.net" and a reload is requested
    Then dns_zone_records is unchanged
    And the reload count reported by /version is unchanged

  @boundary @enforced tests/reload.rs:916
  Scenario: Adding a trailing dot to the origin is not an origin change
    # RFC 1035 §5.1: a trailing dot marks an already-fully-qualified name. A
    # cosmetic edit must not become a spurious 409, so the gate compares
    # canonicalised names and not raw strings.
    Given a running server whose origin came from the file as "example.test"
    When the file origin is changed to "example.test." and a reload is requested
    Then the response status is 200

  @boundary @enforced tests/reload.rs:937
  Scenario: Changing the case of the origin is not an origin change
    # RFC 1034 §3.1 and RFC 4343: DNS names compare case-insensitively over ASCII.
    Given a running server whose origin came from the file as "example.test"
    When the file origin is changed to "EXAMPLE.TEST" and a reload is requested
    Then the response status is 200

  @hostile @enforced tests/reload.rs:958
  Scenario: A refused origin change never builds the new zone
    # Pins the gate ordering: the origin check is step 5 and the zone build is
    # step 6, so a file that is wrong in both ways must report the origin.
    Given a running server whose origin came from the file as "example.test"
    When the file changes the origin and also contains an invalid A value
    Then the response status is 409
    And the body code is "origin_changed"

  # ------------------------------------- FIXED SETTINGS ARE REPORTED, NOT SILENT
  #
  # VEGA-005 group D. A setting that cannot take effect without rebinding a
  # socket, re-registering a listener or rebuilding a subsystem the handler
  # already owns is fixed for the life of the process — and every fixed setting
  # that drifts must appear in the response. The bug being fixed is silence, not
  # tolerance: refusing the whole reload because a restart-only key moved would
  # stop the urgent record change from shipping, which is the opposite of what a
  # reload exists for.

  @boundary @enforced tests/reload.rs:979
  Scenario: A changed UDP listener is reported and not applied
    # A process that dropped CAP_NET_BIND_SERVICE cannot re-bind port 53 at all,
    # so an attempted rebind would fail *after* closing the old socket and leave
    # nothing listening. Restart-only, as in NSD reconfig and Knot server.listen.
    Given a running server bound to the address it was started with
    When the config file changes the UDP listener and a reload is requested
    Then the response status is 200
    And the ignored array contains "server.udp"
    And the server is still bound to its original address
    And a WARN names "server.udp"

  @boundary @enforced tests/reload.rs:1008
  Scenario: A changed rate limit is reported and not applied
    # The limiter is built once in serve() and moved into both the handler and the
    # janitor task, so changing it is not a scalar swap. Today it is not even
    # warned about.
    Given a running server with rate limiting at 10 qps
    When the config file changes the qps to 1000 and a reload is requested
    Then the response status is 200
    And the ignored array contains "server.rate_limit.qps"
    And the effective rate limit is still 10 qps

  @boundary @enforced tests/reload.rs:1050
  Scenario: Every fixed setting that drifts is named in the ignored array
    # The closed set, bounded at nine: server.udp, server.tcp,
    # server.admin_listen, server.tcp_timeout_secs, server.log_level,
    # server.log_format, server.admin_token, server.rate_limit.qps and
    # server.rate_limit.burst.
    Given a running server
    When the config file changes every restart-only setting and a reload is requested
    Then the ignored array names all nine of them

  @hostile @enforced tests/reload.rs:1093
  Scenario: A drifted admin token reports its key path and never its value
    # Token rotation by reload is deliberately not supported — the reload that
    # changes the token is authenticated by the old one — but the drift is still
    # reported, and reporting it must not turn the response or the log into a
    # place secrets appear.
    Given a running server with an admin token
    When the config file changes admin_token and a reload is requested
    Then the ignored array contains "server.admin_token"
    And neither the old nor the new token value appears in the response body
    And neither appears in any log line

  @boundary @enforced tests/reload.rs:1134
  Scenario: A fixed setting that still drifts is reported on every reload
    # Running::config.udp means "what we are bound to", not "what the file last
    # said". A `running = fresh` assignment silences the second warning while the
    # drift from the actual socket is still there; that is a defect.
    Given a config file whose UDP listener differs from the running one
    When a reload is requested twice with no further edit
    Then both responses name "server.udp" in the ignored array

  @empty @enforced tests/reload.rs:1165
  Scenario: A reload with nothing drifted reports an empty ignored array
    # Present and empty, never absent: a consumer must not have to guess whether a
    # missing field means "nothing was ignored" or "this build does not report".
    Given a running server whose config file has not changed
    When a loopback caller posts to /reload
    Then the body carries an ignored array
    And that array is empty

  @boundary @enforced tests/reload.rs:1183
  Scenario: The reload command prints the ignored keys to the terminal
    # An operator who never reads the JSON must still see what did not apply.
    Given a config file whose UDP listener differs from the running one
    When `vega reload` runs without --json
    Then the output names "server.udp"

  # -------------------------------------------------- BAD CONFIG REFUSED
  #
  # VEGA-005 group E. Nothing mutates shared state until every gate has passed,
  # so there is no rollback path because there is nothing to roll back. In every
  # failure below the running zone is byte-identical afterwards, the record-count
  # gauge is unchanged, and the reload counter has not moved.

  @malformed @enforced src/admin.rs:484
  Scenario: A reload that fails to build a zone is reported as a bad request
    Given a running admin server with a reload hook that fails
    When a loopback caller posts to /reload
    Then the response status is 400

  @malformed @enforced src/admin.rs:484
  Scenario: A failed reload says the configuration is unchanged
    Given a running admin server with a reload hook that fails
    When a loopback caller posts to /reload
    Then the body reports status "unchanged"
    And the body carries the underlying error text

  @malformed @enforced src/admin.rs:551
  Scenario: A failed reload does not increment the reload counter
    Given a running admin server with a reload hook that fails
    When a loopback caller posts to /reload
    Then /version still reports 0 reloads

  @malformed @enforced tests/reload.rs:1278
  Scenario: A config whose zone will not build is refused
    # The end-to-end version: a real bad edit on disk, a real reload, and the old
    # answer still being served afterwards.
    Given a running server serving "www" as 203.0.113.10
    When the config file is edited to contain an invalid A value and a reload is requested
    Then the response status is 400
    And the body code is "zone_build_failed"
    And a query for "www.example.test." still holds 203.0.113.10

  @malformed @enforced tests/reload.rs:1239
  Scenario: A reload of unparseable TOML is refused
    Given a running server serving "www" as 203.0.113.10
    When the config file is replaced with unparseable TOML and a reload is requested
    Then the response status is 400
    And the body code is "config_parse_failed"
    And a query for "www.example.test." still holds 203.0.113.10

  @malformed @enforced tests/reload.rs:1257
  Scenario: A semantically invalid config is refused
    # Rejected by Config::merge rather than by the parser: empty origin, zero
    # default_ttl, duplicate listeners, zero tcp_timeout_secs, zero burst.
    Given a running server serving "www" as 203.0.113.10
    When the config file sets default_ttl to 0 and a reload is requested
    Then the response status is 400
    And the body code is "config_invalid"
    And a query for "www.example.test." still holds 203.0.113.10

  @empty @enforced tests/reload.rs:1216
  Scenario: A reload of a deleted config file is refused
    # More common than it looks: config-management tools and editors that write by
    # rename briefly unlink the target, and a reload racing that window gets
    # ENOENT. Retrying is safe.
    Given a running server serving "www" as 203.0.113.10
    When the config file is deleted and a reload is requested
    Then the response status is 400
    And the body code is "config_read_failed"
    And the error names the file path
    And a query for "www.example.test." still holds 203.0.113.10

  @hostile @enforced tests/reload.rs:1297
  Scenario: No failing reload moves the reload counter or the records gauge
    Given a running server
    When each of the four failure modes and an origin change are driven in turn
    Then dns_zone_records is unchanged after every one
    And the reload count reported by /version is unchanged after every one

  @malformed @enforced tests/reload.rs:1340
  Scenario: Every reload error body carries a code from the documented set
    # Scripts key on the code, never on the prose, and VEGA-049's failure counter
    # is labelled by it. The set is closed: config_read_failed,
    # config_parse_failed, config_invalid, zone_build_failed, origin_changed,
    # reload_in_progress, shutting_down, not_configured, forbidden, internal.
    Given a running server
    When a reload is refused for any reason
    Then the body carries a code from the documented set

  # ------------------------------------------------------- IN-FLIGHT QUERIES

  @hostile @gap
  Scenario: A query that started before a reload finishes against the old zone
    # DnsHandler::resolve loads the ArcSwap snapshot once (src/handler.rs:179) so
    # every branch of one query agrees on which zone it is answering from. This
    # is the property the whole ArcSwap design exists for and it has no test.
    Given a running handler serving "www" as 203.0.113.10
    When a query begins resolving and a reload completes mid-resolution
    Then that query's answer is entirely from the pre-reload zone

  @hostile @enforced tests/reload.rs:1404
  Scenario: Fifty reloads under a steady query stream never drop or mix an answer
    # Driven through the real reload_hook and POST /reload, not through
    # replace_zone directly, so it covers the whole pipeline under load.
    Given a running server under a steady stream of queries
    When 50 reloads are requested in succession
    Then every query in the stream is answered
    And no response has rcode SERVFAIL
    And no answer mixes records from two zones

  @hostile @gap
  Scenario: Repeated reloads under load do not leak zones
    Given a running server under a steady stream of queries
    When 50 reloads are requested in succession
    Then memory use is stable

  # -------------------------------------------------------------- GATING

  @boundary @enforced src/admin.rs:525
  Scenario: Reload is unavailable when the server was started without a config file
    # admin_state only gets a hook when config.source is Some.
    Given a running admin server with no reload hook
    When a caller posts to /reload
    Then the response status is 501
    And the body code is "not_configured"

  @hostile @enforced src/admin.rs:568
  Scenario: A reload hook that panics is reported as a server error
    # src/admin.rs handles the JoinError from spawn_blocking. Note the release
    # profile sets panic = "abort", so this arm can only ever be reached in a
    # debug build — which is itself worth stating explicitly.
    Given a running admin server with a reload hook that panics on its first call
    When a loopback caller posts to /reload
    Then the response status is 500
    And a subsequent reload still succeeds

  @hostile @gap
  Scenario: A panicking reload does not leave the reload mutex poisoned
    # The recovery path in the ruling's §5: TryLockError::Poisoned is recovered
    # with into_inner, because the guarded state is a baseline snapshot only and
    # steps 0-8 mutate nothing shared. Not reachable from outside the process:
    # the state lives in ReloadContext inside the binary, and no config file can
    # make the hook panic. Needs reload_hook moved into the library.
    Given a reload hook whose zone build panics while holding the state lock
    When a later reload is requested
    Then it succeeds rather than failing with a poisoned lock

  @hostile @enforced tests/reload.rs:1363
  Scenario: Concurrent reload requests are each applied or refused as in progress
    # AMENDED by the VEGA-005 ruling, which supersedes the previous "every
    # response is 200". Queueing N reloads would pin N tokio blocking-pool threads
    # on identical file IO for an identical result, and buys no ordering guarantee
    # — the last to *complete* wins, not the last submitted. try_lock plus an
    # immediate 409 is honest, O(1) and retryable.
    Given a running admin server with a reload hook
    When 10 reloads are posted concurrently
    Then every response is 200 or 409 "reload_in_progress"
    And at least one response is 200
    And the served zone matches the config file afterwards

  @hostile @gap
  Scenario: A reload arriving after the drain has started is refused
    # VEGA-046 invariant I1: the admin listener stays up through the drain so
    # /readyz can serve 503, which means /reload also stays reachable and must be
    # explicitly gated. Checked twice — before taking the lock and again
    # immediately before the swap — so a drain starting mid-build abandons the
    # freshly built zone rather than installing it into a dying process.
    # Not enforceable from outside the process: SIGTERM and the POST cannot be
    # ordered deterministically, so the test would pass vacuously whenever the
    # listener closed first. Needs VEGA-046's drain-start CancellationToken and
    # reload_hook in the library so the signal can be driven directly.
    Given a running server whose drain has started
    When a loopback caller posts to /reload
    Then the response status is 503
    And the body code is "shutting_down"
    And the zone is not swapped

  # ------------------------------------------------------------- ORDERING

  @hostile @gap
  Scenario: The record-count gauge never describes a zone that is not installed
    # src/main.rs:460-461 sets the gauge *before* replace_zone, so a Prometheus
    # scrape landing between the two reports the new record count for the old
    # zone. The fix is to reverse them: gauge after swap.
    # Not enforceable from outside the process: the window between two adjacent
    # statements is nanoseconds and there is no way to interleave an HTTP scrape
    # into it. Needs reload_hook in the library, where a Metrics double can assert
    # the handler's installed zone at the moment set_zone_records is called.
    Given a running server reloading between a 3-record and a 5-record zone
    When /metrics is scraped concurrently with the reloads
    Then dns_zone_records only ever reports the count of the zone then installed
