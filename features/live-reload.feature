Feature: Live zone reload without restarting
  # WHY THIS MATTERS
  # Reload is the feature that lets an operator change DNS without dropping
  # queries, which means it runs on a production box, under load, driven by a
  # file somebody just edited. Three things must hold or it is worse than a
  # restart. First, the swap must be atomic: a query must never see half of the
  # old zone and half of the new one. Second, a bad edit must be refused with the
  # old zone left serving — a typo in a config file must not take a name server
  # off the internet. Third, queries already in flight must finish against the
  # zone they started with, because a request that resolves against two different
  # zones can produce an answer that neither zone would ever have given.
  #
  # Implementation: src/handler.rs (ArcSwap<Active>, replace_zone, resolve loading
  #                 the snapshot once per query at line 179)
  #                 src/main.rs:399-424 (reload_hook)
  #                 src/admin.rs:230-297 (POST /reload)

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
  Scenario: A reload that changes the origin changes what is refused
    # replace_zone installs a new Active whose builtins are derived from the new
    # origin, so zone and built-ins can never disagree about which zone they are.
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

  # -------------------------------------------------- BAD CONFIG REFUSED

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

  @malformed @gap
  Scenario: A reload with an invalid record value leaves the old zone serving
    # The end-to-end version of the above: a real bad edit on disk, a real
    # reload, and the old answer still being served afterwards. src/main.rs:399
    # (reload_hook) is entirely uncovered, so nothing verifies that the zone is
    # built successfully *before* replace_zone is called.
    Given a running server serving "www" as 203.0.113.10
    When the config file is edited to contain an invalid A value and a reload is requested
    Then the reload is rejected
    And a query for "www.example.com." still holds 203.0.113.10

  @malformed @gap
  Scenario: A reload of a config file with broken TOML leaves the old zone serving
    Given a running server serving "www" as 203.0.113.10
    When the config file is replaced with unparseable TOML and a reload is requested
    Then the reload is rejected
    And a query for "www.example.com." still holds 203.0.113.10

  @empty @gap
  Scenario: A reload of a config file that has been deleted leaves the old zone serving
    # Config::load surfaces a read error; the hook maps it to a string. Untested.
    Given a running server serving "www" as 203.0.113.10
    When the config file is deleted and a reload is requested
    Then the reload is rejected
    And a query for "www.example.com." still holds 203.0.113.10

  @boundary @gap
  Scenario: Changing a listener address is accepted but not applied
    # src/main.rs:413-415 logs a warning and carries on. An operator who edits
    # the listen address and reloads must not silently believe it took effect.
    Given a running server bound to 127.0.0.1:5300
    When the config file changes the UDP listener and a reload is requested
    Then the reload succeeds
    And the server is still bound to 127.0.0.1:5300

  @boundary @gap
  Scenario: Changing the rate limit is accepted but not applied
    # The limiter is constructed once in serve() and never rebuilt by the hook.
    # Same class of silent no-op as the listener address, and not even warned
    # about.
    Given a running server with rate limiting at 10 qps
    When the config file changes the qps to 1000 and a reload is requested
    Then the reload succeeds
    And the effective rate limit is still 10 qps

  # ------------------------------------------------------- IN-FLIGHT QUERIES

  @hostile @gap
  Scenario: A query that started before a reload finishes against the old zone
    # DnsHandler::resolve loads the ArcSwap snapshot once (src/handler.rs:179) so
    # every branch of one query agrees on which zone it is answering from. This
    # is the property the whole ArcSwap design exists for and it has no test.
    Given a running handler serving "www" as 203.0.113.10
    When a query begins resolving and a reload completes mid-resolution
    Then that query's answer is entirely from the pre-reload zone

  @hostile @gap
  Scenario: Continuous queries during a reload are all answered
    # No dropped queries, no errors, no panics while the swap happens under load.
    Given a running server under a steady stream of queries
    When a reload is requested
    Then every query in the stream is answered
    And no response has rcode SERVFAIL

  @hostile @gap
  Scenario: Repeated reloads under load do not leak zones
    Given a running server under a steady stream of queries
    When 50 reloads are requested in succession
    Then memory use is stable
    And every query is answered

  # -------------------------------------------------------------- GATING

  @boundary @enforced src/admin.rs:414
  Scenario: Reload is unavailable when the server was started without a config file
    # admin_state only gets a hook when config.source is Some.
    Given a running admin server with no reload hook
    When a caller posts to /reload
    Then the response status is 501

  @hostile @gap
  Scenario: A reload hook that panics is reported as a server error rather than killing the process
    # src/admin.rs:292-295 handles the JoinError from spawn_blocking. Uncovered.
    # Note the release profile sets panic = "abort", so this arm can only ever be
    # reached in a debug build — which is itself worth stating explicitly.
    Given a running admin server with a reload hook that panics
    When a loopback caller posts to /reload
    Then the response status is 500

  @hostile @gap
  Scenario: Concurrent reload requests do not corrupt the served zone
    # spawn_blocking runs the hook off the async worker but nothing serialises
    # two simultaneous reloads.
    Given a running admin server with a reload hook
    When 10 reloads are posted concurrently
    Then every response is 200
    And the served zone matches the config file
