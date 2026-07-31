Feature: Shutdown drain
  # WHY THIS MATTERS
  # A name server that vanishes the instant it is signalled takes a slice of the
  # internet's resolution with it. Measured today (VEGA-046): SIGTERM to process
  # exit is 1.3 ms, /readyz goes 200 -> connection refused and never once serves
  # 503, and a query already sitting on an established TCP connection is dropped
  # with no answer. terminationGracePeriodSeconds: 20 is decorative, because a
  # grace period is a ceiling on how long the kubelet waits, not a delay it
  # imposes. Every routine deploy is therefore a multi-second resolution stall
  # for everyone still holding our address — and it is invisible in our own
  # metrics, because we never receive the queries we dropped.
  #
  # The fix is a five-phase lifecycle (Starting, Serving, Draining, Stopping,
  # Closing) driven by three tokens that are never shared, cancelled in a strict
  # order: publish 503 first, keep answering DNS for the whole drain window,
  # close the DNS listeners, and close the admin listener last so a probe can
  # still see us going away. The invariant every scenario below exists to hold:
  #
  #   from the moment Draining is entered until the DNS token is cancelled,
  #   /readyz returns 503 AND every DNS query received is answered.
  #
  # Design ruling: .claude/backlog/decisions/VEGA-046-shutdown-drain.md
  # Implementation: src/lifecycle.rs (phase), src/shutdown.rs (signals),
  #                 src/main.rs serve() (ordering), src/admin.rs (status codes),
  #                 src/config.rs (shutdown_drain_secs)
  #
  # The drain window W defaults to 15s, derived in §2.2 as
  # readiness observation (7s) + kube-proxy propagation (5s), and >= the TCP
  # idle timeout (10s). Tests use a short configured window so they stay fast;
  # they assert orderings and inequalities with margin, never exact durations.

  # ----------------------------------------------------------- HAPPY PATH

  @happy @enforced tests/shutdown.rs:675
  Scenario: readyz reports 503 while DNS is still answering
    # The headline criterion of the issue. This is the whole point of a drain:
    # the load balancer is told to stop sending traffic while we can still
    # serve the traffic already in flight and already addressed to us.
    Given a running server with a drain window of 2 seconds
    When the process is sent SIGTERM
    And a client polls /readyz and a UDP query every 10 milliseconds
    Then there is an interval of at least 1.9 seconds in which /readyz answers 503 and every query is answered NOERROR

  @happy @enforced tests/shutdown.rs:718
  Scenario: The shutdown order is readiness, then DNS, then the admin listener
    # Any other order loses queries: closing DNS first drops traffic nothing has
    # been told to stop sending, and closing admin first hides the 503.
    Given a running server with a drain window of 2 seconds
    When the process is sent SIGTERM
    Then /readyz answers 503 before the first unanswered query
    And the first unanswered query comes before /healthz becomes unreachable

  @happy @enforced tests/shutdown.rs:755
  Scenario: The process does not exit before the drain window has elapsed
    Given a running server with a drain window of 2 seconds
    When the process is sent SIGTERM
    Then the time from the signal to process exit is at least 2 seconds
    And the exit code is 0

  @happy @enforced tests/shutdown.rs:785
  Scenario: healthz stays 200 for the whole drain
    # Liveness answers "is this process alive", and a draining process is alive.
    # A 503 here is what gets the container restarted mid-drain on any SIGTERM
    # that does not accompany a delete.
    Given a running server with a drain window of 2 seconds
    When the process is sent SIGTERM
    Then every /healthz poll until the admin listener closes answers 200 with the body "ok\n"

  @happy @enforced tests/shutdown.rs:822
  Scenario: The draining phase is observable
    # A scrape that catches the drain is the only record we will ever have of it.
    Given a running server with a drain window of 3 seconds
    When the process is sent SIGTERM
    And a caller reads the admin endpoints 300 milliseconds later
    Then /metrics reports dns_shutdown_phase 2
    And /version reports phase draining and ready false
    And the response carries the header X-Vega-Phase: draining

  # ------------------------------------------------------------- BOUNDARY

  @boundary @enforced tests/shutdown.rs:862
  Scenario: A zero-length drain still passes through every phase in order
    # 0 is legal and is the right value for CI and `cargo run`. It must not be a
    # second code path: unready is still published before the sockets close.
    Given a running server with a drain window of 0 seconds
    When the process is sent SIGTERM
    Then the process exits 0
    And the log records the draining, stopping and closing phases in that order

  @boundary @enforced tests/shutdown.rs:894
  Scenario: SIGINT runs the same machine with a zero-length window
    # SIGINT comes from a terminal and a human. No orchestrator sends it, so
    # making Ctrl-C block a developer for the drain is a pure usability tax.
    Given a running server started with --shutdown-drain-secs 10
    When the process is sent SIGINT
    Then the process exits within 2 seconds
    And the exit code is 0

  @boundary @enforced tests/shutdown.rs:924
  Scenario: A drain window above the 300 second maximum is refused at startup
    # Above five minutes the value is a typo and the only outcome is a
    # guaranteed SIGKILL. Refusing at startup is cheaper than during a rollout.
    Given a config file with shutdown_drain_secs = 301
    When the process starts
    Then it exits non-zero
    And the error names shutdown_drain_secs and the limit of 300

  @boundary @enforced tests/shutdown.rs:965
  Scenario: The 300 second maximum is itself accepted
    # The range is inclusive; an off-by-one here refuses a legal config.
    Given a config file with shutdown_drain_secs = 300
    When the process starts
    Then it reports ready

  @malformed @enforced tests/shutdown.rs:980
  Scenario: A negative drain window is refused at startup
    Given a config file with shutdown_drain_secs = -1
    When the process starts
    Then it exits non-zero
    And the error names shutdown_drain_secs rather than reporting an unknown key

  @boundary @enforced tests/shutdown.rs:1008
  Scenario: A drain shorter than the TCP idle timeout warns and still starts
    # An operator may deliberately want a short drain; refusing to start a name
    # server over a tuning choice is worse than the degradation it causes.
    Given a config file with shutdown_drain_secs = 2 and tcp_timeout_secs = 10
    When the process starts
    Then it reports ready
    And a warning names the drain and the TCP idle timeout

  @empty @enforced tests/shutdown.rs:1030
  Scenario: With no admin listener the drain still runs, with a warning
    # Nothing can observe the 503, but resolvers holding our address from a
    # cached NS RRset keep getting answers. Degraded, not broken.
    Given a running server with no admin listener and a drain window of 2 seconds
    Then a warning says the drain cannot be observed by a readiness probe
    When the process is sent SIGTERM
    Then the time from the signal to process exit is at least 2 seconds

  @happy @enforced tests/shutdown.rs:1060
  Scenario: Startup states the drain, the hard deadline and the grace-period floor
    # We cannot read terminationGracePeriodSeconds from inside the container, so
    # we publish the number the operator has to beat.
    Given a server started with no drain configured
    When the process starts
    Then one INFO line states the 15 second drain, the 20 second hard deadline and the 22 second terminationGracePeriodSeconds floor

  # ------------------------------------------------------------ IN-FLIGHT

  @happy @enforced tests/shutdown.rs:1091
  Scenario: A query written after SIGTERM on an established TCP connection is answered
    # RFC 7766 §6.2.4 permits closing, and puts retry on the client — so this is
    # an availability defect, not a protocol violation. The client pays a full
    # retry on the transport it chose because the answer did not fit in 512 bytes.
    Given a running server with a drain window of 2 seconds
    And an established DNS-over-TCP connection carrying no query yet
    When the process is sent SIGTERM
    And the client writes a query 100 milliseconds later
    Then a complete NOERROR response with the A record arrives on that connection

  @boundary @enforced tests/shutdown.rs:1119
  Scenario: A query received in the final 50 milliseconds of the window is answered
    # This is what the Stopping phase's 1 second quiesce exists for: hickory
    # aborts every connection task the instant its token is cancelled.
    Given a running server with a drain window of 3 seconds
    And an established DNS-over-TCP connection
    When the process is sent SIGTERM
    And the client writes a query 2950 milliseconds later
    Then a complete NOERROR response arrives on that connection

  @boundary @enforced tests/shutdown.rs:1146
  Scenario: An idle keep-alive connection is closed cleanly, not reset
    # A reset discards data the client has not read yet, including a response we
    # finished writing microseconds earlier. With drain >= tcp_timeout, hickory's
    # own TimeoutStream closes the connection from the read side during the
    # window, which is the only way we get a FIN out of hickory 0.26.1.
    Given a running server with tcp_timeout_secs = 1 and a drain window of 4 seconds
    And an idle DNS-over-TCP connection
    When the process is sent SIGTERM
    Then the client's read returns end-of-file rather than ECONNRESET
    And that happens between 0.5 and 2.5 seconds after the signal, while the process is still draining

  # -------------------------------------------------- SECOND SIGNAL / HOSTILE

  @hostile @enforced tests/shutdown.rs:1207
  Scenario: A second SIGTERM collapses the remaining window
    # "Hurry up", not "corrupt yourself": it never calls exit() and never
    # bypasses the ordering. SIGKILL remains the immediate-exit mechanism.
    Given a running server with a drain window of 10 seconds
    When the process is sent SIGTERM
    And it is sent a second SIGTERM 1 second later
    Then the process exits within 3 seconds of the first signal
    And the exit code is 0

  @hostile @enforced tests/shutdown.rs:1253
  Scenario: A storm of SIGTERMs drives exactly one pass through the machine
    # §13.16 asks for four things and no more: exits once, cleanly, exit code 0,
    # no panic, no double-cancel. An earlier draft of this scenario also demanded
    # that eight of the ten signals reach a live process, which contradicts the
    # scenario above it — the *second* signal collapses the remaining window, so
    # the process is entitled to be gone at t = 15ms and signals 3..10 land on a
    # corpse. Measured: signal 2 at t=14ms, exit at t=14.5ms. What has to hold is
    # that the second signal still finds us draining rather than dead, and that
    # the storm is folded into one pass of the machine rather than restarting it.
    Given a running server with a drain window of 5 seconds
    When the process is sent ten SIGTERMs at 10 millisecond intervals
    Then the second signal still reaches a live, draining process
    And the signals after the first are folded into the running shutdown
    And each stage of the shutdown is logged exactly once, in order
    And the process exits 0 with no panic in the log

  @hostile @enforced tests/shutdown.rs:1337
  Scenario: SIGHUP is ignored rather than killing the process
    # Today SIGHUP is unhandled, so its default disposition terminates us with
    # no drain, no 503 and no log — strictly worse than the SIGTERM this issue
    # is about. A terminal hangup or a stray killall -HUP is enough.
    Given a running server
    When the process is sent SIGHUP
    Then 500 milliseconds later it is still running and still answers queries
    And /readyz still answers 200
    And a warning records the ignored SIGHUP

  @hostile @enforced tests/shutdown.rs:1375
  Scenario: A reload during the drain is refused and the hook is never invoked
    # Swapping the zone in a process seconds from exiting cannot help anything,
    # and is the exact window in which a reload can wedge the drain. The counter
    # is what proves the hook never ran, rather than merely that it failed.
    Given a running server with a drain window of 3 seconds that has reloaded once
    When the process is sent SIGTERM
    And a caller posts to /reload 300 milliseconds later
    Then the response status is 503 with an error of "draining"
    And /version still reports 1 reload

  @hostile @enforced tests/shutdown.rs:1431
  Scenario: A reload is refused by the drain-start token, not the listener-cancel one
    # Stronger than the scenario above, and only writable once the lifecycle
    # exists. Before VEGA-046 the drain-start and listener-cancel tokens were the
    # same instant, so gating /reload on either was equivalent. This change moves
    # them seconds apart: wiring the refusal to the listener-cancel token would
    # let a reload succeed for the whole drain window and install a new zone into
    # a process that is about to exit — strictly worse than the old behaviour.
    # All three conditions are asserted in one interval, bracketed by /readyz, so
    # they cannot each hold at a different moment.
    Given a running server with a drain window of 3 seconds
    When the process is sent SIGTERM
    And a caller reads the admin endpoints 300 milliseconds later
    Then /readyz answers 503 both before and after the observation
    And a DNS query in that same interval is answered NOERROR
    And POST /reload is refused with 503 and code "shutting_down"
    And that refusal carries the header X-Vega-Phase: draining

  @hostile @enforced tests/shutdown.rs:1503
  Scenario: Sustained load through the drain loses no query
    # Two things this scenario had to be corrected on, both about *measurement*.
    # "Before the listeners closed" has to mean before a moment at which DNS was
    # observed to still be answering, not before the first poll that failed —
    # the sockets can close anywhere in the gap between the two, and §1.5
    # promises "a query received during Draining is answered", not "a query
    # received in the final microsecond of Draining". And the metrics have to be
    # read from a process that is still alive: an exited one serves none, so a
    # scrape taken after it can assert nothing about anything.
    Given a running server with a drain window of 2 seconds
    And roughly 1000 queries per second in flight across the signal
    When the process is sent SIGTERM
    Then every query issued while /readyz reported 503, up to the last moment DNS was seen answering, was answered
    And that interval covers at least 1.5 seconds of the 2 second window
    And a /metrics scrape taken from the still-draining process reports dns_send_errors_total 0
    And that same scrape reports no SERVFAIL and hundreds of NOERROR responses

  # ------------------------------------------------------------- DEADLINE

  @happy @enforced tests/shutdown.rs:1601
  Scenario: The hard deadline is armed and counts down in the metrics
    Given a running server with a drain window of 3 seconds
    Then dns_shutdown_deadline_seconds is absent from /metrics before any signal
    When the process is sent SIGTERM
    Then dns_shutdown_deadline_seconds appears
    And it has decreased by at least half a second one second later

  @hostile @enforced tests/shutdown.rs:1647
  Scenario: A shutdown wedged by a blocking task exits 3 within the watchdog grace
    # Failure mode 5. A tokio timer cannot fire if nothing is polling it, so the
    # only thing that can end a wedged runtime is an OS thread. Exit code 3 is
    # distinct from clean (0) and startup failure (1) so an operator can tell
    # from lastState.terminated.exitCode that the shutdown overran.
    Given a running server with a drain window of 0 seconds
    And a reload hook wedged forever on a FIFO with no writer
    When the process is sent SIGTERM
    Then the process exits within the hard deadline plus the 2 second watchdog grace
    And the exit code is 3
    And an ERROR names the deadline and the phase it was stuck in

  @hostile @enforced tests/shutdown.rs:1750
  Scenario: A half-open admin connection does not cost the shutdown its exit code
    # VEGA-079, a consequence VEGA-046 created: `Closing` awaits the admin task,
    # axum's graceful shutdown waits for every accepted connection, and the admin
    # server has no header-read timeout (VEGA-019). Three unauthenticated
    # connections that begin a request header and stop then push every shutdown
    # past the hard deadline, so each rollout reports Error and a real wedge
    # stops being distinguishable from a routine one.
    Given a running server with a drain window of 0 seconds
    And three connections to the admin port whose request headers are never terminated
    When the process is sent SIGTERM
    Then the process exits 0 within the admin close budget
    And the log records shutdown complete
    And a warning says a client held a connection open and it was abandoned

  # ---------------------------------------------------- REGRESSION GUARDS

  @hostile @enforced tests/shutdown.rs:1715
  Scenario: The signal watcher is never handed the DNS token
    # The exact defect: shutdown::watch() is given server.shutdown_token(), so
    # SIGTERM cancels the DNS accept loops directly and no 503 can be served.
    # Asserted structurally today; replace with a type assertion once Signals
    # exists (`let _: fn() -> Signals = shutdown::watch;`).
    Given the source of src/shutdown.rs and src/main.rs
    Then shutdown::watch takes no CancellationToken argument
    And src/main.rs calls shutdown::watch with no arguments

  @hostile @enforced tests/shutdown.rs:1748
  Scenario: A fatal admin error does not cancel the DNS token
    # src/main.rs:403 cancels the DNS token when the admin server dies, so a
    # mid-life admin failure kills DNS with no drain at all.
    Given the source of src/main.rs
    Then the admin task's error path does not cancel a cancellation token
    And the admin server is given its own freshly created token

  @empty @enforced tests/shutdown.rs:1773
  Scenario: An admin listener that cannot bind is a startup failure
    # The behavioural half of the guard above, and VEGA-044's "bind admin before
    # mark_ready", which lands in the same change. Today the admin task cancels
    # the DNS token and the process reports success, hiding the failure from
    # every supervisor.
    Given the configured admin port is already held by another process
    When the process starts
    Then it exits 1
    And the error names the admin listener

  # ------------------------------------------------------------------ GAPS

  @hostile @gap
  Scenario: An admin server that dies mid-drain does not shorten the drain
    # Failure mode 3. From outside the process there is no way to make an
    # already-bound admin server fail, so this needs a test-only fault injection
    # point before it can be enforced. Until then the wiring is pinned only
    # structurally, by the guard above.
    Given a running server in the Draining phase
    When the admin task fails
    Then the DNS listeners keep answering until the drain window elapses
    And the process still exits 0

  @boundary @gap
  Scenario: A drain longer than the TCP idle timeout closes idle connections before Stopping
    # §3.3's stronger claim: with W >= tcp_timeout there is nothing left in the
    # receive queue when the sockets close, so a pipelined-but-unread query
    # cannot produce an RST. Asserting the absence of a reset for a *pipelined*
    # client needs a raw socket that writes without reading, which the current
    # helper does not do.
    Given a client that pipelines a query and never reads
    When the process drains and exits
    Then the client sees an orderly close rather than ECONNRESET

  @boundary @gap
  Scenario: The shipped Kubernetes manifest keeps liveness above the hard deadline
    # §4.1's invariant: livenessProbe.periodSeconds x failureThreshold must
    # exceed D (20s), or the kubelet restarts us mid-drain. This is a property of
    # deploy/kubernetes/vega.yaml, not of the binary, and belongs to devops-sre.
    Given deploy/kubernetes/vega.yaml
    Then livenessProbe periodSeconds times failureThreshold exceeds 20 seconds
    And terminationGracePeriodSeconds exceeds the drain plus 7 seconds
