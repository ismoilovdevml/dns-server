# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — BREAKING

- **`rate_limit.qps` and `.burst` now apply to a source network, not a source
  address.** The limiter keys on an IPv4 **/24** or an IPv6 **/56** (BIND 9's
  documented defaults), with IPv4-mapped IPv6 sources folded to their IPv4 form
  first. Every host inside one /24 now shares one bucket.

  **This will look like an outage if you sized `qps` per resolver.** An operator
  running `qps = 50` whose traffic comes from a resolver farm of 200 hosts inside
  one /24 was granting that farm 10,000 queries per second and is now granting it
  50. Size `qps` for the busiest single /24 you serve, not for a single resolver.
  Rate limiting is off unless `qps` is configured, so no default deployment
  changes behaviour.

  Keying on the full address is what made the limiter both useless and dangerous:
  an attacker holding one IPv6 /64 could present 2^64 distinct "sources", each
  meeting a bucket that had never been touched, so the bucket never fired while
  every forged address cost memory.

### Changed

- **`POST /reload` answers with a machine-readable `code` on every failure, and
  two status codes it never used before.** Anything parsing the old
  `{"status":"unchanged","error":"..."}` prose still works — `status` and
  `error` are unchanged — but a client that treated every non-`200` as the same
  condition now needs to tell three apart:

  | status | `code` | what an operator should do |
  | --- | --- | --- |
  | `400` | `config_read_failed`, `config_parse_failed`, `config_invalid`, `zone_build_failed` | fix the file |
  | `409` | `origin_changed` | this needs a restart, not a reload |
  | `409` | `reload_in_progress` | another reload holds the lock; retry |
  | `503` | `shutting_down` | the process is draining; do not retry here |

  A successful reload now also carries an `ignored` array of the TOML key paths
  that were read but could not be applied, because they are fixed for the life
  of the process — listen addresses, the origin, the rate limits, the admin
  token, the log settings. Previously those were discarded in silence, so an
  operator could edit a listen address, read `200 OK`, and believe it had taken
  effect. `server.admin_token` appears in that array as a key path only; its
  value is never rendered.

- **A wildcard-covered name now answers `NOERROR` with an empty answer section
  where it used to answer `NXDOMAIN`.** This is a wire-visible change and it
  will move your metrics: if you alert on NXDOMAIN rate, expect a step down on
  any zone that holds a wildcard, and a matching step up in NOERROR. Nothing
  that previously resolved changes its answer — see *Fixed* below for why the
  old behaviour was a cache-poisoning vector rather than a cosmetic bug.

### Fixed

- **A wildcard-covered name answered `NXDOMAIN` for every type the wildcard did
  not carry.** With `*.dev A 203.0.113.50` configured, `x.dev.example.com/A`
  answered correctly while `x.dev.example.com/AAAA` — and `TXT`, `MX`, `SRV`,
  `ANY` — answered an authoritative `NXDOMAIN`.

  That is not a cosmetic wrong code. RFC 2308 §5 caches a negative answer for
  the SOA `MINIMUM`, and RFC 8020 §2 lets a resolver conclude that *everything*
  beneath the name is absent too. So one `AAAA` query took the wildcard's own
  live `A` record out of service, for that resolver's whole client population,
  for the negative TTL. No attacker was required: `AAAA` accompanies every `A`
  from every dual-stack client, so ordinary traffic did it.

  The name now answers `NOERROR` with an empty answer section and the SOA in
  authority — RFC 2308 §2.2 NODATA — which is what RFC 1034 §4.3.2 step 3(c)
  has always specified: the name error is set only when the `*` label does not
  exist, and that branch was never conditioned on the query type.

- **The admin token could be written to the logs by a configuration syntax
  error.** Both TOML parsers in use render a parse failure by quoting the
  offending source line back, so a broken or duplicated `admin_token = "..."`
  line put the secret into the `/reload` response body, the startup error, and
  — with `log_format = "json"`, which the shipped Kubernetes manifest and
  Dockerfile both set — into whatever aggregates container logs. Parse errors
  now carry the line and column but never the line's text.

- **Turning rate limiting on was what made the process killable.** The limiter
  kept a `HashMap` entry per source address, created before any packet validation
  and capped by nothing. A measured 186 bytes per forged source meant 2,000,000
  spoofed sources cost 356 MiB and climbing, and a container with
  `limits.memory: 128Mi` was OOM-killed after about 723,000 sources — 7.2 seconds
  at 100,000 spoofed packets per second, which is one rented VPS. The background
  sweeper could not help: entries were not eligible for eviction for 600 seconds,
  and `HashMap::retain` never returns the allocation anyway, so 0.0% of the
  memory came back.

  The map is gone. State is now a fixed table of 262,144 eight-byte slots —
  **2 MiB, allocated once at startup, never grown, never shrunk, never pruned**,
  identical after one query and after a two-million-source flood. There is no
  per-source allocation, no lock and no sweeper task on the query path. Two
  networks whose hashes collide share a bucket, which is always stricter and
  never looser, and a per-process random seed decides which — so a collision set
  cannot be computed offline and aimed at a victim.

  Two consequences worth knowing. Under a flood spread across very many networks
  the table degrades towards a single global limit, and legitimate clients are
  denied alongside the attack: watch `dns_ratelimit_active` against
  `dns_ratelimit_slots`. And two nodes behind one anycast address disagree about
  which networks share a slot, because the seed is per process — that is
  deliberate, and it is what stops the collision set being portable.

- **`SIGTERM` did not drain.** 0.2.0 claimed below that "readiness flips to 503
  while draining" and that shutdown "drains in-flight queries". Neither was
  true: the signal cancelled the DNS listeners directly and the process exited
  about 1.3 ms later, so `/readyz` went from `200` straight to connection
  refused, in-flight TCP queries were dropped unanswered, and
  `terminationGracePeriodSeconds` was decorative. Every rolling update was a
  short resolution failure for whichever clients still had the old endpoint —
  invisible in our own metrics, because those queries never arrived.

  `SIGTERM` now marks the process unready *first*, keeps answering DNS for
  `shutdown_drain_secs` (default 15 s) while `/readyz` reports `503`, then
  closes the DNS listeners and the admin server last. `SIGINT` uses a
  zero-length window. See "Shutdown and draining" in the README.

### Changed

- **Deployment timings now derive from the drain instead of being guesses.**
  Kubernetes `terminationGracePeriodSeconds` 20 → 30, liveness
  `periodSeconds` 15 → 10 and `timeoutSeconds` 3 → 2 (so
  `10 × 3 = 30 s` still exceeds the 20 s hard deadline and the kubelet cannot
  restart a draining pod), readiness `periodSeconds` 5 → 2, `timeoutSeconds`
  3 → 1, `initialDelaySeconds` 1 → 0 so the `503` is observed well inside the
  window. systemd `TimeoutStopSec` 45 → 30 with `KillMode=mixed` and an
  explicit `SendSIGKILL=yes`. Compose gains `stop_grace_period: 30s`, because
  its 10 s default would `SIGKILL` mid-drain. The image declares
  `STOPSIGNAL SIGTERM` explicitly rather than inheriting it.
- **No `preStop` hook**, deliberately: it runs before `SIGTERM`, when `/readyz`
  is still `200`, so it cannot serve the `503` — and it stacks with the drain
  into a guaranteed `SIGKILL`.

### Added

- `shutdown_drain_secs` / `--shutdown-drain-secs` / `VEGA_SHUTDOWN_DRAIN_SECS`,
  `0..=300`, default 15.
- `deploy/check-shutdown-invariants.sh`, run by CI: the shutdown timings across
  the Kubernetes manifest, the systemd unit, the Dockerfile, Compose and the
  image smoke test are only correct relative to each other, so they are checked
  mechanically rather than remembered.
- `dns_ratelimit_slots` and `dns_ratelimit_active`, both gauges, present only
  when rate limiting is configured. `slots` is the constant table size;
  `active` counts the slots whose bucket is below full, computed while the
  scrape is being rendered rather than maintained by a task. The pair is how you
  tell a concentrated attack (total rising, `active` low) from a
  many-network flood that has collapsed the table towards one global limit
  (`active` approaching `slots`). There is deliberately no gauge for the number
  of distinct sources seen: the limiter does not retain that, which is the whole
  point, and a gauge whose name promised it while reporting something else would
  be worse than none.

## [0.2.0] - 2026-07-30

A rewrite. 0.1.0 was a demonstration of the Hickory API with four hard-coded
sub-zones; this release is a name server you can put in front of a real domain.

### Added

**A real zone.** Records come from a TOML file — A, AAAA, CNAME, TXT, MX, NS,
SRV, CAA, SOA, and anything else Hickory's zone-file parser accepts. Wildcards,
per-record TTLs, in-zone CNAME chasing, and NODATA distinguished from NXDOMAIN.

**A CLI that manages the whole thing.** `init`, `check`, `record
list|get|add|delete`, `zone show|export|bump-serial`, `query`, `status`, `reload`,
`healthcheck`, `completions`. Every command has a `--json` form and a meaningful
exit code, so scripts and agents drive it the same way a person does. Config edits
preserve comments and are written atomically.

**Live reload.** `vega reload`, or `record add --reload`, swaps the zone
behind an atomic pointer with no lock on the query path and no dropped queries. An
invalid config is refused and the previous zone keeps serving. `POST /reload`
requires the `--admin-token` bearer token, or a loopback source when no token is
configured.

**Admin endpoints.** `/healthz`, `/readyz`, `/metrics` (Prometheus text format),
`/version`. Readiness flips to 503 while draining so a load balancer can take the
instance out of rotation before the sockets close.

**Metrics.** Queries by transport, responses by rcode, a per-query latency
histogram, rate-limited and send-error counters, zone record count, uptime, and
build info.

**Per-source-IP rate limiting.** A sharded token bucket with a background janitor
that prunes idle entries, so a spoofed-source flood cannot grow the map without
bound. Off by default; `[server.rate_limit] qps = 50` turns it on.

**Graceful shutdown.** `SIGTERM` and `SIGINT` drain in-flight queries instead of
dropping them — the difference between a clean rollout and a container that gets
`SIGKILL`ed ten seconds later.

**Structured logging.** `--log-format json` for log shipping, `pretty` for a
terminal. `RUST_LOG` still wins if it is set.

**Deployment artifacts.** A distroless container that runs as uid 65532 and probes
its own `/healthz` (no curl in the image), a hardened systemd unit, Compose and
Kubernetes manifests, and an `install.sh` that verifies checksums before
installing.

**Tests.** 209 of them: unit tests beside the code, integration tests over real
UDP and TCP sockets, and end-to-end tests that run the real binary.

### Changed

- **Migrated from `trust-vega` 0.22 to `hickory-server` 0.26.** trust-dns
  was renamed and 0.22 no longer receives fixes.
- **Out-of-zone queries answer `REFUSED`** instead of an error. Claiming a name
  does not exist in a namespace we know nothing about is a lie.
- **Negative answers carry the zone SOA** in the authority section, so resolvers
  can cache them.
- **Release profile targets throughput, not size**: `opt-level = 3` instead of
  `"z"`, `codegen-units = 1`, and `panic = "abort"` so a poisoned task takes the
  process down rather than serving from a half-initialised state.
- **The binary is named `vega`**, matching the crate.

### Fixed

- **The Docker image never worked.** The Dockerfile copied
  `/code/target/release/dnsserver`, but the binary is `vega`, so every build
  failed at the `COPY` step.
- **The Docker workflow could not authenticate.** It referenced
  `secrets.ismoilovdev` and `secrets.dckr_pat_…` as if the token value were a
  secret *name*, and pushed to `xfbs/dnsserver` — a namespace belonging to someone
  else. It also triggered on `main` while the default branch was `master`, so it
  never ran.
- **A Docker Hub personal access token was committed** in
  `.github/workflows/docker.yaml`. It is in the git history and must be treated as
  compromised — [revoke it](https://hub.docker.com/settings/security).
- **`Handler::from_options` could panic at startup** on a malformed domain: four
  `Name::from_str(...).unwrap()` calls. Names are now validated when the config is
  loaded, with an error that says which value was wrong.
- **A `--domain` flag that could not be honoured.** `Options::udp` carried a
  `default_value` alongside `Vec<SocketAddr>`, so clap appended to the default
  instead of replacing it.
- **CI used archived actions.** `actions-rs/*` has been unmaintained since 2022
  and `actions/checkout@v2` runs on a Node version GitHub has removed.

### Security

- `unsafe_code = "forbid"` at the crate level.
- No dynamic UPDATE handler: `OpCode::Update` answers `NOTIMP`, so the network has
  no write path into the zone.
- CI runs `cargo audit`, `cargo deny`, CodeQL, a Trivy scan of the image, and a
  secret scan on every push, plus a weekly scheduled audit.
- Release artifacts and container images carry build provenance attestations.

## [0.1.0] - 2022-11-22

Initial version: a Hickory DNS request handler serving `hello.`, `counter.` and
`myip.` sub-zones, as a starting point for a Rust DNS server.

[Unreleased]: https://github.com/ismoilovdevml/vega/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ismoilovdevml/vega/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ismoilovdevml/vega/releases/tag/v0.1.0
