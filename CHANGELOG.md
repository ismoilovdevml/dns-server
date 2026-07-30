# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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
