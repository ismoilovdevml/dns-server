<div align="center">

# dns-server

**An authoritative DNS server written in Rust, driven entirely from the command line.**

[![CI](https://github.com/ismoilovdevml/dns-server/actions/workflows/ci.yml/badge.svg)](https://github.com/ismoilovdevml/dns-server/actions/workflows/ci.yml)
[![Security](https://github.com/ismoilovdevml/dns-server/actions/workflows/security.yml/badge.svg)](https://github.com/ismoilovdevml/dns-server/actions/workflows/security.yml)
[![Docker](https://github.com/ismoilovdevml/dns-server/actions/workflows/docker.yml/badge.svg)](https://github.com/ismoilovdevml/dns-server/actions/workflows/docker.yml)
[![Release](https://img.shields.io/github/v/release/ismoilovdevml/dns-server?logo=github&color=blue)](https://github.com/ismoilovdevml/dns-server/releases/latest)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange?logo=rust)](https://www.rust-lang.org)
[![Hickory DNS](https://img.shields.io/badge/hickory--dns-0.26-6e5494)](https://hickory-dns.org)
[![Container](https://img.shields.io/badge/ghcr.io-dns--server-2496ED?logo=docker&logoColor=white)](https://github.com/ismoilovdevml/dns-server/pkgs/container/dns-server)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)

</div>

<img src="assets/cli-records.png" alt="Creating a zone and adding records from the command line" width="880">

---

## What this is

A single-zone authoritative name server. You describe a zone in one TOML file —
or build it up with `dns-server record add` — and it answers queries for that
zone over UDP and TCP. It is deliberately **not** a resolver: it never recurses,
never caches, and refuses anything outside its own zone.

It is built around one idea: **everything you need to run it is a subcommand.**
Create the config, add records, validate them, reload a live server, query it,
read its metrics — no editor, no `dig`, no `curl` required. Every command also
speaks `--json`, so scripts and agents drive it the same way you do.

```bash
dns-server init --origin example.com
dns-server record add www A 203.0.113.10 --bump-serial --reload
dns-server query www.example.com A
```

| | |
|---|---|
| **Records** | A, AAAA, CNAME, TXT, MX, NS, SRV, CAA, SOA and anything else Hickory parses, in zone-file syntax |
| **DNS correctness** | authoritative answers, wildcards, in-zone CNAME chasing, NODATA vs NXDOMAIN, SOA in the authority section, EDNS(0), TCP fallback |
| **Operations** | live zone reload with no dropped queries, graceful `SIGTERM` drain, `/healthz` `/readyz` `/metrics` `/version` |
| **Protection** | per-source-IP token bucket, `REFUSED` for out-of-zone queries, no dynamic UPDATE surface |
| **Observability** | Prometheus metrics, structured JSON logs, per-query latency histogram |
| **Deployment** | static musl binaries, distroless container, systemd unit, Compose and Kubernetes manifests |
| **Safety** | `unsafe_code = "forbid"`, clippy pedantic clean, 209 tests |

---

## Install

### One line

```bash
curl -fsSL https://raw.githubusercontent.com/ismoilovdevml/dns-server/main/install.sh | sh
```

Downloads the release binary for your platform, verifies its SHA-256 against the
published `SHA256SUMS`, and installs it to `/usr/local/bin`.

Add `--systemd` to also create the service user, a starter config in
`/etc/dns-server/`, and a hardened systemd unit — left **stopped** so you can
review the zone first:

```bash
curl -fsSL https://raw.githubusercontent.com/ismoilovdevml/dns-server/main/install.sh | sh -s -- --systemd
```

<details>
<summary>Other options</summary>

**Docker**

```bash
docker pull ghcr.io/ismoilovdevml/dns-server:latest
```

**From source** (needs Rust 1.88+)

```bash
cargo install --git https://github.com/ismoilovdevml/dns-server --locked
```

**Release archive**

Pick your platform from [releases](https://github.com/ismoilovdevml/dns-server/releases/latest),
then verify before you trust it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf dns-server-v0.2.0-x86_64-unknown-linux-musl.tar.gz
```

**Shell completions**

```bash
dns-server completions bash | sudo tee /etc/bash_completion.d/dns-server
dns-server completions zsh  > ~/.zfunc/_dns-server
dns-server completions fish > ~/.config/fish/completions/dns-server.fish
```

</details>

---

## Quickstart

```bash
# 1. A config file, with a sensible SOA already filled in.
dns-server init --origin example.com

# 2. Records. Values use zone-file syntax, so MX looks like MX.
dns-server record add @   A     203.0.113.10 203.0.113.11
dns-server record add www CNAME example.com.
dns-server record add @   MX    "10 mail.example.com."
dns-server record add @   TXT   '"v=spf1 mx -all"'
dns-server record add '*.apps' A 203.0.113.30    # wildcard
dns-server record add api A 203.0.113.20 --ttl 30

# 3. Check before you serve. Exits non-zero if anything is wrong.
dns-server check

# 4. Serve. Port 53 needs privileges; use 1053 to try it out.
dns-server serve --udp 127.0.0.1:1053 --tcp 127.0.0.1:1053

# 5. In another shell:
dns-server query www.example.com A --server 127.0.0.1:1053
```

`query` prints what `dig` would, plus the timing and the wire size — and it tells
you *why* an empty answer is empty, which is usually the thing you are actually
trying to find out:

<img src="assets/cli-query.png" alt="Querying a live server: a CNAME chase, a wildcard match, and an NXDOMAIN with its SOA" width="860">

---

## The CLI

With no subcommand it serves. Every other subcommand manages or inspects.
`--json` works on all of them, and a command that changed nothing says
`unchanged` and still exits 0.

```text
dns-server                      run the server (same as `serve`)
dns-server init                 write a starter config
dns-server check                validate config + zone, print what would be served
dns-server serve                run the server

dns-server record list          list record sets  [--name N] [--type T]
dns-server record get NAME      show one name's records (exit 1 if absent)
dns-server record add NAME TYPE VALUE...   [--ttl] [--replace] [--bump-serial] [--reload]
dns-server record delete NAME [TYPE]       [--value V] [--bump-serial] [--reload]

dns-server zone show            origin, SOA serial, counts by type
dns-server zone export          BIND zone-file format, for diffing
dns-server zone bump-serial     set the serial to YYYYMMDDnn

dns-server query NAME [TYPE]    send a query  [--server ADDR] [--use-tcp]
dns-server status               health, version, uptime, traffic breakdown
dns-server reload               make a running server re-read its config
dns-server healthcheck          probe /healthz, exit 0 or 1

dns-server completions SHELL    bash | zsh | fish | powershell | elvish
```

`check` resolves the whole configuration, builds the zone, and tells you what
would be served — including the things that are easy to get wrong, like a missing
SOA or an admin listener on a public interface:

<img src="assets/cli-check.png" alt="dns-server check reporting the zone, listeners and protection settings" width="820">

### Config discovery

Without `--config`, these are tried in order:

1. `./dns-server.toml`
2. `/etc/dns-server/dns-server.toml`
3. `/usr/local/etc/dns-server/dns-server.toml`

<img src="assets/cli-zone.png" alt="dns-server zone show summarising the zone and its record types" width="760">

### Scripting and agents

Every command has a machine-readable form and a meaningful exit code, so there is
nothing to scrape:

```bash
# Is this record already there?
if dns-server record get www A --json >/dev/null; then
  echo "already configured"
fi

# What is live right now?
dns-server status --json | jq '.metrics["dns_queries_total"]'

# Idempotent apply: safe to run on every deploy.
dns-server record add www A "$NEW_IP" --replace --bump-serial --reload --json

# Did the query actually answer?
dns-server query www.example.com A --json | jq -r '.rcode'
```

Output honours [`NO_COLOR`](https://no-color.org), drops colour when stdout is
not a terminal, and never colours `--json`. Add `-v` for full detail: raw
counters in `status`, the additional section in `query`.

---

## Live reload

Editing records does not need a restart. The zone sits behind an atomic pointer,
so a reload swaps it with no lock on the query path and no dropped queries —
requests already in flight finish against the old zone.

<img src="assets/cli-reload.png" alt="Adding a record with --reload, then querying it on the live server" width="880">

If the edited config is invalid, **the reload is refused and the old zone keeps
serving** — a typo cannot take the server down.

Listener addresses and the rate limiter are not hot-swappable; changing those
needs a restart, and the server logs a warning if they drift.

`POST /reload` is gated, because it mutates state:

- **no `--admin-token`** → loopback callers only;
- **`--admin-token` set** → that bearer token is required, from anywhere.

---

## Configuration

Precedence: **CLI flag → environment variable → config file → default.**

<details>
<summary>Full example config</summary>

See [`dns-server.example.toml`](dns-server.example.toml) for the annotated
version. The short form:

```toml
[server]
udp = ["0.0.0.0:53", "[::]:53"]
tcp = ["0.0.0.0:53", "[::]:53"]
admin_listen = "127.0.0.1:9100"    # unauthenticated — keep it private
tcp_timeout_secs = 10
log_format = "json"                # or "pretty"
log_level = "info"

[server.rate_limit]
qps = 50                           # per source IP; 0 disables
burst = 100                        # defaults to 2 * qps

[zone]
origin = "example.com"
default_ttl = 300
builtins = true                    # the diagnostic sub-zones, below

[zone.soa]
mname = "ns1.example.com."
rname = "hostmaster.example.com."
serial = 2026073001
minimum = 60                       # negative-cache TTL

[[zone.records]]
name = "@"                         # "@" = apex, "*.sub" = wildcard
type = "A"
ttl = 60                           # optional
values = ["203.0.113.10", "203.0.113.11"]
```

</details>

<details>
<summary>Flags and environment variables</summary>

| Flag | Environment | Meaning |
|---|---|---|
| `--config PATH` | `DNS_CONFIG` | config file |
| `--udp ADDR` | `DNS_UDP` | UDP listener; repeatable |
| `--tcp ADDR` | `DNS_TCP` | TCP listener; repeatable |
| `--admin-listen ADDR` | `DNS_ADMIN_LISTEN` | admin HTTP address |
| `--admin-token TOKEN` | `DNS_ADMIN_TOKEN` | bearer token for `/reload` |
| `--domain ZONE` | `DNS_DOMAIN` | zone origin |
| `--rate-limit-qps N` | `DNS_RATE_LIMIT_QPS` | per-IP queries per second; `0` disables |
| `--rate-limit-burst N` | `DNS_RATE_LIMIT_BURST` | bucket size |
| `--tcp-timeout-secs N` | `DNS_TCP_TIMEOUT_SECS` | TCP idle timeout |
| `--no-builtins` | `DNS_NO_BUILTINS` | disable the diagnostic sub-zones |
| `--log-format FMT` | `DNS_LOG_FORMAT` | `pretty` or `json` |
| `--log-level FILTER` | `DNS_LOG_LEVEL` | `RUST_LOG` syntax |
| `--json` | — | machine-readable output |
| `--verbose`, `-v` | — | extra detail |

`RUST_LOG` overrides `--log-level` if both are set.

</details>

### Diagnostic sub-zones

Enabled by default; a fast way to prove a deployment works end to end. Turn them
off with `--no-builtins` if you would rather not expose server internals.

```bash
dns-server query version.example.com TXT           # "dns-server 0.2.0"
dns-server query counter.example.com TXT           # queries served so far
dns-server query myip.example.com A                # the client's own address
dns-server query anything.hello.example.com TXT    # "hello, anything"
```

---

## Running it in production

### Docker

```bash
docker run -d --name dns-server \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --read-only --security-opt no-new-privileges:true \
  -p 53:53/udp -p 53:53/tcp \
  -p 127.0.0.1:9100:9100 \
  -v "$PWD/dns-server.toml:/etc/dns-server/dns-server.toml:ro" \
  ghcr.io/ismoilovdevml/dns-server:latest \
  --config=/etc/dns-server/dns-server.toml
```

The image is [distroless](https://github.com/GoogleContainerTools/distroless):
no shell, no package manager, runs as uid 65532. Binding `:53` as a non-root user
needs exactly `NET_BIND_SERVICE` and nothing else. `HEALTHCHECK` works because
the binary probes its own `/healthz` — no curl in the image.

Or use [`deploy/docker-compose.yml`](deploy/docker-compose.yml):

```bash
cp dns-server.example.toml deploy/dns-server.toml    # then edit it
docker compose -f deploy/docker-compose.yml up -d
```

### systemd

```bash
curl -fsSL https://raw.githubusercontent.com/ismoilovdevml/dns-server/main/install.sh | sh -s -- --systemd
sudo $EDITOR /etc/dns-server/dns-server.toml
sudo dns-server check --config /etc/dns-server/dns-server.toml
sudo systemctl enable --now dns-server
journalctl -u dns-server -f
```

The [unit](deploy/systemd/dns-server.service) runs as a dedicated user with
`CAP_NET_BIND_SERVICE` as its entire capability set, `ProtectSystem=strict`, a
seccomp filter, and `MemoryDenyWriteExecute=yes`. `ExecStartPre` validates the
config, so a typo fails the start instead of half-starting.

> **`Address already in use` on :53?** `systemd-resolved` usually owns it.
> `sudo systemctl disable --now systemd-resolved`, or listen on another port.

### Kubernetes

```bash
kubectl apply -f deploy/kubernetes/dns-server.yaml
```

Two replicas, `readOnlyRootFilesystem`, all capabilities dropped, `httpGet`
probes against the admin port, a `PodDisruptionBudget`, and
`externalTrafficPolicy: Local` so the client IP survives — without it `myip.` and
the per-source rate limiter both see the node instead of the caller.

### Metrics

`GET /metrics` on the admin port, in Prometheus text format:

| Metric | Type | |
|---|---|---|
| `dns_queries_total` | counter | queries received |
| `dns_queries_by_transport_total{transport}` | counter | `udp`, `tcp`, `other` |
| `dns_responses_total{rcode}` | counter | `noerror`, `nxdomain`, `refused`, … |
| `dns_query_duration_seconds` | histogram | per-query latency |
| `dns_rate_limited_total` | counter | queries the limiter dropped |
| `dns_send_errors_total` | counter | failures writing a response |
| `dns_zone_records` | gauge | records currently loaded |
| `dns_uptime_seconds` | gauge | since start |
| `dns_build_info{version}` | gauge | always 1 |

The pod annotations in the Kubernetes manifest already mark it for scraping. If
you just want a look, `status` renders the same data:

<img src="assets/cli-status.png" alt="dns-server status showing health, uptime, query rate and a response-code breakdown" width="800">

---

## How it works

<img src="assets/architecture.png" alt="Architecture: the query path from listeners through the rate limiter and handler to the zone, and the control plane from the CLI through the config file and admin API back into a zone swap" width="1180">

The zone is the only thing shared between the two halves, and it is swapped
atomically — a reload never blocks a query, and a query never sees a half-applied
zone.


| Module | |
|---|---|
| [`config`](src/config.rs) | CLI + TOML, merged and validated at startup |
| [`zone`](src/zone.rs) | record store, wildcards, CNAME chasing, NODATA vs NXDOMAIN |
| [`handler`](src/handler.rs) | `RequestHandler`: validation, built-ins, response assembly |
| [`ratelimit`](src/ratelimit.rs) | sharded token bucket with a background janitor |
| [`metrics`](src/metrics.rs) | atomic counters, Prometheus exporter |
| [`admin`](src/admin.rs) | health, readiness, metrics, gated reload |
| [`commands`](src/commands/) | what each subcommand does |
| [`editor`](src/editor.rs) | format-preserving, atomic config edits |
| [`dnsclient`](src/dnsclient.rs) | the small `dig` behind `query` |
| [`ui`](src/ui.rs) | colour, tables, formatting |

A few decisions worth knowing about:

- **Out-of-zone queries get `REFUSED`, not `NXDOMAIN`.** We know nothing about
  other namespaces, and saying a name does not exist there would be a lie.
- **Negative answers carry the SOA.** Without it resolvers cannot cache an
  NXDOMAIN and will re-ask forever.
- **Config edits are atomic and comment-preserving.** `record add` writes to a
  temp file in the same directory, fsyncs, and renames — a crash mid-write cannot
  truncate a live zone, and your comments survive.
- **`panic = "abort"` in release.** A poisoned task should take the process down
  and let the supervisor restart it, not keep serving from a half-initialised
  state.

---

## Development

```bash
cargo test --all-features                                    # 209 tests
cargo clippy --all-targets --all-features -- -D warnings     # pedantic, clean
cargo fmt --all --check
cargo deny check                                             # licences + advisories
cargo run -- --config dns-server.example.toml check
```

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security
issues should go through
[a private advisory](https://github.com/ismoilovdevml/dns-server/security/advisories/new),
not a public issue; see [SECURITY.md](SECURITY.md).

## Not implemented

Being explicit about the edges, so nothing surprises you in production:

- **DNSSEC signing.** Hickory supports it; this server does not expose it yet.
- **Recursion or forwarding.** By design. Point a resolver at this for its own
  zone only.
- **Zone transfers (AXFR/IXFR) and `NOTIFY`.** Secondaries cannot pull from this
  server; ship the config file instead.
- **Dynamic UPDATE.** `OpCode::Update` answers `NOTIMP`. Records change through
  the CLI, which is auditable.
- **Multiple zones per process.** One origin per instance; run more than one.
- **DoT / DoH / DoQ.** Plain DNS over UDP and TCP only.

## Built with

[hickory-dns](https://hickory-dns.org) · [tokio](https://tokio.rs) ·
[clap](https://docs.rs/clap) · [axum](https://docs.rs/axum) ·
[toml_edit](https://docs.rs/toml_edit) · [arc-swap](https://docs.rs/arc-swap) ·
[tracing](https://docs.rs/tracing)

## License

[MIT](LICENSE) © [Otabek Ismoilov](https://github.com/ismoilovdevml)
