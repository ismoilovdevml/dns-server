# Security policy

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately through
[GitHub Security Advisories](https://github.com/ismoilovdevml/dns-server/security/advisories/new),
or by email to <ismoilovdev@gmail.com>.

Useful details, if you have them: the version, a configuration that reproduces it,
and the query or request that triggers it. A packet capture or a `dns-server query
… --json` output is ideal.

You can expect an acknowledgement within a few days and a fix or a plan within two
weeks for anything remotely exploitable. Once a fix is released, credit goes to
you in the advisory unless you would rather stay anonymous.

## Supported versions

The latest release gets security fixes. This is a small project with no long-term
support branches — upgrading is the fix.

| Version | Supported |
|---|---|
| 0.2.x | yes |
| 0.1.x | no (different codebase; upgrade) |

## What is in scope

- Remote crashes, hangs, or unbounded memory growth triggered by a DNS query.
- Answering authoritatively for a name outside the configured zone.
- Bypassing the per-source-IP rate limiter.
- Reaching `POST /reload` without the configured token from a non-loopback address.
- Reading or writing files outside the configured config path.
- Amplification behaviour beyond what plain authoritative DNS implies.

## What is not in scope

These are documented behaviours, not vulnerabilities:

- **The admin endpoints are unauthenticated for reads.** `/healthz`, `/readyz`,
  `/metrics` and `/version` are meant for a private interface. Exposing them
  publicly is a deployment choice, and the metrics they leak (query counts,
  uptime, record count) are why the docs say to keep them internal.
- **The diagnostic sub-zones report server state.** `version.<zone>` publishes the
  build, `counter.<zone>` the query total, `myip.<zone>` the caller's address.
  Disable them with `--no-builtins` if that matters to you.
- **UDP source addresses can be spoofed.** That is DNS over UDP. The per-source
  rate limiter reduces the amplification factor but cannot authenticate a source.
  Use response rate limiting at the network edge if you need more.
- **No DNSSEC.** Answers are unsigned, so an on-path attacker can forge them.
  Documented under "Not implemented" in the README.
- **Running as root.** The container, the systemd unit, and the Kubernetes
  manifests all run unprivileged with `CAP_NET_BIND_SERVICE` only. Choosing to run
  it as root is not a bug in the software.

## Hardening a deployment

The shipped manifests already do these; if you write your own, they are the parts
worth copying:

- Bind the admin listener to loopback or a private interface, never `0.0.0.0` on a
  public host.
- Set `--admin-token` if `/reload` needs to be reachable from another host.
- Enable the rate limiter (`[server.rate_limit] qps = 50`). It is off by default
  because the right value depends on your traffic, not because off is safer.
- Run as a non-root user with `CAP_NET_BIND_SERVICE` as the entire capability set.
- Keep the config file read-only to the service user; the server never writes it,
  only the CLI does.
- Scrape `dns_responses_total{rcode="refused"}` and `dns_rate_limited_total`.
  A spike in either is usually the first sign of abuse.

## How this project reduces its own attack surface

- `unsafe_code = "forbid"` at the crate level — no unsafe blocks anywhere.
- No dynamic UPDATE handler: `OpCode::Update` answers `NOTIMP`, so there is no
  write path from the network.
- No recursion or forwarding, so the server cannot be used as an open resolver.
- Out-of-zone queries are `REFUSED` before any lookup happens.
- The container image is distroless: no shell, no package manager, uid 65532.
- CI runs `cargo audit`, `cargo deny`, CodeQL, Trivy against the image, and a
  secret scan on every push, plus a weekly scheduled audit so new advisories
  against unchanged code still get caught.
- Dependabot keeps the dependency tree current, with `hickory-*` updates arriving
  as their own reviewable pull requests.
