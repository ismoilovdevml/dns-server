# Contributing

Thanks for wanting to help. This is a small project; the bar is "would a careful
operator trust this in front of their zone", not ceremony.

## Getting set up

You need Rust 1.88 or newer (the crate's `rust-version`).

```bash
git clone https://github.com/ismoilovdevml/vega
cd vega
cargo test --all-features
```

That should pass on a clean checkout. If it does not, that is a bug worth
reporting on its own.

## Before you open a pull request

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

CI runs the same three, plus an MSRV check, a shellcheck pass over `install.sh`,
validation of the deployment manifests, and `cargo deny`. Running them locally is
faster than waiting for the pipeline to tell you about a formatting nit.

For anything touching the query path, also try it against a real server:

```bash
cargo run -- init --origin dev.test --output /tmp/dev.toml
cargo run -- --config /tmp/dev.toml record add www A 203.0.113.10
cargo run -- --config /tmp/dev.toml serve --udp 127.0.0.1:1053 &
cargo run -- query www.dev.test A --server 127.0.0.1:1053
```

## What we look for

**Tests that would fail without your change.** A test that passes before and
after is not testing the change. Unit tests live next to the code in a
`#[cfg(test)] mod tests`; anything involving sockets or the real binary belongs in
`tests/integration.rs` or `tests/cli.rs`.

**Comments that explain why, not what.** The code says what it does. A comment
earns its place by explaining a decision, a constraint, or a piece of DNS
behaviour that is not obvious — an RFC reference, a failure mode you are guarding
against, a trade-off you made.

**Errors an operator can act on.** `anyhow::Context` on anything that touches the
filesystem or the network. "connecting to 127.0.0.1:9100" beats "connection
refused" with no subject.

**No new `unsafe`.** The crate sets `unsafe_code = "forbid"` and that is not up
for negotiation.

**Anything user-visible stays scriptable.** A new subcommand needs a `--json`
form and a sensible exit code, because agents and CI drive this as much as people
do.

## Project layout

| Path | |
|---|---|
| `src/config.rs` | CLI flags and the TOML file, merged and validated |
| `src/zone.rs` | the record store and lookup algorithm |
| `src/handler.rs` | the `RequestHandler` — validation, built-ins, responses |
| `src/ratelimit.rs` | per-source-IP token bucket |
| `src/metrics.rs` | counters and the Prometheus exporter |
| `src/admin.rs` | `/healthz`, `/readyz`, `/metrics`, `/reload` |
| `src/commands/` | one module per group of subcommands |
| `src/editor.rs` | format-preserving config edits |
| `src/dnsclient.rs` | the small `dig` behind `query` |
| `src/ui.rs` | colour, tables, formatting |
| `tests/` | integration tests over real sockets and the real binary |
| `deploy/` | Compose, systemd and Kubernetes manifests |

## Commits and pull requests

Write commit subjects in the imperative: "add SRV record support", not "added" or
"adds". Explain the *why* in the body if it is not obvious from the diff.

Keep pull requests to one change. A refactor and a bugfix in the same PR means
the reviewer cannot tell which line fixed the bug.

## Reporting bugs

Use the [issue templates](https://github.com/ismoilovdevml/vega/issues/new/choose).
The two most useful things you can include are:

```bash
vega check --json
vega query the.name.that.misbehaved A --json
```

Please report security issues [privately](SECURITY.md), not as a public issue.

## Adding a record type

Most types already work — record values are parsed with Hickory's zone-file
parser, so anything it understands is accepted. If a type needs special handling
in lookup (the way `CNAME` does), the places to touch are:

1. `Zone::resolve` in `src/zone.rs`, for the lookup behaviour;
2. a test in the same file covering the new behaviour and its negative case;
3. an integration test in `tests/integration.rs` proving it survives the wire;
4. a line in `vega.example.toml` showing the syntax.

## Releasing

Maintainers only:

1. bump `version` in `Cargo.toml`;
2. add a `CHANGELOG.md` entry;
3. `git tag -a v0.3.0 -m "v0.3.0" && git push --tags`.

The release workflow refuses to publish if the tag and `Cargo.toml` disagree, or
if the tests do not pass. It then cross-compiles the binaries, publishes
checksums, and attaches build provenance.
