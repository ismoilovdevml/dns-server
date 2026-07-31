#!/bin/sh
# Prove the systemd unit-file guard can actually fail.
#
#   ./deploy/prove-unit-guard-fails.sh [REPO_ROOT]
#
# VEGA-007 shipped `ExecStartPre=... --check` — a flag that does not exist, on a
# Type=simple unit, so ExecStart never ran and nobody who followed the README got
# a working service. It shipped green: no job, no test and no script read the
# unit file, so reverting the fix would still be green today.
#
# The guard that now reads it is `systemd_unit_*` in tests/cli.rs. A guard nobody
# has watched fail is decoration — that is how VEGA-007 shipped in the first
# place — so this reintroduces that exact bug in a scratch copy of the unit,
# points the guard at it with VEGA_UNIT_FILE, and requires the guard to reject
# it. The unit we ship is never modified.
#
# POSIX sh, like check-shutdown-invariants.sh next to it: this runs in CI, on a
# laptop and on a jump box, and a correctness gate should not need a toolchain
# of its own.

set -eu

ROOT="${1:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)}"
UNIT="$ROOT/deploy/systemd/vega.service"

# Matches the guards that read the real file; the `systemd_exec_parser_*` tests
# use inline fixtures and would pass either way.
FILTER=systemd_unit

[ -f "$UNIT" ] || { printf 'error: no such file: %s\n' "$UNIT" >&2; exit 2; }

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT INT TERM

# --- 1. the guard passes on the unit we ship ---------------------------------
#
# And it has to have actually run something: a filter that matches nothing exits
# 0 as well, which would make step 2 prove nothing at all.

printf '==> the guard accepts the shipped unit\n'
if ! (cd "$ROOT" && cargo test --locked --quiet --test cli -- "$FILTER") \
        >"$scratch/pass.log" 2>&1; then
    cat "$scratch/pass.log" >&2
    printf 'error: the guard rejects the unit we ship. Fix the unit, not this script.\n' >&2
    exit 1
fi
if ! grep -qE 'test result: ok\. [1-9][0-9]* passed' "$scratch/pass.log"; then
    cat "$scratch/pass.log" >&2
    printf 'error: no test matching "%s" ran, so nothing guards the unit file.\n' "$FILTER" >&2
    exit 1
fi
grep -m1 'test result:' "$scratch/pass.log"

# --- 2. the guard rejects VEGA-007, reintroduced verbatim --------------------

printf '\n==> the guard rejects VEGA-007 put back\n'
sed 's| check --config | --check --config |' "$UNIT" >"$scratch/vega.service"
if cmp -s "$UNIT" "$scratch/vega.service"; then
    printf 'error: the mutation changed nothing, so nothing was proved.\n' >&2
    printf '       ExecStartPre no longer matches "vega check --config ...";\n' >&2
    printf '       break whatever it looks like now, or this file is a no-op.\n' >&2
    exit 2
fi
grep -m1 '^ExecStartPre=' "$scratch/vega.service"

if (cd "$ROOT" && VEGA_UNIT_FILE="$scratch/vega.service" \
        cargo test --locked --quiet --test cli -- "$FILTER") \
        >"$scratch/fail.log" 2>&1; then
    cat "$scratch/fail.log" >&2
    printf 'error: the guard accepted a unit whose ExecStartPre cannot run.\n' >&2
    printf '       That is VEGA-007 verbatim: with Type=simple the service never\n' >&2
    printf '       starts, and it would ship green a second time.\n' >&2
    exit 1
fi
grep -m1 'test result:' "$scratch/fail.log" || true

printf '\nthe unit-file guard fails on a broken unit, as it must.\n'
