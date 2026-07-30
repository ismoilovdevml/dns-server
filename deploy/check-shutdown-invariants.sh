#!/bin/sh
# Mechanically enforce the shutdown-drain deployment invariants.
#
#   ./deploy/check-shutdown-invariants.sh [REPO_ROOT]
#
# It exists because these numbers are only correct in relation to each other.
# Anyone can raise `shutdown_drain_secs` to 60 in the ConfigMap, or drop
# `livenessProbe.periodSeconds` to 5 to "make the probe more responsive", and
# both changes silently reintroduce the outage the drain fixed: the kubelet
# SIGKILLs or restarts the pod part way through a drain, so queries are dropped
# by the very shutdown that was supposed to stop dropping them. A value that is
# only right because someone remembered it will regress.
#
# The derivation being enforced (see "Shutdown and draining" in the README),
# all in seconds:
#
#   W  = shutdown_drain_secs   drain window, read from the shipped ConfigMap
#   Q  = 1                     quiesce cap        (constant)
#   S  = 5                     stop budget        (constant)
#   D  = W + S                 hard deadline
#   Wd = D + 2                 watchdog thread, the guaranteed death
#
# POSIX sh and awk only: this runs in CI, on a laptop, and on a jump box, and
# adding a YAML parser dependency to a correctness gate defeats the point.

set -eu

ROOT="${1:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)}"

K8S="$ROOT/deploy/kubernetes/vega.yaml"
UNIT="$ROOT/deploy/systemd/vega.service"
COMPOSE="$ROOT/deploy/docker-compose.yml"
DOCKERFILE="$ROOT/Dockerfile"
DOCKER_CI="$ROOT/.github/workflows/docker.yml"
EXAMPLE="$ROOT/vega.example.toml"

# Constants of the shutdown state machine, compiled into the binary and not
# configurable. Only `shutdown_drain_secs` is an operator knob.
QUIESCE_CAP=1
STOP_BUDGET=5
WATCHDOG_SLACK=2

failures=0
checks=0

pass() { checks=$((checks + 1)); printf '  ok    %s\n' "$1"; }
fail() {
    checks=$((checks + 1))
    failures=$((failures + 1))
    printf '  FAIL  %s\n' "$1" >&2
}

# assert_num LABEL ACTUAL OP EXPECTED   (op: eq gt ge lt le)
assert_num() {
    _ok=0
    case "$3" in
        eq) if [ "$2" -eq "$4" ]; then _ok=1; fi ;;
        gt) if [ "$2" -gt "$4" ]; then _ok=1; fi ;;
        ge) if [ "$2" -ge "$4" ]; then _ok=1; fi ;;
        lt) if [ "$2" -lt "$4" ]; then _ok=1; fi ;;
        le) if [ "$2" -le "$4" ]; then _ok=1; fi ;;
        *) printf 'internal error: unknown operator %s\n' "$3" >&2; exit 2 ;;
    esac
    if [ "$_ok" = 1 ]; then
        pass "$1 ($2 $3 $4)"
    else
        fail "$1: got $2, need $2 $3 $4"
    fi
}

need_file() {
    [ -f "$1" ] || { printf 'error: no such file: %s\n' "$1" >&2; exit 2; }
}

# Extract `key: value` from a YAML file, requiring exactly one occurrence. A
# missing key and a duplicated key are both failures: silently checking nothing
# is how a gate becomes decorative.
yaml_scalar() {
    # $1 file, $2 key
    _n=$(grep -c "^[[:space:]]*$2:[[:space:]]" "$1" || true)
    if [ "$_n" != 1 ]; then
        printf 'error: expected exactly one "%s:" in %s, found %s\n' "$2" "$1" "$_n" >&2
        exit 2
    fi
    grep -m1 "^[[:space:]]*$2:[[:space:]]" "$1" | sed -e 's/.*:[[:space:]]*//' -e 's/[[:space:]]*#.*//' -e 's/[[:space:]]*$//'
}

# Extract one field of one probe block out of the pod spec. Indentation-aware:
# the block ends at the first line indented no further than the probe key.
probe_field() {
    # $1 file, $2 probe (liveness|readiness|startup), $3 field
    awk -v want="$2" -v field="$3" '
        function indent(s,   i) { i = match(s, /[^ ]/); return i ? i : 9999 }
        /^[[:space:]]*(liveness|readiness|startup)Probe:[[:space:]]*$/ {
            split($0, a, "Probe"); sub(/^[[:space:]]*/, "", a[1])
            probe = a[1]; ind = indent($0); next
        }
        probe != "" {
            if (indent($0) <= ind) { probe = ""; next }
            if (probe == want) {
                k = $1; sub(/:$/, "", k)
                if (k == field) { v = $2; sub(/#.*/, "", v); print v; exit }
            }
        }
    ' "$1"
}

# Extract `key = value` from the TOML embedded in the ConfigMap.
toml_scalar() {
    # $1 file, $2 key
    grep -m1 "^[[:space:]]*$2[[:space:]]*=" "$1" | sed -e 's/.*=[[:space:]]*//' -e 's/[[:space:]]*#.*//' -e 's/[[:space:]]*$//'
}

is_uint() {
    case "$1" in
        '' | *[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

need_file "$K8S"
need_file "$UNIT"
need_file "$COMPOSE"
need_file "$DOCKERFILE"
need_file "$DOCKER_CI"
need_file "$EXAMPLE"

# --------------------------------------------------------------- derivation --

W=$(toml_scalar "$K8S" shutdown_drain_secs)
if ! is_uint "$W"; then
    printf 'error: shutdown_drain_secs not found (or not an integer) in %s\n' "$K8S" >&2
    printf '       the shipped ConfigMap must state the drain window explicitly;\n' >&2
    printf '       every other number here is derived from it.\n' >&2
    exit 2
fi

D=$((W + STOP_BUDGET))
WD=$((D + WATCHDOG_SLACK))
FLOOR=$((W + STOP_BUDGET + WATCHDOG_SLACK)) # the grace period every supervisor must beat

printf 'vega shutdown invariants\n'
printf '  drain W=%ss  quiesce Q=%ss  stop S=%ss  deadline D=%ss  watchdog Wd=%ss\n\n' \
    "$W" "$QUIESCE_CAP" "$STOP_BUDGET" "$D" "$WD"

# ---------------------------------------------------------------- the drain --

printf 'drain window\n'
assert_num "shutdown_drain_secs within the configured range 0..=300" "$W" le 300
assert_num "shutdown_drain_secs is the designed default" "$W" eq 15

# The example config is what an operator copies to /etc/vega/vega.toml, and it
# is shipped inside the release tarball. If it disagrees with the manifest, half
# our deployments drain for a different length of time than the other half.
ex=$(toml_scalar "$EXAMPLE" shutdown_drain_secs)
if is_uint "$ex"; then
    assert_num "vega.example.toml drain matches the manifest" "$ex" eq "$W"
else
    fail "vega.example.toml does not state shutdown_drain_secs"
fi

# ------------------------------------------------------------------ k8s ------

printf '\nkubernetes: %s\n' "${K8S#"$ROOT"/}"

grace=$(yaml_scalar "$K8S" terminationGracePeriodSeconds)
is_uint "$grace" || { printf 'error: terminationGracePeriodSeconds is not an integer\n' >&2; exit 2; }

# THE invariant. Liveness must not be able to conclude "dead" before the
# process has had its full deadline to leave. Otherwise the kubelet restarts
# the container mid-drain and we drop exactly the queries the drain protects.
lp=$(probe_field "$K8S" liveness periodSeconds)
lf=$(probe_field "$K8S" liveness failureThreshold)
lt=$(probe_field "$K8S" liveness timeoutSeconds)
if ! is_uint "$lp" || ! is_uint "$lf" || ! is_uint "$lt"; then
    printf 'error: livenessProbe period/threshold/timeout missing from %s\n' "$K8S" >&2
    exit 2
fi
assert_num "livenessProbe periodSeconds x failureThreshold exceeds the hard deadline" \
    "$((lp * lf))" gt "$D"
assert_num "livenessProbe periodSeconds is the designed value" "$lp" eq 10
assert_num "livenessProbe failureThreshold is the designed value" "$lf" eq 3
assert_num "livenessProbe timeoutSeconds is the designed value" "$lt" eq 2

# The second half of the scenario in features/shutdown.feature: the grace
# period must cover drain + stop budget + watchdog, or the kubelet SIGKILLs a
# process that was already on its way out.
assert_num "terminationGracePeriodSeconds exceeds drain + 7" "$grace" gt "$FLOOR"
assert_num "terminationGracePeriodSeconds is the designed value" "$grace" eq 30

# Readiness has to be *observed* inside the drain, twice, or the 503 the drain
# exists to serve never reaches the endpoint controller before we stop.
rp=$(probe_field "$K8S" readiness periodSeconds)
rf=$(probe_field "$K8S" readiness failureThreshold)
rt=$(probe_field "$K8S" readiness timeoutSeconds)
rd=$(probe_field "$K8S" readiness initialDelaySeconds)
if ! is_uint "$rp" || ! is_uint "$rf" || ! is_uint "$rt" || ! is_uint "$rd"; then
    printf 'error: readinessProbe period/threshold/timeout/initialDelay missing from %s\n' "$K8S" >&2
    exit 2
fi
assert_num "readinessProbe observation window fits inside the drain" \
    "$((rp * rf + rt))" lt "$W"
assert_num "readinessProbe periodSeconds is the designed value" "$rp" eq 2
assert_num "readinessProbe failureThreshold is the designed value" "$rf" eq 2
assert_num "readinessProbe timeoutSeconds is the designed value" "$rt" eq 1
assert_num "readinessProbe initialDelaySeconds is the designed value" "$rd" eq 0

# Liveness must probe /healthz, readiness /readyz. Pointing liveness at /readyz
# is the classic mistake: a draining pod answers 503 there and gets restarted
# in the middle of the drain, which is the outage the drain was meant to end.
for pair in liveness:/healthz startup:/healthz readiness:/readyz; do
    probe=${pair%%:*}
    want=${pair#*:}
    got=$(probe_field "$K8S" "$probe" path)
    if [ "$got" = "$want" ]; then
        pass "${probe}Probe path is $want"
    else
        fail "${probe}Probe path: got '${got:-<none>}', need '$want'"
    fi
done

# No preStop hook — rejected deliberately, see below.
if grep -qE '^[[:space:]]*(lifecycle|preStop):' "$K8S"; then
    fail "preStop/lifecycle hook present: the drain is in-process, and a preStop sleep runs before SIGTERM so it cannot serve the 503"
else
    pass "no preStop hook"
fi

# --------------------------------------------------------------- systemd -----

printf '\nsystemd: %s\n' "${UNIT#"$ROOT"/}"

ini() { grep -m1 "^$2=" "$1" | sed -e 's/^[^=]*=//' -e 's/[[:space:]]*$//'; }

tss=$(ini "$UNIT" TimeoutStopSec)
is_uint "$tss" || { printf 'error: TimeoutStopSec missing or not a bare integer\n' >&2; exit 2; }
assert_num "TimeoutStopSec exceeds drain + 7" "$tss" gt "$FLOOR"
assert_num "TimeoutStopSec matches terminationGracePeriodSeconds" "$tss" eq "$grace"

for kv in KillSignal=SIGTERM KillMode=mixed SendSIGKILL=yes; do
    k=${kv%%=*}
    want=${kv#*=}
    got=$(ini "$UNIT" "$k" || true)
    if [ "$got" = "$want" ]; then
        pass "$k=$want"
    else
        fail "$k: got '${got:-<unset>}', need '$want'"
    fi
done

# ---------------------------------------------------------------- docker -----

printf '\ndocker: %s, %s\n' "${DOCKERFILE#"$ROOT"/}" "${COMPOSE#"$ROOT"/}"

if grep -qE '^STOPSIGNAL[[:space:]]+SIGTERM$' "$DOCKERFILE"; then
    pass "Dockerfile declares STOPSIGNAL SIGTERM"
else
    fail "Dockerfile must declare STOPSIGNAL SIGTERM explicitly"
fi

# HEALTHCHECK is docker's liveness. Same rule as the kubelet's: it must not
# fail during the drain, so it must not look at /readyz.
if grep -A2 '^HEALTHCHECK' "$DOCKERFILE" | grep -q 'readyz'; then
    fail "Dockerfile HEALTHCHECK probes readiness: a draining container would be marked unhealthy"
else
    pass "Dockerfile HEALTHCHECK does not probe readiness"
fi

sgp=$(grep -m1 '^[[:space:]]*stop_grace_period:' "$COMPOSE" | sed -e 's/.*:[[:space:]]*//' -e 's/[[:space:]]*$//' || true)
case "$sgp" in
    *s) sgp_secs=${sgp%s} ;;
    '') sgp_secs='' ;;
    *) sgp_secs="$sgp" ;;
esac
if is_uint "$sgp_secs"; then
    assert_num "compose stop_grace_period exceeds drain + 7" "$sgp_secs" gt "$FLOOR"
    assert_num "compose stop_grace_period matches terminationGracePeriodSeconds" "$sgp_secs" eq "$grace"
else
    fail "compose stop_grace_period missing: the 10s default SIGKILLs mid-drain"
fi

# The image smoke test stops the container; if its timeout is below the drain,
# CI SIGKILLs the process and then asserts on a log line it prevented.
stop_t=$(grep -m1 -oE 'docker stop -t [0-9]+' "$DOCKER_CI" | grep -oE '[0-9]+$' || true)
if is_uint "$stop_t"; then
    assert_num "docker.yml smoke test 'docker stop -t' exceeds drain + 7" "$stop_t" gt "$FLOOR"
else
    fail "could not find 'docker stop -t <secs>' in ${DOCKER_CI#"$ROOT"/}"
fi

# ----------------------------------------------------------------- verdict --

printf '\n'
if [ "$failures" -eq 0 ]; then
    printf '%s checks passed.\n' "$checks"
    exit 0
fi
printf '%s of %s checks FAILED.\n' "$failures" "$checks" >&2
printf 'These numbers are a system: see "Shutdown and draining" in the README\n' >&2
printf 'before changing any one of them on its own.\n' >&2
exit 1
