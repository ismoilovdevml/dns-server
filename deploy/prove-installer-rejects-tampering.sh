#!/bin/sh
# Prove install.sh refuses an artifact it cannot vouch for.
#
#   ./deploy/prove-installer-rejects-tampering.sh [REPO_ROOT]
#
# VEGA-021: the installer advertised checksum verification and then had two
# ways round it. If the SHA256SUMS fetch failed it printed a yellow warning and
# installed anyway; with no sha256sum and no shasum on PATH `verify_checksum`
# returned 0 and installed anyway. Both are reachable from the README's
# `curl | sh` one-liner, and both are trivially reachable by anyone who can
# already serve you a trojaned tarball — they simply 404 the checksum file.
# A third, quieter one: when SHA256SUMS did not name our archive the code fell
# back to the file's *first* line, so a one-line SHA256SUMS naming some other
# artifact had its digest accepted for ours.
#
# So this builds a scratch "release" on disk, points the real, unmodified
# install.sh at it with VEGA_RELEASE_BASE_URL, and requires a non-zero exit and
# an uninstalled binary for every one of those paths. Case 1 installs a good
# release first: without it every later case could be passing for the wrong
# reason and this file would prove nothing.
#
# POSIX sh, like the other gates in this directory: it runs in CI, on a laptop
# and on a jump box, and a correctness gate should not need a toolchain.

set -eu

ROOT="${1:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)}"
INSTALLER="$ROOT/install.sh"
VERSION="v9.9.9-proof"

[ -f "$INSTALLER" ] || { printf 'error: no such file: %s\n' "$INSTALLER" >&2; exit 2; }

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT INT TERM

# The same mapping install.sh's detect_target() does, so we can name the file it
# will ask for. Kept deliberately small: this only has to work on the platforms
# the gate runs on (Linux CI, macOS laptop).
case "$(uname -s)" in
    Linux)  os_part="unknown-linux-gnu"
            ldd --version 2>&1 | grep -qi glibc || os_part="unknown-linux-musl" ;;
    Darwin) os_part="apple-darwin" ;;
    *) printf 'error: this proof does not know how to name an artifact for %s\n' "$(uname -s)" >&2
       exit 2 ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  arch_part="x86_64" ;;
    aarch64|arm64) arch_part="aarch64" ;;
    *) printf 'error: unsupported architecture: %s\n' "$(uname -m)" >&2; exit 2 ;;
esac
TARGET="$arch_part-$os_part"
ARCHIVE="vega-$VERSION-$TARGET.tar.gz"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Build a release directory: $scratch/<name>/<VERSION>/{archive,SHA256SUMS}.
# $2 is the payload the fake `vega` binary prints, so a tampered archive really
# is a different file and not just a rewritten checksum.
make_release() {
    _name="$1"
    _payload="$2"
    _dir="$scratch/$_name/$VERSION"
    mkdir -p "$_dir/stage"
    cat >"$_dir/stage/vega" <<EOF
#!/bin/sh
echo "vega $_payload"
EOF
    chmod +x "$_dir/stage/vega"
    tar -czf "$_dir/$ARCHIVE" -C "$_dir/stage" vega
    rm -rf "$_dir/stage"
    (cd "$_dir" && printf '%s  %s\n' "$(sha256_of "$ARCHIVE")" "$ARCHIVE" >SHA256SUMS)
}

# Run the real installer against a scratch release. Never touches a system path:
# INSTALL_DIR is under $scratch and NO_SUDO refuses any escalation, so a bug
# that got past the checks would fail loudly here rather than write to /usr.
run_installer() {
    _release="$1"
    shift
    rm -rf "${scratch:?}/bin"
    ( cd "$scratch" \
      && VEGA_RELEASE_BASE_URL="file://$scratch/$_release" \
         INSTALL_DIR="$scratch/bin" \
         NO_SUDO=1 \
         NO_COLOR=1 \
         sh "$INSTALLER" --version "$VERSION" "$@" ) >"$scratch/out.log" 2>&1
}

installed() { [ -x "$scratch/bin/vega" ]; }

fail() {
    printf '\nerror: %s\n' "$1" >&2
    printf -- '--- installer output ---\n' >&2
    cat "$scratch/out.log" >&2
    exit 1
}

# --- 1. a good release installs ----------------------------------------------
#
# The control. If this cannot pass, every "it refused" below is meaningless
# because the installer would have refused a valid release too.

printf '==> 1. a good release installs\n'
make_release good genuine
if ! run_installer good; then
    fail "the installer rejected a release whose checksum is correct. Fix the installer, not this script."
fi
installed || fail "the installer reported success but installed nothing"
grep -q 'checksum verified' "$scratch/out.log" \
    || fail "the good install did not report a verified checksum, so nothing here exercises verification"
printf '    %s\n' "$("$scratch/bin/vega")"

# --- 2. a tampered archive is refused ----------------------------------------
#
# SHA256SUMS is the genuine one; only the tarball was swapped. This is the case
# the installer always claimed to catch.

printf '\n==> 2. a tampered archive is refused\n'
make_release tampered genuine
make_release trojan trojaned
cp "$scratch/trojan/$VERSION/$ARCHIVE" "$scratch/tampered/$VERSION/$ARCHIVE"
if run_installer tampered; then
    fail "the installer accepted an archive whose SHA-256 does not match SHA256SUMS"
fi
installed && fail "a tampered archive was installed"
grep -q 'checksum mismatch' "$scratch/out.log" || fail "refused, but not for the checksum"
grep -m1 'checksum mismatch' "$scratch/out.log"

# --- 3. a missing SHA256SUMS is refused --------------------------------------
#
# VEGA-021 proper. Blocking one request is strictly easier for an attacker than
# forging a digest, so this must be as fatal as case 2.

printf '\n==> 3. a missing SHA256SUMS is refused\n'
make_release nosums genuine
rm "$scratch/nosums/$VERSION/SHA256SUMS"
if run_installer nosums; then
    fail "the installer accepted a download with no published checksum at all (VEGA-021, verbatim)"
fi
installed && fail "an unverified archive was installed"
grep -q 'could not fetch SHA256SUMS' "$scratch/out.log" || fail "refused, but not for the missing checksum file"
grep -m1 'could not fetch SHA256SUMS' "$scratch/out.log"

# --- 4. a SHA256SUMS that does not name our archive is refused ---------------
#
# The old first-line fallback: serve a one-line file naming something else and
# its digest was accepted for whatever we downloaded.

printf '\n==> 4. a SHA256SUMS that does not name our archive is refused\n'
make_release wrongname genuine
cp "$scratch/trojan/$VERSION/$ARCHIVE" "$scratch/wrongname/$VERSION/$ARCHIVE"
printf '%s  %s\n' \
    "$(sha256_of "$scratch/trojan/$VERSION/$ARCHIVE")" "vega-$VERSION-some-other-target.tar.gz" \
    >"$scratch/wrongname/$VERSION/SHA256SUMS"
if run_installer wrongname; then
    fail "the installer took a digest from a line naming a different artifact"
fi
installed && fail "an archive vouched for by the wrong filename was installed"
grep -q 'does not list' "$scratch/out.log" || fail "refused, but not because the archive is unlisted"
grep -m1 'does not list' "$scratch/out.log"

# --- 5. no sha256 tool on PATH is refused ------------------------------------
#
# The second downgrade in VEGA-021: verify_checksum used to `return 0` here.
# PATH is rebuilt from an explicit list so that sha256sum and shasum are the
# only things missing.

printf '\n==> 5. no sha256sum and no shasum on PATH is refused\n'
shimbin="$scratch/shimbin"
mkdir -p "$shimbin"
for _t in sh dash bash uname tar curl wget grep sed awk head cut tr cat mktemp id \
          dirname install chmod rm mkdir ldd file; do
    _p=$(command -v "$_t" 2>/dev/null) || continue
    ln -sf "$_p" "$shimbin/$_t"
done
for _forbidden in sha256sum shasum openssl; do
    [ -e "$shimbin/$_forbidden" ] && fail "the shim PATH still contains $_forbidden"
done
make_release nohash genuine
rm -rf "${scratch:?}/bin"
if ( cd "$scratch" \
     && PATH="$shimbin" \
        VEGA_RELEASE_BASE_URL="file://$scratch/nohash" \
        INSTALL_DIR="$scratch/bin" NO_SUDO=1 NO_COLOR=1 \
        sh "$INSTALLER" --version "$VERSION" ) >"$scratch/out.log" 2>&1; then
    fail "the installer skipped verification because it had no tool to verify with, and installed anyway"
fi
installed && fail "an unverified archive was installed on a box with no sha256 tool"
grep -q 'no sha256sum or shasum on PATH' "$scratch/out.log" \
    || fail "refused, but not because the hashing tool is missing"
grep -m1 'no sha256sum or shasum on PATH' "$scratch/out.log"

# --- 6. the escape hatch works, and only from the command line ---------------
#
# A fatal check with no documented override gets worked around by piping to
# `sh -c` with the verification deleted. One override, typed, and loud.

printf '\n==> 6. --insecure-skip-checksum is the only way past\n'
if ! run_installer nosums --insecure-skip-checksum; then
    fail "--insecure-skip-checksum did not let a deliberate unverified install through"
fi
installed || fail "--insecure-skip-checksum reported success but installed nothing"
grep -q 'UNVERIFIED' "$scratch/out.log" || fail "the unverified install was not announced as such"
grep -m1 'UNVERIFIED' "$scratch/out.log"

# The same downgrade must NOT be reachable from the environment: a `curl | sh`
# pipeline inherits the environment, and an attacker who can set a variable
# should not thereby be able to turn verification off.
rm -rf "${scratch:?}/bin"
if ( cd "$scratch" \
     && INSECURE_SKIP_CHECKSUM=1 SKIP_CHECKSUM=1 VEGA_INSECURE_SKIP_CHECKSUM=1 \
        VEGA_RELEASE_BASE_URL="file://$scratch/nosums" \
        INSTALL_DIR="$scratch/bin" NO_SUDO=1 NO_COLOR=1 \
        sh "$INSTALLER" --version "$VERSION" ) >"$scratch/out.log" 2>&1; then
    fail "verification was switched off by an environment variable"
fi
installed && fail "an environment variable installed an unverified archive"
printf '    the environment cannot switch verification off\n'

# --- 7. --verify-attestation is fatal when gh is absent ----------------------
#
# "Verify if the tool happens to be installed" is the same failure as case 5.
# Asking for the check and silently not getting it is the outcome to prevent.

printf '\n==> 7. --verify-attestation without gh is fatal\n'
rm -rf "${scratch:?}/bin"
if ( cd "$scratch" \
     && PATH="$shimbin" \
        VEGA_RELEASE_BASE_URL="file://$scratch/good" \
        INSTALL_DIR="$scratch/bin" NO_SUDO=1 NO_COLOR=1 \
        sh "$INSTALLER" --version "$VERSION" --verify-attestation --insecure-skip-checksum ) \
        >"$scratch/out.log" 2>&1; then
    fail "--verify-attestation was requested, gh was missing, and the install proceeded anyway"
fi
installed && fail "an unattested archive was installed after --verify-attestation was requested"
grep -q 'needs the GitHub CLI' "$scratch/out.log" || fail "refused, but not because gh is missing"
grep -m1 'needs the GitHub CLI' "$scratch/out.log"

printf '\nthe installer refuses everything it cannot vouch for, as it must.\n'
