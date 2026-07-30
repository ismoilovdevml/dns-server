#!/bin/sh
# vega installer.
#
#   curl -fsSL https://raw.githubusercontent.com/ismoilovdevml/vega/main/install.sh | sh
#
# Downloads the release binary for this platform, verifies its SHA-256 against
# the published checksum file, and installs it. With --systemd it also writes a
# config file and a unit, then leaves the service stopped so you can review the
# zone before starting it.
#
# Environment overrides:
#   VERSION=v0.2.0        install a specific tag instead of the latest release
#   INSTALL_DIR=/opt/bin  where the binary goes (default /usr/local/bin)
#   CONFIG_DIR=/etc/x     where the config goes (default /etc/vega)
#   NO_SUDO=1             never escalate; fail instead
#
# POSIX sh on purpose: this has to run on a minimal box before anything is set up.

set -eu

REPO="ismoilovdevml/vega"
BIN_NAME="vega"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/vega}"
SERVICE_USER="vega"
WITH_SYSTEMD=0
VERSION="${VERSION:-}"

# ---------------------------------------------------------------- output ----

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$(printf '\033[0m')
    C_DIM=$(printf '\033[2m')
    C_RED=$(printf '\033[31m')
    C_GREEN=$(printf '\033[32m')
    C_YELLOW=$(printf '\033[33m')
    C_CYAN=$(printf '\033[36m')
else
    C_RESET='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_CYAN=''
fi

info()  { printf '%s==>%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()    { printf '%s  ok%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%s warn%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()   { printf '%serror%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }
dim()   { printf '%s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }

usage() {
    cat <<EOF
Install $BIN_NAME.

Usage: install.sh [options]

  --systemd              also install a systemd unit and a starter config
  --version VERSION      install a specific release tag (e.g. v0.2.0)
  --install-dir DIR      binary destination (default: $INSTALL_DIR)
  --config-dir DIR       config destination (default: $CONFIG_DIR)
  -h, --help             show this help

Without --systemd this only installs the binary, which is all you need for
Docker, Kubernetes, or running it under another supervisor.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --systemd) WITH_SYSTEMD=1 ;;
        --version) VERSION="${2:-}"; shift ;;
        --version=*) VERSION="${1#*=}" ;;
        --install-dir) INSTALL_DIR="${2:-}"; shift ;;
        --install-dir=*) INSTALL_DIR="${1#*=}" ;;
        --config-dir) CONFIG_DIR="${2:-}"; shift ;;
        --config-dir=*) CONFIG_DIR="${1#*=}" ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

# --------------------------------------------------------------- helpers ----

need() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"
}

# Run a command as root, escalating only if we have to.
as_root() {
    if [ "$(id -u)" = 0 ]; then
        "$@"
    elif [ -n "${NO_SUDO:-}" ]; then
        die "need root to run: $* (NO_SUDO is set)"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        die "need root to run: $* (install sudo, or re-run as root)"
    fi
}

fetch() {
    # $1 url, $2 destination
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 1 -o "$2" "$1"
    else
        wget -q -O "$2" "$1"
    fi
}

fetch_stdout() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 1 "$1"
    else
        wget -q -O - "$1"
    fi
}

# Map uname output onto the target triples the release workflow publishes.
detect_target() {
    os=$(uname -s)
    arch=$(uname -m)

    case "$os" in
        Linux)  os_part="unknown-linux-gnu" ;;
        Darwin) os_part="apple-darwin" ;;
        *) die "unsupported operating system: $os (build from source with \`cargo install --git https://github.com/$REPO\`)" ;;
    esac

    case "$arch" in
        x86_64|amd64)  arch_part="x86_64" ;;
        aarch64|arm64) arch_part="aarch64" ;;
        *) die "unsupported architecture: $arch" ;;
    esac

    # musl builds are published for Linux and are the safer choice on distros
    # whose glibc is older than the build host's.
    if [ "$os" = "Linux" ] && ! ldd --version 2>&1 | grep -qi glibc; then
        os_part="unknown-linux-musl"
    fi

    printf '%s-%s' "$arch_part" "$os_part"
}

latest_version() {
    fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" \
        | grep -m1 '"tag_name"' \
        | sed -e 's/.*"tag_name"[[:space:]]*:[[:space:]]*"//' -e 's/".*//'
}

verify_checksum() {
    # $1 archive path, $2 checksum file, $3 archive file name
    expected=$(grep -F "  $3" "$2" 2>/dev/null | awk '{print $1}' | head -1)
    if [ -z "$expected" ]; then
        expected=$(awk '{print $1}' "$2" | head -1)
    fi
    [ -n "$expected" ] || die "no checksum found for $3"

    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$1" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$1" | awk '{print $1}')
    else
        warn "no sha256sum or shasum found; skipping checksum verification"
        return 0
    fi

    [ "$actual" = "$expected" ] || die "checksum mismatch for $3
  expected $expected
  actual   $actual
Refusing to install. This is either a corrupted download or a tampered artifact."
    ok "checksum verified"
}

# ------------------------------------------------------------------ main ----

command -v curl >/dev/null 2>&1 || need wget
need uname
need tar

TARGET=$(detect_target)
info "platform: $TARGET"

if [ -z "$VERSION" ]; then
    info "resolving the latest release"
    VERSION=$(latest_version)
    [ -n "$VERSION" ] || die "could not determine the latest release; pass --version"
fi
info "version: $VERSION"

ARCHIVE="${BIN_NAME}-${VERSION}-${TARGET}.tar.gz"
BASE_URL="https://github.com/$REPO/releases/download/$VERSION"

TMP=$(mktemp -d)
# Clean up on every exit path, including failure.
trap 'rm -rf "$TMP"' EXIT INT TERM

info "downloading $ARCHIVE"
fetch "$BASE_URL/$ARCHIVE" "$TMP/$ARCHIVE" \
    || die "download failed. Check that $VERSION has an asset for $TARGET:
  https://github.com/$REPO/releases/tag/$VERSION"

if fetch "$BASE_URL/SHA256SUMS" "$TMP/SHA256SUMS" 2>/dev/null; then
    verify_checksum "$TMP/$ARCHIVE" "$TMP/SHA256SUMS" "$ARCHIVE"
else
    warn "no SHA256SUMS published for $VERSION; skipping verification"
fi

tar -xzf "$TMP/$ARCHIVE" -C "$TMP" || die "could not extract $ARCHIVE"
[ -f "$TMP/$BIN_NAME" ] || die "$ARCHIVE did not contain a $BIN_NAME binary"
chmod +x "$TMP/$BIN_NAME"

info "installing to $INSTALL_DIR/$BIN_NAME"
as_root mkdir -p "$INSTALL_DIR"
as_root install -m 0755 "$TMP/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
ok "$("$INSTALL_DIR/$BIN_NAME" --version)"

if [ "$WITH_SYSTEMD" = 1 ]; then
    command -v systemctl >/dev/null 2>&1 || die "--systemd was requested but systemctl is not available"

    info "creating the $SERVICE_USER system user"
    if id "$SERVICE_USER" >/dev/null 2>&1; then
        dim "  user already exists"
    elif command -v useradd >/dev/null 2>&1; then
        as_root useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    elif command -v adduser >/dev/null 2>&1; then
        as_root adduser -S -H -s /sbin/nologin "$SERVICE_USER"
    else
        die "no useradd or adduser found; create the $SERVICE_USER user yourself and re-run"
    fi

    info "writing $CONFIG_DIR/vega.toml"
    as_root mkdir -p "$CONFIG_DIR"
    if [ -f "$CONFIG_DIR/vega.toml" ]; then
        # Never clobber a live zone.
        dim "  config already exists, leaving it alone"
    else
        as_root "$INSTALL_DIR/$BIN_NAME" init \
            --origin example.com \
            --output "$CONFIG_DIR/vega.toml" >/dev/null
        as_root chown -R "root:$SERVICE_USER" "$CONFIG_DIR"
        as_root chmod 0750 "$CONFIG_DIR"
        as_root chmod 0640 "$CONFIG_DIR/vega.toml"
        ok "starter config written"
    fi

    info "writing /etc/systemd/system/vega.service"
    fetch_stdout "https://raw.githubusercontent.com/$REPO/$VERSION/deploy/systemd/vega.service" \
        > "$TMP/vega.service" \
        || die "could not download the systemd unit for $VERSION"
    as_root install -m 0644 "$TMP/vega.service" /etc/systemd/system/vega.service
    as_root systemctl daemon-reload
    ok "unit installed"

    printf '\n'
    dim "The service is installed but not started. Next:"
    printf '  1. edit   %s%s/vega.toml%s\n' "$C_CYAN" "$CONFIG_DIR" "$C_RESET"
    printf '  2. verify %s%s check --config %s/vega.toml%s\n' "$C_CYAN" "$BIN_NAME" "$CONFIG_DIR" "$C_RESET"
    printf '  3. start  %ssystemctl enable --now vega%s\n' "$C_CYAN" "$C_RESET"
    printf '\n'
    dim "Port 53 is usually already taken on Linux. If the service fails to bind,"
    dim "check systemd-resolved: systemctl status systemd-resolved"
else
    printf '\n'
    dim "Next:"
    printf '  %s%s init --origin example.com%s      create a config\n' "$C_CYAN" "$BIN_NAME" "$C_RESET"
    printf '  %s%s record add www A 203.0.113.10%s  add a record\n' "$C_CYAN" "$BIN_NAME" "$C_RESET"
    printf '  %s%s check%s                          validate it\n' "$C_CYAN" "$BIN_NAME" "$C_RESET"
    printf '  %s%s serve%s                          run it\n' "$C_CYAN" "$BIN_NAME" "$C_RESET"
    printf '\n'
    dim "For a systemd service: re-run this installer with --systemd"
fi
