#!/bin/sh
# Every third-party action must be pinned to a commit SHA.
#
#   ./.github/scripts/actions-must-be-sha-pinned.sh [REPO_ROOT]
#
# VEGA-022. `uses: some/action@v3` is a promise from a tag owner that they will
# never move the tag, and tags move: by accident, after a compromise, and on
# purpose. release.yml's publish job holds `contents: write`, `id-token: write`
# and `attestations: write`, so anything that runs there can cut a release,
# mint an OIDC token and attest whatever it likes. A moving tag in that job is
# arbitrary code execution with those scopes, deferred to a moment of the tag
# owner's choosing. A commit SHA cannot be moved.
#
# Rules enforced here:
#   1. every uses: resolves to a 40-character commit SHA, or is a `./` local
#      reusable workflow in this repository;
#   2. every SHA carries a trailing `# <version>` comment, because an
#      unlabelled 40-hex string is a pin nobody will ever dare to bump;
#   3. a local `./` reference points at a file that exists.
#
# A `# vN` comment is not a security control — nothing checks it against the
# SHA — it is the maintenance handle. Dependabot rewrites both together.
#
# POSIX sh, no arithmetic expansion anywhere: a gate that computes is a gate
# that can compute wrong, and `$((010))` is 8.

set -eu

ROOT="${1:-$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)}"
DIR="$ROOT/.github/workflows"

[ -d "$DIR" ] || { printf 'error: no such directory: %s\n' "$DIR" >&2; exit 2; }

# Below this, assume the extraction broke rather than that the workflows really
# got that small. Without it, a rename of the workflow directory or a change to
# the uses: spelling turns this whole gate into a no-op that exits 0.
MIN_REFS=20

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# file:line:indent- uses: owner/repo@ref  # comment
grep -REn '^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]' "$DIR" >"$work/raw" || true

: >"$work/refs"
: >"$work/bad"

while IFS= read -r line; do
    [ -n "$line" ] || continue
    where="${line%%:*}"
    rest="${line#*:}"
    lineno="${rest%%:*}"
    where="$(basename "$where"):$lineno"

    # Everything after the first uses:.
    value="${line#*uses:}"
    # Leading whitespace off, then the reference is the first token.
    value="${value#"${value%%[![:space:]]*}"}"
    ref="${value%%[[:space:]]*}"
    comment="${value#"$ref"}"

    printf '%s\n' "$ref" >>"$work/refs"

    case "$ref" in
        ./*)
            # A reusable workflow from this repository. It is pinned by
            # definition: it is this commit.
            if [ ! -f "$ROOT/${ref#./}" ]; then
                printf '%s: uses %s, which does not exist\n' "$where" "$ref" >>"$work/bad"
            fi
            continue
            ;;
    esac

    sha="${ref##*@}"
    if [ "$sha" = "$ref" ]; then
        printf '%s: %s has no @ref at all\n' "$where" "$ref" >>"$work/bad"
        continue
    fi

    unpinned=0
    [ "${#sha}" = 40 ] || unpinned=1
    case "$sha" in
        *[!0-9a-f]*) unpinned=1 ;;
    esac
    if [ "$unpinned" = 1 ]; then
        printf '%s: %s is pinned to a mutable ref, not a commit SHA\n' "$where" "$ref" >>"$work/bad"
        continue
    fi

    case "$comment" in
        *"#"*) ;;
        *) printf '%s: %s is SHA-pinned but unlabelled; add a trailing "# <version>"\n' \
               "$where" "$ref" >>"$work/bad" ;;
    esac
done <"$work/raw"

found=$(wc -l <"$work/refs" | tr -d ' ')
if [ "$found" -lt "$MIN_REFS" ]; then
    printf 'error: found only %s uses: references under %s, expected at least %s.\n' \
        "$found" "$DIR" "$MIN_REFS" >&2
    printf '       Either the workflows shrank a lot or this check stopped seeing them.\n' >&2
    printf '       Verify by hand, then lower MIN_REFS deliberately.\n' >&2
    exit 2
fi

if [ -s "$work/bad" ]; then
    printf 'error: unpinned GitHub Actions.\n\n' >&2
    sed 's/^/  /' "$work/bad" >&2
    cat >&2 <<'EOF'

Resolve the tag to a commit and pin it, keeping the tag as a comment:

  sha=$(gh api repos/OWNER/REPO/git/ref/tags/TAG --jq '.object.sha')
  # if that object is an annotated tag, dereference it:
  gh api repos/OWNER/REPO/git/tags/$sha --jq '.object.sha'

  uses: OWNER/REPO@<40-hex sha>  # TAG
EOF
    exit 1
fi

printf 'all %s uses: references are SHA-pinned and labelled.\n' "$found"
