#!/bin/sh
# Run the `#[ignore]`d tests and require every one of them to still fail.
#
# This repository uses `#[ignore]` for one thing only: a test that states the
# behaviour we want, fails against the behaviour we have, and is left in the tree
# so whoever fixes the bug finds a failing test waiting instead of having to
# write one. Three of them are also a scope fence — the VEGA-065 and VEGA-083
# rulings both say that if one turns green, the change went outside its fence and
# the change is wrong.
#
# None of that is checked by anything else. `cargo test` skips them by name, and
# the in-tree guard (`zone::tests::the_three_rfc_bugs_this_fix_must_not_touch_
# are_still_ignored_with_their_reasons`) reads the `#[ignore = "…"]` attribute
# text, so it catches a deleted or reworded attribute and cannot catch the case
# its own doc comment names first: a test that turned green while keeping its
# attribute (VEGA-092).
#
# The polarity is the whole point and it is the opposite of a normal test step:
#
#   * an ignored test that FAILS is the expected state — say nothing;
#   * an ignored test that PASSES fails this script, because either the bug is
#     fixed (un-ignore the test, close the issue, and delete its line below) or a
#     change went outside its fence;
#   * a set that no longer matches the list below fails this script too, so a
#     pinned test cannot be quietly deleted or renamed into invisibility.
#
# `cargo test` exits non-zero when the ignored tests fail — which is the state we
# want — so its exit status is not the signal. The per-test result lines are.
#
# Usage: .github/scripts/pinned-bugs-must-stay-red.sh
# Env:   TEST_THREADS (default 2), CARGO (default cargo)

set -eu

CARGO="${CARGO:-cargo}"
TEST_THREADS="${TEST_THREADS:-2}"

# Every test that must still fail, one per line, sorted.
#
# Deleting a line here is a claim that the bug is fixed, and the reviewer's
# question is which commit fixed it. `saving_preserves_the_config_file_
# permissions` is `#[cfg(unix)]`, which is why this script is pinned to a Unix
# runner rather than added to the cross-platform matrix.
# Seven lines were deleted by VEGA-032, each with the commit that earned it:
#
#   bd4b397  S2, empty non-terminals (VEGA-006)
#     an_empty_non_terminal_answers_nodata_over_the_wire
#     zone::tests::an_empty_non_terminal_is_nodata_not_nxdomain
#     zone::tests::the_parent_of_a_wildcard_is_not_nxdomain
#   a54ea5c  S3, the closest encloser (VEGA-009, VEGA-098)
#     a_wildcard_does_not_reach_below_a_name_that_exists
#     zone::tests::a_wildcard_does_not_apply_below_a_name_that_exists
#   4a42fa4  S5, mandatory SOA and apex NS (VEGA-061, VEGA-064)
#     an_rrset_never_mixes_ttls
#     a_cname_is_alone_at_its_owner_name
#
# The three scope fences this script was written to protect are gone with them:
# they existed to stop S1 or S2 quietly fixing an RFC bug that belonged to a
# later step, and every step has now landed. What remains pins four bugs that
# are still live.
expected=$(
	cat <<'EOF'
editor::tests::saving_preserves_the_config_file_permissions
editor::tests::two_concurrent_writers_do_not_corrupt_the_config
txt_record_values_round_trip_through_presentation_format
ui::tests::colour_state_is_not_shared_between_concurrent_tests
EOF
)

log=$(mktemp)
trap 'rm -f "$log"' EXIT INT TERM

# --no-fail-fast matters: without it the first failing test binary stops the run,
# and an ignored test that turned green in a later binary is never executed.
"$CARGO" test --all-features --locked --no-fail-fast -- \
	--ignored --test-threads="$TEST_THREADS" >"$log" 2>&1 || true
cat "$log"

green=$(sed -n 's/^test \(.*\) \.\.\. ok$/\1/p' "$log" | sort)
red=$(sed -n 's/^test \(.*\) \.\.\. FAILED$/\1/p' "$log" | sort)

status=0

if [ -n "$green" ]; then
	echo
	echo "::error::an ignored test passed; it pins a bug that is no longer there, or a fence a change stepped over"
	echo "$green" | sed 's/^/  passed: /'
	echo "If the bug is fixed: remove the #[ignore], delete its line from"
	echo "$0, and close the issue with the commit that fixed it."
	echo "If it is one of the three scope fences: the change is wrong, not the test."
	status=1
fi

if [ "$red" != "$expected" ]; then
	echo
	echo "::error::the set of failing ignored tests is not the set this script pins"
	printf '%s\n' "$expected" >"$log.expected"
	printf '%s\n' "$red" >"$log.actual"
	diff -u "$log.expected" "$log.actual" || true
	rm -f "$log.expected" "$log.actual"
	echo "A test that vanished from this list is a pinned bug nobody is watching."
	status=1
fi

if [ "$status" -eq 0 ]; then
	count=$(echo "$red" | grep -c .)
	echo
	echo "$count pinned bugs, all still red. Nothing was silently fixed or silently deleted."
fi

exit "$status"
