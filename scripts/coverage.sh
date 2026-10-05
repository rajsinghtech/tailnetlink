#!/usr/bin/env bash
# Coverage ratchet.
#
# Runs the test suite with coverage across ./cmd and ./internal, so the
# in-process e2e tests count toward the packages they exercise. Test-only
# packages and the CI tooling under test/ (it has its own tests but is not
# product code) are left out of the profile. Fails if total statement coverage is below the floor in
# .coverage-baseline. When coverage goes up by a point or more it asks you to
# raise the floor in the same PR, so the number only ever moves up.
#
# Target: 85% total, and close to 100% for internal/bridge logic that does not
# need a running tsnet node (that part is covered by the e2e tests instead).
set -euo pipefail
cd "$(dirname "$0")/.."

baseline_file=.coverage-baseline
profile=${COVERPROFILE:-coverage.out}

go test -count=1 -race -covermode=atomic -coverpkg=./cmd/...,./internal/... -coverprofile="$profile.raw" ./...
grep -v -E '/internal/(testutil|e2e)/|/tailnetlink/test/' "$profile.raw" > "$profile"
rm -f "$profile.raw"

total=$(go tool cover -func="$profile" | awk '/^total:/ {sub("%", "", $3); print $3}')
baseline=$(tr -d '[:space:]' < "$baseline_file")
echo "total coverage: ${total}% (floor ${baseline}%, target 85%)"

if awk -v t="$total" -v b="$baseline" 'BEGIN { exit !(t < b) }'; then
	echo "coverage is below the floor in $baseline_file."
	echo "add tests, or if the drop is on purpose, say why in the PR and lower the floor."
	exit 1
fi
if awk -v t="$total" -v b="$baseline" 'BEGIN { exit !(t >= b + 1) }'; then
	echo "coverage is a point or more above the floor. raise $baseline_file to ${total%.*} in this PR."
fi
