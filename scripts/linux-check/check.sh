#!/bin/sh
# The test suite on Linux, as CI runs it but in Docker on this machine: Python 3.12 and 3.9
# (one container each, at the same time), each in two layouts one after the other (the
# checkout under /work, and under a home folder), as a user who is not root, with bubblewrap,
# PHIWARD_REQUIRE_CONFINE=1 and PHIWARD_CHECK_SKIPS=1. It tests a `git archive` of COMMIT
# (default HEAD), so uncommitted changes are not in it. Made-up data only. Needs Docker.
# Usage, from the repository: sh scripts/linux-check/check.sh [COMMIT]
# Logs, skip lists and junit files are left in the folder it prints; exit 0 when all passed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
commit=$(git -C "$repo" rev-parse --verify "${1:-HEAD}^{commit}")
work=$(mktemp -d)
label="phiward-linux-check=$$"
pids=""
stop() {
  # only the containers this run started (by their label), also those still being created
  ids=$(docker ps -aq --filter "label=$label") || return 0
  [ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || true
}
trap 'kill $pids 2>/dev/null; wait; stop; exit 2' INT TERM
mkdir "$work/src"
git -C "$repo" archive "$commit" | tar -x -C "$work/src"
echo "testing $(git -C "$repo" log --oneline -1 "$commit"); output in $work"
for v in 3.12 3.9; do
  mkdir "$work/$v"
  docker pull -q "python:$v-slim" >/dev/null  # today's image, as CI's runner gets
  docker run --rm --privileged --label "$label" -v "$work/src:/repo:ro" -v "$work/$v:/out" \
    "python:$v-slim" sh /repo/scripts/linux-check/inside.sh > "$work/$v.txt" 2>&1 &
  pids="$pids $!"
done
status=0
for p in $pids; do wait "$p" || status=1; done
grep -h "^== " "$work"/3.*.txt || true
[ "$status" -eq 0 ] && echo "PASS linux suites" || echo "FAIL linux suites (logs in $work)"
exit $status
