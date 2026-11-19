#!/bin/sh
# The real Claude Code sandbox check on Linux, in Docker on this machine (docs/releasing.md,
# "Each release", step 3). It builds the image in docker/ (python:3.12-slim, a user tester,
# bubblewrap, socat, git, and Claude Code pinned by docker/package-lock.json), mounts a
# `git archive` of HEAD read only, and runs check.sh inside as tester (Mode A and B; MODES is
# passed). The operator runs it, in a terminal: check.sh asks for the token inside the container.
# The token is never passed in (no -e, no build-arg, no file): a token variable set here is not
# used. Uncommitted changes are not in the check. Output (the report, each mode's redacted stream and facts)
# is left in the folder it prints.
#   --stub   a stand-in claude and a made-up token, no terminal: tests the plumbing, never
#            Claude Code. This is the only form an agent may run.
#   CLAUDE_VERSION   builds another Claude Code version than the lock (unlocked; the report says so)
# Usage, from the repository: sh scripts/sandbox-check/linux.sh [--stub]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
stub=""
[ "${1:-}" = --stub ] && stub=--stub
if [ -z "$stub" ]; then
  [ -z "${CLAUDECODE:-}" ] || { echo "sandbox-check: refused: CLAUDECODE is set (an agent's shell); the operator runs the real check in a terminal, an agent only --stub" >&2; exit 2; }
  [ -t 0 ] || { echo "sandbox-check: a real run needs a terminal (it asks for the token)" >&2; exit 2; }
fi
for v in CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY; do
  eval "val=\${$v:-}"
  [ -z "$val" ] || echo "note: $v is set here; it is not passed into the container"
done
val=""
image=phiward-sandbox-check
work=$(mktemp -d)
label="phiward-sandbox-check=$$"
stop() {
  ids=$(docker ps -aq --filter "label=$label") || return 0
  [ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || true
}
# a signal stops this run's container (so the session ends), then exits 128 + the signal
trap 'stop; exit 130' INT
trap 'stop; exit 143' TERM
trap 'stop; exit 129' HUP
mkdir "$work/src" "$work/out"
chmod 777 "$work/out"  # the container's tester writes there; $work itself is private
git -C "$repo" archive HEAD | tar -x -C "$work/src"
[ -z "$(git -C "$repo" status --porcelain)" ] || echo "note: uncommitted changes are not in the check (it builds HEAD)"
echo "checking $(git -C "$repo" log --oneline -1 HEAD); output in $work/out"
docker build -q -t "$image" --build-arg "CLAUDE_VERSION=${CLAUDE_VERSION:-}" "$here/docker" >/dev/null
id=$(docker image inspect -f '{{.Id}}' "$image")
modes=${MODES:-A B}
tty=""
input=/dev/null
[ -n "$stub" ] || { tty=-it; input=/dev/tty; }
code=0
# in the background (the terminal given explicitly for a real run), so a signal to this script is
# handled at once
docker run --rm $tty --user tester --privileged --security-opt no-new-privileges \
  --label "$label" \
  -e "SBX_IMAGE=$id" -e "MODES=$modes" \
  -v "$work/src:/repo:ro" -v "$work/out:/out" \
  "$image" sh /repo/scripts/sandbox-check/inside.sh $stub < "$input" &
wait $! || code=$?
echo "output in $work/out"
exit $code
