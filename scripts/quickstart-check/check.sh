#!/bin/sh
# A new user's install, checked: a new user on Linux follows docs/quickstart.md (install
# with uv or pipx, `setup` choice 1, `doctor`, then `mcp list` and `mcp wrap`, starts the wrapped
# server from its entry, and runs `doctor` again) in a clean python:3.12-slim container, with
# umask 022 and with 002 (Debian and Ubuntu with a private group make ~/.local/bin
# group-writable), and once with a shared primary group and umask 002. While the wrapped server
# runs, the hook must trust it from the project and from a home-folder session. Then another
# program uses the same Python (new __pycache__ folders) and doctor must stay clean. The
# scenarios: upgrade (a reinstall with umask 002: the one step, then clean), attack (another
# account of the shared group cannot move phiward's folders or plant a .pth), old-settings (an
# older phiward's allowWrite is named with its file), owned-python (pipx on a Python the user
# owns), outside-python (pipx on a Python of the user's outside the home folder, group-writable:
# one step fixes it), home-775 (a group-writable home folder: the chmod step), linked-home (/home is a link,
# as on Fedora Silverblue). It installs the wheel built
# from this checkout instead of PyPI. Made-up data only. Needs Docker.
# Usage, from the repository:
#   sh scripts/quickstart-check/check.sh [--quick] [-j N] [RUN...]   (a RUN as below, in quotes)
# The release check is the default: all the runs, on an image built fresh (`--pull
# --no-cache`, so the prerequisites are today's, as a new user's). `--quick`: the four plain
# runs on the image as cached. `-j N`: N runs at a time (default 4). Each run's output is kept
# in a log; when a run fails, its FAIL lines are printed and every log is kept (the folder is
# named at the end).
set -e
here=$(cd "$(dirname "$0")" && pwd)
quick=0
jobs=4
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) quick=1; shift;;
    -j) jobs=$2; shift 2;;
    *) break;;
  esac
done
work=$(mktemp -d)
label="phiward-quickstart-check=$$"
status=2
pids=""
stop() {
  # only the containers this run started (by their label), also those still being created
  ids=$(docker ps -aq --filter "label=$label") || return 0
  [ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || true
}
finish() {
  stop
  if [ "$status" = 0 ]; then rm -rf "$work"; else echo "logs kept in $work/logs"; fi
}
trap finish EXIT
trap 'status=2; kill $pids 2>/dev/null; wait; exit 2' INT TERM
image=phiward-quickstart-check
if [ "$quick" = 1 ]; then
  docker build -q -t "$image" "$here" >/dev/null
else
  docker build -q --pull --no-cache -t "$image" "$here" >/dev/null
fi
echo "image $(docker image inspect -f '{{.Id}}' "$image" | cut -c1-19):" \
  "$(docker run --rm "$image" sh -c 'echo "bwrap $(bwrap --version | cut -d" " -f2), $(uv --version), pipx $(pipx --version)"')"
mkdir "$work/wheel" "$work/logs"
uv build -q --wheel -o "$work/wheel" "$here/../.."
cp "$here"/run.sh "$here"/user.sh "$here"/answers.txt "$here"/yes.txt "$here"/srv.py \
  "$here"/start.py "$here"/allow.py "$here"/hook.py "$work/"
if [ $# -eq 0 ] && [ "$quick" = 1 ]; then
  set -- "uv 022 private" "uv 002 private" "pipx 022 private" "pipx 002 private"
fi
[ $# -gt 0 ] || set -- "uv 022 private" "uv 002 private" "pipx 022 private" \
  "pipx 002 private" "uv 002 shared" "pipx 002 shared" "uv 002 private upgrade" \
  "uv 002 shared attack" "uv 022 private old-settings" "pipx 002 private owned-python" \
  "uv 022 private home-775" "uv 002 private linked-home" "pipx 002 shared linked-home" \
  "pipx 002 private outside-python"
one() {  # one run, its output in its own log; prints PASS or FAIL with the log
  log="$work/logs/$(echo "$1" | tr ' ' '-').txt"
  set -- $1
  if docker run --rm --privileged --label "$label" -v "$work:/qs:ro" "$image" \
      sh /qs/run.sh "$2" "$1" "$3" "$4" > "$log" 2>&1
  then
    echo "PASS quickstart: $*"
  else
    echo "FAIL quickstart: $* ($log)"
    grep "^FAIL" "$log" || tail -20 "$log"
    return 1
  fi
}
status=0
n=0
for run in "$@"; do
  one "$run" &
  pids="$pids $!"
  n=$((n + 1))
  if [ "$n" -ge "$jobs" ]; then
    for p in $pids; do wait "$p" || status=1; done
    pids=""
    n=0
  fi
done
for p in $pids; do wait "$p" || status=1; done
exit $status
