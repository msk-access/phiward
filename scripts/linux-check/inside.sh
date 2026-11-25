#!/bin/sh
# Inside a clean python:X-slim container (scripts/linux-check/check.sh starts it): the source
# is at /repo (read only), results go to /out (a log, the skips and a junit file per layout).
# Exits non-zero if any run failed.
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq bubblewrap git nodejs rsync tabix >/dev/null  # node: CI's runners have it
useradd -m tester
# a Docker socket where a host with Docker has one (GitHub's runners, most workstations), behind
# the /var/run -> /run link: the gateway must still start (it once failed on this)
[ -L /var/run ] || { echo "linux-check: expected /var/run to be a link" >&2; exit 1; }
python -c 'import socket; socket.socket(socket.AF_UNIX).bind("/run/docker.sock")'
# a host service listening in /run, as on GitHub's runners (snapd, acpid): root's, outside every
# session
python -c 'import os, socket
s = socket.socket(socket.AF_UNIX); s.bind("/run/fake-FAKE.socket"); os.chmod("/run/fake-FAKE.socket", 0o666); s.listen(8)
if os.fork() == 0:
    while True:
        c, _ = s.accept(); c.sendall(b"PEER"); c.close()'
pip install -q -c /repo/tests/constraints.txt pytest pytest-timeout
v=$(python -c 'import sys; print("%d.%d" % sys.version_info[:2])')
status=0
for layout in /work/phiward /home/tester/src/phiward; do
  mkdir -p "$layout" && cp -a /repo/. "$layout"
  pip install -q -e "$layout"   # as CI installs it
  tmp="$(dirname "$layout")/pt"   # the made-up trees outside /tmp, as CI puts them
  chown -R tester "$(dirname "$layout")"
  tag="$v-$(echo "$layout" | cut -d/ -f2)"
  set +e
  su tester -c "cd $layout && PHIWARD_REQUIRE_CONFINE=1 PHIWARD_CHECK_SKIPS=1 \
    PHIWARD_WRITE_SKIPS=/tmp/skips-$tag.txt python -m pytest -p no:cacheprovider -rfE \
    --timeout=300 --basetemp=$tmp --junitxml=/tmp/junit-$tag.xml" > "/out/log-$tag.txt" 2>&1
  code=$?
  set -e
  cp "/tmp/skips-$tag.txt" "/tmp/junit-$tag.xml" /out/ 2>/dev/null || true
  echo "== $tag: $(grep -E '[0-9]+ (passed|failed)' "/out/log-$tag.txt" | tail -1) (pytest exit $code)"
  [ "$code" -eq 0 ] || status=1
done
exit $status
