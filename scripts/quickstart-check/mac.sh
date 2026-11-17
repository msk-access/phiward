#!/bin/sh
# A new user's install on macOS, without touching your own setup: a home folder of its own
# under /private/tmp, a copy of a Python (uv's or Homebrew's, given as PYTHON) so phiward's own
# install changes nothing of yours, `uv tool install` of the wheel, the user config written as
# `setup` writes it, `install claude --user --write`, the broker in the background (no login
# service: nothing is registered with launchd), `doctor`, `mcp wrap` of a tiny server, the
# wrapped server started from its entry (it must answer and must not read the made-up protected
# file), the hook from the project and from the home folder, then `doctor` again. Made-up data
# only. Usage: sh scripts/quickstart-check/mac.sh WHEEL PYTHON
set -e
# both are needed: without PYTHON the copy below would take the folder above this one
if [ $# -ne 2 ] || [ ! -f "$1" ] || [ ! -x "$2" ]; then
  echo "usage: sh scripts/quickstart-check/mac.sh WHEEL PYTHON (uv's or Homebrew's python3)" >&2
  exit 2
fi
wheel=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
python=$2
here=$(cd "$(dirname "$0")" && pwd)
uv=$(command -v uv)
H=$(mktemp -d /private/tmp/phiward-mac-XXXXXX)
broker=""
cleanup() { [ -n "$broker" ] && kill "$broker" 2>/dev/null; [ -n "$KEEP" ] || rm -rf "$H"; }
trap cleanup EXIT
fail() { echo "FAIL: $1"; cat "$2" 2>/dev/null; exit 1; }
# a copy of the Python: phiward compiles and fixes the modes of its own Python, and must not
# change the one this machine uses
base=$(cd "$(dirname "$("$python" -c 'import sys; print(sys.executable)')")/.." && pwd -P)
cp -R "$base" "$H/py"
pyname=$(basename "$("$python" -c 'import sys, os; print(os.path.realpath(sys.executable))')")
export HOME="$H" PATH="$H/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin" UV_TOOL_DIR="$H/.local/share/uv/tools" \
  UV_TOOL_BIN_DIR="$H/.local/bin" UV_CACHE_DIR="$H/.cache/uv" UV_PYTHON_DOWNLOADS=never
unset PHIWARD_CONFIG PHIWARD_SPOOL XDG_CONFIG_HOME XDG_CACHE_HOME CLAUDE_CONFIG_DIR CLAUDE_PROJECT_DIR
umask 022
mkdir -p "$H/data/FAKE-PT-0001" "$H/proj" "$H/.config/phiward"
echo "FAKE-PT-0001 line" > "$H/data/FAKE-PT-0001/a.txt"
(cd "$H/proj" && git init -q)
"$uv" tool install -q --python "$H/py/bin/$pyname" "$wheel" > "$H/install.out" 2>&1 \
  || fail "uv tool install" "$H/install.out"
printf '[protected_paths]\nroots = ["%s/data"]\n[broker]\ncommands = ["wc"]\n' "$H" \
  > "$H/.config/phiward/config.toml"
cd "$H/proj"
phiward install claude --user --write --yes < /dev/null > "$H/wire.out" 2>&1 || fail "install" "$H/wire.out"
# as setup does after it writes the config: approve the listed programs (on a terminal)
printf 'y\ny\n' | script -q /dev/null phiward pin > "$H/pin.out" 2>&1 || fail "pin" "$H/pin.out"
phiward broker > "$H/broker.log" 2>&1 &
broker=$!
sleep 3
phiward doctor > "$H/doctor.out" 2>&1 || true
grep -q WARNING "$H/doctor.out" && fail "doctor has a WARNING" "$H/doctor.out"
cp "$here/srv.py" "$H/proj/srv.py"
printf '{"mcpServers": {"docs": {"command": "/usr/bin/python3", "args": ["%s/proj/srv.py"]}}}\n' "$H" \
  > "$H/.claude.json"
phiward mcp wrap docs --yes > "$H/wrap.out" 2>&1 || fail "mcp wrap" "$H/wrap.out"
phiward mcp list > "$H/list.out" 2>&1
grep -q "docs (~/.claude.json): wrapped" "$H/list.out" || fail "mcp list after wrap" "$H/list.out"
cd "$H/proj" && "$H/py/bin/$pyname" "$here/start.py" > "$H/start.out" 2>&1 || fail "the wrapped server" "$H/start.out"
grep -q answered "$H/start.out" || fail "the wrapped server did not answer" "$H/start.out"
grep -q READ-DENIED "$H/proj/probe.out" || fail "the wrapped server read the protected file" "$H/proj/probe.out"
grep -q "hook from project: exit 0" "$H/start.out" || fail "the hook from the project" "$H/start.out"
grep -q "hook from home: exit 0" "$H/start.out" || fail "the hook from the home folder" "$H/start.out"
phiward doctor > "$H/doctor2.out" 2>&1 || true
grep -q WARNING "$H/doctor2.out" && fail "doctor after wrap has a WARNING" "$H/doctor2.out"
ls "$H/Library/LaunchAgents" 2>/dev/null | grep -q . && fail "a launchd file was written"
echo "ok: macOS, $(basename "$base"), install, doctor, wrap, the wrapped server, the hook, doctor again"
