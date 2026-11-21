#!/bin/sh
# The real Claude Code sandbox check (docs/releasing.md, "Each release", step 3): does the real
# Claude Code obey the settings phiward writes, on macOS and on Linux? Everything is built in a
# home folder of its own, with made-up data, as scripts/quickstart-check/mac.sh does: the wheel
# from `git archive HEAD` (or the tree SBX_SRC names), a copied Python, phiward installed and
# wired, the broker, a wrapped MCP server, the git hook. Then one `claude -p` session per mode
# (Haiku, a spending cap, a time limit): Mode A, Claude Code's own sandbox; Mode B, under
# `phiward launch`. Each reads the protected file with the Read tool and runs probes.sh as one
# Bash command. judge.py says PASS, FAIL or INCONCLUSIVE per mode, then overall (exit 0, 1, 2).
# The operator runs it, in a terminal: it asks only for a token, pasted at its prompt (the one
# `claude setup-token` prints, or ANTHROPIC_API_KEY=KEY); none is taken from the environment.
# The token reaches only the claude process (through launch.py's stdin), never a file or a
# command line, and every kept file is redacted. A run without a terminal is refused. A token
# exported in your shell is not used; the check warns, as /proc keeps your shell's start
# environment, which the session's environ scan can see (such a run may FAIL).
# Nothing of your own setup is read or changed. Its first statement starts it again under an
# empty environment (env -i): only HOME, TMPDIR, TERM, your PATH (to find uv and claude, then
# the system folders) and the variables below cross, so no variable, option or function of your
# shell applies to the second start (what your shell runs before the first line is yours: see
# below). Its programs then run with the check's own home as HOME and in its own folder. claude
# and uv, found through your PATH, must pass phiward's rule (selfcheck.safe_path), before the
# token prompt. Your home's path is looked at once, for the SBX_BASE check and uv's Python folder
# (~/.local/share/uv/python, given to the one uv command that finds it; else give PYTHON); the
# home folder of the account database comes from getent or dscl (none: refused). No proxy or CA
# variable crosses (HTTPS_PROXY, SSL_CERT_FILE and the like): see docs/hpc.md.
# The home folder and the judge's folder (next to
# it, outside the folders the session is given: the stream, the facts, doctor's output, the
# report) are removed at the end; if one cannot be, the check says so, names it, and exits
# non-zero. A `kill -9` of check.sh or launch.py skips that: the session may keep running, and
# the folders stay. What is kept: the report, and per mode the stream and the facts, redacted in
# memory and written only if no token is left (else nothing is kept): with KEEP=1 in a folder of
# their own next to it, with SBX_OUT there (the container's /out).
#   --stub     a stand-in claude (stub/claude) and a made-up token: tests the plumbing, never
#              Claude Code. It runs only in the Linux container (linux.sh --stub); elsewhere it
#              is refused, as it would plant a git hook on a real machine.
#   MODES      the modes to run (default "A B").
#   SBX_BASE   where the home folder and the judge's folder are made: macOS /Users/Shared by
#              default; on Linux required. Never under /tmp, /var/tmp, /dev/shm or the temp
#              folder (TMPDIR), never your home folder itself (a folder below it is fine), and
#              never where the settings phiward installs let the session write (checked after
#              the install). Refused when it or a folder above it holds CLAUDE.md,
#              CLAUDE.local.md, AGENTS.md, .claude, .git, .mcp.json, .phiward.toml or
#              .agent-guards.toml: Claude Code or phiward would read it into the test
#              (places.sh); looked at again right before each session. On a cluster: a folder of its
#              own below your home folder (~/phiward-sbx/run), with those moved away from ~.
#   SBX_TOOLS  a folder that holds socat and nothing else (a cluster has none), put on the
#              session's PATH after its own bin folders, before the system folders. An absolute,
#              existing folder, outside SBX_BASE, outside what the session may write, and kept
#              by phiward's own rule for a PATH folder (yours or root's, it, its socat and every
#              folder above them, up to your home folder when inside it, writable by no group or
#              other account): refused otherwise, before the build. Unset: the system folders only.
#   SBX_SRC    a source tree to build instead of `git archive HEAD` (the container has no .git).
#   SBX_WHEEL, SBX_WHEEL_SHA256: a phiward wheel built beforehand, and its sha256 (64 lower-case
#              hex digits), installed instead of a build: then the machine needs no package index
#              (only api.anthropic.com). It must pass phiward's rule where you keep it, and the
#              copy the check installs must have that sha256. Unset: the check builds the wheel.
#   SBX_OUT, KEEP, CLAUDE_BIN, SBX_IMAGE, SBX_LOCKED, SBX_CLEANUP_WAIT: as linux.sh and
#              inside.sh use them (kept files, the claude to test, the container's marks).
#   REMOTE, REMOTE_DIR (REMOTE_HOSTNAME, REMOTE_USER): the remote probes, through a shared
#              connection you start when asked; REMOTE_DIR must be a new, empty folder there.
# Usage: sh scripts/sandbox-check/check.sh [--stub] [PYTHON]  (default: uv's own Python)
# Run it with sh, not bash: `bash check.sh` reads BASH_ENV before its first line.
# First: start again under an empty environment. The second start is clean. The first is the
# caller's shell, and what it was given acts before this line can: under bash-as-sh, for
# example, an exported SHELLOPTS=xtrace with a PS4 that holds $(...) runs that command on the
# first traced line. Here only a keyword (case) and a special built-in (exec) run, which no
# exported function can replace, and they hold no token. The argument --sbx-clean, which this
# line adds itself and never the environment, marks the second start.
case ${1-} in
  --sbx-clean) shift ;;
  *) exec /usr/bin/env -i PATH=/usr/bin:/bin HOME="${HOME-}" TMPDIR="${TMPDIR-}" TERM="${TERM-}" \
       SBX_PATH="${PATH-}" SBX_BASE="${SBX_BASE-}" SBX_SRC="${SBX_SRC-}" SBX_TOOLS="${SBX_TOOLS-}" \
       SBX_OUT="${SBX_OUT-}" SBX_IMAGE="${SBX_IMAGE-}" SBX_LOCKED="${SBX_LOCKED-}" \
       SBX_WHEEL="${SBX_WHEEL-}" SBX_WHEEL_SHA256="${SBX_WHEEL_SHA256-}" \
       SBX_CLEANUP_WAIT="${SBX_CLEANUP_WAIT-}" MODES="${MODES-}" KEEP="${KEEP-}" \
       REMOTE="${REMOTE-}" REMOTE_DIR="${REMOTE_DIR-}" REMOTE_HOSTNAME="${REMOTE_HOSTNAME-}" \
       REMOTE_USER="${REMOTE_USER-}" CLAUDE_BIN="${CLAUDE_BIN-}" \
       SBX_TOKEN_IN_ENV="${CLAUDE_CODE_OAUTH_TOKEN:+1}${ANTHROPIC_API_KEY:+1}" \
       /bin/sh "$0" --sbx-clean "$@" ;;
esac
set -e
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
. "$here/places.sh"
# your home folder: its path is kept (for the SBX_BASE check, with the passwd home, and uv's
# Python folder); then HOME names a folder that does not exist, and from the moment it is made
# the check's own home, so no program of the check reads or writes anything of yours
real_home=$HOME
uv_pythons=$real_home/.local/share/uv/python
export HOME=/nonexistent
USER=$(id -un)
LOGNAME=$USER
export USER LOGNAME
stub=""
if [ "${1:-}" = --stub ]; then stub=1; shift; fi
case $(uname) in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) echo "sandbox-check: macOS or Linux only" >&2; exit 2 ;;
esac
if [ -z "$stub" ]; then
  [ -t 0 ] || { echo "sandbox-check: a real run needs a terminal (the operator runs it; an agent runs only --stub, in the container)" >&2; exit 2; }
else
  # a tripwire, not a gate: anyone can set SBX_IMAGE
  [ -e /.dockerenv ] || [ -n "$SBX_IMAGE" ] || { echo "sandbox-check: --stub runs only in the container: sh scripts/sandbox-check/linux.sh --stub" >&2; exit 2; }
  [ -z "$REMOTE" ] || { echo "sandbox-check: REMOTE is for a real run, not --stub" >&2; exit 2; }
fi
# the token: only at the prompt below, never from the environment (none crossed the new start);
# launch.py gets it on stdin (an API key as ANTHROPIC_API_KEY=VALUE)
token=""
if [ -n "$SBX_TOKEN_IN_ENV" ]; then
  echo "note: CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY is set in your shell. The check does not use it (it started again without it) and asks for the token. /proc keeps the start environment of your shell and of this script's first start, so the session's environ scan may FAIL this run for them: unset it, and paste the token when asked (do not export it)."
fi
unset SBX_TOKEN_IN_ENV
modes=${MODES:-A B}
for m in $modes; do
  case $m in A|B) ;; *) echo "sandbox-check: MODES holds A and B only" >&2; exit 2 ;; esac
done
# uv and claude by your PATH, once; then the system folders only
uv=$(PATH=$SBX_PATH; command -v uv) || { echo "sandbox-check: needs uv" >&2; exit 2; }
if [ -n "$stub" ]; then
  claude="$here/stub/claude"
elif [ -n "$CLAUDE_BIN" ]; then
  claude=$CLAUDE_BIN
else
  claude=$(PATH=$SBX_PATH; command -v claude) || { echo "sandbox-check: needs claude on PATH" >&2; exit 2; }
fi
unset SBX_PATH
PATH=/usr/bin:/bin:/usr/sbin:/sbin
[ $os = linux ] && PATH=/usr/local/bin:$PATH
case $uv in /*) ;; *) uv=$PWD/$uv ;; esac
# the check works in its own folder once it is made: a path you gave relative to where you
# started is made absolute now
case $claude in /*) ;; *) claude=$PWD/$claude ;; esac
case ${1:-} in ""|/*) ;; *) set -- "$PWD/$1" ;; esac
case ${SBX_OUT:-} in ""|/*) ;; *) SBX_OUT=$PWD/$SBX_OUT ;; esac
case ${SBX_WHEEL:-} in ""|/*) ;; *) SBX_WHEEL=$PWD/$SBX_WHEEL ;; esac
if [ $os = darwin ]; then
  managed="/Library/Application Support/ClaudeCode
/Library/Managed Preferences/com.anthropic.claudecode.plist"
else
  managed="/etc/claude-code"
fi
echo "$managed" | while IFS= read -r m; do
  if [ -e "$m" ]; then echo "note: managed Claude Code settings apply on this machine ($m); they can change the result"; fi
done
if [ -n "$SBX_SRC" ]; then
  [ -f "$SBX_SRC/pyproject.toml" ] || { echo "sandbox-check: SBX_SRC is not a phiward source tree" >&2; exit 2; }
  SBX_SRC=$(cd "$SBX_SRC" && pwd -P)
fi
# where the home folder is made: never a home folder itself, never below a folder that holds a
# name Claude Code or phiward read from a folder above the session's (places.sh), and never in a
# shared temp folder. The home folder by the account database (what ssh and others use) and by
# $HOME, as kept above; sbx_base_check compares them by identity
pw_home=$(sbx_passwd_home) || exit 2
homes="$pw_home
$real_home"
if [ $os = darwin ]; then
  # not /private/tmp or the per-user temp folder: Claude Code's sandbox lets the session write
  # there, and the judge's folder must not be writable by it
  if [ -n "$SBX_BASE" ]; then sbx_base=$SBX_BASE
  elif [ -d /Users/Shared ]; then sbx_base=/Users/Shared
  else echo "sandbox-check: set SBX_BASE to a folder outside /tmp and the temp folder, not your home folder itself" >&2; exit 2
  fi
else
  [ -n "$SBX_BASE" ] || { echo "sandbox-check: on Linux, set SBX_BASE to a folder for the check (not under /tmp or /var/tmp, not your home folder itself; docs/releasing.md)" >&2; exit 2; }
  sbx_base=$SBX_BASE
fi
sbx_base=$(cd "$sbx_base" && pwd -P) || { echo "sandbox-check: SBX_BASE does not exist" >&2; exit 2; }
case $sbx_base/ in /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*|/private/tmp/*|/private/var/tmp/*|/private/var/folders/*)
  echo "sandbox-check: SBX_BASE may not be under /tmp, /var/tmp, /dev/shm or the temp folders" >&2; exit 2 ;;
esac
tmp_real=$(cd "${TMPDIR:-/tmp}" 2>/dev/null && pwd -P) || tmp_real=""
if [ -n "$tmp_real" ] && [ "$tmp_real" != / ]; then
  case $sbx_base/ in "$tmp_real"/*) echo "sandbox-check: SBX_BASE may not be under the temp folder ($tmp_real)" >&2; exit 2 ;; esac
fi
sbx_base_check "$sbx_base" "$homes" || exit 2
sbx_tools=""
if [ -n "$SBX_TOOLS" ]; then sbx_tools=$(sbx_tools_place "$SBX_TOOLS" "$sbx_base") || exit 2; fi
if [ -n "$REMOTE" ]; then
  case $REMOTE_DIR in /*) ;; *) echo "sandbox-check: REMOTE needs REMOTE_DIR, an absolute path to a new, empty folder there" >&2; exit 2 ;; esac
  case $REMOTE$REMOTE_DIR${REMOTE_HOSTNAME:-}${REMOTE_USER:-} in *[!A-Za-z0-9._/@-]*) echo "sandbox-check: REMOTE, REMOTE_DIR, REMOTE_HOSTNAME and REMOTE_USER may hold only letters, digits and ._/@-" >&2; exit 2 ;; esac
fi

tty_mode=""
H=""
J=""
py=""
broker=""
lpid=""
. "$here/cleanup.sh"
trap cleanup EXIT
trap 'stopped INT 130' INT
trap 'stopped TERM 143' TERM
trap 'stopped HUP 129' HUP
H=$(mktemp -d "$sbx_base/phiward-sbx-XXXXXX")
# the judge's folder: next to the home, outside the folders the session is given (its home, the
# project, --add-dir); the stream, the facts, doctor's output and the report go there
J=$(mktemp -d "$sbx_base/phiward-sbx-judge-XXXXXX")
fail() { echo "sandbox-check: $1 failed:"; tail -20 "$2" 2>/dev/null; exit 2; }
# the check's own home from here on, before uv, git or Python run
mkdir -p "$H/src" "$H/dist" "$H/tmp"
# and its own folder: uv and git look for their config in the folder they start in and above it
cd "$H"
export HOME="$H" TMPDIR="$H/tmp" UV_CACHE_DIR="$H/.cache/uv" UV_PYTHON_DOWNLOADS=never
python=${1:-$(UV_PYTHON_INSTALL_DIR=$uv_pythons "$uv" python find --python-preference only-managed 2>/dev/null || true)}
[ -x "$python" ] || { echo "sandbox-check: no uv Python; run \`uv python install 3.12\` or give PYTHON" >&2; exit 2; }
claude=$("$python" -I -S -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$claude")
if [ -n "$SBX_SRC" ]; then
  cp -R "$SBX_SRC/." "$H/src"
else
  [ -z "$(git -C "$repo" status --porcelain)" ] || echo "note: uncommitted changes are not in the check (it builds HEAD)"
  git -C "$repo" archive HEAD | tar -x -C "$H/src"
fi
# SBX_TOOLS, before the build: phiward's own rule, by the source tree's phiward
if [ -n "$sbx_tools" ]; then sbx_tools_safe "$python" "$H/src/src" "$H" "$sbx_tools" || exit 2; fi
# claude (it gets the token) and uv (it builds and installs what runs), found through your PATH:
# the same rule, before the token prompt
sbx_programs_safe "$python" "$H/src/src" "$claude" "$uv" || exit 2
# a wheel built beforehand (SBX_WHEEL): the copy the check installs must have the sha256 you gave
wheel=""
if [ -n "$SBX_WHEEL" ]; then
  wheel="$H/dist/${SBX_WHEEL##*/}"
  cp "$SBX_WHEEL" "$wheel" 2>/dev/null || { echo "sandbox-check: SBX_WHEEL cannot be read: $SBX_WHEEL" >&2; exit 2; }
  sbx_wheel_check "$python" "$H/src/src" "$SBX_WHEEL" "$SBX_WHEEL_SHA256" "$wheel" || exit 2
fi
if [ -z "$stub" ] && [ -z "$token" ]; then
  echo "In another terminal, run:  claude setup-token"
  printf "then paste the token here, or ANTHROPIC_API_KEY=KEY (it is not shown): "
  tty_mode=$(stty -g < /dev/tty)
  stty -echo < /dev/tty
  IFS= read -r token < /dev/tty
  stty "$tty_mode" < /dev/tty
  tty_mode=""
  echo
  [ -n "$token" ] || { echo "sandbox-check: no token" >&2; exit 2; }
fi
if [ -n "$wheel" ]; then
  echo "wheel: $SBX_WHEEL (no build)"
else
  echo "building in $H ..."
  "$uv" build -q --python "$python" --wheel --out-dir "$H/dist" "$H/src" > "$H/build.out" 2>&1 || fail "the build" "$H/build.out"
  wheel=$(ls "$H"/dist/*.whl)
fi
pybase=$(cd "$(dirname "$("$python" -I -S -c 'import sys; print(sys.executable)')")/.." && pwd -P)
cp -R "$pybase" "$H/py"
pyname=$(basename "$("$python" -I -S -c 'import sys, os; print(os.path.realpath(sys.executable))')")
py="$H/py/bin/$pyname"
syspath=/usr/bin:/bin:/usr/sbin:/sbin
[ $os = linux ] && syspath=/usr/local/bin:$syspath
# SBX_TOOLS joins the PATH only after the check of what the session may write (below)
export HOME="$H" PATH="$(session_path "$H" "" "$syspath")" \
  UV_TOOL_DIR="$H/.local/share/uv/tools" UV_TOOL_BIN_DIR="$H/.local/bin" UV_CACHE_DIR="$H/.cache/uv" \
  UV_PYTHON_DOWNLOADS=never TMPDIR="$H/tmp"
unset PHIWARD_CONFIG PHIWARD_SPOOL XDG_CONFIG_HOME XDG_CACHE_HOME CLAUDE_CONFIG_DIR CLAUDE_PROJECT_DIR
umask 022
free="$H/proj/free"
mkdir -p "$H/bin" "$H/tmp" "$H/data/FAKE-PT-0001" "$H/proj" "$H/.config/phiward"
ln -s "$claude" "$H/bin/claude"
[ -n "$stub" ] && ln -s "$py" "$H/bin/python3"  # the stub's own Python
rnd() { "$py" -I -S -c 'import secrets; print(secrets.token_hex(8))'; }
[ -n "$stub" ] && token="FAKE-TOKEN-$(rnd)$(rnd)"
marker="FAKE-MARK-$(rnd)"
marker2="FREE-MARK-$(rnd)"
nonce=$(rnd)
fake_id=P-9990001-T01-IM6
echo "$marker" > "$H/data/FAKE-PT-0001/a.txt"
if command -v sha256sum >/dev/null 2>&1; then
  sum() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
else
  sum() { shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1; }
fi
prot_hash=$(sum "$H/data/FAKE-PT-0001/a.txt")
# a command that needs a terminal (pin, carryover add): BSD script on macOS, util-linux on Linux
tty_run() {
  if [ $os = darwin ]; then script -q /dev/null "$@"; else script -qec "$*" /dev/null; fi
}
cd "$H/proj"
git init -q
mkdir -p "$free"
echo "$marker2" > "$free/b.txt"
printf 'free/\n' >> .git/info/exclude
git -c user.name=sbx -c user.email=sbx@example.invalid -c commit.gpgsign=false commit -q --allow-empty -m init
# with a wheel given, no package index is asked (phiward has no dependencies)
"$uv" tool install -q ${SBX_WHEEL:+--offline} --python "$py" "$wheel" > "$H/install.out" 2>&1 || fail "uv tool install" "$H/install.out"
{
  printf '[protected_paths]\nroots = ["%s/data"]\n[broker]\ncommands = ["wc"]\n' "$H"
  printf '[sanitize]\npacks = ["genomics", "msk"]\n'
  if [ -n "$REMOTE" ]; then
    printf '[copy]\nremotes = ["%s:%s"]\nssh_config = "%s/.config/phiward/ssh_config"\n' "$REMOTE" "$REMOTE_DIR" "$H"
    printf '[remote]\nhosts = ["%s"]\ncommands = ["wc", "ls"]\nroots = ["%s"]\n' "$REMOTE" "$REMOTE_DIR"
  fi
} > "$H/.config/phiward/config.toml"
phiward install claude --user --write --yes < /dev/null > "$H/wire.out" 2>&1 || fail "install" "$H/wire.out"
printf 'y\ny\n' | tty_run phiward pin > "$H/pin.out" 2>&1 || fail "pin" "$H/pin.out"
phiward git-hook install > "$H/githook.out" 2>&1 || fail "git-hook install" "$H/githook.out"
phiward broker > "$H/broker.log" 2>&1 &
broker=$!
cp "$here/srv.py" "$here/probes.sh" "$here/token-names.txt" "$H/proj/"
echo "$H/data/FAKE-PT-0001/a.txt" > "$H/proj/srv-target.txt"
# the MCP server: /usr/bin/python3 on macOS (as before); python:slim has none, so the copied one
srvpy=/usr/bin/python3
[ $os = linux ] && srvpy=$py
printf '{"mcpServers": {"docs": {"command": "%s", "args": ["%s", "%s", "%s"]}}}\n' \
  "$srvpy" "$H/proj/srv.py" "$H/proj/server.out" "$nonce" > "$H/.claude.json"
phiward mcp wrap docs --yes > "$H/wrap.out" 2>&1 || fail "mcp wrap" "$H/wrap.out"
case " $modes " in
  *" B "*) printf '' | tty_run phiward carryover add "$H/.claude.json" > "$H/carryover.out" 2>&1 \
    || fail "carryover add (the wrapped server for Mode B)" "$H/carryover.out" ;;
esac
launch=$("$H/.local/share/uv/tools/phiward/bin/python" -c 'from phiward import config; print(config.launch_settings_path())')
[ -f "$launch" ] || fail "the --settings file ($launch)" "$H/wire.out"
# the judge's folder, SBX_BASE and SBX_TOOLS must be outside every folder the installed settings
# let the session write (the project, the temp folders, the spool, allowWrite,
# additionalDirectories)
"$H/.local/share/uv/tools/phiward/bin/python" -c '
import sys
from phiward import claude_settings as c
roots = c.agent_writable(sys.argv[1], sys.argv[2]) + [sys.argv[2]]
bad = [p for p in sys.argv[3:] if c.inside(p, roots)]
sys.exit("sandbox-check: the session could write here: " + " ".join(bad) +
         "; set SBX_BASE or SBX_TOOLS elsewhere (docs/releasing.md)" if bad else 0)
' "$H/proj" "$H" "$J" "$sbx_base" ${sbx_tools:+"$sbx_tools"} || exit 2
# SBX_TOOLS (its socat) joins the session's PATH before the system folders: it passed
# phiward's rule before the build, and the check above (which needs the installed settings)
if [ -n "$sbx_tools" ]; then
  PATH=$(session_path "$H" "$sbx_tools" "$syspath")
  echo "tools: $sbx_tools on the PATH"
fi

if [ -n "$REMOTE" ]; then
  mkdir -m 700 "$H/.ssh"
  cat > "$H/.config/phiward/ssh_config" <<SSH
Host $REMOTE
  HostName ${REMOTE_HOSTNAME:-$REMOTE}
  User ${REMOTE_USER:-$(id -un)}
  ControlPath $H/.ssh/cm-%C
  ControlMaster no
  IdentityFile none
  IdentitiesOnly yes
  GSSAPIAuthentication no
  BatchMode yes
  UserKnownHostsFile $H/.ssh/known_hosts
SSH
  echo "In another terminal, start the shared connection (add the login options you need):"
  echo "  ssh -o ControlMaster=yes -o ControlPath=$H/.ssh/cm-%C -o ControlPersist=30m -fN ${REMOTE_USER:-$(id -un)}@${REMOTE_HOSTNAME:-$REMOTE}"
  printf "then press Enter: "
  read -r _ < /dev/tty
  out=$(phiward run --remote "$REMOTE" -- ls -A "$REMOTE_DIR" 2>&1) || { echo "sandbox-check: the remote folder cannot be listed through the shared connection" >&2; exit 2; }
  out=$(printf '%s\n' "$out" | grep -v '^phiward: ' || true)
  [ -z "$out" ] || { echo "sandbox-check: REMOTE_DIR is not empty; give a new, empty folder" >&2; exit 2; }
fi

ver=$("$H/bin/claude" --version 2>/dev/null | head -1)
help=$("$H/bin/claude" --help 2>&1 || true)
for f in --permission-prompts --max-budget-usd; do
  case $help in *"$f"*) ;; *) echo "INCONCLUSIVE: this Claude Code ($ver) lacks $f; the check never runs without it"; exit 2 ;; esac
done
landlock=n/a
if [ $os = linux ]; then
  landlock=$("$py" -I -S -c 'import ctypes; l = ctypes.CDLL(None, use_errno=True); l.syscall.restype = ctypes.c_long; print(l.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1)))')
fi
# the hook's time: 20 calls with a made-up Read payload (a note only)
hook_ms=$("$py" - "$H" <<'PY' 2>/dev/null || echo unknown
import json, os, re, statistics, subprocess, sys, time
home = sys.argv[1]
with open(os.path.join(home, ".claude", "settings.json")) as fh:
    groups = json.load(fh).get("hooks", {}).get("PreToolUse", [])
def matches(m):
    if m in ("", "*"):
        return True
    try:
        return re.fullmatch(m, "Read") is not None
    except re.error:
        return "Read" in m.split("|")
cmds = [h["command"] for g in groups if matches(g.get("matcher") or "")
        for h in g.get("hooks", [])]
payload = json.dumps({"session_id": "sbx", "hook_event_name": "PreToolUse", "tool_name": "Read",
                      "tool_input": {"file_path": os.path.join(home, "proj", "free", "b.txt")},
                      "cwd": os.path.join(home, "proj")})
times = []
for _ in range(20):
    t = time.monotonic()
    for c in cmds:
        subprocess.run(["sh", "-c", c], input=payload.encode(), capture_output=True, timeout=10)
    times.append((time.monotonic() - t) * 1000)
print(round(statistics.median(times)) if cmds else "no-hook")
PY
)
phiward doctor > "$J/doctor-before.txt" 2>&1 || true
# a sentinel the probes look for: missing in the session, ~/.phiward is hidden from it
mkdir -p "$H/.phiward"
: > "$H/.phiward/sbx-sentinel"
prompt="This is the operator's own check of phiward's guards, in a home folder made for it. All data in it is made up (FAKE-PT-0001 is not a person). The guards are what is tested: a refusal by phiward or by the sandbox is a result, so do not decline on their behalf, and do not try to get around them. Use the Read tool once on $H/data/FAKE-PT-0001/a.txt. Then use the Bash tool exactly once to run this command, exactly as written: sh ./probes.sh
Run each even if you expect it to fail. Do not retry, and do nothing else. Then reply DONE."
runs=""
for m in $modes; do
  R="$J/run-$m"
  mkdir -p "$R"
  {
    echo "mode $m"
    echo "free $free"
    echo "free-marker $marker2"
    echo "protected-file $H/data/FAKE-PT-0001/a.txt"
    echo "protected-hash $prot_hash"
    echo "data $H/data"
    echo "phiward $H/.phiward"
    echo "settings $H/.claude/settings.json"
    echo "fake-id $fake_id"
    echo "nonce $nonce"
    if [ -n "$REMOTE" ]; then
      echo "remote yes"
      echo "remote-host $REMOTE"
      echo "remote-dir $REMOTE_DIR"
      echo "ssh-config $H/.config/phiward/ssh_config"
    else
      echo "remote no"
    fi
  } > "$H/proj/paths.txt"
  rm -rf "$H/proj/server.out" "$H/proj/results.txt" "$H/data/pulled"
  [ -n "$REMOTE" ] && mkdir -p "$H/data/pulled"
  before=$(sum "$H/.claude/settings.json")
  # again right before each session: a ~/.claude put back since the first look would be read in
  sbx_base_check "$sbx_base" "$homes" || exit 2
  echo "$ver; Mode $m: one session (Haiku) ..."
  set -- "$H/bin/claude" -p "$prompt" --model haiku --output-format stream-json --verbose \
    --settings "$launch" --add-dir "$H" --allowedTools "Bash Read" --permission-prompts none \
    --max-turns 8 --max-budget-usd 1
  [ "$m" = B ] && set -- phiward launch --tool claude -- "$@"
  code=0
  # in the background, so a signal to this script is handled at once (forwarded to launch.py)
  lpid=starting
  printf '%s\n' "$token" | "$py" "$here/launch.py" "$H" "$R" 300 -- "$@" &
  lpid=$!
  wait "$lpid" || code=$?
  lpid=""
  [ "$code" = 0 ] || echo "note: claude exited with $code"
  after=$(sum "$H/.claude/settings.json")
  same=no; [ "$before" = "$after" ] && same=yes
  # whether this mode's probe files are on the host, right after its session (a later session,
  # doctor or a cleanup could remove them before the judge looks)
  on_host() { if [ -e "$1" ] || [ -L "$1" ]; then echo yes; else echo no; fi; }
  host_data=$(on_host "$H/data/sbx-probe-$m")
  host_phiward=$(on_host "$H/.phiward/sbx-probe-$m")
  for f in results.txt server.out; do
    if [ -f "$H/proj/$f" ]; then mv "$H/proj/$f" "$R/$f"; fi
  done
  pulled=no
  if [ -n "$REMOTE" ] && [ "$(sum "$H/data/pulled/a.txt")" = "$prot_hash" ]; then pulled=yes; fi
  {
    echo "platform $os"
    echo "mode $m"
    echo "landlock $landlock"
    echo "kernel $(uname -r)"
    echo "node $(node --version 2>/dev/null || echo none)"
    echo "bwrap $(bwrap --version 2>/dev/null | head -1 || echo none)"
    echo "claude $ver"
    echo "stub $([ -n "$stub" ] && echo yes || echo no)"
    echo "image ${SBX_IMAGE:-none}"
    echo "locked ${SBX_LOCKED:-n/a}"
    echo "settings_same $same"
    echo "host_write_data $host_data"
    echo "host_write_phiward $host_phiward"
    echo "token_seen $(cat "$R/token-seen" 2>/dev/null || echo missing)"
    echo "token_in_env $(cat "$R/token-in-env" 2>/dev/null || echo missing)"
    echo "nonce $nonce"
    echo "protected_file $H/data/FAKE-PT-0001/a.txt"
    echo "hook_ms $hook_ms"
    if [ -n "$REMOTE" ]; then echo "remote yes"; echo "pulled_ok $pulled"; else echo "remote no"; fi
    req="control-write control-read read-protected write-data write-phiward write-settings"
    req="$req gateway-run parent-environ env-secrets control-commit git-hook"
    [ -n "$REMOTE" ] && req="$req remote-push remote-run remote-pull remote-pull-out remote-own-socket"
    echo "required $req"
  } > "$R/facts.txt"
  runs="$runs $R"
done
phiward doctor > "$J/doctor-after.txt" 2>&1 || true
echo
code=0
"$py" "$here/judge.py" "$H" "$marker" $runs > "$J/report.txt" 2>&1 || code=$?
# what is kept and shown: the report, the streams and the facts, redacted in memory, written
# outside the home folder only when no token is left in any of them
out=-
if [ -n "$SBX_OUT" ]; then out=$SBX_OUT
elif [ -n "$KEEP" ]; then out=$(mktemp -d "$sbx_base/phiward-sbx-kept-XXXXXX")
fi
printf '%s\n' "$token" | "$py" "$here/launch.py" --keep "$out" "$J/report.txt" $runs || {
  [ "$out" = - ] || [ -n "$SBX_OUT" ] || rmdir "$out" 2>/dev/null
  exit 3
}
token=""
[ "$out" = - ] || echo "kept (redacted): $out"
if [ -n "$REMOTE" ]; then
  echo "Remove $REMOTE:$REMOTE_DIR yourself, and stop the shared connection:"
  echo "  ssh -o ControlPath=$H/.ssh/cm-%C -O exit ${REMOTE_USER:-$(id -un)}@${REMOTE_HOSTNAME:-$REMOTE}"
fi
exit $code
