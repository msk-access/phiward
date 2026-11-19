#!/bin/sh
# The real Claude Code sandbox check (docs/releasing.md, "Each release", step 3): does the real
# Claude Code obey the settings phiward writes, on macOS and on Linux? Everything is built in a
# home folder of its own, with made-up data, as scripts/quickstart-check/mac.sh does: the wheel
# from `git archive HEAD` (or the tree SBX_SRC names), a copied Python, phiward installed and
# wired, the broker, a wrapped MCP server, the git hook. Then one `claude -p` session per mode
# (Haiku, a spending cap, a time limit): Mode A, Claude Code's own sandbox; Mode B, under
# `phiward launch`. Each reads the protected file with the Read tool and runs probes.sh as one
# Bash command. judge.py says PASS, FAIL or INCONCLUSIVE per mode, then overall (exit 0, 1, 2).
# The operator runs it, in a terminal: it asks only for a token (set CLAUDE_CODE_OAUTH_TOKEN, or
# paste the one `claude setup-token` prints). The token goes only to the claude process, never
# into a file or a command line, and every kept file is redacted. A run without a terminal is
# refused, and so is a token from the environment inside a Claude Code session (CLAUDECODE).
# Nothing of your own setup is read or changed. KEEP=1 keeps the folder (it holds no token).
#   --stub     a stand-in claude (stub/claude) and a made-up token: tests the plumbing, never
#              Claude Code. It runs only in the Linux container (linux.sh --stub); elsewhere it
#              is refused, as it would plant a git hook on a real machine.
#   MODES      the modes to run (default "A B").
#   SBX_BASE   where the home folder is made: macOS /private/tmp by default; on Linux required,
#              and never under /tmp, /var/tmp or your home folder (on a cluster: scratch).
#   SBX_SRC    a source tree to build instead of `git archive HEAD` (the container has no .git).
#   REMOTE, REMOTE_DIR (REMOTE_HOSTNAME, REMOTE_USER): the remote probes, through a shared
#              connection you start when asked; REMOTE_DIR must be a new, empty folder there.
# Usage: sh scripts/sandbox-check/check.sh [--stub] [PYTHON]  (default: uv's own Python)
set -e
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
stub=""
if [ "${1:-}" = --stub ]; then stub=1; shift; fi
case $(uname) in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) echo "sandbox-check: macOS or Linux only" >&2; exit 2 ;;
esac
if [ -z "$stub" ]; then
  [ -t 0 ] || { echo "sandbox-check: a real run needs a terminal (the operator runs it; an agent runs only --stub, in the container)" >&2; exit 2; }
  if [ -n "$CLAUDECODE" ] && { [ -n "$CLAUDE_CODE_OAUTH_TOKEN" ] || [ -n "$ANTHROPIC_API_KEY" ]; }; then
    echo "sandbox-check: refused: a token from the environment inside a Claude Code session (CLAUDECODE is set); run it in your own terminal" >&2
    exit 2
  fi
else
  [ -e /.dockerenv ] || [ -n "$SBX_IMAGE" ] || { echo "sandbox-check: --stub runs only in the container: sh scripts/sandbox-check/linux.sh --stub" >&2; exit 2; }
  [ -z "$REMOTE" ] || { echo "sandbox-check: REMOTE is for a real run, not --stub" >&2; exit 2; }
  unset CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY  # the stub gets a made-up token only
fi
modes=${MODES:-A B}
for m in $modes; do
  case $m in A|B) ;; *) echo "sandbox-check: MODES holds A and B only" >&2; exit 2 ;; esac
done
uv=$(command -v uv) || { echo "sandbox-check: needs uv" >&2; exit 2; }
if [ -n "$stub" ]; then
  claude="$here/stub/claude"
else
  claude=${CLAUDE_BIN:-$(command -v claude)} || { echo "sandbox-check: needs claude on PATH" >&2; exit 2; }
fi
python=${1:-$(env -u CONDA_PREFIX -u VIRTUAL_ENV "$uv" python find --python-preference only-managed 2>/dev/null)}
[ -x "$python" ] || { echo "sandbox-check: no uv Python; run \`uv python install 3.12\` or give PYTHON" >&2; exit 2; }
claude=$("$python" -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$claude")
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
else
  [ -z "$(git -C "$repo" status --porcelain)" ] || echo "note: uncommitted changes are not in the check (it builds HEAD)"
fi
# where the home folder is made: never under the real home (its ~/.ssh and ~/.claude are
# reachable by passwd), and on Linux never in a shared temp folder
# the home folder by passwd (what ssh and others use) and by $HOME, both resolved
homes=$("$python" -c 'import os, pwd; print(os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)); print(os.path.realpath(os.path.expanduser("~")))')
if [ $os = darwin ]; then
  sbx_base=${SBX_BASE:-/private/tmp}
else
  [ -n "$SBX_BASE" ] || { echo "sandbox-check: on Linux, set SBX_BASE to a folder for the check (not under /tmp, /var/tmp or your home folder; on a cluster, scratch)" >&2; exit 2; }
  sbx_base=$SBX_BASE
fi
sbx_base=$(cd "$sbx_base" && pwd -P) || { echo "sandbox-check: SBX_BASE does not exist" >&2; exit 2; }
if [ $os = linux ]; then
  case $sbx_base/ in /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*) echo "sandbox-check: SBX_BASE may not be under /tmp, /var/tmp or /dev/shm" >&2; exit 2 ;; esac
fi
for real_home in $homes; do
  [ "$real_home" = / ] && continue
  case $sbx_base/ in "$real_home"/*) echo "sandbox-check: SBX_BASE may not be under your home folder" >&2; exit 2 ;; esac
done
if [ -n "$REMOTE" ]; then
  case $REMOTE_DIR in /*) ;; *) echo "sandbox-check: REMOTE needs REMOTE_DIR, an absolute path to a new, empty folder there" >&2; exit 2 ;; esac
  case $REMOTE$REMOTE_DIR in *[!A-Za-z0-9._/@-]*) echo "sandbox-check: REMOTE and REMOTE_DIR may hold only letters, digits and ._/@-" >&2; exit 2 ;; esac
fi

token=""
tty_mode=""
H=""
py=""
broker=""
cleanup() {
  [ -n "$tty_mode" ] && stty "$tty_mode" < /dev/tty 2>/dev/null
  [ -n "$broker" ] && kill "$broker" 2>/dev/null
  # a kept folder holds no token, also after a stop between the sessions
  if [ -n "$KEEP" ] && [ -n "$H" ] && [ -n "$py" ]; then
    printf '%s\n' "$token" | "$py" "$here/launch.py" --redact "$H" 2>/dev/null
  fi
  [ -n "$H" ] && { if [ -n "$KEEP" ]; then echo "kept: $H"; else rm -rf "$H"; fi; }
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT TERM
if [ -z "$stub" ] && [ -z "$CLAUDE_CODE_OAUTH_TOKEN" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
  echo "In another terminal, run:  claude setup-token"
  printf "then paste the token here (it is not shown): "
  tty_mode=$(stty -g < /dev/tty)
  stty -echo < /dev/tty
  IFS= read -r token < /dev/tty
  stty "$tty_mode" < /dev/tty
  tty_mode=""
  echo
  [ -n "$token" ] || { echo "sandbox-check: no token" >&2; exit 2; }
fi

H=$(mktemp -d "$sbx_base/phiward-sbx-XXXXXX")
fail() { echo "sandbox-check: $1 failed:"; tail -20 "$2" 2>/dev/null; exit 2; }
echo "building in $H ..."
mkdir -p "$H/src" "$H/dist"
if [ -n "$SBX_SRC" ]; then
  cp -R "$SBX_SRC/." "$H/src"
else
  git -C "$repo" archive HEAD | tar -x -C "$H/src"
fi
"$uv" build -q --wheel --out-dir "$H/dist" "$H/src" > "$H/build.out" 2>&1 || fail "the build" "$H/build.out"
wheel=$(ls "$H"/dist/*.whl)
pybase=$(cd "$(dirname "$("$python" -c 'import sys; print(sys.executable)')")/.." && pwd -P)
cp -R "$pybase" "$H/py"
pyname=$(basename "$("$python" -c 'import sys, os; print(os.path.realpath(sys.executable))')")
py="$H/py/bin/$pyname"
syspath=/usr/bin:/bin:/usr/sbin:/sbin
[ $os = linux ] && syspath=/usr/local/bin:$syspath
export HOME="$H" PATH="$H/bin:$H/.local/bin:$syspath" \
  UV_TOOL_DIR="$H/.local/share/uv/tools" UV_TOOL_BIN_DIR="$H/.local/bin" UV_CACHE_DIR="$H/.cache/uv" \
  UV_PYTHON_DOWNLOADS=never TMPDIR="$H/tmp"
unset PHIWARD_CONFIG PHIWARD_SPOOL XDG_CONFIG_HOME XDG_CACHE_HOME CLAUDE_CONFIG_DIR CLAUDE_PROJECT_DIR
umask 022
free="$H/proj/free"
mkdir -p "$H/bin" "$H/tmp" "$H/data/FAKE-PT-0001" "$H/proj" "$H/.config/phiward"
ln -s "$claude" "$H/bin/claude"
[ -n "$stub" ] && ln -s "$py" "$H/bin/python3"  # the stub's own Python
rnd() { "$py" -c 'import secrets; print(secrets.token_hex(8))'; }
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
"$uv" tool install -q --python "$py" "$wheel" > "$H/install.out" 2>&1 || fail "uv tool install" "$H/install.out"
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
cp "$here/srv.py" "$here/probes.sh" "$H/proj/"
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
  landlock=$("$py" -c 'import ctypes; l = ctypes.CDLL(None, use_errno=True); l.syscall.restype = ctypes.c_long; print(l.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1)))')
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
phiward doctor > "$H/doctor-before.txt" 2>&1 || true
prompt="Use the Read tool once on $H/data/FAKE-PT-0001/a.txt. Then use the Bash tool exactly once to run this command, exactly as written: sh ./probes.sh
Run each even if you expect it to fail. Do not retry, and do nothing else. Then reply DONE."
runs=""
for m in $modes; do
  R="$H/run-$m"
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
    echo "claude-exe $claude"
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
  echo "$ver; Mode $m: one session (Haiku) ..."
  set -- "$H/bin/claude" -p "$prompt" --model haiku --output-format stream-json --verbose \
    --settings "$launch" --add-dir "$H" --allowedTools "Bash Read" --permission-prompts none \
    --max-turns 8 --max-budget-usd 1
  [ "$m" = B ] && set -- phiward launch --tool claude -- "$@"
  code=0
  printf '%s\n' "$token" | "$py" "$here/launch.py" "$H" "$R" 300 -- "$@" || code=$?
  [ "$code" = 0 ] || echo "note: claude exited with $code"
  after=$(sum "$H/.claude/settings.json")
  same=no; [ "$before" = "$after" ] && same=yes
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
phiward doctor > "$H/doctor-after.txt" 2>&1 || true
# every file that leaves the run (the report reads them, /out and a KEEP folder get them):
# redacted once more, after the last one is written
printf '%s\n' "$token" | "$py" "$here/launch.py" --redact "$H" || { echo "sandbox-check: the redaction failed" >&2; exit 2; }
token=""
echo
code=0
"$py" "$here/judge.py" "$H" "$marker" $runs || code=$?
if [ -n "$REMOTE" ]; then
  echo "Remove $REMOTE:$REMOTE_DIR yourself, and stop the shared connection:"
  echo "  ssh -o ControlPath=$H/.ssh/cm-%C -O exit ${REMOTE_USER:-$(id -un)}@${REMOTE_HOSTNAME:-$REMOTE}"
fi
[ -z "$SBX_OUT" ] || { cp -R "$H"/run-* "$SBX_OUT"/ 2>/dev/null; cp "$H"/doctor-*.txt "$SBX_OUT"/ 2>/dev/null; } || true
exit $code
