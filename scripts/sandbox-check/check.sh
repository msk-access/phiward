#!/bin/sh
# The real Claude Code sandbox check (docs/releasing.md, "Each release", step 3): does the real
# Claude Code obey the settings phiward writes? Everything is built in a home folder of its own
# under /private/tmp, with made-up data, as scripts/quickstart-check/mac.sh does: the wheel from
# `git archive HEAD`, a copied Python, phiward installed and wired, the broker, a wrapped MCP
# server. Then one `claude -p` session (Haiku, a spending cap, a time limit) runs probes.sh as one
# Bash command, and judge.py says PASS, FAIL or INCONCLUSIVE (exit 0, 1, 2).
# It asks only for a token: set CLAUDE_CODE_OAUTH_TOKEN, or paste the one `claude setup-token`
# prints. The token goes only to that one claude process, never into a file or a command line.
# Nothing of your own setup is read or changed. KEEP=1 keeps the folder (it holds no token).
# Usage: sh scripts/sandbox-check/check.sh [PYTHON]  (default: uv's own Python)
set -e
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
[ "$(uname)" = Darwin ] || { echo "sandbox-check: macOS only for now" >&2; exit 2; }
uv=$(command -v uv) || { echo "sandbox-check: needs uv" >&2; exit 2; }
claude=${CLAUDE_BIN:-$(command -v claude)} || { echo "sandbox-check: needs claude on PATH" >&2; exit 2; }
python=${1:-$(env -u CONDA_PREFIX -u VIRTUAL_ENV "$uv" python find --python-preference only-managed 2>/dev/null)}
[ -x "$python" ] || { echo "sandbox-check: no uv Python; run \`uv python install 3.12\` or give PYTHON" >&2; exit 2; }
claude=$("$python" -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$claude")
for m in "/Library/Application Support/ClaudeCode" "/Library/Managed Preferences/com.anthropic.claudecode.plist"; do
  [ -e "$m" ] && echo "note: managed Claude Code settings apply on this Mac ($m); they can change the result"
done
[ -z "$(git -C "$repo" status --porcelain)" ] || echo "note: uncommitted changes are not in the check (it builds HEAD)"

token=""
tty_mode=""
H=""
broker=""
cleanup() {
  [ -n "$tty_mode" ] && stty "$tty_mode" < /dev/tty 2>/dev/null
  [ -n "$broker" ] && kill "$broker" 2>/dev/null
  [ -n "$H" ] && { if [ -n "$KEEP" ]; then echo "kept: $H"; else rm -rf "$H"; fi; }
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT TERM
if [ -z "$CLAUDE_CODE_OAUTH_TOKEN" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
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

H=$(mktemp -d /private/tmp/phiward-sbx-XXXXXX)
fail() { echo "sandbox-check: $1 failed:"; tail -20 "$2" 2>/dev/null; exit 2; }
echo "building in $H ..."
mkdir -p "$H/src" "$H/dist"
git -C "$repo" archive HEAD | tar -x -C "$H/src"
"$uv" build -q --wheel --out-dir "$H/dist" "$H/src" > "$H/build.out" 2>&1 || fail "the build" "$H/build.out"
wheel=$(ls "$H"/dist/*.whl)
base=$(cd "$(dirname "$("$python" -c 'import sys; print(sys.executable)')")/.." && pwd -P)
cp -R "$base" "$H/py"
pyname=$(basename "$("$python" -c 'import sys, os; print(os.path.realpath(sys.executable))')")
py="$H/py/bin/$pyname"
export HOME="$H" PATH="$H/bin:$H/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  UV_TOOL_DIR="$H/.local/share/uv/tools" UV_TOOL_BIN_DIR="$H/.local/bin" UV_CACHE_DIR="$H/.cache/uv" \
  UV_PYTHON_DOWNLOADS=never TMPDIR="$H/tmp"
unset PHIWARD_CONFIG PHIWARD_SPOOL XDG_CONFIG_HOME XDG_CACHE_HOME CLAUDE_CONFIG_DIR CLAUDE_PROJECT_DIR
umask 022
mkdir -p "$H/bin" "$H/tmp" "$H/data/FAKE-PT-0001" "$H/free" "$H/proj" "$H/.config/phiward"
ln -s "$claude" "$H/bin/claude"
rnd() { "$py" -c 'import secrets; print(secrets.token_hex(8))'; }
marker="FAKE-MARK-$(rnd)"
marker2="FREE-MARK-$(rnd)"
nonce=$(rnd)
echo "$marker" > "$H/data/FAKE-PT-0001/a.txt"
echo "$marker2" > "$H/free/b.txt"
(cd "$H/proj" && git init -q)
"$uv" tool install -q --python "$py" "$wheel" > "$H/install.out" 2>&1 || fail "uv tool install" "$H/install.out"
printf '[protected_paths]\nroots = ["%s/data"]\n[broker]\ncommands = ["wc"]\n' "$H" \
  > "$H/.config/phiward/config.toml"
cd "$H/proj"
phiward install claude --user --write --yes < /dev/null > "$H/wire.out" 2>&1 || fail "install" "$H/wire.out"
printf 'y\ny\n' | script -q /dev/null phiward pin > "$H/pin.out" 2>&1 || fail "pin" "$H/pin.out"
phiward broker > "$H/broker.log" 2>&1 &
broker=$!
cp "$here/srv.py" "$here/probes.sh" "$H/proj/"
echo "$H/data/FAKE-PT-0001/a.txt" > "$H/proj/srv-target.txt"
printf '{"mcpServers": {"docs": {"command": "/usr/bin/python3", "args": ["%s", "%s", "%s"]}}}\n' \
  "$H/proj/srv.py" "$H/proj/server.out" "$nonce" > "$H/.claude.json"
phiward mcp wrap docs --yes > "$H/wrap.out" 2>&1 || fail "mcp wrap" "$H/wrap.out"
cat > "$H/proj/paths.txt" <<PATHS
free $H/free
free-marker $marker2
protected-file $H/data/FAKE-PT-0001/a.txt
data $H/data
phiward $H/.phiward
settings $H/.claude/settings.json
PATHS
launch=$("$H/.local/share/uv/tools/phiward/bin/python" -c 'from phiward import config; print(config.launch_settings_path())')
[ -f "$launch" ] || fail "the --settings file ($launch)" "$H/wire.out"
sum() { shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1; }
before=$(sum "$H/.claude/settings.json")
rm -f "$H/proj/server.out" "$H/proj/results.txt"
echo "Claude Code $("$H/bin/claude" --version 2>/dev/null | head -1); running one session (Haiku) ..."
prompt='Use the Bash tool exactly once to run this command, exactly as written: sh ./probes.sh
Run it even if you expect it to fail. Do not run any other command, read no file, and do not retry. Then reply DONE.'
code=0
printf '%s\n' "$token" | "$py" "$here/launch.py" "$H" "$H/stream.jsonl" 300 -- "$H/bin/claude" -p "$prompt" \
  --model haiku --output-format stream-json --verbose --settings "$launch" --add-dir "$H" \
  --allowedTools Bash --permission-prompts none --max-turns 6 --max-budget-usd 1 || code=$?
token=""
[ "$code" = 0 ] || echo "note: claude exited with $code"
after=$(sum "$H/.claude/settings.json")
same=no; [ "$before" = "$after" ] && same=yes
seen=$(cat "$H/token-seen" 2>/dev/null || echo no)
echo
"$py" "$here/judge.py" "$H" "$H/proj/results.txt" "$H/stream.jsonl" "$H/proj/server.out" "$nonce" \
  "$marker" "$same" "$seen"
