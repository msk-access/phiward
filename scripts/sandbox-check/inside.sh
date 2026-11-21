#!/bin/sh
# Inside the sandbox-check image, as the user tester (scripts/sandbox-check/linux.sh starts it):
# the source is at /repo (read only, a `git archive` of HEAD), results go to /out. It runs
# check.sh with SBX_BASE=/work, SBX_SRC=/repo and SBX_OUT=/out: check.sh keeps there only the
# redacted report, streams and facts; the console output goes to /out/console.txt. It exits as
# check.sh does. --stub runs in a cluster's shape instead: SBX_BASE in a folder below the home
# folder (~/sbx/run) and SBX_TOOLS next to it (~/sbx/tools/bin).
# --stub: the stand-in claude. The run must then end exactly as expected (below): Mode A, where
# nothing confines the stub, FAILs on the kernel probes (the judge sees the holes), Mode B passes
# (the wrapped MCP server starts in both modes), and the rest
# works (the hook, the gateway, the git hook, doctor before, the redaction, the cleanup). Exit 0 only
# when every expected line is in the report.
set -u
stub=""
[ "${1:-}" = --stub ] && stub=--stub
SBX_LOCKED=$(cat /opt/claude/locked 2>/dev/null || echo unknown)
export SBX_BASE=/work SBX_SRC=/repo SBX_OUT=/out SBX_LOCKED
if [ -n "$stub" ]; then
  SBX_BASE=$HOME/sbx/run SBX_TOOLS=$HOME/sbx/tools/bin
  mkdir -p -m 755 "$SBX_BASE" "$SBX_TOOLS"
  ln -s /usr/bin/socat "$SBX_TOOLS/socat"  # root's: the one name SBX_TOOLS may hold
  export SBX_TOOLS
fi
{ sh /repo/scripts/sandbox-check/check.sh $stub 2>&1; echo $? > /out/rc; } | (trap '' INT; tee /out/console.txt)  # tee outlives a Ctrl-C, so the output is all there
code=$(cat /out/rc)
[ -n "$stub" ] || exit "$code"

status=0
expect() {
  if grep -qxF -- "$1" /out/report.txt; then echo "== ok    $1"
  else echo "== MISSING $1"; status=1; fi
}
# Mode A: no sandbox around the stub, so every kernel probe got through, and each write
# reached the host
expect "== Mode A (linux)"
expect "FAIL read-protected: OK: it got through"
expect "FAIL write-data: OK: it got through, and the file reached the host"
expect "FAIL write-phiward: OK: it got through, and the file reached the host"
expect "FAIL write-settings: OK: it got through, and the file reached the host"
expect "FAIL Mode A"
# the rest works in both modes: phiward's hook refused the Read, the gateway masked, the git hook
# refused without the identifier, the wrapped MCP server could not read the file
for m in A B; do
  sed -n "/^== Mode $m /,/^[A-Z]* Mode $m\$/p" /out/report.txt > "/tmp/mode-$m.txt"
  for ln in "ok   read-tool: the Read tool was refused by phiward" \
            "ok   gateway-run: phiward run worked and masked the protected path" \
            "ok   git-hook: the commit was refused, and the identifier not shown" \
            "ok   the token is not in the commands' environment"; do
    if grep -qxF -- "$ln" "/tmp/mode-$m.txt"; then echo "== ok    Mode $m: $ln"
    else echo "== MISSING Mode $m: $ln"; status=1; fi
  done
  # the probe found the stand-in (as it finds claude) and could, or could not, read its environ
  if grep -qE "^(note the session can read the claude process's environment|ok   the session cannot read the claude process's environment)" "/tmp/mode-$m.txt"; then
    echo "== ok    Mode $m: the probe found the claude process"
  else echo "== MISSING Mode $m: the probe found the claude process"; status=1; fi
done
# Mode B: the stub under the real `phiward launch`: the kernel probes are refused, and the wrapped
# MCP server starts inside the session (its own launch runs it directly), so Mode B passes
expect "== Mode B (linux)"
expect "PASS Mode B"
for m in A B; do
  if grep -qxF "ok   the wrapped MCP server started and could not read the protected file" "/tmp/mode-$m.txt"; then
    echo "== ok    Mode $m: the wrapped MCP server started"
  else echo "== MISSING Mode $m: the wrapped MCP server started"; status=1; fi
done
for p in read-protected write-data write-phiward write-settings; do
  if grep -qE "^(ok   $p: refused by the sandbox|note $p: the write worked inside the sandbox \(Mode B\), and nothing reached the host)" /tmp/mode-B.txt; then
    echo "== ok    Mode B: $p refused"
  else
    echo "== MISSING Mode B: $p refused"; status=1
  fi
done
# doctor: clean before the sessions; after them it must see the settings file that Mode A's
# unconfined stub wrote (a new warning, so FAIL)
if grep -q "^???? doctor: a warning before" /out/report.txt; then
  echo "== MISSING a clean doctor before the sessions"; status=1
else echo "== ok    doctor clean before the sessions"; fi
expect "FAIL doctor"
expect "FAIL"
# only the redacted files are kept; the token in none of them; the check's home removed
kept=$(cd /out && ls -A | grep -vxE 'console.txt|rc' | tr '\n' ' ')
if [ "$kept" = "facts-A.txt facts-B.txt report.txt stream-A.jsonl stream-B.jsonl " ]; then
  echo "== ok    kept: $kept"
else echo "== WRONG kept files: $kept"; status=1; fi
if grep -rqs "FAKE-TOKEN-" /out; then echo "== FOUND the made-up token in /out"; status=1
else echo "== ok    the made-up token is in no kept file"; fi
if ls -d "$SBX_BASE"/phiward-sbx-* >/dev/null 2>&1; then echo "== LEFT the check's home in $SBX_BASE"; status=1
else echo "== ok    the check's home is removed"; fi
# the base below the home folder was taken, and the tools folder put on the session's PATH
if grep -qxF "tools: $SBX_TOOLS on the PATH" /out/console.txt; then echo "== ok    SBX_TOOLS on the PATH"
else echo "== MISSING SBX_TOOLS on the PATH"; status=1; fi
# refusals in the cluster's shape (Linux keeps letter case and group bits as a cluster does): a
# tools folder another account could write, or its parent, or its socat, is refused before the
# build; a CLAUDE.md that appears above SBX_BASE after the first check (the operator put ~/.claude
# back during the token prompt) is refused before the first session
refused() {  # NAME TEXT: check.sh exited 2, said TEXT, and never started a session
  o=$HOME/out-$1
  if [ "$(cat "$o/rc")" = 2 ] && grep -qF -- "$2" "$o/console.txt" \
      && ! grep -q "one session" "$o/console.txt"; then echo "== ok    refused: $1"
  else echo "== NOT REFUSED: $1"; sed 's/^/   | /' "$o/console.txt" | tail -5; status=1; fi
  # and left none of its folders
  if ls -d "$HOME/sbx-$1/run"/phiward-sbx-* >/dev/null 2>&1; then
    echo "== LEFT  the check's folders of refusal $1"; status=1
  else echo "== ok    refusal $1 removed its folders"; fi
}
refusal_run() {  # NAME BASE TOOLS: one check.sh --stub, its output in ~/out-NAME
  o=$HOME/out-$1
  mkdir -p -m 755 "$o"
  SBX_BASE=$2 SBX_TOOLS=$3 SBX_OUT=$o sh /repo/scripts/sandbox-check/check.sh --stub > "$o/console.txt" 2>&1
  echo $? > "$o/rc"
}
tools_case() {  # NAME: a base and a tools folder with a socat, both private
  mkdir -p -m 755 "$HOME/sbx-$1/run" "$HOME/sbx-$1/tools/bin"
  printf '#!/bin/sh\nexit 1\n' > "$HOME/sbx-$1/tools/bin/socat"
  chmod 755 "$HOME/sbx-$1/tools/bin/socat"
}
tools_case gw; chmod 775 "$HOME/sbx-gw/tools/bin"
refusal_run gw "$HOME/sbx-gw/run" "$HOME/sbx-gw/tools/bin"
refused gw "SBX_TOOLS is not a safe PATH folder"
tools_case gp; chmod 775 "$HOME/sbx-gp/tools"
refusal_run gp "$HOME/sbx-gp/run" "$HOME/sbx-gp/tools/bin"
refused gp "SBX_TOOLS is not a safe PATH folder"
tools_case gs; chmod 666 "$HOME/sbx-gs/tools/bin/socat"
refusal_run gs "$HOME/sbx-gs/run" "$HOME/sbx-gs/tools/bin"
refused gs "SBX_TOOLS is not a safe PATH folder"
for n in gw gp gs; do
  if grep -q "^building in" "$HOME/out-$n/console.txt"; then echo "== LATE  refused $n after the build began"; status=1
  else echo "== ok    refused $n before the build"; fi
done
tools_case late
# the name appears once the check is past its first look (the wrapped server is set up)
( for _i in $(seq 1200); do
    if ls "$HOME"/sbx-late/run/phiward-sbx-*/wrap.out >/dev/null 2>&1; then
      echo made up > "$HOME/sbx-late/CLAUDE.md"; exit 0
    fi
    sleep 0.1
  done ) &
refusal_run late "$HOME/sbx-late/run" "$HOME/sbx-late/tools/bin"
wait
refused late "$HOME/sbx-late/CLAUDE.md is above SBX_BASE"
[ "$status" = 0 ] && echo "PASS stub plumbing" || echo "FAIL stub plumbing"
exit $status
