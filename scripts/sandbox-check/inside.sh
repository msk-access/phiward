#!/bin/sh
# Inside the sandbox-check image, as the user tester (scripts/sandbox-check/linux.sh starts it):
# the source is at /repo (read only, a `git archive` of HEAD), results go to /out. It runs
# check.sh with SBX_BASE=/work, SBX_SRC=/repo and SBX_OUT=/out: check.sh keeps there only the
# redacted report, streams and facts; the console output goes to /out/console.txt. It exits as
# check.sh does.
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
{ sh /repo/scripts/sandbox-check/check.sh $stub 2>&1; echo $? > /out/rc; } | (trap '' INT; tee /out/console.txt)  # tee outlives a Ctrl-C, so the output is all there
code=$(cat /out/rc)
[ -n "$stub" ] || exit "$code"

status=0
expect() {
  if grep -qxF -- "$1" /out/report.txt; then echo "== ok    $1"
  else echo "== MISSING $1"; status=1; fi
}
# Mode A: no sandbox around the stub, so every kernel probe got through
expect "== Mode A (linux)"
expect "FAIL read-protected: OK: it got through"
expect "FAIL write-data: OK: it got through"
expect "FAIL write-phiward: OK: it got through"
expect "FAIL write-settings: OK: it got through"
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
  if grep -qE "^(ok   $p: refused by the sandbox|note $p: the write worked inside launch)" /tmp/mode-B.txt; then
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
if ls -d /work/phiward-sbx-* >/dev/null 2>&1; then echo "== LEFT the check's home in /work"; status=1
else echo "== ok    the check's home is removed"; fi
[ "$status" = 0 ] && echo "PASS stub plumbing" || echo "FAIL stub plumbing"
exit $status
