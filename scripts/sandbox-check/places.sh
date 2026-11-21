# Sourced by check.sh: where the check's folders may be (SBX_BASE) and which tools folder the
# session's PATH may hold (SBX_TOOLS). A refusal prints why and returns 2. The tests run these on
# made-up folders (tests/test_sandbox_check_judge.py), so nothing is built there.

# the names Claude Code or phiward pick up from a folder above the session's: Claude Code reads
# CLAUDE.md and CLAUDE.local.md in every parent, .claude/rules in every parent, .claude/skills and
# the nearest .claude's settings; phiward reads the settings (and .mcp.json) of every .claude or
# .git above a call, and its repository config (.phiward.toml, the old .agent-guards.toml) above
# the folder it runs in
SBX_PICKED_UP="CLAUDE.md CLAUDE.local.md .claude .git .mcp.json .phiward.toml .agent-guards.toml"

# _at_or_below A B: A is B or inside it, by identity (a folder has more than one spelling: macOS
# folds letter case, /System/Volumes/Data)
_at_or_below() {
  _a=$1
  while :; do
    [ "$_a" -ef "$2" ] && return 0
    [ "$_a" = / ] && return 1
    _a=$(dirname "$_a")
  done
}

# sbx_base_check BASE HOMES: BASE (a real path) is not a home folder (HOMES: one per line), and no
# folder from BASE up to / holds a name above, so nothing of your own setup is read into the test
sbx_base_check() {
  _b=$1
  _bad=$(printf '%s\n' "$2" | while IFS= read -r _h; do
    [ -n "$_h" ] && [ "$_h" != / ] && [ "$_b" -ef "$_h" ] && echo home
  done || true)
  [ -z "$_bad" ] || { echo "sandbox-check: SBX_BASE may not be your home folder; make a folder for it below it (docs/releasing.md)" >&2; return 2; }
  _d=$_b
  while :; do
    for _n in $SBX_PICKED_UP; do
      if [ -e "${_d%/}/$_n" ] || [ -L "${_d%/}/$_n" ]; then
        echo "sandbox-check: ${_d%/}/$_n is above SBX_BASE: Claude Code or phiward would read it into the test; move it while the check runs, or choose another SBX_BASE (docs/releasing.md)" >&2
        return 2
      fi
    done
    [ "$_d" = / ] && break
    _d=$(dirname "$_d")
  done
  return 0
}

# sbx_tools_place TOOLS BASE: TOOLS is an absolute, existing folder, outside BASE (where the
# check's home and judge's folder are made) and not above it; prints its real path
sbx_tools_place() {
  case $1 in /*) ;; *) echo "sandbox-check: SBX_TOOLS must be an absolute path" >&2; return 2 ;; esac
  _t=$(cd "$1" 2>/dev/null && pwd -P) || { echo "sandbox-check: SBX_TOOLS is not an existing folder" >&2; return 2; }
  if _at_or_below "$_t" "$2"; then echo "sandbox-check: SBX_TOOLS may not be in SBX_BASE (the check's home is made there)" >&2; return 2; fi
  if _at_or_below "$2" "$_t"; then echo "sandbox-check: SBX_TOOLS may not hold SBX_BASE" >&2; return 2; fi
  printf '%s\n' "$_t"
}

# sbx_tools_safe PY TOOLS: the installed phiward's own rule for a PATH folder
# (service.path_entries: selfcheck.safe_path, not a project's, not a temp folder or one the
# session may write), run by its Python PY with the check's HOME
sbx_tools_safe() {
  "$1" -c '
import sys
from phiward import selfcheck, service
t = sys.argv[1]
if service.path_entries(t, service.path_inputs()) != [t]:
    why = selfcheck.safe_path(t) or "a temp folder, a project, or a folder the session may write"
    sys.exit("sandbox-check: SBX_TOOLS is not a safe PATH folder (" + why + "): " + t)
' "$2" || return 2
}

# session_path H TOOLS SYSPATH: the session's PATH, with TOOLS (when given) before the system
session_path() {
  printf '%s\n' "$1/bin:$1/.local/bin${2:+:$2}:$3"
}
