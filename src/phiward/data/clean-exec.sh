#!/bin/sh
# phiward's hooks start here. Claude Code runs this file with the hook as its arguments: the
# program (a full path, or a name on PATH), then the program's own arguments. The file unsets
# every Python and loader variable (the names come from clean-env.awk beside it, run by awk's
# full path), then runs its arguments. Each refusal exits 2, which blocks the tool call or the
# prompt; a prompt check's refusal also prints the block reply on stdout. Started with no
# arguments (a Claude Code that ignores a hook's `args`), it refuses. It reads no input.
what=
for a in "$@"; do
  case $a in hook | session-note | prompt-scan) what=$a ;; esac
done
refuse() {
  if [ "$what" = prompt-scan ]; then
    printf '{"decision": "block", "reason": "%s; every prompt and tool call is refused", "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": true}}\n' "$1"
    echo "$1; every prompt and tool call is refused" >&2
  else
    echo "$1; every tool call is refused" >&2
  fi
  exit 2
}
note() {
  # the start-of-session note: a start is never stopped, the note says what is wrong
  echo "$1"
  exit 0
}
[ "$#" -gt 0 ] || refuse "phiward: its hook started without its arguments (it needs Claude Code 2.1.295 or newer)"
case $0 in */*) here=${0%/*} ;; *) here=. ;; esac
V=$(/usr/bin/awk -f "$here/clean-env.awk") ||
  refuse "phiward: /usr/bin/awk could not list the Python and loader variables to clear"
IFS=" "
unset $V
case $1 in
  */*)
    if [ ! -f "$1" ] || [ ! -x "$1" ]; then
      [ "$what" = session-note ] && note "phiward's Python is not there: its guards refuse every tool call until \`(cd ~ && phiward install claude --user --write)\` runs again"
      refuse "phiward's Python is not there (it moved, or phiward was removed): run \`(cd ~ && phiward install claude --user --write)\` again"
    fi ;;
  *)
    if ! command -v "$1" >/dev/null 2>&1; then
      [ "$what" = session-note ] && note "phiward is not installed: its guards refuse every tool call until it is; ask the operator"
      refuse "phiward is not installed or not on PATH: install it (step 1 of its quickstart), then start Claude Code again"
    fi ;;
esac
exec "$@"
