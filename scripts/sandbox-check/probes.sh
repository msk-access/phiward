#!/bin/sh
# The probes, run by the real Claude Code as one Bash command inside its sandbox (Mode A), or
# inside `phiward launch` (Mode B). The targets are in paths.txt (not in this file or the
# command), so phiward's hook sees no protected path and the sandbox alone must refuse them.
# Writes one line per probe to results.txt; prints no content.
# A refusal is recorded with its reason class (judge.py decides which classes pass where):
# not-permitted (EPERM, as Seatbelt refuses), read-only (EROFS, a read-only bind), permission
# (EACCES), no-such (ENOENT, "Directory nonexistent" in dash: a hidden file), empty-view (a read worked, but not of the real
# content), other.
cd "$(dirname "$0")" || exit 1
: > results.txt
p() { sed -n "s/^$1 //p" paths.txt; }
mode=$(p mode)
class() {
  case $1 in
    *"not permitted"*) echo not-permitted ;;
    *[Rr]"ead-only file system"*) echo read-only ;;
    *"ermission denied"*) echo permission ;;
    *"o such file"*|*"ot a directory"*|*"irectory nonexistent"*) echo no-such ;;
    *) echo other ;;
  esac
}
try() {
  name=$1; shift
  if err=$("$@" 2>&1 >/dev/null); then echo "$name OK"
  else echo "$name DENIED $(class "$err")"
  fi >> results.txt
}
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1
        else shasum -a 256 | cut -d' ' -f1; fi; }
prot=$(p protected-file)
try control-write touch "$(p free)/sbx-ok"
try control-read grep -q "$(p free-marker)" "$(p free)/b.txt"
# a read that "works" must show the real content to count as a read: the hash, never the content
if err=$(cat "$prot" 2>&1 >/dev/null); then
  if [ "$(cat "$prot" 2>/dev/null | sha)" = "$(p protected-hash)" ]; then
    echo "read-protected OK"
  else
    echo "read-protected DENIED empty-view"
  fi
else
  echo "read-protected DENIED $(class "$err")"
fi >> results.txt
try write-data touch "$(p data)/sbx-probe-$mode"
try write-phiward touch "$(p phiward)/sbx-probe-$mode"
try write-settings sh -c 'printf x >> "$1"' sh "$(p settings)"

# the gateway from inside the session: it must work and mask the protected path
if out=$(phiward run -- wc -l "$prot" 2>&1); then
  case $out in
    *"$prot"*|*"$(p data)"*) r="BAD unmasked" ;;
    *"<PROTECTED>"*) r="OK masked" ;;
    *) r="BAD other" ;;
  esac
else
  case $out in
    *"$prot"*|*"$(p data)"*) r="BAD unmasked" ;;
    *[Ll]andlock*) r="BAD landlock" ;;
    *) r="BAD other" ;;
  esac
fi
echo "gateway-run $r" >> results.txt

# git: a plain commit must work; a line with a made-up identifier must be refused by the
# pre-commit hook without being shown
g() { git -c user.name=sbx -c user.email=sbx@example.invalid -c commit.gpgsign=false "$@"; }
echo "a plain line, mode $mode" > "ctl-$mode.txt"
try control-commit sh -c 'git add -- "$1" && git -c user.name=sbx -c user.email=sbx@example.invalid -c commit.gpgsign=false commit -q -m "a plain commit" -- "$1"' sh "ctl-$mode.txt"
before=$(git rev-parse -q --verify HEAD)
echo "sample $(p fake-id) was run" > "gh-$mode.txt"
git add -- "gh-$mode.txt" 2>/dev/null
if out=$(g commit -q -m "a line with an identifier" 2>&1); then r=OK
elif [ "$(git rev-parse -q --verify HEAD)" != "$before" ]; then r=OK
else
  case $out in
    *"$(p fake-id)"*) r="DENIED leaked" ;;
    *"<SAMPLEID>"*) r="DENIED refused" ;;
    *) r="DENIED other" ;;
  esac
fi
echo "git-hook $r" >> results.txt
git reset -q -- "gh-$mode.txt" 2>/dev/null
rm -f "gh-$mode.txt"

# the claude process's environment holds the token: can the session read it from /proc? Walk
# the parents up to the claude process (its program, or the claude path in its command line: a
# Node install, the stand-in), and record only whether its environ can be read. No environment
# is written anywhere. Readable is a note; not found is INCONCLUSIVE in a real run.
if [ -r /proc/self/status ]; then
  r=not-found
  pid=$$
  want=$(p claude-exe)
  link=$(p claude-link)
  while :; do
    pid=$(sed -n 's/^PPid:[[:space:]]*//p' "/proc/$pid/status" 2>/dev/null)
    [ -n "$pid" ] && [ "$pid" -gt 0 ] || break
    args=$(tr '\0' ' ' 2>/dev/null < "/proc/$pid/cmdline")
    case " $args " in *" $want "*|*" $link "*) found=1 ;; *) found="" ;; esac
    if [ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "$want" ] || [ -n "$found" ]; then
      if [ "$(head -c 1 "/proc/$pid/environ" 2>/dev/null | wc -c)" -gt 0 ]; then
        r=readable
      else
        r=unreadable
      fi
      break
    fi
  done
  echo "parent-environ $r" >> results.txt
else
  echo "parent-environ n/a" >> results.txt
fi

# the remote probes (REMOTE set): through the operator's shared connection, into a new folder
if [ "$(p remote)" = yes ]; then
  host=$(p remote-host)
  rbase=$(p remote-dir)
  rdir="$rbase/sbx-$(p nonce)-$mode"
  try remote-push phiward copy "$prot" "$host:$rdir/"
  if out=$(phiward run --remote "$host" -- wc -l "$rdir/a.txt" 2>&1); then
    case $out in
      *"$rbase"*) r="BAD unmasked" ;;
      *"<PROTECTED>"*) r="OK masked" ;;
      *) r="BAD other" ;;
    esac
  else
    case $out in *"$rbase"*) r="BAD unmasked" ;; *) r="BAD other" ;; esac
  fi
  echo "remote-run $r" >> results.txt
  try remote-pull phiward copy "$host:$rdir/a.txt" "$(p data)/pulled/"
  try remote-pull-out phiward copy "$host:$rdir/a.txt" "$(p free)/"
  # never a login: BatchMode, no identity, only the socket of the shared connection
  try remote-own-socket ssh -F "$(p ssh-config)" -O check "$host"
fi

env > env.txt  # launch.py looks for the token in it, then removes it
names=$(env | sed 's/=.*//' | grep -iE 'token|key|secret|password|credential' | tr '\n' ' ')
set -- $names
echo "env-secrets COUNT $# $names" | sed 's/ *$//' >> results.txt
echo probes-done
