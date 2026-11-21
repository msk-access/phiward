#!/bin/sh
# The probes, run by the real Claude Code as one Bash command inside its sandbox (Mode A), or
# inside `phiward launch` (Mode B). The targets are in paths.txt (not in this file or the
# command), so phiward's hook sees no protected path and the sandbox alone must refuse them.
# Writes one line per probe to results.txt; prints no content. When `phiward run` fails for
# another reason, gateway-why records one word from a fixed list; no text of its output is kept.
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
# is each write's target hidden from the session (an empty view, /dev/null)? Looked at before the
# writes, which could fill an empty view: ~/.phiward without the sentinel check.sh put there,
# the settings empty or not there (the protected file's read above covers the data folder)
if out=$(ls -A "$(p phiward)" 2>&1); then
  case "
$out
" in *"
sbx-sentinel
"*) r=present ;; *) r=hidden ;; esac
else
  case $(class "$out") in no-such) r=hidden ;; *) r=unreadable ;; esac
fi
echo "hidden-phiward $r" >> results.txt
s=$(p settings)
if err=$(cat "$s" 2>&1 >/dev/null); then
  if [ "$(cat "$s" 2>/dev/null | wc -c)" -eq 0 ]; then r=hidden; else r=present; fi
else
  case $(class "$err") in no-such) r=hidden ;; *) r=unreadable ;; esac
fi
echo "hidden-settings $r" >> results.txt
try write-data touch "$(p data)/sbx-probe-$mode"
try write-phiward touch "$(p phiward)/sbx-probe-$mode"
try write-settings sh -c 'printf x >> "$1"' sh "$(p settings)"

# the gateway from inside the session: it must work and mask the protected path
code=0
if out=$(phiward run -- wc -l "$prot" 2>&1); then
  case $out in
    *"$prot"*|*"$(p data)"*) r="BAD unmasked" ;;
    *"<PROTECTED>"*) r="OK masked" ;;
    *) r="BAD other" ;;
  esac
else
  code=$?
  case $out in
    *"$prot"*|*"$(p data)"*) r="BAD unmasked" ;;
    *[Ll]andlock*) r="BAD landlock" ;;
    *) r="BAD other" ;;
  esac
fi
echo "gateway-run $r" >> results.txt
# why it failed, for the report: one word, by the phrases phiward prints (broker.py, run.py)
if [ "$r" = "BAD other" ]; then
  case $out in
    *"no phiward broker is running"*|*"refused: the broker runs with the spool"*|*"to the broker's spool"*|*"the broker's reply in the spool"*|*"the broker is busy"*) why=no-broker ;;
    *"the broker stopped before the command finished"*) why=stopped ;;
    *) case $code in 126|127) why=not-found ;; *) why="" ;; esac ;;
  esac
  if [ -z "$why" ]; then
    case $out in
      *"not on the broker's PATH"*|*": not found"*|*"ommand not found"*) why=not-found ;;
      *"refused: "*|*" was refused "*) why=refused ;;
      *" done: exit="*) why=failed ;;
      *) why=other ;;
    esac
  fi
  echo "gateway-why $why" >> results.txt
  # its exit code, and one error class matched in its output (the OS's words for an errno, the
  # gateway's own refusals in confine.py, a Python failure); never any text of the output
  case $out in
    *[Ll]andlock*) err=landlock ;;
    *"bwrap:"*) err=bwrap ;;
    *"phiward gateway: "*) err=gateway ;;
    *"Permission denied"*|*EACCES*) err=permission-denied ;;
    *"Read-only file system"*|*EROFS*) err=read-only ;;
    *"Operation not permitted"*|*EPERM*) err=not-permitted ;;
    *"No such file"*|*ENOENT*) err=no-such ;;
    *"Fatal Python error"*) err=python-fatal ;;
    *Traceback*) err=traceback ;;
    *) err=none ;;
  esac
  case $code in ''|*[!0-9]*) code=unknown ;; esac
  echo "gateway-exit $code" >> results.txt
  echo "gateway-error $err" >> results.txt
fi

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
# is written anywhere. Readable is a note; not found is INCONCLUSIVE in a real run, except
# own-pid-ns (the judge takes it in Mode A only): the walk reached PID 1, PID 1 is bwrap, at
# least one process between is and all of them are shells, and no process anywhere in /proc is
# claude. Then the shell is in a PID namespace of its own and claude, which started that bwrap,
# is outside (Claude Code's Linux sandbox runs bwrap with --unshare-pid). /proc/$$ must be this
# process (/proc/self), else foreign-proc. PROC is /proc (paths.txt may name another, for tests).
proc=$(p proc)
[ -n "$proc" ] || proc=/proc
want=$(p claude-exe)
link=$(p claude-link)
is_claude() {
  args=$(tr '\0' ' ' 2>/dev/null < "$proc/$1/cmdline")
  case " $args " in *" $want "*|*" $link "*) return 0 ;; esac
  [ "$(readlink "$proc/$1/exe" 2>/dev/null)" = "$want" ]
}
if [ ! -r "$proc/self/status" ]; then
  echo "parent-environ n/a" >> results.txt
elif ! [ "$proc/self/status" -ef "$proc/$$/status" ] 2>/dev/null; then
  echo "parent-environ foreign-proc" >> results.txt
else
  r=not-found
  pid=$$
  shells=yes
  between=0
  top=""
  while :; do
    ppid=$(sed -n 's/^PPid:[[:space:]]*//p' "$proc/$pid/status" 2>/dev/null)
    case $ppid in ''|*[!0-9]*) break ;; esac
    if [ "$ppid" -eq 0 ]; then top=$pid; break; fi
    pid=$ppid
    if is_claude "$pid"; then
      if [ "$(head -c 1 "$proc/$pid/environ" 2>/dev/null | wc -c)" -gt 0 ]; then
        r=readable
      else
        r=unreadable
      fi
      break
    fi
    comm=$(cat "$proc/$pid/comm" 2>/dev/null)
    case $pid:$comm in
      1:bwrap) ;;
      1:*) shells=no ;;
      *:sh|*:bash|*:dash|*:zsh) between=$((between + 1)) ;;
      *) shells=no ;;
    esac
  done
  if [ "$r" = not-found ] && [ "$top" = 1 ] && [ "$shells" = yes ] && [ "$between" -gt 0 ]; then
    seen=""
    for d in "$proc"/[0-9]*; do
      [ -d "$d" ] || continue
      if is_claude "${d##*/}"; then seen=1; break; fi
    done
    [ -n "$seen" ] || r=own-pid-ns
  fi
  echo "parent-environ $r" >> results.txt
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
