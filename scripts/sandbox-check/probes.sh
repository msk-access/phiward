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
set +x  # no trace, whatever started it: no command here may show what it reads
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

# the network and unix sockets, through net.py (beside this file): it prints fixed words and
# digits only, and only those forms are kept, so nothing a server sends passes through the
# shell. A probe whose target paths.txt does not name gives no line (the judge: INCONCLUSIVE).
py=$(p python)
net() { [ -n "$py" ] && "$py" -I -S ./net.py "$@" 2>/dev/null; }
fixed() {
  case $1 in
    "RESPONSE "[0-9][0-9][0-9]|"RESPONSE other"|CONNECTED|"STATUS "[0-9][0-9][0-9]) echo "$1" ;;
    "REFUSED "*|"FAILED "*)
      case ${1#* } in
        refused|not-permitted|permission|no-such|unreachable|timeout|no-name|tunnel|tls|other)
          echo "$1" ;;
        *) echo "${1%% *} other" ;;
      esac ;;
    *) echo n/a ;;
  esac
}
# a made-up server on this machine's loopback, outside the session (netsrv.py), by each spelling
port=$(p loopback-port)
if [ -n "$port" ]; then
  for t in 127=127.0.0.1 localhost=localhost v6=::1 mapped=::ffff:127.0.0.1; do
    echo "loopback-${t%%=*} $(fixed "$(net tcp "${t#*=}" "$port")")" >> results.txt
  done
fi
# the network itself, through the proxies the session's environment names
url=$(p net-url)
[ -z "$url" ] || echo "net-api $(fixed "$(net https "$url")")" >> results.txt
# files that other tools run later (check.sh made their folders and .Rprofile): opened for
# writing, nothing written (check.sh looks for new ones on the host); .Rprofile, which exists,
# gets a marker line, which check.sh looks for on the host; an installed tree (node_modules) must
# stay writable
w() { try "runs-later-$1" sh -c 'mkdir -p "$(dirname "$1")" && : >> "$1"' sh "$2"; }
w settings .claude/settings.json
w skill .claude/skills/x/SKILL.md
w vscode .vscode/tasks.json
w sub-vscode sub/.vscode/tasks.json
try runs-later-rprofile sh -c 'echo "# phiward sandbox check" >> "$1"' sh .Rprofile
w node-modules node_modules/pkg/.vscode/x
# unix sockets outside the session (netsrv.py): one bound, then renamed, before the session; one
# bound once this file says the session runs (it waits up to 20 seconds to see it)
s=$(p unix-renamed)
[ -z "$s" ] || echo "unix-renamed $(fixed "$(net unix "$s")")" >> results.txt
s=$(p unix-late)
if [ -n "$s" ]; then
  : > "unix-ready-$mode"
  i=0
  while [ ! -S "$s" ] && [ "$i" -lt 40 ]; do sleep 0.5; i=$((i + 1)); done
  echo "unix-late $(fixed "$(net unix "$s")")" >> results.txt
fi

# a token in another process's environment: read the environ of every process in /proc other
# than this one, and record only how many had a non-empty environ (readable), an empty one, or
# were refused, how many hold a credential variable's name (token-names.txt, beside this file),
# how many of those are this shell's own ancestors, whether a step failed, how many hold
# CLAUDE_CODE_MESSAGING_TOKEN (given to Bash on purpose: a count apart), and their PIDs. No value
# passes through the shell or reaches a file: each environ is opened once, and goes from tr
# straight to awk, which prints numbers only. /proc/$$ must be this process (/proc/self), else foreign-proc. PROC is /proc
# (paths.txt may name another, for tests).
proc=$(p proc)
[ -n "$proc" ] || proc=/proc
# the name list, used whole or not at all: no CRLF, every line a comment, empty, or a name
names=""
cr=$(printf '\r')
if [ -r token-names.txt ] && ! grep -q "$cr" token-names.txt &&
   ! grep -v '^#' token-names.txt | grep -v '^$' | grep -qvE '^[A-Z][A-Z0-9_]*$'; then
  names=$(grep -v '^#' token-names.txt | grep -v '^$' | tr '\n' '|')
  names=${names%|}
fi
if [ ! -r "$proc/self/status" ]; then
  echo "parent-environ n/a" >> results.txt
elif ! [ "$proc/self/status" -ef "$proc/$$/status" ] 2>/dev/null; then
  echo "parent-environ foreign-proc" >> results.txt
else
  # this shell's ancestors, by PID (at most 256 steps)
  anc=" "
  pid=$$
  n=0
  while [ "$n" -lt 256 ]; do
    n=$((n + 1))
    pid=$(sed -n 's/^PPid:[[:space:]]*//p' "$proc/$pid/status" 2>/dev/null)
    case $pid in ''|0|*[!0-9]*) break ;; esac
    case $anc in *" $pid "*) break ;; esac
    anc="$anc$pid "
  done
  readable=0
  empty=0
  refused=0
  named=0
  ancestors=0
  failed=0
  messaging=0
  pids=""
  [ -n "$names" ] || failed=1
  for d in "$proc"/[0-9]*; do
    pid=${d##*/}
    case $pid in ''|*[!0-9]*) continue ;; esac
    [ "$pid" = "$$" ] && continue
    # one open of the environ, one pipeline: tr feeds awk, which prints counts only (lines,
    # credential names, the messaging token); tr's status comes back on fd 3. No "tr=" means
    # the open was refused; any other failure of the read is a scan error.
    res=$( { { tr '\0' '\n'; echo "tr=$?" >&3; } < "$d/environ" |
             LC_ALL=C awk -v names="$names" '
               names != "" && $0 ~ ("^(" names ")=") { h++ }
               /^CLAUDE_CODE_MESSAGING_TOKEN=/ { m++ }
               END { printf "lines=%d hits=%d msg=%d\n", NR, h, m }'
           echo "awk=$?"; } 3>&1 2>/dev/null )
    case $res in *tr=*) ;; *) refused=$((refused + 1)); continue ;; esac
    t=""; a=""; nl=""; h=""; m=""
    for w in $res; do
      case $w in
        tr=*) t=${w#tr=} ;; awk=*) a=${w#awk=} ;; lines=*) nl=${w#lines=} ;;
        hits=*) h=${w#hits=} ;; msg=*) m=${w#msg=} ;; *) t=x ;;
      esac
    done
    case $t:$a:$nl:$h:$m in
      0:0:[0-9]*:[0-9]*:[0-9]*) ;;
      *) failed=1; continue ;;
    esac
    case $nl$h$m in *[!0-9]*) failed=1; continue ;; esac
    [ "$nl" -eq 0 ] && { empty=$((empty + 1)); continue; }
    readable=$((readable + 1))
    if [ "$h" -gt 0 ]; then
      named=$((named + 1))
      pids="$pids,$pid"
      case $anc in *" $pid "*) ancestors=$((ancestors + 1)) ;; esac
    fi
    [ "$m" -gt 0 ] && messaging=$((messaging + 1))
  done
  pids=${pids#,}
  echo "parent-environ readable=$readable empty=$empty refused=$refused token-names=$named ancestors=$ancestors scan-error=$failed messaging=$messaging pids=${pids:--}" >> results.txt
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
