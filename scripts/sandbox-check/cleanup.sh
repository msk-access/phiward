# The sandbox check's cleanup and signal handling, sourced by check.sh (and by its test):
# cleanup stops the broker and the made-up servers (netsrv.py), removes the home folder H (with
# their sockets) and the judge's folder J, and says so if it cannot;
# stopped passes a signal on to launch.py (pid in lpid), then exits.
# Uses: H, J, lpid, broker, netsrv, tty_mode; SBX_CLEANUP_WAIT (seconds, default 2).
cleanup() {
  st=$?
  trap '' INT TERM HUP  # a second signal must not cut the cleanup short
  set +e  # nor a failure
  [ -n "$tty_mode" ] && stty "$tty_mode" < /dev/tty 2>/dev/null
  [ -n "$broker" ] && kill "$broker" 2>/dev/null
  [ -n "${netsrv:-}" ] && kill "$netsrv" 2>/dev/null
  # nothing of the home folder or the judge's folder is kept. After a short wait, so that a
  # process the session left behind (one in a session of its own outlives the stop) has less
  # time to write again; folders the session made unwritable are made writable first
  left=""
  for d in "$H" "$J"; do
    [ -n "$d" ] || continue
    sleep "${SBX_CLEANUP_WAIT:-2}"
    chmod -R u+rwX "$d" 2>/dev/null
    rm -rf "$d" 2>/dev/null
    [ -e "$d" ] && left="$left $d"
  done
  if [ -n "$left" ]; then
    echo "sandbox-check: the run folder could not be removed: remove it yourself:$left" >&2
    [ "$st" = 0 ] && st=2
  fi
  exit "$st"
}
# a signal is passed on to launch.py as TERM (an async child of sh may start with INT ignored),
# launch.py stops the session; then the cleanup runs. lpid is "starting" from just before the
# `&` until it holds launch.py's pid: then $! names launch.py if the `&` ran, else an earlier
# job (the broker, or a launch.py already waited for), which the cleanup stops anyway.
stopped() {
  trap '' INT TERM HUP
  pid=$lpid
  [ "$pid" = starting ] && pid=${!:-}
  if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; fi
  exit "$2"
}
