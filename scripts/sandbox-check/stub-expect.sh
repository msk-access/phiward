# Sourced by inside.sh (and by its test): what the stub's Mode B must show for the newer guards,
# from facts about the kit and the host, never from a fixed list of allowed failures. The
# stand-in has no sandbox of its own, so under launch each line shows phiward's guard alone:
# - loopback-*: refused when the kit has the session's network proxy (src/phiward/netproxy.py);
#   without it, a FAIL is labelled "kit has no proxy";
# - unix-*: refused when the kit's code has Landlock's RESOLVE_UNIX and the host's Landlock ABI
#   (the run's `landlock` fact) is 9 or more; otherwise a FAIL is labelled as relying on Claude
#   Code's sandbox, which the stub does not have.
# Any other FAIL or INCONCLUSIVE line, or a verdict that does not match the lines, is a failure.
# sbx_newer_expect REPORT KIT ABI: REPORT is Mode B's part of the report; prints == lines,
# returns 1 on a failure.
sbx_newer_expect() {
  _r=$1 _kit=$2 _abi=$3 _st=0
  _proxy=no
  [ -f "$_kit/src/phiward/netproxy.py" ] && _proxy=yes
  case $_abi in ''|*[!0-9]*) _abi=0 ;; esac
  _unix=no
  if grep -qs RESOLVE_UNIX "$_kit"/src/phiward/*.py && [ "$_abi" -ge 9 ]; then _unix=yes; fi
  echo "== kit: proxy $_proxy, unix-socket guard on this host $_unix (Landlock ABI $_abi)"
  for _p in loopback-127 loopback-localhost loopback-v6 loopback-mapped unix-renamed unix-late; do
    case $_p in
      loopback-*) _must=$_proxy _why="kit has no proxy" ;;
      *) _must=$_unix _why="relies on Claude Code's sandbox (not in the stub)" ;;
    esac
    if grep -q "^ok   $_p: " "$_r"; then
      echo "== ok    Mode B: $_p refused"
    elif { [ "$_p" = loopback-v6 ] || [ "$_p" = loopback-mapped ]; } &&
         grep -q "^note $_p: not tested" "$_r"; then
      echo "== ok    Mode B: $_p not tested here (no IPv6 loopback)"
    elif [ "$_must" = no ] && grep -q "^FAIL $_p: " "$_r"; then
      echo "== label Mode B: $_p: $_why"
    else
      echo "== FAIL  Mode B: $_p is not refused, and the kit and host say it must be"; _st=1
    fi
  done
  _others=$(grep -E '^(FAIL|\?\?\?\?) ' "$_r" | grep -vxF 'FAIL Mode B' |
            grep -vE '^FAIL (loopback-[a-z0-9]+|unix-renamed|unix-late): ' || true)
  if [ -n "$_others" ]; then
    printf '%s\n' "$_others" | sed 's/^/== FAIL  Mode B, unexpected: /'; _st=1
  fi
  if grep '^FAIL ' "$_r" | grep -qvxF 'FAIL Mode B'; then _want="FAIL Mode B"
  else _want="PASS Mode B"; fi
  if grep -qxF "$_want" "$_r"; then echo "== ok    $_want"
  else echo "== FAIL  the verdict is not $_want"; _st=1; fi
  return $_st
}
