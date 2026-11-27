"""The hook under `phiward launch`: a fast, helpful first layer.

Under `launch` the kernel decides about every file the tool touches, so the hook only has to
turn an attempt at a protected path into a helpful refusal (use the gateway) before the tool
wastes a turn on a kernel error. It loads only `json`, `os` and the gateway's command parser
(to allow a whole `phiward run|copy` call): the protected paths come from
`PHIWARD_HOOK_ROOTS`, which `launch` sets in the tool's environment. Allow is
silence; deny is exit 2 with one short line. A payload it cannot read is allowed: the kernel is
the boundary here, and this layer must never stop work by mistake.
"""

import json
import os
import sys

REASON = ("phiward: that path is protected; read it with `phiward run -- CMD` "
          "(see AGENTS.md)")


PATH_FIELDS = ("file_path", "path", "notebook_path", "pattern")


def _protected(s: str, keys, cwd: str, fold: bool) -> bool:
    cand = s.casefold() if fold else s
    if any(k in cand for k in keys):
        return True
    if s.startswith(("/", "~", ".")) and len(s) < 4096 and "\n" not in s:
        p = os.path.realpath(os.path.join(cwd, os.path.expanduser(s)))
        p = p.casefold() if fold else p
        return any(p == k or p.startswith(k + "/") for k in keys)
    return False


def main() -> int:
    try:
        roots = [r for r in json.loads(os.environ.get("PHIWARD_HOOK_ROOTS", "[]"))
                 if isinstance(r, str) and r.startswith("/")]
        payload = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    if not isinstance(payload, dict):
        return 0
    if payload.get("hook_event_name", "PreToolUse") != "PreToolUse":
        # the words of core.REWIRE_STEP (this file loads no phiward code)
        sys.stderr.write("phiward: this hook is a PreToolUse hook; this event is refused: ask "
                         "the operator to reinstall phiward or to run `(cd ~ && phiward install "
                         "claude --user --write)` in their own terminal\n")
        return 2
    fold = sys.platform == "darwin"
    keys = [(r.rstrip("/").casefold() if fold else r.rstrip("/")) for r in roots]
    tool = payload.get("tool_name") or payload.get("toolName") or ""
    inp = payload.get("tool_input") or payload.get("toolArgs") or {}
    cwd = payload.get("cwd") or os.getcwd()
    if not isinstance(inp, dict):
        return 0
    if tool in ("Bash", "bash"):
        cmd = inp.get("command", "")
        if not isinstance(cmd, str):
            return 0
        if "phiward" in cmd:
            # a whole gateway call names protected paths by design
            from phiward import gateway
            if gateway.parse_call(cmd) is not None:
                return 0
        texts = [cmd]
    else:
        # only where a file tool goes, not what it writes: a script may name the data folder
        #
        texts = [inp[f] for f in PATH_FIELDS if isinstance(inp.get(f), str)]
    for s in texts:
        if _protected(s, keys, cwd, fold):
            sys.stderr.write(REASON + "\n")
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
