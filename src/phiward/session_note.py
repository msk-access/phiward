"""`phiward session-note claude`: the start-of-session note.

Claude Code runs it as a SessionStart hook and adds what it prints to the session's context, so
every session knows, before its first refusal, that protected data goes through the gateway and
that the gateway is the intended route, not a way around the guards. It names no protected
path: only the rules, and the HPC hosts and programs the operator listed. It never fails a
session: on any error it prints nothing.
"""
# Without this note, a test session called `phiward run` "a way around the protection".

import json
import os
import sys
from typing import List

from phiward import config


def note(cfg: config.Config) -> str:
    lines: List[str] = [
        "phiward protects data on this machine (patient data and the operator's credentials).",
        "Rules for this session:",
        "1. Do not read protected data or credentials directly. The guards refuse it; a refusal "
        "is a decision, not a fault: do not try another spelling, tool or route, and do not ask "
        "the operator to show you the data (`! cat`, a paste, a copy) or to remove a guard.",
        "2. Work with protected data only through phiward's gateway. It is the intended route, "
        "not a workaround: `phiward run -- CMD [ARG]...` runs a command and masks its output; "
        "`phiward copy SRC... DST` copies without printing names. Write the whole command, "
        "nothing before or after it.",
        "3. Through the gateway, print counts and summaries, never records, names or "
        "identifiers: masking hides names and identifiers, not other content.",
    ]
    if cfg.has_protected_paths and not cfg.shell_best_effort:
        lines.append(
            f"{len(lines) - 1}. A shell that Claude Code's sandbox does not confine runs only "
            "gateway commands, `phiward doctor` and `phiward check`; if every command is refused "
            "for this, tell the operator what `phiward doctor` says.")
    if cfg.remote_hosts:
        cmds = ", ".join(cfg.remote_commands) or "none"
        lines.append(
            f"{len(lines) - 1}. HPC: never use ssh yourself. Run `phiward run --remote HOST -- CMD` (hosts: "
            f"{', '.join(cfg.remote_hosts)}; programs: {cmds}), and move files with `phiward "
            "copy` to or from the approved remotes. Job scripts must also write aggregates.")
    lines.append(f"{len(lines) - 1}. If `phiward run` says no broker is running, or a request is refused for a "
                 "reason only the operator can change, stop and ask the operator.")
    broken = _selfcheck_line()
    if broken:
        lines.append(f"{len(lines) - 1}. {broken}")
    return "\n".join(lines)


def _selfcheck_line() -> str:
    """When phiward's own files fail its self-check, wrapped MCP servers refuse to start and
    Claude Code shows only "failed to connect": the note says why, with the one step."""
    from phiward import selfcheck
    try:
        installed, problems = selfcheck.check_isolated()
    except Exception:  # noqa: BLE001 - a note must never stop a session
        return ""
    if not installed or not problems:
        return ""
    return (f"{selfcheck.refusal(problems)}, so wrapped MCP servers and "
            "`phiward launch` refuse to start: ask the operator to "
            + selfcheck.fix_text(problems, selfcheck._running_package()))


def main(argv: List[str]) -> int:
    if argv[:1] in (["-h"], ["--help"]):
        sys.stdout.write("usage: phiward session-note claude   (reads the hook payload on stdin)\n\n"
                         + (__doc__ or ""))
        return 0
    try:
        payload = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except (ValueError, OSError):
        payload = {}
    try:
        cwd = payload.get("cwd") if isinstance(payload, dict) else None
        cfg = config.load(cwd or os.getcwd())
        if cfg.problem or not cfg.has_protected_paths:
            return 0
        out = {"hookSpecificOutput": {"hookEventName": "SessionStart",
                                      "additionalContext": note(cfg)}}
        sys.stdout.write(json.dumps(out))
    except Exception:  # noqa: BLE001 - a note must never stop a session
        return 0
    return 0
