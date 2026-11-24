"""`phiward session-note claude`: the start-of-session note.

Claude Code runs it as a SessionStart hook and adds what it prints to the session's context, so
every session knows, before its first refusal, that protected data goes through the gateway and
that the gateway is the intended route, not a way around the guards. It names no protected
path: only the rules, and the HPC hosts and programs the operator listed. When the project scan
(within its 2 s budget) finds subject IDs in the project's files, it says so by kind and count
(not under `phiward launch`, which scanned the project before the session). It names the typical
limits of a session (credentials for git, `@file` mentions, package caches) with the way around
each, so the agent does not retry them. It never fails a session: on any error it prints nothing.
"""
# Without this note, a test session called `phiward run` "a way around the protection".

import json
import os
import sys
from typing import List

from phiward import config


def note(cfg: config.Config, project: str = "") -> str:
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
    lines.append(f"{len(lines) - 1}. {_limits_line()}")
    broken = _selfcheck_line()
    if broken:
        lines.append(f"{len(lines) - 1}. {broken}")
    found = _scan_line(cfg, project)
    if found:
        lines.append(f"{len(lines) - 1}. {found}")
    return "\n".join(lines)


LIMITS_GIT = ("git push, pull and fetch that need the operator's SSH key or keychain run in the "
              "operator's own terminal")
LIMITS_MENTIONS = "`@file` mentions attach nothing here: read the file with the Read tool"
LIMITS_CACHES = ("the pip, uv and npm caches outside the project are read-only: use `pip install "
                 "--no-cache-dir`, or set PIP_CACHE_DIR=$TMPDIR/pip, UV_CACHE_DIR=$TMPDIR/uv and "
                 "npm_config_cache=$TMPDIR/npm")


def _limits_line() -> str:
    """What typical work meets in this session, each with its way around: credentials are not
    reachable, `@file` mentions are off (when the settings turn them off), and package caches
    are read-only in Claude Code's sandbox (not under `phiward launch`, which gives the session
    caches of its own)."""
    parts = [LIMITS_GIT]
    from phiward import install
    if os.environ.get(install.MENTIONS_OFF) == "1":
        parts.append(LIMITS_MENTIONS)
    try:
        from phiward import wholetool
        launched = wholetool.already_confined(dict(os.environ))
    except Exception:  # noqa: BLE001 - a note must never stop a session
        launched = False
    if not launched:
        parts.append(LIMITS_CACHES)
    return "Known limits of this session, each with its way around: " + "; ".join(parts) + "."


def _scan_line(cfg: config.Config, project: str) -> str:
    """The project scan (projectscan) within launch's time budget: kinds and counts of what it
    found, or "". A warning only: it never stops a session."""
    if not project:
        return ""
    from phiward import projectscan, wholetool
    try:
        # under `phiward launch`, which scanned the project just before (it refuses on a
        # finding); its proof is the kernel profile, not a variable a settings file could set
        if wholetool.already_confined(dict(os.environ)) or projectscan.place_problem(cfg, project):
            return ""
        r = projectscan.scan(cfg, project, projectscan.deadline())
    except Exception:  # noqa: BLE001 - a note must never stop a session
        return ""
    if not r.hits:
        return ""
    return (f"phiward's project scan found {projectscan.found_text(r)} in this project, outside "
            "the protected roots: do not read, quote or copy those files; tell the operator to "
            "run `phiward doctor --show-paths` in their own terminal.")


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
                         "Options:\n  -h, --help   show this help\n\n"
                         + (__doc__ or ""))
        return 0
    try:
        payload = json.load(sys.stdin) if not sys.stdin.isatty() else {}
    except (ValueError, OSError):
        payload = {}
    try:
        cwd = payload.get("cwd") if isinstance(payload, dict) else None
        project = cwd if isinstance(cwd, str) and cwd else os.getcwd()
        cfg = config.load(project)
        if cfg.problem or not cfg.has_protected_paths:
            return 0
        out = {"hookSpecificOutput": {"hookEventName": "SessionStart",
                                      "additionalContext": note(cfg, project)}}
        sys.stdout.write(json.dumps(out))
    except Exception:  # noqa: BLE001 - a note must never stop a session
        return 0
    return 0
