"""`phiward session-note claude`: the start-of-session note.

Claude Code runs it as a SessionStart hook and adds what it prints to the session's context, so
every session knows, before its first refusal, that protected data goes through the gateway and
that the gateway is the intended route, not a way around the guards. It names no protected
path: only the rules, and the HPC hosts and programs the operator listed. When the project scan
(within its 2 s budget) finds subject IDs in the project's files, it says so by kind and count
(not under `phiward launch`, which scanned the project before the session); when the scan could
not run, it says that and names `phiward doctor`. It names the typical
limits of a session (credentials for git, `@file` mentions, package caches) with the way around
each, so the agent does not retry them. In a folder the operator lists in `[no_phi] folders`, a
`systemMessage` tells the person whether it is relaxed, why not, or that the scan found data
there or could not run. It never fails a session: on any error it prints nothing.
"""
# Without this note, a test session called `phiward run` "a way around the protection".

import json
import os
import re
import sys
from typing import List, Optional

from phiward import config


def note(cfg: config.Config, project: str = "", no_phi: bool = False,
         found: Optional[str] = None) -> str:
    """`no_phi`: the session's project is a no-PHI folder that passed its check. `found`: what
    the project scan found (`_scan_found`), when the caller already ran it."""
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
    if no_phi:
        lines.append(f"{len(lines) - 1}. {NO_PHI_CONTEXT}")
    elif cfg.has_protected_paths and not cfg.shell_best_effort:
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
    loader = _loader_line(project)
    if loader:
        lines.append(f"{len(lines) - 1}. {loader}")
    found = _scan_found(cfg, project) if found is None else found
    if found == SCAN_FAILED:
        lines.append(f"{len(lines) - 1}. phiward's project scan could not run, so this note "
                     "cannot say whether the project holds subject IDs outside the protected "
                     "roots: " + config.DOCTOR_STEP + ".")
    elif found:
        lines.append(f"{len(lines) - 1}. phiward's project scan found {found} in this project, "
                     "outside the protected roots: do not read, quote or copy those files; tell "
                     "the operator to run `phiward doctor --show-paths` in their own terminal.")
    return "\n".join(lines)


# the no-PHI folder's lines (PLAN-USABILITY-FIXES §5): for the model, and for the person
NO_PHI_CONTEXT = ("The operator marked this folder as holding no PHI. Protected paths are still "
                  "refused; use phiward run for them.")
NO_PHI_RELAXED = ("phiward: no-PHI folder (your user config): the shell's sandbox openers are "
                  "checked by text here; protected roots are still denied and prompts still "
                  "scanned.")
NO_PHI_FOUND = ("phiward: WARNING: this folder is listed as holding no PHI, but the project scan "
                "found {found}; check it (phiward doctor --show-paths) or take it off [no_phi] "
                "folders.")
NO_PHI_UNSCANNED = ("phiward: WARNING: this folder is listed as holding no PHI, but the project "
                    "scan could not run; run phiward doctor in your own terminal.")


def no_phi_refused(why: str, step: str = "") -> str:
    """Why a listed folder is not relaxed, with the step that relaxes it when there is one, for
    the person (the note and doctor; `claude_settings.no_phi_relaxed`)."""
    return (f"phiward: [no_phi] folders lists this folder, but {why}: not relaxed"
            + (f"; to relax it, {step}." if step else "."))


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


SCAN_FAILED = "the project scan could not run"  # `_scan_found` then; never a `found_text`


def _scan_found(cfg: config.Config, project: str) -> str:
    """The project scan (projectscan) within launch's time budget: kinds and counts of what it
    found, "", or SCAN_FAILED. A warning only: it never stops a session."""
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
        return SCAN_FAILED
    if r.error:
        return SCAN_FAILED
    return projectscan.found_text(r) if r.hits else ""


_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _loader_line(project: str) -> str:
    """The loader keys (`env.LD_*` and the like) the project's Claude Code settings set: the
    shell that starts each hook loads them before the hook clears them (docs/threat-model.md).
    Key names only, and at most 5: a key is the project's text, and the model reads this note."""
    if not project:
        return ""
    from phiward import claude_settings, pathid
    try:
        keys = claude_settings.project_loader_keys(project, pathid.home())
    except Exception:  # noqa: BLE001 - a note must never stop a session
        return ""
    keys = [k for k in keys if isinstance(k, str) and _KEY.fullmatch(k)][:5]
    if not keys:
        return ""
    return ("This project's Claude Code settings set " + ", ".join("env." + k for k in keys)
            + ": programs load these before phiward's hooks clear them; tell the operator.")


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
        found = _scan_found(cfg, project)
        # the hook's own test (adapters.decide): the named project is a listed folder
        from phiward import claude_settings, pathid
        home = pathid.home()
        entry, why = claude_settings.no_phi_relaxed(
            cfg, os.environ.get("CLAUDE_PROJECT_DIR", ""), home,
            claude_settings.confining_folders(project, home)) \
            if claude_settings.named_project_holds(project) else ("", None)
        out: dict = {"hookSpecificOutput": {"hookEventName": "SessionStart",
                                            "additionalContext": note(
                                                cfg, project, bool(entry) and why is None,
                                                found)}}
        if entry:
            out["systemMessage"] = (no_phi_refused(why.text, why.step) if why else
                                    NO_PHI_UNSCANNED if found == SCAN_FAILED else
                                    NO_PHI_FOUND.format(found=found) if found else NO_PHI_RELAXED)
        sys.stdout.write(json.dumps(out))
    except Exception:  # noqa: BLE001 - a note must never stop a session
        return 0
    return 0
