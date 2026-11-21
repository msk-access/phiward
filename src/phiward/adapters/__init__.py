"""Adapters: translate a tool's hook payload into an Action and a Decision into the tool's reply.
No policy lives here."""

import os
import sys
from dataclasses import replace
from typing import Dict, List

from phiward import config, pathid
from phiward.core import ALLOW, ASK, SHELL, Action, Decision, Guard, dispatch
from phiward.guards import protected_paths

GUARDS: Dict[str, Guard] = {protected_paths.NAME: protected_paths.check}


def decide(action: Action, claude_sandbox: bool = False) -> Decision:
    """`claude_sandbox`: the call may run in Claude Code's sandbox (the only thing that confines
    a shell call; phiward does not confine the shell itself)."""
    cfg = config.load(action.cwd)
    # only Claude Code's own shell tools run in its sandbox
    claude_sandbox = claude_sandbox and action.tool in ("Bash", "Monitor")
    # also before protected paths exist: the hidden list is guarded the same way
    if claude_sandbox and action.kind == SHELL and not cfg.problem:
        from phiward import claude_settings
        home = pathid.home()
        from phiward import hidden
        secret = [h for h in hidden.paths(None, cfg, session=True) if os.path.lexists(h)]
        # the named project must hold the call (otherwise the settings Claude Code reads may be
        # in a folder that cannot be found from it), and it and every project folder in it
        # above the call must confine it (claude_settings.confining_folders)
        folders = claude_settings.confining_folders(action.cwd, home) or [None]
        if not claude_settings.named_project_holds(action.cwd):
            r = (claude_settings.Reason("Claude Code did not give the hook $CLAUDE_PROJECT_DIR",
                                        claude_settings.NO_PROJECT_STEP)
                 if not os.environ.get("CLAUDE_PROJECT_DIR") else
                 claude_settings.Reason("the command runs outside the session's project "
                                        "($CLAUDE_PROJECT_DIR), whose settings phiward checks",
                                        claude_settings.OUTSIDE_PROJECT_STEP))
        else:
            r = None
            for p in folders:
                r = claude_settings.confinement_reason(p, home, cfg.all_roots, cfg.patterns,
                                                       config.guard_files(), hidden=secret)
                if r is not None:
                    break
        action = replace(action, confined=r is None, unconfined_why=r.text if r else "",
                         unconfined_step=r.step if r else "")
    return dispatch(action, cfg, GUARDS)


HOOK_HELP = """usage: phiward hook claude

Options:
  -h, --help   show this help

Read a Claude Code hook payload on stdin and reply as Claude Code expects. Claude Code runs it
before each tool call; `phiward install claude` writes the wiring. It refuses a tool call that
would read protected data. claude is the only tool for now.
"""

CHECK_HELP = """usage: phiward check [--cwd DIR] -- COMMAND...

Options:
  --cwd DIR    decide as if the command ran in DIR (default: the current folder)
  -h, --help   show this help

Show what the guard decides for a shell command, and why, as if it ran in Claude Code's
sandbox (outside it, only gateway calls run). Nothing runs. The exit status is 0 when the
command is allowed, 1 when it would ask, and 2 when it is refused.
"""


def run_hook(argv: List[str]) -> int:
    if argv[:1] in (["-h"], ["--help"]):
        sys.stdout.write(HOOK_HELP)
        return 0
    if argv[:1] != ["claude"]:
        print("usage: phiward hook claude   (claude is the only tool for now)", file=sys.stderr)
        return 2
    from phiward.adapters import claude
    return claude.main(sys.stdin, sys.stdout, sys.stderr)


def run_check(argv: List[str]) -> int:
    """`phiward check [--cwd DIR] -- COMMAND...`: the decision for a shell command."""
    if argv[:1] in (["-h"], ["--help"]):
        sys.stdout.write(CHECK_HELP)
        return 0
    cwd = os.getcwd()
    args = list(argv)
    if args[:1] == ["--cwd"] and len(args) > 1:
        cwd, args = os.path.abspath(args[1]), args[2:]
    if args[:1] == ["--"]:
        args = args[1:]
    if not args:
        print("usage: phiward check [--cwd DIR] -- COMMAND", file=sys.stderr)
        return 2
    # as under Claude Code's sandbox: without it every shell call but the gateway is refused,
    # and that answer would say nothing about the command
    d = decide(Action(SHELL, cwd, command=" ".join(args), confined=True))
    print(d.verdict + (f": {d.reason}" if d.reason else "") +
          " (as in Claude Code's sandbox)")
    return {ALLOW: 0, ASK: 1}.get(d.verdict, 2)


def run_install(argv: List[str]) -> int:
    from phiward import install
    return install.main(argv)
