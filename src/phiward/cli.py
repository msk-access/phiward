"""The `phiward` command. Each subcommand lives in its own module and is imported on use,
so a hook call loads only what it needs."""

import sys
from typing import List, Optional

USAGE = """usage: phiward <command> [args]
       phiward <command> --help
       phiward --version          the installed version (also: phiward version, -V)

The operator's commands (run them in your own terminal, not through an agent):
  setup              first-time setup: asks questions and writes the user config
                     (--first-run: the first config without questions, only when none exists)
  pin                approve the listed programs; record the derived protected folders
  broker             run the gateway commands outside the agent; start it yourself
                     (broker --service [--write]: install it as a login service)
  carryover status|add|show|accept|reset
                     read and keep what `launch` sessions put in quarantine
  pseudonymize (--new-key NAME | --key NAME) --columns H[=NEW],... IN OUT
                     a copy of one table with its ID columns coded (S0042), inside a
                     protected root; the key stays in ~/.phiward/backups/keys

Wire a project and a tool:
  init [--root DIR]  set up a project: AGENTS.md rules, settings, git hooks (it only adds)
  install claude     print the wiring for Claude Code, or write it after a diff and a yes
  doctor             show the config in force and what may turn the guards off
  mcp list|wrap|unwrap  show your MCP servers; run one under `phiward launch` (wrap), or
                     not (unwrap, in your own terminal)

Work with protected data:
  run [GRANTS] -- CMD  run CMD with read access to protected data, output masked
  copy SRC... DST    copy into a protected folder or a configured remote, nothing printed
  launch [--tool NAME] [--memory] [--report FILE] [-- PROGRAM...]
                     run a whole agent tool in the kernel profile (Mode B)
  check -- CMD       show the decision for a shell command in the current folder
  sanitize           filter stdin to stdout, masking protected paths and identifiers

Called by tools (you rarely run these yourself):
  hook claude        read a hook payload on stdin and reply as Claude Code expects
  session-note claude  the start-of-session note (a SessionStart hook)
  mcp                an MCP server with the gateway as tools
  git-hook NAME      run a git hook (pre-commit, pre-push), or install them
"""


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:3] == ["hook", "claude", "--launched"]:
        # written only by `launch` into the tool's own settings: the kernel decides, this is a
        # fast first layer; without the roots it is the full hook (a variable alone never
        # chooses it)
        if "PHIWARD_HOOK_ROOTS" in __import__("os").environ:
            from phiward import fasthook
            return fasthook.main()
        args = args[:2]
    if args[:1] in (["--version"], ["-V"], ["version"]):
        from phiward import __version__
        print(f"phiward {__version__}")
        return 0
    if not args or args[0] in ("-h", "--help", "help"):
        print(USAGE, end="")
        return 0 if args else 2
    cmd, rest = args[0], args[1:]
    if cmd == "hook":
        from phiward.adapters import run_hook
        return run_hook(rest)
    if cmd == "init":
        from phiward import init
        return init.main(rest)
    if cmd == "mcp":
        from phiward import mcp
        return mcp.main(rest)
    if cmd == "session-note":
        from phiward import session_note
        return session_note.main(rest)
    if cmd == "check":
        from phiward.adapters import run_check
        return run_check(rest)
    if cmd == "sanitize":
        from phiward import sanitize
        return sanitize.main(rest)
    if cmd == "run":
        from phiward import run
        return run.main(rest)
    if cmd == "setup":
        from phiward import setup_cmd
        return setup_cmd.main(rest)
    if cmd == "pin":
        from phiward import pin
        return pin.main(rest)
    if cmd == "broker":
        from phiward import broker
        return broker.main(rest)
    if cmd == "launch":
        from phiward import wholetool
        return wholetool.main(rest)
    if cmd == "pseudonymize":
        from phiward import pseudonymize
        return pseudonymize.main(rest)
    if cmd == "carryover":
        from phiward import carryover
        return carryover.main(rest)
    if cmd == "copy":
        from phiward import copying as copy
        return copy.main(rest)
    if cmd == "git-hook":
        from phiward import githooks
        return githooks.main(rest)
    if cmd == "install":
        from phiward.adapters import run_install
        return run_install(rest)
    if cmd == "doctor":
        from phiward import doctor
        return doctor.main(rest)
    print(f"phiward: unknown command '{cmd}'\n" + USAGE, file=sys.stderr, end="")
    return 2
