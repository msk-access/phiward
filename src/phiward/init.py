"""`phiward init [--root DIR]...`: set up a project for phiward in one step.

In the project folder (the top of a repository) it:
- adds phiward's rules to `AGENTS.md` (the "Protected data (phiward)" section), unless they are
  there;
- with `--root`, adds those folders to the project's `.phiward.toml` (a repo config can add
  protection, never remove it);
- writes the project's Claude Code settings (`install claude --project --no-hooks`): the sandbox
  and permission rules that are the same for every contributor into `.claude/settings.json`, and
  this person's own into `.claude/settings.local.json`;
- adds `.claude/settings.local.json` to `.gitignore`;
- installs the git hooks (when the folder is a git repository).

It only adds, so an agent may run it. Each contributor runs it once (it is safe to run again).
The hooks of each session come from the user wiring (`phiward install claude --user`).
"""

import os
import sys
from typing import List

from phiward import config, pathid

USAGE = "usage: phiward init [--root DIR]...\n"
MARK = "## Protected data (phiward)"


def _agents_text() -> str:
    with open(os.path.join(os.path.dirname(__file__), "data", "agents-section.md"),
              encoding="utf-8") as fh:
        return fh.read()


def _add_agents(project: str, out: List[str]) -> None:
    path = os.path.join(project, "AGENTS.md")
    old = ""
    if os.path.lexists(path):
        if os.path.islink(path) or not os.path.isfile(path):
            out.append("AGENTS.md: not a plain file; not changed")
            return
        old = _read_plain(path)
        if MARK in old:
            out.append("AGENTS.md: the phiward rules are there already")
            return
    _write_plain(path, old + ("\n" if old and not old.endswith("\n\n") else "") + _agents_text())
    out.append("AGENTS.md: added the phiward rules")


def _read_plain(path: str) -> str:
    from phiward import safeio
    return safeio.read_text(path)  # never through a link


def _write_plain(path: str, text: str) -> None:
    """The whole file again, through a fresh name (`safeio.write_new`): a link or a second name
    put there meanwhile is replaced, never written through. Its mode is kept."""
    import stat as _stat
    from phiward import safeio
    try:
        mode = _stat.S_IMODE(os.lstat(path).st_mode)
    except OSError:
        mode = 0o644
    safeio.write_new(path, text, mode=mode)


def _add_roots(project: str, roots: List[str], out: List[str]) -> int:
    if not roots:
        return 0
    from phiward import setup_cmd
    home = pathid.home()
    path = os.path.join(project, config.REPO_FILE)
    if os.path.islink(path):
        out.append(f"{config.REPO_FILE}: a link; not changed")
        return 2
    try:
        data = setup_cmd._read_existing(path) if os.path.exists(path) else {}
    except Exception:  # noqa: BLE001 - say so, change nothing
        out.append(f"{config.REPO_FILE}: cannot be read; not changed")
        return 2
    have = data.setdefault("protected_paths", {}).setdefault("roots", [])
    for r in roots:
        full = r if r.startswith(("/", "~")) else os.path.normpath(os.path.join(project, r))
        why = setup_cmd.check_root(full, home)
        if why:
            out.append(f"--root {r}: {why}; not added")
            return 2
        if full not in have:
            have.append(full)
    setup_cmd._write(path, setup_cmd.dump(data).replace(
        "# phiward user config, written by `phiward setup`.", "# phiward repo config"))
    out.append(f"{config.REPO_FILE}: {len(have)} protected root(s)")
    return 0


def _add_gitignore(project: str, out: List[str]) -> None:
    path = os.path.join(project, ".gitignore")
    line = ".claude/settings.local.json"
    old = ""
    if os.path.isfile(path) and not os.path.islink(path):
        old = _read_plain(path)
        if line in old.splitlines():
            out.append(".gitignore: has the personal settings line already")
            return
    elif os.path.lexists(path):
        out.append(".gitignore: not a plain file; not changed")
        return
    _write_plain(path, old + ("" if not old or old.endswith("\n") else "\n") + line + "\n")
    out.append(".gitignore: added .claude/settings.local.json")


def main(argv: List[str]) -> int:
    if argv[:1] in (["-h"], ["--help"]):
        sys.stdout.write(USAGE + "\n" + (__doc__ or ""))
        return 0
    roots: List[str] = []
    it = iter(argv)
    for w in it:
        if w == "--root":
            v = next(it, "")
            if not v:
                sys.stderr.write(USAGE)
                return 2
            roots.append(v)
        else:
            sys.stderr.write(USAGE)
            return 2
    project = os.getcwd()
    home = os.path.realpath(pathid.home())
    if os.path.realpath(project) in ("/", home):
        sys.stderr.write("phiward init: run it in a project folder, not in / or your home "
                         "folder.\n")
        return 2
    out: List[str] = []
    _add_agents(project, out)
    code = _add_roots(project, roots, out)
    _add_gitignore(project, out)
    from phiward import install
    rc = install.main(["claude", "--project", "--no-hooks", "--write", "--yes"])
    out.append("Claude Code project settings: " + (
        "written" if rc == 0 else "not written (install said why, above): run "
        "`phiward init` again here in your own terminal"))
    if os.path.isdir(os.path.join(project, ".git")):
        from phiward import githooks
        g = githooks.install(project, False)
        out.append("git hooks: " + ("installed" if g == 0 else f"not installed ({g})"))
    else:
        out.append("git hooks: not a git repository; skipped")
    sys.stdout.write("\nphiward init:\n" + "".join(f"  {line}\n" for line in out))
    commit = [f for f in ("AGENTS.md", ".phiward.toml", ".gitignore", ".claude/settings.json")
              if os.path.exists(os.path.join(project, f))
              and not (f == ".claude/settings.json" and rc != 0)]
    if commit:
        sys.stdout.write("Commit " + ", ".join(commit) + "; never .claude/settings.local.json "
                         "(in a repository that is not yours: list them in .git/info/exclude).\n")
    return code or rc
