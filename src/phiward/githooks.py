"""Git hooks: `phiward git-hook pre-commit | pre-push | install [--force]`.

- pre-commit refuses a staged file inside the protected set, and any added line or file name that
  holds an identifier (the sanitizer, in table mode, would change it).
- pre-push refuses a push to a protected branch (`[git] protected_branches` in the repo config).
- install writes small `#!/bin/sh` hooks that call this module.

Output rule: what these hooks print can reach the AI model, so they never print a line's content or
a raw file name. They print the sanitized name, a line number and the placeholder words (for
example `<SAMPLEID>`). Any internal fault refuses (exit 1): a guard bug must not let a commit
through silently.
"""

import os
import re
import subprocess
import sys
from typing import List, Optional, Sequence, Tuple

from phiward import config, paths

MARKER = "# phiward managed hook"
HOOKS = ("pre-commit", "pre-push")
OVERRIDE = ("To override, the human can run `git commit --no-verify` "
            "(only the human should use it).")
PUSH_OVERRIDE = "To override, the human can run `git push --no-verify`."
FAULT = ("phiward: the git hook failed, so the operation is refused. "
         "Report this as a bug; the human can use --no-verify.")
BAD_CONFIG = ("phiward: refused: the guard configuration has a problem: "
              + config.DOCTOR_STEP + " to see it, and fixes it.")
USAGE = "usage: phiward git-hook pre-commit | pre-push | install [--force]"
HELP = USAGE + """

Commands:
  pre-commit       check the staged changes (git runs it before a commit)
  pre-push         check the branches to be pushed (git runs it before a push)
  install          write both hooks into this repository's hooks folder
  install --force  replace hooks that are there already

Options:
  -h, --help       show this help

pre-commit refuses a staged file inside a protected folder, and an added line or file name
that holds an identifier. pre-push refuses a push to a protected branch
(`[git] protected_branches` in the repo config). The hooks never print a line's content or a
raw file name. If a hook fails, the operation is refused.
"""

_PLACEHOLDER = re.compile(r"<[A-Za-z_][A-Za-z0-9_]*>")
_HUNK = re.compile(rb"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitError(Exception):
    pass


def _git(args: Sequence[str], cwd: str, stdin: Optional[bytes] = None) -> bytes:
    try:
        proc = subprocess.run(["git"] + list(args), cwd=cwd, input=stdin,
                              capture_output=True, check=False)
    except OSError as exc:
        raise GitError(type(exc).__name__)
    if proc.returncode != 0:
        raise GitError("git exited with %d" % proc.returncode)
    return proc.stdout


def _toplevel(cwd: str) -> str:
    return _git(["rev-parse", "--show-toplevel"], cwd).decode("utf-8", "surrogateescape").strip()


def _names(blob: bytes) -> List[str]:
    return [n.decode("utf-8", "surrogateescape") for n in blob.split(b"\0") if n]


def _words(text: str) -> List[str]:
    return _PLACEHOLDER.findall(text)


def _introduced(before: str, after: str) -> str:
    """The sorted placeholder words the cleaning added (never any content)."""
    new = set(_words(after)) - set(_words(before))
    return " ".join(sorted(new or set(_words(after)))) or "<MASKED>"


def _make_sanitizer(cfg: "config.Config"):
    from phiward.sanitize import Sanitizer
    # With no packs configured, from_config uses the default pack: the scan always runs.
    return Sanitizer.from_config(cfg)


def _added_lines(top: str, name: str) -> List[Tuple[int, str]]:
    """The added lines of one staged file as (line number, text); binary files give none."""
    out = _git(["--literal-pathspecs", "diff", "--cached", "-U0", "--no-color", "--no-ext-diff",
                "--", name], top)
    lines: List[Tuple[int, str]] = []
    cur = 0
    in_hunk = False
    for raw in out.split(b"\n"):
        m = _HUNK.match(raw)
        if m:
            cur = int(m.group(1))
            in_hunk = True
            continue
        if not in_hunk or raw.startswith(b"\\"):
            continue
        if raw.startswith(b"+"):
            text = raw[1:].decode("utf-8", "replace").rstrip("\r")
            lines.append((cur, text))
            cur += 1
    return lines


def pre_commit(cwd: str) -> int:
    top = _toplevel(cwd)
    cfg = config.load(top)
    if cfg.problem:
        print(BAD_CONFIG, file=sys.stderr)
        return 1
    try:
        san = _make_sanitizer(cfg)
    except Exception:  # noqa: BLE001 - SanitizerError or any fault: fail closed
        print("phiward: refused: the sanitizer could not be set up. "
              "Run `phiward doctor` to see why.", file=sys.stderr)
        return 1
    pset = paths.ProtectedSet(cfg.roots, cfg.patterns)
    staged = _names(_git(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"], top))
    report: List[str] = []
    inside = 0
    for name in staged:
        shown = san.clean(name)
        if pset and pset.relation(os.path.join(top, name)) == paths.INSIDE:
            # never the name: a repo-relative path does not match the absolute-root mask
            inside += 1
            continue
        if shown != name:
            report.append("  %s: the file name holds an identifier %s"
                          % (shown, _introduced(name, shown)))
        for lineno, text in _added_lines(top, name):
            cleaned = san.clean(text, table=True)
            if cleaned != text:
                report.append("  %s:%d: identifier %s" % (shown, lineno, _introduced(text, cleaned)))
    if inside:
        report.insert(0, f"  {inside} staged file(s) inside a protected folder (names withheld)")
    if not report:
        return 0
    print("phiward: commit refused. The staged changes hold protected data or identifiers:",
          file=sys.stderr)
    for line in report:
        print(line, file=sys.stderr)
    print(OVERRIDE, file=sys.stderr)
    return 1


def pre_push(cwd: str, stdin_text: str) -> int:
    top = _toplevel(cwd)
    cfg = config.load(top)
    if cfg.problem:
        print(BAD_CONFIG, file=sys.stderr)
        return 1
    blocked: List[str] = []
    for line in stdin_text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        remote_ref = parts[2]
        if remote_ref.startswith("refs/heads/"):
            branch = remote_ref[len("refs/heads/"):]
            if branch in cfg.protected_branches and branch not in blocked:
                blocked.append(branch)
    if not blocked:
        return 0
    for b in blocked:
        print("phiward: push refused: branch '%s' is protected." % b, file=sys.stderr)
    print(PUSH_OVERRIDE, file=sys.stderr)
    return 1


def _hooks_dir(top: str) -> str:
    try:
        custom = _git(["config", "--get", "core.hooksPath"], top).decode(
            "utf-8", "surrogateescape").strip()
    except GitError:
        custom = ""  # unset
    if custom:
        custom = os.path.expanduser(custom)
        return os.path.normpath(custom if os.path.isabs(custom) else os.path.join(top, custom))
    got = _git(["rev-parse", "--git-path", "hooks"], top).decode(
        "utf-8", "surrogateescape").strip()
    return os.path.normpath(got if os.path.isabs(got) else os.path.join(top, got))


def _script(name: str) -> str:
    return ("#!/bin/sh\n%s\n"
            "if command -v phiward >/dev/null 2>&1; then\n"
            "  exec phiward git-hook %s \"$@\"\n"
            "fi\n"
            "exec python3 -m phiward git-hook %s \"$@\"\n" % (MARKER, name, name))


def install(cwd: str, force: bool) -> int:
    top = _toplevel(cwd)
    hdir = _hooks_dir(top)
    plan: List[Tuple[str, str]] = []
    for name in HOOKS:
        target = os.path.join(hdir, name)
        if os.path.lexists(target) and not force:
            try:
                with open(target, encoding="utf-8", errors="replace") as fh:
                    ours = MARKER in fh.read()
            except OSError:
                ours = False
            if not ours:
                print("phiward: refused: %s already exists and is not ours. "
                      "Nothing was written. Use --force to replace it." % target,
                      file=sys.stderr)
                return 1
        plan.append((name, target))
    os.makedirs(hdir, exist_ok=True)
    for name, target in plan:
        from phiward import safeio
        safeio.write_new(target, _script(name), mode=0o755)  # never through a link
        print("phiward: wrote %s" % target)
    return 0


def main(argv: List[str]) -> int:
    try:
        if argv[:1] in (["-h"], ["--help"]):
            print(HELP, end="")
            return 0
        if not argv:
            print(USAGE, file=sys.stderr)
            return 2
        cmd, rest = argv[0], list(argv[1:])
        cwd = os.getcwd()
        if cmd == "pre-commit":
            return pre_commit(cwd)
        if cmd == "pre-push":
            data = sys.stdin.buffer.read().decode("utf-8", "replace")
            return pre_push(cwd, data)
        if cmd == "install":
            if "-h" in rest or "--help" in rest:  # the operator's; never pre-commit or pre-push
                print(HELP, end="")
                return 0
            if any(a != "--force" for a in rest):
                print(USAGE, file=sys.stderr)
                return 2
            return install(cwd, "--force" in rest)
        print(USAGE, file=sys.stderr)
        return 2
    except Exception:  # noqa: BLE001 - fail closed on any fault
        print(FAULT, file=sys.stderr)
        return 1
