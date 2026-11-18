"""Helpers shared by the test files (made-up trees only; see conftest.py for the fixtures)."""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from phiward import config, confine
from phiward.core import SHELL, Action
from phiward.guards import protected_paths


# Whether the gateway's confinement works here (None) or why not: one sandboxed `true`, at
# import (not inside a test, whose HOME and PATH are made up). With PHIWARD_REQUIRE_CONFINE=1
# (CI) a missing backend fails the run instead of skipping the tests that need it.
CONFINE_WHY = confine.self_test()
if CONFINE_WHY and os.environ.get("PHIWARD_REQUIRE_CONFINE") == "1":
    raise RuntimeError(f"confinement is required here but does not work: {CONFINE_WHY}")
needs_confine = pytest.mark.skipif(CONFINE_WHY is not None,
                                   reason=f"no confinement: {CONFINE_WHY}")


class Tty:
    """A stdin that is a terminal: the operator's own (printing paths needs one)."""

    def isatty(self):
        return True


def gone(out, words):
    """No word of `words` is left in `out` (as a whole word)."""
    for word in words.split():
        assert not re.search(rf"(?<![A-Za-z0-9]){re.escape(word)}(?![A-Za-z0-9])", out), (word, out)


def protect(tree, patterns, root="phi", best_effort=True):
    """The user config with the root `tree/<root>` and `patterns`, loaded for the repo.
    `best_effort`: `[shell] best_effort`, on by default here, since most shell tests check the
    text check that it keeps (without it, every unconfined shell call is refused)."""
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = [{json.dumps(f"{tree}/{root}")}]\n'
        f'patterns = {json.dumps(patterns)}\n'
        + ("[shell]\nbest_effort = true\n" if best_effort else ""))
    return config.load(str(tree / "repo"))


def check_shell(tree, cfg, cmd):
    """The hook's decision for a shell command run in the repo."""
    return protected_paths.check(Action(SHELL, str(tree / "repo"), command=cmd), cfg)


def user_settings(tree, data):
    """Claude Code's user settings in the tree's home folder."""
    d = tree / "home" / ".claude"
    d.mkdir(parents=True, exist_ok=True)
    (d / "settings.json").write_text(json.dumps(data))


def git_repo(top: Path):
    """A git repository with one commit."""
    top.mkdir(parents=True, exist_ok=True)

    def git(*a):
        subprocess.run(["git", *a], cwd=top, check=True, capture_output=True)
    git("init", "-q")
    # no background maintenance after the commit: it works in .git while a test removes it
    git("config", "maintenance.auto", "false")
    git("config", "gc.auto", "0")
    (top / "f").write_text("x\n")
    git("add", "f")
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "i")


def launcher_by_path(monkeypatch, module, exe):
    """Give the made-up MCP entries of a test module (its UPPER-case constants) the launcher by
    its full path, `phiward` by name never counts as wrapped (test_v2_launcher_identity), and an
    entry id of their own (test_v2_entry_id)."""
    def fix(x):
        if isinstance(x, dict):
            y = {k: fix(v) for k, v in x.items()}
            if y.get("command") == "phiward":
                y["command"] = str(exe)
                args = y.get("args")
                if isinstance(args, list) and args[:1] == ["launch"] and "--entry" not in args:
                    # its own id, as `wrap` gives it (test_v2_entry_id); a copy of the entry
                    # keeps the same one
                    import hashlib
                    eid = hashlib.sha256(repr(args).encode()).hexdigest()[:16]
                    y["args"] = ["launch", "--entry", eid] + args[1:]
            return y
        if isinstance(x, list):
            return [fix(v) for v in x]
        if isinstance(x, tuple):
            return tuple(fix(v) for v in x)
        return x
    for k, v in list(vars(module).items()):
        if k.isupper() and isinstance(v, (dict, list, tuple)):
            monkeypatch.setattr(module, k, fix(v))
    monkeypatch.setattr(module, "PHIWARD", str(exe), raising=False)  # for entries made in a test


def installed_site(tree, scripts=("phiward", "agent-guards"), package=True):
    """A made-up installed phiward: site-packages/phiward, its record (with package files, unless
    `package` is false: an editable install), and its bin/ scripts. (record, package, launcher)"""
    site = tree / "inst" / "lib" / "python3" / "site-packages"
    (site / "phiward").mkdir(parents=True)
    (site / "phiward" / "__init__.py").write_text("")
    info = site / "phiward-0.2.0b1.dist-info"
    info.mkdir()
    rows = ["phiward/__init__.py,sha256=x,0"] if package else ["__editable__.phiward.pth,,"]
    bin_ = tree / "inst" / "bin"
    bin_.mkdir(parents=True)
    for n in scripts:
        (bin_ / n).write_text("#!/bin/sh\n")
        (bin_ / n).chmod(0o755)
        rows.append(f"../../../bin/{n},sha256=y,0")
    rows.append("phiward-0.2.0b1.dist-info/RECORD,,")
    (info / "RECORD").write_text("\n".join(rows) + "\n")
    return str(info / "RECORD"), str(site / "phiward"), str(bin_ / "phiward")


def confinement(project, home, roots, patterns, guard=(), env=None, hidden=(), user_data=None):
    """(confined, why not and its step) in one string, for tests that read it so (round 6:
    phiward itself uses `claude_settings.confinement_reason`)."""
    from phiward import claude_settings
    r = claude_settings.confinement_reason(project, home, roots, patterns, guard, env, hidden,
                                           user_data)
    return (True, "") if r is None else (False, f"{r.text}; to fix it: {r.step}")


def write_file(p, mode=0o644, text="x = 1\n"):
    """A file at `p` (its folders made) with `text` and `mode`."""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    os.chmod(p, mode)
    return p


def ready_line(proc, word="READY", seconds=60):
    """The first line of `proc`'s stdout that starts with `word`, waiting at most `seconds`
    (the test fails at the limit, it does not go on as if the other side were there). It reads
    the pipe's descriptor itself, so a line that came in the same write as an earlier one is
    not left in a buffer `select` cannot see. Call it before anything else reads stdout."""
    import select
    import time
    fd = proc.stdout.fileno()
    end = time.monotonic() + seconds
    data = b""
    while True:
        lines = data.split(b"\n")
        for line in lines[:-1]:
            if line.decode("utf-8", "replace").startswith(word):
                return line.decode("utf-8", "replace") + "\n"
        left = end - time.monotonic()
        r = select.select([fd], [], [], max(0.0, left))[0] if left > 0 else []
        chunk = os.read(fd, 65536) if r else b""
        if not chunk:
            proc.kill()
            raise AssertionError(f"no {word} line within {seconds} s: {data!r}")
        data += chunk
