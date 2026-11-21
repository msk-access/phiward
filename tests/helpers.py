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


def landlock_abi() -> int:
    """Linux: the kernel's Landlock ABI version (0 without Landlock, and on other systems)."""
    import ctypes
    import sys
    if not sys.platform.startswith("linux"):
        return 0
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return max(0, libc.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1)))


# A made-up stand-in for Claude Code's `apply-seccomp` (usage: apply-seccomp CMD [ARG]...):
# it denies socket(AF_UNIX) with EPERM and io_uring with ENOSYS, then runs CMD. With
# works=False it runs CMD with no filter, as a broken or replaced filter would.
_FAKE_FILTER = r'''
import ctypes, os, platform, struct, sys
if WORKS:
    m = platform.machine()
    arch = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}[m]
    sock = 41 if m == "x86_64" else 198
    ld, jeq, ret = 0x20, 0x15, 0x06
    p = [(ld, 0, 0, 4), (jeq, 1, 0, arch), (ret, 0, 0, 0x80000000), (ld, 0, 0, 0)]
    for n in (425, 426, 427):
        p += [(jeq, 0, 1, n), (ret, 0, 0, 0x50026)]
    p += [(jeq, 0, 3, sock), (ld, 0, 0, 16), (jeq, 0, 1, 1), (ret, 0, 0, 0x50001),
          (ret, 0, 0, 0x7FFF0000)]
    b = b"".join(struct.pack("<HBBI", *i) for i in p)
    buf = ctypes.create_string_buffer(b, len(b))
    class F(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("f", ctypes.c_void_p)]
    fp = F(len(p), ctypes.cast(buf, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(22, 2, ctypes.byref(fp), 0, 0) != 0:
        sys.exit("apply-seccomp (made up): the filter could not be set")
os.execvp(sys.argv[1], sys.argv[1:])
'''


# The help of the made-up native build: commander's layout, as Claude Code prints it
CLAUDE_HELP = """Usage: claude [options] [command] [prompt]

Claude Code (made up)

Arguments:
  prompt                      Your prompt

Options:
  -d, --debug [filter]        Debug mode, with an optional filter
  --model <model>             The model for the session
  -p, --print                 Print the answer and exit
  --settings <file-or-json>   Settings to load
  --add-dir <directories...>  More folders
  -h, --help                  Display help for command

Commands:
  doctor                      Check the installation
  logs [options] [id]         Show a background session's log
  mcp                         Configure MCP servers
  sandbox                     Sandbox status
  ultrareview                 Review in the cloud
  update|upgrade              Update Claude Code
  help [command]              display help for command
"""


def fake_native_claude(path, works=True, runs=True, python=False, help=CLAUDE_HELP):
    """A made-up stand-in for Claude Code's native build at `path`: started with
    ARGV0=apply-seccomp it is the filter (it denies socket(AF_UNIX), unless not `works`, and runs
    CMD; with runs=False it exits 0 without running CMD), as the real binary carries
    apply-seccomp; otherwise it prints ARGV and its arguments as JSON, or with `python` runs as
    Python with its arguments (python -c CODE ignores the --settings launch adds last). With
    just --help it prints `help`."""
    import sys
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"#!{sys.executable} -IS\nimport json, os, sys\n"
                 f"if sys.argv[1:] == ['--help']:\n    print({help!r}, end='')\n    sys.exit(0)\n"
                 "if os.environ.get('ARGV0') == 'apply-seccomp':\n"
                 f"    if not {bool(runs)}:\n        sys.exit(0)\n"
                 f"    WORKS = {bool(works)}\n" +
                 "".join("    " + ln + "\n" for ln in _FAKE_FILTER.strip().splitlines()) +
                 ("os.execv(sys.executable, [sys.executable] + sys.argv[1:])\n" if python else
                  "print('ARGV', json.dumps(sys.argv[1:]))\n"))
    os.chmod(p, 0o755)
    return p


def tool_py(tree, tool="claude") -> str:
    """The Python a test runs under `launch --tool TOOL`: for claude, the made-up native build
    that runs as Python, which the tree fixture plants (below Landlock ABI 9 launch judges the
    seccomp filter of the program that runs, and Python itself is not Claude Code); else Python
    itself."""
    import sys
    return str(Path(tree) / "claude-py" / "claude") if tool == "claude" else sys.executable
