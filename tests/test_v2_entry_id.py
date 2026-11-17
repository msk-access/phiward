"""One entry, one launcher: `phiward mcp wrap` gives each entry its own id (`phiward launch
--entry ID -- PROGRAM`), so each entry's launcher has its own launch hash. A launcher vouches
only for the entry with its id, and an id found more than once in the config files, in any
spelling or wrapper (`nice`, `sh -c "..."`, a copy of the entry), makes no entry with it
trusted: no entry is parsed for what it might start. A configured entry wrapped without an id
(an older wrap) counts as not wrapped, and `wrap` gives it one. Made-up trees only."""

import io
import json
import os
import re
import sys

import pytest

from phiward import mcp_config
from phiward.adapters import claude
from helpers import Tty, protect

ID = "0123456789abcdef"
RUN = {"command": "id"}


@pytest.fixture()
def t(tree, monkeypatch, launchers):
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(sys, "stdin", Tty())
    protect(tree, [], best_effort=False)
    mcp_config._launcher_exes.cache_clear()
    return _T(tree, launchers, str(b / "phiward"))


class _T:
    """The made-up tree, its stand-in launchers and its launcher's path."""

    def __init__(self, tree, launchers, exe):
        self.tree, self.L, self.exe = tree, launchers, exe

    def __truediv__(self, other):
        return self.tree / other


def _wrapped(t, eid=ID, prog=("npx", "-y", "some-server")):
    return {"command": t.exe, "args": ["launch", "--entry", eid, "--"] + list(prog)}


def _user(t, servers):
    (t / "home" / ".claude.json").write_text(json.dumps({"mcpServers": servers}))


def _hook(t, name):
    p = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(t / "repo"),
         "permission_mode": "default", "tool_name": f"mcp__{name}__run_command",
         "tool_input": RUN, "mcp_server": {"name": name, "source": "user"}}
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), io.StringIO())


def _start(t, spec):
    t.L.start(mcp_config._spec_hash(spec))


def test_wrap_gives_each_entry_its_own_id(t):
    _user(t, {"a": {"command": "npx", "args": ["x"]}, "b": {"command": "npx", "args": ["x"]}})
    assert mcp_config.main(["wrap", "--all", "--yes"]) == 0
    got = json.loads((t / "home" / ".claude.json").read_text())["mcpServers"]
    ids = [g["args"][g["args"].index("--entry") + 1] for g in (got["a"], got["b"])]
    assert all(re.fullmatch(r"[0-9a-f]{16}", i) for i in ids) and ids[0] != ids[1]
    assert mcp_config.entry_state(got["a"]) == "wrapped"


def test_an_entry_with_its_own_launcher_is_trusted(t):
    _user(t, {"a": _wrapped(t)})
    assert _hook(t, "a") == 2  # no launcher yet: still running as it started
    _start(t, _wrapped(t))
    assert _hook(t, "a") == 0


def test_the_launcher_of_another_entry_does_not_vouch(t):
    # same program, another entry: before the wrap, `a` may still run bare
    _user(t, {"a": _wrapped(t), "b": _wrapped(t, "fedcba9876543210")})
    _start(t, _wrapped(t, "fedcba9876543210"))
    assert _hook(t, "a") == 2 and _hook(t, "b") == 0


@pytest.mark.parametrize("twin", [
    lambda t: dict(_wrapped(t), cwd="/tmp"),
    lambda t: {"command": "nice", "args": [t.exe, "launch", "--entry", ID, "--", "npx"]},
    lambda t: {"command": "sh", "args": ["-c", f'exec "$0" launch --entry {ID} -- "$@"', t.exe]},
    lambda t: {"command": "python3", "args": ["-c", f"import os; os.execv('x', ['--entry {ID}'])"]},
])
def test_an_id_found_twice_is_trusted_for_nothing(t, twin):
    _user(t, {"a": _wrapped(t), "twin": twin(t)})
    _start(t, _wrapped(t))
    _start(t, _wrapped(t))
    assert _hook(t, "a") == 2


def test_an_id_twice_across_files_is_trusted_for_nothing(t):
    _user(t, {"a": _wrapped(t)})
    (t / "repo" / ".mcp.json").write_text(json.dumps({"mcpServers": {"p": _wrapped(t)}}))
    _start(t, _wrapped(t))
    assert _hook(t, "a") == 2


def test_an_entry_wrapped_without_an_id_is_not_wrapped_and_wrap_gives_it_one(t, capsys):
    old = {"command": t.exe, "args": ["launch", "--", "npx", "srv"]}
    _user(t, {"a": old})
    assert mcp_config.entry_state(old) != "wrapped"
    assert mcp_config.main(["list"]) == 0
    assert "entry id" in capsys.readouterr().out
    assert mcp_config.main(["wrap", "a", "--yes"]) == 0
    got = json.loads((t / "home" / ".claude.json").read_text())["mcpServers"]["a"]
    assert got["args"][:2] == ["launch", "--entry"] and got["args"][-3:] == ["--", "npx", "srv"]


def test_a_malformed_id_is_not_an_id(t):
    assert mcp_config.entry_state(_wrapped(t, "short")) != "wrapped"


def test_launch_accepts_the_entry_option():
    from phiward import wholetool
    assert "--entry" in wholetool.USAGE
