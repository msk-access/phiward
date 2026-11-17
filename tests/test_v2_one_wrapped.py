"""One answer to "is this entry wrapped", from one place (`mcp_config.placed_state`), for `mcp
list`, `doctor`, the hook and `wrap`: an entry wrapped without an id (an older phiward) or with a
copied id is not wrapped for any of them, and each says the same fix. phiward reads the one user
file Claude Code reads (`$CLAUDE_CONFIG_DIR/.claude.json` when that is set, else
`~/.claude.json`). Entry ids are counted only inside `mcpServers` objects, so an id in pasted
prompt history does not make an entry a copy, and counting stays fast in a large file.
Made-up trees only."""

import io
import json
import os
import sys
import time

import pytest

from phiward import doctor, mcp_config
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
    tree.joinpath("exe").write_text(str(b / "phiward"))
    return tree, launchers, str(b / "phiward")


def _w(exe, eid=ID):
    return {"command": exe, "args": ["launch", "--entry", eid, "--", "npx", "srv"]}


def _old(exe):
    return {"command": exe, "args": ["launch", "--", "npx", "srv"]}


def _user(tree, servers, **extra):
    (tree / "home" / ".claude.json").write_text(json.dumps(dict(extra, mcpServers=servers)))


def _hook(tree, name="a"):
    p = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
         "permission_mode": "default", "tool_name": f"mcp__{name}__run_command",
         "tool_input": RUN, "mcp_server": {"name": name, "source": "user"}}
    err = io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err), err.getvalue()


@pytest.mark.parametrize("kind", ["no id", "copied"])
def test_list_doctor_and_the_hook_agree_and_name_wrap(t, kind):
    tree, L, exe = t
    if kind == "no id":
        _user(tree, {"a": _old(exe)})
        L.start(mcp_config.launch_hash(_old(exe)["args"][1:]))
    else:
        _user(tree, {"a": _w(exe), "b": _w(exe)})
        L.start(mcp_config.launch_hash(_w(exe)["args"][1:]))
    home = str(tree / "home")
    assert not mcp_config.servers(str(tree / "repo"), home)["a"].wrapped
    can, _cannot = doctor.bare_split(str(tree / "repo"), home)
    assert "a" in can
    code, err = _hook(tree)
    assert code == 2 and "phiward mcp wrap a" in err, err
    assert "starts Claude Code again" not in err or "phiward mcp wrap" in err


def test_with_claude_config_dir_only_that_file_is_read(t, monkeypatch, capsys):
    tree, _L, exe = t
    conf = tree / "conf"
    conf.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(conf))
    (conf / ".claude.json").write_text(json.dumps({"mcpServers": {"new": {"command": "npx"}}}))
    _user(tree, {"old": {"command": "npx"}})  # ~/.claude.json: Claude Code does not read it now
    names = {e.name for e in mcp_config.entries(str(tree / "repo"), str(tree / "home"))}
    assert names == {"new"}
    assert mcp_config.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "old" not in out and "new" in out
    can, _ = doctor.bare_split(str(tree / "repo"), str(tree / "home"))
    assert can == ["new"]


def test_an_id_outside_the_server_entries_is_no_copy(t):
    tree, _L, exe = t
    # Claude Code keeps other things in the same file (a project's history, say)
    _user(tree, {"a": _w(exe)}, projects={str(tree / "repo"): {"history": [
        {"display": f"look at --entry {ID}"}]}})
    assert mcp_config.id_count(ID, str(tree / "repo"), str(tree / "home")) == 1
    e = [x for x in mcp_config.entries(str(tree / "repo"), str(tree / "home")) if x.name == "a"]
    assert e[0].state == "wrapped"


def test_counting_ids_in_a_large_file_is_fast(t):
    tree, _L, exe = t
    servers = {f"s{i}": _w(exe, f"{i:016x}") for i in range(30)}
    big = {"projects": {f"/p/{i}": {"history": [{"display": "x" * 2000}] * 100}
                        for i in range(30)}}
    _user(tree, servers, **big)
    assert os.path.getsize(tree / "home" / ".claude.json") > 5_000_000
    start = time.monotonic()
    found = mcp_config.entries(str(tree / "repo"), str(tree / "home"))
    assert len(found) == 30 and all(e.state == "wrapped" for e in found)
    assert time.monotonic() - start < 1.0
