"""Without an install record (a source checkout, an editable install: test_v2_launcher_identity has
the rule for an installed phiward), the launcher of a wrapped MCP server must be the phiward found
only on PATH folders the agent cannot write (`service._safe_path_entries`). A `phiward` in a
project folder on PATH (an activated `.venv/bin`) is not the launcher: an entry that names
`phiward` and finds that one counts as not wrapped, and `wrap` writes the installed launcher's full
path in every file, the project's `.mcp.json` too, so no folder on PATH can supply another one.
Made-up trees only."""

import json
import os
import sys

import pytest

from phiward import mcp_config
from helpers import Tty

BARE = {"command": "npx", "args": ["-y", "some-server"]}
BY_NAME = {"command": "phiward",
           "args": ["launch", "--entry", "00000000000000d1", "--", "npx", "-y", "some-server"]}


def _exe(folder):
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / "phiward"
    p.write_text("#!/bin/sh\n")
    p.chmod(0o755)
    return p


@pytest.fixture()
def env(tree, monkeypatch):
    safe = _exe(tree / "bin")
    monkeypatch.setenv("PATH", f"{safe.parent}:{os.environ.get('PATH', '')}")
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(sys, "stdin", Tty())
    mcp_config._launcher_exes.cache_clear()
    yield tree
    mcp_config._launcher_exes.cache_clear()


def _shadow(env, monkeypatch):
    """An activated project venv ahead of the installed phiward on PATH."""
    fake = _exe(env / "repo" / ".venv" / "bin")
    monkeypatch.setenv("PATH", f"{fake.parent}:{os.environ['PATH']}")
    mcp_config._launcher_exes.cache_clear()
    return fake


def _project(tree, servers):
    p = tree / "repo" / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": servers}, indent=2))
    return p


def _user(tree, servers):
    p = tree / "home" / ".claude.json"
    p.write_text(json.dumps({"mcpServers": servers}, indent=2))
    return p


def test_a_phiward_from_a_project_folder_on_path_is_not_the_launcher(env, monkeypatch):
    _shadow(env, monkeypatch)
    assert mcp_config.entry_state(BY_NAME) != "wrapped"
    _project(env, {"x": BY_NAME})
    assert not mcp_config.servers(str(env / "repo"), str(env / "home"))["x"].wrapped


def test_the_full_path_of_the_installed_launcher_still_counts(env, monkeypatch):
    _shadow(env, monkeypatch)
    spec = dict(BY_NAME, command=str(env / "bin" / "phiward"))
    assert mcp_config.entry_state(spec) == "wrapped"


def test_wrap_writes_the_full_path_in_the_project_file_too(env):
    p = _project(env, {"b": BARE})
    assert mcp_config.main(["wrap", "b", "--yes"]) == 0
    got = json.loads(p.read_text())["mcpServers"]["b"]["command"]
    assert os.path.realpath(got) == os.path.realpath(env / "bin" / "phiward")


def test_wrap_refuses_when_phiward_is_only_in_a_folder_the_agent_can_write(env, monkeypatch,
                                                                           capsys):
    fake = _exe(env / "repo" / ".venv" / "bin")
    monkeypatch.setenv("PATH", f"{fake.parent}:/usr/bin:/bin")
    mcp_config._launcher_exes.cache_clear()
    u = _user(env, {"docs": BARE})
    before = u.read_text()
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 2
    assert "Nothing was changed" in capsys.readouterr().err
    assert u.read_text() == before


def test_list_says_a_launcher_by_name_needs_its_path(env, capsys):
    _project(env, {"x": BY_NAME})
    assert mcp_config.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "without its path" in out and "phiward mcp wrap x" in out, out


def test_wrap_gives_a_launcher_by_name_its_full_path(env):
    p = _project(env, {"x": BY_NAME})
    assert mcp_config.main(["wrap", "x", "--yes"]) == 0
    got = json.loads(p.read_text())["mcpServers"]["x"]
    assert os.path.realpath(got["command"]) == os.path.realpath(env / "bin" / "phiward")
    assert got["args"].count("launch") == 1 and got["args"][-4:] == BY_NAME["args"][-4:]


def test_wrap_does_not_wrap_a_shadowed_launcher_twice(env, monkeypatch):
    _shadow(env, monkeypatch)
    p = _project(env, {"x": BY_NAME})
    assert mcp_config.main(["wrap", "x", "--yes"]) == 0
    got = json.loads(p.read_text())["mcpServers"]["x"]
    assert os.path.realpath(got["command"]) == os.path.realpath(env / "bin" / "phiward")
    assert got["args"].count("launch") == 1 and got["args"][-4:] == BY_NAME["args"][-4:]


def test_a_phiward_in_the_claude_project_is_not_the_launcher_from_another_folder(env,
                                                                               monkeypatch):
    # the hook knows the project from Claude Code, also when it runs in another folder and the
    # project is not a git work tree
    proj = env / "elsewhere"
    fake = _exe(proj / ".venv" / "bin")
    monkeypatch.chdir(env / "home")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(proj))
    monkeypatch.setenv("PATH", f"{fake.parent}:{os.environ['PATH']}")
    mcp_config._launcher_exes.cache_clear()
    assert mcp_config.entry_state(BY_NAME) != "wrapped"
    assert mcp_config.entry_state(dict(BY_NAME, command=str(env / "bin" / "phiward"))) == "wrapped"
