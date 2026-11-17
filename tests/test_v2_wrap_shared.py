"""`phiward mcp wrap` is safe for files a team shares: the project's `.mcp.json` (committed with the
repository) gets the installed launcher's full path like every file (by name, a folder on PATH the
agent can write could supply another one: test_v2_launcher_path) and says so (the backups:
test_v2_backups); the file as it was before phiward first changed it is kept and never overwritten;
flags are read as flags; it says to close Claude Code before it shows the change. Made-up trees
only."""

import json
import os
import sys

import pytest

from phiward import mcp_config
from helpers import Tty

BARE = {"command": "npx", "args": ["-y", "some-server"]}


@pytest.fixture()
def env(tree, monkeypatch):
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(sys, "stdin", Tty())
    return tree


def _user(tree, servers):
    p = tree / "home" / ".claude.json"
    p.write_text(json.dumps({"mcpServers": servers}, indent=2))
    return p


def _project(tree, servers):
    p = tree / "repo" / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": servers}, indent=2))
    return p


def test_both_files_get_the_installed_launchers_path(env):
    u, p = _user(env, {"a": BARE}), _project(env, {"b": BARE})
    assert mcp_config.main(["wrap", "--all", "--yes"]) == 0
    assert json.loads(p.read_text())["mcpServers"]["b"]["command"] == str(env / "bin" / "phiward")
    assert json.loads(u.read_text())["mcpServers"]["a"]["command"] == str(env / "bin" / "phiward")
    got = mcp_config.servers(str(env / "repo"), str(env / "home"))
    assert got["a"].wrapped and got["b"].wrapped


def test_the_project_file_message_says_it_is_shared(env, capsys):
    _project(env, {"b": BARE})
    assert mcp_config.main(["wrap", "b", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "shared" in out and "this machine's" in out, out


def test_dash_y_is_yes(env, capsys):
    u = _user(env, {"docs": BARE})
    assert mcp_config.main(["wrap", "docs", "-y"]) == 0
    assert json.loads(u.read_text())["mcpServers"]["docs"]["args"][0] == "launch"


@pytest.mark.parametrize("what", ["wrap", "unwrap", "list"])
def test_an_unknown_flag_gives_the_usage_and_changes_nothing(env, capsys, what):
    u = _user(env, {"docs": BARE})
    before = u.read_text()
    assert mcp_config.main([what, "--bogus", "docs"]) == 2
    err = capsys.readouterr().err
    assert "usage:" in err and "--bogus" in err, err
    assert u.read_text() == before


def test_wrap_says_close_claude_code_before_the_change(env, capsys):
    _user(env, {"docs": BARE})
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "Close Claude Code" in out and out.index("Close Claude Code") < out.index("-> ")
    # one instruction: close it now, start it again after; not also "reconnect it"
    assert "/mcp" not in out and "reconnect" not in out, out


def test_the_usage_says_unwrap_needs_your_terminal_even_with_yes(env, capsys):
    mcp_config.main([])
    err = capsys.readouterr().err
    assert "unwrap" in err and "even with --yes" in err, err


def test_help_lists_the_mcp_commands_with_the_operators_commands():
    from phiward import cli
    usage = cli.USAGE
    assert usage.index("mcp list|wrap|unwrap") < usage.index("Called by tools")

