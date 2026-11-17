"""`phiward mcp wrap|unwrap|list`: the operator wraps a local MCP server's command in
`phiward launch --` (its tools then run in the kernel profile), or unwraps it, in
`~/.claude.json` (user and local scope) and `.mcp.json` (project scope). Only the server entries
change; a backup is kept; unwrapping needs the operator's own terminal. Made-up trees only."""

import json
import os
import stat
import sys

import pytest

from phiward import mcp_config
from helpers import Tty


@pytest.fixture()
def env(tree, monkeypatch):
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(sys, "stdin", Tty())
    return tree


def _user(tree, data):
    p = tree / "home" / ".claude.json"
    p.write_text(json.dumps(data, indent=2))
    p.chmod(0o600)
    return p


BARE = {"command": "npx", "args": ["-y", "some-server"], "env": {"TOKEN_FILE": "/x"}}


def test_wrap_rewrites_only_the_server_and_keeps_the_rest(env, capsys):
    p = _user(env, {"numStartups": 7, "mcpServers": {"docs": BARE, "web": {
        "type": "http", "url": "https://x.invalid"}}})
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 0
    data = json.loads(p.read_text())
    docs = data["mcpServers"]["docs"]
    assert docs["command"] == str(env / "bin" / "phiward")
    assert docs["args"][:2] == ["launch", "--entry"]
    assert docs["args"][3:] == ["--", "npx", "-y", "some-server"]
    assert docs["env"] == {"TOKEN_FILE": "/x"}
    assert data["numStartups"] == 7 and data["mcpServers"]["web"]["type"] == "http"
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    folder = mcp_config.backup_dir(str(env / "home" / ".claude.json"), str(env / "home"))
    assert os.path.exists(os.path.join(folder, "last"))
    out = capsys.readouterr().out
    assert "docs" in out and "pass_env" in out and "TOKEN_FILE" in out
    assert mcp_config.servers(str(env / "repo"), str(env / "home"))["docs"].wrapped


def test_wrap_all_covers_user_local_and_project_scopes(env):
    _user(env, {"mcpServers": {"a": BARE},
                "projects": {str(env / "repo"): {"mcpServers": {"b": BARE}}}})
    (env / "repo" / ".mcp.json").write_text(json.dumps({"mcpServers": {"c": BARE}}))
    assert mcp_config.main(["wrap", "--all", "--yes"]) == 0
    s = mcp_config.servers(str(env / "repo"), str(env / "home"))
    assert s["a"].wrapped and s["b"].wrapped and s["c"].wrapped


def test_unwrap_gives_the_old_command_back(env):
    p = _user(env, {"mcpServers": {"docs": BARE}})
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 0
    assert mcp_config.main(["unwrap", "docs", "--yes"]) == 0
    docs = json.loads(p.read_text())["mcpServers"]["docs"]
    assert docs["command"] == "npx" and docs["args"] == ["-y", "some-server"]


def test_unwrap_needs_the_operators_terminal(env, monkeypatch, capsys):
    _user(env, {"mcpServers": {"docs": BARE}})
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 0
    monkeypatch.setattr(sys, "stdin", open(os.devnull))
    assert mcp_config.main(["unwrap", "docs", "--yes"]) == 2
    assert "terminal" in capsys.readouterr().err


def test_a_declined_wrap_writes_nothing(env, monkeypatch):
    p = _user(env, {"mcpServers": {"docs": BARE}})
    before = p.read_text()
    monkeypatch.setattr("builtins.input", lambda _q: "n")
    assert mcp_config.main(["wrap", "docs"]) == 1
    assert p.read_text() == before


def test_a_link_at_the_config_is_refused(env, capsys):
    real = env / "elsewhere.json"
    real.write_text(json.dumps({"mcpServers": {"docs": BARE}}))
    (env / "home" / ".claude.json").symlink_to(real)
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 3
    assert json.loads(real.read_text())["mcpServers"]["docs"] == BARE


def test_an_unknown_or_remote_server_is_said_plainly(env, capsys):
    _user(env, {"mcpServers": {"web": {"type": "http", "url": "https://x.invalid"}}})
    assert mcp_config.main(["wrap", "nope", "--yes"]) == 2
    assert mcp_config.main(["wrap", "web", "--yes"]) == 0
    assert "remote" in capsys.readouterr().out


def test_without_phiward_on_path_wrap_refuses(env, monkeypatch, capsys):
    monkeypatch.setenv("PATH", "/nonexistent")
    _user(env, {"mcpServers": {"docs": BARE}})
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 2
    assert "PATH" in capsys.readouterr().err


def test_list_says_which_are_wrapped(env, capsys):
    _user(env, {"mcpServers": {"docs": BARE}})
    assert mcp_config.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "docs" in out and "phiward mcp wrap docs" in out


def test_doctor_names_the_wrap_line(env):
    from phiward import config, doctor
    _user(env, {"mcpServers": {"docs": BARE}})
    lines = doctor.mode_report(str(env / "repo"), str(env / "home"),
                               config.load(str(env / "repo")))
    assert any("phiward mcp wrap docs" in ln for ln in lines), lines


def test_phiward_mcp_with_no_arguments_is_still_the_server():
    import inspect
    from phiward import mcp
    assert "wrap" in inspect.getsource(mcp.main)


def test_headless_counts_a_bare_server_as_not_ready(env):
    from phiward import doctor
    _user(env, {"mcpServers": {"docs": BARE}})
    probs = doctor.headless_problems(str(env / "repo"), str(env / "home"))
    assert any("docs" in p and "mcp wrap" in p for p in probs), probs


def test_wrap_edits_a_project_key_spelled_another_way(env):
    p = _user(env, {"projects": {str(env / "repo") + "/": {"mcpServers": {"docs": BARE}}}})
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 0
    data = json.loads(p.read_text())
    assert data["projects"][str(env / "repo") + "/"]["mcpServers"]["docs"]["args"][0] == "launch"


def test_wrap_uses_claude_config_dir(env, monkeypatch):
    conf = env / "cc"
    conf.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(conf))
    (conf / ".claude.json").write_text(json.dumps({"mcpServers": {"docs": BARE}}))
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 0
    assert json.loads((conf / ".claude.json").read_text())["mcpServers"]["docs"]["args"][0] == "launch"


def test_a_linked_file_holding_no_named_entry_does_not_stop_a_wrap(env):
    # round 14 (B9): only the file that changes must be a plain file
    p = _user(env, {"mcpServers": {"docs": BARE}})
    real = env / "proj.json"
    real.write_text(json.dumps({"mcpServers": {"other": BARE}}))
    os.symlink(real, env / "repo" / ".mcp.json")
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 0
    assert json.loads(p.read_text())["mcpServers"]["docs"]["args"][0] == "launch"
    assert json.loads(real.read_text()) == {"mcpServers": {"other": BARE}}


def test_wrapping_an_entry_in_a_linked_file_names_the_real_file(env, capsys):
    real = env / "proj.json"
    real.write_text(json.dumps({"mcpServers": {"other": BARE}}))
    os.symlink(real, env / "repo" / ".mcp.json")
    assert mcp_config.main(["wrap", "other", "--yes"]) == 3
    err = capsys.readouterr().err
    assert str(real) in err and "Nothing was changed" in err, err
    assert json.loads(real.read_text()) == {"mcpServers": {"other": BARE}}


def test_a_file_that_gives_a_key_twice_is_not_rewritten(env, capsys):
    # round 14 (B8): Claude Code reads the last; a rewrite would drop the other
    p = env / "home" / ".claude.json"
    text = '{"mcpServers": {"docs": ' + json.dumps(BARE) + ', "docs": ' + json.dumps(BARE) + "}}"
    p.write_text(text)
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 3
    assert "twice" in capsys.readouterr().err and p.read_text() == text
