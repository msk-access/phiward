"""`doctor` warns when Claude Code would start an MCP server's program from a folder the agent can
write: an entry that names its program without a path (`npx`, `uvx`, `phiward`) is looked up on
Claude Code's PATH when the session starts, so a folder of PATH that the agent can write (the
project's `.venv/bin`, a relative entry, a folder the sandbox's `allowWrite` or
`additionalDirectories` opens, the temp folder), ahead of the real program, lets the agent choose
what runs with the operator's rights. phiward cannot prevent this; it can name it. The folders
the agent can write come from Claude Code's own settings, the same ones the sandbox uses.
Made-up trees only."""

import json

import pytest

from phiward import claude_settings, doctor


def _exe(folder, name):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text("#!/bin/sh\n")
    (folder / name).chmod(0o755)


@pytest.fixture()
def t(tree, monkeypatch):
    _exe(tree / "sys" / "bin", "npx")  # the real program, in a folder the agent cannot write
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    # the made-up tree lies under the temp folder, which the agent can write: here it stands for
    # the rest of the machine
    monkeypatch.setattr(claude_settings, "_temp_roots", lambda: [])
    (tree / "home" / ".claude.json").write_text(json.dumps(
        {"mcpServers": {"docs": {"command": "npx", "args": ["-y", "some-server"]}}}))
    return tree


def _risks(t, path):
    return doctor.path_risks(str(t / "repo"), str(t / "home"), path)


def test_a_project_venv_ahead_on_path_is_a_risk(t):
    path = f"{t}/repo/.venv/bin:{t}/sys/bin"
    assert _risks(t, path) == [("docs", "npx", 1)]


def test_the_temp_folder_counts_as_the_agents(t, monkeypatch):
    monkeypatch.setattr(claude_settings, "_temp_roots", lambda: [str(t / "tmp")])
    assert _risks(t, f"{t}/tmp/bin:{t}/sys/bin") == [("docs", "npx", 1)]


def test_a_relative_or_empty_path_entry_is_a_risk(t):
    assert _risks(t, f"bin:{t}/sys/bin") == [("docs", "npx", 1)]
    assert _risks(t, f":{t}/sys/bin") == [("docs", "npx", 1)]


def test_a_folder_the_sandbox_lets_the_agent_write_is_a_risk(t):
    extra = t / "scratch"
    extra.mkdir()
    s = t / "home" / ".claude" / "settings.json"
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(json.dumps({"sandbox": {"filesystem": {"allowWrite": [str(extra)]}},
                             "permissions": {"additionalDirectories": [str(t / "more")]}}))
    assert _risks(t, f"{extra}:{t}/sys/bin") == [("docs", "npx", 1)]
    assert _risks(t, f"{t}/more/bin:{t}/sys/bin") == [("docs", "npx", 1)]


def test_folders_after_the_real_program_do_not_matter(t):
    assert _risks(t, f"{t}/sys/bin:{t}/repo/.venv/bin") == []


def test_an_entry_with_a_full_path_is_no_risk(t):
    (t / "home" / ".claude.json").write_text(json.dumps(
        {"mcpServers": {"docs": {"command": f"{t}/sys/bin/npx"}}}))
    assert _risks(t, f"{t}/repo/.venv/bin:{t}/sys/bin") == []


def test_doctor_names_it_as_a_warning_with_the_fix(t, monkeypatch, capsys):
    monkeypatch.setenv("PATH", f"{t}/repo/.venv/bin:{t}/sys/bin:/usr/bin:/bin")
    lines = doctor.path_risk_lines(str(t / "repo"), str(t / "home"))
    assert len(lines) == 1 and "WARNING" in lines[0], lines
    assert "docs" in lines[0] and "npx" in lines[0] and "your rights" in lines[0], lines[0]
