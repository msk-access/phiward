"""All of `~/.phiward` is denied to Claude Code's sandbox (`config.sandbox_denied`), so nothing in
a session can write, rename or replace phiward's own state (the launch records, wrap's backups,
the broker's status): not a session opened in the home folder, not `--add-dir ~`, not an
`allowWrite` that covers it (Claude Code's `denyWrite` holds inside writable folders). The spool,
the one folder the agent must write, lives outside it (`~/.phiward-spool`). The shell counts as
confined only when the sandbox denies `~/.phiward` and no `allowWrite` re-opens part of it. So
the hook trusts the records wherever the session was opened. `install` makes the folders up
front, so bubblewrap can protect them from the first session on. Made-up trees only."""

import io
import json
import os
import stat
import sys

import pytest

from phiward import claude_settings, config, install, mcp_config
from phiward.adapters import claude
from helpers import launcher_by_path, protect
from helpers import confinement

WRAPPED = {"command": "phiward", "args": ["launch", "--", "npx", "-y", "some-server"]}
RUN = {"command": "id"}


@pytest.fixture()
def t(tree, monkeypatch, launchers):
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    launcher_by_path(monkeypatch, sys.modules[__name__], b / "phiward")
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    protect(tree, [], best_effort=False)
    (tree / "home" / ".claude.json").write_text(json.dumps({"mcpServers": {"a": WRAPPED}}))
    launchers.start(mcp_config.launch_hash(WRAPPED["args"][1:]))
    return tree


def _hook(tree, project):
    p = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": project,
         "permission_mode": "default", "tool_name": "mcp__a__run_command",
         "tool_input": RUN, "mcp_server": {"name": "a", "source": "user"}}
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), io.StringIO())


def test_the_spool_lives_outside_phiwards_own_folder(tree, monkeypatch):
    monkeypatch.delenv("PHIWARD_SPOOL", raising=False)
    home = os.environ["HOME"]
    spool = config.spool_dir()
    assert spool == os.path.join(home, ".phiward-spool")
    assert not spool.startswith(os.path.join(home, ".phiward") + "/")


def test_the_sandbox_denies_all_of_phiwards_folder(tree):
    cfg = config.load(str(tree / "repo"))
    home = os.environ["HOME"]
    want = install.wiring(cfg)["sandbox"]["filesystem"]
    deny = [os.path.join(home, x[2:]) if x.startswith("~/") else x for x in want["denyWrite"]]
    assert os.path.join(home, ".phiward") in deny
    allow = [os.path.join(home, x[2:]) if x.startswith("~/") else x for x in want["allowWrite"]]
    assert all(not a.startswith(os.path.join(home, ".phiward") + "/") for a in allow), allow
    project = install.wiring(cfg, project=True)["sandbox"]["filesystem"]["denyWrite"]
    assert "~/.phiward" in project


def _settings(tree, fs):
    s = tree / "home" / ".claude" / "settings.json"
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(json.dumps({"sandbox": {"enabled": True, "failIfUnavailable": True,
                                         "allowUnsandboxedCommands": False, "filesystem": fs}}))


def _confined(tree):
    cfg = config.load(str(tree / "repo"))
    return confinement(str(tree / "repo"), str(tree / "home"), cfg.all_roots,
                                       cfg.patterns, config.guard_files())


def test_a_sandbox_that_does_not_deny_phiwards_folder_is_not_confined(tree):
    protect(tree, [], best_effort=False)
    cfg = config.load(str(tree / "repo"))
    fs = install.wiring(cfg)["sandbox"]["filesystem"]
    fs = dict(fs, denyWrite=[x for x in fs["denyWrite"] if not x.rstrip("/").endswith(".phiward")])
    _settings(tree, fs)
    ok, why = _confined(tree)
    assert not ok and "denyWrite" in why, why


def test_an_allow_write_inside_phiwards_folder_is_not_confined(tree):
    protect(tree, [], best_effort=False)
    cfg = config.load(str(tree / "repo"))
    fs = install.wiring(cfg)["sandbox"]["filesystem"]
    _settings(tree, dict(fs, allowWrite=fs["allowWrite"] + ["~/.phiward/launched"]))
    ok, why = _confined(tree)
    assert not ok and "allowWrite" in why and ".phiward" in why, why


def test_a_session_in_the_home_folder_trusts_its_wrapped_server(t, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(t / "home"))
    assert _hook(t, str(t / "home")) == 0


def test_a_project_session_trusts_its_wrapped_server(t):
    assert _hook(t, str(t / "repo")) == 0


def test_install_makes_the_folders_private_up_front(tree):
    home = tree / "home2"
    home.mkdir()
    config.make_state_dirs(str(home))
    for d in (home / ".phiward" / "launched", home / ".phiward" / "backups"):
        assert d.is_dir() and stat.S_IMODE(os.stat(d).st_mode) == 0o700


@pytest.mark.parametrize("key", ["additionalDirectories", "allowWrite"])
def test_an_added_home_folder_changes_nothing(t, key):
    # `--add-dir ~` and `/add-dir ~` are the same to the sandbox as additionalDirectories: the
    # agent may write the home folder, but `~/.phiward` stays denied, so the records stay trusted
    s = t / "home" / ".claude" / "settings.json"
    s.parent.mkdir(parents=True, exist_ok=True)
    home = str(t / "home")
    s.write_text(json.dumps({"permissions": {"additionalDirectories": [home]}} if
                            key == "additionalDirectories" else
                            {"sandbox": {"filesystem": {"allowWrite": [home]}}}))
    assert _hook(t, str(t / "repo")) == 0


def test_a_home_session_does_not_take_the_user_settings_for_a_projects(t, monkeypatch):
    # the project is the home folder: ~/.claude/settings.json is the operator's own user
    # settings, where install pins the shell (env.CLAUDE_CODE_SHELL); it is not a project's
    s = t / "home" / ".claude" / "settings.json"
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(json.dumps({"env": {"CLAUDE_CODE_SHELL": "/bin/bash"}}))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(t / "home"))
    assert claude_settings.project_redirects(str(t / "home"), str(t / "home")) == []
    assert _hook(t, str(t / "home")) == 0
    # a settings.local.json there is still a project's file
    (s.parent / "settings.local.json").write_text(json.dumps({"env": {"CLAUDE_CODE_SHELL": "x"}}))
    assert claude_settings.project_redirects(str(t / "home"), str(t / "home"))
