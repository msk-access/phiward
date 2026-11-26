"""The shell-code paths: what Claude Code runs as shell code before an agent's command. A
project's settings may not name such a file, and the file tools may not write the folder where
Claude Code keeps its own per-session one. Made-up trees only; the real `claude` never runs."""

import json

import pytest

from phiward import claude_settings, config, doctor
from phiward.core import DENY, FILE_WRITE, SHELL, Action
from phiward.guards import protected_paths
from helpers import protect


@pytest.fixture()
def home(tree, monkeypatch):
    monkeypatch.setenv("HOME", str(tree / "home"))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    return tree / "home"


def _project_env(tree, env, name="settings.json"):
    (tree / "repo" / ".claude").mkdir(exist_ok=True)
    (tree / "repo" / ".claude" / name).write_text(json.dumps({"env": env}))


def test_a_project_that_names_the_session_env_file_is_refused_with_its_safe_way(tree, home):
    _project_env(tree, {"CLAUDE_ENV_FILE": str(tree / "repo" / ".claude" / ".env")})
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command="ls"),
                              config.load(str(tree / "repo")))
    assert d.verdict == DENY and "CLAUDE_ENV_FILE" in d.reason, d.reason
    # R1: the refusal ships with its safe way
    assert "`env`" in d.reason and "SessionStart hook" in d.reason, d.reason


def test_the_local_settings_file_is_read_too(tree, home):
    _project_env(tree, {"CLAUDE_ENV_FILE": "/x"}, name="settings.local.json")
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command="ls"),
                              config.load(str(tree / "repo")))
    assert d.verdict == DENY and "CLAUDE_ENV_FILE" in d.reason, d.reason


def test_doctor_gives_the_safe_way_too(tree, home):
    _project_env(tree, {"CLAUDE_ENV_FILE": "/x"})
    probs = [p for p in doctor.headless_problems(str(tree / "repo"), str(tree / "home"))
             if "CLAUDE_ENV_FILE" in p]
    assert len(probs) == 1 and "SessionStart hook" in probs[0], probs


def test_the_safe_way_is_said_only_for_that_name(tree, home):
    _project_env(tree, {"PATH": "/x"})
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command="ls"),
                              config.load(str(tree / "repo")))
    assert d.verdict == DENY and "SessionStart hook" not in d.reason, d.reason


def _write(tree, path):
    cfg = protect(tree, [], best_effort=False)
    return protected_paths.check(Action(FILE_WRITE, str(tree / "repo"), paths=(str(path),),
                                        tool="Write"), cfg)


@pytest.mark.parametrize("name", [".claude/session-env",
                                  ".claude/session-env/FAKE-SESSION/sessionstart-hook-0.sh"])
def test_a_file_tool_cannot_write_the_session_env_folder(tree, name):
    d = _write(tree, tree / "home" / name)
    assert d.verdict == DENY, (name, d.reason)


def test_a_claude_config_dir_moves_the_session_env_folder_with_it(tree, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tree / "cc"))
    assert _write(tree, tree / "cc" / "session-env" / "s" / "hook.sh").verdict == DENY


def test_the_session_env_folder_is_in_the_one_list():
    assert "/h/.claude/session-env" in claude_settings.shell_code_paths("/h", {})
