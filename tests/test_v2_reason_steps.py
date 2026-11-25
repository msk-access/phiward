"""Each reason the shell is not confined carries its own step (round 5), the same in the hook's
refusal and in `doctor`: `install claude --user --write` only for what install fixes (the three
sandbox switches it sets, the deny lists it writes); "remove KEY from FILE" for a setting in the
user or a project file that install never removes (an opener, excludedCommands, an allowRead or
allowWrite entry); the admin's step for managed settings. Made-up trees only."""

import io
import json

import pytest

from phiward import claude_settings, config, install
from phiward.adapters import claude
from helpers import protect

INSTALL = "phiward install claude --user --write"


def _wired(tree, **extra):
    cfg = config.load(str(tree / "repo"))
    want = install.wiring(cfg)
    for k, v in extra.items():
        want["sandbox"][k] = v
    s = tree / "home" / ".claude" / "settings.json"
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(json.dumps(want))
    return want


def _project(tree, data, name="settings.json"):
    f = tree / "repo" / ".claude" / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data))


def _reason(tree):
    cfg = config.load(str(tree / "repo"))
    return claude_settings.confinement_reason(str(tree / "repo"), str(tree / "home"),
                                              cfg.all_roots, cfg.patterns, config.guard_files())


def _hook(tree, monkeypatch, command="ls", code=2):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    payload = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
               "permission_mode": "default", "tool_name": "Bash",
               "tool_input": {"command": command}}
    out, err = io.StringIO(), io.StringIO()
    assert claude.main(io.StringIO(json.dumps(payload)), out, err) == code
    return out.getvalue() + err.getvalue()


def test_a_confined_shell_has_no_reason(tree):
    protect(tree, [], best_effort=False)
    _wired(tree)
    assert _reason(tree) is None


def test_excluded_commands_in_the_user_file_name_that_file_not_install(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    _wired(tree, excludedCommands=["docker *"])
    r = _reason(tree)
    assert "excludedCommands" in r.text
    assert "~/.claude/settings.json" in r.step and INSTALL not in r.step, r
    # b1: with only excludedCommands open, every call gets the text check, not the blanket
    # refusal: a call that names the root is refused, `ls` runs
    text = _hook(tree, monkeypatch, f"cat {tree}/phi/FAKE-PT-0001.bam")
    assert "names a protected path" in text, text
    # a path the guard cannot see: the refusal gives the same step as doctor
    text = _hook(tree, monkeypatch, "cat $UNSEEN")
    assert r.step in text and INSTALL not in text, text
    _hook(tree, monkeypatch, "ls", code=0)


def test_an_opener_in_the_user_file_names_that_file(tree):
    protect(tree, [], best_effort=False)
    _wired(tree, allowNestedUserNamespaces=True)
    r = _reason(tree)
    assert "allowNestedUserNamespaces" in r.step and "~/.claude/settings.json" in r.step, r


def test_sandbox_off_in_the_project_file_names_that_file(tree):
    protect(tree, [], best_effort=False)
    _wired(tree)
    _project(tree, {"sandbox": {"enabled": False}})
    r = _reason(tree)
    assert "enabled" in r.text and ".claude/settings.json" in r.step and INSTALL not in r.step, r


def test_sandbox_off_with_no_settings_is_fixed_by_install(tree):
    protect(tree, [], best_effort=False)
    r = _reason(tree)
    assert r.step == INSTALL or INSTALL in r.step, r


def test_a_list_in_managed_settings_gets_the_admins_step(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    _wired(tree)
    managed = tree / "managed" / "managed-settings.json"
    managed.parent.mkdir()
    managed.write_text(json.dumps({"sandbox": {"excludedCommands": ["x"]}}))
    monkeypatch.setattr(claude_settings, "MANAGED", (str(managed),))
    r = _reason(tree)
    assert "admin" in r.step and str(managed) in r.step, r


def test_the_last_managed_drop_in_wins(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    _wired(tree)
    managed = tree / "managed" / "managed-settings.json"
    (managed.parent / "managed-settings.d").mkdir(parents=True)
    managed.write_text(json.dumps({"sandbox": {"enabled": True}}))
    (managed.parent / "managed-settings.d" / "10-a.json").write_text(
        json.dumps({"sandbox": {"enabled": True}}))
    (managed.parent / "managed-settings.d" / "20-b.json").write_text(
        json.dumps({"sandbox": {"enabled": False}}))
    monkeypatch.setattr(claude_settings, "MANAGED", (str(managed),))
    r = _reason(tree)
    assert r is not None and "enabled" in r.text and "20-b.json" in r.step, r


def test_an_allow_read_into_a_root_names_its_file(tree):
    protect(tree, [], best_effort=False)
    _wired(tree)
    _project(tree, {"sandbox": {"filesystem": {"allowRead": [str(tree / "phi" / "sub")]}}},
             "settings.local.json")
    r = _reason(tree)
    assert "allowRead" in r.text and ".claude/settings.local.json" in r.step, r


def test_a_failure_on_another_local_candidate_keeps_its_step(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    _wired(tree)
    other = tree / "other" / "settings.local.json"
    other.parent.mkdir()
    other.write_text(json.dumps({"sandbox": {"excludedCommands": ["x"]}}))
    real = claude_settings.local_candidates
    monkeypatch.setattr(claude_settings, "local_candidates",
                        lambda project, home: list(real(project, home)) + [str(other)])
    r = _reason(tree)
    assert r is not None and str(other) in r.text and "excludedCommands" in r.step, r


@pytest.mark.parametrize("named", [None, "elsewhere"])
def test_the_hook_without_the_named_project_gives_its_own_step(tree, monkeypatch, named):
    protect(tree, [], best_effort=False)
    _wired(tree)
    if named is None:
        monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    else:
        (tree / named).mkdir()
        monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / named))
    payload = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
               "permission_mode": "default", "tool_name": "Bash", "tool_input": {"command": "ls"}}
    out, err = io.StringIO(), io.StringIO()
    assert claude.main(io.StringIO(json.dumps(payload)), out, err) == 2
    text = out.getvalue() + err.getvalue()
    assert INSTALL not in text, text
    assert ("update Claude Code" in text) if named is None else ("inside the project" in text)


def test_doctor_gives_the_same_step(tree, monkeypatch):
    import os
    import subprocess
    import sys
    from pathlib import Path
    protect(tree, [], best_effort=False)
    _wired(tree, excludedCommands=["docker *"])
    r = _reason(tree)
    src = str(Path(__file__).resolve().parents[1] / "src")
    out = subprocess.run([sys.executable, "-m", "phiward", "doctor"], cwd=str(tree / "repo"),
                         capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
                         env=dict(os.environ, PYTHONPATH=src)).stdout
    line = next(ln for ln in out.splitlines() if "sandbox confines the shell" in ln)
    assert r.step in line, line
