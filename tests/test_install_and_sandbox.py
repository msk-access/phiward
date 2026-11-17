"""`install claude` (print and write), Claude Code sandbox detection, and the hook's use of it.

All settings files live under the test's HOME and folders; nothing touches the real ~/.claude.
"""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import config
from phiward.adapters import claude
from helpers import confinement

SRC = str(Path(__file__).resolve().parents[1] / "src")


def ag(args, cwd, stdin="", env=None):
    env = dict(env or os.environ, PYTHONPATH=SRC)
    return subprocess.run([sys.executable, "-m", "phiward"] + args, cwd=str(cwd),
                          input=stdin, capture_output=True, text=True, env=env, timeout=60)


def user_settings(t):
    return t / "home" / ".claude" / "settings.json"


# --- install ---------------------------------------------------------------------------------

def expanded(xs):
    # install writes paths under the home folder as ~/... (no user name in a file)
    home = os.environ["HOME"]
    return [os.path.join(home, x[2:]) if x.startswith("~/") else x for x in xs]


def test_install_prints_hooks_and_sandbox_and_writes_nothing(tree, capsys, monkeypatch):
    from phiward import install
    monkeypatch.setattr("sys.stdin", type("Tty", (), {"isatty": lambda self: True})())
    monkeypatch.chdir(tree / "repo")
    assert install.main(["claude", "--json"]) == 0  # printing needs a terminal
    body = json.loads(capsys.readouterr().out)
    assert body["sandbox"]["allowUnsandboxedCommands"] is False
    assert str(tree / "phi") in body["sandbox"]["filesystem"]["denyRead"]
    assert str(tree / "phi") in body["sandbox"]["filesystem"]["denyWrite"]
    assert os.environ["PHIWARD_CONFIG"] in expanded(body["sandbox"]["filesystem"]["denyWrite"])
    assert expanded(body["sandbox"]["filesystem"]["allowWrite"]) == [config.spool_dir()]
    assert "excludedCommands" not in body["sandbox"]
    assert all(h["hooks"][0]["onFailure"] == "block" for h in body["hooks"]["PreToolUse"])
    assert not user_settings(tree).exists()


def test_install_write_needs_a_yes(tree):
    from conftest import default_place_env
    r = ag(["install", "claude", "--write"], tree / "repo", env=default_place_env(tree))  # no terminal
    assert r.returncode == 1 and "not written" in r.stdout
    assert "+" in r.stdout  # the diff was shown
    assert not user_settings(tree).exists()


def test_install_write_merges_and_keeps_a_backup(tree):
    s = user_settings(tree)
    s.parent.mkdir(parents=True)
    s.write_text(json.dumps({"model": "x", "sandbox": {"enabled": False, "excludedCommands": [
                                 "docker *", "phiward run *"]},
                             "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                                 {"type": "command", "command": "mine"}]}]}}))
    from conftest import default_place_env
    env = default_place_env(tree)
    r = ag(["install", "claude", "--write", "--yes"], tree / "repo", env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    after = json.loads(s.read_text())
    assert after["model"] == "x"  # nothing removed
    assert after["sandbox"]["enabled"] is True
    assert after["sandbox"]["excludedCommands"] == ["docker *"]  # only the old gateway entry goes
    default_cfg = str(tree / "home" / ".config" / "phiward" / "config.toml")
    assert default_cfg in expanded(after["sandbox"]["filesystem"]["denyWrite"])
    assert any(h["command"] == "mine" for g in after["hooks"]["PreToolUse"] for h in g["hooks"])
    assert (s.parent / "settings.json.phiward.bak").exists()
    again = ag(["install", "claude", "--write", "--yes"], tree / "repo", env=env)
    assert "already has" in again.stdout


def test_install_refuses_a_settings_file_that_is_not_json(tree):
    s = user_settings(tree)
    s.parent.mkdir(parents=True)
    s.write_text("{not json")
    from conftest import default_place_env
    r = ag(["install", "claude", "--write", "--yes"], tree / "repo", env=default_place_env(tree))
    assert r.returncode == 3 and s.read_text() == "{not json"


# --- sandbox detection -----------------------------------------------------------------------

def write_sandbox(t, **over):
    cfg = config.load(str(t / "repo"))
    from phiward import hidden
    secret = hidden.paths(None, cfg, session=True)  # as install writes it
    sb = {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
          "filesystem": {"denyRead": list(cfg.all_roots) + secret,
                         "denyWrite": list(cfg.all_roots) + config.guard_files() + config.sandbox_denied()}}
    sb.update(over)
    s = user_settings(t)
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(json.dumps({"sandbox": sb}))
    return cfg


def roots_only(t):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(f'[protected_paths]\nroots = ["{t}/phi"]\n')


def confined(t, hidden_paths=()):
    cfg = config.load(str(t / "repo"))
    return confinement(str(t / "repo"), str(t / "home"), cfg.all_roots,
                                       cfg.patterns, config.guard_files(), hidden=hidden_paths)


def test_a_sandbox_that_leaves_a_credential_readable_is_not_confined(tree):
    # an older install covered the roots only
    roots_only(tree)
    cfg = config.load(str(tree / "repo"))
    s = user_settings(tree)
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(json.dumps({"sandbox": {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
                                         "filesystem": {"denyRead": list(cfg.all_roots),
                                                        "denyWrite": list(cfg.all_roots) +
                                                        config.guard_files()}}}))
    key = tree / "home" / ".ssh"
    key.mkdir(exist_ok=True)
    ok, why = confined(tree, [str(key)])
    assert not ok and "credential" in why


def test_full_sandbox_is_confined(tree):
    roots_only(tree)
    write_sandbox(tree)
    assert confined(tree) == (True, "")


@pytest.mark.parametrize("over,why", [
    ({"enabled": False}, "enabled"),
    ({"allowUnsandboxedCommands": True}, "allowUnsandboxedCommands"),
    ({"filesystem": {"denyRead": []}}, "denyRead"),
    ({"excludedCommands": ["phiward run *"]}, "excludedCommands"),
    ({"filesystem": {"denyRead": ["/"]}}, "denyWrite"),
    ({"network": {"allowAllUnixSockets": True}}, "allowAllUnixSockets"),
    ({"network": {"allowUnixSockets": ["/var/run/docker.sock"]}}, "allowUnixSockets"),
])
def test_partial_sandbox_is_not_confined(tree, over, why):
    roots_only(tree)
    write_sandbox(tree, **over)
    ok, reason = confined(tree)
    assert not ok and why in reason


def test_patterns_are_never_confined_for_claude(tree):
    write_sandbox(tree)  # conftest config has a pattern
    ok, reason = confined(tree)
    assert not ok and "pattern" in reason


def test_a_project_file_can_break_confinement(tree):
    roots_only(tree)
    write_sandbox(tree)
    proj = tree / "repo" / ".claude"
    proj.mkdir()
    (proj / "settings.json").write_text(json.dumps({"sandbox": {"excludedCommands": ["cat *"]}}))
    assert confined(tree)[0] is False


def hook(payload):
    out, err = io.StringIO(), io.StringIO()
    return claude.main(io.StringIO(json.dumps(payload)), out, err), err.getvalue()


def bash(t, cmd, **extra):
    p = {"hook_event_name": "PreToolUse", "cwd": str(t / "repo"), "permission_mode": "default",
         "tool_name": "Bash", "tool_input": {"command": cmd}}
    p.update(extra)
    return p


def test_hook_refuses_less_only_when_confined(tree, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    roots_only(tree)
    assert hook(bash(tree, "ls .."))[0] == 2  # not confined: above a root
    write_sandbox(tree)
    assert hook(bash(tree, "ls .."))[0] == 0  # confined: the kernel is the boundary
    assert hook(bash(tree, "cat ../phi/FAKE-PT-0001.bam"))[0] == 2  # still named


def test_copilot_payloads_are_never_confined(tree, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    roots_only(tree)
    write_sandbox(tree)
    p = {"cwd": str(tree / "repo"), "toolName": "bash", "toolArgs": {"command": "ls .."}}
    assert hook(p)[0] == 2


def test_doctor_reports_confinement(tree):
    roots_only(tree)
    r = ag(["doctor", "--verbose"], tree / "repo")
    assert "sandbox confines the shell: NO" in r.stdout
    # not wired yet: without --verbose, one next step stands for the parts
    r = ag(["doctor"], tree / "repo")
    assert "not wired" in r.stdout and "sandbox confines the shell: NO" not in r.stdout
    write_sandbox(tree)
    r = ag(["doctor"], tree / "repo")
    assert "sandbox confines the shell: yes" in r.stdout


# --- git hook: protected names are withheld --------------------------------------------------

def test_pre_commit_withholds_protected_names(tree):
    repo = tree / "gitrepo"
    (repo / "phi").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "phi" / "FAKE-PT-0042.txt").write_text("x\n")
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(f'[protected_paths]\nroots = ["{repo}/phi"]\n')
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    r = ag(["git-hook", "pre-commit"], repo)
    assert r.returncode == 1
    assert "FAKE-PT-0042" not in r.stdout + r.stderr and "names withheld" in r.stderr
