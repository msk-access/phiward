"""Claude Code's sandbox is the only boundary for the shell: `phiward exec`, the shell prefix
and phiward's agent profiles are gone. A shell call the sandbox does not confine is refused,
except a gateway call, `doctor` or `check` written whole (or the opt-in `[shell] best_effort`).
Made-up trees only."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import cli, config, install
from phiward.core import ALLOW, DENY
from helpers import check_shell, protect

SRC = str(Path(__file__).resolve().parents[1] / "src")


def _phiward(*args, cwd):
    e = dict(os.environ, PYTHONPATH=SRC)
    return subprocess.run([sys.executable, "-m", "phiward", *args], cwd=str(cwd),
                          capture_output=True, text=True, env=e, timeout=60)


def test_exec_is_not_a_command(tree):
    r = _phiward("exec", "-c", "echo RAN", cwd=tree / "repo")
    assert r.returncode == 2 and "RAN" not in r.stdout
    assert " exec " not in cli.USAGE


@pytest.mark.parametrize("cmd", ["phiward exec -c 'ls'", "ls"])
def test_an_unsandboxed_call_is_refused_and_told_the_way(tree, cmd):
    d = check_shell(tree, protect(tree, [], best_effort=False), cmd)
    assert d.verdict == DENY
    assert "Claude Code's sandbox" in d.reason and "phiward run" in d.reason, d.reason
    assert "exec" not in d.reason and "--shell-prefix" not in d.reason, d.reason


@pytest.mark.parametrize("cmd", ["phiward doctor", "phiward check -- ls", "phiward run -- ls"])
def test_gateway_doctor_and_check_still_pass(tree, cmd):
    d = check_shell(tree, protect(tree, [], best_effort=False), cmd)
    assert d.verdict == ALLOW, d.reason


def test_check_answers_as_under_the_sandbox(tree):
    protect(tree, [], best_effort=False)
    r = _phiward("check", "--", "ls", cwd=tree / "repo")
    assert r.returncode == 0 and r.stdout.startswith("allow"), r.stdout
    assert "sandbox" in r.stdout
    r = _phiward("check", "--", "cat", str(tree / "phi" / "FAKE-PT-0001.bam"), cwd=tree / "repo")
    assert r.returncode == 2, r.stdout


def test_a_reinstall_drops_the_old_prefix_and_exec_form_hooks(tree):
    cfg = config.load(str(tree / "repo"))
    py = sys.executable
    old_hook = {"type": "command", "command": "/bin/sh",
                "args": ["-c", f"{install.CLEAN_ENV}exec {py} -I -m phiward hook claude"]}
    old = {"env": {"FOO": "1", "CLAUDE_CODE_SHELL_PREFIX": config.shell_prefix_path()},
           "hooks": {"PreToolUse": [{"matcher": m, "hooks": [dict(old_hook)]}
                                    for m in install.MATCHERS]}}
    new = install.merge(old, install.wiring(cfg))
    assert "CLAUDE_CODE_SHELL_PREFIX" not in new["env"] and new["env"]["FOO"] == "1"
    hooks = [h for g in new["hooks"]["PreToolUse"] for h in g["hooks"]]
    want = install.wiring(cfg)["hooks"]["PreToolUse"][0]["hooks"][0]
    assert hooks == [want] and all(h["command"] != "/bin/sh" for h in hooks), hooks


def test_install_has_no_shell_prefix_option():
    assert "--shell-prefix" not in install.HELP + install.USAGE
    assert not hasattr(install, "shell_prefix_script")


def test_the_session_note_does_not_name_exec(tree):
    from phiward import session_note
    protect(tree, [], best_effort=False)
    assert "phiward exec" not in session_note.note(config.load(str(tree / "repo")))


def test_doctor_names_no_prefix_and_no_exec(tree):
    protect(tree, [], best_effort=False)
    r = _phiward("doctor", cwd=tree / "repo")
    out = r.stdout + r.stderr
    assert "--shell-prefix" not in out and "phiward exec" not in out, out
    assert "shell prefix" not in out, out


def test_an_old_launcher_stays_write_protected(tree):
    launcher = Path(config.shell_prefix_path())
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/bin/sh\n")
    assert str(launcher) in config.guard_files()


def test_doctor_warns_about_an_old_prefix_and_reads_old_exec_form_hooks(tree):
    from phiward import doctor
    from helpers import user_settings
    protect(tree, [], best_effort=False)
    py = sys.executable
    old_hook = {"type": "command", "command": "/bin/sh", "timeout": 10, "onFailure": "block",
                "args": ["-c", f"{install.CLEAN_ENV}exec {py} -I -m phiward hook claude"]}
    assert doctor.hook_form(old_hook) == "isolated"
    user_settings(tree, {"env": {"CLAUDE_CODE_SHELL_PREFIX": config.shell_prefix_path()}})
    r = _phiward("doctor", cwd=tree / "repo")
    assert "older phiward" in r.stdout and "install claude --user --write" in r.stdout, r.stdout
