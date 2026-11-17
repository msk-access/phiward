"""The sixteenth review round, fixed by moving the decision to the kernel: a shell call that
Claude Code's sandbox does not confine is refused, except a phiward command written whole (the
gateway, `doctor`, `check`). The text check stays only where the operator turns it on in the
user config (`[shell] best_effort`). Strict mode is gone. Made-up trees only."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import config, confine
from phiward.adapters import claude, decide
from phiward.core import ALLOW, DENY, SHELL, Action
from phiward.guards import protected_paths
from helpers import CONFINE_WHY, check_shell, protect

SRC = str(Path(__file__).resolve().parents[1] / "src")
seatbelt = pytest.mark.skipif(confine.backend() != "seatbelt" or CONFINE_WHY is not None,
                              reason="Seatbelt only")
REFUSED = "not confined by Claude Code's sandbox"


def strict_default(tree):
    """The user config without the opt-in: unconfined shell calls are refused."""
    return protect(tree, [], best_effort=False)


# --- the rule ------------------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", ["ls", "cat README.md", "git status", "echo hi > out.txt",
                                 "phiward exec -c \"$(cat f)\"", "phiward exec -c 'ls'; cat f",
                                 "phiward exec ls", "/usr/local/bin/phiward exec -c ls",
                                 "phiward exec -c ls extra", "x=1 phiward exec -c ls",
                                 "phiward exec -c ls | cat", "phiward exec -c `id`",
                                 "phiward exec -c $X", "phiward exec -l -c ls"])
def test_an_unconfined_shell_call_is_refused_by_default(tree, cmd):
    d = check_shell(tree, strict_default(tree), cmd)
    assert d.verdict == DENY and REFUSED in d.reason, (cmd, d.reason)


def test_the_refusal_says_how_to_fix_it(tree):
    d = check_shell(tree, strict_default(tree), "ls")
    assert "install claude --user --write" in d.reason and "phiward doctor" in d.reason
    assert "phiward exec" not in d.reason


def test_a_confined_shell_call_is_not_refused(tree):
    cfg = strict_default(tree)
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command="ls", confined=True), cfg)
    assert d.verdict == ALLOW, d.reason


@pytest.mark.parametrize("cmd", ["phiward doctor", "phiward check -- ls -la",
                                 "phiward run -- wc -l README.md"])
def test_a_phiward_command_written_whole_is_not_refused_for_being_unconfined(tree, cmd):
    d = check_shell(tree, strict_default(tree), cmd)
    assert REFUSED not in d.reason, (cmd, d.reason)


@pytest.mark.parametrize("cmd", ["phiward doctor", "phiward check -- ls -la"])
def test_those_commands_are_allowed(tree, cmd):
    assert check_shell(tree, strict_default(tree), cmd).verdict == ALLOW


def test_before_any_protected_path_exists_the_shell_is_not_refused(tree):
    Path(os.environ["PHIWARD_CONFIG"]).write_text("")
    cfg = config.load(str(tree / "repo"))
    assert check_shell(tree, cfg, "ls").verdict == ALLOW


def test_monitor_follows_the_rule(tree):
    strict_default(tree)
    a = Action(SHELL, str(tree / "repo"), command="ls", tool="Monitor")
    d = decide(a, claude_sandbox=False)
    assert d.verdict == DENY and REFUSED in d.reason


def test_a_copilot_shell_call_is_refused_by_default(tree):
    strict_default(tree)
    p = {"cwd": str(tree / "repo"), "toolName": "bash", "toolArgs": json.dumps({"command": "ls"})}
    fout, ferr = io.StringIO(), io.StringIO()
    code = claude.main(io.StringIO(json.dumps(p)), fout, ferr)
    assert code == 2 and REFUSED in ferr.getvalue(), (code, fout.getvalue(), ferr.getvalue())


# --- the opt-in ----------------------------------------------------------------------------------

def test_best_effort_keeps_the_text_check(tree):
    cfg = protect(tree, [], best_effort=True)
    assert cfg.shell_best_effort
    assert check_shell(tree, cfg, "ls").verdict == ALLOW
    d = check_shell(tree, cfg, "cat ../phi/FAKE-PT-0001.bam")
    assert d.verdict == DENY and REFUSED not in d.reason


def test_a_repository_file_cannot_turn_best_effort_on(tree):
    strict_default(tree)
    (tree / "repo" / ".phiward.toml").write_text("[shell]\nbest_effort = true\n")
    cfg = config.load(str(tree / "repo"))
    assert not cfg.shell_best_effort and "shell.best_effort" in cfg.ignored
    assert check_shell(tree, cfg, "ls").verdict == DENY


def test_the_old_strict_keys_still_load_and_do_nothing(tree):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = [{json.dumps(str(tree / "phi"))}]\n'
        '[shell]\nstrict = true\ncommands = ["jq"]\n')
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem, cfg.problem
    d = check_shell(tree, cfg, "ls")
    assert d.verdict == DENY and REFUSED in d.reason  # the default rule, not strict mode


def test_strict_mode_is_gone():
    import importlib.util
    assert importlib.util.find_spec("phiward.strictshell") is None


# --- the check command, doctor and the session note ----------------------------------------------

def _cli(tree, *args):
    env = dict(os.environ, PYTHONPATH=SRC)
    env.pop("CLAUDE_PROJECT_DIR", None)
    return subprocess.run([sys.executable, "-m", "phiward", *args], cwd=str(tree / "repo"),
                          capture_output=True, text=True, env=env)


def test_doctor_says_unconfined_shell_calls_are_refused(tree):
    strict_default(tree)
    r = _cli(tree, "doctor")
    assert "shell calls outside Claude Code's sandbox: refused" in r.stdout, r.stdout


def test_doctor_warns_about_best_effort(tree):
    protect(tree, [], best_effort=True)
    r = _cli(tree, "doctor")
    assert "WARNING: [shell] best_effort is on" in r.stdout, r.stdout


def test_the_session_note_names_the_rule(tree):
    from phiward import session_note
    text = session_note.note(strict_default(tree))
    rule = "Claude Code's sandbox does not confine"
    assert rule in text and "phiward exec" not in text
    assert rule not in session_note.note(protect(tree, [], best_effort=True))
