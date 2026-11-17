"""The seventeenth review round. The file tools cannot write what a shell runs before a command
(startup files, Claude Code's shell snapshots), so a planted `phiward` cannot stand in for the
real one in a shell no sandbox confines. Tools whose name says shell are shells; only Claude
Code's own Bash and Monitor can count as confined. (Its bubblewrap and `phiward exec` parts are
gone with them.) Made-up trees only."""

import io
import json
from pathlib import Path

import pytest

from phiward import claude_settings
from phiward.adapters import claude, decide
from phiward.core import ALLOW, DENY, FILE_WRITE, SHELL, Action
from phiward.guards import protected_paths
from helpers import protect

SRC = str(Path(__file__).resolve().parents[1] / "src")
REFUSED = "not confined by Claude Code's sandbox"


def _write(tree, path):
    cfg = protect(tree, [], best_effort=False)
    return protected_paths.check(Action(FILE_WRITE, str(tree / "repo"), paths=(str(path),),
                                        tool="Write"), cfg)


# --- 1. what a shell runs before a command -------------------------------------------------------

@pytest.mark.parametrize("name", [".bashrc", ".bash_profile", ".profile", ".bash_aliases",
                                  ".zshrc", ".zshenv", ".zprofile", ".zlogin",
                                  ".claude/shell-snapshots/snapshot-zsh-1.sh",
                                  ".claude/shell-snapshots"])
def test_a_file_tool_cannot_write_what_the_shell_runs_first(tree, name):
    d = _write(tree, tree / "home" / name)
    assert d.verdict == DENY, (name, d.reason)


def test_zdotdir_and_bash_env_are_covered(tree, monkeypatch):
    z = tree / "zdot"
    z.mkdir()
    monkeypatch.setenv("ZDOTDIR", str(z))
    monkeypatch.setenv("BASH_ENV", str(tree / "benv.sh"))
    assert _write(tree, z / ".zshrc").verdict == DENY
    assert _write(tree, tree / "benv.sh").verdict == DENY


def test_a_claude_config_dir_moves_the_snapshots_with_it(tree, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tree / "cc"))
    assert _write(tree, tree / "cc" / "shell-snapshots" / "s.sh").verdict == DENY


def test_an_ordinary_file_is_still_writable(tree):
    assert _write(tree, tree / "repo" / "notes.md").verdict == ALLOW
    assert _write(tree, tree / "home" / "bashrc-notes.txt").verdict == ALLOW


def test_the_list_is_one_list():
    paths = claude_settings.shell_code_paths("/h", {})
    assert "/h/.bashrc" in paths and "/h/.claude/shell-snapshots" in paths
    assert len(paths) == len(set(paths))


# --- 4. tools whose name says shell --------------------------------------------------------------

def _hook(payload):
    fout, ferr = io.StringIO(), io.StringIO()
    code = claude.main(io.StringIO(json.dumps(payload)), fout, ferr)
    return code, fout.getvalue(), ferr.getvalue()


@pytest.mark.parametrize("tool", ["write_bash", "Shell", "run_shell_command", "mcp__x__shell"])
def test_a_tool_whose_name_says_shell_is_refused_without_the_kernel(tree, tool):
    protect(tree, [], best_effort=False)
    code, _, err = _hook({"cwd": str(tree / "repo"), "toolName": tool,
                          "toolArgs": json.dumps({"command": "ls", "input": "ls"})})
    assert code == 2 and "outside Claude Code's sandbox" in err, (tool, err)


@pytest.mark.parametrize("tool", ["powershell", "PowerShell", "pwsh_powershell"])
def test_powershell_in_any_letter_case_is_refused(tree, tool):
    protect(tree, [], best_effort=True)
    code, _, err = _hook({"cwd": str(tree / "repo"), "toolName": tool,
                          "toolArgs": json.dumps({"command": "Get-ChildItem"})})
    assert code == 2, (tool, err)


@pytest.mark.parametrize("tool", ["BashOutput", "KillShell", "KillBash"])
def test_claude_code_s_shell_output_tools_are_not_shells(tree, tool):
    protect(tree, [], best_effort=False)
    p = {"session_id": "fake", "hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
         "permission_mode": "default", "tool_name": tool, "tool_input": {"bash_id": "b1"}}
    assert _hook(p)[0] == 0


def test_only_bash_and_monitor_can_count_as_confined(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    monkeypatch.setattr(claude_settings, "named_project_holds", lambda cwd: True)
    monkeypatch.setattr(claude_settings, "confinement_reason", lambda *a, **k: None)
    for tool, want in (("Bash", ALLOW), ("Monitor", ALLOW), ("mcp__x__shell", DENY)):
        a = Action(SHELL, str(tree / "repo"), command="ls", tool=tool)
        d = decide(a, claude_sandbox=True)
        assert d.verdict == want, (tool, d.reason)
