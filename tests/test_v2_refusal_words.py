"""Refusals that say what to change: a gateway call that is not the whole command names the part
to remove; a shell Claude Code's sandbox does not confine is told, once, what makes it work; the
tail is short and names `write_to` only where it matters; an MCP tool's advice always names a
path that works (a gateway call in Bash works confined or not). Made-up trees only."""

import io
import json

import pytest

from phiward.core import DENY, FILE_READ, Action
from phiward.guards import protected_paths
from helpers import check_shell, protect


@pytest.mark.parametrize("cmd, extra", [
    ("phiward run -- wc -l notes.txt | head", "| head"),
    ("cd sub && phiward run -- ls", "cd sub &&"),
    ("phiward run -- ls > out.txt", "> out.txt"),
    ("phiward copy a b; echo done", "; echo done"),
])
def test_a_gateway_call_that_is_not_whole_names_what_to_remove(tree, cmd, extra):
    d = check_shell(tree, protect(tree, [], best_effort=False), cmd)
    assert d.verdict == DENY
    assert "whole command" in d.reason and f"`{extra}`" in d.reason, d.reason


def test_a_gateway_call_with_a_substitution_says_fixed_words(tree):
    d = check_shell(tree, protect(tree, [], best_effort=False), "phiward run -- ls $(pwd)")
    assert d.verdict == DENY and "$(" in d.reason, d.reason


def test_a_plain_command_in_an_unconfined_shell_is_told_once_what_fixes_it(tree):
    d = check_shell(tree, protect(tree, [], best_effort=False), "ls")
    assert d.verdict == DENY
    assert "phiward install claude --user --write" in d.reason, d.reason
    assert d.reason.count("phiward run") == 1, d.reason
    assert "protected data" not in d.reason and "write_to" not in d.reason, d.reason
    assert len(d.reason) < 400, len(d.reason)


def test_a_file_refusal_has_a_short_tail_without_write_to(tree):
    cfg = protect(tree, [], best_effort=False)
    f = str(tree / "phi" / "FAKE-PT-0001.bam")
    d = protected_paths.check(Action(FILE_READ, str(tree / "repo"), paths=[f]), cfg)
    assert d.verdict == DENY and "phiward run" in d.reason and "write_to" not in d.reason, d.reason


def _hook(tree, tool, name, source):
    from phiward.adapters import claude
    p = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
         "permission_mode": "default", "tool_name": tool, "tool_input": {"command": "id"},
         "mcp_server": {"name": name, "source": source}}
    err = io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err), err.getvalue()


@pytest.mark.parametrize("name, source", [("plugin:p:srv", "plugin"), ("x", "sdk"),
                                          ("ide", "user")])
def test_mcp_advice_names_a_gateway_call_in_bash(tree, monkeypatch, name, source):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    protect(tree, [], best_effort=False)
    (tree / "home" / ".claude.json").write_text(json.dumps({"mcpServers": {
        "ide": {"type": "http", "url": "http://127.0.0.1:9/mcp"}}}))
    code, err = _hook(tree, f"mcp__{name.replace(':', '_')}__run_command", name, source)
    assert code == 2
    assert "use Bash or the gateway" not in err and "`phiward run -- CMD`" in err, err


def test_phiward_as_an_argument_is_not_told_to_remove_the_command(tree):
    d = check_shell(tree, protect(tree, [], best_effort=False), "echo phiward run -- ls")
    assert d.verdict == DENY
    assert "remove `echo`" not in d.reason and "argument" in d.reason, d.reason


def test_two_gateway_calls_on_two_lines_are_told_to_run_one_per_call(tree):
    d = check_shell(tree, protect(tree, [], best_effort=False),
                    "phiward run -- ls\nphiward run -- pwd")
    assert d.verdict == DENY
    assert "one gateway call" in d.reason and "install claude" not in d.reason, d.reason


@pytest.mark.parametrize("prefix", ["sudo", "time", "nohup", "exec", "command", "nice"])
def test_a_prefix_command_before_a_gateway_call_is_told_to_go(tree, prefix):
    d = check_shell(tree, protect(tree, [], best_effort=False), f"{prefix} phiward run -- ls")
    assert d.verdict == DENY
    assert f"remove `{prefix}`" in d.reason and "argument" not in d.reason, d.reason
