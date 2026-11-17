"""Review 18, finding 4: a tool that runs shell commands under another name (VS Code Copilot's
`run_in_terminal`, `run_terminal_cmd`, `execute_command`, an MCP server's `run_command`) is a
shell, judged by its name (test_v2_tool_rule.py has the whole rule). Only Claude Code's own Bash
and Monitor can be confined, so such a tool runs only one whole gateway call. Made-up trees
only."""

import io
import json

import pytest

from phiward.adapters import claude
from phiward.core import OTHER
from helpers import protect

REFUSED = "outside Claude Code's sandbox"


def _copilot(tree, tool, args):
    p = {"cwd": str(tree / "repo"), "toolName": tool, "toolArgs": json.dumps(args)}
    fout, ferr = io.StringIO(), io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), fout, ferr), ferr.getvalue()


def _claude(tree, tool, args):
    p = {"session_id": "fake", "hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
         "permission_mode": "default", "tool_name": tool, "tool_input": args}
    fout, ferr = io.StringIO(), io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), fout, ferr), ferr.getvalue()


@pytest.mark.parametrize("tool,key", [("run_in_terminal", "command"),
                                      ("run_terminal_cmd", "command"),
                                      ("execute_command", "command"),
                                      ("mcp__x__run_command", "cmd")])
def test_a_tool_with_a_command_string_is_a_shell(tree, tool, key):
    protect(tree, [], best_effort=False)
    code, err = _copilot(tree, tool, {key: "ls"})
    assert code == 2 and REFUSED in err, (tool, err)
    code, err = _claude(tree, tool, {key: "ls"})
    assert code == 2 and REFUSED in err, (tool, err)


def test_such_a_tool_may_still_make_a_gateway_call(tree):
    protect(tree, [], best_effort=False)
    code, err = _claude(tree, "mcp__x__run_command", {"cmd": "phiward run -- wc -l README.md"})
    assert code == 0, err


@pytest.mark.parametrize("tool,inp", [("mcp__s__search", {"input": "ls"}),
                                      ("mcp__s__lookup", {"query": "ls", "command": 3}),
                                      ("SlashCommand", {"command": "/review"})])
def test_a_tool_without_a_command_string_is_not_a_shell(tree, tool, inp):
    a, _ = claude.to_action({"tool_name": tool, "cwd": str(tree / "repo"), "tool_input": inp})
    assert a.kind == OTHER, tool


def test_phiward_s_own_mcp_tools_stay_other(tree):
    a, _ = claude.to_action({"tool_name": "mcp__phiward__phiward_run", "cwd": str(tree / "repo"),
                             "tool_input": {"command": ["wc", "-l", "f"]}})
    assert a.kind == OTHER


# --- the review of 4df18cd..62cc296: decoys, lists, other shapes ---------------------------------

@pytest.mark.parametrize("inp", [
    {"command": "phiward doctor", "script": "cat {t}/phi/FAKE-PT-0001.bam"},
    {"command": "phiward doctor", "cmd": "c''at /x"},
    {"cmd": "phiward run -- ls", "note": "{t}/phi"},
])
def test_a_decoy_command_does_not_hide_the_real_one(tree, inp):
    protect(tree, [], best_effort=False)
    inp = {k: v.format(t=tree) for k, v in inp.items()}
    code, err = _claude(tree, "mcp__x__run_script", inp)
    assert code == 2, (inp, err)


def test_a_decoy_is_refused_with_best_effort_too(tree):
    protect(tree, [], best_effort=True)
    code, err = _claude(tree, "mcp__x__run_script",
                        {"command": "true", "script": f"cat {tree}/phi/FAKE-PT-0001.bam"})
    assert code == 2, err


def test_a_list_command_on_a_shell_named_tool_is_checked(tree):
    protect(tree, [], best_effort=True)
    code, err = _claude(tree, "mcp__x__shell",
                        {"command": ["cat", f"{tree}/phi/FAKE-PT-0001.bam"]})
    assert code == 2, err


@pytest.mark.parametrize("tool,inp", [("Workflow", {"script": "export const meta = {}"}),
                                      ("SlashCommand", {"command": "/review"})])
def test_claude_code_s_own_non_shell_tools_stay_other(tree, tool, inp):
    a, _ = claude.to_action({"tool_name": tool, "cwd": str(tree / "repo"), "tool_input": inp})
    assert a.kind == OTHER
