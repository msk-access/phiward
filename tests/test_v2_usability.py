"""What the review found too strict or too slow, now usable without opening a leak: many paths in
one call stay fast; a URL or a remote server's text may name `.mcp.json` or Claude Code's
settings (nothing here is written); the app's own booleans that start with `_` (`_consent`) do
not count as a field that changes what runs. Made-up trees only."""

import io
import json
import os
import time

import pytest

from helpers import protect

REMOTE = {"type": "http", "url": "https://mcp.example.invalid/x"}
BARE = {"command": "npx", "args": ["-y", "some-server"]}


@pytest.fixture()
def t(tree, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    protect(tree, [], best_effort=False)
    (tree / "home" / ".claude.json").write_text(json.dumps({"mcpServers": {
        "docs": REMOTE, "srv": BARE}}))
    return tree


def _hook(t, tool, inp, name, source="user"):
    from phiward.adapters import claude
    p = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(t / "repo"),
         "permission_mode": "default", "tool_name": tool, "tool_input": inp,
         "mcp_server": {"name": name, "source": source}}
    err = io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err), err.getvalue()


def test_many_paths_in_one_call_stay_fast(t):
    inp = {"files": [f"src/mod{i}/file{i}.py" for i in range(2000)]}
    start = time.perf_counter()
    code, err = _hook(t, "mcp__srv__index_files", inp, "srv")
    took = time.perf_counter() - start
    assert code == 0, err
    assert took < 2.0, f"{took:.2f}s"


@pytest.mark.parametrize("url", [
    "https://github.com/example/repo/blob/main/.mcp.json",
    "https://docs.example.invalid/en/.claude/settings.json",
    "wss://example.invalid/.claude/settings.local.json",
])
def test_a_url_may_name_the_files_that_control_the_guards(t, url):
    assert _hook(t, "mcp__srv__fetch", {"url": url}, "srv")[0] == 0


def test_a_file_url_to_them_is_still_refused(t):
    url = "file://" + str(t / "repo" / ".mcp.json")
    assert _hook(t, "mcp__srv__fetch", {"url": url}, "srv")[0] == 2


def test_a_remote_servers_text_may_name_them(t):
    assert _hook(t, "mcp__docs__search", {"q": ".claude/settings.json"}, "docs")[0] == 0
    assert _hook(t, "mcp__docs__search", {"q": "~/.claude/settings.json"}, "docs")[0] == 0


def test_a_local_servers_text_naming_them_is_still_refused(t):
    assert _hook(t, "mcp__srv__save", {"path": ".claude/settings.json"}, "srv")[0] == 2


def test_a_remote_server_still_may_not_name_protected_data(t):
    code, err = _hook(t, "mcp__docs__search", {"q": str(t / "phi" / "FAKE-PT-0001.bam")}, "docs")
    assert code == 2, err


def test_the_apps_consent_flag_is_not_a_field_that_changes_what_runs(t):
    assert _hook(t, "mcp__terminal__open_terminal_tab",
                 {"cwd": str(t / "repo"), "_consent": True}, "terminal", "sdk")[0] == 0
    assert _hook(t, "mcp__terminal__run_in_terminal",
                 {"command": "phiward doctor", "_consent": True}, "terminal", "sdk")[0] == 0


@pytest.mark.parametrize("value", ["yes", {"a": 1}, ["x"], 1])
def test_an_underscore_field_that_is_not_a_boolean_is_the_wrong_shape(t, value):
    assert _hook(t, "mcp__terminal__run_in_terminal",
                 {"command": "phiward doctor", "_consent": value}, "terminal", "sdk")[0] == 2


def test_an_underscore_field_does_not_open_a_terminal_without_a_command(t):
    code, err = _hook(t, "mcp__terminal__open_terminal_tab",
                      {"cwd": str(t / "repo"), "_run": "id"}, "terminal", "sdk")
    assert code == 2, err
    assert os.path.isdir(t / "repo")
