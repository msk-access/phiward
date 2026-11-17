"""A plugin's twin entry: the same wrapped command as another of the plugin's copy, plus a `cwd`
or an `env` key that changes what runs, or the launcher started through another program. It
counts as bare itself, but Claude Code still starts its launcher, which has the same command.
A plugin's twins are counted by that command, so the twin's launcher never vouches for the other
entry. A configured entry needs no counting: it has its own entry id (test_v2_entry_id).
Made-up trees only."""

import io
import json
import os
import sys

import pytest

from phiward import mcp_config
from phiward.adapters import claude
from helpers import protect, launcher_by_path

WRAPPED = {"command": "phiward", "args": ["launch", "--", "npx", "-y", "some-server"]}
PLUG = {"command": "phiward", "args": ["launch", "--", "${CLAUDE_PLUGIN_ROOT}/bin/srv"]}
RUN = {"command": "id"}
CHANGES = [{"cwd": "/tmp"}, {"env": {"PATH": "/made/up/bin"}}, {"env": {"PYTHONPATH": "/x"}}]

_L = None


@pytest.fixture()
def t(tree, monkeypatch, launchers):
    global _L
    _L = launchers
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    launcher_by_path(monkeypatch, sys.modules[__name__], b / "phiward")
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
    protect(tree, [], best_effort=False)
    return tree


def _user(t, servers):
    (t / "home" / ".claude.json").write_text(json.dumps({"mcpServers": servers}))


def _copy(t, servers):
    root = t / "plug-a"
    (root / ".claude-plugin").mkdir(parents=True, exist_ok=True)
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    reg = t / "home" / ".claude" / "plugins"
    reg.mkdir(parents=True, exist_ok=True)
    (reg / "installed_plugins.json").write_text(json.dumps(
        {"version": 2, "plugins": {"myp@m": [{"scope": "user", "installPath": str(root)}]}}))
    return str(root)


def _hook(t, tool, name, source):
    p = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(t / "repo"),
         "permission_mode": "default", "tool_name": tool, "tool_input": RUN,
         "mcp_server": {"name": name, "source": source}}
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), io.StringIO())


def _hash(spec, **env):
    return mcp_config._spec_hash(mcp_config._expand(spec, dict(os.environ, **env)))


@pytest.mark.parametrize("extra", CHANGES)
def test_a_plugin_twin_that_changes_what_runs_still_needs_its_own_launcher(t, extra):
    root = _copy(t, {"srv": PLUG, "twin": dict(PLUG, **extra)})
    _user(t, {})
    h = _hash(PLUG, CLAUDE_PLUGIN_ROOT=root)
    _L.start(h, plugin=root)
    assert _hook(t, "mcp__plugin_myp_srv__run_command", "plugin:myp:srv", "plugin") == 2
    _L.start(h, plugin=root)
    assert _hook(t, "mcp__plugin_myp_srv__run_command", "plugin:myp:srv", "plugin") == 0


# a twin that starts the plugin's launcher through another program: Claude Code starts it, and
# its launcher has the same command, so it is counted too (counting more only asks for more
# launchers). A configured entry has its own entry id instead (test_v2_entry_id).
def _through(kind, spec):
    import shlex
    if kind == "nice":
        return {"command": "nice", "args": [spec["command"]] + spec["args"]}
    return {"command": "sh", "args": ["-c", "exec " + shlex.join([spec["command"]] + spec["args"])]}


@pytest.mark.parametrize("kind", ["nice", "sh"])
def test_a_plugin_twin_through_another_program_still_needs_its_own_launcher(t, kind):
    root = _copy(t, {"srv": PLUG, "twin": _through(kind, PLUG)})
    _user(t, {})
    h = _hash(PLUG, CLAUDE_PLUGIN_ROOT=root)
    _L.start(h, plugin=root)
    assert _hook(t, "mcp__plugin_myp_srv__run_command", "plugin:myp:srv", "plugin") == 2
    _L.start(h, plugin=root)
    assert _hook(t, "mcp__plugin_myp_srv__run_command", "plugin:myp:srv", "plugin") == 0
