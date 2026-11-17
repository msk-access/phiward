"""What the review of the source and launcher-record round found, closed. A string that looks
like a web address but climbs out of it (`..`) is checked as a path; a "remote" server whose
address is this machine counts as a local one; a plugin server with the same command as a
configured one needs its own launcher; the launcher records are not trusted through a link; one
malformed entry does not make every wrapped server bare; only the plugin copy that applies to
this project counts; of the app's own `_` fields only `_consent` is ignored; without a source,
every server a tool name may belong to is checked. Made-up trees only."""

import io
import json
import os
import sys
import socket

import pytest

from phiward import mcp_config
from phiward.adapters import claude
from helpers import protect, launcher_by_path

WRAPPED = {"command": "phiward", "args": ["launch", "--", "npx", "-y", "some-server"]}
OTHER = {"command": "phiward", "args": ["launch", "--", "npx", "-y", "other-server"]}
RUN = {"command": "id"}

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
    protect(tree, [], best_effort=False)
    return tree


def _config(t, user=None, local=None, start=True):
    data = {}
    if user is not None:
        data["mcpServers"] = user
    if local is not None:
        data["projects"] = {str(t / "repo"): {"mcpServers": local}}
    (t / "home" / ".claude.json").write_text(json.dumps(data))
    if start:
        _L.start_config()


def _hook(t, tool, inp, server=None):
    p = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(t / "repo"),
         "permission_mode": "default", "tool_name": tool, "tool_input": inp}
    if server is not None:
        p["mcp_server"] = server
    err = io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err), err.getvalue()


def _src(name, source="user"):
    return {"name": name, "source": source}


def _hash(spec, **env):
    return mcp_config._spec_hash(mcp_config._expand(spec, dict(os.environ, **env)))


# --- 1. a web address that climbs out of itself is a path -----------------------------------------

@pytest.mark.parametrize("text", [
    "https://x/../../.mcp.json",
    "https://x/../../.claude/settings.json",
    "http://x/%2e%2e/%2e%2e/.mcp.json",
])
def test_a_url_that_climbs_to_a_guard_file_is_refused(t, text):
    _config(t, user={"srv": {"command": "npx"}})
    code, err = _hook(t, "mcp__srv__read_file", {"path": text}, _src("srv"))
    assert code == 2, err


@pytest.mark.parametrize("text", ["https://x/../../leak.txt", "https://x/%2E%2E/%2E%2E/leak.txt",
                                  "wss://x/a/../../../leak.txt"])
def test_a_url_that_climbs_through_a_link_into_a_root_is_refused(t, text):
    _config(t, user={"srv": {"command": "npx"}})
    code, err = _hook(t, "mcp__srv__read_file", {"path": text}, _src("srv"))
    assert code == 2, err


@pytest.mark.parametrize("text", ["https://github.com/example/repo/blob/main/.mcp.json",
                                  "https://example.invalid/a/../.claude/settings.json"])
def test_an_ordinary_url_still_may_name_them(t, text):
    _config(t, user={"srv": {"command": "npx"}})
    assert _hook(t, "mcp__srv__fetch", {"url": text}, _src("srv"))[0] == 0


# --- 2. a "remote" server on this machine is a local one ------------------------------------------

@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "LOCALHOST.", "[::1]", "127.1",
                                  "2130706433", "0x7f.0.0.1", "0.0.0.0", "ide.localhost",
                                  "169.254.1.2", "[fe80::1]", "[::ffff:127.0.0.1]", "[::]",
                                  "HOSTNAME", "HOSTNAME.local"])
def test_a_remote_server_on_this_machine_is_not_remote(t, host):
    host = host.replace("HOSTNAME", socket.gethostname().split(".")[0])
    _config(t, user={"ide": {"type": "http", "url": f"http://{host}:8123/mcp"}})
    code, err = _hook(t, "mcp__ide__execute_terminal_command", RUN, _src("ide"))
    assert code == 2, err
    assert not mcp_config._is_remote({"type": "sse", "url": f"http://{host}:8123/mcp"})


@pytest.mark.parametrize("url", ["not a url", "http://", "http://[::1", ""])
def test_a_url_phiward_cannot_read_is_not_remote(url):
    assert not mcp_config._is_remote({"type": "http", "url": url})


def test_a_real_remote_server_stays_remote(t):
    _config(t, user={"db": {"type": "http", "url": "https://mcp.example.invalid/x"}})
    assert _hook(t, "mcp__db__execute_sql", {"sql": "select 1"}, _src("db"))[0] == 0
    assert mcp_config._is_remote({"type": "http", "url": "https://10.1.2.3/mcp"})


# --- 3. a plugin server with the same command needs its own launcher ------------------------------

def _plugin(t, servers, installs=None, name="myp"):
    installs = installs or [{"scope": "user"}]
    roots = []
    for i, inst in enumerate(installs):
        root = t / f"plugroot{i}"
        (root / ".claude-plugin").mkdir(parents=True, exist_ok=True)
        (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
        roots.append(root)
        inst.update(installPath=str(root), version="1")
    reg = t / "home" / ".claude" / "plugins"
    reg.mkdir(parents=True, exist_ok=True)
    (reg / "installed_plugins.json").write_text(json.dumps({"version": 2, "plugins": {
        f"{name}@market": installs}}))
    return roots


def test_a_plugin_launcher_does_not_vouch_for_a_user_server_of_the_same_command(t):
    roots = _plugin(t, {"p": WRAPPED})
    _config(t, user={"a": WRAPPED}, start=False)
    _L.start(_hash(WRAPPED), plugin=str(roots[0]))  # the plugin's (the user server runs bare)
    assert _hook(t, "mcp__a__run_command", RUN, _src("a"))[0] == 2
    _L.start(_hash(WRAPPED))
    assert _hook(t, "mcp__a__run_command", RUN, _src("a"))[0] == 0


# --- 4. the records are not trusted through a link -------------------------------------------------

def test_records_reached_through_a_link_do_not_count(t):
    real = t / "elsewhere"
    real.mkdir(mode=0o700)
    os.symlink(real, t / "home" / ".phiward")
    _config(t, user={"a": WRAPPED})
    assert _hook(t, "mcp__a__run_command", RUN, _src("a"))[0] == 2


def test_the_launched_folder_as_a_link_does_not_count(t):
    (t / "home" / ".phiward").mkdir(mode=0o700)
    real = t / "elsewhere"
    real.mkdir(mode=0o700)
    os.symlink(real, t / "home" / ".phiward" / "launched")
    _config(t, user={"a": WRAPPED})
    assert _hook(t, "mcp__a__run_command", RUN, _src("a"))[0] == 2


# --- 5. one malformed entry does not make every wrapped server bare --------------------------------

@pytest.mark.parametrize("bad", [{"command": "x", "args": 5}, {"command": "x", "args": ["a\0b"]},
                                 {"command": 7}, {"command": "phiward", "args": [None, {"a": 1}]},
                                 {"command": "phiward", "args": "launch -- x"},
                                 {"command": "x", "env": "PATH=/tmp"}])
def test_a_malformed_entry_does_not_stop_the_others(t, bad):
    _config(t, user={"a": WRAPPED, "bad": bad})
    assert _hook(t, "mcp__a__run_command", RUN, _src("a"))[0] == 0
    code, err = _hook(t, "mcp__bad__run_command", RUN, _src("bad"))
    assert code == 2, err


def test_a_malformed_entry_without_a_source_does_not_stop_the_others(t):
    _config(t, user={"a": WRAPPED, "bad": {"command": "x", "args": 5}})
    assert _hook(t, "mcp__a__run_command", RUN)[0] == 0
    assert _hook(t, "mcp__bad__run_command", RUN)[0] == 2


# --- 6. the plugin copy that applies to this project -----------------------------------------------

PLUG = {"command": "phiward", "args": ["launch", "--", "${CLAUDE_PLUGIN_ROOT}/bin/srv"]}


def test_a_plugin_installed_for_another_project_too_is_trusted(t):
    roots = _plugin(t, {"srv": PLUG}, [{"scope": "user"},
                                       {"scope": "project", "projectPath": str(t / "other")}])
    _config(t, start=False)
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=str(roots[0])), plugin=str(roots[0]))
    code, err = _hook(t, "mcp__plugin_myp_srv__run_command", RUN, _src("plugin:myp:srv", "plugin"))
    assert code == 0, err


def test_the_copy_for_this_project_wins_over_the_users(t):
    roots = _plugin(t, {"srv": PLUG}, [{"scope": "user"},
                                       {"scope": "project", "projectPath": str(t / "repo")}])
    _config(t, start=False)
    src = _src("plugin:myp:srv", "plugin")
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=str(roots[0])), plugin=str(roots[0]))  # not used
    assert _hook(t, "mcp__plugin_myp_srv__run_command", RUN, src)[0] == 2
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=str(roots[1])), plugin=str(roots[1]))
    assert _hook(t, "mcp__plugin_myp_srv__run_command", RUN, src)[0] == 0


def test_a_launcher_of_any_copy_of_the_same_rank_vouches(t):
    """A tool name stands for one plugin server in a session: whichever copy runs, its own
    launcher (with its own folder and command) shows it is wrapped."""
    roots = _plugin(t, {"srv": PLUG}, [{"scope": "user"}, {"scope": "somewhere"}])
    _config(t, start=False)
    src = _src("plugin:myp:srv", "plugin")
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=str(roots[0])))  # not the plugin's: no folder
    assert _hook(t, "mcp__plugin_myp_srv__run_command", RUN, src)[0] == 2
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=str(roots[1])), plugin=str(roots[1]))
    assert _hook(t, "mcp__plugin_myp_srv__run_command", RUN, src)[0] == 0


# --- 8. only `_consent` among the app's own fields ---------------------------------------------

@pytest.mark.parametrize("key", ["_raw", "_shell", "_unsafe", "_"])
def test_other_underscore_flags_are_fields_that_may_change_what_runs(t, key):
    _config(t)
    code, err = _hook(t, "mcp__terminal__run_in_terminal",
                      {"command": "phiward doctor", key: True}, _src("terminal", "sdk"))
    assert code == 2, err


def test_consent_is_still_ignored(t):
    _config(t)
    assert _hook(t, "mcp__terminal__run_in_terminal", {"command": "phiward doctor",
                 "_consent": True}, _src("terminal", "sdk"))[0] == 0


# --- 9. without a source, every server a tool name may belong to ---------------------------------

def test_without_a_source_every_name_of_the_prefix_needs_its_launcher(t):
    _config(t, user={"a.b": WRAPPED, "a_b": OTHER}, start=False)
    _L.start(_hash(WRAPPED))
    assert _hook(t, "mcp__a_b__run_command", RUN)[0] == 2
    _L.start(_hash(OTHER))
    assert _hook(t, "mcp__a_b__run_command", RUN)[0] == 0
