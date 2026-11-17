"""A launcher says whose it is. Claude Code exports `CLAUDE_PLUGIN_ROOT` into the process of a
plugin's stdio MCP server (and not into a configured server's), so each `phiward launch` records
a hash of it. A configured server is vouched for only by launchers without one, a plugin's
server only by a launcher of its own copy. So a plugin never vouches for a configured server, a
broken, disabled or duplicated plugin does not matter to one, and a configured server's call
reads no plugin. Made-up trees only."""

import io
import json
import os
import sys

import pytest

from phiward import mcp_config
from phiward.adapters import claude
from helpers import protect, launcher_by_path

PHIWARD = "phiward"  # the launcher by its path, set by launcher_by_path
WRAPPED = {"command": "phiward", "args": ["launch", "--", "npx", "-y", "some-server"]}
PLUG = {"command": "phiward", "args": ["launch", "--", "${CLAUDE_PLUGIN_ROOT}/bin/srv"]}
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
    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
    protect(tree, [], best_effort=False)
    return tree


def _user(t, servers):
    (t / "home" / ".claude.json").write_text(json.dumps({"mcpServers": servers}))


def _registry(t, plugins):
    reg = t / "home" / ".claude" / "plugins"
    reg.mkdir(parents=True, exist_ok=True)
    (reg / "installed_plugins.json").write_text(json.dumps({"version": 2, "plugins": plugins}))


def _copy(t, label, servers, plugin_json=None):
    root = t / f"plug-{label}"
    (root / ".claude-plugin").mkdir(parents=True, exist_ok=True)
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    if plugin_json is not None:
        (root / ".claude-plugin" / "plugin.json").write_text(plugin_json)
    return str(root)


def _hook(t, tool, inp, name, source="user"):
    p = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(t / "repo"),
         "permission_mode": "default", "tool_name": tool, "tool_input": inp,
         "mcp_server": {"name": name, "source": source}}
    err = io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err), err.getvalue()


def _hash(spec, **env):
    return mcp_config._spec_hash(mcp_config._expand(spec, dict(os.environ, **env)))


PSRC = ("mcp__plugin_myp_srv__run_command", RUN, "plugin:myp:srv", "plugin")


# --- the two sides never vouch for each other ------------------------------------------------------

def test_a_config_launcher_does_not_vouch_for_a_plugin_server(t):
    root = _copy(t, "a", {"srv": PLUG})
    _registry(t, {"myp@m": [{"scope": "user", "installPath": root}]})
    _user(t, {})
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=root))  # same command, but no plugin folder
    assert _hook(t, *PSRC)[0] == 2
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=root), plugin=root)
    assert _hook(t, *PSRC)[0] == 0


def test_a_launcher_of_another_copy_does_not_vouch(t):
    a, b = _copy(t, "a", {"srv": PLUG}), _copy(t, "b", {"srv": PLUG})
    _registry(t, {"myp@m": [{"scope": "user", "installPath": a}]})
    _user(t, {})
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=a), plugin=b)
    assert _hook(t, *PSRC)[0] == 2


# --- a plugin does not matter to a configured server -----------------------------------------------

@pytest.mark.parametrize("registry", [
    {"other@m": [{"scope": "user", "installPath": "relative/path"}]},
    {"other@m": [{"scope": "user", "installPath": "/x", "projectPath": "/a\u0000b"}]},
    {"other@m": "not a list", "x@m": [5]},
])
def test_a_broken_registry_does_not_change_a_configured_server(t, registry):
    _registry(t, registry)
    _user(t, {"a": WRAPPED})
    _L.start(_hash(WRAPPED))
    code, err = _hook(t, "mcp__a__run_command", RUN, "a")
    assert code == 0, err


def test_a_plugin_launcher_never_vouches_for_a_configured_server_even_if_plugins_are_unreadable(t):
    root = _copy(t, "a", {"p": WRAPPED}, plugin_json='{"a": 1, "a": 2}')
    _registry(t, {"myp@m": [{"scope": "user", "installPath": root}],
                  "other@m": [{"scope": "user", "installPath": "relative"}]})
    _user(t, {"a": WRAPPED})
    _L.start(_hash(WRAPPED), plugin=root)
    assert _hook(t, "mcp__a__run_command", RUN, "a")[0] == 2


def test_a_plugin_that_does_not_run_does_not_block_a_configured_server(t):
    root = _copy(t, "a", {"p": WRAPPED})  # installed, perhaps disabled: no launcher of its own
    _registry(t, {"myp@m": [{"scope": "user", "installPath": root}]})
    _user(t, {"a": WRAPPED})
    _L.start(_hash(WRAPPED))
    assert _hook(t, "mcp__a__run_command", RUN, "a")[0] == 0


def test_a_configured_servers_call_reads_no_plugin(t, monkeypatch):
    for i in range(20):
        _copy(t, f"p{i}", {"s": PLUG})
    _registry(t, {f"p{i}@m": [{"scope": "user", "installPath": str(t / f"plug-p{i}")}]
                  for i in range(20)})
    _user(t, {"a": WRAPPED})
    _L.start(_hash(WRAPPED))
    calls = []
    real = mcp_config._plugin_group
    monkeypatch.setattr(mcp_config, "_plugin_group", lambda root: calls.append(root) or real(root))
    assert _hook(t, "mcp__a__run_command", RUN, "a")[0] == 0
    assert calls == []


# --- copies of one plugin ---------------------------------------------------------------------

def test_two_copies_of_the_same_rank_need_only_the_one_that_runs(t):
    a, b = _copy(t, "a", {"srv": PLUG}), _copy(t, "b", {"srv": PLUG})
    _registry(t, {"myp@m": [{"scope": "user", "installPath": a},
                            {"scope": "user", "installPath": b}]})
    _user(t, {})
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=b), plugin=b)
    code, err = _hook(t, *PSRC)
    assert code == 0, err


def test_two_plugin_ids_of_one_name_need_a_launcher_each(t):
    a, b = _copy(t, "a", {"srv": PLUG}), _copy(t, "b", {"srv": PLUG})
    _registry(t, {"myp@one": [{"scope": "user", "installPath": a}],
                  "myp@two": [{"scope": "user", "installPath": b}]})
    _user(t, {})
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=a), plugin=a)
    assert _hook(t, *PSRC)[0] == 2
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=b), plugin=b)
    assert _hook(t, *PSRC)[0] == 0


def test_two_servers_of_one_copy_with_one_command_need_two_launchers(t):
    root = _copy(t, "a", {"srv": PLUG, "twin": PLUG})
    _registry(t, {"myp@m": [{"scope": "user", "installPath": root}]})
    _user(t, {})
    h = _hash(PLUG, CLAUDE_PLUGIN_ROOT=root)
    _L.start(h, plugin=root)
    assert _hook(t, *PSRC)[0] == 2
    _L.start(h, plugin=root)
    assert _hook(t, *PSRC)[0] == 0


def test_a_bad_entry_of_this_plugin_makes_it_bare_without_a_crash(t):
    root = _copy(t, "a", {"srv": PLUG})
    _registry(t, {"myp@m": [{"scope": "user", "installPath": root},
                            {"scope": "user", "installPath": "relative"}]})
    _user(t, {})
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=root), plugin=root)
    code, err = _hook(t, *PSRC)
    assert code == 2 and "could not decide" not in err, err


# --- the record ---------------------------------------------------------------------------------

@pytest.mark.parametrize("key", ["CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA"])
def test_a_configured_entry_that_sets_the_plugin_variables_is_bare(t, key):
    spec = dict(WRAPPED, env={key: "/somewhere"})
    _user(t, {"a": spec})
    _L.start(_hash(spec))
    _L.start(_hash(spec), plugin="/somewhere")
    assert _hook(t, "mcp__a__run_command", RUN, "a")[0] == 2


def test_record_launch_keeps_the_plugin_folder_hash(t, monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", "/made/up/root")
    path = mcp_config.record_launch(["--", "x"])
    try:
        rec = json.loads(open(path).read())
        assert rec["plugin"] == mcp_config.plugin_hash("/made/up/root") != ""
    finally:
        mcp_config.end_launch(path)
    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT")
    path = mcp_config.record_launch(["--", "x"])
    try:
        assert json.loads(open(path).read())["plugin"] == ""
    finally:
        mcp_config.end_launch(path)


def test_a_record_without_the_field_counts_for_nobody(t):
    """The records came in with this release: one without the field is not trusted (a plugin's
    launcher of a development build may have written it)."""
    _user(t, {"a": WRAPPED})
    p = _L.start(_hash(WRAPPED))
    path = os.path.join(mcp_config.launched_dir(), f"{p.pid}.json")
    rec = json.loads(open(path).read())
    del rec["plugin"]
    with open(path, "w") as fh:
        json.dump(rec, fh)
    assert _hook(t, "mcp__a__run_command", RUN, "a")[0] == 2


# --- the review of 7f7b0ec ---------------------------------------------------------------------------

@pytest.mark.parametrize("env", [{"CLAUDE_PLUGIN_ROOT": ""}, {"CLAUDE_PLUGIN_DATA": "/x"},
                                 {"CLAUDE_PLUGIN_ROOT": "", "CLAUDE_PLUGIN_DATA": ""}])
def test_a_launcher_with_any_plugin_variable_is_never_a_configured_one(t, monkeypatch, env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    path = mcp_config.record_launch(["--", "x"])
    try:
        assert json.loads(open(path).read())["plugin"] not in ("",)
    finally:
        mcp_config.end_launch(path)


def test_a_plugin_folder_spelled_differently_still_matches(t, monkeypatch):
    root = _copy(t, "a", {"srv": PLUG})
    _registry(t, {"myp@m": [{"scope": "user", "installPath": root + "/"}]})
    _user(t, {})
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", root + "/./")
    path = mcp_config.record_launch(["--", "x"])
    try:
        got = json.loads(open(path).read())["plugin"]
    finally:
        mcp_config.end_launch(path)
    assert got == mcp_config.plugin_hash(root)
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=root + "/"), plugin=root)
    code, err = _hook(t, *PSRC)
    assert code == 0, err


DATA = {"command": "phiward", "args": ["launch", "--", "node", "${CLAUDE_PLUGIN_DATA}/srv.js"]}


def test_a_plugin_command_using_its_data_folder_is_filled_in_as_claude_code_does(t, monkeypatch):
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", "/the/hooks/own/plugin")  # the hook's own plugin's
    root = _copy(t, "a", {"srv": DATA})
    _registry(t, {"myp@m.x": [{"scope": "user", "installPath": root}]})
    _user(t, {})
    data = str(t / "home" / ".claude" / "plugins" / "data" / "myp-m-x")
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA")
    _L.start(_hash(DATA, CLAUDE_PLUGIN_DATA=data), plugin=root)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", "/the/hooks/own/plugin")
    code, err = _hook(t, *PSRC)
    assert code == 0, err


def test_a_configured_entry_is_filled_in_without_the_hooks_own_plugin_variables(t, monkeypatch):
    spec = {"command": PHIWARD, "args": ["launch", "--entry", "00000000000000a1", "--",
                                         "${CLAUDE_PLUGIN_ROOT}/srv"]}
    _user(t, {"a": spec})
    _L.start(_hash(spec))  # Claude Code leaves the placeholder of a configured entry as written
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", "/the/hooks/own/plugin")
    code, err = _hook(t, "mcp__a__run_command", RUN, "a")
    assert code == 0, err


# --- the review of 16745bb: the folder as Claude Code may spell it --------------------------------

# Claude Code 2.1.318 fills a plugin entry with the folder exactly as it is and the data folder
# without a trailing `/` (the operator's check-script run): only that fill counts. Another
# spelling may name another file (`${CLAUDE_PLUGIN_ROOT}x`), so it fails closed.

@pytest.mark.parametrize("registry,claude", [("{r}/", "{r}"), ("{r}", "{r}/"), ("{r}/./", "{r}")])
def test_a_plugin_command_filled_with_another_spelling_is_not_trusted(t, registry, claude):
    root = _copy(t, "a", {"srv": PLUG})
    _registry(t, {"myp@m": [{"scope": "user", "installPath": registry.format(r=root)}]})
    _user(t, {})
    spelled = claude.format(r=root)
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=spelled), plugin=spelled)
    assert _hook(t, *PSRC)[0] == 2
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=registry.format(r=root)), plugin=spelled)
    code, err = _hook(t, *PSRC)
    assert code == 0, err


def test_a_plugin_data_folder_with_a_trailing_slash_is_not_the_fill(t):
    root = _copy(t, "a", {"srv": DATA})
    _registry(t, {"myp@m": [{"scope": "user", "installPath": root}]})
    _user(t, {})
    data = str(t / "home" / ".claude" / "plugins" / "data" / "myp-m")
    _L.start(_hash(DATA, CLAUDE_PLUGIN_DATA=data + "/"), plugin=root)
    assert _hook(t, *PSRC)[0] == 2
    _L.start(_hash(DATA, CLAUDE_PLUGIN_DATA=data), plugin=root)
    assert _hook(t, *PSRC)[0] == 0


def test_a_launcher_of_a_file_beside_the_copy_does_not_vouch(t):
    spec = {"command": PHIWARD, "args": ["launch", "--", "${CLAUDE_PLUGIN_ROOT}x"]}
    root = _copy(t, "a", {"srv": spec})
    _registry(t, {"myp@m": [{"scope": "user", "installPath": root}]})
    _user(t, {})
    _L.start(_hash(spec, CLAUDE_PLUGIN_ROOT=root + "/"), plugin=root)  # runs `root/x`, not `rootx`
    assert _hook(t, *PSRC)[0] == 2


def test_two_servers_that_differ_by_a_slash_are_two_commands(t):
    one = {"command": PHIWARD, "args": ["launch", "--", "${CLAUDE_PLUGIN_ROOT}/bin/srv", "--data",
                                          "${CLAUDE_PLUGIN_DATA}/"]}
    two = {"command": PHIWARD, "args": ["launch", "--", "${CLAUDE_PLUGIN_ROOT}/bin/srv", "--data",
                                          "${CLAUDE_PLUGIN_DATA}"]}
    root = _copy(t, "a", {"srv": one, "other": two})
    _registry(t, {"myp@m": [{"scope": "user", "installPath": root}]})
    _user(t, {})
    data = str(t / "home" / ".claude" / "plugins" / "data" / "myp-m")
    _L.start(_hash(one, CLAUDE_PLUGIN_ROOT=root, CLAUDE_PLUGIN_DATA=data), plugin=root)
    _L.start(_hash(two, CLAUDE_PLUGIN_ROOT=root, CLAUDE_PLUGIN_DATA=data), plugin=root)
    code, err = _hook(t, *PSRC)
    assert code == 0, err


def test_another_folder_is_still_not_trusted(t):
    root, other = _copy(t, "a", {"srv": PLUG}), _copy(t, "b", {"srv": PLUG})
    _registry(t, {"myp@m": [{"scope": "user", "installPath": root}]})
    _user(t, {})
    _L.start(_hash(PLUG, CLAUDE_PLUGIN_ROOT=other), plugin=root)
    assert _hook(t, *PSRC)[0] == 2
