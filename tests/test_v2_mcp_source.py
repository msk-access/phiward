"""The hook decides by where Claude Code says an MCP server's definition came from: the
`mcp_server` object of the hook input (`{name, source}`, Claude Code 2.1.274 and newer). It looks
the server up in exactly that scope, by its exact name. `sdk` (a server the app runs in itself,
such as the desktop app's own `terminal`) and every source phiward cannot read count as bare,
whatever a config file says about a server of the same name. Without `mcp_server` (an older
Claude Code, Copilot) only the operator's own config can make a server wrapped, never a
repository's `.mcp.json`. Made-up trees only."""

import io
import json
import sys

import pytest

from phiward import mcp_config
from phiward.adapters import claude
from helpers import protect, launcher_by_path

SID = "5a7c2a9e-1111-4222-8333-944455556666"
WRAPPED = {"command": "phiward", "args": ["launch", "--", "npx", "-y", "some-server"]}
BARE = {"command": "npx", "args": ["-y", "some-server"]}
REMOTE = {"type": "http", "url": "https://mcp.example.invalid/x"}
RUN = {"command": "id"}  # not a gateway call: refused by a shell-named tool of a bare server


_L = None  # the stand-in launchers of the running test


@pytest.fixture()
def t(tree, monkeypatch, launchers):
    global _L
    _L = launchers
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    launcher_by_path(monkeypatch, sys.modules[__name__], b / "phiward")
    import os
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    protect(tree, [], best_effort=False)
    return tree


def _config(t, user=None, local=None, project=None):
    data = {}
    if user is not None:
        data["mcpServers"] = user
    if local is not None:
        data["projects"] = {str(t / "repo"): {"mcpServers": local}}
    (t / "home" / ".claude.json").write_text(json.dumps(data))
    if project is not None:
        (t / "repo" / ".mcp.json").write_text(json.dumps({"mcpServers": project}))
    _L.start_config()  # Claude Code starts the servers: each wrapped one under a launcher


def _hook(t, tool, inp, server=None):
    p = {"session_id": SID, "hook_event_name": "PreToolUse", "cwd": str(t / "repo"),
         "permission_mode": "default", "tool_name": tool, "tool_input": inp}
    if server is not None:
        p["mcp_server"] = server
    err = io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err), err.getvalue()


def _src(name, source):
    return {"name": name, "source": source}


# --- H1: a repository's server cannot speak for one of the app's own --------------------------------

def test_an_app_server_is_bare_whatever_mcp_json_says(t):
    _config(t, project={"terminal": WRAPPED})
    code, err = _hook(t, "mcp__terminal__run_in_terminal", RUN, _src("terminal", "sdk"))
    assert code == 2, err


def test_the_project_server_itself_is_trusted_when_it_is_wrapped(t):
    _config(t, project={"terminal": WRAPPED})
    assert _hook(t, "mcp__terminal__run_in_terminal", RUN, _src("terminal", "project"))[0] == 0


@pytest.mark.parametrize("source", ["dynamic", "managed", "enterprise", "agent", "something-new",
                                    "", None, 7])
def test_sources_phiward_cannot_read_are_bare(t, source):
    _config(t, user={"srv": WRAPPED}, project={"srv": WRAPPED})
    assert _hook(t, "mcp__srv__run_command", RUN, {"name": "srv", "source": source})[0] == 2


@pytest.mark.parametrize("server", ["srv", ["srv"], {"source": "user"}, {"name": 3, "source": "user"}])
def test_a_malformed_mcp_server_counts_as_bare(t, server):
    _config(t, user={"srv": WRAPPED})
    assert _hook(t, "mcp__srv__run_command", RUN, server)[0] == 2


def test_other_tools_of_an_app_server_still_get_the_text_check(t):
    _config(t)
    assert _hook(t, "mcp__terminal__list_terminal_tabs", {}, _src("terminal", "sdk"))[0] == 0
    code, err = _hook(t, "mcp__terminal__set_title", {"title": str(t / "phi" / "FAKE-PT-0001.bam")},
                      _src("terminal", "sdk"))
    assert code == 2, err


# --- exact scope, exact name -------------------------------------------------------------------------

@pytest.mark.parametrize("source,code", [("user", 0), ("local", 2), ("project", 2)])
def test_the_entry_of_the_scope_claude_code_names_decides(t, source, code):
    _config(t, user={"srv": WRAPPED}, local={"srv": BARE}, project={"srv": BARE})
    assert _hook(t, "mcp__srv__run_command", RUN, _src("srv", source))[0] == code


def test_the_local_entry_wrapped_is_trusted_from_local(t):
    _config(t, user={"srv": BARE}, local={"srv": WRAPPED})
    assert _hook(t, "mcp__srv__run_command", RUN, _src("srv", "local"))[0] == 0


def test_names_are_exact_not_prefixes(t):
    _config(t, user={"a": WRAPPED, "a_": BARE})
    assert _hook(t, "mcp__a__run_command", RUN, _src("a", "user"))[0] == 0
    assert _hook(t, "mcp__a___run_command", RUN, _src("a_", "user"))[0] == 2


def test_the_tool_name_must_belong_to_the_named_server(t):
    _config(t, user={"term": WRAPPED, "other": BARE})
    assert _hook(t, "mcp__other__run_command", RUN, _src("term", "user"))[0] == 2


def test_a_name_that_is_not_configured_is_bare(t):
    _config(t, user={"srv": WRAPPED})
    assert _hook(t, "mcp__nope__run_command", RUN, _src("nope", "user"))[0] == 2


def test_an_unreadable_mcp_json_makes_only_the_project_scope_bare(t):
    _config(t, user={"u": WRAPPED})
    (t / "repo" / ".mcp.json").write_text('{"mcpServers": {"p": 1,}}')
    assert _hook(t, "mcp__u__run_command", RUN, _src("u", "user"))[0] == 0
    assert _hook(t, "mcp__p__run_command", RUN, _src("p", "project"))[0] == 2


# --- remote servers ----------------------------------------------------------------------------------

def test_a_remote_user_server_gets_the_text_check(t):
    _config(t, user={"db": REMOTE})
    assert _hook(t, "mcp__db__execute_sql", {"sql": "select 1"}, _src("db", "user"))[0] == 0


def test_a_remote_project_server_gets_the_text_check(t):
    _config(t, project={"db": REMOTE})
    assert _hook(t, "mcp__db__execute_sql", {"sql": "select 1"}, _src("db", "project"))[0] == 0


def test_a_claude_ai_connector_gets_the_text_check(t):
    _config(t)
    tool = "mcp__claude_ai_Example__execute_query"
    assert _hook(t, tool, {"q": "x"}, _src("claude.ai Example", "claudeai"))[0] == 0
    code, err = _hook(t, tool, {"q": str(t / "phi" / "FAKE-PT-0001.bam")},
                      _src("claude.ai Example", "claudeai"))
    assert code == 2, err


# --- plugins -----------------------------------------------------------------------------------------

def _plugin(t, servers, in_plugin_json=False, name="myp"):
    root = t / "plugroot"
    (root / ".claude-plugin").mkdir(parents=True, exist_ok=True)
    if in_plugin_json:
        (root / ".claude-plugin" / "plugin.json").write_text(
            json.dumps({"name": name, "mcpServers": servers}))
    else:
        (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    reg = t / "home" / ".claude" / "plugins"
    reg.mkdir(parents=True, exist_ok=True)
    (reg / "installed_plugins.json").write_text(json.dumps({"version": 2, "plugins": {
        f"{name}@market": [{"scope": "user", "installPath": str(root), "version": "1"}]}}))
    return root


@pytest.mark.parametrize("in_plugin_json", [False, True])
def test_a_remote_plugin_server_gets_the_text_check(t, in_plugin_json):
    _config(t)
    _plugin(t, {"db": REMOTE}, in_plugin_json)
    assert _hook(t, "mcp__plugin_myp_db__execute_sql", {"sql": "select 1"},
                 _src("plugin:myp:db", "plugin"))[0] == 0


def test_a_local_plugin_server_is_bare(t):
    _config(t)
    _plugin(t, {"srv": {"command": "${CLAUDE_PLUGIN_ROOT}/bin/srv"}})
    assert _hook(t, "mcp__plugin_myp_srv__execute_sql", {"sql": "x"},
                 _src("plugin:myp:srv", "plugin"))[0] == 2


def test_an_unknown_plugin_is_bare(t):
    _config(t)
    assert _hook(t, "mcp__plugin_nope_db__execute_sql", {"sql": "x"},
                 _src("plugin:nope:db", "plugin"))[0] == 2


def test_the_plugin_tool_name_must_match_its_server(t):
    _config(t)
    _plugin(t, {"db": REMOTE})
    assert _hook(t, "mcp__plugin_myp_other__execute_sql", {"sql": "x"},
                 _src("plugin:myp:db", "plugin"))[0] == 2


def test_placeholders_are_filled_in_as_claude_code_does(t, monkeypatch):
    spec = {"command": "${CLAUDE_PLUGIN_ROOT}/srv", "args": ["${SOME_VAR}/a", "${UNSET_VAR:-dflt}",
                                                         "${UNSET_VAR}", "$SOME_VAR"]}
    out = mcp_config._expand(spec, {"CLAUDE_PLUGIN_ROOT": "/p", "SOME_VAR": "/opt/x"})
    assert out == {"command": "/p/srv", "args": ["/opt/x/a", "dflt", "${UNSET_VAR}", "$SOME_VAR"]}


# --- without `mcp_server`: only the operator's own config ------------------------------------------

def test_without_a_source_mcp_json_cannot_make_a_server_wrapped(t):
    _config(t, project={"srv": WRAPPED})
    code, err = _hook(t, "mcp__srv__run_command", RUN)
    assert code == 2, err
    assert "2.1.274" in err, err


def test_without_a_source_the_user_config_still_counts(t):
    _config(t, user={"srv": WRAPPED})
    assert _hook(t, "mcp__srv__run_command", RUN)[0] == 0


def test_without_a_source_a_remote_mcp_json_server_is_not_remote(t):
    _config(t, project={"db": REMOTE})
    assert _hook(t, "mcp__db__execute_sql", {"sql": "select 1"})[0] == 2


# --- the refusal ----------------------------------------------------------------------------------

def test_the_refusal_shows_the_name_without_control_characters(t):
    _config(t)
    name = "x\x1b[31mred\nline"
    code, err = _hook(t, "mcp__x__31mred_line__run_command", RUN, _src(name, "user"))
    assert code == 2
    assert "\x1b" not in err and "red\nline" not in err, repr(err)


@pytest.mark.parametrize("source,words", [
    ("sdk", "cannot see this server's command"),
    ("user", "phiward mcp wrap"),
    ("plugin", "cannot see this server's command"),
])
def test_the_advice_follows_the_source(t, source, words):
    _config(t, user={"srv": BARE})
    name = "plugin:p:srv" if source == "plugin" else "srv"
    tool = "mcp__plugin_p_srv__run_command" if source == "plugin" else "mcp__srv__run_command"
    code, err = _hook(t, tool, RUN, _src(name, source))
    assert code == 2 and words in err, err


# --- doctor ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("version,warned", [((2, 1, 212), True), ((2, 1, 274), False), (None, False)])
def test_doctor_warns_when_claude_code_is_too_old_to_name_the_source(t, monkeypatch, version,
                                                                     warned):
    from phiward import claude_settings, config, doctor
    monkeypatch.setattr(claude_settings, "claude_version", lambda: version)
    _config(t, user={"srv": WRAPPED})
    lines = doctor.mode_report(str(t / "repo"), str(t / "home"), config.load(str(t / "repo")))
    assert any("does not tell the hook which server" in ln for ln in lines) == warned, lines
