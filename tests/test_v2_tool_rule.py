"""Tools other than Claude Code's Bash and Monitor, judged by what confines them: a tool of an
MCP server wrapped in `phiward launch --` runs in the kernel profile (text check only); a
shell-named tool of a bare server (or Copilot's terminal tools) may make one whole gateway call
in one exact form, and nothing else; every other tool gets the text check of every string
(usable: a coupon `code` is not a shell). Made-up trees only."""

import io
import json
import os
import sys

import pytest

from phiward import mcp_config
from phiward.adapters import claude
from phiward.core import DENY, FILE_WRITE, OTHER, SHELL, Action
from phiward.guards import protected_paths
from helpers import protect, launcher_by_path

REFUSED = "outside Claude Code's sandbox"


def _hook(tree, tool, inp, copilot=False, server=None):
    if copilot:
        p = {"cwd": str(tree / "repo"), "toolName": tool, "toolArgs": json.dumps(inp)}
    else:
        p = {"session_id": "f", "hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
             "permission_mode": "default", "tool_name": tool, "tool_input": inp}
        if server is not None:
            p["mcp_server"] = server
    err = io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err), err.getvalue()


def _servers(tree, servers, where="user"):
    if where == "user":
        (tree / "home" / ".claude.json").write_text(json.dumps({"mcpServers": servers}))
    else:
        (tree / "repo" / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    # Claude Code starts these servers: each wrapped one runs under a live launcher
    _L.start_config()


PHIWARD = "phiward"  # the launcher by its path, set by launcher_by_path
WRAPPED = {"command": "phiward", "args": ["launch", "--", "npx", "-y", "some-server"]}
BARE = {"command": "npx", "args": ["-y", "some-server"]}


_L = None  # the stand-in launchers of the running test


@pytest.fixture(autouse=True)
def phiward_on_path(tree, monkeypatch, launchers):
    """An installed phiward on PATH: "wrapped" means the server's command is that program."""
    global _L
    _L = launchers
    import os
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    launcher_by_path(monkeypatch, sys.modules[__name__], b / "phiward")
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))


@pytest.fixture()
def strict(tree):
    protect(tree, [], best_effort=False)
    return tree


# --- refused: the review's leaks ------------------------------------------------------------------

@pytest.mark.parametrize("tool,inp", [
    ("mcp__x__run_many_commands", {"commands": ["phiward doctor", "id"]}),
    ("mcp__x__run_command", {"command": "phiward doctor", "env": {"PATH": "/tmp/x"}}),
    ("mcp__x__run_command", {"command": "phiward doctor", "shell": "/tmp/a.sh"}),
    ("mcp__x__run_command", {"command": "phiward doctor", "args": ["&&", "id"]}),
    ("mcp__x__run_command", {"command": "phiward doctor", "cwd": "/tmp"}),
    ("mcp__x__run_command", {"command": {"program": "phiward", "a": "doctor"}}),
    ("mcp__x__run_script", {"command": "phiward doctor", "script": "id"}),
    ("mcp__x__execute_command", {"command": "ls"}),
    ("mcp__ide__executeCode", {"code": "print(1)"}),
    ("mcp__dc__start_process", {"command": "ls", "timeout_ms": 1000}),
    ("run_in_terminal", {"command": "ls", "explanation": "list"}),
])
def test_a_bare_shell_tool_runs_only_one_exact_gateway_call(strict, tool, inp):
    _servers(strict, {"x": BARE, "ide": BARE, "dc": BARE})
    code, err = _hook(strict, tool, inp)
    assert code == 2 and REFUSED in err, (tool, inp, err)


def test_a_decoy_field_with_a_protected_path_is_refused_anywhere(strict):
    code, err = _hook(strict, "mcp__x__search", {"query": "ok", "note": f"{strict}/phi/x"})
    assert code == 2, err


# --- allowed: usability ----------------------------------------------------------------------------

@pytest.mark.parametrize("tool,inp", [
    ("mcp__shop__apply_discount", {"code": "SAVE10"}),
    ("mcp__docs__query", {"query": "useEffect", "code": "print(1)"}),
    ("mcp__geo__lookup", {"country": {"code": "US"}}),
    ("mcp__terminal__read_terminal", {"lines": 200}),
    ("mcp__terminal__list_terminal_tabs", {}),
    ("mcp__slack__send_message", {"channel": "c1", "text": "hello"}),
    ("mcp__y__runner", {"script": "ls"}),
])
def test_ordinary_tools_work(strict, tool, inp):
    _servers(strict, {"shop": BARE, "docs": BARE, "geo": BARE, "terminal": BARE, "slack": BARE})
    code, err = _hook(strict, tool, inp)
    assert code == 0, (tool, err)


@pytest.mark.parametrize("tool,inp", [
    ("run_in_terminal", {"command": "phiward run -- wc -l README.md", "explanation": "count",
                         "isBackground": False}),
    ("mcp__x__run_command", {"command": "phiward doctor", "description": "d", "timeout": 30}),
    ("mcp__x__run_command", {"argv": ["phiward", "doctor"]}),
])
def test_one_whole_gateway_call_in_the_exact_form_is_allowed(strict, tool, inp):
    _servers(strict, {"x": BARE})
    code, err = _hook(strict, tool, inp)
    assert code == 0, (tool, err)


def test_the_hooks_own_folder_is_a_harmless_cwd(strict):
    _servers(strict, {"x": BARE})
    code, err = _hook(strict, "mcp__x__run_command",
                      {"command": "phiward doctor", "cwd": str(strict / "repo")})
    assert code == 0, err


def test_a_shell_tool_of_a_wrapped_server_runs(strict):
    _servers(strict, {"term": WRAPPED})
    code, err = _hook(strict, "mcp__term__run_command", {"command": "ls -la", "shell": "bash"})
    assert code == 0, err
    code, err = _hook(strict, "mcp__term__run_command", {"command": f"cat {strict}/phi/f"})
    assert code == 2, err  # still the text check


def test_a_project_server_can_be_the_wrapped_one(strict):
    # only when Claude Code says the tool is that server's (`mcp_server.source`): without it, a
    # server of the app's own may have the same name (test_v2_mcp_source)
    _servers(strict, {"term": WRAPPED}, where="project")
    code, err = _hook(strict, "mcp__term__execute_command", {"command": "ls"},
                      server={"name": "term", "source": "project"})
    assert code == 0, err
    assert _hook(strict, "mcp__term__execute_command", {"command": "ls"})[0] == 2


def test_best_effort_gives_a_bad_shape_the_text_check(tree):
    protect(tree, [], best_effort=True)
    _servers(tree, {"x": BARE})
    assert _hook(tree, "mcp__x__run_command", {"command": "ls", "env": {"A": "1"}})[0] == 0
    code, _ = _hook(tree, "mcp__x__run_command",
                    {"command": "ls", "env": {"A": f"{tree}/phi/FAKE-PT-0001.bam"}})
    assert code == 2


# --- the mapping from a tool to its server ---------------------------------------------------------

def test_wrapped_and_bare_servers_are_told_apart(tree):
    _servers(tree, {"a": WRAPPED, "b": BARE, "r": {"type": "http", "url": "https://x.invalid"},
                    "o": {"command": PHIWARD, "args": ["launch", "--tool", "x", "--entry",
                                                       "00000000000000e1", "--", "srv"]}})
    s = mcp_config.servers(str(tree / "repo"), str(tree / "home"))
    # round 4: a wrapped entry takes only `--entry ID` before `--` (no `--tool`, `--memory`,
    # `--report`): one with options is not wrapped, and `wrap` drops them
    assert s["a"].wrapped and not s["b"].wrapped and s["r"].remote and not s["o"].wrapped


def test_a_tool_maps_to_its_server(tree):
    _servers(tree, {"term": WRAPPED, "my.srv": BARE})
    home, repo = str(tree / "home"), str(tree / "repo")
    assert mcp_config.server_of("mcp__term__run_command", repo, home).name == "term"
    assert mcp_config.server_of("mcp__my_srv__x", repo, home).name == "my.srv"
    assert mcp_config.server_of("mcp__plugin_p_s__x", repo, home) is None
    assert mcp_config.server_of("mcp__nope__x", repo, home) is None


def test_a_wrapper_in_another_form_counts_as_bare(tree):
    _servers(tree, {"w": {"command": "sh", "args": ["-c", "exec phiward launch -- srv"]}})
    assert not mcp_config.servers(str(tree / "repo"), str(tree / "home"))["w"].wrapped


# --- the config the mapping trusts cannot be written by the agent -----------------------------------

def test_a_file_tool_cannot_write_the_user_mcp_config(tree):
    cfg = protect(tree, [], best_effort=False)
    d = protected_paths.check(Action(FILE_WRITE, str(tree / "repo"),
                                     paths=(str(tree / "home" / ".claude.json"),), tool="Write"),
                              cfg)
    assert d.verdict == DENY


def test_classification(strict):
    _servers(strict, {"x": BARE, "w": WRAPPED})

    def kind(tool, inp):
        return claude.to_action({"tool_name": tool, "cwd": str(strict / "repo"),
                                 "session_id": "f", "tool_input": inp})[0].kind
    assert kind("mcp__x__run_command", {"command": "ls"}) == SHELL
    assert kind("mcp__w__run_command", {"command": "ls"}) == OTHER
    assert kind("mcp__x__query", {"code": "x"}) == OTHER
    assert kind("SlashCommand", {"command": "/review"}) == OTHER


# --- reading the config as Claude Code does (review of d8e6b43, items 2-6) --------------------------

def _s(tree):
    return mcp_config.servers(str(tree / "repo"), str(tree / "home"))


@pytest.mark.parametrize("spec", [{"command": "bash-mcp", "url": "x"},
                                  {"type": "stdio", "command": "bash-mcp", "url": "x"}])
def test_a_stray_url_does_not_make_a_local_server_remote(tree, spec):
    _servers(tree, {"srv": spec})
    s = _s(tree)["srv"]
    assert not s.remote and not s.wrapped


def test_a_remote_server_stays_remote(tree):
    _servers(tree, {"r": {"type": "http", "url": "https://x.invalid"},
                    "e": {"type": "sse", "url": "https://x.invalid"}})
    assert _s(tree)["r"].remote and _s(tree)["e"].remote


def test_a_wrapped_prefix_does_not_claim_another_servers_tools(tree):
    _servers(tree, {"Terminal": WRAPPED})
    home, repo = str(tree / "home"), str(tree / "repo")
    assert mcp_config.server_of("mcp__Terminal__Other_Name___run_command", repo, home) is None
    assert mcp_config.server_of("mcp__Terminal__run_command", repo, home).wrapped


def test_claude_config_dir_is_where_claude_code_reads(tree, monkeypatch):
    conf = tree / "cc"
    conf.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(conf))
    (conf / ".claude.json").write_text(json.dumps({"mcpServers": {"srv": BARE}}))
    _servers(tree, {"srv": WRAPPED})  # ~/.claude.json, not read by Claude Code now
    assert not _s(tree)["srv"].wrapped
    assert mcp_config.user_file(str(tree / "home")) == str(conf / ".claude.json")


@pytest.mark.parametrize("extra", [{"env": {"PATH": "/tmp/x"}}, {"env": {"PHIWARD_CONFIG": "/x"}},
                                   {"env": {"PYTHONPATH": "/x"}}, {"env": {"HOME": "/x"}},
                                   {"env": {"XDG_CONFIG_HOME": "/x"}}, {"cwd": "/tmp"}])
def test_a_wrapped_entry_that_changes_what_runs_counts_as_bare(tree, extra):
    _servers(tree, {"srv": dict(WRAPPED, **extra)})
    assert not _s(tree)["srv"].wrapped


def test_an_ordinary_env_key_keeps_it_wrapped(tree):
    _servers(tree, {"srv": dict(WRAPPED, env={"API_TOKEN_FILE": "/x"})})
    assert _s(tree)["srv"].wrapped


def test_a_project_key_spelled_another_way_is_read(tree):
    (tree / "home" / ".claude.json").write_text(json.dumps({
        "mcpServers": {"srv": WRAPPED},
        "projects": {str(tree / "repo") + "/": {"mcpServers": {"srv": BARE}}}}))
    assert not _s(tree)["srv"].wrapped


def test_duplicate_keys_make_the_servers_bare(tree):
    (tree / "home" / ".claude.json").write_text(
        '{"mcpServers": {"srv": ' + json.dumps(BARE) + ', "srv": ' + json.dumps(WRAPPED) + '}}')
    assert not _s(tree)["srv"].wrapped


def test_a_command_path_with_a_space_is_kept_whole(tree):
    app = tree / "My App"
    app.mkdir()
    (app / "srv").write_text("#!/bin/sh\n")
    assert mcp_config._command({"command": str(app / "srv")}) == [str(app / "srv")]
    assert mcp_config._command({"command": "npx -y srv"}) == ["npx", "-y", "srv"]
    assert mcp_config._command({"command": "my srv", "args": ["a"]}) == ["my srv", "a"]


# --- the name rule (review of d8e6b43, items 7, 8, 9, 11) ------------------------------------------

@pytest.mark.parametrize("tool,inp", [
    ("mcp__x__run_python", {"code": "print(1)"}),
    ("mcp__x__run_code", {"code": "print(1)"}),
    ("mcp__x__interact_with_process", {"pid": 1, "input": "ls"}),
    ("mcp__x__browser_run_code", {"code": "1"}),
    ("mcp__x__send_keys", {"keys": "ls"}),
    ("mcp__x__python_repl", {"code": "1"}),
    ("mcp__x__run_applescript", {"script": "x"}),
    ("mcp__x__list_and_execute", {"items": []}),
    ("mcp__x__create_process", {"argv": ["ls"]}),
    ("mcp__x__invoke_command", {"command": "ls"}),
])
def test_more_command_runners_are_shells(strict, tool, inp):
    _servers(strict, {"x": BARE})
    code, err = _hook(strict, tool, inp)
    assert code == 2 and REFUSED in err, (tool, err)


@pytest.mark.parametrize("tool,inp", [
    ("mcp__db__execute_sql", {"query": "select 1"}),  # a remote server (below)
    ("mcp__db__run_query", {"sql": "select 1"}),
    ("mcp__jira__executeJql", {"jql": "project = X"}),
    ("mcp__chrome__execute_javascript", {"tab": 1, "code": "1+1"}),
    ("mcp__terminal__search_shell_history", {"q": "x"}),
    ("mcp__terminal__get_terminal_output", {"id": 1}),
    ("mcp__terminal__open_terminal_tab", {"cwd": "/somewhere"}),
])
def test_tools_that_run_elsewhere_or_nothing_work(strict, tool, inp):
    remote = {"type": "http", "url": "https://x.invalid"}
    _servers(strict, {"db": remote, "jira": remote, "chrome": BARE, "terminal": BARE})
    code, err = _hook(strict, tool, inp)
    assert code == 0, (tool, err)


def test_open_terminal_tab_with_a_command_is_a_shell(strict):
    _servers(strict, {"terminal": BARE})
    code, err = _hook(strict, "mcp__terminal__open_terminal_tab", {"command": "ls"})
    assert code == 2 and REFUSED in err, err


@pytest.mark.parametrize("inp", [
    {"command": "phiward doctor", "timeout": "30"},
    {"command": "phiward doctor", "timeout": True},
    {"command": "phiward doctor", "isBackground": "yes"},
    {"command": "phiward doctor", "description": 5},
])
def test_harmless_fields_must_have_their_type(strict, inp):
    _servers(strict, {"x": BARE})
    assert _hook(strict, "mcp__x__run_command", inp)[0] == 2


def test_the_refusal_says_what_to_do_for_each_kind_of_server(strict):
    _servers(strict, {"x": BARE})
    _, err = _hook(strict, "mcp__x__run_command", {"command": "ls"})
    assert "phiward mcp wrap x" in err, err
    _, err = _hook(strict, "mcp__plugin_p_s__run_command", {"command": "ls"})
    assert "cannot see" in err and "Bash" in err, err
    _, err = _hook(strict, "run_in_terminal", {"command": "ls"}, copilot=True)
    assert "gateway" in err and "mcp wrap" not in err, err


# --- the text check: percent-encoding and links (older gaps) ----------------------------------------

def test_a_percent_encoded_file_url_is_checked(strict):
    from urllib.parse import quote
    url = "file://" + quote(str(strict / "phi" / "FAKE-PT-0001.bam"), safe="")
    code, _ = _hook(strict, "mcp__b__navigate_page", {"url": url})
    assert code == 2
    assert _hook(strict, "mcp__b__navigate_page", {"url": "https://example.org/a%20b"})[0] == 0


def test_a_path_through_a_link_into_a_root_is_checked(strict):
    # the tree's repo/leak.txt links to phi/FAKE-PT-0001.bam
    for p in ("leak.txt", str(strict / "repo" / "leak.txt")):
        code, _ = _hook(strict, "mcp__fs__read_file", {"path": p})
        assert code == 2, p
    assert _hook(strict, "mcp__fs__read_file", {"path": "README.md"})[0] == 0


def test_a_huge_string_is_not_resolved(strict):
    import time
    t = time.time()
    assert _hook(strict, "mcp__fs__write_note", {"text": "x" * (10 * 1024 * 1024)})[0] == 0
    assert time.time() - t < 30


@pytest.mark.parametrize("inp", [
    {"command": "phiward run -- true \\\nwhoami"},
    {"command": "phiward doctor\rwhoami"},
    {"command": "phiward doctor\x00x"},
    {"argv": ["phiward", "check", "--", "x\nwhoami"]},
])
def test_a_control_character_inside_the_command_is_the_wrong_shape(strict, inp):
    _servers(strict, {"x": BARE})
    code, err = _hook(strict, "mcp__x__run_command", inp)
    assert code == 2, (inp, err)


def test_one_trailing_newline_is_fine(strict):
    _servers(strict, {"x": BARE})
    assert _hook(strict, "mcp__x__run_command", {"command": "phiward doctor\n"})[0] == 0


# --- the review of cc00293: regressions undone ------------------------------------------------------

def test_a_plain_word_that_names_a_folder_is_not_a_path(tree):
    from pathlib import Path
    (tree / "repo" / "data").mkdir()
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/repo/data"]\n')
    _servers(tree, {"slack": BARE})
    for tool, inp in (("mcp__slack__send_message", {"text": "data"}),
                      ("mcp__jira__search", {"query": "data"}), ("WebSearch", {"query": "data"})):
        assert _hook(tree, tool, inp)[0] == 0, tool
    assert _hook(tree, "mcp__slack__send_message", {"text": "./data/x"})[0] == 2


def test_the_path_check_takes_the_stripped_form_and_a_new_file_in_a_linked_folder(strict):
    (strict / "repo" / "lnk").symlink_to(strict / "phi")
    _servers(strict, {"fs": BARE})
    assert _hook(strict, "mcp__fs__read_file", {"path": "leak.txt "})[0] == 2
    assert _hook(strict, "mcp__fs__write_file", {"path": "lnk/new.txt", "content": "x"})[0] == 2


def test_the_path_check_also_resolves_from_the_project_folder(strict, monkeypatch):
    (strict / "repo" / "sub").mkdir()
    _servers(strict, {"fs": BARE})
    p = {"session_id": "f", "hook_event_name": "PreToolUse", "cwd": str(strict / "repo" / "sub"),
         "permission_mode": "default", "tool_name": "mcp__fs__read_file",
         "tool_input": {"path": "leak.txt"}}
    err = io.StringIO()
    assert claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err) == 2, err.getvalue()


def test_a_local_query_runner_is_a_shell_and_a_remote_one_is_not(strict):
    _servers(strict, {"pg": BARE, "cloud": {"type": "http", "url": "https://x.invalid"}})
    assert _hook(strict, "mcp__pg__execute_sql", {"sql": "select 1"})[0] == 2
    assert _hook(strict, "mcp__cloud__execute_sql", {"sql": "select 1"})[0] == 0


@pytest.mark.parametrize("tool,inp", [
    ("mcp__t__type_in_terminal", {"text": "ls"}),
    ("mcp__t__paste_to_terminal", {"text": "ls"}),
    ("mcp__t__open_terminal", {"initial_command": "ls"}),
    ("mcp__node__execute_javascript", {"code": "1", "tab": 1}),
])
def test_input_fields_do_not_turn_a_runner_into_a_reader(strict, tool, inp):
    _servers(strict, {"t": BARE, "node": BARE})
    assert _hook(strict, tool, inp)[0] == 2, tool


def test_a_terminal_tool_with_only_harmless_fields_and_a_browser_server_still_work(strict):
    _servers(strict, {"terminal": BARE, "Control_Chrome": BARE})
    assert _hook(strict, "mcp__terminal__open_terminal_tab", {"cwd": str(strict / "repo"),
                                                               "title": "t"})[0] == 0
    assert _hook(strict, "mcp__Control_Chrome__execute_javascript", {"code": "1"})[0] == 0


@pytest.mark.parametrize("cmd", ["phiward doctor\x85whoami", "phiward doctor whoami"])
def test_unicode_line_breaks_are_control_characters(strict, cmd):
    _servers(strict, {"x": BARE})
    assert _hook(strict, "mcp__x__run_command", {"command": cmd})[0] == 2


# --- the guard files through other tools, and what changes a wrapped server ------------------------

def test_an_mcp_tool_cannot_name_the_files_that_control_the_guards(strict):
    from phiward import config
    _servers(strict, {"fs": BARE})
    for p in (os.environ["PHIWARD_CONFIG"], str(strict / "home" / ".claude" / "settings.json"),
              os.path.join(mcp_config.launched_dir(), "x.json"),
              str(strict / "repo" / ".claude" / "settings.local.json")):
        code, err = _hook(strict, "mcp__fs__write_file", {"path": p, "content": "{}"})
        assert code == 2, (p, err)
    assert config  # imported for the guard list
    assert _hook(strict, "mcp__fs__write_file", {"path": "notes.md", "content": "x"})[0] == 0


@pytest.mark.parametrize("extra", [{"env": {"OPENSSL_CONF": "/x"}}, {"env": {"GCONV_PATH": "/x"}},
                                   {"env": {"__PYVENV_LAUNCHER__": "/x"}},
                                   {"env": {"MALLOC_CONF": "x"}}])
def test_more_variables_change_what_a_wrapped_server_runs(tree, extra):
    _servers(tree, {"srv": dict(WRAPPED, **extra)})
    assert not mcp_config.servers(str(tree / "repo"), str(tree / "home"))["srv"].wrapped


def test_args_that_are_not_a_list_count_as_bare(tree):
    _servers(tree, {"srv": {"command": "phiward", "args": {"0": "launch", "1": "--", "2": "x"}}})
    assert not mcp_config.servers(str(tree / "repo"), str(tree / "home"))["srv"].wrapped


# --- round 18 (MC-M4): a launcher whose profile differs from the hook's vouches for nothing ------

def test_a_launcher_built_from_other_settings_does_not_vouch(strict, monkeypatch):
    real = _L.start
    monkeypatch.setattr(_L, "start", lambda h, **k: real(h, view="0" * 64, **k))
    _servers(strict, {"term": WRAPPED})
    code, err = _hook(strict, "mcp__term__run_command", {"command": "ls -la"})
    assert code == 2, err
    assert "other settings" in err, err
