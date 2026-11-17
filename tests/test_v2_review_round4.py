"""What the review of fcc0f44 found, closed (part 1). A "remote" MCP server counts as remote only
when its URL surely names another machine, read the strict way (Claude Code parses URLs with
Node's WHATWG parser, which turns `\\` into `/`, decodes `%31`, maps full-width digits and reads
`0177.1` as octal); a web address in a tool's input still goes through the link check (only the
guard-file check skips it); `phiward mcp wrap` leaves a server that listens on this machine
alone and says it cannot be wrapped. Made-up trees only."""

import io
import json
import os
import shutil
import socket
import subprocess
import sys

import pytest

from phiward import mcp_config
from phiward.adapters import claude
from helpers import Tty, protect

RUN = {"command": "id"}
ME = socket.gethostname().split(".")[0]

# Each of these is this machine to Node's URL parser (or not a URL it accepts at all)
LOCAL = [
    "http://127.0.0.1:8123/mcp", "http://localhost/", "HTTP://LOCALHOST./", "http://[::1]/",
    "http://127.1/", "http://0177.1/", "http://0x7f.1/", "http://2130706433/", "http://0/",
    "http://127.000.000.001/", "http://127.0.0.1.:1/", "http://0.0.0.0/", "http://ide.localhost/",
    "http://169.254.1.2/", "http://[fe80::1]/", "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/", "http://[::]/", "http://[::127.0.0.1]/",
    f"http://{ME}/", f"http://{ME}.local/",
    # spellings Python and Node read differently
    "http://127.0.0.1\\@example.com:8123/mcp", "http://%31%32%37.0.0.1:8123/mcp",
    "http://１２７.０.０.１:8123/mcp", "http://localhost。:8123/mcp",
    "http://localhost%2e:8123/mcp", "http://ｌｏｃａｌｈｏｓｔ/",
    "http://①②⑦.0.0.1/", "http:127.0.0.1/", "http:/127.0.0.1/",
    "http:\\\\127.0.0.1/", "  http://127.0.0.1/", "http://\t127.0.0.1/", "http://127.0.0.1\n/",
    "http://user:pw@127.0.0.1/", "http://ex%41mple.com/",
    # not a URL phiward reads strictly: local too
    "http://", "http://[::1", "not a url", "", "ftp://example.com/", "http://exa mple.com/",
    "http://256.256.256.256/", "http://1.2.3.4.5/", "http://example..com/",
]
REMOTE = ["https://mcp.example.com/x", "https://10.1.2.3/mcp", "http://8.8.8.8:80/",
          "https://xn--nxasmq6b.com/", "wss://mcp.example.com/ws?x=1#y", "http://[2001:db8::1]/",
          "https://mcp.example.com", "http://127.0.0.1.example.com/"]


@pytest.mark.parametrize("url", LOCAL)
def test_a_url_that_may_be_this_machine_is_not_remote(url):
    assert not mcp_config._is_remote({"type": "http", "url": url})


@pytest.mark.parametrize("url", REMOTE)
def test_a_url_that_surely_names_another_machine_is_remote(url):
    assert mcp_config._is_remote({"type": "http", "url": url})


def test_names_etc_hosts_maps_to_this_machine_are_local(tmp_path, monkeypatch):
    hosts = tmp_path / "hosts"
    hosts.write_text("# made up\n127.0.0.1   dev-box.example  alias-two\n"
                     "::1 six.example\n10.0.0.9 far.example\n")
    monkeypatch.setattr(mcp_config, "HOSTS_FILE", str(hosts))
    mcp_config._loopback_names.cache_clear()
    try:
        for name in ("dev-box.example", "ALIAS-TWO", "six.example."):
            assert not mcp_config._is_remote({"type": "http", "url": f"http://{name}/"}), name
        assert mcp_config._is_remote({"type": "http", "url": "http://far.example/"})
    finally:
        mcp_config._loopback_names.cache_clear()


_NODE = shutil.which("node")


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
def test_phiward_never_calls_remote_what_node_reads_as_this_machine(tmp_path):
    """Claude Code reads the URL with Node's parser: whenever Node's host is this machine (or
    Node refuses the URL), phiward must not call it remote."""
    cases = LOCAL + REMOTE
    (tmp_path / "cases.json").write_text(json.dumps(cases))
    (tmp_path / "n.js").write_text(
        "const c=require(process.argv[2]);const o={};for(const u of c){try{o[u]=new URL(u)"
        ".hostname}catch(e){o[u]=null}}console.log(JSON.stringify(o))")
    got = json.loads(subprocess.run([_NODE, str(tmp_path / "n.js"), str(tmp_path / "cases.json")],
                                    capture_output=True, text=True, check=True).stdout)
    for url in cases:
        host = got[url]
        here = host is None or not mcp_config._host_elsewhere(host)
        if here:
            assert not mcp_config._is_remote({"type": "http", "url": url}), (url, host)


# --- the hook --------------------------------------------------------------------------------------

@pytest.fixture()
def t(tree, monkeypatch, launchers):
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    protect(tree, [], best_effort=False)
    return tree


def _hook(t, tool, inp, name, source="user"):
    p = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(t / "repo"),
         "permission_mode": "default", "tool_name": tool, "tool_input": inp,
         "mcp_server": {"name": name, "source": source}}
    err = io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err), err.getvalue()


def _user(t, servers):
    (t / "home" / ".claude.json").write_text(json.dumps({"mcpServers": servers}))


@pytest.mark.parametrize("url", ["http://127.0.0.1\\@example.com:8123/mcp",
                                 "http://%31%32%37.0.0.1:8123/mcp",
                                 "http://ｌｏｃａｌｈｏｓｔ/"])
def test_a_local_terminal_in_any_spelling_may_make_only_gateway_calls(t, url):
    _user(t, {"ide": {"type": "http", "url": url}})
    code, err = _hook(t, "mcp__ide__execute_terminal_command", RUN, "ide")
    assert code == 2, err
    assert "phiward mcp wrap" not in err and "this machine" in err
    assert _hook(t, "mcp__ide__execute_terminal_command", {"command": "phiward doctor"},
                 "ide")[0] == 0


def test_a_remote_server_still_works(t):
    _user(t, {"db": {"type": "http", "url": "https://mcp.example.com/x"}})
    assert _hook(t, "mcp__db__execute_sql", {"sql": "select 1"}, "db")[0] == 0


# --- 2. a web address still goes through the link check ---------------------------------------

@pytest.fixture()
def linked(t):
    os.symlink(t, t / "repo" / "https:")
    _user(t, {"srv": {"command": "npx"}})
    return t


@pytest.mark.parametrize("text", ["https://phi/FAKE-PT-0001.bam", "https://repo/leak.txt",
                                  "https:/phi/FAKE-PT-0001.bam", "https://phi/sub/FAKE-PT-0002.bam"])
def test_a_url_through_a_link_named_like_a_scheme_is_refused(linked, text):
    code, err = _hook(linked, "mcp__srv__read_file", {"path": text}, "srv")
    assert code == 2, err


def test_where_a_link_is_named_like_the_scheme_a_url_may_not_name_the_guard_files(linked):
    assert _hook(linked, "mcp__srv__fetch",
                 {"url": "https://github.com/example/repo/blob/main/.mcp.json"}, "srv")[0] == 2


def test_elsewhere_a_url_may_still_name_the_guard_files(t):
    _user(t, {"srv": {"command": "npx"}})
    assert _hook(t, "mcp__srv__fetch",
                 {"url": "https://github.com/example/repo/blob/main/.mcp.json"}, "srv")[0] == 0


# --- 4. `phiward mcp wrap` and a server that listens on this machine -------------------------

@pytest.fixture()
def env(tree, monkeypatch):
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(sys, "stdin", Tty())
    return tree


IDE = {"type": "http", "url": "http://127.0.0.1:8123/mcp"}


@pytest.mark.parametrize("args", [["wrap", "--all", "--yes"], ["wrap", "ide", "--yes"]])
def test_wrap_leaves_a_local_http_server_alone(env, capsys, args):
    p = env / "home" / ".claude.json"
    p.write_text(json.dumps({"mcpServers": {"ide": IDE}}))
    before = p.read_text()
    assert mcp_config.main(args) == 0
    assert p.read_text() == before
    out = capsys.readouterr().out
    assert "ide" in out and "this machine" in out and "cannot be wrapped" in out


def test_list_says_a_local_http_server_cannot_be_wrapped(env, capsys):
    (env / "home" / ".claude.json").write_text(json.dumps({"mcpServers": {"ide": IDE}}))
    assert mcp_config.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "ide" in out and "cannot be wrapped" in out and "phiward mcp wrap" not in out


# --- hardening ----------------------------------------------------------------------------------

def test_a_nul_in_a_place_is_not_the_same_place():
    assert not mcp_config._same_place("/a\0b", "/a")


# --- the review of 786bbdf..49715f2 ------------------------------------------------------------

@pytest.mark.parametrize("text", ["https://repo/.mcp.json", "https://repo/.claude/settings.json",
                                  "http://repo/.mcp.json"])
def test_a_url_through_a_scheme_link_may_not_name_the_guard_files(linked, text):
    if text.startswith("http:"):
        os.symlink(linked, linked / "repo" / "http:")
    code, err = _hook(linked, "mcp__srv__write_file", {"path": text}, "srv")
    assert code == 2, err


@pytest.mark.parametrize("url", ["http://-1.1/", "http://0x-1.1/", "http://08.1/",
                                 "http://0x1g.1/", "http://1.2.3.99999999999999999999/"])
def test_a_host_node_refuses_is_not_remote_and_does_not_crash(url):
    assert not mcp_config._is_remote({"type": "http", "url": url})


def test_a_bad_url_entry_does_not_stop_list_wrap_or_the_hook(env, capsys):
    (env / "repo" / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "odd": {"type": "http", "url": "http://0x-1.1/"}, "ok": {"command": "echo"}}}))
    assert mcp_config.main(["list"]) == 0
    assert mcp_config.main(["wrap", "--all", "--yes"]) == 0
    assert mcp_config.servers(str(env / "repo"), str(env / "home"))["ok"].wrapped


@pytest.mark.parametrize("spec,words", [
    ({"type": "stdio", "command": ""}, "no command"),
    ({"type": "http", "url": ["x"]}, "no command"),
    ({"type": "http", "url": "http://127.0.0.1:1/"}, "this machine"),
])
def test_list_and_wrap_agree_on_entries_that_cannot_be_wrapped(env, capsys, spec, words):
    (env / "home" / ".claude.json").write_text(json.dumps({"mcpServers": {"odd": spec}}))
    assert mcp_config.main(["list"]) == 0
    listed = capsys.readouterr().out
    assert words in listed and "cannot be wrapped" in listed and "phiward mcp wrap" not in listed
    assert mcp_config.main(["wrap", "odd", "--yes"]) == 0
    wrapped = capsys.readouterr().out
    assert words in wrapped and "cannot be wrapped" in wrapped


def test_unwrap_of_an_entry_without_a_command_does_not_talk_of_wrapping(env, capsys):
    (env / "home" / ".claude.json").write_text(json.dumps({"mcpServers": {"odd": {
        "type": "stdio", "command": ""}}}))
    assert mcp_config.main(["unwrap", "odd", "--yes"]) == 0
    assert "cannot be wrapped" not in capsys.readouterr().out


# --- the review of 16745bb ---------------------------------------------------------------------

@pytest.mark.parametrize("text", ["https://../.mcp.json", "https://../.claude/settings.json",
                                  "http://../.mcp.json", "wss://../.mcp.json", "https://./../.mcp.json",
                                  "https://%2e%2e/.mcp.json"])
def test_a_url_whose_host_climbs_may_not_name_the_guard_files(t, text):
    _user(t, {"srv": {"command": "npx"}})
    code, err = _hook(t, "mcp__srv__write_file", {"path": text}, "srv")
    assert code == 2, err


BIG = "http://1." + "9" * 5000 + "/"


@pytest.mark.parametrize("url", [BIG, "http://0x" + "f" * 5000 + "/"])
def test_a_very_long_number_in_a_host_does_not_crash(url):
    assert not mcp_config._is_remote({"type": "http", "url": url})


def test_a_long_run_of_leading_zeros_is_read_as_node_reads_it():
    # Node: `000...01.1` is 1.0.0.1, another machine
    assert mcp_config._is_remote({"type": "http", "url": "http://" + "0" * 5000 + "1.1/"})


def test_a_very_long_number_does_not_stop_list_or_wrap(env):
    (env / "repo" / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "odd": {"type": "http", "url": BIG}, "ok": {"command": "echo"}}}))
    assert mcp_config.main(["list"]) == 0
    assert mcp_config.main(["wrap", "--all", "--yes"]) == 0


def test_leading_zeros_are_read_as_node_reads_them():
    assert not mcp_config._is_remote({"type": "http", "url": "http://" + "0" * 40 + "177.1/"})


def test_a_name_with_a_command_in_one_scope_is_listed_as_wrappable(env, capsys):
    (env / "home" / ".claude.json").write_text(json.dumps({
        "mcpServers": {"odd": {"command": "echo"}},
        "projects": {str(env / "repo"): {"mcpServers": {"odd": {"type": "stdio", "command": ""}}}}}))
    assert mcp_config.main(["list"]) == 0
    assert "phiward mcp wrap odd" in capsys.readouterr().out


def test_an_untrusted_remote_project_server_is_not_called_commandless():
    s = mcp_config.Server("x", False)
    assert not s.unwrappable
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "repo"))
        os.makedirs(os.path.join(d, "home"))
        with open(os.path.join(d, "repo", ".mcp.json"), "w") as fh:
            json.dump({"mcpServers": {"web": {"type": "http", "url": "https://mcp.example.com/"}}}, fh)
        got = mcp_config.servers(os.path.join(d, "repo"), os.path.join(d, "home"),
                                 trust_project=False)["web"]
        assert not got.unwrappable and not got.wrapped


# --- the review of e6e181d ---------------------------------------------------------------------

def test_list_says_which_entry_keeps_a_name_bare(env, capsys):
    (env / "home" / ".claude.json").write_text(json.dumps({"mcpServers": {"x": IDE}}))
    (env / "repo" / ".mcp.json").write_text(json.dumps({"mcpServers": {"x": {"command": "echo"}}}))
    assert mcp_config.main(["wrap", "x", "--yes"]) == 0
    capsys.readouterr()
    assert mcp_config.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "this machine" in out and "cannot be wrapped" in out


def test_without_a_source_a_project_server_gets_advice_about_the_source(t):
    (t / "repo" / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "web": {"type": "http", "url": "https://mcp.example.com/"}}}))
    _user(t, {})
    p = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(t / "repo"),
         "permission_mode": "default", "tool_name": "mcp__web__run_command", "tool_input": RUN}
    err = io.StringIO()
    assert claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err) == 2
    text = err.getvalue()
    assert "phiward mcp wrap" not in text and ".mcp.json" in text
