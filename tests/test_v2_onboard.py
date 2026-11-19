"""Easy onboarding. `setup --first-run`, the broker the operator's once phiward is
set up, `phiward init`, and `phiward mcp` (the gateway as MCP tools)."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import config
from phiward.core import DENY, OTHER, SHELL, Action
from phiward.guards import protected_paths
from helpers import needs_confine

ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / "src")


def ph(args, cwd, env=None, stdin=None):
    return subprocess.run([sys.executable, "-m", "phiward"] + args, cwd=str(cwd),
                          capture_output=True, text=True, input=stdin,
                          env=dict(env or os.environ, PYTHONPATH=SRC))


# --- setup --first-run ---------------------------------------------------------------------------

def test_first_run_writes_roots_and_remotes_only(tree, monkeypatch):
    env = {k: v for k, v in os.environ.items() if k not in ("PHIWARD_CONFIG", "PHIWARD_SPOOL")}
    env["HOME"] = str(tree / "home")
    cfg = tree / "home" / ".config" / "phiward" / "config.toml"
    r = ph(["setup", "--first-run", "--root", str(tree / "phi"), "--remote", "hpc:/work/me"],
           tree / "home", env=env)
    assert r.returncode == 0, r.stderr
    text = cfg.read_text()
    assert str(tree / "phi") in text and "hpc:/work/me" in text
    assert "write_to" not in text and "net" not in text
    # a push lands only under [remote] roots: the remote's folder is one (masking, not a grant)
    from phiward import config
    c = config.load(str(tree / "repo"), env=dict(env, PHIWARD_CONFIG=str(cfg)))
    assert c.remote_roots == ["/work/me"], text


def test_first_run_refuses_when_a_config_exists(tree):
    from conftest import default_place_env
    r = ph(["setup", "--first-run", "--root", str(tree / "phi")], tree / "home",
           env=default_place_env(tree))
    assert r.returncode == 2 and "exists already" in r.stderr


def test_first_run_needs_a_root_and_checks_it(tree, monkeypatch):
    env = {k: v for k, v in os.environ.items() if k not in ("PHIWARD_CONFIG", "PHIWARD_SPOOL")}
    env["HOME"] = str(tree / "home")
    assert ph(["setup", "--first-run"], tree / "home", env=env).returncode == 2
    assert ph(["setup", "--first-run", "--root", "relative/x"], tree / "home",
              env=env).returncode == 2
    assert not (tree / "home" / ".config" / "phiward" / "config.toml").exists()


def test_first_run_refuses_an_override_without_a_terminal(tree, monkeypatch):
    monkeypatch.setenv("PHIWARD_CONFIG", str(tree / "home" / "agent.toml"))
    r = ph(["setup", "--first-run", "--root", str(tree / "phi")], tree / "home")
    assert r.returncode == 2 and "PHIWARD_CONFIG" in r.stderr


@pytest.mark.parametrize("cmd", ["phiward setup --first-run --root /x", "phiward broker",
                                 "phiward broker --service --write", "phiward pin",
                                 "phiward carryover accept 1"])
def test_once_set_up_the_operator_commands_are_refused_to_the_agent(tree, cmd):
    cfg = config.load(str(tree / "repo"))
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command=cmd), cfg)
    assert d.verdict == DENY and "operator" in d.reason


def test_the_service_refuses_a_config_override_without_a_terminal(tree, monkeypatch):
    monkeypatch.setenv("PHIWARD_CONFIG", str(tree / "agent.toml"))
    r = ph(["broker", "--service", "--write"], tree / "home", stdin="")
    assert r.returncode == 2 and "PHIWARD_CONFIG" in r.stderr


# --- phiward init -------------------------------------------------------------------------------

def test_init_sets_a_project_up_and_only_adds(tree):
    proj = tree / "repo"
    subprocess.run(["git", "init", "-q"], cwd=str(proj), check=True)
    (proj / "AGENTS.md").write_text("# Project rules\n\nBe kind.\n")
    (proj / "data").mkdir()
    from conftest import default_place_env
    env = default_place_env(tree)
    r = ph(["init", "--root", "data"], proj, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    agents = (proj / "AGENTS.md").read_text()
    assert agents.startswith("# Project rules") and "## Protected data (phiward)" in agents
    assert str(proj / "data") in (proj / ".phiward.toml").read_text()
    assert ".claude/settings.local.json" in (proj / ".gitignore").read_text().splitlines()
    shared = json.loads((proj / ".claude" / "settings.json").read_text())
    assert shared["hooks"]["PreToolUse"] == []  # --no-hooks: the user wiring carries them
    assert "./data" in shared["sandbox"]["filesystem"]["denyRead"]
    assert (proj / ".git" / "hooks" / "pre-commit").exists()
    again = ph(["init"], proj, env=env)
    assert again.returncode == 0
    assert (proj / "AGENTS.md").read_text().count("## Protected data (phiward)") == 1
    assert (proj / ".gitignore").read_text().count(".claude/settings.local.json") == 1


def test_init_refuses_the_home_folder(tree):
    assert ph(["init"], tree / "home").returncode == 2


def test_the_bundled_rules_template_holds_the_rules():
    # the template `phiward init` adds to other projects; this repository's own AGENTS.md is a
    # contributor guide and is not compared with it
    text = (ROOT / "src" / "phiward" / "data" / "agents-section.md").read_text()
    assert text.startswith("## Protected data (phiward)\n")
    for rule in ("phiward run --", "phiward copy", "phiward check --", "--remote HOST"):
        assert rule in text, rule


# --- phiward mcp --------------------------------------------------------------------------------

def mcp(tree, msgs):
    lines = "".join(json.dumps(m) + "\n" for m in msgs)
    r = ph(["mcp"], tree / "repo", stdin=lines)
    return [json.loads(x) for x in r.stdout.splitlines() if x.strip()]


def test_the_mcp_server_lists_the_gateway_tools(tree):
    out = mcp(tree, [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                     {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
    assert out[0]["result"]["serverInfo"]["name"] == "phiward"
    names = {t["name"] for t in out[1]["result"]["tools"]}
    assert names == {"phiward_run", "phiward_copy", "phiward_remote", "phiward_check",
                     "phiward_doctor"}


def test_the_mcp_check_tool_gives_the_guards_decision(tree):
    out = mcp(tree, [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "phiward_check", "arguments": {"command": f"cat {tree}/phi/FAKE-PT-0001.bam"}}}])
    assert out[0]["result"]["content"][0]["text"].startswith("deny")


def test_the_mcp_run_tool_without_a_broker_says_so(tree, monkeypatch):
    monkeypatch.setenv("PHIWARD_SPOOL", str(tree / "no-spool"))
    out = mcp(tree, [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "phiward_run", "arguments": {"command": ["wc", "-l", "README.md"]}}}])
    res = out[0]["result"]
    assert res["isError"] and "broker" in res["content"][0]["text"]


@needs_confine
def test_the_mcp_run_tool_masks_through_the_broker(tree, broker):
    out = mcp(tree, [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "phiward_run",
        "arguments": {"command": ["wc", "-l", str(tree / "phi" / "FAKE-PT-0001.bam")]}}}])
    text = out[0]["result"]["content"][0]["text"]
    assert "FAKE-PT-0001" not in text and "run done: exit=0" in text, text


def test_the_hook_lets_phiwards_own_mcp_tools_pass_and_checks_others(tree):
    from phiward.adapters import claude
    cfg = config.load(str(tree / "repo"))
    path = f"{tree}/phi/FAKE-PT-0001.bam"
    for name in ("mcp__plugin_phiward_phiward__phiward_run", "mcp__phiward__phiward_copy"):
        action, _ = claude.to_action({"tool_name": name, "cwd": str(tree / "repo"),
                                      "tool_input": {"command": ["wc", path]}})
        assert protected_paths.check(action, cfg).verdict != DENY, name
    action, _ = claude.to_action({"tool_name": "mcp__other__read", "cwd": str(tree / "repo"),
                                  "tool_input": {"path": path}})
    assert action.kind == OTHER and protected_paths.check(action, cfg).verdict == DENY


# --- onboarding fixes -----------------------------------------------------------------------------

def test_a_planted_link_as_the_brokers_reply_shows_nothing(tree, monkeypatch):
    # H1: the MCP server's client runs outside the sandbox; a link planted as out-<id>.log
    # must not make it read the target
    import threading
    import time
    from phiward import broker
    spool = tree / "spool"
    spool.mkdir(mode=0o700)
    monkeypatch.setenv("PHIWARD_SPOOL", str(spool))
    monkeypatch.setenv("PHIWARD_BROKER_WAIT", "5")
    secret = tree / "phi" / "FAKE-PT-0001.bam"

    def plant():
        for _ in range(200):
            (spool / "broker.alive").touch()
            reqs = list(spool.glob("req-*.json"))
            if reqs:
                rid = reqs[0].name[4:-5]
                os.symlink(secret, spool / f"out-{rid}.log")
                (spool / f"done-{rid}.json").write_text('{"exit": 0}')
                return
            time.sleep(0.02)

    (spool / "broker.alive").touch()
    t = threading.Thread(target=plant)
    t.start()
    out = io.StringIO()
    code = broker.client("run", ["--", "true"], out)
    t.join()
    assert "SECRET" not in out.getvalue() and code == 3, out.getvalue()


def test_init_refuses_a_claude_folder_that_is_a_link(tree):
    from conftest import default_place_env
    proj = tree / "repo"
    elsewhere = tree / "pub" / "claude-elsewhere"
    elsewhere.mkdir(parents=True)
    os.symlink(elsewhere, proj / ".claude")
    r = ph(["init"], proj, env=default_place_env(tree))
    assert "not written" in r.stdout and not (elsewhere / "settings.json").exists(), r.stdout


def test_install_refuses_an_agent_chosen_spool(tree, monkeypatch):
    monkeypatch.setenv("PHIWARD_SPOOL", str(tree / "home" / "Library" / "LaunchAgents"))
    r = ph(["install", "claude", "--project", "--write", "--yes"], tree / "repo", stdin="")
    assert r.returncode == 2 and "PHIWARD_SPOOL" in r.stderr


def test_the_service_refuses_an_xdg_override(tree, monkeypatch):
    monkeypatch.delenv("PHIWARD_CONFIG", raising=False)
    monkeypatch.delenv("PHIWARD_SPOOL", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tree / "agentcfg"))
    r = ph(["broker", "--service", "--write"], tree / "home", stdin="")
    assert r.returncode == 2 and "XDG_CONFIG_HOME" in r.stderr


def test_before_a_config_credentials_are_still_refused(tree, monkeypatch):
    # B2: the guided setup runs before a config exists
    empty = tree / "home" / "empty.toml"
    empty.write_text("")
    monkeypatch.setenv("PHIWARD_CONFIG", str(empty))
    (tree / "home" / ".ssh").mkdir()
    (tree / "home" / ".ssh" / "id_x").write_text("k")
    cfg = config.load(str(tree / "repo"))
    assert not cfg.has_protected_paths
    from phiward.core import FILE_READ
    for a in (Action(FILE_READ, str(tree / "repo"), paths=[str(tree / "home" / ".ssh" / "id_x")]),
              Action(SHELL, str(tree / "repo"), command="cat ~/.ssh/id_x")):
        assert protected_paths.check(a, cfg).verdict == DENY
    ok = Action(SHELL, str(tree / "home"), command="cd ~ && phiward install claude --user --write")
    assert protected_paths.check(ok, cfg).verdict != DENY


@pytest.mark.parametrize("cmd", ["sh -c 'phiward broker --service --write'", "p=phiward; $p broker",
                                 "echo broker | xargs phiward", "python3 -m phiward setup"])
def test_operator_commands_in_other_spellings_are_refused(tree, cmd):
    cfg = config.load(str(tree / "repo"))
    assert protected_paths.check(Action(SHELL, str(tree / "repo"), command=cmd), cfg).verdict == DENY


def test_a_gateway_call_that_mentions_an_operator_word_is_not_refused(tree):
    cfg = config.load(str(tree / "repo"))
    cmd = "phiward run -- grep -c setup README.md"
    assert protected_paths.check(Action(SHELL, str(tree / "repo"), command=cmd), cfg).verdict != DENY


def test_writes_to_the_mcp_config_are_refused(tree):
    from phiward.core import FILE_WRITE
    cfg = config.load(str(tree / "repo"))
    assert protected_paths.check(Action(FILE_WRITE, str(tree / "repo"),
                                        paths=[str(tree / "repo" / ".mcp.json")]), cfg).verdict == DENY
    assert protected_paths.check(Action(SHELL, str(tree / "repo"), command="echo '{}' > .mcp.json",
                                        confined=True), cfg).verdict == DENY
