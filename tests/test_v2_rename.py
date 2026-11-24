"""The rename from agent-guards to phiward (v0.2.0b1): the old program name is an alias, so every
check that looks for the program covers both; the old config files are refused, never ignored."""

import os

import pytest

from phiward import config, gateway, hidden


@pytest.mark.parametrize("cmd", [
    "agent-guards setup", "/opt/bin/agent-guards carryover accept 1", "python -m agent_guards pin",
    "phiward setup", "x; agent-guards pin add /p",
])
def test_operator_commands_are_found_under_both_names(cmd):
    assert gateway.is_operator_command(cmd)


def test_only_the_new_name_is_a_gateway_call():
    assert gateway.parse_call("phiward run -- wc -l f") is not None
    # the old name is not a gateway call: it is judged like any command (fails closed)
    assert gateway.parse_call("agent-guards run -- wc -l f") is None


def test_an_old_repo_config_is_refused(tree):
    (tree / "repo" / ".agent-guards.toml").write_text('[paths]\nroots = ["/x"]\n')
    cfg = config.load(str(tree / "repo"))
    assert ".phiward.toml" in cfg.problem


def test_an_old_user_config_is_refused(tree, monkeypatch):
    xdg = tree / "xdg"
    (xdg / "agent-guards").mkdir(parents=True)
    (xdg / "agent-guards" / "config.toml").write_text("")
    env = dict(os.environ, XDG_CONFIG_HOME=str(xdg))
    env.pop("PHIWARD_CONFIG", None)
    cfg = config.load(str(tree / "repo"), env)
    assert "~/.config/phiward" in cfg.problem


def test_sessions_cannot_read_the_old_state_folder():
    assert ".agent-guards" in hidden.CREDENTIALS


def test_the_alias_launcher_is_a_guard_file(tree):
    bin_ = tree / "bin"
    bin_.mkdir()
    for n in ("phiward", "agent-guards"):
        (bin_ / n).write_text("#!/bin/sh\n")
        os.chmod(bin_ / n, 0o755)
    files = config.guard_files(dict(os.environ, PATH=str(bin_)))
    assert str(bin_ / "agent-guards") in files and str(bin_ / "phiward") in files
