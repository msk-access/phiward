"""The launcher of a wrapped MCP server is known from phiward's own install record, not from PATH:
the console script the record lists, in a folder the guard list covers. An entry counts as
wrapped only when its command is that file by its full path; `phiward` by name never counts (a
folder on Claude Code's PATH could hold another one when it starts the server). `wrap` writes
that path whatever PATH holds. A source checkout or an editable install has no such record and
keeps the PATH rule (test_v2_launcher_path). Made-up trees only."""

import json
import os
import sys

import pytest

from phiward import config, mcp_config, selfcheck
from helpers import Tty, installed_site

BARE = {"command": "npx", "args": ["-y", "some-server"]}


def _site(tree, scripts=("phiward", "agent-guards"), package=True):
    return installed_site(tree, scripts, package)


def test_the_record_names_the_launcher(tree):
    record, pkg, exe = _site(tree)
    got = selfcheck.launcher_scripts(record, pkg)
    assert os.path.realpath(exe) in got and len(got) == 2


def test_an_editable_record_or_another_package_names_none(tree):
    record, pkg, _exe = _site(tree, package=False)
    assert selfcheck.launcher_scripts(record, pkg) is None
    record2, _pkg2, _ = _site(tree / "other")
    assert selfcheck.launcher_scripts(record2, str(tree / "elsewhere" / "phiward")) is None


@pytest.fixture()
def inst(tree, monkeypatch):
    """phiward installed with a record; PATH holds another `phiward` ahead of it."""
    _record, _pkg, exe = _site(tree)
    monkeypatch.setattr(selfcheck, "launcher_scripts",
                        lambda record=None, package_dir=None: frozenset(
                            {os.path.realpath(exe), os.path.realpath(
                                os.path.join(os.path.dirname(exe), "agent-guards"))}))
    other = tree / "bin"
    other.mkdir()
    (other / "phiward").write_text("#!/bin/sh\n")
    (other / "phiward").chmod(0o755)
    monkeypatch.setenv("PATH", f"{other}:/usr/bin:/bin")
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(sys, "stdin", Tty())
    mcp_config._launcher_exes.cache_clear()
    yield exe
    mcp_config._launcher_exes.cache_clear()


def _spec(cmd, rest=("launch", "--entry", "00000000000000c1", "--", "npx", "-y", "some-server")):
    return {"command": cmd, "args": list(rest)}


def test_only_the_recorded_launcher_by_its_path_counts(inst, tree):
    assert mcp_config.entry_state(_spec(inst)) == "wrapped"
    # another `phiward`, even on a folder phiward would otherwise trust
    assert mcp_config.entry_state(_spec(str(tree / "bin" / "phiward"))) != "wrapped"


def test_phiward_by_name_never_counts(inst):
    assert mcp_config.entry_state(_spec("phiward")) != "wrapped"


def test_wrap_writes_the_recorded_path_whatever_path_holds(inst, tree):
    p = tree / "home" / ".claude.json"
    p.write_text(json.dumps({"mcpServers": {"docs": BARE}}))
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 0
    got = json.loads(p.read_text())["mcpServers"]["docs"]
    assert got["command"] == inst and got["args"][:2] == ["launch", "--entry"]


def test_wrap_works_with_no_phiward_on_path(inst, tree, monkeypatch):
    # a group-writable ~/.local/bin (umask 002) or none at all: the record decides
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    p = tree / "home" / ".claude.json"
    p.write_text(json.dumps({"mcpServers": {"docs": BARE}}))
    assert mcp_config.main(["wrap", "docs", "--yes"]) == 0


def test_list_says_a_launcher_by_name_must_get_its_path(inst, tree, capsys):
    (tree / "repo" / ".mcp.json").write_text(json.dumps({"mcpServers": {"x": _spec("phiward")}}))
    assert mcp_config.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "without its path" in out and "phiward mcp wrap x" in out, out


def test_wrap_gives_a_launcher_by_name_its_path_once(inst, tree):
    p = tree / "repo" / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": {"x": _spec("phiward")}}))
    assert mcp_config.main(["wrap", "x", "--yes"]) == 0
    got = json.loads(p.read_text())["mcpServers"]["x"]
    assert got["command"] == inst and got["args"].count("launch") == 1


def test_a_launch_without_its_program_is_named_and_left_alone(inst, tree, capsys):
    spec = _spec(inst, ("launch", "srv"))
    p = tree / "repo" / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": {"x": spec}}))
    before = p.read_text()
    assert mcp_config.main(["list"]) == 0
    assert "`--` and a program" in capsys.readouterr().out
    assert mcp_config.main(["wrap", "x", "--yes"]) == 0
    assert p.read_text() == before


def test_the_recorded_launcher_is_a_guard_file(inst):
    assert os.path.realpath(inst) in [os.path.realpath(g) for g in config.guard_files()]
