"""`phiward mcp wrap` keeps its backups only in phiward's own guarded folder,
`~/.phiward/backups/<file>-<hash>/`: `original` (the file before phiward first changed it, never
overwritten) and `last` (before the latest change). Nothing is written beside the config file,
so nothing there (a file the agent could plant beside the project's `.mcp.json`) is ever shown
as the operator's original. Made-up trees only."""

import json
import os
import sys

import pytest

from phiward import config, mcp_config
from helpers import Tty

BARE = {"command": "npx", "args": ["-y", "some-server"]}


@pytest.fixture()
def env(tree, monkeypatch):
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(sys, "stdin", Tty())
    mcp_config._launcher_exes.cache_clear()
    return tree


def _folder(env, path):
    return mcp_config.backup_dir(str(path), str(env / "home"))


def _project(env, servers):
    p = env / "repo" / ".mcp.json"
    p.write_text(json.dumps({"mcpServers": servers}, indent=2))
    return p


def test_backups_go_to_phiwards_folder_and_none_beside_the_file(env, capsys):
    p = _project(env, {"a": BARE})
    before = p.read_text()
    assert mcp_config.main(["wrap", "a", "--yes"]) == 0
    out = capsys.readouterr().out
    assert [n for n in os.listdir(env / "repo") if "phiward." in n] == []
    folder = _folder(env, p)
    assert folder.startswith(str(env / "home" / ".phiward" / "backups"))
    assert open(os.path.join(folder, "original")).read() == before
    assert open(os.path.join(folder, "last")).read() == before
    assert os.stat(folder).st_mode & 0o777 == 0o700
    assert "~/.phiward/backups/" in out, out


def test_the_original_is_kept_through_later_wraps(env):
    p = _project(env, {"a": BARE, "b": BARE})
    before = p.read_text()
    assert mcp_config.main(["wrap", "a", "--yes"]) == 0
    middle = p.read_text()
    assert mcp_config.main(["wrap", "b", "--yes"]) == 0
    folder = _folder(env, p)
    assert open(os.path.join(folder, "original")).read() == before
    assert open(os.path.join(folder, "last")).read() == middle


def test_a_file_beside_the_project_file_is_never_shown_as_the_original(env, capsys):
    p = _project(env, {"a": BARE})
    planted = env / "repo" / ".mcp.json.phiward.orig"
    planted.write_text('{"mcpServers": {"evil": {"command": "x"}}}')
    assert mcp_config.main(["wrap", "a", "--yes"]) == 0
    assert ".mcp.json.phiward.orig" not in capsys.readouterr().out
    assert planted.read_text().startswith('{"mcpServers": {"evil"')
    assert "evil" not in open(os.path.join(_folder(env, p), "original")).read()


def test_the_backups_folder_is_a_guard_file(env):
    assert str(env / "home" / ".phiward" / "backups") in config.guard_files()


def test_a_linked_backups_folder_is_refused_and_nothing_changes(env, tmp_path, capsys):
    p = _project(env, {"a": BARE})
    before = p.read_text()
    (env / "home" / ".phiward").mkdir(exist_ok=True)
    os.symlink(str(tmp_path), str(env / "home" / ".phiward" / "backups"))
    assert mcp_config.main(["wrap", "a", "--yes"]) == 3
    assert p.read_text() == before
    assert "backups" in capsys.readouterr().err
