"""Part 6: read blocking outside the project (`--block-outside-reads`), each setting from the
Claude Code version that knows it. Made-up trees only; the real `claude` never runs."""

import json
import sys

import pytest

from phiward import claude_settings, config, doctor, install
from helpers import Tty

BLOCK = claude_settings.VERSION_BLOCK_READS
PROMPTS = claude_settings.VERSION_DENY_PROMPTS


@pytest.mark.parametrize("version,want", [
    (None, {}), ((2, 1, 200), {}),
    (BLOCK, {"blockReadsOutsideWorkingDirectories": True}),
    (PROMPTS, {"blockReadsOutsideWorkingDirectories": True, "denyInsteadOfPrompting": True})])
def test_the_wiring_sets_what_this_claude_code_knows(tree, version, want):
    perms = install.wiring(config.load(str(tree / "repo")), version=version,
                           block_reads=True)["permissions"]
    assert {k: v for k, v in perms.items() if k != "deny"} == want


def test_the_settings_are_off_unless_asked_and_merged_when_asked(tree):
    cfg = config.load(str(tree / "repo"))
    plain = install.wiring(cfg, version=PROMPTS)
    assert set(plain["permissions"]) == {"deny"}
    merged = install.merge({"permissions": {"allow": ["Bash(ls)"]}},
                           install.wiring(cfg, version=PROMPTS, block_reads=True))
    assert merged["permissions"]["blockReadsOutsideWorkingDirectories"] is True
    assert merged["permissions"]["denyInsteadOfPrompting"] is True
    assert merged["permissions"]["allow"] == ["Bash(ls)"]


@pytest.mark.parametrize("argv,version", [(["--project"], PROMPTS), ([], None), ([], (2, 1, 200))])
def test_install_refuses_where_it_cannot_hold(tree, monkeypatch, capsys, argv, version):
    monkeypatch.setattr(claude_settings, "claude_version", lambda: version)
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.chdir(tree / "repo")
    assert install.main(["claude", "--block-outside-reads", "--write", "--yes"] + argv) == 2
    assert "--block-outside-reads" in capsys.readouterr().err


def test_doctor_reports_read_blocking(tree, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tree / "home"))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.chdir(tree / "repo")
    user = tree / "home" / ".claude" / "settings.json"
    user.parent.mkdir(parents=True, exist_ok=True)
    user.write_text(json.dumps({"permissions": {"blockReadsOutsideWorkingDirectories": True}}))
    doctor.main([])
    assert "read blocking outside the project: blockReadsOutsideWorkingDirectories" in \
        capsys.readouterr().out
