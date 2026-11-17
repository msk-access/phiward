"""Part 2: protected patterns in Claude Code's sandbox (denyRead and, on macOS, denyWrite), the
version gate, and when the shell counts as confined with patterns. Made-up trees only."""

import sys

import pytest

from phiward import claude_settings, config, install
from helpers import protect, user_settings
from helpers import confinement

macos = pytest.mark.skipif(sys.platform != "darwin", reason="patterns confine the shell on macOS")
NEW = claude_settings.VERSION_PATTERNS
OLD = (2, 1, 200)


def _confinement(tree, cfg):
    return confinement(str(tree / "repo"), str(tree / "home"), cfg.all_roots,
                                       cfg.patterns, config.guard_files())


def _wired(tree, cfg, version=NEW, extra_allow=()):
    """The user settings as `install claude --user --write` would make them."""
    want = install.wiring(cfg, version=version)
    want["sandbox"]["filesystem"]["allowRead"] = list(extra_allow)
    user_settings(tree, want)


def test_the_wiring_lists_patterns_only_with_a_new_enough_claude_code(tree, monkeypatch):
    monkeypatch.setenv("HOME", str(tree / "home"))
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    reads = install.wiring(cfg, version=NEW)["sandbox"]["filesystem"]["denyRead"]
    assert any(e.endswith("/runs/*/panel") for e in reads)
    assert any(e.endswith("/runs/*/panel/**") for e in reads)
    for version in (OLD, None):
        fs = install.wiring(cfg, version=version)["sandbox"]["filesystem"]
        assert not any("*/panel" in e for e in fs["denyRead"] + fs["denyWrite"]), version
    assert not any("*/panel" in e for e in
                   install.wiring(cfg, project=True, project_dir=str(tree / "repo"),
                                  version=NEW)["sandbox"]["filesystem"]["denyRead"])


def test_patterns_are_not_write_denied_off_macos(tree, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    reads, writes = install.pattern_sandbox([f"{tree}/runs/*/panel"], str(tree / "home"))
    assert reads and writes == []


@macos
def test_the_shell_with_patterns_counts_as_confined_on_macos(tree, monkeypatch):
    monkeypatch.setenv("HOME", str(tree / "home"))
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    _wired(tree, cfg)
    ok, why = _confinement(tree, cfg)
    assert ok, why


@macos
@pytest.mark.parametrize("version", [OLD, None])
def test_without_the_pattern_entries_the_shell_is_not_confined(tree, monkeypatch, version):
    monkeypatch.setenv("HOME", str(tree / "home"))
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    _wired(tree, cfg, version=version)
    ok, why = _confinement(tree, cfg)
    assert not ok and "pattern" in why, why


@macos
@pytest.mark.parametrize("allow", ["{t}/runs/r1/panel", "{t}/runs/r1/panel/x", "{t}/runs/*/x"])
def test_an_allow_read_into_a_match_breaks_confinement(tree, monkeypatch, allow):
    monkeypatch.setenv("HOME", str(tree / "home"))
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    _wired(tree, cfg, extra_allow=[allow.format(t=tree)])
    ok, why = _confinement(tree, cfg)
    assert not ok and "allowRead" in why, why


@macos
def test_an_allow_read_beside_the_matches_keeps_confinement(tree, monkeypatch):
    monkeypatch.setenv("HOME", str(tree / "home"))
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    _wired(tree, cfg, extra_allow=[f"{tree}/other", f"{tree}/runs/r1/notes"])
    ok, why = _confinement(tree, cfg)
    assert ok, why


def test_patterns_never_confine_the_shell_off_macos(tree, monkeypatch):
    monkeypatch.setenv("HOME", str(tree / "home"))
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    _wired(tree, cfg)
    monkeypatch.setattr(sys, "platform", "linux")
    ok, why = _confinement(tree, cfg)
    assert not ok and "pattern" in why, why
