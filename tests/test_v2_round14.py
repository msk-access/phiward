"""The fourteenth review round: wildcard allowRead entries that reach into a protected pattern,
and the env settings `install` merges. (Its `phiward exec` and shell prefix parts are gone with
them.) Made-up trees and fake keys only."""

import json
import sys
from pathlib import Path

import pytest

from phiward import claude_settings, config, install
from phiward.sanitize import Sanitizer
from helpers import gone, protect, user_settings
from helpers import confinement

SRC = str(Path(__file__).resolve().parents[1] / "src")
macos = pytest.mark.skipif(sys.platform != "darwin", reason="patterns confine the shell on macOS")


# --- H2: a wildcard allowRead that reaches into a protected pattern ------------------------------

@pytest.mark.parametrize("allow,reaches", [
    ("{t}/r*/run1/panel", True),
    ("{t}/*/*/panel/**", True),
    ("{t}/**", True),
    ("{t}/runs/*/panel/x.maf", True),
    ("{t}/runs/run1/panel", True),
    ("{t}/runs/*/x", True),  # below the pattern's literal start: taken widely
    ("{t}/r*/run1/other", False),
    ("{t}/o*/run1/panel", False),
    ("{t}/r*", False),  # above every match: a wider allow does not re-open a deny
    ("{t}/runs", False),
    ("{t}/runs/run1/notes", False),
])
def test_an_allow_read_entry_reaches_into_a_pattern(tree, allow, reaches):
    pat = f"{tree}/runs/*/panel"
    assert claude_settings._reaches_into(allow.format(t=tree), pat) is reaches


@macos
@pytest.mark.parametrize("which", [0, 1])
def test_a_pattern_needs_both_of_its_sandbox_entries(tree, monkeypatch, which):
    monkeypatch.setenv("HOME", str(tree / "home"))
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    want = install.wiring(cfg, version=claude_settings.VERSION_PATTERNS)
    entry = claude_settings.pattern_entries(f"{tree}/runs/*/panel")[which]
    fs = want["sandbox"]["filesystem"]
    for key in ("denyRead", "denyWrite"):
        fs[key] = [e for e in fs[key] if e != entry]
    user_settings(tree, want)
    ok, why = confinement(str(tree / "repo"), str(tree / "home"), cfg.all_roots,
                                          cfg.patterns, config.guard_files())
    assert not ok and "pattern" in why, why


# --- M2: the env settings install merges ----------------------------------------------------------

def test_install_says_when_it_changes_the_user_s_shell(tree, capsys):
    target = tree / "home" / ".claude" / "settings.json"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({"env": {"CLAUDE_CODE_SHELL": "/bin/zsh"}}))
    cfg = config.load(str(tree / "repo"))
    assert install._write(str(target), install.wiring(cfg), [], ["--yes"]) == 0
    notes = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("Note:")]
    assert any("CLAUDE_CODE_SHELL" in n and "/bin/zsh" in n for n in notes), notes


# --- L1-L3 -------------------------------------------------------------------------------------

def test_the_plain_spelling_step_leaves_the_text_before_a_protected_path(tree):
    san = Sanitizer.from_config(protect(tree, []), entries=False)
    out = san.clean(f"see https://example.org/a and {tree}/phi\\/Zorro")
    assert out.startswith("see https://example.org/a and "), out
    gone(out, "Zorro")


def test_the_wiring_lists_each_entry_once(tree):
    cfg = config.load(str(tree / "repo"))
    for want in (install.wiring(cfg, version=claude_settings.VERSION_PATTERNS), install.wiring(cfg)):
        for key, values in want["sandbox"]["filesystem"].items():
            assert len(values) == len(set(values)), (key, [v for v in values if values.count(v) > 1])
        rules = want["permissions"]["deny"]
        assert len(rules) == len(set(rules))
