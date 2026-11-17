"""A refusal's step says install only when install fixes it, and says it whenever it does
(round 6): the `excludedCommands` entries an older phiward wrote are ones install removes (one
list, used by both); `doctor` gives the install step when install would confine the shell; on
macOS the pattern entries need Claude Code 2.1.236 or newer, so the step says so, exactly when
the version is known; in a session started from the home folder the after-install simulation
replaces every level that reads the user file. Made-up trees only."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

from phiward import claude_settings, config, doctor, install
from phiward.adapters import claude
from helpers import protect

INSTALL = "phiward install claude --user --write"
OLD = ["phiward run *", "phiward copy *"]


def _wired(tree, version=None, **extra):
    cfg = config.load(str(tree / "repo"))
    want = install.wiring(cfg, version=version)
    want["sandbox"].update(extra)
    s = tree / "home" / ".claude" / "settings.json"
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(json.dumps(want))
    return want


def _reason(tree, project=None, version=None):
    cfg = config.load(str(tree / "repo"))
    return claude_settings.confinement_reason(str(project or tree / "repo"), str(tree / "home"),
                                              cfg.all_roots, cfg.patterns, config.guard_files(),
                                              version=version)


def _hook(tree, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    payload = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
               "permission_mode": "default", "tool_name": "Bash", "tool_input": {"command": "ls"}}
    out, err = io.StringIO(), io.StringIO()
    assert claude.main(io.StringIO(json.dumps(payload)), out, err) == 2
    return out.getvalue() + err.getvalue()


def test_one_list_of_the_entries_install_removes():
    assert install.OLD_EXCLUDES is claude_settings.OLD_EXCLUDES
    merged = install.merge({"sandbox": {"excludedCommands": OLD + ["make *"]}},
                           {"hooks": {"PreToolUse": []}, "permissions": {"deny": []},
                            "sandbox": {"filesystem": {}}})
    assert merged["sandbox"]["excludedCommands"] == ["make *"]


def test_old_excludes_in_the_user_file_get_the_install_step(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    _wired(tree, excludedCommands=OLD)
    r = _reason(tree)
    assert "excludedCommands" in r.text and r.step.endswith(INSTALL + ")`"), r
    assert INSTALL in _hook(tree, monkeypatch)


def test_an_entry_install_keeps_gets_the_remove_step(tree):
    protect(tree, [], best_effort=False)
    _wired(tree, excludedCommands=OLD + ["make *"])
    r = _reason(tree)
    assert "~/.claude/settings.json" in r.step and "install never removes it" in r.step, r
    assert INSTALL not in r.step


def test_old_excludes_in_a_project_file_do_not_say_install_never_removes_them(tree):
    protect(tree, [], best_effort=False)
    _wired(tree)
    f = tree / "repo" / ".claude" / "settings.json"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps({"sandbox": {"excludedCommands": OLD}}))
    r = _reason(tree)
    assert ".claude/settings.json" in r.step and "never" not in r.step, r


def test_doctor_gives_the_install_step_for_the_upgrade(tree):
    protect(tree, [], best_effort=False)
    _wired(tree, excludedCommands=OLD)
    src = str(Path(__file__).resolve().parents[1] / "src")
    out = subprocess.run([sys.executable, "-m", "phiward", "doctor"], cwd=str(tree / "repo"),
                         capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
                         env=dict(os.environ, PYTHONPATH=src)).stdout
    line = next(ln for ln in out.splitlines() if "sandbox confines the shell" in ln)
    assert INSTALL in line and "removes" not in line, line


def test_the_pattern_step_follows_the_claude_code_version(tree, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    protect(tree, ["**/*.bam"], best_effort=False)
    _wired(tree, version=None)  # an install that saw no Claude Code: no pattern entries
    old = _reason(tree, version=(2, 1, 200))
    assert "pattern" in old.text and "updates Claude Code to 2.1.236" in old.step, old
    new = _reason(tree, version=(2, 1, 300))
    assert new.step == claude_settings.INSTALL_STEP, new
    unknown = _reason(tree)
    assert "`claude --version` prints 2.1.236 or newer" in unknown.step, unknown


def test_doctor_simulates_install_with_the_claude_code_version(tree, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    protect(tree, ["**/*.bam"], best_effort=False)
    _wired(tree, version=None)
    cfg = config.load(str(tree / "repo"))
    home, project = str(tree / "home"), str(tree / "repo")
    monkeypatch.setenv("HOME", home)
    assert doctor._after_install(project, home, cfg, [], version=(2, 1, 300)) is None
    still = doctor._after_install(project, home, cfg, [], version=(2, 1, 200))
    assert still is not None and "updates Claude Code" in still.step, still


def test_a_home_folder_session_simulates_install_on_every_level_of_the_user_file(tree,
                                                                                monkeypatch):
    protect(tree, [], best_effort=False)
    _wired(tree, excludedCommands=OLD)
    home = tree / "home"
    monkeypatch.setenv("HOME", str(home))
    cfg = config.load(str(tree / "repo"))
    # round 18 (HK-F5): a session in the home folder is never confined, whatever install
    # writes: its sandbox may write the places that start programs later
    first = doctor._after_install(str(home), str(home), cfg, [])
    assert first is not None and "home folder" in first.text, first
    _wired(tree, excludedCommands=OLD + ["make *"])
    still = doctor._after_install(str(home), str(home), cfg, [])
    assert still is not None and "home folder" in still.text, still


def test_confinement_lives_in_the_tests_only():
    assert not hasattr(claude_settings, "confinement")
