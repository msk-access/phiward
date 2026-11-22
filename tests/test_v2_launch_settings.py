"""The `--settings` file: `claude --settings FILE` with `allowUnsandboxedCommands: false` makes
Claude Code's sandbox admin-required for one person with no admin rights, so a repository's
settings cannot turn it off or loosen it. `install claude --user --write` writes the file,
`doctor` checks it, and on Linux `doctor` checks bubblewrap's version. Made-up trees only."""

import json
import os
import sys
from pathlib import Path

from phiward import config, doctor, install
from helpers import confinement


def test_the_file_sets_the_three_switches():
    assert install.LAUNCH_SETTINGS == {"sandbox": {
        "enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False},
        "env": {"CLAUDE_CODE_DISABLE_FILE_MENTIONS": "1"}}


def test_the_file_lives_with_the_user_config_and_is_guarded(tree):
    p = config.launch_settings_path()
    assert p == os.path.join(str(tree / "home"), ".config", "phiward", "claude-settings.json")
    assert os.path.dirname(p) in config.guard_files()  # its folder: the file and its place


def _install(tree, monkeypatch):
    """`install claude --user --write --yes` in the operator's own terminal."""
    from helpers import Tty
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.chdir(tree / "repo")
    return install.main(["claude", "--user", "--write", "--yes"])


def test_install_writes_it_and_says_how_to_start_claude(tree, monkeypatch, capsys):
    assert _install(tree, monkeypatch) == 0
    p = Path(config.launch_settings_path())
    assert json.loads(p.read_text()) == install.LAUNCH_SETTINGS
    assert f"claude --settings {p}" in capsys.readouterr().out
    assert _install(tree, monkeypatch) == 0
    assert json.loads(p.read_text()) == install.LAUNCH_SETTINGS


def test_install_replaces_a_changed_file(tree, monkeypatch):
    p = Path(config.launch_settings_path())
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('{"sandbox": {"enabled": false}}')
    assert _install(tree, monkeypatch) == 0
    assert json.loads(p.read_text()) == install.LAUNCH_SETTINGS


def test_a_project_install_writes_no_settings_file(tree, monkeypatch):
    from helpers import Tty
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.chdir(tree / "repo")
    install.main(["claude", "--project", "--write", "--yes"])
    assert not os.path.exists(config.launch_settings_path())


def test_doctor_reports_the_file(tree):
    p = Path(config.launch_settings_path())
    lines = doctor.launch_settings_report()
    assert any("NOTE" in ln and "install claude --user --write" in ln for ln in lines), lines
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('{"sandbox": {"enabled": true}}')
    lines = doctor.launch_settings_report()
    assert any("WARNING" in ln for ln in lines), lines
    p.write_text(json.dumps(install.LAUNCH_SETTINGS))
    lines = doctor.launch_settings_report()
    assert any(f"claude --settings {p}" in ln for ln in lines), lines
    assert not any("WARNING" in ln for ln in lines), lines
    assert any("cannot tell" in ln for ln in lines), lines


class _R:
    def __init__(self, out, code=0):
        self.stdout, self.returncode = out, code


def test_doctor_checks_the_bubblewrap_version(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda p, path=None: "/usr/bin/" + p)
    old = doctor.sandbox_needs("linux", run=lambda *a, **k: _R("bubblewrap 0.3.3\n"))
    assert any("0.4" in ln and "WARNING" in ln for ln in old), old
    assert doctor.sandbox_needs("linux", run=lambda *a, **k: _R("bubblewrap 0.4.0\n")) == []
    assert doctor.sandbox_needs("darwin") == []


def test_doctor_names_socat_on_the_path_without_admin(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which",
                        lambda p, path=None: None if p == "socat" else "/usr/bin/" + p)
    lines = doctor.sandbox_needs("linux", run=lambda *a, **k: _R("bubblewrap 0.4.0\n"))
    assert any("socat" in ln and "PATH" in ln for ln in lines), lines


# --- the review of 62cc296: where the file is guarded, a bad place, an older wiring ------------

def _write_tool(tree, path):
    from phiward.core import FILE_WRITE, Action
    from phiward.guards import protected_paths
    cfg = config.load(str(tree / "repo"))
    return protected_paths.check(Action(FILE_WRITE, str(tree / "repo"), paths=(str(path),),
                                        tool="Write"), cfg).verdict


def test_the_file_is_guarded_at_both_places(tree, monkeypatch):
    from phiward.core import DENY
    home = tree / "home"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tree / "xdg"))
    assert _write_tool(tree, home / ".config" / "phiward" / "claude-settings.json") == DENY
    assert _write_tool(tree, tree / "xdg" / "phiward" / "claude-settings.json") == DENY


def test_its_folder_cannot_be_replaced_by_a_file(tree):
    from phiward.core import DENY
    # PHIWARD_CONFIG names a config elsewhere (the tree fixture does), so the folder of the
    # --settings file is not the config's folder
    assert _write_tool(tree, tree / "home" / ".config" / "phiward") == DENY


def test_install_refuses_a_bad_place_without_a_traceback(tree, capsys):
    folder = Path(config.launch_settings_path()).parent
    folder.parent.mkdir(parents=True, exist_ok=True)
    folder.write_text("not a folder")
    assert install._write_launch_settings() == 3
    err = capsys.readouterr().err
    assert "install refused" in err and "Traceback" not in err


def test_install_refuses_a_link_at_the_file(tree, capsys):
    p = Path(config.launch_settings_path())
    p.parent.mkdir(parents=True, exist_ok=True)
    (tree / "elsewhere.json").write_text("{}")
    p.symlink_to(tree / "elsewhere.json")
    assert install._write_launch_settings() == 3
    assert (tree / "elsewhere.json").read_text() == "{}"


def test_an_older_wiring_is_told_to_run_install_again(tree):
    folder = os.path.dirname(config.launch_settings_path())
    guard = [g for g in config.guard_files() if g != folder]
    fs = {"denyRead": [str(tree / "phi")], "denyWrite": [str(tree / "phi")] + guard}
    sb = {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
          "filesystem": fs}
    d = tree / "home" / ".claude"
    d.mkdir(parents=True, exist_ok=True)
    (d / "settings.json").write_text(json.dumps({"sandbox": sb}))
    ok, why = confinement(str(tree / "repo"), str(tree / "home"),
                                          [str(tree / "phi")], [], config.guard_files())
    assert not ok and "install claude --user --write" in why, why


def test_doctor_finds_bwrap_only_on_a_safe_path(tree, monkeypatch):
    unsafe = tree / "repo" / "bin"
    unsafe.mkdir()
    for name in ("bwrap", "socat"):
        f = unsafe / name
        f.write_text("#!/bin/sh\necho bubblewrap 9.9\n")
        f.chmod(0o755)
    monkeypatch.setenv("PATH", f"{unsafe}:/nonexistent")
    monkeypatch.chdir(tree / "repo")  # the agent's project: its folders are not searched
    lines = doctor.sandbox_needs("linux")
    assert any("bwrap" in ln and "socat" in ln for ln in lines), lines


# --- a dotfiles setup: ~/.config/phiward is a link to a folder of the operator's ----------------

def test_a_linked_config_folder_of_the_operator_is_accepted_and_guarded(tree, capsys):
    real = tree / "dotfiles" / "phiward"
    real.mkdir(parents=True)
    real.chmod(0o700)
    link = tree / "home" / ".config" / "phiward"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(real)
    assert install._write_launch_settings() == 0, capsys.readouterr().err
    assert json.loads((real / "claude-settings.json").read_text()) == install.LAUNCH_SETTINGS
    assert str(real) in config.guard_files()


def test_a_linked_folder_others_can_write_is_refused(tree):
    real = tree / "shared"
    real.mkdir()
    real.chmod(0o777)
    link = tree / "home" / ".config" / "phiward"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(real)
    assert install._write_launch_settings() == 3
