"""The sandbox's denyWrite holds the shell-code paths too: what a shell runs before an agent's
command. Claude Code's own sandbox refuses only some of them (measured with 2.1.327: not
`.zshenv`, `.bash_login`, `.bash_aliases`, `.bash_logout`, `.zlogin`, `.zlogout`, `.bashrc.d`),
so a session opened in the home folder could plant code there. Made-up trees only."""

import os

import pytest

from phiward import claude_settings, config, install, pathid
from phiward.core import DENY, FILE_WRITE, Action
from phiward.guards import protected_paths
from helpers import protect


@pytest.fixture()
def clean_env(monkeypatch):
    for name in ("ZDOTDIR", "BASH_ENV", "ENV", "CLAUDE_CONFIG_DIR"):
        monkeypatch.delenv(name, raising=False)


def _deny_write(w):
    return w["sandbox"]["filesystem"]["denyWrite"]


def _has(entries, path, home):
    """`path` is in `entries`, in any spelling the settings use (`~/...`, as named, canonical)."""
    forms = {path, pathid.canon_new(path)}
    for p in list(forms):
        if p.startswith(home.rstrip("/") + "/"):
            forms.add("~/" + p[len(home.rstrip("/")) + 1:])
    return bool(forms & set(entries))


NOT_COVERED_BY_CLAUDE_CODE = (".zshenv", ".bash_login", ".bash_aliases", ".bash_logout",
                              ".zlogin", ".zlogout", ".bashrc.d")


@pytest.mark.parametrize("name", NOT_COVERED_BY_CLAUDE_CODE)
def test_the_user_wiring_denies_the_sandbox_a_startup_file(tree, clean_env, name):
    home = str(tree / "home")
    w = install.wiring(config.load(str(tree / "repo")))
    assert _has(_deny_write(w), os.path.join(home, name), home), (name, _deny_write(w))


def test_every_shell_code_path_is_in_the_user_wiring(tree, clean_env, monkeypatch):
    # the one list the hook reads, values from the variables included
    monkeypatch.setenv("ZDOTDIR", str(tree / "zdot"))
    monkeypatch.setenv("BASH_ENV", str(tree / "envs" / "bash-env.sh"))
    home = str(tree / "home")
    deny = _deny_write(install.wiring(config.load(str(tree / "repo"))))
    missing = [p for p in claude_settings.shell_code_paths(home) if not _has(deny, p, home)]
    assert not missing, missing


def test_a_claude_config_dir_moves_the_two_folders_in_the_sandbox_too(tree, clean_env, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tree / "cc"))
    home = str(tree / "home")
    deny = _deny_write(install.wiring(config.load(str(tree / "repo"))))
    for sub in ("session-env", "shell-snapshots"):
        assert _has(deny, str(tree / "cc" / sub), home), (sub, deny)


def test_the_local_file_of_a_project_carries_them(tree, clean_env, monkeypatch):
    monkeypatch.setenv("ZDOTDIR", str(tree / "zdot"))
    home = str(tree / "home")
    deny = _deny_write(install.local_wiring(config.load(str(tree / "repo")), str(tree / "repo")))
    missing = [p for p in claude_settings.shell_code_paths(home) if not _has(deny, p, home)]
    assert not missing, missing
    assert len(deny) == len(set(deny)), deny  # no entry twice


def test_the_committed_project_file_names_no_value_from_a_variable(tree, clean_env, monkeypatch):
    # a committed file is the same for every contributor: no ZDOTDIR of this machine in it
    monkeypatch.setenv("ZDOTDIR", str(tree / "zdot"))
    home = str(tree / "home")
    deny = _deny_write(install.wiring(config.load(str(tree / "repo")), True, str(tree / "repo")))
    there = [p for p in claude_settings.shell_code_paths(home) if _has(deny, p, home)]
    assert not there, there


def test_a_file_tool_cannot_write_into_bashrc_d(tree, clean_env):
    # the RHEL skeleton .bashrc sources every file in ~/.bashrc.d
    cfg = protect(tree, [], best_effort=False)
    d = protected_paths.check(Action(FILE_WRITE, str(tree / "repo"),
                                     paths=(str(tree / "home" / ".bashrc.d" / "x.sh"),),
                                     tool="Write"), cfg)
    assert d.verdict == DENY, d.reason


def _write_user_settings(tree, data):
    import json
    s = tree / "home" / ".claude" / "settings.json"
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(json.dumps(data))


def _startup_line(tree):
    from phiward import doctor
    lines = doctor.mode_report(str(tree / "repo"), str(tree / "home"),
                               config.load(str(tree / "repo")))
    return next(ln for ln in lines if "shell startup files in the sandbox" in ln)


def test_doctor_counts_the_startup_files_after_install(tree, clean_env):
    protect(tree, [], best_effort=False)
    _write_user_settings(tree, install.wiring(config.load(str(tree / "repo"))))
    line = _startup_line(tree)
    n = len(claude_settings.shell_code_paths(str(tree / "home")))
    assert f"{n} of {n}" in line and "WARNING" not in line, line


def test_doctor_warns_when_older_settings_leave_them_out(tree, clean_env):
    # settings that an older install wrote: the sandbox's denyWrite has no startup files
    protect(tree, [], best_effort=False)
    w = install.wiring(config.load(str(tree / "repo")))
    home = str(tree / "home")
    w["sandbox"]["filesystem"]["denyWrite"] = [
        p for p in _deny_write(w) if not any(_has([p], s, home)
                                             for s in claude_settings.shell_code_paths(home))]
    _write_user_settings(tree, w)
    line = _startup_line(tree)
    assert "WARNING" in line and "phiward install claude --user --write" in line, line
