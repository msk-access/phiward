"""Findings of the final review before v0.2.0b1. Made-up data only."""

import os
import re
import shutil
import sys
from pathlib import Path

import pytest

from phiward import config
from phiward.sanitize import Sanitizer

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_confinement import gate  # noqa: E402


# --- 1. a protected name with a space is masked whole ------------------------------------------

@pytest.fixture()
def spaced(tree):
    d = tree / "phi" / "Doe Jane 1970"
    d.mkdir()
    (d / "scan one.txt").write_text("SECRET-CONTENT-9\n")
    (tree / "phi" / "Ünïcode Näme").mkdir()
    return Sanitizer.from_config(config.load(str(tree / "repo")), entries=True)


@pytest.mark.parametrize("line", [
    "{phi}/Doe Jane 1970/scan one.txt",
    "{phi}/Doe Jane 1970",
    "ls: cannot access '{phi}/Doe Jane 1970/scan one.txt': No such file or directory",
    "12\t{phi}/Doe Jane 1970",
    "{phi}/Ünïcode Näme",
    "./Doe Jane 1970/scan one.txt",
    "Doe Jane 1970",
])
def test_no_part_of_a_spaced_name_is_left(tree, spaced, line):
    out = spaced.clean(line.format(phi=tree / "phi"))
    for word in ("Doe", "Jane", "1970", "scan", "Ünïcode", "Näme", str(tree / "phi")):
        assert word not in out, out


def test_text_after_a_masked_path_stays_after_a_tab_or_a_path(tree, spaced):
    # after a space, a word may be more of a name (round 8): the mask runs to the tab or the end
    phi = tree / "phi"
    assert spaced.clean(f"open {phi}/Doe Jane 1970/scan one.txt now") == "open <PROTECTED>"
    assert spaced.clean(f"open {phi}/FAKE-PT-0001.bam /tmp/out") == "open <PROTECTED> /tmp/out"
    assert spaced.clean(f"12\t{phi}/Doe Jane 1970\tdone") == "12\t<PROTECTED>\tdone"


def test_a_spaced_name_through_the_gateway(tree, broker):
    if CONFINE_WHY is not None:
        pytest.skip("no confinement backend")
    d = tree / "phi" / "Doe Jane 1970"
    d.mkdir()
    (d / "scan one.txt").write_text("x\n")
    broker()
    code, out = gate(tree, ["--", "find", str(tree / "phi"), "-type", "f"])
    assert "<PROTECTED>" in out, out
    for word in ("Jane", "1970", "scan"):
        assert word not in out, out


# --- 2. the hook's verdict for a glob does not depend on names inside a root ----------------

from phiward.core import DENY, FILE_READ, FILE_SEARCH, FILE_WRITE, SHELL, Action  # noqa: E402
from phiward.guards import protected_paths  # noqa: E402


def _shell(tree, command, confined=False):
    cfg = config.load(str(tree / "repo"))
    return protected_paths.check(Action(SHELL, str(tree / "repo"), command=command,
                                        confined=confined), cfg).verdict


@pytest.mark.parametrize("confined", [False, True])
@pytest.mark.parametrize("pair", [
    ("echo {t}/p*/F*", "echo {t}/p*/G*"),
    ("echo {t}/phi/FAKE-PT-000[0-4]*", "echo {t}/phi/FAKE-PT-000[5-9]*"),
    ("echo {t}/ph?/sub/F*", "echo {t}/ph?/sub/Q*"),
    ("cd {t}/p*/s* && pwd", "cd {t}/p*/z* && pwd"),
    ("echo {t}/**/FAKE-PT-0002.bam", "echo {t}/**/NOPE-0002.bam"),
])
def test_a_glob_into_a_root_gets_one_verdict_whatever_is_there(tree, pair, confined):
    a, b = (c.format(t=tree) for c in pair)
    assert _shell(tree, a, confined) == _shell(tree, b, confined) == DENY


def test_a_glob_through_a_link_the_agent_made_gets_one_verdict(tree):
    os.symlink(tree / "phi", tree / "repo" / "lnk")
    assert _shell(tree, "echo lnk/F*") == _shell(tree, "echo lnk/G*") == DENY
    assert _shell(tree, "echo l*/F*") == _shell(tree, "echo l*/G*") == DENY
    os.symlink(tree, tree / "repo" / "up")
    assert _shell(tree, "echo up/p*/F*") == _shell(tree, "echo up/p*/G*") == DENY


def test_a_glob_that_cannot_reach_a_root_is_still_allowed(tree):
    from phiward.core import ALLOW
    assert _shell(tree, f"echo {tree}/pu*/x*") == ALLOW
    assert _shell(tree, "ls src/*.py") == ALLOW


def test_a_glob_to_a_link_into_a_root_is_still_refused(tree):
    assert _shell(tree, "cat lea*") == DENY  # repo/leak.txt -> a protected file


@pytest.mark.parametrize("kind", [FILE_READ, FILE_WRITE, FILE_SEARCH])
def test_file_tools_get_one_verdict_for_a_glob(tree, kind):
    cfg = config.load(str(tree / "repo"))

    def v(p):
        d = protected_paths.check(Action(kind, str(tree / "repo"), paths=(p,)), cfg)
        return d.verdict, d.reason

    assert v(f"{tree}/p*/F*") == v(f"{tree}/p*/G*")
    assert v(f"{tree}/p*/F*")[0] == DENY


# --- 4, 5. the shell counts as confined only with a sandbox that must start and is whole -------

import json  # noqa: E402

from phiward import claude_settings, install  # noqa: E402
from helpers import CONFINE_WHY, confinement  # noqa: E402


def _confined(tree, extra_sandbox=None, drop=()):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/phi"]\n')  # no patterns: they are never confined
    cfg = config.load(str(tree / "repo"))
    want = install.merge({}, install.wiring(cfg))
    for k in drop:
        want["sandbox"].pop(k, None)
    for k, v in (extra_sandbox or {}).items():
        if "." in k:
            a, b = k.split(".")
            want["sandbox"].setdefault(a, {})[b] = v
        else:
            want["sandbox"][k] = v
    d = tree / "home" / ".claude"
    d.mkdir(exist_ok=True)
    (d / "settings.json").write_text(json.dumps(want))
    return confinement(str(tree / "repo"), str(tree / "home"), cfg.all_roots,
                                       cfg.patterns, config.guard_files())


def test_install_writes_fail_if_unavailable(tree):
    w = install.wiring(config.load(str(tree / "repo")))
    assert w["sandbox"]["failIfUnavailable"] is True
    assert install.merge({"sandbox": {"failIfUnavailable": False}}, w)["sandbox"][
        "failIfUnavailable"] is True


def test_the_wired_settings_count_as_confined(tree):
    assert _confined(tree) == (True, "")


def test_without_fail_if_unavailable_the_shell_is_not_confined(tree):
    ok, why = _confined(tree, drop=("failIfUnavailable",))
    assert not ok and "failIfUnavailable" in why


@pytest.mark.parametrize("key,value", [
    ("filesystem.disabled", True), ("enableWeakerNestedSandbox", True),
    ("allowAppleEvents", True), ("allowNestedUserNamespaces", True),
    ("network.allowLocalBinding", True), ("network.allowMachLookup", ["com.example.*"]),
])
def test_a_setting_that_opens_the_sandbox_means_not_confined(tree, key, value):
    ok, why = _confined(tree, {key: value})
    assert not ok and key.split(".")[-1] in why


def test_doctor_names_what_the_sandbox_needs_on_linux(monkeypatch):
    import shutil
    from phiward import doctor
    monkeypatch.setattr(shutil, "which", lambda p, path=None: None if p == "socat" else "/usr/bin/" + p)
    assert "socat" in doctor.sandbox_needs("linux")[0]
    assert doctor.sandbox_needs("darwin") == []


# --- 6. the local settings of a git repository are read where Claude Code reads them ---------

def _git(*args, cwd):
    import subprocess
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True,
                   env=dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null"))


def test_the_repository_roots_local_file_is_read_for_a_session_in_a_subfolder(tree):
    repo = tree / "repo"
    _git("init", "-q", cwd=repo)
    (repo / ".claude").mkdir()
    (repo / ".claude" / "settings.local.json").write_text(
        json.dumps({"sandbox": {"excludedCommands": ["cat *"]}}))
    files = [p for _l, p, _d in claude_settings.levels(str(repo / "src"), str(tree / "home"))]
    assert str(repo / ".claude" / "settings.local.json") in files


def test_a_worktrees_local_file_is_the_main_checkouts(tree):
    repo = tree / "repo"
    _git("init", "-q", cwd=repo)
    _git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q",
         "--allow-empty", "-m", "x", cwd=repo)
    _git("worktree", "add", "-q", str(tree / "wt"), cwd=repo)
    files = [p for _l, p, _d in claude_settings.levels(str(tree / "wt"), str(tree / "home"))]
    assert str(repo / ".claude" / "settings.local.json") in files


# --- the version: one place, shown by the CLI and doctor ---------------------------------------

def test_the_cli_and_doctor_show_the_version(capsys):
    from phiward import __version__, cli
    assert cli.main(["--version"]) == 0 and cli.main(["version"]) == 0
    assert capsys.readouterr().out == f"phiward {__version__}\nphiward {__version__}\n"
    cli.main(["--help"])
    assert "--version" in capsys.readouterr().out


def test_the_built_package_takes_the_version_from_the_module():
    import re
    root = Path(__file__).resolve().parents[1]
    py = (root / "pyproject.toml").read_text()
    assert not re.search(r'(?m)^version = "', py)  # no second copy to forget


# --- 9. a project's settings cannot point the hook at another home or config -------------------

@pytest.mark.parametrize("key", ["PHIWARD_CONFIG", "PHIWARD_SPOOL", "PHIWARD_DEV", "KRB5CCNAME",
                                 "KRB5_CONFIG", "USER", "LOGNAME"])
def test_a_project_env_that_redirects_the_hook_refuses_everything(tree, key, monkeypatch, capsys):
    from phiward import doctor
    d = tree / "repo" / ".claude"
    d.mkdir()
    (d / "settings.json").write_text(json.dumps({"env": {key: str(tree / "pub")}}))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    cfg = config.load(str(tree / "repo"))
    dec = protected_paths.check(Action(FILE_READ, str(tree / "repo"),
                                       paths=(str(tree / "repo" / "README.md"),)), cfg)
    assert dec.verdict == DENY and f"env.{key}" in dec.reason
    doctor.main([])
    assert f"env.{key}" in capsys.readouterr().out


@pytest.mark.parametrize("key", ["HOME", "XDG_CONFIG_HOME", "CLAUDE_CONFIG_DIR", "TMPDIR"])
def test_a_project_env_key_that_claude_code_ignores_is_not_refused(tree, key, monkeypatch):
    from phiward.core import ALLOW
    d = tree / "repo" / ".claude"
    d.mkdir()
    (d / "settings.json").write_text(json.dumps({"env": {key: str(tree / "pub")}}))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    dec = protected_paths.check(Action(FILE_READ, str(tree / "repo"),
                                       paths=(str(tree / "repo" / "README.md"),)),
                                config.load(str(tree / "repo")))
    assert dec.verdict == ALLOW


def test_a_project_settings_file_that_does_not_parse_refuses_everything(tree, monkeypatch):
    d = tree / "repo" / ".claude"
    d.mkdir()
    (d / "settings.json").write_text('{"env": {"PHIWARD_CONFIG": "/x"},}')
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    dec = protected_paths.check(Action(FILE_READ, str(tree / "repo"),
                                       paths=(str(tree / "repo" / "README.md"),)),
                                config.load(str(tree / "repo")))
    assert dec.verdict == DENY and "cannot be read" in dec.reason


def test_a_project_env_with_other_keys_is_fine(tree, monkeypatch):
    from phiward.core import ALLOW
    d = tree / "repo" / ".claude"
    d.mkdir()
    (d / "settings.json").write_text(json.dumps({"env": {"FOO": "1"}}))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    cfg = config.load(str(tree / "repo"))
    dec = protected_paths.check(Action(FILE_READ, str(tree / "repo"),
                                       paths=(str(tree / "repo" / "README.md"),)), cfg)
    assert dec.verdict == ALLOW


def test_the_powershell_tool_is_refused_while_paths_are_protected(tree):
    from phiward.core import OTHER
    cfg = config.load(str(tree / "repo"))
    d = protected_paths.check(Action(OTHER, str(tree / "repo"), text=("Get-ChildItem",),
                                     tool="PowerShell"), cfg)
    assert d.verdict == DENY and "Bash" in d.reason


# --- second review: the glob verdict, again ------------------------------------------------

def _file(tree, kind, p):
    cfg = config.load(str(tree / "repo"))
    return protected_paths.check(Action(kind, str(tree / "repo"), paths=(p,)), cfg).verdict


@pytest.mark.parametrize("confined", [False, True])
def test_a_link_under_a_double_star_gets_one_verdict(tree, confined):
    d1 = tree / "repo" / "d1"
    d1.mkdir()
    os.symlink(tree / "phi" / "sub", d1 / "g")        # exists in the root
    os.symlink(tree / "phi" / "NOPE", d1 / "h")       # does not
    # in the sandbox the kernel stops the read, so the hook allows it (from the pattern
    # alone); without it the hook refuses it. Either way, the same in both trees
    want = "allow" if confined else DENY
    for cmd in ("cat d1/**/zzz", "cat d1/**"):
        assert _shell(tree, cmd, confined) == want, cmd
    (d1 / "g").unlink()
    for cmd in ("cat d1/**/zzz", "cat d1/**"):
        assert _shell(tree, cmd, confined) == want, cmd


def test_a_link_under_a_double_star_in_the_glob_tool(tree):
    d1 = tree / "repo" / "d1"
    d1.mkdir()
    os.symlink(tree / "phi" / "NOPE", d1 / "h")
    assert _file(tree, FILE_SEARCH, str(d1 / "**" / "zzz")) == DENY


def test_a_folder_too_large_to_check_fails_closed(tree):
    big = tree / "repo" / "big"
    big.mkdir()
    for i in range(4200):
        (big / f"f{i:05d}").mkdir() if i < 10 else (big / f"f{i:05d}").write_text("")
    os.symlink(tree / "phi", big / "zlink")
    assert _shell(tree, "cat big/z*/FAKE*") == DENY
    assert _shell(tree, "cat big/*/FAKE*") == DENY


def test_a_large_folder_at_the_last_level_is_still_listed(tree):
    from phiward.core import ALLOW
    big = tree / "repo" / "big"
    big.mkdir()
    for i in range(4200):
        (big / f"f{i:05d}.txt").write_text("")
    assert _shell(tree, "ls big/*.txt") == ALLOW
    os.symlink(tree / "phi" / "FAKE-PT-0001.bam", big / "zz.txt")
    assert _shell(tree, "ls big/*.txt") == DENY  # the link is checked past the limit


@pytest.mark.parametrize("glob", ["[!P]hi", "[^x]hi", "[[:alpha:]]hi", "[pP]hi", "?hi"])
def test_bracket_classes_reach_a_root(tree, glob):
    assert _shell(tree, f"cat {tree}/{glob}/FAKE*") == DENY


def test_dot_globbing_counts_dot_names(tree):
    os.symlink(tree / "phi", tree / "repo" / ".hid")
    assert _shell(tree, "shopt -s dotglob; cat */FAKE*") == DENY
    assert _shell(tree, "GLOBIGNORE=x; cat */FAKE*") == DENY


@pytest.mark.parametrize("cmd", ["ls /tmp/*.log", "ls ~/*", "du -sh ~/*", "ls /var/tmp/*.sock",
                                 "rm -f /tmp/build-*.tmp"])
def test_ordinary_globs_are_allowed_in_a_sandboxed_session(tree, cmd):
    from phiward.core import ALLOW
    assert _shell(tree, cmd, confined=True) == ALLOW


# --- second review: only a settings file Claude Code reads can raise confinement ---------------

def _wire_user(tree):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(f'[protected_paths]\nroots = ["{tree}/phi"]\n')
    cfg = config.load(str(tree / "repo"))
    d = tree / "home" / ".claude"
    d.mkdir(exist_ok=True)
    (d / "settings.json").write_text(json.dumps(install.merge({}, install.wiring(cfg))))
    return cfg


def _confined_at(tree, project, cfg):
    return confinement(str(project), str(tree / "home"), cfg.all_roots,
                                       cfg.patterns, config.guard_files())


def test_a_decoy_local_file_cannot_raise_confinement(tree):
    cfg = _wire_user(tree)
    repo = tree / "repo"
    _git("init", "-q", cwd=repo)
    (repo / ".claude").mkdir()
    (repo / ".claude" / "settings.local.json").write_text(
        json.dumps({"sandbox": {"enabled": False}}))  # the file Claude Code reads
    sub = repo / "src" / ".claude"
    sub.mkdir(parents=True)
    (sub / "settings.local.json").write_text(json.dumps(
        {"sandbox": {"enabled": True, "failIfUnavailable": True,
                     "allowUnsandboxedCommands": False}}))
    ok, why = _confined_at(tree, repo / "src", cfg)
    assert not ok and "enabled" in why


def test_a_planted_gitfile_cannot_choose_the_local_file(tree):
    repo = tree / "repo"
    x = tree / "pub" / "x"
    (x / ".claude").mkdir(parents=True)
    (x / ".claude" / "settings.local.json").write_text(json.dumps({"sandbox": {
        "enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
        "filesystem": {"denyRead": [str(tree / "phi")], "denyWrite": [str(tree / "phi")]}}}))
    (repo / ".git").write_text(f"gitdir: {x}/.git/worktrees/w\n")
    assert claude_settings.local_file(str(repo), str(tree / "home")) == \
        str(repo / ".claude" / "settings.local.json")
    cfg = config.load(str(repo))
    ok, _why = _confined_at(tree, repo, cfg)
    assert not ok


def test_a_local_file_that_weakens_the_sandbox_anywhere_means_not_confined(tree):
    cfg = _wire_user(tree)
    repo = tree / "repo"
    _git("init", "-q", cwd=repo)
    sub = repo / "src" / ".claude"
    sub.mkdir(parents=True)
    (sub / "settings.local.json").write_text(json.dumps({"sandbox": {"excludedCommands": ["cat"]}}))
    ok, why = _confined_at(tree, repo / "src", cfg)
    assert not ok and "settings.local.json" in why


def test_a_project_settings_file_that_does_not_parse_means_not_confined(tree):
    cfg = _wire_user(tree)
    d = tree / "repo" / ".claude"
    d.mkdir()
    (d / "settings.json").write_text('{"sandbox": {"excludedCommands": ["cat"]},}')
    ok, why = _confined_at(tree, tree / "repo", cfg)
    assert not ok and "cannot be read" in why


def test_a_repository_owned_by_someone_else_keeps_the_local_file_in_the_project(tree, monkeypatch):
    repo = tree / "repo"
    _git("init", "-q", cwd=repo)
    monkeypatch.setattr(claude_settings, "_owned", lambda p: False)
    assert claude_settings.local_file(str(repo / "src"), str(tree / "home")) == \
        str(repo / "src" / ".claude" / "settings.local.json")


# --- second review: the user wiring starts the hook so Python ignores PYTHON* variables --------

def test_the_user_hook_runs_python_isolated(tree):
    import sys as _sys
    w = install.wiring(config.load(str(tree / "repo")))
    for g in w["hooks"]["PreToolUse"]:
        assert install.isolated_python(g["hooks"][0]["command"]) == _sys.executable
    note = w["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    assert install.isolated_python(note, "session-note") == _sys.executable


def test_the_user_hook_clears_python_and_loader_variables(tree):
    import subprocess
    fake = tree / "fakepython"
    fake.write_text("#!/bin/sh\n/usr/bin/env\n")
    fake.chmod(0o755)
    cmd = install.isolated_command(str(fake), "hook")
    evil = tree / "evilbin"  # an `awk` a project's PATH could put first: not used
    evil.mkdir()
    (evil / "awk").write_text("#!/bin/sh\nexit 0\n")
    (evil / "awk").chmod(0o755)
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                         env={"PATH": f"{evil}:/usr/bin:/bin", "LD_FOO": "1", "DYLD_BAR": "1",
                              "PYTHONPATH": "/evil", "__PYVENV_LAUNCHER__": "/evil/bin/python",
                              "OPENSSL_CONF": "/evil.cnf", "OPENSSL_MODULES": "/evil",
                              "GCONV_PATH": "/evil", "LOCPATH": "/evil", "GLIBC_TUNABLES": "x",
                              "XDG_CONFIG_HOME": "/kept", "KEEP_ME": "yes"}).stdout
    assert "KEEP_ME=yes" in out and "XDG_CONFIG_HOME=/kept" in out  # what the hook reads stays
    for name in ("LD_FOO", "DYLD_BAR", "PYTHONPATH", "__PYVENV_LAUNCHER__", "OPENSSL_CONF",
                 "OPENSSL_MODULES", "GCONV_PATH", "LOCPATH", "GLIBC_TUNABLES"):
        assert name not in out, out


def test_install_refuses_without_the_clean_up_tools(tree, monkeypatch, capsys):
    monkeypatch.setattr(install, "CLEAN_TOOLS", ("/nonexistent/env",))
    monkeypatch.setattr("sys.stdin", type("Tty", (), {"isatty": lambda self: True})())
    monkeypatch.chdir(tree / "repo")
    assert install.main(["claude", "--user", "--write", "--yes"]) == 2
    assert "/nonexistent/env" in capsys.readouterr().err


def test_merge_replaces_the_older_launcher_hook(tree):
    w = install.wiring(config.load(str(tree / "repo")))
    old = {"hooks": {"PreToolUse": [{"matcher": "Bash|Monitor|PowerShell", "hooks": [
        {"type": "command", "command": "/Users/me/.local/bin/phiward hook claude",
         "timeout": 10, "onFailure": "block"}]},
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-own-hook"}]}],
        "SessionStart": [{"hooks": [{"type": "command",
                                     "command": "/Users/me/.local/bin/phiward session-note claude"}]}]}}
    m = install.merge(old, w)
    cmds = [h["command"] for g in m["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert "/Users/me/.local/bin/phiward hook claude" not in cmds and "my-own-hook" in cmds
    notes = [h["command"] for g in m["hooks"]["SessionStart"] for h in g["hooks"]]
    assert not any(c.startswith("/Users/me/") for c in notes)


def test_doctor_counts_the_project_hook_as_phiward(tree):
    from phiward import doctor
    d = tree / "repo" / ".claude"
    d.mkdir()
    (d / "settings.json").write_text(json.dumps(install.wiring(
        config.load(str(tree / "repo")), project=True, project_dir=str(tree / "repo"))))
    assert doctor.wiring_state(str(tree / "repo"), str(tree / "home")).wired


# --- second review: spaced names under patterns and in escaped output --------------------------

def test_a_spaced_folder_matched_by_a_pattern_is_masked(tree):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/phi"]\n'
        f'patterns = ["{tree}/runs/*/panel", "{tree}/wild/phi_*"]\n')
    (tree / "runs" / "My Run" / "panel" / "Poe Pat").mkdir(parents=True)
    (tree / "runs" / "My Run" / "panel" / "Poe Pat" / "f").write_text("x")
    (tree / "wild" / "phi_Moe Max" / "inner").mkdir(parents=True)
    san = Sanitizer.from_config(config.load(str(tree / "repo")), entries=True)
    out = san.clean(f"{tree}/runs/My Run/panel/Poe Pat/f and {tree}/wild/phi_Moe Max/inner/f")
    for word in ("Poe", "Pat", "Moe", "Max", "inner"):
        assert word not in out, out
    assert "Moe Max" not in san.clean("the folder phi_Moe Max")


def test_an_escaped_space_does_not_hide_a_name(tree, spaced):
    phi = tree / "phi"
    out = spaced.clean(f"{phi}/Doe\\ Jane\\ 1970/scan\\ one.txt")
    for word in ("Doe", "Jane", "1970", "scan"):
        assert word not in out, out
    assert "Jane" not in spaced.clean("Doe\\ Jane\\ 1970")


def test_the_bare_name_hooks_clear_the_python_variables(tree):
    import subprocess
    # the plugin's and the project's hooks run `phiward` by name: a project's PYTHONPATH must
    # not reach the launcher's Python
    for cmd in (install.PROJECT_HOOK, install.PROJECT_NOTE):
        assert install.CLEAN_ENV in cmd
    fake = tree / "fakebin"
    fake.mkdir()
    (fake / "phiward").write_text('#!/bin/sh\necho "PP=${PYTHONPATH:-unset}"\n')
    (fake / "phiward").chmod(0o755)
    r = subprocess.run(["/bin/sh", "-c", install.PROJECT_HOOK.split("sh -c ", 1)[1].strip("'")],
                       env=dict(os.environ, PATH=f"{fake}:/usr/bin:/bin", PYTHONPATH="/evil"),
                       capture_output=True, text=True, input="{}")
    assert "PP=unset" in r.stdout, r.stdout + r.stderr


def test_doctor_names_a_hook_by_its_exact_shape_only():
    import sys as _sys
    from phiward import doctor
    assert doctor.hook_form({"command": install.PROJECT_HOOK}) == "project"
    assert doctor.hook_form({"command": install.isolated_command(_sys.executable, "hook")}) == \
        "isolated"
    assert doctor.hook_form({"command": f"{_sys.executable} -I -m phiward hook claude"}) == \
        "launcher"  # an earlier form: the loader variables are not cleared
    assert doctor.hook_form({"type": "prompt",
                             "command": install.isolated_command(_sys.executable, "hook")}) == ""
    assert doctor.hook_form({"command": "/x/bin/phiward hook claude"}) == "launcher"
    for other in ("sh -c 'echo phiward hook claude'", "phiward hook claude",
                  f"{_sys.executable} -m phiward hook claude",
                  "sh -c 'exit 0; exec phiward hook claude'"):
        assert doctor.hook_form({"command": other}) == "", other


# --- third review: the hook's start-up and a project's env --------------------------------------

def _run_project_hook(tree, extra_env):
    import subprocess
    fake = tree / "fakebin"
    fake.mkdir(exist_ok=True)
    (fake / "phiward").write_text("#!/bin/sh\nenv\n")
    (fake / "phiward").chmod(0o755)
    body = install.PROJECT_HOOK.split("sh -c ", 1)[1][1:-1]
    return subprocess.run(["/bin/sh", "-c", body], capture_output=True, text=True, input="{}",
                          env=dict(PATH=f"{fake}:/usr/bin:/bin", **extra_env)).stdout


def test_the_bare_name_hook_clears_every_python_and_loader_variable(tree):
    out = _run_project_hook(tree, {"PYTHONPYCACHEPREFIX": "/x", "PYTHONPATH": "/evil",
                                   "PYTHONWHATEVER": "1", "LD_FOO": "1", "DYLD_BAR": "1",
                                   "KEEP_ME": "yes"})
    assert "KEEP_ME=yes" in out
    for name in ("PYTHONPYCACHEPREFIX", "PYTHONPATH", "PYTHONWHATEVER", "LD_FOO", "DYLD_BAR"):
        assert name not in out, out


@pytest.mark.parametrize("key", ["PYTHONUNBUFFERED", "PYTHONPATH", "LD_LIBRARY_PATH"])
def test_a_project_env_that_both_hook_forms_clear_is_not_refused(tree, key, monkeypatch):
    from phiward.core import ALLOW
    d = tree / "repo" / ".claude"
    d.mkdir()
    (d / "settings.json").write_text(json.dumps({"env": {key: "1"}}))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    dec = protected_paths.check(Action(FILE_READ, str(tree / "repo"),
                                       paths=(str(tree / "repo" / "README.md"),)),
                                config.load(str(tree / "repo")))
    assert dec.verdict == ALLOW


def test_install_refuses_a_python_that_cannot_import_phiward_isolated(tree, monkeypatch, capsys):
    import sys as _sys
    monkeypatch.delenv("PHIWARD_DEV")
    monkeypatch.setattr(_sys, "executable", "/usr/bin/false")
    monkeypatch.setattr(_sys, "stdin", type("Tty", (), {"isatty": lambda self: True})())
    monkeypatch.chdir(tree / "repo")
    assert install.main(["claude", "--user", "--write", "--yes"]) == 2
    assert "cannot import phiward" in capsys.readouterr().err
    assert not (tree / "home" / ".claude" / "settings.json").exists()


def test_merge_replaces_a_stale_isolated_hook(tree):
    w = install.wiring(config.load(str(tree / "repo")))
    stale = "'/old/env with space/bin/python' -I -m phiward hook claude"
    old = {"hooks": {"PreToolUse": [{"matcher": "Bash|Monitor|PowerShell", "hooks": [
        {"type": "command", "command": stale, "timeout": 10, "onFailure": "block"}]}]}}
    cmds = [h["command"] for g in install.merge(old, w)["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert stale not in cmds and w["hooks"]["PreToolUse"][0]["hooks"][0]["command"] in cmds


# --- third review: settings files Claude Code reads, and doctor --headless ----------------------

def _fake_worktree(tree, where):
    """A planted `.git` file and a fake git folder that only looks like a worktree's."""
    fake = tree / "pub" / "fake" / ".git"
    w = fake / "worktrees" / "w"
    w.mkdir(parents=True)
    for d in (fake, w):
        (d / "HEAD").write_text("ref: refs/heads/main\n")
        (d / "objects").mkdir(exist_ok=True)
    (w / "commondir").write_text("../..\n")
    where.mkdir(parents=True, exist_ok=True)
    (where / ".git").write_text(f"gitdir: {w}\n")
    return fake.parent


def test_a_planted_worktree_cannot_choose_the_local_file(tree):
    sub = tree / "repo" / "sub"
    _fake_worktree(tree, sub)  # no `gitdir` back-pointer: git refuses it
    assert claude_settings.local_file(str(sub), str(tree / "home")) == \
        str(sub / ".claude" / "settings.local.json")


def test_a_planted_empty_git_folder_is_not_a_repository_root(tree):
    repo = tree / "repo"
    _git("init", "-q", cwd=repo)
    (repo / "src" / ".git").mkdir()  # empty: git goes on to the real root
    assert claude_settings.local_file(str(repo / "src"), str(tree / "home")) == \
        str(repo / ".claude" / "settings.local.json")


def test_a_real_worktree_still_reads_the_main_checkout(tree):
    repo = tree / "repo"
    _git("init", "-q", cwd=repo)
    _git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q",
         "--allow-empty", "-m", "x", cwd=repo)
    _git("worktree", "add", "-q", str(tree / "wt2"), cwd=repo)
    assert claude_settings.local_file(str(tree / "wt2"), str(tree / "home")) == \
        str(repo / ".claude" / "settings.local.json")


def test_a_repository_root_owned_by_someone_else_is_not_a_candidate(tree, monkeypatch):
    up = tree / "pub" / "shared"
    (up / ".git").mkdir(parents=True)
    (up / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (up / ".git" / "objects").mkdir()
    (up / ".claude").mkdir()
    (up / ".claude" / "settings.local.json").write_text("")
    proj = up / "work"
    proj.mkdir()
    real = claude_settings._owned
    monkeypatch.setattr(claude_settings, "_owned",
                        lambda p: False if str(p).startswith(str(up)) and not str(p).startswith(str(proj)) else real(p))
    assert str(up / ".claude" / "settings.local.json") not in \
        claude_settings.local_candidates(str(proj), str(tree / "home"))


def test_an_empty_project_settings_file_is_empty_settings(tree, monkeypatch):
    from phiward.core import ALLOW
    d = tree / "repo" / ".claude"
    d.mkdir()
    (d / "settings.json").write_text("")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    dec = protected_paths.check(Action(FILE_READ, str(tree / "repo"),
                                       paths=(str(tree / "repo" / "README.md"),)),
                                config.load(str(tree / "repo")))
    assert dec.verdict == ALLOW


def test_the_refusal_names_the_unreadable_file(tree, monkeypatch):
    d = tree / "repo" / ".claude"
    d.mkdir()
    (d / "settings.json").write_text("{,}")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    dec = protected_paths.check(Action(FILE_READ, str(tree / "repo"),
                                       paths=(str(tree / "repo" / "README.md"),)),
                                config.load(str(tree / "repo")))
    assert dec.verdict == DENY and str(d / "settings.json") in dec.reason


def _headless_with(tree, user_hook=None, project=None, entry_extra=None, local=None):
    from phiward import doctor
    Path(os.environ["PHIWARD_CONFIG"]).write_text(f'[protected_paths]\nroots = ["{tree}/phi"]\n')
    data = install.merge({}, install.wiring(config.load(str(tree / "repo"))))
    for g in data["hooks"]["PreToolUse"]:
        for h in g["hooks"]:
            if user_hook is not None:
                h["command"] = user_hook
            h.update(entry_extra or {})
    if user_hook == "":
        data["hooks"]["PreToolUse"] = []
    d = tree / "home" / ".claude"
    d.mkdir(exist_ok=True)
    (d / "settings.json").write_text(json.dumps(data))
    if project is not None:
        p = tree / "repo" / ".claude"
        p.mkdir(exist_ok=True)
        (p / "settings.json").write_text(json.dumps(project))
    if local is not None:
        sub = tree / "repo" / "src" / ".claude"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "settings.local.json").write_text(json.dumps(local))
    return [p for p in doctor.headless_problems(str(tree / "repo"), str(tree / "home"))
            if "broker" not in p and "socat" not in p]


def test_headless_is_ready_with_the_isolated_user_hook(tree):
    assert _headless_with(tree) == []


@pytest.mark.parametrize("case", ["project_only", "legacy_launcher", "exit_first", "python3x",
                                  "no_isolation", "async", "if"])
def test_headless_is_not_ready_with_a_weaker_hook(tree, case):
    import shlex
    import sys as _sys
    py = shlex.quote(_sys.executable)
    hooks = {"legacy_launcher": f"{shutil.which('true')} hook claude",
             "exit_first": "sh -c 'exit 0; exec phiward hook claude'",
             "python3x": f"{py}x -m phiward hook claude",
             "no_isolation": f"{py} -m phiward hook claude"}
    if case == "project_only":
        proj = install.wiring(config.load(str(tree / "repo")), project=True,
                              project_dir=str(tree / "repo"))
        problems = _headless_with(tree, user_hook="", project=proj)
    elif case in ("async", "if"):
        problems = _headless_with(tree, entry_extra={"async": True} if case == "async"
                                  else {"if": "Bash(git *)"})
    else:
        problems = _headless_with(tree, user_hook=hooks[case])
    assert problems, case


def test_headless_reads_disable_all_hooks_from_every_candidate_file(tree):
    from phiward import doctor
    repo = tree / "repo"
    _git("init", "-q", cwd=repo)
    assert _headless_with(tree, local={"disableAllHooks": True}) == []  # not this session's
    # a session that starts in src: Claude Code reads the root's local file, phiward also
    # the starting folder's, which can only make the answer stricter
    problems = doctor.headless_problems(str(repo / "src"), str(tree / "home"))
    assert any("disableAllHooks" in p for p in problems), problems


# --- third review: the sanitizer keeps counts and plain words ----------------------------------

def test_counts_after_a_pattern_path_stay(tree):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/phi"]\n'
        f'patterns = ["{tree}/runs/*/panel", "{tree}/wild/phi_*"]\n')
    (tree / "wild" / "phi_A").mkdir(parents=True)
    (tree / "wild" / "phi_Moe Max" / "inner").mkdir(parents=True)
    san = Sanitizer.from_config(config.load(str(tree / "repo")), entries=True)
    assert san.clean(f"{tree}/wild/phi_A: 12 reads, 3 errors") == "<PROTECTED>: 12 reads, 3 errors" \
        or san.clean(f"{tree}/wild/phi_A: 12 reads, 3 errors").endswith(" 12 reads, 3 errors")
    # numbers after a space may be more of a name (`phi_A 4471`): masked (round 8)
    assert san.clean(f"{tree}/wild/phi_A 120 44 9") == "<PROTECTED>"
    assert san.clean("the gene panel covers 3 genes") == "the gene panel covers 3 genes"
    out = san.clean(f"{tree}/wild/phi_Moe Max/inner/f and more")
    assert out == "<PROTECTED>", out  # words after a space may be more of a name (round 8)


# --- fourth review: masking never trades a name for a count -------------------------------------

@pytest.mark.parametrize("line,secret", [
    ("{t}/wild/phi_Yo Yo", "Yo Yo"),
    ("ls: {t}/wild/phi_Yo Yo: Permission denied", "Yo Yo"),
    ("{t}/wild/phi_Zed, Quux/in/f", "Zed Quux"),
    ("{t}/wild/phi_Odd: Name/in/x", "Odd Name"),
    ("{t}/runs/my run/panel", "my run"),
])
def test_a_spaced_name_under_a_pattern_never_leaks(tree, line, secret):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/phi"]\n'
        f'patterns = ["{tree}/runs/*/panel", "{tree}/wild/phi_*"]\n')
    for name in ("phi_Yo Yo", "phi_Zed, Quux/in", "phi_Odd: Name/in"):
        (tree / "wild" / name).mkdir(parents=True, exist_ok=True)
    (tree / "runs" / "my run" / "panel").mkdir(parents=True)
    san = Sanitizer.from_config(config.load(str(tree / "repo")), entries=True)
    out = san.clean(line.format(t=tree))
    for word in secret.split():  # every word of the name, not only the last
        assert not re.search(rf"(?<![A-Za-z]){word}(?![A-Za-z])", out), (word, out)


# --- fourth review: settings files ------------------------------------------------------------

def test_every_candidate_local_file_must_agree(tree):
    cfg = _wire_user(tree)
    data = json.loads((tree / "home" / ".claude" / "settings.json").read_text())
    data["sandbox"]["filesystem"]["denyRead"] = []  # the user file alone does not cover
    (tree / "home" / ".claude" / "settings.json").write_text(json.dumps(data))
    repo = tree / "repo"
    _git("init", "-q", cwd=repo)
    plant = repo / "src"
    (plant / ".git" / "objects").mkdir(parents=True)
    (plant / ".git" / "refs").mkdir()
    (plant / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (plant / ".claude").mkdir()
    (plant / ".claude" / "settings.local.json").write_text(json.dumps({"sandbox": {
        "filesystem": {"denyRead": [str(tree / "phi")], "denyWrite": [str(tree / "phi")]}}}))
    ok, why = _confined_at(tree, plant, cfg)
    assert not ok, why


@pytest.mark.parametrize("text", ["{,}", '{"sandbox": NaN}', "﻿{}"])
def test_an_unreadable_user_settings_file_means_not_confined(tree, text):
    cfg = _wire_user(tree)
    (tree / "home" / ".claude" / "settings.json").write_text(text)
    ok, why = _confined_at(tree, tree / "repo", cfg)
    assert not ok and "cannot be read" in why, why


def test_owned_is_true_only_for_a_missing_path(tree, monkeypatch):
    def boom(*a, **k):
        raise PermissionError
    monkeypatch.setattr(os, "stat", boom)
    assert claude_settings._owned(str(tree / "repo")) is False


def test_a_git_folder_without_refs_is_not_a_repository(tree):
    repo = tree / "repo"
    _git("init", "-q", cwd=repo)
    plant = repo / "src" / ".git"
    (plant / "objects").mkdir(parents=True)
    (plant / "HEAD").write_text("ref: refs/heads/main\n")
    assert claude_settings.local_file(str(repo / "src"), str(tree / "home")) == \
        str(repo / ".claude" / "settings.local.json")


def test_a_git_link_to_a_folder_counts(tree):
    real = tree / "pub" / "realgit"
    _git("init", "-q", cwd=tree / "pub")
    os.rename(tree / "pub" / ".git", real)
    os.symlink(real, tree / "pub" / ".git")
    (tree / "pub" / "sub").mkdir()  # a session in a subfolder reads the root's file
    assert claude_settings.local_file(str(tree / "pub" / "sub"), str(tree / "home")) == \
        str(tree / "pub" / ".claude" / "settings.local.json")


# --- fifth review: the hook's start-up --------------------------------------------------------

def _hook_marker(tree):
    """A stand-in for phiward's Python that leaves a file when it runs."""
    fake = tree / "fakepython"
    fake.write_text(f"#!/bin/sh\ntouch {tree}/RAN\n")
    fake.chmod(0o755)
    return fake


@pytest.mark.parametrize("form", ["user", "project"])
def test_the_hook_stops_when_its_clean_up_cannot_run(tree, form):
    import subprocess
    fake = _hook_marker(tree)
    cmd = (install.isolated_command(str(fake), "hook") if form == "user"
           else install.PROJECT_HOOK.replace("exec phiward", f"exec {fake}")
           .replace("command -v phiward", f"command -v {fake}"))
    assert "/usr/bin/awk" in cmd
    broken = cmd.replace("/usr/bin/awk", str(tree / "no-awk"))
    r = subprocess.run(broken, shell=True, capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "LD_PRELOAD": "/evil.so"})
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert not (tree / "RAN").exists()
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "LD_PRELOAD": "/evil.so"})
    assert r.returncode == 0 and (tree / "RAN").exists(), r.stderr


@pytest.mark.parametrize("key", ["SHELLOPTS", "BASHOPTS", "PS4", "BASH_ENV", "ENV",
                                 "PROMPT_COMMAND", "IFS", "CDPATH", "GLOBIGNORE",
                                 "BASH_FUNC_ls%%", "PATH", "CLAUDE_PROJECT_DIR"])
def test_a_project_env_that_steers_the_hook_shell_is_listed(tree, key):
    (tree / "repo" / ".claude").mkdir()
    (tree / "repo" / ".claude" / "settings.json").write_text(json.dumps({"env": {key: "x"}}))
    assert key in claude_settings.project_redirects(str(tree / "repo"), str(tree / "home"))


def test_install_json_and_headless_check_the_clean_up_tool(tree, monkeypatch, capsys):
    from phiward import doctor
    monkeypatch.setattr(install, "CLEAN_TOOLS", ("/nonexistent/awk",))
    monkeypatch.setattr("sys.stdin", type("Tty", (), {"isatty": lambda self: True})())
    monkeypatch.chdir(tree / "repo")
    assert install.main(["claude", "--user", "--json"]) == 2
    assert "/nonexistent/awk" in capsys.readouterr().err
    probs = doctor.headless_problems(str(tree / "repo"), str(tree / "home"))
    assert any("/nonexistent/awk" in p for p in probs), probs


def test_owned_is_true_for_a_missing_path(tree):
    assert claude_settings._owned(str(tree / "nothing-here")) is True


@pytest.mark.slow
def test_many_folders_under_a_pattern_build_the_sanitizer_fast(tree):
    import time
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/phi"]\npatterns = ["{tree}/wild/phi_*"]\n')
    for i in range(20000):
        (tree / "wild" / f"phi_Fake Name {i:05d}").mkdir(parents=True)
    start = time.monotonic()
    san = Sanitizer.from_config(config.load(str(tree / "repo")), entries=True)
    took = time.monotonic() - start
    out = san.clean(f"{tree}/wild/phi_Fake Name 00042: 12 reads")
    assert "Fake" not in out and out.endswith(": 12 reads"), out
    assert took < 15.0, took


def test_the_hook_refuses_every_call_while_a_project_env_steers_it(tree, monkeypatch):
    (tree / "repo" / ".claude").mkdir()
    (tree / "repo" / ".claude" / "settings.json").write_text(
        json.dumps({"env": {"SHELLOPTS": "xtrace"}}))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command="ls"),
                              config.load(str(tree / "repo")))
    assert d.verdict == DENY and "env.SHELLOPTS" in d.reason, d.reason


def test_the_plugin_and_project_hooks_start_sh_by_path():
    assert install.PROJECT_HOOK.startswith("/bin/sh -c ")
    assert install.PROJECT_NOTE.startswith("/bin/sh -c ")


# --- sixth review: a name on disk is masked whole, whatever it holds -----------------------------

@pytest.mark.parametrize("folders,line,secret", [
    (["phi_Ann", "phi_Ann Zorroquux Vexlar"], "{t}/wild/phi_Ann Zorroquux Vexlar", "Zorroquux Vexlar"),
    (["phi_Ann", "phi_Ann Zorroquux Vexlar"], "{t}/wild/phi_Ann Zorroquux Vexlar/sub/x.bam: 3",
     "Zorroquux Vexlar"),
    (["phi_Doe", "phi_Doe Jane"], "error in {t}/wild/phi_Doe Jane.", "Jane"),
    (["phi_O'Brien Pat"], "{t}/wild/phi_O'Brien Pat: 12 reads", "Brien Pat"),
    (["phi_Doe (Jane)"], "{t}/wild/phi_Doe (Jane)/x", "Doe Jane"),
    (["phi_Lee&Kim Zed"], "{t}/wild/phi_Lee&Kim Zed done", "Lee Kim Zed"),
])
def test_a_name_on_disk_is_masked_whole(tree, folders, line, secret):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/phi"]\npatterns = ["{tree}/wild/phi_*"]\n')
    for f in folders:
        (tree / "wild" / f).mkdir(parents=True, exist_ok=True)
    out = Sanitizer.from_config(config.load(str(tree / "repo")), entries=True).clean(
        line.format(t=tree))
    for word in secret.split():
        assert not re.search(rf"(?<![A-Za-z]){word}(?![A-Za-z])", out), (word, out)


def test_a_long_line_under_a_pattern_is_masked_fast(tree):
    import time
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/phi"]\npatterns = ["{tree}/wild/phi_*"]\n')
    (tree / "wild" / "phi_A").mkdir(parents=True)
    san = Sanitizer.from_config(config.load(str(tree / "repo")), entries=True)
    line = f"{tree}/wild/phi_A" + " a b" * 50000
    start = time.monotonic()
    san.clean(line)
    assert time.monotonic() - start < 2.0


def test_doctor_notes_loader_variables_a_project_sets(tree, monkeypatch, capsys):
    from phiward import doctor
    (tree / "repo" / ".claude").mkdir()
    (tree / "repo" / ".claude" / "settings.json").write_text(
        json.dumps({"env": {"LD_LIBRARY_PATH": "/opt/lib"}}))
    assert claude_settings.project_loader_keys(str(tree / "repo"), str(tree / "home")) == \
        ["LD_LIBRARY_PATH"]
    assert claude_settings.project_redirects(str(tree / "repo"), str(tree / "home")) == []
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.chdir(tree / "repo")
    doctor.main([])
    assert "NOTE: this project's Claude Code settings set env.LD_LIBRARY_PATH" in \
        capsys.readouterr().out


# --- seventh review: no part of a name leaks, whatever its letters ------------------------------

def _wild(tree, *folders):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/phi"]\npatterns = ["{tree}/wild/phi_*"]\n')
    for f in folders:
        (tree / "wild" / f).mkdir(parents=True, exist_ok=True)
    return Sanitizer.from_config(config.load(str(tree / "repo")), entries=True)


def _gone(out, words):
    for word in words.split():
        assert not re.search(rf"(?<![A-Za-z]){re.escape(word)}(?![A-Za-z])", out), (word, out)


@pytest.mark.skipif(sys.platform != "darwin", reason="case folding is macOS's")
@pytest.mark.parametrize("name,words", [("phi_Straße O'Brien Pat", "Brien Pat"),
                                        ("phi_İstanbul O'Neil", "Neil")])
def test_a_name_whose_case_folded_form_is_longer_is_masked_whole(tree, name, words):
    out = _wild(tree, "phi_Ann", name).clean(f"{tree}/wild/{name}: 3")
    _gone(out, words)


@pytest.mark.parametrize("line,words", [
    ("{t}/wild/phi_New;Quux Smith", "Quux Smith"),
    ("{t}/wild/phi_New'Quux Smith", "Quux Smith"),
    ("{t}/wild/phi_New(Quux Smith)", "Quux Smith"),
    ("{t}/wild/phi_Newname&Other Person", "Other Person"),
    ("{t}/wild/phi_Ann:1 Smith Jones", "Smith Jones"),
    ("{t}/wild/phi_Ann,5 Carol Dan", "Carol Dan"),
    ("wrote {t}/phi/New Person 7/x.bam: 3", "Person"),
])
def test_a_name_not_on_disk_never_leaks(tree, line, words):
    _gone(_wild(tree, "phi_Ann").clean(line.format(t=tree)), words)


def test_counts_after_a_name_on_disk_still_stay(tree):
    san = _wild(tree, "phi_A")
    assert san.clean(f"{tree}/wild/phi_A: 12 reads, 3 errors").endswith(": 12 reads, 3 errors")
    assert san.clean(f"{tree}/wild/phi_A 120 44 9") == "<PROTECTED>"  # may be a longer name
    assert san.clean(f"cat {tree}/phi/FAKE-PT-0001.bam /tmp/out").endswith(" /tmp/out")


def test_the_hook_reads_the_project_of_the_call_too(tree, monkeypatch):
    decoy = tree / "pub" / "decoy"
    decoy.mkdir(parents=True)
    (tree / "repo" / ".claude").mkdir()
    (tree / "repo" / ".claude" / "settings.json").write_text(
        json.dumps({"env": {"SHELLOPTS": "xtrace"}}))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(decoy))  # pointed away from the real project
    d = protected_paths.check(Action(SHELL, str(tree / "repo" / "src"), command="ls"),
                              config.load(str(tree / "repo")))
    assert d.verdict == DENY and "env.SHELLOPTS" in d.reason, d.reason
    assert str(tree / "repo") in claude_settings.project_folders(str(tree / "repo" / "src"),
                                                                 str(tree / "home"))
