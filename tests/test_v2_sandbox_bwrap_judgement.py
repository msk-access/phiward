"""The bwrap and socat Claude Code's sandbox runs (PR 3, threat-model gap 14).

On Linux, sandbox-runtime runs `bwrap` and `socat` by bare name for each wrapped command (C2,
measured), so the first one on Claude Code's PATH confines the shell. A PATH folder the agent can
write before it (a project's `.venv/bin`, an empty or relative entry, an allowWrite folder) lets
the agent put one there that runs the next command unconfined. A `denyWrite` glob cannot close
that on Linux (P3-4, measured: srt skips write globs), so the hook refuses while such a folder
comes first. A group-writable prefix is a warning until PR 7 (the operator, 2026-11-27).

Made-up trees and stubs only. The Linux tests patch `sys.platform`, so they run on a Mac too.
"""

import json
import os
import sys

import pytest

from phiward import adapters, claude_settings, config, doctor
from phiward.core import ALLOW, DENY, FILE_WRITE, SHELL, Action, Decision

# the real system folders, mapped into each test's tree by `lin`
REAL_SYSTEM = claude_settings.SYSTEM_PREFIXES
REAL_LAUNCH_ENV = claude_settings._launch_env
STUB = "#!/bin/sh\nexit 0\n"


def _prog(folder, name="bwrap"):
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / name
    p.write_text(STUB)
    p.chmod(0o755)
    return p


def _path(*parts):
    return ":".join(str(p) for p in parts)


@pytest.fixture
def lin(tree, monkeypatch):
    """Linux, with made-up temp and system folders (the real /tmp is agent-writable, and the
    trees live under it), a safe made-up prefix `home/claude-env` holding bwrap and socat, and
    the session's project `repo`."""
    monkeypatch.setattr(sys, "platform", "linux")
    (tree / "tmp").mkdir()
    monkeypatch.setattr(claude_settings, "_temp_roots", lambda: [str(tree / "tmp")])
    monkeypatch.setattr(claude_settings, "SYSTEM_PREFIXES",
                        tuple(str(tree) + s for s in REAL_SYSTEM), raising=False)
    monkeypatch.setattr(claude_settings, "_launch_env", dict)
    env = tree / "home" / "claude-env"
    _prog(env / "bin", "bwrap")
    _prog(env / "bin", "socat")
    (env / "lib").mkdir()
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    return env


def _problem(tree, path, name="bwrap"):
    return claude_settings.sandbox_program_problem(name, path, str(tree / "repo"),
                                                   str(tree / "home"))


def _decided(tree, monkeypatch, path, settings_env_path=None):
    """The action the hook hands to the guards for a sandboxed Bash call, with `path` as the
    hook's (Claude Code's) PATH."""
    monkeypatch.setenv("PATH", path)
    monkeypatch.setattr(claude_settings, "named_project_holds", lambda cwd: True)
    monkeypatch.setattr(claude_settings, "shell_reason", lambda *a, **k: None)
    monkeypatch.setattr(claude_settings, "excluded_entries", lambda *a, **k: [])
    if settings_env_path is not None:
        d = tree / "repo" / ".claude"
        d.mkdir(exist_ok=True)
        (d / "settings.json").write_text(json.dumps({"env": {"PATH": settings_env_path}}))
    seen = {}

    def dispatch(action, cfg, guards):
        seen["action"] = action
        return Decision(ALLOW)
    monkeypatch.setattr(adapters, "dispatch", dispatch)
    adapters.decide(Action(SHELL, str(tree / "repo"), command="ls", tool="Bash"),
                    claude_sandbox=True)
    return seen["action"]


# --- the judgement --------------------------------------------------------------------------

def test_a_project_venv_first_on_path_is_refused_with_the_deactivate_step(tree, lin):
    _prog(tree / "repo" / ".venv" / "bin")
    r = _problem(tree, _path(tree / "repo" / ".venv" / "bin", lin / "bin"))
    assert r is not None and "deactivate" in r.step, r


def test_a_venv_folder_with_no_bwrap_yet_is_refused_too(tree, lin):
    # the agent can put one there between the hook's check and the next command (C2)
    (tree / "repo" / ".venv" / "bin").mkdir(parents=True)
    r = _problem(tree, _path(tree / "repo" / ".venv" / "bin", lin / "bin"))
    assert r is not None and "deactivate" in r.step, r


def test_an_empty_entry_counts_as_the_project(tree, lin):
    r = _problem(tree, ":" + str(lin / "bin"))
    assert r is not None, r


def test_an_allow_write_folder_before_the_bwrap_is_refused(tree, lin):
    s = claude_settings.user_dir(str(tree / "home"))
    os.makedirs(s, exist_ok=True)
    with open(os.path.join(s, "settings.json"), "w") as fh:
        json.dump({"sandbox": {"filesystem": {"allowWrite": [str(tree / "pub")]}}}, fh)
    r = _problem(tree, _path(tree / "pub", lin / "bin"))
    assert r is not None, r


def test_a_safe_prefix_first_on_path_passes(tree, lin):
    # regression: also passes on develop's behaviour of judging nothing
    assert _problem(tree, _path(lin / "bin")) is None


def test_a_missing_entry_outside_what_the_agent_writes_passes(tree, lin):
    # PATH often lists folders that do not exist (~/.cargo/bin) (review H3)
    assert _problem(tree, _path(tree / "nowhere" / "bin", lin / "bin")) is None


def test_a_missing_entry_inside_the_project_is_refused(tree, lin):
    # the agent can make it
    r = _problem(tree, _path(tree / "repo" / ".venv" / "bin", lin / "bin"))
    assert r is not None, r


def test_an_entry_in_a_loop_of_links_cannot_be_decided(tree, lin):
    os.symlink(tree / "loopb", tree / "loopa")
    os.symlink(tree / "loopa", tree / "loopb")
    r = _problem(tree, _path(tree / "loopa", lin / "bin"))
    assert r is not None and str(tree / "loopa") in r.step, r


def test_a_bwrap_with_a_second_name_is_refused(tree, lin):
    os.link(lin / "bin" / "bwrap", lin / "bin" / "bwrap-again")
    r = _problem(tree, _path(lin / "bin"))
    assert r is not None and "setup" in r.step, r


def test_a_hard_linked_system_bwrap_passes(tree, lin):
    # ostree systems hard-link /usr/bin (review M5): st_nlink counts outside /usr and /bin only
    sysbin = tree / "usr" / "bin"
    b = _prog(sysbin)
    os.link(b, sysbin / "bubblewrap")
    assert _problem(tree, _path(sysbin)) is None


def test_a_link_to_a_safe_bwrap_is_judged_by_its_target(tree, lin):
    hb = tree / "home" / "bin"
    hb.mkdir()
    os.symlink(lin / "bin" / "bwrap", hb / "bwrap")
    assert _problem(tree, _path(hb)) is None


def test_a_link_in_a_folder_the_agent_writes_is_refused(tree, lin):
    tools = tree / "repo" / "tools"
    tools.mkdir()
    os.symlink(lin / "bin" / "bwrap", tools / "bwrap")
    r = _problem(tree, _path(tools))
    assert r is not None, r


def test_a_world_writable_lib_is_refused_with_the_chmod_step(tree, lin):
    (lin / "lib").chmod(0o777)
    r = _problem(tree, _path(lin / "bin"))
    assert r is not None and "chmod -R go-w" in r.step, r


def test_a_group_writable_lib_is_only_a_warning_until_pr7(tree, lin):
    (lin / "lib").chmod(0o775)
    assert _problem(tree, _path(lin / "bin")) is None
    lines = doctor.sandbox_program_lines(str(tree / "repo"), str(tree / "home"),
                                         _path(lin / "bin"))
    text = "\n".join(lines)
    assert "WARNING" in text and "chmod" in text, text


def test_socat_is_judged_too(tree, lin):
    _prog(tree / "repo" / ".venv" / "bin", "socat")
    r = _problem(tree, _path(tree / "repo" / ".venv" / "bin", lin / "bin"), name="socat")
    assert r is not None, r


# --- the hook -------------------------------------------------------------------------------

def test_the_hook_refuses_a_bash_call_while_a_venv_comes_first(tree, lin, monkeypatch):
    _prog(tree / "repo" / ".venv" / "bin")
    a = _decided(tree, monkeypatch, _path(tree / "repo" / ".venv" / "bin", lin / "bin"))
    assert not a.confined and "bwrap" in a.unconfined_why and "deactivate" in a.unconfined_step, a


def test_the_hook_judges_socat_after_bwrap(tree, lin, monkeypatch):
    _prog(tree / "repo" / ".venv" / "bin", "socat")
    a = _decided(tree, monkeypatch, _path(tree / "repo" / ".venv" / "bin", lin / "bin"))
    assert not a.confined and "socat" in a.unconfined_why, a


def test_the_hook_judges_a_settings_env_path_too(tree, lin, monkeypatch):
    # P3-1 is read, not measured: Claude Code applies settings env.PATH to its own process, so
    # the hook also judges it (fail closed)
    _prog(tree / "repo" / ".venv" / "bin")
    a = _decided(tree, monkeypatch, _path(lin / "bin"),
                 settings_env_path=_path(tree / "repo" / ".venv" / "bin", lin / "bin"))
    assert not a.confined and "bwrap" in a.unconfined_why, a


def test_the_hook_passes_a_safe_prefix(tree, lin, monkeypatch):
    a = _decided(tree, monkeypatch, _path(lin / "bin"))
    assert a.confined, a


def test_macos_judges_nothing(tree, lin, monkeypatch):
    # regression: macOS's sandbox is /usr/bin/sandbox-exec, which no PATH picks
    _prog(tree / "repo" / ".venv" / "bin")
    monkeypatch.setattr(sys, "platform", "darwin")
    a = _decided(tree, monkeypatch, _path(tree / "repo" / ".venv" / "bin", lin / "bin"))
    assert a.confined, a


def test_a_file_tool_write_into_the_prefix_is_refused(tree, lin, monkeypatch):
    monkeypatch.setenv("PATH", _path(lin / "bin"))
    target = str(lin / "lib" / "x")
    d = adapters.decide(Action(FILE_WRITE, str(tree / "repo"), paths=(target,), tool="Write"))
    assert not d.allowed, d


# --- review round 1 (2026-11-27) ------------------------------------------------------------

def test_a_project_venv_that_is_a_link_out_is_refused(tree, lin):
    # review 1: the agent can replace the link `.venv` with a folder of its own
    out = tree / "venvs" / "x" / "bin"
    out.mkdir(parents=True)
    os.symlink(tree / "venvs" / "x", tree / "repo" / ".venv")
    r = _problem(tree, _path(tree / "repo" / ".venv" / "bin", lin / "bin"))
    assert r is not None, r


def test_a_link_on_the_way_through_a_temp_folder_is_refused(tree, lin):
    # review 1: home/bin/bwrap -> tmp/l -> the safe bwrap; the agent can change tmp/l
    hb = tree / "home" / "bin"
    hb.mkdir()
    os.symlink(lin / "bin" / "bwrap", tree / "tmp" / "l")
    os.symlink(tree / "tmp" / "l", hb / "bwrap")
    r = _problem(tree, _path(hb))
    assert r is not None, r


def test_a_bwrap_in_home_bin_does_not_guard_the_whole_home(tree, lin, monkeypatch):
    # review 2: the prefix of ~/bin/bwrap is ~; only the program's own folders are guarded
    hb = tree / "home" / "bin"
    _prog(hb)
    _prog(hb, "socat")
    monkeypatch.setenv("PATH", _path(hb))
    places = claude_settings.sandbox_prefixes(str(tree / "home"))
    assert str(tree / "home") not in places and str(hb) in places, places
    d = adapters.decide(Action(FILE_WRITE, str(tree / "repo"),
                               paths=(str(tree / "home" / "notes.txt"),), tool="Write"))
    assert d.verdict != DENY or "guard" not in d.reason, d


def test_a_write_of_bwrap_into_a_path_folder_before_it_is_refused(tree, lin, monkeypatch):
    # review 3: ~/bin comes first and holds no bwrap; a file tool may not put one there
    hb = tree / "home" / "bin"
    hb.mkdir()
    monkeypatch.setenv("PATH", _path(hb, lin / "bin"))
    d = adapters.decide(Action(FILE_WRITE, str(tree / "repo"), paths=(str(hb / "bwrap"),),
                               tool="Write"))
    assert d.verdict == DENY, d


def test_a_world_writable_usr_local_bwrap_is_refused(tree, lin):
    # review 5: only the system's own bin folders are exempt, not all of /usr
    ul = tree / "usr" / "local" / "bin"
    _prog(ul).chmod(0o777)
    r = _problem(tree, _path(ul))
    assert r is not None, r


def test_a_settings_env_path_refusal_names_the_settings_file(tree, lin, monkeypatch):
    # review 6a: restarting from another shell does not change a settings env.PATH
    _prog(tree / "repo" / ".venv" / "bin")
    s = claude_settings.user_dir(str(tree / "home"))
    os.makedirs(s, exist_ok=True)
    with open(os.path.join(s, "settings.json"), "w") as fh:
        json.dump({"env": {"PATH": _path(tree / "repo" / ".venv" / "bin", lin / "bin")}}, fh)
    a = _decided(tree, monkeypatch, _path(lin / "bin"))
    assert not a.confined and os.path.join(s, "settings.json") in a.unconfined_step, a


def test_an_entry_that_cannot_be_looked_at_says_to_leave_it_out(tree, lin):
    # review 6b: doctor cannot help with a folder the user may not open
    if os.getuid() == 0:
        pytest.skip("root opens every folder")
    shut = tree / "shut"
    (shut / "bin").mkdir(parents=True)
    shut.chmod(0)
    try:
        r = _problem(tree, _path(shut / "bin", lin / "bin"))
    finally:
        shut.chmod(0o755)
    assert r is not None and str(shut / "bin") in r.step, r


def test_a_loader_path_the_agent_can_write_is_refused(tree, lin, monkeypatch):
    # review 4: bwrap is not setuid, so LD_LIBRARY_PATH from Claude Code's start loads a
    # planted library into it
    monkeypatch.setattr(claude_settings, "_launch_env",
                        lambda: {"LD_LIBRARY_PATH": str(tree / "repo" / "lib")})
    a = _decided(tree, monkeypatch, _path(lin / "bin"))
    assert not a.confined and "LD_LIBRARY_PATH" in a.unconfined_why, a


def test_a_settings_env_preload_the_agent_can_write_is_refused(tree, lin, monkeypatch):
    s = claude_settings.user_dir(str(tree / "home"))
    os.makedirs(s, exist_ok=True)
    with open(os.path.join(s, "settings.json"), "w") as fh:
        json.dump({"env": {"LD_PRELOAD": str(tree / "tmp" / "x.so")}}, fh)
    a = _decided(tree, monkeypatch, _path(lin / "bin"))
    assert not a.confined and "LD_PRELOAD" in a.unconfined_why, a


def test_a_safe_loader_path_passes(tree, lin, monkeypatch):
    monkeypatch.setattr(claude_settings, "_launch_env",
                        lambda: {"LD_LIBRARY_PATH": str(lin / "lib"), "LD_PRELOAD": "libx.so"})
    a = _decided(tree, monkeypatch, _path(lin / "bin"))
    assert a.confined, a


def test_a_lib_folder_that_links_into_the_project_is_refused(tree, lin):
    # review 4: `_owned_safe` stats through the link and sees the user as owner
    (lin / "lib").rmdir()
    (tree / "repo" / "lib").mkdir()
    os.symlink(tree / "repo" / "lib", lin / "lib")
    r = _problem(tree, _path(lin / "bin"))
    assert r is not None, r


# --- review round 2 (2026-11-27) ------------------------------------------------------------

def test_an_excluded_commands_list_does_not_skip_the_bwrap_check(tree, lin, monkeypatch):
    # review 2.1: the text check cannot see what a planted bwrap runs
    _prog(tree / "repo" / ".venv" / "bin")
    monkeypatch.setenv("PATH", _path(tree / "repo" / ".venv" / "bin", lin / "bin"))
    monkeypatch.setattr(claude_settings, "named_project_holds", lambda cwd: True)
    monkeypatch.setattr(claude_settings, "shell_reason", lambda *a, **k: None)
    monkeypatch.setattr(claude_settings, "excluded_entries", lambda *a, **k: ["docker"])
    monkeypatch.setattr(claude_settings, "excluded_step", lambda *a, **k: ("f", "step"))
    seen = {}
    monkeypatch.setattr(adapters, "dispatch",
                        lambda action, cfg, guards: seen.update(a=action) or Decision(ALLOW))
    adapters.decide(Action(SHELL, str(tree / "repo"), command="ls", tool="Bash"),
                    claude_sandbox=True)
    a = seen["a"]
    assert "bwrap" in a.unconfined_why and not a.text_checked, a


def test_a_no_phi_folder_does_not_relax_a_planted_bwrap(tree, lin, monkeypatch):
    # review 2.1: no_phi relaxes only what the sandbox openers alone leave
    _prog(tree / "repo" / ".venv" / "bin")
    monkeypatch.setenv("PATH", _path(tree / "repo" / ".venv" / "bin", lin / "bin"))
    monkeypatch.setattr(claude_settings, "named_project_holds", lambda cwd: True)
    monkeypatch.setattr(claude_settings, "shell_reason",
                        lambda *a, **k: claude_settings.Reason("an opener", "step"))
    monkeypatch.setattr(claude_settings, "no_phi_relaxed", lambda *a, **k: ("x", None))
    real_load = config.load

    def load(cwd):
        c = real_load(cwd)
        c.no_phi_folders = ["x"]
        return c
    monkeypatch.setattr(config, "load", load)
    seen = {}
    monkeypatch.setattr(adapters, "dispatch",
                        lambda action, cfg, guards: seen.update(a=action, c=cfg) or Decision(ALLOW))
    adapters.decide(Action(SHELL, str(tree / "repo"), command="ls", tool="Bash"),
                    claude_sandbox=True)
    assert "bwrap" in seen["a"].unconfined_why and not seen["c"].no_phi_here, seen


def test_a_settings_path_equal_to_the_hooks_names_the_settings_file(tree, lin, monkeypatch):
    # review 2.2: Claude Code applies settings env.PATH to itself, so the hook inherits it
    _prog(tree / "repo" / ".venv" / "bin")
    p = _path(tree / "repo" / ".venv" / "bin", lin / "bin")
    s = claude_settings.user_dir(str(tree / "home"))
    os.makedirs(s, exist_ok=True)
    with open(os.path.join(s, "settings.json"), "w") as fh:
        json.dump({"env": {"PATH": p}}, fh)
    a = _decided(tree, monkeypatch, p)
    assert os.path.join(s, "settings.json") in a.unconfined_step, a


def test_no_proc_on_linux_is_refused(tree, lin, monkeypatch):
    # review 2.3: the hook's own environment has no loader variables (clean-exec.sh), so an
    # environment that cannot be read is no answer
    def gone():
        raise FileNotFoundError(2, "No such file or directory")
    monkeypatch.setattr(claude_settings, "_read_parent_environ", gone, raising=False)
    monkeypatch.setattr(claude_settings, "_launch_env", REAL_LAUNCH_ENV)
    r = claude_settings.loader_reason(str(tree / "repo"), str(tree / "home"))
    assert r is not None, r


def test_a_prefix_that_holds_the_project_does_not_guard_it(tree, lin, monkeypatch):
    # review 2.4: a lab folder with bin/ and projects/ in it
    lab = tree / "lab"
    _prog(lab / "bin")
    _prog(lab / "bin", "socat")
    proj = lab / "projects" / "x"
    proj.mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(proj))
    monkeypatch.setenv("PATH", _path(lab / "bin"))
    places = claude_settings.sandbox_prefixes(str(tree / "home"))
    assert str(lab) not in places and str(lab / "bin") in places, places


def test_an_empty_loader_entry_says_where_it_is(tree, lin):
    # review 2.5: a trailing `:` from an rc file
    r = claude_settings.loader_reason(str(tree / "repo"), str(tree / "home"),
                                      env={"LD_LIBRARY_PATH": "/opt/x/lib:"})
    assert r is not None and "empty" in r.text, r
