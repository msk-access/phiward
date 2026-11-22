"""macOS: `phiward launch` runs the tool with no Python helper in between.

The tool's profile is a file in `~/.phiward/profiles` (as the gateway's is), and the command is
`/usr/bin/sandbox-exec -f FILE TOOL ARGS...`, the tool by its full path, found on the session's
`PATH` before the start. A launch inside a session decides from two facts, both: the canary at
the account's home folder (never `HOME`) is denied with EPERM, and a new file can be made in
this session's own run folder (`PHIWARD_RUN`, of one exact shape under the account's home, with
no link on the way). Static unless marked: the backend is set to Seatbelt and `sandbox-exec` is
a made-up recorder, so these run on every platform and start no real sandbox. Made-up names only.
"""

import errno
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import confine, config, wholetool

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
NAME = re.compile(r"[0-9a-f]{32}\.sb")
RUN_ID = "20261122-101010-0a1b2c3d"
ci_macos = pytest.mark.skipif(
    sys.platform != "darwin" or not os.environ.get("GITHUB_ACTIONS"),
    reason="macOS on GitHub Actions only: no sandbox is started on a maintainer's machine")


@pytest.fixture()
def seatbelt(monkeypatch):
    monkeypatch.setattr(confine, "backend", lambda: "seatbelt")
    from phiward import selfcheck
    monkeypatch.setattr(selfcheck, "check_isolated", lambda *a, **k: (False, []))


@pytest.fixture()
def recorder(tree, monkeypatch, seatbelt):
    """A made-up `sandbox-exec`: it saves its arguments and the profile file it is given to
    $REC, then runs the command (no sandbox)."""
    fake = tree / "bin-fake" / "sandbox-exec"
    fake.parent.mkdir()
    fake.write_text('#!/bin/sh\n[ "$1" = -f ] || exit 99\ncp "$2" "$REC" || exit 98\n'
                    'shift 2\nexec "$@"\n')
    fake.chmod(0o755)
    monkeypatch.setattr(confine, "SANDBOX_EXEC", str(fake))
    monkeypatch.setenv("REC", str(tree / "recorded.sb"))
    return tree / "recorded.sb"


def _build(tree, argv, env=None):
    env = dict(os.environ) if env is None else env
    return wholetool.build(argv, str(tree / "repo"), env, wholetool.ADAPTERS["generic"])


def _profiles(tree) -> Path:
    return tree / "home" / ".phiward" / "profiles"


# --- the command ------------------------------------------------------------------------------

def test_the_tool_runs_from_a_profile_file_with_no_python_word(tree, seatbelt):
    cmd, child_env, fds, _project, _ready = _build(tree, ["/bin/echo", "FAKE-PT-0001"])
    assert fds == []
    assert cmd[:2] == [confine.SANDBOX_EXEC, "-f"], cmd
    assert cmd[3:] == ["/bin/echo", "FAKE-PT-0001"], cmd
    assert "-p" not in cmd[:3] and "-c" not in cmd and sys.executable not in cmd, cmd
    p = Path(cmd[2])
    assert p.parent == _profiles(tree) and NAME.fullmatch(p.name), p
    text = p.read_text()
    assert text.startswith("(version 1)") and wholetool.CANARY in text
    confine.release_profile(cmd)
    assert not p.exists()


def test_a_bare_name_is_found_on_the_sessions_path(tree, seatbelt, monkeypatch):
    tools = tree / "made-up-tools"
    tools.mkdir()
    tool = tools / "fake-agent"
    tool.write_text("#!/bin/sh\nexit 0\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tools}:{os.environ.get('PATH', '/usr/bin:/bin')}")
    cmd, *_ = _build(tree, ["fake-agent", "--made-up"])
    assert cmd[3:] == [str(tool), "--made-up"], cmd
    confine.release_profile(cmd)


def test_a_missing_tool_gives_exit_127_and_runs_nothing(tree, seatbelt, monkeypatch):
    monkeypatch.setattr(wholetool, "already_confined", lambda env: False)
    monkeypatch.chdir(tree / "repo")
    started = []

    def no_start(*a, **k):
        started.append(a)
        raise AssertionError("the tool was started")
    monkeypatch.setattr(wholetool.subprocess, "Popen", no_start)
    run = wholetool._Run()
    code = wholetool._launch("generic", False, ["--", "no-such-tool-FAKE-PT-0001"],
                             dict(os.environ), run, "")
    assert code == 127 and not started, (code, run.notes)
    assert any("could not start" in n and "no-such-tool-FAKE-PT-0001" in n for n in run.notes), \
        run.notes
    assert not [n for n in os.listdir(_profiles(tree)) if NAME.fullmatch(n)] \
        if _profiles(tree).exists() else True


def test_the_session_is_told_its_own_run_folder(tree, seatbelt):
    cmd, child_env, *_ = _build(tree, ["/bin/echo"])
    run = child_env.get("PHIWARD_RUN", "")
    home = os.path.realpath(str(tree / "home"))
    assert re.fullmatch(re.escape(os.path.join(home, ".phiward", "tools", "generic", "runs"))
                        + r"/\d{8}-\d{6}-[0-9a-f]{8}", run), run
    assert os.path.isdir(run)
    confine.release_profile(cmd)


def test_the_profile_file_is_gone_when_the_tool_ends(tree, recorder, monkeypatch):
    monkeypatch.setattr(wholetool, "already_confined", lambda env: False)
    monkeypatch.chdir(tree / "repo")
    run = wholetool._Run()
    code = wholetool._launch("generic", False, ["--", "/usr/bin/true"], dict(os.environ), run, "")
    assert code == 0, run.notes
    assert recorder.read_text().startswith("(version 1)")
    assert not [n for n in os.listdir(_profiles(tree)) if NAME.fullmatch(n)]


def test_a_failed_start_points_to_doctor(tree, recorder, monkeypatch):
    monkeypatch.setattr(wholetool, "already_confined", lambda env: False)
    monkeypatch.chdir(tree / "repo")
    run = wholetool._Run()
    code = wholetool._launch("generic", False, ["--", "/usr/bin/false"], dict(os.environ), run,
                             "")
    assert code != 0
    assert any("phiward doctor" in n for n in run.notes), run.notes


def test_no_private_sandbox_function_in_the_source():
    hits = [str(p.relative_to(ROOT)) for p in sorted((SRC / "phiward").rglob("*.py"))
            if "sandbox_check" in p.read_text()]
    assert not hits, hits


# --- doctor names why sandbox-exec fails ------------------------------------------------------

def _fail_with(monkeypatch, stderr: bytes):
    real = subprocess.run

    def fake(cmd, *a, **k):
        if cmd and cmd[0] == confine.SANDBOX_EXEC:
            return subprocess.CompletedProcess(cmd, 1, b"", stderr)
        return real(cmd, *a, **k)
    monkeypatch.setattr(confine.subprocess, "run", fake)


def test_doctor_names_a_start_inside_another_sandbox(tree, seatbelt, monkeypatch):
    _fail_with(monkeypatch, b"sandbox-exec: sandbox_apply: Operation not permitted\n")
    why = confine.self_test()
    assert why and "inside another sandbox" in why, why


def test_doctor_names_a_profile_that_does_not_compile(tree, seatbelt, monkeypatch):
    _fail_with(monkeypatch, b"sandbox-exec: unbound variable: made-up\n")
    why = confine.self_test()
    assert why and "does not compile" in why, why


# --- launch inside launch: the two facts ------------------------------------------------------

@pytest.fixture()
def facts(tree, monkeypatch):
    """The account's home is the tree's home; `deny_canary()` makes the canary there give EPERM
    (as a profile that denies it does); `run_folder()` makes a run folder of the right shape."""
    home = Path(os.path.realpath(str(tree / "home")))
    monkeypatch.setattr(wholetool, "_account_home", lambda: str(home), raising=False)
    # the old check's first fact, where it is still there: some sandbox holds
    monkeypatch.setattr(wholetool, "_sandbox_check_self", lambda: True, raising=False)
    monkeypatch.setattr(sys, "platform", "darwin")
    os.makedirs(config.spool_dir(dict(os.environ)), exist_ok=True)
    (home / ".phiward").mkdir(exist_ok=True)
    real_lstat, real_open = os.lstat, os.open
    denied = set()

    def lstat(p, *a, **k):
        if not k.get("dir_fd") and os.fspath(p) in denied:
            raise PermissionError(errno.EPERM, "denied", os.fspath(p))
        return real_lstat(p, *a, **k)

    def opener(p, *a, **k):
        if not k.get("dir_fd") and os.fspath(p) in denied:
            raise PermissionError(errno.EPERM, "denied", os.fspath(p))
        return real_open(p, *a, **k)
    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "open", opener)

    class F:
        account = home

        @staticmethod
        def deny_canary(base=home):
            c = base / ".phiward" / wholetool.CANARY
            c.parent.mkdir(parents=True, exist_ok=True)
            c.write_text("made-up canary\n")
            denied.add(str(c))

        @staticmethod
        def run_folder(base=home, adapter="claude", rid=RUN_ID):
            r = base / ".phiward" / "tools" / adapter / "runs" / rid
            r.mkdir(parents=True, exist_ok=True)
            return r
    return F


def _env(**kw):
    env = dict(os.environ)
    env.update(kw)
    return env


def test_the_start_check_needs_both_facts(facts):
    facts.deny_canary()
    run = facts.run_folder()
    os.chmod(run, 0o500)  # a sandbox that denies writes there (Mode A's denies all of ~/.phiward)
    try:
        assert wholetool.already_confined(_env(PHIWARD_RUN=str(run))) is False
    finally:
        os.chmod(run, 0o700)
    # the canary alone is not enough; the run folder alone is not either
    assert wholetool.already_confined(_env(PHIWARD_RUN="")) is False


def test_both_facts_together_are_a_session(facts):
    facts.deny_canary()
    run = facts.run_folder()
    assert wholetool.already_confined(_env(PHIWARD_RUN=str(run))) is True
    assert os.listdir(run) == []  # the probe file is removed


def test_a_writable_run_folder_without_the_denied_canary_is_not_a_session(facts):
    run = facts.run_folder()
    assert wholetool.already_confined(_env(PHIWARD_RUN=str(run))) is False


def test_a_home_that_points_elsewhere_does_not_count(facts, tree):
    other = Path(os.path.realpath(str(tree / "pub"))) / "made-up-home"
    facts.deny_canary(other)
    run = facts.run_folder(other)
    os.makedirs(config.spool_dir(_env(HOME=str(other))), exist_ok=True)
    assert wholetool.already_confined(_env(HOME=str(other), PHIWARD_RUN=str(run))) is False


@pytest.mark.parametrize("shape", ["elsewhere", "no-adapter", "bad-id", "dotdot", "deeper"])
def test_a_run_folder_of_another_shape_does_not_count(facts, tree, shape):
    facts.deny_canary()
    good = facts.run_folder()
    home = facts.account
    path = {
        "elsewhere": tree / "pub" / "runs" / RUN_ID,
        "no-adapter": home / ".phiward" / "tools" / "made-up" / "runs" / RUN_ID,
        "bad-id": home / ".phiward" / "tools" / "claude" / "runs" / "FAKE-PT-0001",
        "dotdot": Path(str(good) + "/../" + RUN_ID),
        "deeper": good / "tmp",
    }[shape]
    os.makedirs(path, exist_ok=True)
    assert wholetool.already_confined(_env(PHIWARD_RUN=str(path))) is False


@pytest.mark.parametrize("where", ["leaf", "runs", "adapter", "tools"])
def test_a_link_on_the_run_folders_path_does_not_count(facts, tree, where):
    facts.deny_canary()
    home = facts.account
    real = tree / "pub" / "real"
    parts = [".phiward", "tools", "claude", "runs", RUN_ID]
    cut = {"leaf": 5, "runs": 4, "adapter": 3, "tools": 2}[where]
    above = home.joinpath(*parts[:cut - 1])
    above.mkdir(parents=True, exist_ok=True)
    target = real.joinpath(*parts[cut - 1:])
    target.mkdir(parents=True, exist_ok=True)
    os.symlink(real / parts[cut - 1], above / parts[cut - 1])
    run = home.joinpath(*parts)
    assert run.is_dir()
    assert wholetool.already_confined(_env(PHIWARD_RUN=str(run))) is False


def test_a_canary_link_does_not_count_even_with_the_run_folder(facts):
    run = facts.run_folder()
    c = facts.account / ".phiward" / wholetool.CANARY
    os.symlink("/nonexistent-target", c)
    assert wholetool.already_confined(_env(PHIWARD_RUN=str(run))) is False


# --- macOS CI only: a real sandbox ------------------------------------------------------------

def _account_home() -> str:
    import pwd
    return os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)


def _confined_in(profile: str, run: str) -> str:
    code = ("import os, sys; sys.path.insert(0, %r); from phiward import wholetool; "
            "print('CONFINED-%%s' %% wholetool.already_confined(dict(os.environ)))" % str(SRC))
    r = subprocess.run([confine.SANDBOX_EXEC, "-p", profile, sys.executable, "-I", "-c", code],
                       capture_output=True, text=True, timeout=60,
                       env=dict(os.environ, HOME=_account_home(), PHIWARD_RUN=run))
    return r.stdout + r.stderr


@ci_macos
def test_ci_a_sandbox_that_only_tightens_is_not_a_session(tmp_path):
    home = _account_home()
    canary = os.path.join(home, ".phiward", wholetool.CANARY)
    os.makedirs(os.path.dirname(canary), exist_ok=True)
    wholetool._make_canary(canary)
    run = os.path.join(home, ".phiward", "tools", "generic", "runs", RUN_ID)
    os.makedirs(run, exist_ok=True)
    s = confine._sb_str
    deny = f"(version 1)(allow default)(deny file* (literal {s(canary)}))"
    try:
        # Mode A's sandbox denies every write to ~/.phiward: not a session
        out = _confined_in(deny + f"(deny file-write* (subpath {s(os.path.join(home, '.phiward'))}))",
                           run)
        assert "CONFINED-False" in out, out
        # control: the same canary deny, and the run folder writable: both facts hold
        out = _confined_in(deny, run)
        assert "CONFINED-True" in out, out
    finally:
        os.rmdir(run)


@ci_macos
def test_ci_doctor_names_a_start_inside_another_sandbox(tmp_path):
    code = ("import sys; sys.path.insert(0, %r); from phiward import confine; "
            "print(confine.self_test())" % str(SRC))
    home = tmp_path / "home"
    home.mkdir()
    r = subprocess.run([confine.SANDBOX_EXEC, "-p", "(version 1)(allow default)",
                        sys.executable, "-I", "-c", code], capture_output=True, text=True,
                       timeout=60, env=dict(os.environ, HOME=str(home)))
    assert "inside another sandbox" in r.stdout, r.stdout + r.stderr


@ci_macos
def test_ci_the_tool_starts_with_sigpipe_at_its_default(tree):
    env = dict(os.environ, PYTHONPATH=str(SRC))
    r = subprocess.run([sys.executable, "-m", "phiward", "launch", "--", "/bin/sh", "-c",
                        "ps -o sigignore= -p $$"], cwd=str(tree / "repo"), capture_output=True,
                       text=True, env=env, timeout=120, stdin=subprocess.DEVNULL)
    words = [w for w in r.stdout.split() if re.fullmatch(r"[0-9a-fA-F]+", w)]
    assert r.returncode == 0 and words, r.stdout + r.stderr
    assert int(words[-1], 16) & (1 << 12) == 0, r.stdout  # SIGPIPE (13) is not ignored


@ci_macos
def test_ci_launch_inside_launch_still_runs_its_command_directly(tree):
    # the account's home as HOME: the run folder must be where the inner check looks
    env = dict(os.environ, PYTHONPATH=str(SRC), HOME=_account_home())
    inner = (f"{json.dumps(sys.executable)} -m phiward launch -- /bin/echo NESTED-FAKE-OK")
    r = subprocess.run([sys.executable, "-m", "phiward", "launch", "--", "/bin/sh", "-c", inner],
                       cwd=str(tree / "repo"), capture_output=True, text=True, env=env,
                       timeout=180, stdin=subprocess.DEVNULL)
    assert r.returncode == 0 and "NESTED-FAKE-OK" in r.stdout, r.stdout + r.stderr
