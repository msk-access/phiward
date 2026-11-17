"""Four bugs found while running the HPC probe through the gateway: a test that reached the real
`launchctl`, `doctor` silent about a broker on another spool, a literal `~` in PHIWARD_CONFIG,
and `run --remote` asking for local protected paths. Made-up trees only."""

import io
import os
import subprocess
import sys
from pathlib import Path

from phiward import broker as brk
from phiward import config, run, service

SRC = str(Path(__file__).resolve().parents[1] / "src")


# --- 1. no test loads a real login service -------------------------------------------------------

def test_the_tests_set_the_no_load_seam():
    assert os.environ.get("PHIWARD_SERVICE_RUNNER") == "none"


def test_with_the_seam_load_runs_nothing(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a real service command ran")
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setenv("PHIWARD_SERVICE_RUNNER", "none")
    assert service.load(str(tmp_path / "x.plist")) is False


def test_a_given_runner_still_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("PHIWARD_SERVICE_RUNNER", "none")
    seen = []

    class R:
        returncode = 0

    def fake(cmd, **k):
        seen.append(cmd)
        return R()
    assert service.load(str(tmp_path / "x.plist"), runner=fake) is True and seen


# --- 2. doctor names a broker on another spool ---------------------------------------------------

def _doctor(cwd, **env):
    e = dict(os.environ, PYTHONPATH=SRC, **env)
    r = subprocess.run([sys.executable, "-m", "phiward", "doctor"], cwd=str(cwd),
                       capture_output=True, text=True, env=e, timeout=60)
    return r.stdout + r.stderr


def test_the_status_records_the_spool(tree, monkeypatch):
    monkeypatch.setenv("PHIWARD_SPOOL", str(tree / "sp"))
    assert brk._status()["spool"] == str(tree / "sp")


def test_doctor_names_a_broker_on_another_spool(tree, broker, tmp_path):
    spool = os.environ["PHIWARD_SPOOL"]
    out = _doctor(tree / "repo", PHIWARD_SPOOL=str(tmp_path / "other-spool"))
    assert "NOT RUNNING" in out
    assert spool in out and "PHIWARD_SPOOL" in out, out


def test_doctor_names_both_configs(tree, broker, tmp_path):
    empty = tmp_path / "empty.toml"
    empty.write_text("")
    out = _doctor(tree / "repo", PHIWARD_CONFIG=str(empty))
    assert str(empty) in out and os.environ["PHIWARD_CONFIG"] in out, out


# --- 3. a literal ~ in PHIWARD_CONFIG -----------------------------------------------------------

def test_a_tilde_in_phiward_config_is_expanded(tree):
    home = str(tree / "home")
    env = {"HOME": home, "PHIWARD_CONFIG": "~/phiward.toml"}
    assert config.user_config_path(env) == os.path.join(home, "phiward.toml")
    assert not config.load(str(tree / "repo"), env).problem


def test_a_relative_phiward_config_is_a_problem(tree):
    env = {"HOME": str(tree / "home"), "PHIWARD_CONFIG": "phiward.toml"}
    p = config.load(str(tree / "home"), env).problem
    assert p and "absolute" in p, p


def test_the_broker_refuses_to_start_with_a_config_problem(tree, tmp_path):
    e = dict(os.environ, PYTHONPATH=SRC, PHIWARD_CONFIG=str(tmp_path / "missing.toml"),
             PHIWARD_SPOOL=str(tmp_path / "sp"))
    r = subprocess.run([sys.executable, "-m", "phiward", "broker"], cwd=str(tree / "home"),
                       capture_output=True, text=True, env=e, timeout=30,
                       stdin=subprocess.DEVNULL)
    assert r.returncode == 3 and "PHIWARD_CONFIG" in r.stderr, r.stderr


# --- 4. run --remote needs only [remote] ---------------------------------------------------------

def test_a_remote_run_needs_no_local_protected_paths(tree):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        '[remote]\nhosts = ["hpc-test"]\ncommands = ["squeue"]\n')
    out = io.StringIO()
    assert run.execute(["--remote", "other", "--", "squeue"], str(tree / "repo"),
                       dict(os.environ), out) == 2
    assert "no protected paths" not in out.getvalue()
    assert "[remote] hosts" in out.getvalue(), out.getvalue()


def test_a_local_run_still_needs_protected_paths(tree):
    Path(os.environ["PHIWARD_CONFIG"]).write_text('[remote]\nhosts = ["hpc-test"]\n')
    out = io.StringIO()
    assert run.execute(["--", "true"], str(tree / "repo"), dict(os.environ), out) == 2
    assert "no protected paths" in out.getvalue()


# --- the broker's PATH reaches `pin` and `doctor` --------------------------------------------------

def test_program_path_is_the_running_broker_s(tree, monkeypatch):
    spool = tree / "sp"
    spool.mkdir()
    monkeypatch.setenv("PHIWARD_SPOOL", str(spool))
    monkeypatch.setattr(brk, "command_env", lambda: {"PATH": "/usr/bin:/bin"})
    brk.write_status()
    monkeypatch.setattr(brk, "command_env", lambda: {"PATH": "/this/process/bin"})
    assert brk.program_path() == "/this/process/bin"  # no heartbeat: no broker runs
    (spool / "broker.alive").write_text("")
    assert brk.program_path() == "/usr/bin:/bin"


def test_the_broker_s_path_keeps_only_safe_folders(tree, monkeypatch):
    import stat as st_
    spool = tree / "sp2"
    spool.mkdir()
    monkeypatch.setenv("PHIWARD_SPOOL", str(spool))
    shared = tree / "shared-bin"
    shared.mkdir()
    shared.chmod(0o777)
    monkeypatch.setattr(brk, "command_env", lambda: {"PATH": f"{shared}:/usr/bin:relative"})
    brk.write_status()
    (spool / "broker.alive").write_text("")
    assert brk.program_path() == "/usr/bin"
    os.chmod(config.status_path(), 0o644)  # not the broker's own private file any more
    monkeypatch.setattr(brk, "command_env", lambda: {"PATH": "/this/process/bin"})
    assert brk.program_path() == "/this/process/bin"
    assert st_.S_IMODE(os.stat(config.status_path()).st_mode) == 0o644
