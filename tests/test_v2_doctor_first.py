"""`doctor` for a new user: before Claude Code is wired, one next step in place of a WARNING per
part (each part's line is behind `--verbose`); a config without a program list warns, and says
how to add one; the detail counts are behind `--verbose`. `setup --first-run` says the next step
too. Made-up trees only."""

import os
import subprocess
import sys
from pathlib import Path

from helpers import protect

SRC = str(Path(__file__).resolve().parents[1] / "src")
INSTALL = "phiward install claude --user --write"


def _phiward(*args, cwd):
    e = dict(os.environ, PYTHONPATH=SRC)
    return subprocess.run([sys.executable, "-m", "phiward", *args], cwd=str(cwd),
                          capture_output=True, text=True, env=e, timeout=120,
                          stdin=subprocess.DEVNULL)


def test_unwired_doctor_gives_one_next_step(tree):
    protect(tree, [], best_effort=False)
    out = _phiward("doctor", cwd=tree / "repo").stdout
    assert out.count(INSTALL) == 1, out
    line = next(ln for ln in out.splitlines() if INSTALL in ln)
    assert "not wired" in line and "--verbose" in line, line
    assert "sandbox confines the shell" not in out and "hidden list in the sandbox" not in out


def test_verbose_shows_each_part(tree):
    protect(tree, [], best_effort=False)
    out = _phiward("doctor", "--verbose", cwd=tree / "repo").stdout
    assert "sandbox confines the shell" in out and "hidden list in the sandbox" in out, out
    assert "unresolved:" in out and "derived" in out


def test_the_detail_counts_are_behind_verbose(tree):
    protect(tree, [], best_effort=False)
    out = _phiward("doctor", cwd=tree / "repo").stdout
    line = next(ln for ln in out.splitlines() if ln.startswith("protected roots:"))
    assert "unresolved" not in line and "derived" not in line, line


def test_no_program_list_is_a_warning_with_the_way_to_add_one(tree):
    protect(tree, [], best_effort=False)
    out = _phiward("doctor", cwd=tree / "repo").stdout
    line = next(ln for ln in out.splitlines() if "programs gateway commands may run" in ln)
    assert line.startswith("WARNING:") and "phiward setup" in line, line


def test_first_run_says_the_next_step(tree):
    env = {k: v for k, v in os.environ.items()
           if k not in ("PHIWARD_CONFIG", "PHIWARD_SPOOL", "XDG_CONFIG_HOME")}
    env["HOME"] = str(tree / "home")
    r = subprocess.run([sys.executable, "-m", "phiward", "setup", "--first-run", "--root",
                        str(tree / "phi")], cwd=str(tree / "home"), capture_output=True,
                       text=True, env=dict(env, PYTHONPATH=SRC), stdin=subprocess.DEVNULL)
    assert r.returncode == 0, r.stderr
    assert "phiward setup" in r.stdout and "choose 1" in r.stdout, r.stdout


def test_the_usage_names_verbose(tree):
    r = _phiward("doctor", "--help", cwd=tree / "repo")
    assert "--verbose" in r.stdout


def test_a_sandbox_cause_install_cannot_fix_is_shown_without_verbose(tree):
    # the project's own settings turn the sandbox off: they win over the user wiring, so
    # `install claude --user --write` alone would not confine the shell
    protect(tree, [], best_effort=False)
    proj = tree / "repo" / ".claude"
    proj.mkdir()
    (proj / "settings.json").write_text('{"sandbox": {"enabled": false}}')
    out = _phiward("doctor", cwd=tree / "repo").stdout
    assert "sandbox confines the shell: NO" in out and "sandbox.enabled" in out, out


def test_a_cause_install_cannot_fix_names_what_stays_after_install(tree):
    protect(tree, [], best_effort=False)
    proj = tree / "repo" / ".claude"
    proj.mkdir()
    (proj / "settings.json").write_text('{"sandbox": {"enabled": false}}')
    out = _phiward("doctor", cwd=tree / "repo").stdout
    line = next(ln for ln in out.splitlines() if "sandbox confines the shell: NO" in ln)
    # round 5: the step of what stays after install, naming its file
    assert "removes sandbox.enabled from .claude/settings.json" in line, line
    assert "phiward install claude --user --write" not in line, line


def test_the_hidden_list_count_follows_links_as_the_sandbox_does(tree, monkeypatch):
    # on macOS /tmp is a link to /private/tmp, and /var/run/docker.sock one to ~/.docker: install
    # writes the real path to denyRead, and doctor must count it as covered (found by the macOS
    # quickstart check: "hidden list in the sandbox: 0 of 3" right after install)
    import json
    from phiward import config, doctor, hidden
    protect(tree, [], best_effort=False)
    real = tree / "pub" / "krb5cc_fake"
    real.parent.mkdir(exist_ok=True)
    real.write_text("x")
    link = tree / "linkdir"
    os.symlink(tree / "pub", link)
    monkeypatch.setattr(hidden, "paths", lambda *a, **k: [str(link / "krb5cc_fake")])
    s = tree / "home" / ".claude" / "settings.json"
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(json.dumps({"sandbox": {"filesystem": {"denyRead": [str(real)]}}}))
    lines = doctor.mode_report(str(tree / "repo"), str(tree / "home"),
                               config.load(str(tree / "repo")))
    line = next(ln for ln in lines if "hidden list in the sandbox" in ln)
    assert "1 of 1" in line and "WARNING" not in line, line
