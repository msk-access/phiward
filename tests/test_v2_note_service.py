"""The start-of-session note (a SessionStart hook) and the broker as a login
service."""

import json
import os
import subprocess
import sys
from pathlib import Path

from phiward import config, install, service, session_note

SRC = str(Path(__file__).resolve().parents[1] / "src")


def test_the_note_names_the_gateway_as_the_route_and_no_protected_path(tree):
    cfg = config.load(str(tree / "repo"))
    text = session_note.note(cfg)
    assert "phiward run -- CMD" in text and "intended route" in text
    assert str(tree / "phi") not in text and "phi" not in text.replace("phiward", "")


def test_the_note_lists_hpc_hosts_and_programs_only_when_configured(tree):
    p = Path(os.environ["PHIWARD_CONFIG"])
    assert "HPC" not in session_note.note(config.load(str(tree / "repo")))
    p.write_text(p.read_text() + '[remote]\nhosts = ["hpc-test"]\ncommands = ["squeue"]\n')
    text = session_note.note(config.load(str(tree / "repo")))
    assert "hpc-test" in text and "squeue" in text and "never use ssh" in text


def test_the_hook_prints_session_start_context(tree):
    r = subprocess.run([sys.executable, "-m", "phiward", "session-note", "claude"],
                       input=json.dumps({"cwd": str(tree / "repo"), "hook_event_name": "SessionStart"}),
                       capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC))
    assert r.returncode == 0
    out = json.loads(r.stdout)["hookSpecificOutput"]
    assert out["hookEventName"] == "SessionStart" and "phiward run" in out["additionalContext"]


def test_the_note_never_fails_a_session(tree, monkeypatch):
    monkeypatch.setenv("PHIWARD_CONFIG", str(tree / "missing.toml"))
    r = subprocess.run([sys.executable, "-m", "phiward", "session-note", "claude"],
                       input="not json", capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=SRC))
    assert r.returncode == 0 and r.stdout == ""


def test_install_wires_the_note_once(tree):
    w = install.wiring(config.load(str(tree / "repo")))
    assert install.hook_python(w["hooks"]["SessionStart"][0]["hooks"][0], "session-note")
    m = install.merge({}, w)
    assert install.merge(m, w) == m
    assert len(m["hooks"]["SessionStart"]) == 1


def test_the_service_runs_the_broker_and_discards_output(tree, monkeypatch):
    monkeypatch.setenv("PHIWARD_SPOOL", str(tree / "spool"))
    text = service.render("/opt/bin/phiward")
    assert "/opt/bin/phiward" in text and "broker" in text
    assert str(tree / "spool") in text and "/dev/null" in text or "null" in text


def test_the_service_file_is_a_guard_file(tree):
    assert service.service_file() in config.guard_files()


def test_writing_the_service_prints_the_load_command_and_runs_nothing(tree, monkeypatch):
    home = tree / "home"
    monkeypatch.setenv("HOME", str(home))
    bin_ = tree / "bin"
    bin_.mkdir()
    os.chmod(bin_, 0o755)  # a PATH folder others can write is not trusted
    (bin_ / "phiward").write_text("#!/bin/sh\n")
    (bin_ / "phiward").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_}:/usr/bin:/bin")
    # an agent tool has no terminal: the service must use the default places
    monkeypatch.delenv("PHIWARD_CONFIG", raising=False)
    monkeypatch.delenv("PHIWARD_SPOOL", raising=False)
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        assert service.main(["--write"]) == 0
    path = service.service_file(str(home))
    assert os.path.isfile(path) and str(bin_ / "phiward") in open(path).read()
    assert ("launchctl bootstrap" in buf.getvalue()) or ("systemctl --user" in buf.getvalue())


# --- the Claude Code plugin and marketplace -------------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]


def test_the_marketplace_lists_the_plugin_at_the_package_version():
    import phiward
    m = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    p = json.loads((ROOT / "plugin" / ".claude-plugin" / "plugin.json").read_text())
    assert m["plugins"][0]["name"] == p["name"] == "phiward"
    assert m["plugins"][0]["source"] == "./plugin"
    assert m["plugins"][0]["version"] == p["version"] == phiward.__version__


def test_the_plugin_hooks_run_phiward_by_name_from_the_plugins_script():
    h = json.loads((ROOT / "plugin" / "hooks" / "hooks.json").read_text())["hooks"]
    script = "${CLAUDE_PLUGIN_ROOT}/hooks/clean-exec.sh"
    assert [g["matcher"] for g in h["PreToolUse"]] == install.MATCHERS
    assert all(g["hooks"][0]["command"] == script and
               g["hooks"][0]["args"] == ["phiward", "hook", "claude"] and
               g["hooks"][0]["onFailure"] == "block" for g in h["PreToolUse"])
    note = h["SessionStart"][0]["hooks"][0]
    assert note["command"] == script and note["args"] == ["phiward", "session-note", "claude"]


def test_the_plugin_skill_is_the_skill():
    assert (ROOT / "plugin" / "skills" / "phiward" / "SKILL.md").read_text() == \
        (ROOT / "skills" / "phiward" / "SKILL.md").read_text()


def test_the_plugin_never_turns_the_user_hooks_off(tree):
    # a project can name the plugin (or turn it off), so install
    # keeps its own hooks unless the operator says --no-hooks
    from conftest import default_place_env
    proj = tree / "repo"
    (proj / ".claude").mkdir(exist_ok=True)
    (proj / ".claude" / "settings.json").write_text(json.dumps(
        {"enabledPlugins": {"phiward@phiward": True}}))
    import pty
    master, slave = pty.openpty()  # printing the wiring needs the operator's terminal

    def show(*extra):
        return subprocess.run([sys.executable, "-m", "phiward", "install", "claude", "--user",
                               *extra], cwd=str(proj), capture_output=True, text=True,
                              stdin=slave, env=dict(default_place_env(tree), PYTHONPATH=SRC))
    try:
        r = show()
        assert r.returncode == 0, r.stderr
        assert '"PreToolUse": []' not in r.stdout
        r = show("--no-hooks")
    finally:
        os.close(master)
        os.close(slave)
    assert '"PreToolUse": []' in r.stdout


def test_doctor_reads_the_plugin_like_claude_code(tree):
    proj = tree / "repo"
    home = Path(os.environ["HOME"])
    (home / ".claude").mkdir(exist_ok=True)
    (home / ".claude" / "settings.json").write_text(json.dumps(
        {"enabledPlugins": {"phiward@phiward": True}}))
    (proj / ".claude").mkdir(exist_ok=True)
    (proj / ".claude" / "settings.json").write_text(json.dumps(
        {"enabledPlugins": {"phiward@phiward": False, "phiward@evil": True},
         "env": {"PATH": "/tmp/x"}}))
    on, level, off, path = install.plugin_state(str(proj), str(home))
    assert on is False and level == "project" and off and path


def test_a_shell_write_to_claude_settings_is_refused(tree):
    from phiward.core import SHELL, Action
    from phiward.guards import protected_paths
    cfg = config.load(str(tree / "repo"))
    for cmd in ("printf '{}' > .claude/settings.local.json", "cp x .claude/settings.json",
                "python3 -c 'open(\".claude/settings.json\",\"w\")'"):
        d = protected_paths.check(Action(SHELL, str(tree / "repo"), command=cmd, confined=True), cfg)
        assert d.verdict == "deny", cmd
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command="cat .claude/settings.json",
                                     confined=True), cfg)
    assert d.verdict != "deny"


def test_loading_without_the_service_manager_fails_without_a_crash():
    # a container, WSL, an HPC node: no systemctl (or launchctl) to run
    def missing(cmd, **k):
        raise FileNotFoundError(2, "No such file or directory", cmd[0])
    assert service.load("/nonexistent/phiward-broker.service", runner=missing) is False


def test_no_service_manager_says_to_start_the_broker_yourself(monkeypatch):
    monkeypatch.setattr(service.shutil, "which", lambda name, path=None: None)
    text = service.no_manager_text()
    assert "phiward broker" in text and "no " in text, text


def test_the_service_names_the_launcher_of_the_install_record(tree, monkeypatch):
    # umask 002 makes ~/.local/bin group-writable, so it is off the safe PATH; the record still
    # names the installed launcher (test_v2_launcher_identity)
    from helpers import installed_site
    from phiward import selfcheck
    _record, _pkg, exe = installed_site(tree)
    monkeypatch.setattr(selfcheck, "launcher_scripts",
                        lambda record=None, package_dir=None: frozenset({os.path.realpath(exe)}))
    home = tree / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.delenv("PHIWARD_CONFIG", raising=False)
    monkeypatch.delenv("PHIWARD_SPOOL", raising=False)
    import io
    import contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        assert service.main(["--write"]) == 0
    assert os.path.realpath(exe) in open(service.service_file(str(home))).read()
