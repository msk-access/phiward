"""Each refusal names a step its reader can take (PLAN-PR0-refusal-steps, 3.11 and 3.9).

The agent reads a hook, `run` or `copy` refusal, and cannot run `phiward doctor` there: a config
problem says the operator runs it in their own terminal. When the hook itself cannot run, every
tool call is refused, so the step is the operator's. A doctor WARNING names its fix. Messages
only: no verdict changes. Made-up trees and names only (FAKE-PT-0001).
"""

import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import claude_settings, config, doctor, install, selfcheck, session_note, wholetool
from phiward.adapters import claude

SRC = str(Path(__file__).resolve().parents[1] / "src")
PKG = Path(SRC) / "phiward"

STEP = "the operator runs `phiward doctor` in their own terminal"
OPERATOR = "(cd ~ && phiward install claude --user --write)"


def _cli(args, cwd, stdin="", env=None):
    e = dict(os.environ, PYTHONPATH=SRC)
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "phiward"] + args, cwd=str(cwd), input=stdin,
                          capture_output=True, text=True, env=e, timeout=60)


@pytest.fixture()
def broken(tree, monkeypatch):
    """A user config that cannot be used: $PHIWARD_CONFIG names no file."""
    gone = str(tree / "home" / "gone.toml")
    monkeypatch.setenv("PHIWARD_CONFIG", gone)
    assert config.load(str(tree / "repo")).problem
    return {"PHIWARD_CONFIG": gone}


def _payload(tree, tool, tool_input, event="PreToolUse"):
    return json.dumps({"hook_event_name": event, "tool_name": tool, "tool_input": tool_input,
                       "cwd": str(tree / "repo"), "permission_mode": "default"})


def _hook(payload):
    err = io.StringIO()
    code = claude.main(io.StringIO(payload), io.StringIO(), err)
    return code, err.getvalue()


# --- a config problem: the operator runs doctor --------------------------------------------------

def test_the_hook_refusal_names_the_operators_doctor_step(tree, broken):
    code, err = _hook(_payload(tree, "Bash", {"command": f"cat {tree}/phi/FAKE-PT-0001.bam"}))
    assert code == 2 and "cannot be used" in err and STEP in err, err


def test_run_and_copy_name_the_operators_doctor_step(tree, broken):
    from phiward import copying, run
    out = io.StringIO()
    assert run.execute(["--", "/bin/true"], str(tree / "repo"), dict(os.environ), out) == 3
    assert out.getvalue().startswith("run refused:") and STEP in out.getvalue(), out.getvalue()
    out = io.StringIO()
    code = copying.execute([str(tree / "phi" / "FAKE-PT-0001.bam"), str(tree / "phi" / "c.bam")],
                           str(tree / "repo"), dict(os.environ), out)
    assert code == 3 and out.getvalue().startswith("copy refused:"), out.getvalue()
    assert STEP in out.getvalue(), out.getvalue()


def test_launch_names_the_operators_doctor_step(tree, broken):
    with pytest.raises(wholetool.LaunchError) as exc:
        wholetool.build(["/bin/echo", "x"], str(tree / "repo"), dict(os.environ),
                        wholetool.ADAPTERS["generic"])
    assert STEP in str(exc.value), exc.value


def test_the_git_hook_names_the_operators_doctor_step(tree, broken):
    subprocess.run(["git", "init", "-q", str(tree / "repo")], check=True)
    r = _cli(["git-hook", "pre-commit"], tree / "repo", env=broken)
    assert r.returncode != 0 and STEP in r.stderr, r


def test_the_prompt_scan_names_the_operators_doctor_step(tree, broken):
    payload = json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hello",
                          "cwd": str(tree / "repo")})
    r = _cli(["prompt-scan", "claude"], tree / "repo", stdin=payload, env=broken)
    assert "not sent" in r.stdout + r.stderr and STEP in r.stdout + r.stderr, r


# --- the hook itself cannot run: the operator's step ---------------------------------------------

def test_a_wrong_event_names_the_operators_step(tree, monkeypatch):
    code, err = _hook(_payload(tree, "Bash", {"command": "ls"}, event="PostToolUse"))
    assert code == 2 and OPERATOR in err and "ask the operator" in err, err
    from phiward import fasthook
    monkeypatch.setattr(sys, "stdin", io.StringIO(_payload(tree, "Bash", {"command": "ls"},
                                                           event="PostToolUse")))
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    assert fasthook.main() == 2
    assert OPERATOR in err.getvalue() and "ask the operator" in err.getvalue(), err.getvalue()


def test_a_hook_that_cannot_decide_names_the_operators_doctor_step(tree, monkeypatch):
    import phiward.adapters

    def boom(*_a, **_k):
        raise RuntimeError("made-up failure")

    monkeypatch.setattr(phiward.adapters, "decide", boom)
    code, err = _hook(_payload(tree, "Bash", {"command": "ls"}))
    assert code == 2 and "could not decide" in err and STEP in err, err


def test_code_that_cannot_load_names_the_operators_step(tmp_path):
    moved = tmp_path / "phiward" / "entry.py"  # a package folder without the package
    moved.parent.mkdir()
    shutil.copy2(PKG / "entry.py", moved)
    r = subprocess.run([sys.executable, "-I", "-S", str(moved), "hook", "claude"],
                       capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"}, timeout=60)
    assert r.returncode == 2 and OPERATOR in r.stderr and "ask the operator" in r.stderr, r


# --- a write to a guard file: the operator's own editor --------------------------------------------

def test_a_write_to_the_config_names_the_operators_editor(tree):
    code, err = _hook(_payload(tree, "Write", {"file_path": str(tree / "home" / "phiward.toml"),
                                               "content": "x"}))
    assert code == 2 and "their own editor or terminal" in err, err


# --- doctor: each WARNING touched names its fix ----------------------------------------------------

def test_another_prompt_hook_names_its_fix():
    line = doctor._other_prompt_hook("the user settings", "UserPromptSubmit", {"type": "http"})
    assert "remove that hook" in line, line


def _settings(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def test_disable_all_hooks_names_its_fix(tree):
    _settings(tree / "repo" / ".claude" / "settings.json", {"disableAllHooks": True})
    w = doctor.wiring_state(str(tree / "repo"), str(tree / "home"))
    line = next(x for x in w.lines if "disableAllHooks is true at" in x)
    assert "to false in" in line, line


def test_disable_all_hooks_at_the_managed_level_names_the_admin(tree, monkeypatch):
    managed = tree / "managed" / "managed-settings.json"
    _settings(managed, {"disableAllHooks": True})
    real = claude_settings.levels

    def levels(project, home):
        return [("managed", str(managed), None)] + [x for x in real(project, home)
                                                    if x[0] != "managed"]

    monkeypatch.setattr(claude_settings, "levels", levels)
    w = doctor.wiring_state(str(tree / "repo"), str(tree / "home"))
    line = next(x for x in w.lines if "disableAllHooks is true at" in x)
    assert "admin" in line, line


def test_the_plugin_off_and_env_path_name_their_fix(tree, monkeypatch):
    monkeypatch.setattr(install, "plugin_state", lambda p, h: (True, "user", True, True))
    w = doctor.wiring_state(str(tree / "repo"), str(tree / "home"))
    off = next(x for x in w.lines if "turn the phiward plugin off" in x)
    path = next(x for x in w.lines if "set env.PATH" in x)
    assert "enabledPlugins" in off and "remove" in off, off
    assert "remove `env.PATH`" in path, path


def test_a_self_check_that_cannot_run_names_its_fix(monkeypatch):
    def boom():
        raise OSError("made-up failure")

    monkeypatch.setattr(selfcheck, "check_full_isolated", boom)
    lines = doctor.selfcheck_lines()
    assert len(lines) == 1 and "reinstall phiward" in lines[0], lines


def test_an_old_claude_code_names_claude_update(tree, monkeypatch):
    _settings(tree / "repo" / ".mcp.json", {"mcpServers": {"fake": {"command": "/bin/true"}}})
    monkeypatch.setattr(claude_settings, "claude_version", lambda *a, **k: (2, 0, 1))
    lines = doctor.mode_report(str(tree / "repo"), str(tree / "home"),
                               config.load(str(tree / "repo")))
    line = next(x for x in lines if "does not tell" in x)
    assert "`claude update`" in line, line


def test_a_hard_linked_file_names_its_fix(tree):
    os.link(tree / "phi" / "FAKE-PT-0001.bam", tree / "pub" / "other-name")
    r = _cli(["doctor"], tree / "repo")
    line = next(x for x in r.stdout.splitlines() if "other hard links" in x)
    assert "protect the other names too, or give the file one name" in line, line
    assert "remove" not in line, line


# --- the session note: the loader keys, by name ----------------------------------------------------

def _note(tree):
    return session_note.note(config.load(str(tree / "repo")), str(tree / "repo"))


def test_the_note_names_the_projects_loader_keys(tree):
    _settings(tree / "repo" / ".claude" / "settings.json",
              {"env": {"LD_LIBRARY_PATH": "/made/up", "LD_FAKE\nnot a name": "x"}})
    text = _note(tree)
    line = next(x for x in text.splitlines() if "env.LD_LIBRARY_PATH" in x)
    assert "tell the operator" in line, line
    assert "not a name" not in text, text


def test_the_note_names_at_most_five_loader_keys(tree):
    _settings(tree / "repo" / ".claude" / "settings.json",
              {"env": {f"LD_FAKE_{i}": "x" for i in range(8)}})
    line = next(x for x in _note(tree).splitlines() if "env.LD_FAKE_0" in x)
    assert line.count("env.LD_FAKE_") == 5, line


def test_a_failing_loader_lookup_keeps_the_rest_of_the_note(tree, monkeypatch):
    def boom(*_a, **_k):
        raise OSError("made-up failure")

    monkeypatch.setattr(claude_settings, "project_loader_keys", boom)
    text = _note(tree)
    assert "Rules for this session:" in text and "phiward run --" in text, text


# --- the sanitizer cannot start: a config problem too (review of PR 0) ---------------------------

def test_a_sanitizer_that_cannot_start_names_the_operators_doctor_step(tree, monkeypatch, capsys):
    from phiward import copying, githooks, run, sanitize

    def boom(*_a, **_k):
        raise sanitize.SanitizerError("made-up failure")

    monkeypatch.setattr(run.Sanitizer, "from_config", boom)
    monkeypatch.setattr(copying.Sanitizer, "from_config", boom)
    out = io.StringIO()
    assert run.execute(["--", sys.executable, "-c", "pass"], str(tree / "repo"),
                       dict(os.environ), out) == 3, out.getvalue()
    assert "sanitizer cannot start" in out.getvalue() and STEP in out.getvalue(), out.getvalue()
    out = io.StringIO()
    code = copying.execute([str(tree / "phi" / "FAKE-PT-0001.bam"), str(tree / "phi" / "c.bam")],
                           str(tree / "repo"), dict(os.environ), out)
    assert code == 3 and "sanitizer cannot start" in out.getvalue(), out.getvalue()
    assert STEP in out.getvalue(), out.getvalue()
    subprocess.run(["git", "init", "-q", str(tree / "repo")], check=True)
    monkeypatch.setattr(githooks, "_make_sanitizer", boom)
    assert githooks.pre_commit(str(tree / "repo")) == 1
    err = capsys.readouterr().err
    assert "could not be set up" in err and STEP in err, err
