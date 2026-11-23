"""`sandbox.excludedCommands` (PLAN-USABILITY-FIXES b1): Claude Code runs a call outside its
sandbox when every command of the call matches an entry, by its own text matcher. phiward does
not guess which calls match: while the effective list is non-empty, every Bash and Monitor call
gets the text check of an unsandboxed call (as with `[shell] best_effort`), not the blanket
refusal. `confinement_reason` keeps its meaning. Made-up trees only (`tests/conftest.py`)."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import claude_settings, config, install
from phiward.adapters import claude
from helpers import protect

USER_FILE = "~/.claude/settings.json"
D8 = "Write the paths out in full"


def _wired(tree, **extra):
    cfg = config.load(str(tree / "repo"))
    want = install.wiring(cfg)
    want["sandbox"].update(extra)
    s = tree / "home" / ".claude" / "settings.json"
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(json.dumps(want))
    return want


def _hook(tree, monkeypatch, command, tool="Bash", cwd=None, project=None):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project or tree / "repo"))
    payload = {"session_id": "s", "hook_event_name": "PreToolUse",
               "cwd": str(cwd or tree / "repo"), "permission_mode": "default",
               "tool_name": tool, "tool_input": {"command": command}}
    out, err = io.StringIO(), io.StringIO()
    code = claude.main(io.StringIO(json.dumps(payload)), out, err)
    return code, out.getvalue() + err.getvalue()


def _refused_by_text(tree, monkeypatch, command, tool="Bash", **kw):
    code, text = _hook(tree, monkeypatch, command, tool, **kw)
    assert code == 2, text
    assert "names a protected path" in text, text
    assert "every command is refused but a whole gateway call" not in text, text


@pytest.fixture()
def docker(tree):
    protect(tree, [], best_effort=False)
    _wired(tree, excludedCommands=["docker *"])
    return str(tree / "phi")


@pytest.mark.parametrize("command", [
    "docker run -v {R}:/x img",
    "d''ocker run -v {R}:/x img",
    '"docker" run -v {R}:/x img',
    "\\docker run -v {R}:/x img",
    "$(echo docker) run -v {R}:/x img",
    "doc*er run -v {R}:/x img",
    "env docker run -v {R}:/x img",
    "FOO=1 docker run -v {R}:/x img",
    "ls; docker run -v {R}:/x img",
    "ls && docker run -v {R}:/x img",
    "ls | docker run -v {R}:/x img",
    "ls\ndocker run -v {R}:/x img",
    "docker run -v {R}\\\n:/x img",
    "cat {R}/FAKE-PT-0001.bam",
])
def test_every_shape_of_an_excluded_call_gets_the_text_check(tree, monkeypatch, docker,
                                                             command):
    _refused_by_text(tree, monkeypatch, command.format(R=docker))


@pytest.mark.parametrize("command", ["ls *.py", "pytest", "git status", "echo docker",
                                     "grep docker README.md", "cat $HOME/x"])
def test_typical_calls_pass_with_an_entry(tree, monkeypatch, docker, command):
    code, text = _hook(tree, monkeypatch, command)
    assert code == 0, text


def test_monitor_gets_the_same_text_check(tree, monkeypatch, docker):
    code, text = _hook(tree, monkeypatch, "ls *.py", tool="Monitor")
    assert code == 0, text
    _refused_by_text(tree, monkeypatch, f"tail -f {docker}/x.log", tool="Monitor")


def test_a_path_the_guard_cannot_see_names_the_entry_and_the_way_out(tree, monkeypatch, docker):
    code, text = _hook(tree, monkeypatch, "docker run -v $UNSEEN:/x img")
    assert code == 2, text
    assert D8 in text and "sandbox.excludedCommands" in text, text
    assert USER_FILE in text and "removes" in text, text


def test_a_folder_above_a_root_names_the_entry_and_the_way_out(tree, monkeypatch, docker):
    code, text = _hook(tree, monkeypatch, f"cd {tree} && ls")
    assert code == 2 and "folder that holds protected data" in text, text
    assert "sandbox.excludedCommands" in text and USER_FILE in text and "removes" in text, text


def test_without_an_entry_the_same_call_is_allowed(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    _wired(tree)
    code, text = _hook(tree, monkeypatch, "docker run -v $UNSEEN:/x img")
    assert code == 0, text
    assert "excludedCommands" not in text, text


@pytest.mark.parametrize("entry", ["env *", "FOO=1 make *", "docker:*", "do*er"])
def test_any_entry_gives_the_text_check(tree, monkeypatch, entry):
    protect(tree, [], best_effort=False)
    _wired(tree, excludedCommands=[entry])
    code, text = _hook(tree, monkeypatch, "ls *.py")
    assert code == 0, text
    _refused_by_text(tree, monkeypatch, f"cat {tree}/phi/FAKE-PT-0001.bam")


def test_an_entry_in_a_project_folder_above_the_call_counts(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    _wired(tree)
    sub = tree / "repo" / "sub"
    (sub / ".claude").mkdir(parents=True)
    (sub / ".claude" / "settings.json").write_text("{}")
    s = tree / "repo" / ".claude"
    s.mkdir()
    (s / "settings.json").write_text(json.dumps({"sandbox": {"excludedCommands": ["docker *"]}}))
    code, text = _hook(tree, monkeypatch, "docker run -v $UNSEEN:/x img", cwd=sub)
    assert code == 2 and "sandbox.excludedCommands" in text and D8 in text, text
    code, text = _hook(tree, monkeypatch, "ls *.py", cwd=sub)
    assert code == 0, text


def test_another_opener_still_refuses_the_whole_shell(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    _wired(tree, excludedCommands=["docker *"], enableWeakerNestedSandbox=True)
    code, text = _hook(tree, monkeypatch, "ls")
    assert code == 2 and "every command is refused but a whole gateway call" in text, text


def test_dangerously_disable_sandbox_still_refuses(tree, monkeypatch, docker):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    payload = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
               "permission_mode": "default", "tool_name": "Bash",
               "tool_input": {"command": "ls", "dangerouslyDisableSandbox": True}}
    out, err = io.StringIO(), io.StringIO()
    assert claude.main(io.StringIO(json.dumps(payload)), out, err) == 2


def test_the_confinement_reason_keeps_its_meaning(tree, docker):
    cfg = config.load(str(tree / "repo"))
    r = claude_settings.confinement_reason(str(tree / "repo"), str(tree / "home"),
                                           cfg.all_roots, cfg.patterns, config.guard_files())
    assert r is not None and "excludedCommands" in r.text, r
    assert claude_settings.shell_reason(str(tree / "repo"), str(tree / "home"), cfg.all_roots,
                                        cfg.patterns, config.guard_files()) is None
    assert claude_settings.excluded_entries(str(tree / "repo"), str(tree / "home")) == \
        ["docker *"]


def test_inner_mode_still_counts_an_entry(tree):
    s = tree / "repo" / ".claude"
    s.mkdir()
    (s / "settings.json").write_text(json.dumps({"sandbox": {"excludedCommands": ["docker"]}}))
    flag = {"sandbox": {"enabled": True, "failIfUnavailable": True,
                        "allowUnsandboxedCommands": False}}
    why = claude_settings.launch_sandbox_reason(str(tree / "repo"), str(tree / "home"), None,
                                                flag)
    assert why is not None and "excludedCommands" in why, why


def test_doctor_says_the_shell_is_text_checked(tree, docker):
    src = str(Path(__file__).resolve().parents[1] / "src")
    out = subprocess.run([sys.executable, "-m", "phiward", "doctor"], cwd=str(tree / "repo"),
                         capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
                         env=dict(os.environ, PYTHONPATH=src)).stdout
    line = next(ln for ln in out.splitlines() if "sandbox confines the shell" in ln)
    assert "excludedCommands is not empty" in line and USER_FILE in line, line
    assert line.count("the hook checks the text of every command") == 1, line
    assert "refuses shell commands except gateway calls" not in line, line


# --- b2: on macOS allowLocalBinding stays an opener (on Linux: test_v2_final_review.py) -------

def test_allow_local_binding_on_macos_says_where_a_dev_server_runs(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    _wired(tree, network={"allowLocalBinding": True})
    monkeypatch.setattr(sys, "platform", "darwin")
    cfg = config.load(str(tree / "repo"))
    r = claude_settings.confinement_reason(str(tree / "repo"), str(tree / "home"),
                                           cfg.all_roots, cfg.patterns, config.guard_files())
    assert r is not None and "allowLocalBinding" in r.text, r
    assert "dev server" in r.step and "your own terminal" in r.step, r
    assert USER_FILE in r.step, r
