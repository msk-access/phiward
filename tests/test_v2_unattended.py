"""Unattended agents (headless `claude -p`, the Agent SDK): the wiring as one JSON for an SDK
app, the `doctor --headless` preflight, and the PreToolUse callback printed in
docs/unattended.md. Made-up data only; the real `claude` never runs."""

import asyncio
import json
import os
import re
import stat
import sys
from pathlib import Path

import pytest

from phiward import config, doctor, install

ROOT = Path(__file__).resolve().parents[1]


def test_install_json_prints_the_user_wiring_as_one_json(tree, capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", Tty())
    assert install.main(["claude", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == install.wiring(config.load(os.getcwd()))
    assert data["sandbox"]["failIfUnavailable"] is True and data["hooks"]["PreToolUse"]


def test_install_json_is_for_the_user_wiring_only(tree, capsys):
    assert install.main(["claude", "--json", "--project"]) == 2
    assert install.main(["claude", "--json", "--write"]) == 2


def test_doctor_headless_fails_when_nothing_is_wired(tree, capsys, monkeypatch):
    monkeypatch.chdir(tree / "repo")
    assert doctor.main(["--headless"]) == 1
    out = capsys.readouterr().out
    assert "headless: NOT READY" in out and "not wired" in out and "broker" in out


def test_doctor_headless_passes_when_wired_and_the_broker_runs(tree, broker, capsys, monkeypatch):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(f'[protected_paths]\nroots = ["{tree}/phi"]\n')
    user_settings(tree, install.merge({}, install.wiring(config.load(str(tree / "repo")))))
    broker()
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.setattr(doctor, "sandbox_needs", lambda *a: [])  # its own test covers it
    code = doctor.main(["--headless"])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "headless: ready" in out


# --- the callback in docs/unattended.md --------------------------------------------------------

def _snippet() -> str:
    text = (ROOT / "docs" / "unattended.md").read_text()
    m = re.search(r"<!-- sdk-callback-python -->\s*```python\n(.*?)```", text, re.S)
    assert m, "the Python callback is missing from docs/unattended.md"
    return m.group(1)


@pytest.fixture()
def guard(tree, monkeypatch):
    bin_ = tree / "bin"
    bin_.mkdir()
    shim = bin_ / "phiward"
    shim.write_text(f"#!/bin/sh\nPYTHONPATH={ROOT / 'src'} exec {sys.executable} -m phiward \"$@\"\n")
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_}:{os.environ['PATH']}")
    ns: dict = {}
    exec(compile(_snippet(), "unattended.md", "exec"), ns)
    return ns["phiward_guard"]


def _call(fn, tool, tool_input, cwd, mode="bypassPermissions"):
    data = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input,
            "cwd": cwd, "session_id": "s", "permission_mode": mode}
    return asyncio.run(fn(data, "t1", None))


def _denied(r):
    return r.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


def test_the_callback_denies_a_protected_read(tree, guard):
    r = _call(guard, "Read", {"file_path": f"{tree}/phi/FAKE-PT-0001.bam"}, str(tree / "repo"))
    assert _denied(r) and "protected" in r["hookSpecificOutput"]["permissionDecisionReason"]


def test_the_callback_allows_an_ordinary_read(tree, guard):
    assert _call(guard, "Read", {"file_path": f"{tree}/repo/README.md"}, str(tree / "repo")) == {}


def test_the_callback_judges_the_shell_as_not_sandboxed(tree, guard):
    # with the wiring on disk, the CLI hook would trust the sandbox; an SDK app may not load it
    Path(os.environ["PHIWARD_CONFIG"]).write_text(f'[protected_paths]\nroots = ["{tree}/phi"]\n')
    user_settings(tree, install.merge({}, install.wiring(config.load(str(tree / "repo")))))
    import subprocess
    cmd = {"command": f"ls {tree}"}  # above a root: refused unless the sandbox is trusted
    data = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": cmd,
            "cwd": str(tree / "repo"), "permission_mode": "default"}
    trusting = subprocess.run(["phiward", "hook", "claude"], input=json.dumps(data), text=True,
                              capture_output=True, env=dict(os.environ,
                                                            CLAUDE_PROJECT_DIR=str(tree / "repo")))
    assert trusting.returncode == 0, trusting.stderr  # the CLI hook trusts the wired sandbox
    os.environ["CLAUDE_PROJECT_DIR"] = str(tree / "repo")
    try:
        r = _call(guard, "Bash", cmd, str(tree / "repo"), mode="default")
    finally:
        del os.environ["CLAUDE_PROJECT_DIR"]
    assert _denied(r)  # the callback does not


def test_the_callback_fails_closed_without_phiward(tree, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    ns: dict = {}
    exec(compile(_snippet(), "unattended.md", "exec"), ns)
    r = _call(ns["phiward_guard"], "Read", {"file_path": f"{tree}/repo/README.md"},
              str(tree / "repo"))
    assert _denied(r)


# --- headless Mode B: `launch` with no terminal, and a report for the script that started it --

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v2_carryover import launch, needs_confine  # noqa: E402
from helpers import Tty, user_settings


@needs_confine
def test_launch_runs_headless_and_passes_the_arguments_through(tree):
    import subprocess
    from test_v2_carryover import PY, env
    r = subprocess.run([PY, "-m", "phiward", "launch", "--tool", "claude", "--", PY, "-c",
                        "import sys; print('ARGS', sys.argv[1:], 'TTY', sys.stdin.isatty())",
                        "-p", "summarize the counts"],
                       cwd=str(tree / "repo"), capture_output=True, text=True, env=env(),
                       timeout=120, stdin=subprocess.DEVNULL)
    assert r.returncode == 0, r.stderr
    from helpers import landlock_abi
    if sys.platform.startswith("linux") and landlock_abi() < 9:
        # below Landlock ABI 9 launch adds, last, the --settings that keep Claude Code's
        # sandbox on (wholetool.INNER_SETTINGS); the operator's arguments come first, unchanged
        from phiward import wholetool
        want = ["-p", "summarize the counts", "--settings", json.dumps(wholetool.INNER_SETTINGS)]
        assert f"ARGS {want!r} TTY False" in r.stdout, r.stdout
    else:
        assert "ARGS ['-p', 'summarize the counts'] TTY False" in r.stdout


@needs_confine
def test_launch_report_says_nothing_to_review(tree):
    rep = tree / "home" / "report.json"
    code, out, err = launch(tree, "print('hi')", extra=("--report", str(rep)))
    assert code == 0, err
    data = json.loads(rep.read_text())
    assert data["exit"] == 0 and data["needs_review"] is False and data["notes"] == []


@needs_confine
def test_launch_report_flags_a_changed_project_and_keeps_the_exit(tree):
    rep = tree / "home" / "report.json"
    code, out, err = launch(tree, "open('CLAUDE.md','w').write('x'); raise SystemExit(3)",
                            extra=("--report", str(rep)))
    assert code == 3
    data = json.loads(rep.read_text())
    assert data["exit"] == 3 and data["needs_review"] is True
    assert any("CLAUDE.md" in n for n in data["notes"])


@needs_confine
def test_launch_report_never_writes_through_a_link(tree):
    target = tree / "pub" / "elsewhere.json"
    rep = tree / "home" / "report.json"
    os.symlink(target, rep)
    code, out, err = launch(tree, "print('hi')", extra=("--report", str(rep)))
    assert code == 0, err
    assert not target.exists()  # the link is replaced, never written through
    assert not rep.is_symlink() and json.loads(rep.read_text())["exit"] == 0


def _js_snippet() -> str:
    text = (ROOT / "docs" / "unattended.md").read_text()
    m = re.search(r"<!-- sdk-callback-js -->\s*```js\n(.*?)```", text, re.S)
    assert m, "the JavaScript callback is missing from docs/unattended.md"
    return m.group(1)


@pytest.mark.skipif(__import__("shutil").which("node") is None, reason="no node")
def test_the_javascript_callback_decides_like_the_python_one(tree, guard):
    import subprocess
    (tree / "cb.mjs").write_text(_js_snippet())
    driver = tree / "drive.mjs"
    driver.write_text(
        "import { phiwardGuard } from './cb.mjs';\n"
        "const input = JSON.parse(process.argv[2]);\n"
        "console.log(JSON.stringify(await phiwardGuard(input)));\n")

    def run(path, path_env=None):
        data = {"hook_event_name": "PreToolUse", "tool_name": "Read",
                "tool_input": {"file_path": path}, "cwd": str(tree / "repo"),
                "permission_mode": "bypassPermissions"}
        env = dict(os.environ, **({"PATH": path_env} if path_env else {}))
        r = subprocess.run([__import__("shutil").which("node"), str(driver), json.dumps(data)],
                           capture_output=True, text=True, timeout=60, env=env)
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout)

    assert _denied(run(f"{tree}/phi/FAKE-PT-0001.bam"))
    assert run(f"{tree}/repo/README.md") == {}
    only_node = tree / "only-node"  # a PATH with node and no phiward
    only_node.mkdir()
    os.symlink(os.path.realpath(__import__("shutil").which("node")), only_node / "node")
    assert _denied(run(f"{tree}/repo/README.md", path_env=str(only_node)))


# --- doctor --headless sees what turns the hook off (second review) ----------------------------

def _wired_tree(tree, mutate=None, project=None):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(f'[protected_paths]\nroots = ["{tree}/phi"]\n')
    data = install.merge({}, install.wiring(config.load(str(tree / "repo"))))
    if mutate:
        mutate(data)
    user_settings(tree, data)
    if project is not None:
        d = tree / "repo" / ".claude"
        d.mkdir(exist_ok=True)
        (d / "settings.json").write_text(json.dumps(project))
    from phiward import doctor as _d
    return _d.headless_problems(str(tree / "repo"), str(tree / "home"))


def _hooks(data):
    return [h for g in data["hooks"]["PreToolUse"] for h in g["hooks"]]


@pytest.mark.parametrize("case", ["project_disable", "user_disable", "no_onfailure",
                                  "missing_program", "one_matcher", "echo", "no_deny_rules"])
def test_headless_sees_what_turns_the_hook_off(tree, case):
    project = None

    def mutate(d):
        if case == "user_disable":
            d["disableAllHooks"] = True
        elif case == "no_onfailure":
            for h in _hooks(d):
                h.pop("onFailure")
        elif case == "missing_program":
            for h in _hooks(d):
                h["command"] = "/nonexistent/phiward hook claude"
        elif case == "one_matcher":
            # one tool only: the hook covers every tool with `*` (round 14)
            d["hooks"]["PreToolUse"][0]["matcher"] = "Bash"
        elif case == "echo":
            for h in _hooks(d):
                h["command"] = "echo phiward hook claude"
        elif case == "no_deny_rules":
            d["permissions"]["deny"] = []
    if case == "project_disable":
        project = {"disableAllHooks": True}
    problems = _wired_tree(tree, mutate, project)
    assert any("broker" not in p for p in problems), (case, problems)


def test_headless_has_no_wiring_problem_when_wired(tree):
    problems = _wired_tree(tree)
    assert [p for p in problems if "broker" not in p and "socat" not in p] == [], problems


def test_headless_reports_patterns_the_sandbox_does_not_deny(tree, capsys, monkeypatch):
    from phiward import claude_settings
    monkeypatch.setenv("HOME", str(tree / "home"))
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/phi"]\npatterns = ["{tree}/runs/*/panel"]\n')
    cfg = config.load(str(tree / "repo"))
    user_settings(tree, install.merge({}, install.wiring(cfg)))  # no version: no pattern entries
    problems = doctor.headless_problems(str(tree / "repo"), str(tree / "home"))
    assert any("pattern" in p for p in problems), problems
    if sys.platform == "darwin":  # with them, macOS's sandbox denies the patterns too
        user_settings(tree, install.merge({}, install.wiring(
            cfg, version=claude_settings.VERSION_PATTERNS)))
        problems = doctor.headless_problems(str(tree / "repo"), str(tree / "home"))
        assert not any("pattern" in p for p in problems), problems


# --- launch --report is safe against the session it reports on (second review) -----------------

@needs_confine
def test_launch_report_refuses_a_place_the_session_can_write(tree):
    code, out, err = launch(tree, "print('RAN')", extra=("--report", "run.json"))
    assert code == 2 and "RAN" not in out and "report" in err
    assert not (tree / "repo" / "run.json").exists()


@needs_confine
def test_launch_report_replaces_a_fifo_and_a_hard_link_without_touching_them(tree):
    victim = tree / "home" / "victim.txt"
    victim.write_text("keep\n")
    rep = tree / "home" / "report.json"
    os.link(victim, rep)
    code, out, err = launch(tree, "print('hi')", extra=("--report", str(rep)))
    assert code == 0, err
    assert victim.read_text() == "keep\n" and json.loads(rep.read_text())["exit"] == 0
    fifo = tree / "home" / "fifo.json"
    os.mkfifo(fifo)
    code, out, err = launch(tree, "print('hi')", extra=("--report", str(fifo)))
    assert code == 0, err
    assert json.loads(fifo.read_text())["exit"] == 0


@needs_confine
def test_launch_report_that_cannot_be_written_fails_the_run(tree):
    (tree / "home" / "adir").mkdir()
    code, out, err = launch(tree, "print('hi')", extra=("--report", str(tree / "home" / "adir")))
    assert code != 0 and "report" in err


def test_launch_report_is_written_on_an_early_exit(tree):
    import subprocess
    from test_v2_carryover import PY, env
    rep = tree / "home" / "report.json"
    rep.write_text('{"exit": 0, "needs_review": false}')
    r = subprocess.run([PY, "-m", "phiward", "launch", "--report", str(rep), "--tool", "nosuch",
                        "--", "true"], cwd=str(tree / "repo"), capture_output=True, text=True,
                       env=env(), timeout=60)
    assert r.returncode == 2
    data = json.loads(rep.read_text())
    assert data["exit"] == 2 and data["needs_review"] is True


@needs_confine
def test_launch_report_counts_changes_by_kind(tree):
    rep = tree / "home" / "report.json"
    code, out, err = launch(tree, "open('notes.txt','w').write('x')", extra=("--report", str(rep)))
    data = json.loads(rep.read_text())
    assert data["needs_review"] is False, data
    assert data["project_changed"] == {"instructions": 0, "runs_later": 0, "settings": 0,
                                       "other": 1}
    code, out, err = launch(tree, "open('Makefile','w').write('x')", extra=("--report", str(rep)))
    data = json.loads(rep.read_text())
    assert data["needs_review"] is True and data["project_changed"]["runs_later"] == 1


# --- second review: printing the wiring (it holds every root) needs your terminal -------------

def test_install_prints_the_wiring_only_on_a_terminal(tree, capsys, monkeypatch):
    assert install.main(["claude", "--json"]) == 2
    assert install.main(["claude"]) == 2
    assert str(tree / "phi") not in capsys.readouterr().out
    monkeypatch.setattr(sys, "stdin", Tty())
    assert install.main(["claude", "--json"]) == 0
    json.loads(capsys.readouterr().out)


def test_install_json_stays_json_without_protected_paths(tree, capsys, monkeypatch):
    Path(os.environ["PHIWARD_CONFIG"]).write_text("")
    monkeypatch.setattr(sys, "stdin", Tty())
    assert install.main(["claude", "--json"]) == 0
    json.loads(capsys.readouterr().out)


def test_doctor_show_paths_works_when_its_output_is_redirected(tree, capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.chdir(tree / "repo")
    doctor.main(["--show-paths"])
    assert str(tree / "phi") in capsys.readouterr().out


def test_both_callbacks_refuse_a_reply_they_cannot_read(tree, monkeypatch):
    import shutil
    import subprocess
    bad = tree / "badbin"
    bad.mkdir()
    shim = bad / "phiward"
    shim.write_text("#!/bin/sh\necho 'not json'\n")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bad}:{os.environ['PATH']}")
    ns: dict = {}
    exec(compile(_snippet(), "unattended.md", "exec"), ns)
    assert _denied(_call(ns["phiward_guard"], "Read", {"file_path": "/x"}, str(tree / "repo")))
    if shutil.which("node") is None:
        return
    (tree / "cb.mjs").write_text(_js_snippet())
    (tree / "drive.mjs").write_text("import { phiwardGuard } from './cb.mjs';\n"
                                    "console.log(JSON.stringify(await phiwardGuard({})));\n")
    r = subprocess.run([shutil.which("node"), str(tree / "drive.mjs")], capture_output=True,
                       text=True, timeout=60)
    assert _denied(json.loads(r.stdout)), r.stderr


# --- third review: the report's place, and a report on every way launch can end ------------------

@needs_confine
def test_launch_report_refuses_the_project_in_another_case(tree):
    if sys.platform != "darwin":
        pytest.skip("case folding is macOS's")
    other = str(tree / "repo").replace("/repo", "/REPO")
    code, out, err = launch(tree, "print('RAN')", extra=("--report", other + "/r.json"))
    assert code == 2 and "RAN" not in out


@needs_confine
def test_launch_report_refuses_a_guard_file(tree):
    target = tree / "home" / ".claude" / "settings.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('{"keep": true}')
    code, out, err = launch(tree, "print('RAN')", extra=("--report", str(target)))
    assert code == 2 and "RAN" not in out and json.loads(target.read_text()) == {"keep": True}


@needs_confine
def test_launch_report_refuses_a_folder_before_the_tool_runs(tree):
    (tree / "home" / "adir").mkdir()
    code, out, err = launch(tree, "print('RAN')", extra=("--report", str(tree / "home" / "adir")))
    assert code == 2 and "RAN" not in out


@needs_confine
def test_launch_writes_a_started_report_before_the_tool_runs(tree):
    # read from outside: the session cannot see the report's place (that is the rule)
    import subprocess
    import time
    from test_v2_carryover import PY, env
    rep = tree / "home" / "report.json"
    code = ("import time; open('STARTED', 'w').close(); "
            "[time.sleep(0.1) for _ in range(300) if not __import__('os').path.exists('GO')]")
    p = subprocess.Popen([PY, "-m", "phiward", "launch", "--tool", "claude", "--report", str(rep),
                          "--", PY, "-c", code], cwd=str(tree / "repo"), env=env(),
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(300):
            if (tree / "repo" / "STARTED").exists():
                break
            time.sleep(0.1)
        during = json.loads(rep.read_text())
        assert during["exit"] is None and during["ran"] is False and during["needs_review"]
        (tree / "repo" / "GO").write_text("")
        assert p.wait(timeout=60) == 0
    finally:
        if p.poll() is None:
            p.kill()
    assert json.loads(rep.read_text())["exit"] == 0


def test_a_truncated_project_scan_needs_review():
    from phiward import carryover, wholetool
    run = wholetool._Run()
    run.ran = True
    _groups, run.truncated = carryover.project_changes({carryover.TRUNCATED: ("t",)}, {}, "")
    assert run.data(0)["needs_review"] is True


@needs_confine
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root writes into a read-only folder")
def test_launch_does_not_run_when_the_started_report_cannot_be_written(tree):
    locked = tree / "home" / "locked"
    locked.mkdir()
    (locked / "report.json").write_text('{"exit": 0, "needs_review": false}')
    locked.chmod(0o500)
    try:
        code, out, err = launch(tree, "print('RAN')", extra=("--report", str(locked / "report.json")))
    finally:
        locked.chmod(0o755)
    assert code == 2 and "RAN" not in out and "report" in err


def test_launch_inside_launch_stops_when_its_report_cannot_be_written(tree, monkeypatch):
    from phiward import wholetool
    ran = []
    monkeypatch.setattr(wholetool, "already_confined", lambda env: True)
    monkeypatch.setattr(wholetool, "_write_report", lambda path, data: False)
    monkeypatch.setattr(wholetool.os, "execvp", lambda *a: ran.append(a))
    run = wholetool._Run()
    code = wholetool._launch("generic", False, ["--", "/bin/true"], dict(os.environ), run,
                             str(tree / "home" / "report.json"))
    assert code == 2 and not ran and any("report" in m for m in run.notes), run.notes
