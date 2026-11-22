"""The hooks phiward writes run from files in the installed package, not from inline code.

The user wiring, the plugin and the hook under `phiward launch` name a script or a module file
by its path, with fixed words as its arguments (exec form: `command` and `args`). The script
clears the Python and loader variables (its list is `clean-env.awk`, made from the constants in
`install`) and then runs its arguments. Each failure still blocks: a script that is not there
cannot start (`onFailure: "block"`), a program that is not there, an awk list that cannot be
read and a start with no arguments (a Claude Code that ignores `args`) exit 2, and the launched
module exits 2 when phiward's code cannot be loaded. Made-up names only.
"""

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import config, install

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "src" / "phiward"
SCRIPT = PKG / "data" / "clean-exec.sh"
AWK = PKG / "data" / "clean-env.awk"
PLUGIN = ROOT / "plugin"
EVENTS = {"PreToolUse": "hook", "SessionStart": "session-note", "UserPromptSubmit": "prompt-scan"}
OLD_CLAUDE = "2.1.200 (Claude Code)"


def _entries(hooks):
    return [(ev, h) for ev, groups in hooks.items() for g in groups for h in g["hooks"]]


def _old_entry(py, what):
    """The user wiring as an earlier phiward wrote it: one `/bin/sh -c` line."""
    clean = install.PROMPT_CLEAN_ENV if what == "prompt-scan" else install.CLEAN_ENV
    line = f"{clean}exec {shlex.quote(py)} -I -m phiward {what} claude"
    h = {"type": "command", "command": "/bin/sh -c " + shlex.quote(line), "timeout": 10}
    if what != "session-note":
        h["onFailure"] = "block"
    return h


def _run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          timeout=30, **kw)


# --- the files ----------------------------------------------------------------------------------

def test_the_hook_files_ship_in_the_package_and_the_plugin():
    assert SCRIPT.read_text().startswith("#!/bin/sh\n")
    assert os.access(SCRIPT, os.X_OK)
    assert AWK.read_text() == install.clean_env_awk()  # one list: the constants
    assert (PKG / "entry.py").is_file()
    for name in ("clean-exec.sh", "clean-env.awk"):
        assert (PLUGIN / "hooks" / name).read_bytes() == (PKG / "data" / name).read_bytes(), name
    assert os.access(PLUGIN / "hooks" / "clean-exec.sh", os.X_OK)
    text = (ROOT / "pyproject.toml").read_text()
    assert '"data/*.sh"' in text and '"data/*.awk"' in text
    assert install.CLEAN_EXEC == str(Path(install.__file__).parent / "data" / "clean-exec.sh")


# --- what phiward writes ------------------------------------------------------------------------

def test_the_user_wiring_runs_the_script_with_fixed_words(tree):
    w = install.wiring(config.load(str(tree / "repo")))
    got = _entries(w["hooks"])
    assert sorted(ev for ev, _h in got) == sorted(EVENTS)
    for ev, h in got:
        # the script itself is the command: a Claude Code that ignores `args` runs it alone,
        # and it refuses
        assert h["command"] == install.CLEAN_EXEC, h
        assert h["args"] == [sys.executable, "-I", "-m", "phiward", EVENTS[ev], "claude"], h
        assert h["timeout"] == 10
        assert h.get("onFailure") == (None if ev == "SessionStart" else "block"), h
        assert install.hook_python(h, EVENTS[ev]) == sys.executable


def test_the_plugin_runs_its_own_script_as_the_command():
    data = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
    got = _entries(data["hooks"])
    assert sorted(ev for ev, _h in got) == sorted(EVENTS)
    for ev, h in got:
        assert h["command"] == "${CLAUDE_PLUGIN_ROOT}/hooks/clean-exec.sh", h
        assert h["args"] == ["phiward", EVENTS[ev], "claude"], h
        assert h["timeout"] == 10
        assert h.get("onFailure") == (None if ev == "SessionStart" else "block"), h
    mcp = json.loads((PLUGIN / ".mcp.json").read_text())
    assert mcp["mcpServers"]["phiward"] == {"command": "phiward", "args": ["mcp"]}


def _launched(folder):
    from phiward import wholetool
    fd = os.open(str(folder), os.O_RDONLY)
    try:
        wholetool.ADAPTERS["claude"].turn_own_sandbox_off(fd)
    finally:
        os.close(fd)
    return json.loads((folder / "settings.json").read_text())


def test_the_launched_hooks_run_phiwards_module_file(tmp_path):
    from phiward import wholetool
    entry = str(Path(wholetool.__file__).parent / "entry.py")
    s = _launched(tmp_path)
    pre = [h for g in s["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert pre == [{"type": "command", "command": sys.executable,
                    "args": ["-I", "-S", entry, "hook", "claude", "--launched"],
                    "timeout": 5, "onFailure": "block"}], pre
    scan = [h for g in s["hooks"]["UserPromptSubmit"] for h in g["hooks"]]
    assert scan == [{"type": "command", "command": sys.executable,
                     "args": ["-I", "-S", entry, "prompt-scan", "claude"],
                     "timeout": 10, "onFailure": "block"}], scan
    assert _launched(tmp_path) == s  # replaced, never doubled


def test_the_launched_hooks_replace_the_older_inline_form(tmp_path):
    old = (f"{shlex.quote(sys.executable)} -I -S -c 'import sys; from phiward.cli import main; "
           "sys.exit(main())' hook claude --launched")
    mine = {"type": "command", "command": "/opt/tools/my-own-hook"}
    (tmp_path / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": old, "timeout": 5}]},
        {"matcher": "Bash", "hooks": [mine]}]}}))
    pre = [h for g in _launched(tmp_path)["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert mine in pre and len(pre) == 2 and all("-c" not in h.get("args", []) for h in pre)
    assert not any(" -c " in h["command"] for h in pre), pre


# --- the script ---------------------------------------------------------------------------------

def test_the_script_clears_the_python_and_loader_variables(tmp_path):
    evil = tmp_path / "evilbin"  # an `awk` first on PATH: not the one used
    evil.mkdir()
    (evil / "awk").write_text("#!/bin/sh\nexit 0\n")
    (evil / "awk").chmod(0o755)
    env = {"PATH": f"{evil}:/usr/bin:/bin", "PYTHONPATH": "/evil", "PYTHONWHATEVER": "1",
           "LD_PRELOAD": "/evil.so", "DYLD_INSERT_LIBRARIES": "/evil.dylib",
           "__PYVENV_LAUNCHER__": "/evil/python", "OPENSSL_CONF": "/evil.cnf",
           "MallocStackLogging": "1", "GCONV_PATH": "/evil", "TZ": ":/evil/zone",
           "KEEP_ME": "FAKE-PT-0001", "XDG_CONFIG_HOME": "/kept"}
    r = _run([str(SCRIPT), "/usr/bin/env"], env=env)
    assert r.returncode == 0, r.stderr
    assert "KEEP_ME=FAKE-PT-0001" in r.stdout and "XDG_CONFIG_HOME=/kept" in r.stdout
    for name in env:
        if name not in ("PATH", "KEEP_ME", "XDG_CONFIG_HOME"):
            assert name + "=" not in r.stdout, (name, r.stdout)


def test_the_script_refuses_when_started_without_its_arguments(tmp_path):
    marker = tmp_path / "RAN"
    r = _run([str(SCRIPT)], env={"PATH": "/usr/bin:/bin"})
    assert r.returncode == 2 and r.stdout == "", (r.returncode, r.stdout)
    assert "2.1.295" in r.stderr
    # an old Claude Code runs the command through `sh -c` and gives it the hook's input: the
    # script reads no input, so nothing in it runs
    payload = json.dumps({"tool_input": {"command": f"$(touch {marker})"}})
    r = subprocess.run(["/bin/sh", "-c", str(SCRIPT)], input=payload, capture_output=True,
                       text=True, env={"PATH": "/usr/bin:/bin"}, timeout=30)
    assert r.returncode == 2 and not marker.exists()


@pytest.mark.parametrize("what", ["hook", "prompt-scan", "session-note"])
def test_the_script_refuses_a_program_that_is_not_there(tmp_path, what):
    for argv in (["phiward", what, "claude"],  # by name, not on PATH
                 [str(tmp_path / "gone" / "python"), "-I", "-m", "phiward", what, "claude"]):
        r = _run([str(SCRIPT)] + argv, env={"PATH": str(tmp_path)})
        if what == "session-note":  # the note says so; a start is never stopped
            assert r.returncode == 0 and "phiward" in r.stdout, (r.returncode, r.stdout)
            continue
        assert r.returncode == 2, (argv, r.returncode, r.stdout, r.stderr)
        assert "refused" in r.stderr
        if what == "prompt-scan":  # a plugin's exit 2 needs the block reply on stdout
            reply = json.loads(r.stdout)
            assert reply["decision"] == "block" and "every prompt" in reply["reason"]
            assert reply["hookSpecificOutput"]["suppressOriginalPrompt"] is True
        else:
            assert r.stdout == ""


@pytest.mark.parametrize("what", ["hook", "prompt-scan"])
def test_the_script_refuses_when_its_list_cannot_be_read(tmp_path, what):
    copy = tmp_path / "pkg" / "clean-exec.sh"  # beside it, no clean-env.awk
    copy.parent.mkdir()
    shutil.copy2(SCRIPT, copy)
    fake = tmp_path / "fakepython"
    fake.write_text(f"#!/bin/sh\ntouch {tmp_path}/RAN\n")
    fake.chmod(0o755)
    r = _run([str(copy), str(fake), "-I", "-m", "phiward", what, "claude"],
             env={"PATH": "/usr/bin:/bin", "LD_PRELOAD": "/evil.so"})
    assert r.returncode == 2 and not (tmp_path / "RAN").exists(), (r.returncode, r.stderr)
    assert "awk" in r.stderr
    if what == "prompt-scan":
        assert json.loads(r.stdout)["decision"] == "block"
    shutil.copy2(AWK, copy.parent / "clean-env.awk")
    r = _run([str(copy), str(fake), "-I", "-m", "phiward", what, "claude"],
             env={"PATH": "/usr/bin:/bin", "LD_PRELOAD": "/evil.so"})
    assert r.returncode == 0 and (tmp_path / "RAN").exists(), r.stderr


def test_a_script_that_is_not_there_cannot_start_and_the_entry_blocks(tree, tmp_path):
    w = install.wiring(config.load(str(tree / "repo")))
    for ev, h in _entries(w["hooks"]):
        gone = [str(tmp_path / "moved" / "clean-exec.sh")] + h["args"]
        with pytest.raises(FileNotFoundError):  # Claude Code: the hook cannot start
            subprocess.run(gone, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        if ev != "SessionStart":
            assert h["onFailure"] == "block"


# --- the launched module ------------------------------------------------------------------------

def test_the_launched_module_starts_phiward():
    r = _run([sys.executable, "-I", "-S", str(PKG / "entry.py"), "--version"],
             env={"PATH": "/usr/bin:/bin"})
    assert r.returncode == 0 and r.stdout.startswith("phiward "), (r.stdout, r.stderr)


def test_the_launched_module_exits_2_when_phiwards_code_is_gone(tmp_path):
    moved = tmp_path / "phiward" / "entry.py"  # a package folder without the package
    moved.parent.mkdir()
    shutil.copy2(PKG / "entry.py", moved)
    r = _run([sys.executable, "-I", "-S", str(moved), "hook", "claude", "--launched"],
             env={"PATH": "/usr/bin:/bin"})
    assert r.returncode == 2 and "refused" in r.stderr, (r.returncode, r.stderr)
    r = _run([sys.executable, "-I", "-S", str(tmp_path / "gone" / "entry.py"), "hook", "claude"],
             env={"PATH": "/usr/bin:/bin"})
    assert r.returncode == 2, r.returncode  # Python's own exit for a file that is not there


# --- launch's Claude Code floor (macOS) ---------------------------------------------------------

def _fake(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)
    return str(path)


def test_the_claude_code_floor(tmp_path):
    from phiward import wholetool
    old = _fake(tmp_path / "a" / "claude", f"#!/bin/sh\necho '{OLD_CLAUDE}'\n")
    assert "2.1.295" in wholetool.claude_version_problem(old)
    new = _fake(tmp_path / "b" / "claude", "#!/bin/sh\necho '2.1.330 (Claude Code)'\n")
    assert wholetool.claude_version_problem(new) == ""
    mute = _fake(tmp_path / "c" / "claude", "#!/bin/sh\nexit 1\n")
    assert wholetool.claude_version_problem(mute)  # a Claude Code that gives no version
    other = _fake(tmp_path / "d" / "made-up-agent", "#!/bin/sh\necho 'made-up 1.0'\n")
    assert wholetool.claude_version_problem(other) == ""  # not Claude Code


def test_launch_on_macos_refuses_a_claude_code_below_the_floor(tree, monkeypatch):
    from phiward import confine, selfcheck, wholetool
    monkeypatch.setattr(confine, "backend", lambda: "seatbelt")
    monkeypatch.setattr(selfcheck, "check_isolated", lambda *a, **k: (False, []))
    old = _fake(tree / "made-up-bin" / "claude", f"#!/bin/sh\necho '{OLD_CLAUDE}'\n")
    with pytest.raises(wholetool.LaunchError, match="2.1.295"):
        wholetool.build([old], str(tree / "repo"), dict(os.environ), wholetool.ADAPTERS["claude"])


# --- existing installs --------------------------------------------------------------------------

def test_install_replaces_the_old_entries_in_place(tree):
    w = install.wiring(config.load(str(tree / "repo")))
    mine = {"type": "command", "command": "/opt/tools/my-own-hook"}
    current = {"hooks": {
        "PreToolUse": [{"matcher": "*", "hooks": [_old_entry(sys.executable, "hook"), mine]}],
        "SessionStart": [{"hooks": [_old_entry(sys.executable, "session-note")]}],
        "UserPromptSubmit": [{"hooks": [_old_entry(sys.executable, "prompt-scan")]}]}}
    m = install.merge(current, w)
    assert m["hooks"]["PreToolUse"] == [
        {"matcher": "*", "hooks": [w["hooks"]["PreToolUse"][0]["hooks"][0], mine]}], m["hooks"]
    for ev in ("SessionStart", "UserPromptSubmit"):
        assert m["hooks"][ev] == w["hooks"][ev], m["hooks"][ev]
    assert install.merge(m, w) == m


def test_install_replaces_an_entry_whose_python_moved(tree):
    w = install.wiring(config.load(str(tree / "repo")))
    moved = {"type": "command",
             "command": "/made-up/old/lib/python3.11/site-packages/phiward/data/clean-exec.sh",
             "args": ["/made-up/old/bin/python", "-I", "-m", "phiward", "hook", "claude"],
             "timeout": 10, "onFailure": "block"}
    m = install.merge({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [moved]}]}}, w)
    assert m["hooks"]["PreToolUse"] == w["hooks"]["PreToolUse"], m["hooks"]["PreToolUse"]


def _user_settings(tree, hooks):
    d = tree / "home" / ".claude"
    d.mkdir(exist_ok=True)
    (d / "settings.json").write_text(json.dumps({"hooks": hooks}))


def test_doctor_asks_for_install_again_for_an_old_form_entry(tree):
    from phiward import doctor
    _user_settings(tree, {
        "PreToolUse": [{"matcher": "*", "hooks": [_old_entry(sys.executable, "hook")]}],
        "UserPromptSubmit": [{"hooks": [_old_entry(sys.executable, "prompt-scan")]}]})
    w = doctor.wiring_state(str(tree / "repo"), str(tree / "home"))
    assert w.wired
    assert any("older phiward" in ln and "install claude --user --write" in ln
               for ln in w.lines), w.lines


def test_doctor_takes_the_new_form_as_phiwards_own(tree):
    from phiward import doctor
    hooks = install.wiring(config.load(str(tree / "repo")))["hooks"]
    _user_settings(tree, hooks)
    w = doctor.wiring_state(str(tree / "repo"), str(tree / "home"))
    assert w.wired and w.isolated, (w.lines, w.problems)
    assert not any("older phiward" in ln for ln in w.lines), w.lines
    assert not [p for p in w.problems if "hook" in p or "prompt" in p], w.problems
    assert doctor.hook_form(hooks["PreToolUse"][0]["hooks"][0]) == "isolated"
    assert doctor.is_prompt_scan(hooks["UserPromptSubmit"][0]["hooks"][0])


def test_doctor_names_a_moved_python(tree):
    from phiward import doctor
    gone = "/made-up/old/lib/python3.11/site-packages/phiward/data/clean-exec.sh"
    entry = {"type": "command", "command": gone, "timeout": 10, "onFailure": "block",
             "args": ["/made-up/old/bin/python", "-I", "-m", "phiward", "hook", "claude"]}
    scan = dict(entry, args=entry["args"][:4] + ["prompt-scan", "claude"])
    _user_settings(tree, {"PreToolUse": [{"matcher": "*", "hooks": [entry]}],
                          "UserPromptSubmit": [{"hooks": [scan]}]})
    w = doctor.wiring_state(str(tree / "repo"), str(tree / "home"))
    assert any("moved" in p and "install claude --user --write" in p for p in w.problems), \
        w.problems


# --- the checks install and doctor run ----------------------------------------------------------

def test_install_and_doctor_start_no_inline_code(monkeypatch):
    from phiward import doctor
    seen = []

    def fake_run(argv, *a, **k):
        seen.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "/made-up/bin/" + name)
    assert install._isolated_import_problem() == ""
    assert doctor.clean_start_problem() is None
    assert seen == [[sys.executable, "-I", "-m", "phiward", "--version"],
                    [install.CLEAN_EXEC, "phiward", "--help"]], seen
