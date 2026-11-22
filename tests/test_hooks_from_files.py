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
           # a loader variable that does not stop /bin/sh itself when it is wrong: where SIP is
           # off (GitHub's macOS runners), DYLD_INSERT_LIBRARIES acts on the shell before the
           # script's first line, which no script can clear; the awk list covers every DYLD_ name
           "LD_PRELOAD": "/evil.so", "DYLD_LIBRARY_PATH": "/evil", "DYLD_FALLBACK_LIBRARY_PATH": "/evil",
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


# --- launch's Claude Code floor (macOS and Linux) -----------------------------------------------

def _fake(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)
    return str(path)


def _npm(folder: Path, version: str, marker: Path, name: str = "@anthropic-ai/claude-code",
         text: str = "") -> str:
    """A made-up npm build: a script that leaves `marker` if it is ever started, and its
    package's package.json beside it."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "package.json").write_text(
        text or json.dumps({"name": name, "version": version, "bin": {"claude": "claude"}}))
    return _fake(folder / "claude", f"#!/bin/sh\ntouch {marker}\necho '{version} (Claude Code)'\n")


def test_the_claude_code_floor(tmp_path):
    from phiward import wholetool
    places = [str(tmp_path / "project")]
    ran = tmp_path / "RAN"
    old = _npm(tmp_path / "a", "2.1.200", ran)
    assert "2.1.295" in wholetool.claude_version_problem(old, places)
    new = _npm(tmp_path / "b", "2.1.330", ran)
    assert wholetool.claude_version_problem(new, places) == ""
    # a link to the script (npm's bin/claude) finds the package the same way
    os.symlink(new, tmp_path / "claude-link")
    assert wholetool.claude_version_problem(str(tmp_path / "claude-link"), places) == ""
    assert not ran.exists()  # a script is read, never started
    # no version, whatever the program's name: refused, with the way on
    for name, text in (("claude", "exit 1"), ("claude", "echo"),
                       ("made-up-agent", "echo 'made-up 1.0'"),
                       ("my-claude", f"exec {new} --verbose \"$@\"")):  # a wrapper
        p = _fake(tmp_path / "c" / name, f"#!/bin/sh\ntouch {ran}\n{text}\n")
        why = wholetool.claude_version_problem(p, places)
        assert "directly" in why and "--tool generic" in why, (name, why)
    assert not ran.exists()


@pytest.mark.parametrize("bad", ["another-name", "not json", "too big", "no version", "a list"])
def test_a_script_whose_package_json_is_not_claude_codes_is_refused(tmp_path, bad):
    from phiward import wholetool
    ran = tmp_path / "RAN"
    text = {"not json": "{2.1.330", "a list": "[\"2.1.330\"]",
            "too big": json.dumps({"name": "@anthropic-ai/claude-code", "version": "2.1.330",
                                   "x": "y" * 200_000}),
            "no version": json.dumps({"name": "@anthropic-ai/claude-code"})}.get(bad, "")
    p = _npm(tmp_path / "pkg", "2.1.330", ran, name="made-up-claude", text=text)
    why = wholetool.claude_version_problem(p, [str(tmp_path / "project")])
    assert "directly" in why and "--tool generic" in why, why
    assert not ran.exists()


def test_a_script_with_no_package_json_is_refused_unstarted(tmp_path, monkeypatch):
    # a mise or asdf shim, or an npm build whose PATH puts a project folder ahead of node: the
    # interpreter it names could be the session's, so it is never started to ask a version
    from phiward import wholetool
    ran = tmp_path / "RAN"
    shim = _fake(tmp_path / "shims" / "claude", "#!/usr/bin/env node\n")
    node = _fake(tmp_path / "project" / "bin" / "node", f"#!/bin/sh\ntouch {ran}\n")
    monkeypatch.setenv("PATH", f"{os.path.dirname(node)}:/usr/bin:/bin")
    why = wholetool.claude_version_problem(shim, [str(tmp_path / "project")], dict(os.environ))
    assert why and not ran.exists(), why


def test_a_native_build_is_asked_from_the_root_folder(tmp_path, monkeypatch):
    from phiward import wholetool
    native = tmp_path / "opt" / "claude"
    native.parent.mkdir()
    native.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 64)
    native.chmod(0o755)
    seen = {}

    def run(cmd, **kw):
        seen.update(kw, cmd=cmd)
        return subprocess.CompletedProcess(cmd, 0, "2.1.330 (Claude Code)\n", "")
    monkeypatch.setattr(wholetool.subprocess, "run", run)
    assert wholetool.claude_version_problem(str(native), [str(tmp_path / "project")]) == ""
    assert seen["cmd"] == [str(native), "--version"] and seen.get("cwd") == "/", seen


def test_the_floor_never_starts_a_claude_the_session_can_write(tmp_path):
    from phiward import wholetool
    marker = tmp_path / "RAN"
    places = [str(tmp_path / "project")]
    inside = _fake(tmp_path / "project" / "bin" / "claude",
                   f"#!/bin/sh\ntouch {marker}\necho '2.1.330 (Claude Code)'\n")
    why = wholetool.claude_version_problem(inside, places)
    assert why and "write" in why and not marker.exists(), why
    # nor through a link from outside to a file inside
    os.symlink(inside, tmp_path / "claude")
    why = wholetool.claude_version_problem(str(tmp_path / "claude"), places)
    assert why and "write" in why and not marker.exists(), why
    # nor with a package.json that links into a write place
    pkg = tmp_path / "pkg"
    _npm(pkg, "2.1.330", marker)
    (tmp_path / "project" / "package.json").write_text((pkg / "package.json").read_text())
    (pkg / "package.json").unlink()
    os.symlink(tmp_path / "project" / "package.json", pkg / "package.json")
    why = wholetool.claude_version_problem(str(pkg / "claude"), places)
    assert why and not marker.exists(), why


@pytest.mark.timeout(30)
def test_a_fifo_named_as_claude_is_refused_without_a_hang(tmp_path):
    from phiward import wholetool
    fifo = tmp_path / "bin" / "claude"
    fifo.parent.mkdir()
    os.mkfifo(fifo)
    assert wholetool.claude_version_problem(str(fifo), [str(tmp_path / "project")])


@pytest.mark.parametrize("backend", ["seatbelt", "bwrap"])
def test_launch_refuses_a_claude_code_below_the_floor(tree, monkeypatch, backend):
    from phiward import confine, selfcheck, wholetool
    monkeypatch.setattr(confine, "backend", lambda: backend)
    monkeypatch.setattr(selfcheck, "check_isolated", lambda *a, **k: (False, []))
    # on this Mac the test's folder is in the per-user temp folder, a write place
    monkeypatch.setattr(wholetool, "_darwin_user_dir", lambda name: "")
    old = _npm(tree / "made-up-bin", "2.1.200", tree / "RAN")
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
