"""The hook trusts an MCP server as wrapped only when it really runs wrapped: each `phiward
launch` keeps a record of its own process (pid, start time, parent, a hash of what it runs) in
~/.phiward/launched while it runs, and the hook needs a live launcher of the server's command
that is a child of the hook's own Claude Code process. A server wrapped in the config after
Claude Code started it still runs bare; `/mcp` reconnect starts it under a launcher. Resume,
clear and compact change nothing. Made-up trees only."""

import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from phiward import config, mcp_config, procinfo
from phiward.adapters import claude
from helpers import CONFINE_WHY, launcher_by_path, protect

SRC = str(Path(__file__).resolve().parents[1] / "src")
SERVER = str(Path(__file__).resolve().parent / "probes" / "mcp_reader.py")
PHIWARD = "phiward"  # the launcher by its path, set by launcher_by_path
WRAPPED = {"command": "phiward", "args": ["launch", "--", "npx", "-y", "some-server"]}
BARE = {"command": "npx", "args": ["-y", "some-server"]}
H0 = mcp_config.launch_hash(["--", "npx", "-y", "some-server"])  # a launcher's own record


def _H():
    """The launch hash of WRAPPED as the test gives it (its full path and entry id)."""
    return mcp_config.launch_hash(WRAPPED["args"][1:])
RUN = {"command": "id"}


@pytest.fixture()
def t(tree, monkeypatch):
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    launcher_by_path(monkeypatch, sys.modules[__name__], b / "phiward")
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    protect(tree, [], best_effort=False)
    return tree


def _servers(t, servers):
    (t / "home" / ".claude.json").write_text(json.dumps({"mcpServers": servers}))


def _hook(t, tool="mcp__term__run_command", inp=RUN, sid="0f7c2a9e-1111-4222-8333-944455556666",
          name="term"):
    p = {"session_id": sid, "hook_event_name": "PreToolUse", "cwd": str(t / "repo"),
         "permission_mode": "default", "tool_name": tool, "tool_input": inp,
         "mcp_server": {"name": name, "source": "user"}}
    err = io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err), err.getvalue()


def test_a_wrapped_server_with_a_live_launcher_is_trusted(t, launchers):
    _servers(t, {"term": WRAPPED})
    launchers.start(_H())
    assert _hook(t)[0] == 0


def test_wrapping_while_the_bare_server_runs_is_not_trusted_until_it_is_restarted(t, launchers):
    _servers(t, {"term": BARE})  # Claude Code starts it bare: no launcher
    _servers(t, {"term": WRAPPED})  # the operator wraps it
    code, err = _hook(t)
    assert code == 2 and "starts Claude Code again" in err, err
    launchers.start(_H())  # started again: now it runs under a launcher
    assert _hook(t)[0] == 0


@pytest.mark.parametrize("sid", ["1f7c2a9e-1111-4222-8333-944455556666", "", "../x"])
def test_the_session_id_does_not_matter(t, launchers, sid):
    _servers(t, {"term": WRAPPED})
    launchers.start(_H())
    assert _hook(t, sid=sid)[0] == 0


def test_a_launcher_that_ended_does_not_count(t, launchers):
    _servers(t, {"term": WRAPPED})
    p = launchers.start(_H())
    p.kill()
    p.wait()
    assert _hook(t)[0] == 2


def test_a_record_with_another_start_time_does_not_count(t, launchers):
    _servers(t, {"term": WRAPPED})
    p = launchers.start(_H())
    path = Path(mcp_config.launched_dir()) / f"{p.pid}.json"
    rec = json.loads(path.read_text())
    rec["start"] += 1  # the number was taken again by another process
    path.write_text(json.dumps(rec))
    assert _hook(t)[0] == 2


def test_a_launcher_of_another_command_does_not_count(t, launchers):
    _servers(t, {"term": WRAPPED})
    launchers.start(mcp_config.launch_hash(["--", "npx", "-y", "other-server"]))
    assert _hook(t)[0] == 2


@pytest.mark.parametrize("mode", [0o644, 0o622])
def test_a_record_others_can_read_or_write_does_not_count(t, launchers, mode):
    _servers(t, {"term": WRAPPED})
    launchers.start(_H(), mode=mode)
    assert _hook(t)[0] == 2


def test_a_folder_others_can_read_does_not_count(t, launchers):
    _servers(t, {"term": WRAPPED})
    launchers.start(_H())
    os.chmod(mcp_config.launched_dir(), 0o755)
    assert _hook(t)[0] == 2


def test_a_launcher_that_is_not_a_child_of_this_claude_code_does_not_count(t, launchers):
    """A launcher the agent starts from Bash has the sandboxed shell as its parent: not an
    ancestor of the hook. Here: a launcher whose parent is a shell this test started."""
    _servers(t, {"term": WRAPPED})
    sh = subprocess.Popen(["sh", "-c", "sleep 300 & echo $!; wait"], stdout=subprocess.PIPE,
                          text=True)
    try:
        child = int(sh.stdout.readline())
        got = procinfo.info(child)
        assert got is not None and got[0] == sh.pid
        folder = mcp_config.launched_dir()
        os.makedirs(folder, mode=0o700, exist_ok=True)
        path = os.path.join(folder, f"{child}.json")
        with open(path, "w") as fh:
            json.dump({"pid": child, "ppid": got[0], "start": got[1], "argv": _H()}, fh)
        os.chmod(path, 0o600)
        assert _hook(t)[0] == 2
    finally:
        sh.kill()
        sh.wait()
        try:
            os.kill(child, 9)
        except (OSError, UnboundLocalError):
            pass


def test_two_names_need_two_ids_and_two_launchers(t, launchers):
    """One of them may still run bare (it was wrapped after it started): one launcher of the
    command cannot speak for both."""
    _servers(t, {"term": WRAPPED, "term2": WRAPPED})  # a copy: one entry id twice
    launchers.start(_H())
    launchers.start(_H())
    assert _hook(t)[0] == 2  # trusted for nothing (test_v2_entry_id)
    other = dict(WRAPPED, args=["launch", "--entry", "00000000000000aa"] + WRAPPED["args"][3:])
    _servers(t, {"term": WRAPPED, "term2": other})
    assert _hook(t)[0] == 0
    assert _hook(t, tool="mcp__term2__run_command", name="term2")[0] == 2
    launchers.start(mcp_config.launch_hash(other["args"][1:]))
    assert _hook(t, tool="mcp__term2__run_command", name="term2")[0] == 0


def test_the_folder_is_a_guard_file(t):
    assert mcp_config.launched_dir() in config.guard_files()


def test_session_start_writes_no_record(t):
    from phiward import session_note
    payload = {"session_id": "0f7c2a9e-1111-4222-8333-944455556666",
               "hook_event_name": "SessionStart", "source": "startup", "cwd": str(t / "repo")}
    old = sys.stdin
    sys.stdin = io.StringIO(json.dumps(payload))
    try:
        session_note.main(["claude"])
    finally:
        sys.stdin = old
    assert not (t / "home" / ".phiward" / "sessions").exists()


def test_record_launch_writes_a_private_record_and_end_launch_removes_it(t):
    path = mcp_config.record_launch(["--", "npx", "-y", "some-server"])
    assert path is not None
    rec = json.loads(Path(path).read_text())
    assert rec["pid"] == os.getpid() and rec["argv"] == H0
    assert (rec["ppid"], rec["start"]) == procinfo.info(os.getpid())
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert os.stat(os.path.dirname(path)).st_mode & 0o777 == 0o700
    mcp_config.end_launch(path)
    assert not os.path.exists(path)


def test_records_of_ended_launchers_are_removed(t, launchers):
    p = launchers.start(_H())
    path = Path(mcp_config.launched_dir()) / f"{p.pid}.json"
    p.kill()
    p.wait()
    mcp_config.end_launch(mcp_config.record_launch(["x"]))
    assert not path.exists()


def test_the_process_reader_knows_this_process():
    got = procinfo.info(os.getpid())
    if got is None:
        pytest.skip("no process reader on this system")
    assert got[0] == os.getppid()
    assert procinfo.info(10 ** 9) is None
    assert procinfo.ancestors()[0] == os.getppid()
    assert 1 not in procinfo.ancestors()


# --- a real `phiward launch` ---------------------------------------------------------------------


@pytest.mark.skipif(CONFINE_WHY is not None, reason=f"no confinement: {CONFINE_WHY}")
def test_a_real_launcher_is_trusted_while_it_runs(t, monkeypatch):
    """This test process stands in for Claude Code: it starts the server's command from the
    config (`python -m phiward launch -- python -I mcp_reader.py`) and then asks the hook."""
    if sys.platform.startswith("linux") and str(t).startswith("/tmp/"):
        pytest.skip("Linux: the tree is under the session's own /tmp; run with --basetemp")
    real = procinfo.ancestors
    monkeypatch.setattr(procinfo, "ancestors",
                        lambda pid=None, depth=4: [os.getpid()] + real(os.getpid(), depth - 1))
    # the launcher as a file, as an installed phiward has it (Python with `-m phiward` never
    # counts: test_v2_attacks); the fixture's folder is on the PATH phiward trusts
    launcher = t / "bin" / "phiward"
    launcher.write_text(f"#!/bin/sh\nPYTHONPATH={SRC} exec {sys.executable} -m phiward \"$@\"\n")
    launcher.chmod(0o755)
    cmd = [str(launcher), "launch", "--entry", "0123456789abcdef", "--",
           sys.executable, "-I", SERVER]
    _servers(t, {"term": {"command": cmd[0], "args": cmd[1:]}})
    env = dict(os.environ, PYTHONPATH=SRC, PHIWARD_DEV="1")
    p = subprocess.Popen(cmd, cwd=str(t / "repo"), env=env, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    try:
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                  "params": {}}) + "\n")
        p.stdin.flush()
        assert "result" in json.loads(p.stdout.readline())
        record = Path(mcp_config.launched_dir()) / f"{p.pid}.json"
        assert record.exists()
        assert _hook(t)[0] == 0
    finally:
        p.stdin.close()
        p.wait(timeout=60)
    deadline = time.time() + 10
    while record.exists() and time.time() < deadline:
        time.sleep(0.1)
    assert not record.exists()
    assert _hook(t)[0] == 2


def test_a_record_being_written_by_another_launcher_is_left_alone(t):
    folder = Path(mcp_config.launched_dir())
    folder.mkdir(parents=True, mode=0o700)
    tmp = folder / "12345.json.0123456789abcdef.tmp"
    tmp.write_text('{"pid": 12')  # half written
    mcp_config.end_launch(mcp_config.record_launch(["x"]))
    assert tmp.exists()
    old = time.time() - 120
    os.utime(tmp, (old, old))
    mcp_config.end_launch(mcp_config.record_launch(["x"]))
    assert not tmp.exists()
