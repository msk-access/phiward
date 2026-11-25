"""`phiward launch`, the whole agent tool in the kernel profile.

A fake agent (a Python script) stands in for the tool: whatever it and its children do, the
kernel decides. Checks with the real tool are done by hand.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from helpers import needs_confine, tool_py

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
pytestmark = needs_confine


def launch(tree, code, cwd="repo", extra=()):
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([PY, "-m", "phiward", "launch", *extra, "--",
                        tool_py(tree, "generic" if "generic" in extra else "claude"), "-c", code],
                       cwd=str(tree / cwd), capture_output=True, text=True, env=env, timeout=60)
    return r.returncode, r.stdout + r.stderr


def tries(path, mode="r"):
    return (f"import sys\ntry:\n    open({path!r}, {mode!r}).{'read' if mode == 'r' else 'write'}"
            f"({'' if mode == 'r' else repr('x')})\n    print('DONE')\nexcept OSError as e:\n"
            f"    print('REFUSED', e.errno)\n")


def test_w1_the_tool_cannot_read_a_root(tree):
    _, out = launch(tree, tries(str(tree / "phi" / "FAKE-PT-0001.bam")))
    assert "REFUSED" in out and "SECRET" not in out, out


def test_w1_a_child_of_the_tool_cannot_read_a_root(tree):
    code = (f"import subprocess; print(subprocess.run(['cat', {str(tree / 'phi' / 'FAKE-PT-0001.bam')!r}],"
            " capture_output=True, text=True).stdout or 'EMPTY')")
    _, out = launch(tree, code)
    assert "SECRET" not in out, out


def test_w1_the_tool_writes_in_the_project(tree):
    _, out = launch(tree, tries(str(tree / "repo" / "notes.txt"), "w"))
    assert "DONE" in out, out


@pytest.mark.parametrize("rel", ["home/.zshrc", "home/.gitconfig", "pub/x.txt"])
def test_w1_the_tool_cannot_write_outside_its_places(tree, rel):
    _, out = launch(tree, tries(str(tree / rel), "w"))
    # Linux: pytest's tree is under /tmp, which the tool sees as its own private /tmp; the real
    # file must stay untouched either way
    assert not (tree / rel).exists(), out
    if sys.platform == "darwin":
        assert "REFUSED" in out, out


@pytest.mark.parametrize("rel", [".git/config", ".claude/settings.json"] +
                         ([".mcp.json"] if sys.platform == "darwin" else []))
def test_w1_files_in_the_project_that_run_code_later_are_read_only(tree, rel):
    (tree / "repo" / ".git").mkdir(exist_ok=True)
    (tree / "repo" / ".git" / "config").write_text("[core]\n")  # as in a real repository
    (tree / "repo" / ".claude").mkdir(exist_ok=True)
    _, out = launch(tree, tries(str(tree / "repo" / rel), "w"))
    assert "REFUSED" in out, out


def test_w1_the_tool_cannot_write_the_user_config(tree):
    _, out = launch(tree, tries(os.environ["PHIWARD_CONFIG"], "a"))
    assert "REFUSED" in out, out


def test_w1_the_tool_cannot_read_credentials(tree):
    ssh = tree / "home" / ".ssh"
    ssh.mkdir()
    (ssh / "id_fake").write_text("FAKE-KEY\n")
    _, out = launch(tree, tries(str(ssh / "id_fake")))
    assert "FAKE-KEY" not in out and "REFUSED" in out, out


@macos
def test_w1_the_tool_cannot_reach_a_unix_socket_peer(tree):
    import tempfile
    d = tempfile.mkdtemp(dir="/tmp")
    path = os.path.join(d, "s")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)
    def serve():
        try:
            srv.accept()[0].sendall(b"PEER")
        except OSError:
            pass  # closed by the test: the confined client never connected
    threading.Thread(target=serve, daemon=True).start()
    code = (f"import socket\ns=socket.socket(socket.AF_UNIX)\ntry:\n    s.connect({path!r})\n"
            "    print(s.recv(4))\nexcept OSError as e:\n    print('REFUSED', e.errno)\n")
    try:
        _, out = launch(tree, code)
    finally:
        srv.close()
        shutil.rmtree(d, ignore_errors=True)
    assert "REFUSED" in out and "PEER" not in out, out


def test_w1_the_tool_gets_a_config_folder_of_its_own_with_its_sandbox_off(tree):
    # read inside the session: its config folder is discarded at exit
    code = ("import os, json; c = os.environ.get('CLAUDE_CONFIG_DIR', ''); print('CFG=' + c)\n"
            "print('SB=' + json.dumps(json.load(open(os.path.join(c, 'settings.json'))).get('sandbox')))")
    _, out = launch(tree, code, extra=("--tool", "claude"))
    cfg = out.split("CFG=", 1)[1].split()[0]
    assert cfg and not cfg.startswith(str(tree / "home" / ".claude"))
    if sys.platform == "darwin":  # macOS cannot nest sandboxes; Linux keeps the tool's own on
        assert json.loads(out.split("SB=", 1)[1].split("\n")[0])["enabled"] is False, out


def test_w1_shared_tmp_is_not_a_write_place(tree):
    target = os.path.join("/tmp", "ag-w1-probe-" + os.urandom(4).hex())
    _, out = launch(tree, tries(target, "w"))
    try:
        assert not os.path.exists(target), out  # Linux: written to the tool's private /tmp
        if sys.platform == "darwin":
            assert "REFUSED" in out, out
    finally:
        if os.path.exists(target):
            os.unlink(target)
    # the temp folder is the session's own: by its full path on macOS; on Linux by /tmp, the name
    # the view gives the run folder's tmp (a unix socket's path must fit under it)
    _, out = launch(tree, "import os, tempfile\nt = tempfile.mkstemp()[1]\nprint('TEMP', t)\n"
                          "own = os.path.join(os.path.dirname(os.environ['XDG_CACHE_HOME']), 'tmp')\n"
                          "print('OWN', os.path.samefile(os.path.dirname(t), own))\n")
    if sys.platform == "darwin":
        assert "/.phiward/tools/" in out, out
    else:
        assert "TEMP /tmp/" in out, out
    assert "OWN True" in out, out


# macOS: the launch inside looks for the session's run folder under the account's home folder,
# never HOME, so the test runs there with HOME set to it: on GitHub Actions only
@pytest.mark.skipif(sys.platform == "darwin" and not os.environ.get("GITHUB_ACTIONS"),
                    reason="macOS on GitHub Actions only: a launch inside a session uses the "
                           "account's home")
def test_w1_launch_inside_launch_runs_directly(tree, monkeypatch):
    if sys.platform == "darwin":
        import pwd
        monkeypatch.setenv("HOME", pwd.getpwuid(os.getuid()).pw_dir)
    inner = (f"import subprocess, os; r = subprocess.run([{PY!r}, '-m', 'phiward', 'launch', '--', "
             f"{PY!r}, '-c', 'print(\"INNER-RAN\")'], capture_output=True, text=True, env=dict(os.environ, "
             f"PYTHONPATH={SRC!r})); print(r.stdout + r.stderr)")
    _, out = launch(tree, inner)
    # Linux too: the tool's seccomp fingerprint says it is inside a session, so it does not
    # wrap again (test_v2_nested_launch.py)
    assert "INNER-RAN" in out, out


def test_w1_launch_refuses_inside_a_root(tree):
    code, out = launch(tree, "print('RAN')", cwd="phi")
    assert code != 0 and "RAN" not in out.split("\n")[-2:], out


def test_w1_launch_refuses_a_bad_config(tree):
    Path(os.environ["PHIWARD_CONFIG"]).write_text("[nope]\n")
    code, out = launch(tree, "print('RAN')")
    assert code != 0 and "RAN" not in out


def test_w1_keystroke_injection_is_refused_in_the_profile(tree):
    import pty
    master, slave = pty.openpty()
    env = dict(os.environ, PYTHONPATH=SRC)
    code = ("import fcntl, termios, sys\ntry:\n    fcntl.ioctl(0, termios.TIOCSTI, b'#')\n"
            "    print('INJECTED')\nexcept OSError as e:\n    print('REFUSED', e.errno)\n")
    r = subprocess.run([PY, "-m", "phiward", "launch", "--", tool_py(tree), "-c", code],
                       cwd=str(tree / "repo"), stdin=slave, capture_output=True, text=True,
                       env=env, timeout=60)
    os.close(master)
    os.close(slave)
    assert "REFUSED" in r.stdout + r.stderr, r.stdout + r.stderr
