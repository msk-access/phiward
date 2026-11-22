"""The first fixes to `launch`. A fake agent (a Python script) runs under `phiward launch`."""

import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from helpers import CONFINE_WHY, landlock_abi, tool_py

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
pytestmark = pytest.mark.skipif(CONFINE_WHY is not None, reason=f"no confinement: {CONFINE_WHY}")
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")


def launch(tree, code, cwd="repo", extra=(), env_extra=None, stdin=subprocess.DEVNULL):
    env = dict(os.environ, PYTHONPATH=SRC)
    env.update(env_extra or {})
    r = subprocess.run([PY, "-m", "phiward", "launch", *extra, "--",
                        tool_py(tree, "generic" if "generic" in extra else "claude"), "-c", code],
                       cwd=str(tree / cwd), capture_output=True, text=True, env=env, timeout=60,
                       stdin=stdin)
    return r.returncode, r.stdout + r.stderr


def tries(path, mode="w"):
    return (f"try:\n    f = open({path!r}, {mode!r})\n    f.write('x') if 'r' not in {mode!r} else f.read()\n"
            f"    print('DONE')\nexcept OSError as e:\n    print('REFUSED', e.errno)\n")


# --- A: launch follows the trusted-side rules ---------------------------------------------------

def test_a1_the_tool_holds_no_descriptor_of_the_launcher(tree):
    code = ("import os\nfds = [int(x) for x in os.listdir('/dev/fd')]\n"
            "print('EXTRA', sorted(f for f in fds if f > 2 and os.path.exists(f'/dev/fd/{f}')))")
    _, out = launch(tree, code)
    extra = out.split("EXTRA", 1)[1].strip().splitlines()[0] if "EXTRA" in out else out
    assert extra in ("[]", "[3]"), out  # 3: the listing's own descriptor


@macos
def test_a2_a_write_place_replaced_by_a_link_does_not_widen_the_next_session(tree):
    home = tree / "home"
    launch(tree, "print('first')", extra=("--tool", "claude"))
    state = home / ".local" / "state" / "claude"
    state.parent.mkdir(parents=True, exist_ok=True)
    if state.exists() and not state.is_symlink():
        os.rmdir(state)
    os.symlink(home, state)  # planted between sessions
    _, out = launch(tree, tries(str(home / ".zshrc")), extra=("--tool", "claude"))
    assert "REFUSED" in out or "nothing runs" in out, out
    assert not (home / ".zshrc").exists()


def test_a3_a_planted_link_at_the_tools_settings_is_not_followed(tree):
    home = tree / "home"
    folder = home / ".phiward" / "tools" / "claude"
    folder.mkdir(parents=True)
    victim = home / "victim.json"
    victim.write_text('{"keep": true}\n')
    os.symlink(victim, folder / "settings.json")
    launch(tree, "print('x')", extra=("--tool", "claude"))
    assert victim.read_text() == '{"keep": true}\n'


@macos
def test_a4_ordinary_permissions_are_not_taken_for_the_sandbox(tree):
    os.chmod(tree / "phi", 0o311)
    cfgf = Path(os.environ["PHIWARD_CONFIG"])
    os.chmod(cfgf, 0o444)
    try:
        _, out = launch(tree, tries(str(tree / "home" / ".zshrc")))
    finally:
        os.chmod(tree / "phi", 0o755)
        os.chmod(cfgf, 0o644)
    assert "REFUSED" in out and not (tree / "home" / ".zshrc").exists(), out


# --- B: narrow, inert write places --------------------------------------------------------------

@pytest.mark.parametrize("rel", [".cache/uv/x", "Library/Caches/x", ".local/share/claude/versions/x"])
def test_b1_shared_caches_and_the_tool_binary_are_read_only(tree, rel):
    target = tree / "home" / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    _, out = launch(tree, tries(str(target)), extra=("--tool", "claude"))
    assert not target.exists(), out  # Linux: pytest's tree is in the tool's private /tmp
    if sys.platform == "darwin":
        assert "REFUSED" in out, out


def test_b1_package_caches_go_to_the_tools_own_folder(tree):
    code = "import os; print(os.environ.get('npm_config_cache'), os.environ.get('XDG_CACHE_HOME'))"
    _, out = launch(tree, code, extra=("--tool", "claude"))
    assert out.count("/.phiward/tools/claude/") >= 2, out


@pytest.mark.parametrize("rel", [".git/commondir", ".git/info/attributes", ".git/modules/m/config",
                                 ".git/worktrees/w/gitdir", ".vscode/settings.json"])
def test_b2_git_and_editor_control_files_are_read_only(tree, rel):
    g = tree / "repo" / ".git"
    (g / "objects").mkdir(parents=True, exist_ok=True)
    (g / "config").write_text("[core]\n")
    (tree / "repo" / ".vscode").mkdir(exist_ok=True)
    target = tree / "repo" / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    _, out = launch(tree, tries(str(target)))
    if sys.platform == "darwin":
        assert "REFUSED" in out, out
    else:  # Linux: a missing file cannot be covered; the session end reports it instead
        assert "REFUSED" in out or "changed" in out.lower(), out


def test_b2_git_working_files_stay_writable(tree):
    g = tree / "repo" / ".git"
    (g / "objects").mkdir(parents=True, exist_ok=True)
    (g / "config").write_text("[core]\n")
    _, out = launch(tree, tries(str(g / "objects" / "ab")))
    assert "DONE" in out, out


def test_b2_claude_commands_are_read_only(tree):
    # a command runs as code later, outside launch: .claude is read-only as a whole
    (tree / "repo" / ".claude" / "commands").mkdir(parents=True)
    _, out = launch(tree, tries(str(tree / "repo" / ".claude" / "commands" / "x.md")))
    assert "REFUSED" in out and "DONE" not in out, out


@macos
def test_b3_preference_writes_are_denied(tree):
    code = ("import subprocess\nr = subprocess.run(['defaults', 'write', 'com.example.agfake', 'k', 'v'],"
            " capture_output=True, text=True)\nprint('RC', r.returncode)")
    _, out = launch(tree, code)
    assert "RC 0" not in out, out


# --- C: peers and credentials -------------------------------------------------------------------

def _peer(path):
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(2)

    def serve():
        try:
            while True:
                c, _ = srv.accept()
                c.sendall(b"PEER")
                c.close()
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()
    return srv


def _connect(path):
    return (f"import socket\ns=socket.socket(socket.AF_UNIX)\ntry:\n    s.connect({path!r})\n"
            "    print('GOT', s.recv(4))\nexcept OSError as e:\n    print('REFUSED', e.errno)\n")


@linux
def test_c1_a_path_socket_outside_is_not_reachable(tree):
    import tempfile
    d = tempfile.mkdtemp(prefix="ssh-FAKE", dir="/tmp")
    srv = _peer(os.path.join(d, "agent.1"))
    try:
        _, out = launch(tree, _connect(os.path.join(d, "agent.1")))
    finally:
        srv.close()
    assert "GOT" not in out, out


@linux
def test_c1_an_abstract_socket_outside_is_not_reachable(tree):
    srv = _peer("\0ag-fake-abstract-" + os.urandom(4).hex())
    name = srv.getsockname()
    try:
        _, out = launch(tree, _connect(name))
    finally:
        srv.close()
    assert "GOT" not in out, out


def test_c1_credential_variables_are_removed(tree):
    code = "import os; print('ENV', [k for k in ('SSH_AUTH_SOCK','KRB5CCNAME','DBUS_SESSION_BUS_ADDRESS') if k in os.environ])"
    _, out = launch(tree, code, env_extra={"SSH_AUTH_SOCK": "/tmp/x", "KRB5CCNAME": "FILE:/tmp/k",
                                           "DBUS_SESSION_BUS_ADDRESS": "unix:path=/x"})
    assert "ENV []" in out, out


@pytest.mark.parametrize("rel", [".git-credentials", ".config/git/credentials", ".pgpass", ".npmrc",
                                 ".pypirc", ".config/rclone/rclone.conf"])
def test_c2_more_credential_files_are_denied(tree, rel):
    f = tree / "home" / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("FAKE-CREDENTIAL\n")
    _, out = launch(tree, tries(str(f), "r"))
    assert "FAKE-CREDENTIAL" not in out and "REFUSED" in out, out


@linux
def test_c2_a_kerberos_ticket_in_tmp_is_hidden(tree):
    t = f"/tmp/krb5cc_{os.getuid()}_agfake"
    Path(t).write_text("FAKE-TICKET\n")
    try:
        _, out = launch(tree, tries(t, "r"))
    finally:
        os.unlink(t)
    assert "FAKE-TICKET" not in out, out


@macos
def test_c3_processes_outside_cannot_be_signalled(tree):
    victim = subprocess.Popen(["sleep", "30"])
    try:
        code = (f"import os, signal\ntry:\n    os.kill({victim.pid}, 0)\n    print('REACHED')\n"
                "except OSError as e:\n    print('REFUSED', e.errno)\n")
        _, out = launch(tree, code)
    finally:
        victim.kill()
    assert "REACHED" not in out, out


# --- over-blocking ------------------------------------------------------------------------------

@pytest.mark.parametrize("dev", ["/dev/stdout", "/dev/stderr"])
def test_o1_writing_to_stdout_and_stderr_works(tree, dev):
    _, out = launch(tree, f"open({dev!r}, 'w').write('VISIBLE\\n')")
    assert "VISIBLE" in out, out


def test_o2_the_tool_can_use_its_own_sockets(tree):
    code = ("import socket, os, tempfile, threading\n"
            "os.chdir(tempfile.mkdtemp()); p = 's'  # relative: unix socket paths are short\n"
            "try:\n"
            "    srv = socket.socket(socket.AF_UNIX)\n"
            "except OSError as e:\n"
            "    print('NO UNIX SOCKETS', e.errno); raise SystemExit\n"
            "srv.bind(p); srv.listen(1)\n"
            "threading.Thread(target=lambda: srv.accept()[0].sendall(b'OWN'), daemon=True).start()\n"
            "c = socket.socket(socket.AF_UNIX); c.connect(p); print('GOT', c.recv(3))\n")
    _, out = launch(tree, code)
    if sys.platform.startswith("linux") and landlock_abi() < 9:
        # below Landlock ABI 9 the tool's filter denies every unix socket (`--tool generic`):
        # only Landlock can tell the session's own sockets from those outside
        assert "NO UNIX SOCKETS 1" in out and "GOT" not in out, out
    else:
        assert "GOT b'OWN'" in out, out


@macos
def test_o3_apple_developer_tools_run(tree):
    _, out = launch(tree, "import subprocess; r = subprocess.run(['git', '--version'], "
                          "capture_output=True, text=True); print(r.stdout, r.stderr)")
    # a stale xcrun cache makes the /usr/bin shim print a warning (its cache is never written
    # under launch); the tool itself runs
    assert "git version" in out, out


# --- path model items -----------------------------------------------------------------------------

def test_p22_a_planted_git_file_naming_the_projects_git_does_not_stop_launch(tree):
    g = tree / "repo" / ".git"
    (g / "objects").mkdir(parents=True)
    (g / "HEAD").write_text("ref: refs/heads/main\n")
    (tree / ".git").write_text(f"gitdir: {g}\n")  # planted above the root phi
    code, out = launch(tree, "print('RAN')")
    assert "RAN" in out, out


def test_a4b_a_root_that_cannot_be_opened_does_not_protect_its_parent(tree):
    from phiward import paths
    os.chmod(tree / "phi", 0o311)
    try:
        assert paths.ProtectedSet([str(tree / "phi")], []).relation(str(tree / "repo")) is None
    finally:
        os.chmod(tree / "phi", 0o755)
