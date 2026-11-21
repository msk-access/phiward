"""Unix sockets under `phiward launch` on Linux: what limits them is the kernel, never a socket's
name. Landlock ABI 9 and later: `RESOLVE_UNIX` for the whole tool (sockets made in the session
stay reachable). Below ABI 9: `--tool generic` and a wrapped server cannot make unix sockets at
all (the tool's seccomp filter); `--tool claude` relies on Claude Code's own sandbox, whose
seccomp filter blocks them for Bash, and does not start unless that filter is found and works.
Made-up sockets and a made-up filter only (helpers.fake_filter)."""

import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from helpers import CONFINE_WHY, fake_filter, filter_in_home, landlock_abi, ready_line

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
ABI = landlock_abi()
pytestmark = [
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux"),
    pytest.mark.skipif(CONFINE_WHY is not None, reason=f"no confinement: {CONFINE_WHY}"),
]
abi9 = pytest.mark.skipif(ABI < 9, reason="needs Landlock ABI 9 (Linux 7.1)")
below9 = pytest.mark.skipif(ABI >= 9, reason="Landlock ABI 9 holds unix sockets here")


def env(extra=None):
    return dict(os.environ, PYTHONPATH=SRC, **(extra or {}))


def launch(tree, code, tool="generic", extra_env=None, program=None):
    prog = program if program is not None else ["--", PY, "-c", code]
    r = subprocess.run([PY, "-m", "phiward", "launch", "--tool", tool, *prog],
                       cwd=str(tree / "repo"), capture_output=True, text=True,
                       env=env(extra_env), timeout=120, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


def start(tree, code, tool="generic"):
    return subprocess.Popen([PY, "-m", "phiward", "launch", "--tool", tool, "--", PY, "-c", code],
                            cwd=str(tree / "repo"), env=env(), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def peer(path):
    """A made-up server outside the session (an ssh ControlMaster, an agent, docker)."""
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(4)

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


def connect(path):
    # socket() itself may be refused: inside the try
    return (f"import socket\ntry:\n    s = socket.socket(socket.AF_UNIX)\n    s.connect({path!r})\n"
            "    print('GOT', s.recv(4))\nexcept OSError as e:\n    print('REFUSED', e.errno)\n")


def waits_then(code):
    return "import sys\nprint('READY', flush=True)\nsys.stdin.readline()\n" + code


def sockets(tree):
    d = tree / "pub" / "s"  # a folder of the host the session sees whole
    d.mkdir(parents=True)
    return d


TOOLS = ["generic", pytest.param("claude", marks=abi9)]


# --- outside sockets: none is reachable, whatever its name -----------------------------------

@pytest.mark.parametrize("tool", TOOLS)
def test_a_socket_bound_by_one_name_and_linked_to_another_is_not_reachable(tree, tool):
    # OpenSSH's ControlMaster: bound as a temp name, linked to the final name, the temp
    # name removed; /proc/net/unix still lists the temp name
    d = sockets(tree)
    srv = peer(str(d / "cm-FAKE.Xa1b2tmp"))
    os.link(d / "cm-FAKE.Xa1b2tmp", d / "cm-FAKE")
    os.unlink(d / "cm-FAKE.Xa1b2tmp")
    try:
        _, out = launch(tree, connect(str(d / "cm-FAKE")), tool)
    finally:
        srv.close()
    assert "REFUSED" in out and "GOT" not in out, out


@pytest.mark.parametrize("tool", TOOLS)
def test_a_socket_bound_again_after_the_start_is_not_reachable(tree, tool):
    d = sockets(tree)
    srv = peer(str(d / "agent-FAKE"))
    p = start(tree, waits_then(connect(str(d / "agent-FAKE"))), tool)
    try:
        ready_line(p)
        srv.close()  # the server restarts: its socket file goes and comes back
        os.unlink(d / "agent-FAKE")
        srv = peer(str(d / "agent-FAKE"))
        out = p.communicate("go\n".encode(), timeout=60)[0].decode()
    finally:
        srv.close()
    assert "REFUSED" in out and "GOT" not in out, out


@pytest.mark.parametrize("tool", TOOLS)
def test_a_socket_made_after_the_start_is_not_reachable(tree, tool):
    d = sockets(tree)
    p = start(tree, waits_then(connect(str(d / "late-FAKE"))), tool)
    srv = None
    try:
        ready_line(p)
        srv = peer(str(d / "late-FAKE"))  # a ControlMaster opened in another terminal
        out = p.communicate("go\n".encode(), timeout=60)[0].decode()
    finally:
        if srv:
            srv.close()
    assert "REFUSED" in out and "GOT" not in out, out


# --- what keeps working -----------------------------------------------------------------------

CONTROLS = r"""
import multiprocessing, os, pwd, socket, subprocess, sys
a, b = socket.socketpair(); a.sendall(b"x"); print("PAIR", b.recv(1) == b"x")
r, w = os.pipe(); os.write(w, b"x"); print("PIPE", os.read(r, 1) == b"x")
print("LOOKUP", bool(socket.getaddrinfo("localhost", 80)))
print("PASSWD", pwd.getpwuid(os.getuid()).pw_uid == os.getuid())
ctx = multiprocessing.get_context("spawn")
with ctx.Pool(1) as pool:
    print("SPAWN", pool.apply(abs, (-3,)) == 3)
# a stdio MCP server and a command hook speak over pipes
srv = subprocess.run([sys.executable, "-c", "import sys; print(sys.stdin.readline().strip()[::-1])"],
                     input='{"jsonrpc"}\n', capture_output=True, text=True)
print("STDIO", srv.stdout.strip() == '}"cprnosj"{')
"""


def test_socketpairs_pipes_lookups_and_child_processes_still_work(tree):
    _, out = launch(tree, "if __name__ == '__main__':\n" +
                    "".join("    " + ln + "\n" for ln in CONTROLS.strip().splitlines()))
    for word in ("PAIR", "PIPE", "LOOKUP", "PASSWD", "SPAWN", "STDIO"):
        assert f"{word} True" in out, out


def test_a_cross_folder_move_and_a_git_commit_work(tree):
    # Landlock refuses a cross-folder rename unless REFER is granted (git renames files
    # between folders when it commits)
    script = ("set -e; mkdir new && cd new && git init -q && mkdir a b && echo x > a/x && "
              "git add a && git -c user.email=f@example.invalid -c user.name=F commit -qm one && "
              "git mv a/x b/x && git -c user.email=f@example.invalid -c user.name=F commit -qm two "
              "&& mkdir c && mv b/x c/x && echo MOVED")
    _, out = launch(tree, f"import subprocess\nr = subprocess.run(['sh', '-c', {script!r}], "
                          "capture_output=True, text=True)\nprint(r.stdout, r.stderr, 'RC', r.returncode)")
    assert "MOVED" in out and "RC 0" in out, out


@abi9
def test_a_name_service_socket_stays_reachable(tree):
    d = Path("/var/lib/sss/pipes")
    if not (d.is_dir() and os.access(d, os.W_OK)):
        pytest.skip("needs a writable made-up /var/lib/sss/pipes (a container set up as root)")
    srv = peer(str(d / "nss-FAKE"))
    try:
        _, out = launch(tree, connect(str(d / "nss-FAKE")))
    finally:
        srv.close()
        os.unlink(d / "nss-FAKE")
    assert "GOT b'PEER'" in out, out


# --- the helper stops when Landlock cannot hold unix sockets --------------------------------------

def helper(mode, text=None):
    from phiward import wholetool
    return subprocess.run([PY, "-I", "-S", "-c", text or wholetool.HELPER, "-1", mode, "-", "0",
                           PY, "-c", "print('RAN')"], capture_output=True, text=True, timeout=60,
                          stdin=subprocess.DEVNULL)


@below9
def test_the_helper_stops_when_the_kernel_cannot_hold_unix_sockets_by_landlock():
    r = helper("landlock")
    assert r.returncode == 126 and "RAN" not in r.stdout, (r.returncode, r.stdout, r.stderr)


@abi9
def test_the_helper_stops_when_a_name_service_folder_cannot_be_opened(tmp_path):
    from phiward import wholetool
    locked = tmp_path / "locked"
    (locked / "pipes").mkdir(parents=True)
    os.chmod(locked, 0)
    try:
        text = wholetool.HELPER.replace('"/var/lib/sss/pipes"', repr(str(locked / "pipes")))
        assert text != wholetool.HELPER
        r = helper("landlock", text)
    finally:
        os.chmod(locked, 0o755)
    assert r.returncode == 126 and "RAN" not in r.stdout, (r.returncode, r.stdout, r.stderr)


# --- below ABI 9: --tool claude needs Claude Code's filter, and settings that keep it ----------

@below9
def test_claude_starts_when_its_filter_blocks_unix_sockets(tree):
    code, out = launch(tree, "print('RAN')", "claude")
    assert "RAN" in out, out


@below9
@pytest.mark.parametrize("how", ["missing", "no filter"])
def test_claude_does_not_start_without_a_filter_that_works(tree, how):
    f = filter_in_home(tree / "home")
    if how == "missing":
        f.unlink()
    else:
        fake_filter(f, works=False)
    code, out = launch(tree, "print('RAN')", "claude")
    assert code == 126 and "RAN" not in out, out
    assert "npm install -g @anthropic-ai/sandbox-runtime" in out, out


@below9
def test_claude_does_not_start_with_a_filter_the_session_could_replace(tree):
    # sandbox-runtime looks next to Claude Code's own files first: here, inside the project
    tools = tree / "repo" / "tools"
    tools.mkdir()
    stub = tools / "claude"
    stub.write_text(f"#!{PY}\nprint('STUB')\n")
    stub.chmod(0o755)
    m = filter_in_home(tree / "home").parent.name
    fake_filter(tools / "vendor" / "seccomp" / m / "apply-seccomp")
    code, out = launch(tree, "print('RAN')", "claude",
                       extra_env={"PATH": f"{tools}:{os.environ['PATH']}"})
    assert code == 126 and "RAN" not in out and "STUB" not in out, out


@below9
@pytest.mark.parametrize("sandbox", [{"network": {"allowAllUnixSockets": True}},
                                     {"network": {"allowUnixSockets": ["/run/docker.sock"]}},
                                     {"excludedCommands": ["docker"]},
                                     {"enableWeakerNestedSandbox": True}])
def test_claude_does_not_start_when_settings_open_its_sandbox(tree, sandbox):
    import json
    s = tree / "repo" / ".claude"
    s.mkdir(exist_ok=True)
    (s / "settings.json").write_text(json.dumps({"sandbox": sandbox}))
    code, out = launch(tree, "print('RAN')", "claude")
    assert code == 126 and "RAN" not in out, out


@below9
def test_claude_gets_settings_that_keep_its_sandbox_on(tree):
    import json
    b = tree / "bin"
    b.mkdir(exist_ok=True)
    stub = b / "claude"
    stub.write_text(f"#!{PY}\nimport json, sys\nprint('ARGV', json.dumps(sys.argv[1:]))\n")
    stub.chmod(0o755)
    code, out = launch(tree, "", "claude", extra_env={"PATH": f"{b}:{os.environ['PATH']}"},
                       program=[])
    line = [ln for ln in out.splitlines() if ln.startswith("ARGV ")]
    assert line, out
    argv = json.loads(line[0][5:])
    assert argv[0] == "--settings", argv
    assert json.loads(argv[1]) == {"sandbox": {"enabled": True, "failIfUnavailable": True,
                                               "allowUnsandboxedCommands": False}}, argv


def test_claude_does_not_start_on_an_architecture_without_the_filter(tree):
    from phiward import wholetool
    why = wholetool.inner_sandbox_reason(str(tree / "repo"), {"HOME": str(tree / "home")},
                                         machine="riscv64")
    assert why and "riscv64" in why, why
    assert wholetool.inner_sandbox_reason(str(tree / "repo"), {"HOME": str(tree / "home")},
                                          machine="x86_64") is None
