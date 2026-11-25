"""Security review findings (second set), each as a command that runs for real.

Class A: no shell outside the sandbox interprets a gateway command (the broker gets argv).
Class B: a link planted in a root does not carry gateway writes out (the agent profile is gone).
Class C: the gateway has no channel out except its sanitized output.
Class D: entry names are masked as substrings, from a list built fresh for each run.
Class E: the hook reads Claude Code settings from the project folder and CLAUDE_CONFIG_DIR.
"""

import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

from helpers import CONFINE_WHY

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
needs_confine = pytest.mark.skipif(CONFINE_WHY is not None, reason=f"no confinement: {CONFINE_WHY}")
macos = pytest.mark.skipif(sys.platform != "darwin", reason="a macOS service")


# The operator's side starts like the installed `phiward` script: the working folder is not
# on the module path (with `python -m`, a planted ./phiward would replace the wrapper itself).
LAUNCH = ("import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; "
          "from phiward.cli import main; sys.exit(main())")


def ag(args, cwd, timeout=60, env=None):
    e = dict(os.environ, PYTHONPATH=SRC)
    e.update(env or {})
    r = subprocess.run([PY, "-c", LAUNCH] + args, cwd=str(cwd), capture_output=True,
                       text=True, env=e, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def agent(t, cmd, cwd="repo", env=None):
    """A command the agent runs in its own shell (here unconfined: these tests are about what
    the gateway lets out, not about the agent's sandbox)."""
    e = dict(os.environ, PYTHONPATH=SRC)
    e.update(env or {})
    r = subprocess.run(["/bin/sh", "-c", cmd], cwd=str(t / cwd), capture_output=True, text=True,
                       env=e, timeout=60)
    return r.returncode, r.stdout + r.stderr


def gate(t, args, cwd="repo"):
    """A gateway call as the agent makes it, from its shell."""
    return agent(t, " ".join([PY, "-m", "phiward", "run"] + [_q(a) for a in args]), cwd)


def _q(a):
    return "'" + a.replace("'", "'\\''") + "'"


# --- class A: the broker, not a passthrough ---------------------------------------------------

@needs_confine
def test_a_gateway_call_works_through_the_broker(tree, broker):
    (tree / "phi" / "Doe Jane").mkdir()  # a plain name: masked because it exists
    code, out = gate(tree, ["--", "ls", "../phi"])
    # FAKE-PT-0001.bam: the genomics rule masks a .bam name whether or not it exists
    assert code == 0 and "<BAMFILE>" in out and "FAKE-PT" not in out
    assert "<ENTRY>" in out and "Doe" not in out, out


@needs_confine
def test_a_grants_are_refused_when_nobody_can_answer(tree, broker):
    # braces, expanded by the agent's own shell, reach the broker as plain words
    code, out = agent(tree, f"{PY} -m phiward run --{{write-to,x}} ../pub -- "
                            "sh -c 'echo x > ../pub/granted'")
    assert code != 0 and not (tree / "pub" / "granted").exists()


def test_a_client_without_a_broker_says_so(tree, monkeypatch, request):
    spool = tempfile.mkdtemp(prefix="ags-", dir="/tmp")
    request.addfinalizer(lambda: shutil.rmtree(spool, ignore_errors=True))
    monkeypatch.setenv("PHIWARD_SPOOL", spool)
    monkeypatch.setenv("PHIWARD_BROKER_WAIT", "1")
    t0 = time.time()
    code, out = ag(["run", "--", "ls", "../phi"], tree / "repo")
    assert code == 3 and "broker" in out and time.time() - t0 < 20
    assert "FAKE-PT" not in out


# --- class B: the agent profile denies all access ---------------------------------------------

@needs_confine
def test_b_a_link_planted_in_a_root_does_not_carry_gateway_writes_out(tree, broker):
    agent(tree, "echo empty > ../pub/target ; ln ../pub/target ../phi/planted")
    gate(tree, ["--", "sh", "-c", "cat ../phi/FAKE-PT-0001.bam > ../phi/planted"])
    _, out = agent(tree, "cat ../pub/target")
    assert "SECRET-CONTENT" not in out


# --- class C: no channel out of the gateway but its output ------------------------------------

@needs_confine
@macos
def test_c_no_clipboard(tree, broker):
    board = "ruler"  # a pasteboard nobody uses, so the operator's clipboard is left alone
    gate(tree, ["--", "sh", "-c", f"pbcopy -pboard {board} < ../phi/FAKE-PT-0001.bam"])
    _, out = agent(tree, f"pbpaste -pboard {board}")
    subprocess.run(["sh", "-c", f"printf '' | pbcopy -pboard {board}"])
    assert "SECRET-CONTENT" not in out


@needs_confine
@macos
def test_c_no_preferences(tree, broker):
    domain = f"phiward.test.{uuid.uuid4().hex[:8]}"
    gate(tree, ["--", "sh", "-c", f'defaults write {domain} k "$(cat ../phi/FAKE-PT-0001.bam)"'])
    _, out = agent(tree, f"defaults read {domain} k")
    subprocess.run(["defaults", "delete", domain], capture_output=True)
    assert "SECRET-CONTENT" not in out


@needs_confine
@macos
def test_c_no_notification_state(tree, broker):
    key = f"phiward.test.{uuid.uuid4().hex[:8]}"
    gate(tree, ["--", "notifyutil", "-s", key, "4242"])
    r = subprocess.run(["notifyutil", "-g", key], capture_output=True, text=True)
    assert "4242" not in r.stdout


@needs_confine
def test_c_no_unix_socket(tree, broker):
    d = tempfile.mkdtemp(prefix="agsock-", dir="/tmp")
    path = os.path.join(d, "s")
    srv = socket.socket(socket.AF_UNIX)
    try:
        srv.bind(path)
        srv.listen(4)
        code, out = gate(tree, ["--", PY, "-c",
                                "import socket\ntry:\n    c = socket.socket(socket.AF_UNIX)\n"
                                "    c.connect(%r)\nexcept OSError as e:\n    print('REFUSED', e.errno)\n"
                                "else:\n    c.send(open('../phi/FAKE-PT-0001.bam','rb').read())" % path])
        # the program ran in the gateway, and its socket or its connect was refused (Linux's
        # filter refuses the socket itself)
        assert "REFUSED" in out, out
        # the gateway call has ended: a connection it made waits in the backlog, with its data
        got = []
        srv.setblocking(False)
        while True:
            try:
                c, _ = srv.accept()
            except BlockingIOError:
                break
            c.settimeout(5)
            got.append(c.recv(100))
            c.close()
        assert not any(b"SECRET-CONTENT" in g for g in got)
        # the control: a connection from outside the gateway arrives and is read the same way
        c = socket.socket(socket.AF_UNIX)
        c.connect(path)
        c.send(b"CONTROL")
        acc, _ = srv.accept()
        acc.settimeout(5)
        assert acc.recv(100) == b"CONTROL"
        acc.close()
        c.close()
    finally:
        srv.close()
        shutil.rmtree(d, ignore_errors=True)


@needs_confine
def test_c_no_fifo_outside_the_roots(tree, broker):
    fifo = tree / "pub" / "fifo"
    os.mkfifo(fifo)
    fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)  # a reader, so a writer would not block
    try:
        gate(tree, ["--", "sh", "-c", "cat ../phi/FAKE-PT-0001.bam > ../pub/fifo"])
        try:
            data = os.read(fd, 1000)
        except BlockingIOError:
            data = b""
    finally:
        os.close(fd)
    assert b"SECRET-CONTENT" not in data


_PROBE = ("import ctypes, os, platform; libc = ctypes.CDLL(None, use_errno=True); "
          "x86 = platform.machine() in ('x86_64', 'amd64'); "
          "nr = {'io_uring_setup': 425, 'unshare': 272 if x86 else 97, 'ptrace': 101 if x86 else 117}"
          "[%r]; buf = ctypes.create_string_buffer(256); "
          "args = {'io_uring_setup': (1, buf), 'unshare': (0x10000000,), 'ptrace': (16, 1, 0, 0)}[%r]; "
          "r = libc.syscall(nr, *args); print('OPEN' if r >= 0 else 'BLOCKED-%%d' %% ctypes.get_errno())")


@needs_confine
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the Linux seccomp filter")
@pytest.mark.parametrize("call", ["io_uring_setup", "unshare", "ptrace"])
def test_c_linux_gateway_filter_blocks(tree, broker, call):
    code, out = gate(tree, ["--", PY, "-c", _PROBE % (call, call)])
    assert "BLOCKED-1" in out, out  # EPERM from the filter


# --- class D: substring masking, built fresh ---------------------------------------------------

@needs_confine
@pytest.mark.parametrize("name,cmd", [
    ("FAKE PT 0007.bam", "ls ../phi"),
    ("FAKE-PT-0001.bam", "ls ../phi | sed 's/^/+/'"),
    ("FAKE-PT-0008.sh", "ls -F ../phi"),
    ("FAKE-PT-0001.bam", "ls ../phi | tr a-z A-Z"),
])
def test_d_names_are_masked_as_substrings(tree, broker, name, cmd):
    p = tree / "phi" / name
    if not p.exists():
        p.write_text("x\n")
        p.chmod(0o755)
    _, out = gate(tree, ["--", "sh", "-c", cmd])
    stem = name.split(".")[0]
    assert stem.lower() not in out.lower(), out


@needs_confine
def test_d_a_new_file_is_masked_at_once(tree, broker):
    gate(tree, ["--", "ls", "../phi"])
    (tree / "phi" / "FAKE-PT-0010.bam").write_text("x\n")
    _, out = gate(tree, ["--", "ls", "../phi"])
    assert "FAKE-PT-0010" not in out


# --- class E: the Claude Code settings path ---------------------------------------------------

def _hook(payload, env):
    r = subprocess.run([PY, "-m", "phiward", "hook", "claude"], input=json.dumps(payload),
                       capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=SRC, **env),
                       timeout=30)
    return r.returncode


def _full_sandbox(t):
    from phiward import config, hidden
    cfg = config.load(str(t / "repo"))
    return {"sandbox": {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
                        # the hidden list too, as install writes it
                        "filesystem": {"denyRead": list(cfg.all_roots) +
                                       hidden.paths(None, cfg, session=True),
                                       "denyWrite": list(cfg.all_roots) + config.guard_files() + config.sandbox_denied()}}}


def _roots_only(t):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(f'[protected_paths]\nroots = ["{t}/phi"]\n')


def test_e_project_settings_come_from_the_project_folder(tree):
    _roots_only(tree)
    user = tree / "home" / ".claude"
    user.mkdir()
    (user / "settings.json").write_text(json.dumps(_full_sandbox(tree)))
    proj = tree / "repo" / ".claude"
    proj.mkdir()
    (proj / "settings.json").write_text(json.dumps({"sandbox": {"excludedCommands": ["ls *"]}}))
    payload = {"hook_event_name": "PreToolUse", "cwd": str(tree / "repo" / "src"),
               "permission_mode": "default", "tool_name": "Bash",
               "tool_input": {"command": "ls ../.."}}
    # the shell is in repo/src; the project's settings (repo/.claude) break confinement
    assert _hook(payload, {"CLAUDE_PROJECT_DIR": str(tree / "repo")}) == 2


def test_e_user_settings_follow_claude_config_dir(tree):
    _roots_only(tree)
    alt = tree / "altclaude"
    alt.mkdir()
    (alt / "settings.json").write_text(json.dumps(_full_sandbox(tree)))
    payload = {"hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
               "permission_mode": "default", "tool_name": "Bash", "tool_input": {"command": "ls .."}}
    env = {"CLAUDE_PROJECT_DIR": str(tree / "repo"), "CLAUDE_CONFIG_DIR": str(alt)}
    assert _hook(payload, env) == 0  # confined by the settings in CLAUDE_CONFIG_DIR


def test_e_without_the_project_folder_the_shell_is_not_confined(tree):
    _roots_only(tree)
    user = tree / "home" / ".claude"
    user.mkdir()
    (user / "settings.json").write_text(json.dumps(_full_sandbox(tree)))
    payload = {"hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
               "permission_mode": "default", "tool_name": "Bash", "tool_input": {"command": "ls .."}}
    env = dict(os.environ)
    env.pop("CLAUDE_PROJECT_DIR", None)
    r = subprocess.run([PY, "-m", "phiward", "hook", "claude"], input=json.dumps(payload),
                       capture_output=True, text=True, env=dict(env, PYTHONPATH=SRC), timeout=30)
    assert r.returncode == 2


# --- the spool: requests are untrusted data ---------------------------------------------------

def _request(spool, rid, body):
    tmp = os.path.join(spool, f".tmp-{rid}")
    with open(tmp, "w") as fh:
        json.dump(body, fh)
    os.rename(tmp, os.path.join(spool, f"req-{rid}.json"))


def _wait(ok, secs=8):
    """Whether `ok()` became true within `secs` seconds."""
    for _ in range(int(secs * 20)):
        if ok():
            return True
        time.sleep(0.05)
    return False


def _wait_gone(path, secs=8):
    return _wait(lambda: not os.path.lexists(path), secs)


@needs_confine
def test_spool_broker_never_follows_a_planted_link(tree, broker):
    victim = tree / "pub" / "victim.txt"
    victim.write_text("original\n")
    rid = uuid.uuid4().hex
    os.symlink(victim, os.path.join(broker.spool, f"out-{rid}.log"))
    _request(broker.spool, rid, {"v": 1, "cmd": "run", "args": ["--", "echo", "OVERWRITE"],
                                 "cwd": str(tree / "repo"), "env": {}})
    _wait_gone(os.path.join(broker.spool, f"req-{rid}.json"))
    time.sleep(1)
    assert victim.read_text() == "original\n"
    assert broker().poll() is None  # a fresh start works; the old one did not crash first


@needs_confine
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_spool_broker_reads_only_plain_request_files(tree, broker, kind):
    rid = uuid.uuid4().hex
    req = os.path.join(broker.spool, f"req-{rid}.json")
    if kind == "symlink":
        os.symlink(tree / "phi" / "FAKE-PT-0001.bam", req)
    elif kind == "hardlink":
        os.link(tree / "phi" / "FAKE-PT-0001.bam", req)
    else:
        os.mkfifo(req)
    # the broker refuses it after trying to read it: its done file says it got that far
    assert _wait(lambda: os.path.exists(os.path.join(broker.spool, f"done-{rid}.json"))), \
        "no done file: the request was not refused"
    leaked = []
    for name in os.listdir(broker.spool):
        p = os.path.join(broker.spool, name)
        if name.startswith(("out-", "done-")) and stat.S_ISREG(os.lstat(p).st_mode):
            leaked.append(open(p, errors="replace").read())
    assert not any("SECRET-CONTENT" in x for x in leaked)
    # the broker still serves the next request
    code, out = gate(tree, ["--", "true"])
    assert code == 0, out


@needs_confine
def test_spool_repo_config_roots_are_not_writable_by_the_gateway(tree, broker):
    (tree / "repo" / ".phiward.toml").write_text(
        f'[protected_paths]\nroots = ["{tree}/pub"]\n')
    gate(tree, ["--", "sh", "-c", "cat ../phi/FAKE-PT-0001.bam > ../pub/copied"])
    assert not (tree / "pub" / "copied").exists()


@needs_confine
def test_spool_loader_variables_do_not_reach_the_launcher(tree, broker):
    # set inside the client, so the client itself starts normally and sends them in its request
    code, out = agent(tree, f"{PY} -c " + _q(
        "import os, sys; os.environ['LD_PRELOAD'] = '/nonexistent/x.so'; "
        "os.environ['DYLD_INSERT_LIBRARIES'] = '/nonexistent/x.dylib'; "
        "sys.argv = ['phiward', 'run', '--', 'env']; "
        "from phiward.cli import main; sys.exit(main())"))
    assert code == 0, out
    assert "LD_PRELOAD" not in out and "DYLD_INSERT_LIBRARIES" not in out


# --- the broker's prompt: grants and confirm = "all" need a yes on its terminal ----------------

@needs_confine
def test_grants_come_from_the_user_config(tree, broker):
    code, out = gate(tree, ["--write-to", "../pub", "--", "sh", "-c", "echo x > ../pub/granted"])
    assert code == 2 and not (tree / "pub" / "granted").exists(), out
    cfg = tree / "home" / "phiward.toml"
    cfg.write_text(cfg.read_text() + f'[broker]\nwrite_to = ["{tree}/pub"]\n')
    broker()  # a changed config takes effect when the operator restarts the broker
    code, out = gate(tree, ["--write-to", "../pub", "--", "sh", "-c", "echo x > ../pub/granted"])
    assert code == 0 and (tree / "pub" / "granted").exists(), out


@needs_confine
def test_a_cancelled_request_stops_its_command(tree, broker):
    rid = uuid.uuid4().hex
    _request(broker.spool, rid, {"v": 1, "cmd": "run", "cwd": str(tree / "repo"), "env": {
        "PATH": os.environ["PATH"]}, "args": ["--", "sh", "-c", "echo STARTED; sleep 30"]})
    out = os.path.join(broker.spool, f"out-{rid}.log")
    assert _wait(lambda: os.path.exists(out) and "STARTED" in open(out).read()), \
        "the command did not start"  # cancelled while it runs, not while it waits
    open(os.path.join(broker.spool, f"cancel-{rid}"), "w").close()
    done = os.path.join(broker.spool, f"done-{rid}.json")
    assert _wait(lambda: os.path.exists(done), 10), "not stopped (sleep 30 still runs)"
    assert json.load(open(done))["exit"] != 0
    assert "before it started" not in open(out).read()
