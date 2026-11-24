"""Unix sockets under `phiward launch` on Linux: what limits them is the kernel, never a socket's
name. Landlock ABI 9 and later: `RESOLVE_UNIX` for the whole tool (sockets made in the session
stay reachable). Below ABI 9: `--tool generic` and a wrapped server cannot make unix sockets at
all (the tool's seccomp filter); `--tool claude` relies on Claude Code's own sandbox, whose
seccomp filter blocks them for Bash, and does not start unless the program that runs is the
native build and its filter works. Made-up sockets and a made-up native build only
(helpers.fake_native_claude)."""

import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from helpers import CONFINE_WHY, fake_native_claude, landlock_abi, ready_line, records_fd, \
    tool_py

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


# Claude Code's sandbox bridges its proxies with `socat UNIX-LISTEN:$TMPDIR/claude-http-<16 hex>
# .sock` (and claude-socks-...), tmux makes $TMUX_TMPDIR/tmux-UID/default: a socket's path holds
# at most 107 bytes, so the session's temp folders must leave room for these names wherever the
# run folder is (the real check: "Failed to create bridge sockets after 5 attempts")
BRIDGE = r"""
import os, socket, tempfile
for name, d in (("claude", os.environ.get("CLAUDE_CODE_TMPDIR") or tempfile.gettempdir()),
                ("tmux", os.path.join(os.environ.get("TMUX_TMPDIR", "/tmp"), "tmux-%d" % os.getuid()))):
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "claude-http-0123456789abcdef.sock" if name == "claude" else "default")
    try:
        s = socket.socket(socket.AF_UNIX)
        s.bind(p)
        s.listen(1)
        print("BOUND", name)
    except OSError as e:
        print("NOT-BOUND", name, len(p), e)
"""


def test_the_sessions_temp_folders_take_claude_codes_bridge_and_tmuxs_socket_names(tree):
    _, out = launch(tree, "", "claude", program=["--", tool_py(tree), "-c", BRIDGE])
    assert "BOUND claude" in out and "BOUND tmux" in out, out


@pytest.mark.parametrize("where", ["project", "spool"])
def test_a_write_place_that_is_tmp_is_refused(tree, where):
    """A write place that is /tmp (or holds it) would cover the session's own /tmp, which its
    temp variables name, with the host's shared one: nothing runs."""
    cwd, extra = str(tree / "repo"), {}
    if where == "project":
        cwd = "/tmp"
    else:
        extra = {"PHIWARD_SPOOL": "/tmp"}
    r = subprocess.run([PY, "-m", "phiward", "launch", "--", PY, "-c", "print('RAN')"], cwd=cwd,
                       capture_output=True, text=True, env=env(extra), timeout=120,
                       stdin=subprocess.DEVNULL)
    out = r.stdout + r.stderr
    assert r.returncode != 0 and "RAN" not in out, out
    assert "/tmp" in out and "below /tmp" in out, out


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
    fd = records_fd()  # a records file that matches: the stop below is the unix sockets' own
    try:
        return subprocess.run([PY, "-I", "-S", "-c", text or wholetool.HELPER, str(fd), mode, "0",
                               PY, "-c", "print('RAN')"], pass_fds=[fd], capture_output=True,
                              text=True, timeout=60, stdin=subprocess.DEVNULL)
    finally:
        os.close(fd)


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
    code, out = launch(tree, "", "claude", program=["--", tool_py(tree), "-c", "print('RAN')"])
    assert "RAN" in out, out


@below9
@pytest.mark.parametrize("where", ["opt", "project", "cli.js"])
def test_a_javascript_claude_is_refused(tree, where):
    # a JavaScript build (or any node program) carries no filter of its own: below ABI 9 only
    # the native build is accepted, wherever the program is
    if where == "cli.js":
        prog = tree / "js" / "cli.js"
        prog.parent.mkdir()
        prog.write_text(f"#!{PY}\nprint('STUB')\n")
    else:
        prog = (tree / "opt" if where == "opt" else tree / "repo" / "tools") / "npx"
        prog.parent.mkdir()
        prog.write_text("#!/usr/bin/env node\nconsole.log('STUB')\n")
    prog.chmod(0o755)
    code, out = launch(tree, "", "claude", program=["--", str(prog)])
    assert code == 126 and "STUB" not in out, out
    # in the project, the write-place refusal comes first: the file is not even read
    assert ("folder the session can write" if where == "project" else "native build") in out, out


@below9
def test_claude_does_not_start_when_the_session_could_replace_it(tree):
    claude = fake_native_claude(tree / "repo" / "tools" / "claude")
    code, out = launch(tree, "", "claude", program=["--", str(claude)])
    assert code == 126 and "ARGV" not in out, out


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


# what launch passes: the file `install` writes for `claude --settings`
INNER = {"sandbox": {"enabled": True, "failIfUnavailable": True,
                     "allowUnsandboxedCommands": False},
         "env": {"CLAUDE_CODE_DISABLE_FILE_MENTIONS": "1"}}


def argv_of(out):
    import json
    line = [ln for ln in out.splitlines() if ln.startswith("ARGV ")]
    assert line, out
    return json.loads(line[0][5:])


def native(tree, **kw):
    """A made-up native Claude Code on PATH (tree/bin/claude)."""
    return fake_native_claude(tree / "bin" / "claude", **kw)


def on_path(tree):
    return {"PATH": f"{tree / 'bin'}:{os.environ['PATH']}"}


@below9
def test_claude_gets_settings_that_keep_its_sandbox_on(tree):
    import json
    native(tree)
    code, out = launch(tree, "", "claude", extra_env=on_path(tree), program=[])
    argv = argv_of(out)
    assert argv[-2] == "--settings" and json.loads(argv[-1]) == INNER, argv


@below9
def test_a_native_claude_whose_filter_works_starts(tree):
    native(tree)
    code, out = launch(tree, "", "claude", extra_env=on_path(tree), program=[])
    assert code == 0 and argv_of(out), out


@below9
@pytest.mark.parametrize("kw", [{"works": False}, {"runs": False}])
def test_a_native_claude_whose_filter_does_not_block_unix_sockets_is_refused(tree, kw):
    fake_native_claude(tree / "bin" / "claude", **kw)
    code, out = launch(tree, "", "claude", extra_env=on_path(tree), program=[])
    assert code == 126 and "ARGV" not in out, out


@below9
@pytest.mark.parametrize("which", ["another claude", "python"])
def test_the_program_that_runs_is_the_one_whose_filter_is_proved(tree, which):
    native(tree)  # a working claude on PATH
    prog = (str(fake_native_claude(tree / "other" / "claude", works=False))
            if which == "another claude" else PY)
    code, out = launch(tree, "", "claude", extra_env=on_path(tree),
                       program=["--", prog, "-c", "print('RAN')"])
    assert code == 126 and "RAN" not in out and "ARGV" not in out, out
    assert "directly" in out, out


@below9
def test_a_wrapper_that_adds_arguments_is_refused_with_a_hint(tree):
    real = fake_native_claude(tree / "opt" / "claude")
    w = tree / "bin" / "my-claude"
    w.parent.mkdir(exist_ok=True)
    w.write_text(f'#!/bin/sh\nexec "{real}" --verbose "$@"\n')
    w.chmod(0o755)
    code, out = launch(tree, "", "claude", program=["--", str(w), "-p", "hello"])
    assert code == 126 and "ARGV" not in out, out
    assert "wrapper" in out, out


@below9
@pytest.mark.parametrize("given", [["--settings", "{}"], ["--settings={}"]])
def test_the_users_own_settings_flag_is_refused(tree, given):
    claude = native(tree)
    code, out = launch(tree, "", "claude", program=["--", str(claude), "-p", "x", *given])
    assert code == 126 and "ARGV" not in out, out
    assert "phiward carryover" in out, out


@below9
@pytest.mark.parametrize("sub,word", [(["mcp", "list"], "mcp"), (["doctor"], "doctor"),
                                      (["update"], "update"), (["ultrareview"], "ultrareview"),
                                      (["sandbox"], "sandbox"), (["logs"], "logs"),
                                      (["upgrade"], "upgrade"), (["daemon", "status"], "daemon"),
                                      (["rc"], "rc"), (["remote-control"], "remote-control"),
                                      (["bridge"], "bridge"), (["sync"], "sync"),
                                      (["--debug", "mcp", "list"], "mcp"),
                                      (["--model", "opus", "doctor"], "doctor")])
def test_a_claude_subcommand_is_refused(tree, sub, word):
    claude = native(tree)
    code, out = launch(tree, "", "claude", program=["--", str(claude), *sub])
    assert code == 126 and "ARGV" not in out, out
    assert "outside" in out and word in out, out


@below9
def test_claude_gets_the_settings_whatever_its_path(tree):
    import json
    real = fake_native_claude(tree / "home" / ".local" / "share" / "claude" / "versions" /
                              "2.1.330")
    code, out = launch(tree, "", "claude", program=["--", str(real), "-p", "hello"])
    argv = argv_of(out)
    assert argv[:2] == ["-p", "hello"], argv
    assert argv[-2] == "--settings" and json.loads(argv[-1]) == INNER, argv


@below9
def test_a_wrapper_around_claude_is_refused_unstarted(tree):
    # a script with no Claude Code package.json gives no version, and is never started to ask
    real = fake_native_claude(tree / "home" / ".local" / "share" / "claude" / "versions" /
                              "2.1.330")
    prog = tree / "bin" / "my-claude"
    prog.parent.mkdir(exist_ok=True)
    prog.write_text(f'#!/bin/sh\nexec "{real}" "$@"\n')
    prog.chmod(0o755)
    code, out = launch(tree, "", "claude", program=["--", str(prog), "-p", "hello"])
    assert code == 126 and "ARGV" not in out, out
    assert "directly" in out, out


@below9
def test_claude_does_not_start_when_the_settings_cannot_be_passed(tree):
    # after `--`, Claude Code reads every word as an argument, --settings too
    real = fake_native_claude(tree / "bin" / "claude")
    code, out = launch(tree, "", "claude", program=["--", str(real), "--", "-p"])
    assert code == 126 and "ARGV" not in out, out


def test_claude_does_not_start_on_an_architecture_without_the_filter(tree):
    from phiward import wholetool
    why = wholetool.inner_sandbox_reason(str(tree / "repo"), {"HOME": str(tree / "home")},
                                         machine="riscv64")
    assert why and "riscv64" in why, why
    assert wholetool.inner_sandbox_reason(str(tree / "repo"), {"HOME": str(tree / "home")},
                                          machine="x86_64") is None


@below9
@pytest.mark.parametrize("form", ["file", "inline"])
def test_settings_that_say_what_launch_passes_are_passed_once(tree, form):
    import json
    claude = native(tree)
    f = tree / "home" / "launch-settings.json"
    f.write_text(json.dumps(INNER))
    given = ["--settings", str(f)] if form == "file" else [f"--settings={json.dumps(INNER)}"]
    code, out = launch(tree, "", "claude", program=["--", str(claude), "-p", "x", *given])
    argv = argv_of(out)
    assert argv[:2] == ["-p", "x"] and argv.count("--settings") == 1, argv
    assert argv[-2] == "--settings" and json.loads(argv[-1]) == INNER, argv


@below9
def test_the_file_install_writes_is_passed_once(tree):
    # the shell alias `claude --settings ~/.config/phiward/claude-settings.json`
    import json
    from phiward import install
    claude = native(tree)
    f = tree / "home" / ".config" / "phiward" / "claude-settings.json"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(install.LAUNCH_SETTINGS, indent=2) + "\n")
    code, out = launch(tree, "", "claude", program=["--", str(claude), "--settings", str(f)])
    argv = argv_of(out)
    assert argv.count("--settings") == 1, argv
    assert argv[-2] == "--settings" and json.loads(argv[-1]) == INNER, argv


@below9
@pytest.mark.parametrize("args", [["init"], ["--model", "mcp", "explain"], ["-p", "fix", "mcp"],
                                  ["tag"], ["update the readme"], ["help"]])
def test_words_that_are_not_commands_of_this_claude_start_as_a_prompt(tree, args):
    # the commands are those the binary's own help lists: `init` and `tag` are not, and `mcp`
    # after --model is the model's name, after a prompt a word of it
    claude = native(tree)
    code, out = launch(tree, "", "claude", program=["--", str(claude), *args])
    assert code == 0 and argv_of(out)[:len(args)] == args, out


@below9
@pytest.mark.parametrize("help", ["", "Claude Code\n\nno usage line here\n"])
def test_claude_does_not_start_when_its_help_cannot_be_read(tree, help):
    claude = fake_native_claude(tree / "bin" / "claude", help=help)
    code, out = launch(tree, "", "claude", program=["--", str(claude), "-p", "x"])
    assert code == 126 and "ARGV" not in out, out
    assert "--help" in out, out


@below9
@pytest.mark.parametrize("bad", ["hang", "fail"])
def test_claude_does_not_start_when_a_words_help_cannot_be_read(tree, bad):
    claude = fake_native_claude(tree / "bin" / "claude", bad={"fix": bad})
    code, out = launch(tree, "", "claude", program=["--", str(claude), "fix", "it"])
    assert code == 126 and "ARGV" not in out, out
