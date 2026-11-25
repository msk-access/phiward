"""HPC requests through the operator's shared connection (no credential, no network
but its socket), and pushes as a one-way stream read by the broker itself.

A fake ssh stands in for the real one: it answers `-G` (the control socket) and `-O check` like
ssh, and otherwise records what it receives. It also tries to read a fake key, which the
profile must refuse. The real push and pull against a cluster are checked by hand."""

import io
import os
import shutil
import socket
import stat
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

from phiward import confine, copying, remote, run
from helpers import CONFINE_WHY, needs_confine


def user_cfg(extra):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + extra)


@pytest.fixture()
def hpc(tree, monkeypatch):
    """A fake shared connection: a listening unix socket under a short ~/.ssh (the trust rule
    wants it there; unix socket names are short), a fake ssh, a sink for what it gets."""
    home = Path(tempfile.mkdtemp(prefix="pwh-", dir="/tmp"))
    monkeypatch.setenv("HOME", str(home))
    (home / ".ssh").mkdir(mode=0o700)
    sock = str(home / ".ssh" / "cm")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(sock)
    srv.listen(1)
    # what the fake remote receives: a test folder, not a protected root (the gateway writes
    # only its grants); a real push writes nothing locally, ssh only talks to its socket
    sinkdir = tree / "sink"
    sinkdir.mkdir()
    sink = sinkdir / "received.tar"
    from phiward import run as runmod
    real_run = runmod.run_confined

    def with_sink(cmd, cfg, san, write_to, *a, **k):
        return real_run(cmd, cfg, san, list(write_to) + [str(sinkdir)], *a, **k)
    monkeypatch.setattr(runmod, "run_confined", with_sink)
    key = home / ".ssh" / "id_fake"
    key.write_text("FAKE-PRIVATE-KEY\n")
    outbox = tree / "pub" / "outbox"  # what the fake remote sends on a pull
    (outbox / "res").mkdir(parents=True)
    (outbox / "res" / "summary.tsv").write_text("count\t3\n")
    fake = tree / "pub" / "fake-ssh"
    fake.write_text(
        "#!/bin/sh\n"
        'case " $* " in\n'
        f'  *" -G "*) echo "controlpath {sock}"; exit 0;;\n'
        '  *" -O "*) exit 0;;\n'
        f'  *"tar -c"*) cd {outbox} && exec tar -c -f - res;;\n'
        "esac\n"
        f"cat {key} 2>/dev/null\n"
        f"cat > {sink}\n"
        "echo received\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(copying, "system_program",
                        lambda name: str(fake) if name == "ssh" else
                        next((p for p in (f"/usr/bin/{name}", f"/bin/{name}") if os.path.exists(p)), None))
    ssh_cfg = tree / "home" / "phiward-ssh"
    ssh_cfg.write_text(f"Host hpc-test\n  ControlPath {sock}\n  ControlMaster no\n")
    # a push lands only under [remote] roots: the folder the pushes go to is one ([copy] stays
    # last: tests append keys to it)
    user_cfg('\n[remote]\nroots = ["/work/me"]\n'
             f'[copy]\nremotes = ["hpc-test:/work/me"]\nssh_config = "{ssh_cfg}"\n')
    yield {"sock": sock, "sink": sink, "srv": srv, "home": home, "key": key}
    srv.close()
    import shutil
    shutil.rmtree(home, ignore_errors=True)


def fake_visible(tree):
    # Linux: a request through the shared connection gets a fresh /tmp, so a fake ssh that lives
    # in a test tree under /tmp is not there (the real one is /usr/bin/ssh)
    if sys.platform.startswith("linux") and str(tree).startswith("/tmp/"):
        pytest.skip("Linux: the test tree is under /tmp, which the request replaces; run with --basetemp")


def push(tree, *args):
    out = io.StringIO()
    code = copying.execute(list(args), str(tree / "repo"), dict(os.environ), out)
    return code, out.getvalue()


def names_in(sink):
    with tarfile.open(sink) as t:
        return sorted(m.name for m in t.getmembers())


# --- the shared connection ----------------------------------------------------------------------

def test_no_control_path_is_refused(tree, monkeypatch):
    from phiward import config
    user_cfg('\n[copy]\nremotes = ["hpc-test:/work/me"]\n')
    sock, why = remote.shared_socket(config.load(str(tree / "repo")), "hpc-test")
    # no [copy] ssh_config at all: the refusal points to the one-time HPC setup
    assert sock == "" and "ssh_config" in why and "hpc.md" in why


def test_a_connection_that_is_not_running_is_refused(tree, hpc):
    hpc["srv"].close()
    os.unlink(hpc["sock"])
    code, out = push(tree, "README.md", "hpc-test:/work/me")
    assert code == 2 and "ssh -fN hpc-test" in out, out
    assert not hpc["sink"].exists()


def test_the_route_reads_no_credential_and_has_no_network(tree, hpc):
    from phiward import config
    rt, why = remote.route(config.load(str(tree / "repo")), "hpc-test")
    assert rt is not None, why
    assert rt.socket == os.path.realpath(hpc["sock"]) and rt.net is False
    assert str(hpc["home"] / ".ssh") in rt.deny_read
    assert "ForwardAgent=no" in rt.ssh and "ForwardX11=no" in rt.ssh
    assert "-S" in rt.ssh and "ControlMaster=no" in rt.ssh


def test_local_net_runs_cannot_reach_unix_sockets():
    if sys.platform != "darwin":
        pytest.skip("Linux: the gateway's seccomp filter refuses AF_UNIX sockets")
    prof = confine.seatbelt_gateway_profile([], [], True)
    assert "(deny network-outbound (remote unix-socket))" in prof


# --- pushes -------------------------------------------------------------------------------------

@needs_confine
def test_a_push_streams_the_sources_and_the_key_stays_hidden(tree, hpc):
    fake_visible(tree)
    (tree / "repo" / "src" / "lib").mkdir()
    (tree / "repo" / "src" / "lib" / "util.py").write_text("x = 1\n")
    code, out = push(tree, "src", "README.md", "hpc-test:/work/me/proj")
    assert code == 0, out
    assert "FAKE-PRIVATE-KEY" not in out
    assert names_in(hpc["sink"]) == ["README.md", "src", "src/app.py", "src/lib",
                                     "src/lib/util.py"]
    assert "copy sent: files=3 folders=2 skipped=0" in out


@needs_confine
def test_a_trailing_slash_sends_the_contents(tree, hpc):
    fake_visible(tree)
    code, out = push(tree, "src/", "hpc-test:/work/me/proj")
    assert code == 0, out
    assert names_in(hpc["sink"]) == ["app.py"]


@needs_confine
def test_links_and_hard_links_inside_are_skipped(tree, hpc):
    fake_visible(tree)
    os.symlink(hpc["key"], tree / "repo" / "src" / "key")
    os.link(tree / "repo" / "README.md", tree / "repo" / "src" / "readme2")
    code, out = push(tree, "src", "hpc-test:/work/me/proj")
    assert code == 0, out
    assert names_in(hpc["sink"]) == ["src", "src/app.py"]
    assert "skipped=2" in out


@needs_confine
def test_a_source_swapped_for_a_link_after_the_check_sends_nothing_of_it(tree, hpc, monkeypatch):
    fake_visible(tree)
    # the race, made deterministic: the check passes, then the source
    # is swapped for a link to the folder that holds the key
    (tree / "repo" / "s").mkdir()
    (tree / "repo" / "s" / "notes.txt").write_text("harmless\n")
    real_survey = remote.survey

    def survey_then_swap(*a, **k):
        r = real_survey(*a, **k)
        os.rename(tree / "repo" / "s", tree / "repo" / "s-old")
        os.symlink(hpc["home"] / ".ssh", tree / "repo" / "s")
        return r

    monkeypatch.setattr(remote, "survey", survey_then_swap)
    code, out = push(tree, "s", "hpc-test:/work/me/proj")
    assert code != 0, out
    data = hpc["sink"].read_bytes() if hpc["sink"].exists() else b""
    assert b"FAKE-PRIVATE-KEY" not in data and "FAKE-PRIVATE-KEY" not in out


def test_a_link_to_a_credential_is_refused_at_the_check(tree, hpc):
    os.symlink(hpc["home"] / ".ssh", tree / "repo" / "via")
    code, out = push(tree, "via", "hpc-test:/work/me/proj")
    assert code == 2 and "credential" in out, out


def test_a_push_over_the_limit_is_the_operators(tree, hpc):
    user_cfg("push_limit_gib = 1\n")
    with open(tree / "repo" / "src" / "big.bin", "wb") as fh:
        fh.truncate((1 << 30) + 1)  # sparse: no disk used
    code, out = push(tree, "src", "hpc-test:/work/me/proj")
    assert code == 2 and "ask the operator" in out, out


def test_a_dry_run_counts_without_sending(tree, hpc):
    code, out = push(tree, "--dry-run", "src", "hpc-test:/work/me/proj")
    assert code == 0 and "would send files=1 folders=1" in out, out
    assert not hpc["sink"].exists()


def test_the_receiving_command_is_one_word_per_path():
    import shlex
    cmd = remote.receive_script("/work/me/proj")
    words = shlex.split(cmd)
    assert words[0:2] == ["sh", "-c"] and words[3:] == ["sh", "/work/me/proj"]
    assert "pwd -P" in words[2] and "!" not in cmd and "\\" not in cmd


def test_a_copy_between_two_remotes_is_refused(tree, hpc):
    code, out = push(tree, "hpc-test:/work/me/a", "hpc-test:/work/me/b")
    assert code == 2, out


# --- fixes to the shared connection ---------------------------------------------------------------

def test_a_socket_outside_ssh_or_not_a_socket_is_not_trusted(tmp_path, monkeypatch):
    d = tempfile.mkdtemp(prefix="pwx-", dir="/tmp")
    try:
        s = socket.socket(socket.AF_UNIX)
        s.bind(os.path.join(d, "cm"))
        assert "under ~/.ssh" in remote.socket_problem(os.path.join(d, "cm"))
        s.close()
        os.symlink("/etc/hosts", os.path.join(d, "ln"))
        assert "not a socket" in remote.socket_problem(os.path.join(d, "ln"))
        assert remote.socket_problem(os.path.join(d, "none")) == "missing"
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def test_a_group_writable_folder_above_the_socket_is_not_trusted(tree, hpc):
    os.chmod(hpc["home"] / ".ssh", 0o770)
    try:
        assert "not yours alone" in remote.socket_problem(hpc["sock"])
    finally:
        os.chmod(hpc["home"] / ".ssh", 0o700)


def test_dev_proc_and_sys_sources_are_refused(tree, hpc):
    code, out = push(tree, "/dev/fd/0", "hpc-test:/work/me/proj")
    assert code == 2 and "/dev, /proc or /sys" in out, out


@needs_confine
def test_a_dot_source_sends_the_contents(tree, hpc):
    fake_visible(tree)
    code, out = push(tree, "src/.", "hpc-test:/work/me/proj")
    assert code == 0, out
    assert names_in(hpc["sink"]) == ["app.py"]


def test_the_pull_sends_one_tar_stream():
    assert remote.send_script("/work/me/res") == "tar -c -f - -C /work/me -- res"
    assert remote.send_script("/work/me/res/") == "tar -c -f - -C /work/me/res ."


@needs_confine
def test_a_pull_lands_in_a_protected_root_through_a_confined_tar(tree, hpc):
    fake_visible(tree)
    user_cfg("")  # the fixture's remotes cover hpc-test:/work/me
    out = io.StringIO()
    code = copying.execute(["hpc-test:/work/me/res", str(tree / "phi" / "pulled")],
                           str(tree / "repo"), dict(os.environ), out)
    assert code == 0, out.getvalue()
    assert (tree / "phi" / "pulled" / "res" / "summary.tsv").read_text() == "count\t3\n"


def test_copy_output_masks_remote_roots(tree, hpc):
    from phiward import config
    from phiward.sanitize import Sanitizer
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text().replace('roots = ["/work/me"]', 'roots = ["/work/me", "/data/protected"]'))
    cfg = config.load(str(tree / "repo"))
    san = Sanitizer.from_config(cfg)
    run.add_remote_roots(san, cfg)
    assert "P-1" not in san.clean("tar: /data/protected/P-1/x.bam: Cannot open")


# --- second check of the shared connection --------------------------------------------------------

def test_dev_spelled_in_another_case_is_refused(tree, hpc):
    if sys.platform != "darwin":
        pytest.skip("only macOS folds case on the root volume")
    r, w = os.pipe()
    try:
        code, out = push(tree, f"/DEV/fd/{r}", "hpc-test:/work/me/proj")
    finally:
        os.close(r)
        os.close(w)
    assert code == 2 and "/dev, /proc or /sys" in out, out


@needs_confine
def test_a_pull_that_the_extraction_refuses_does_not_hang(tree, hpc):
    fake_visible(tree)
    # the fake remote sends 20 MB that are not a tar archive: the local tar stops early, and
    # ssh must be ended rather than left blocked on a full pipe
    fake = tree / "pub" / "fake-ssh"
    text = fake.read_text().replace(
        'exec tar -c -f - res;;',
        'exec head -c 20000000 /dev/zero | tr "\\\\0" x;;')
    fake.write_text(text)
    import threading
    result = {}

    def go():
        out = io.StringIO()
        result["code"] = copying.execute(["hpc-test:/work/me/res", str(tree / "phi" / "p")],
                                         str(tree / "repo"), dict(os.environ), out)
        result["out"] = out.getvalue()

    t = threading.Thread(target=go, daemon=True)
    t.start()
    t.join(timeout=60)
    assert not t.is_alive(), "the pull hung"
    assert result["code"] != 0, result


@pytest.mark.skipif(not sys.platform.startswith("linux") or CONFINE_WHY is not None,
                    reason="Linux confinement")
def test_linux_socket_mode_reaches_only_the_shared_connection(tree, hpc):
    import subprocess
    other_dir = tempfile.mkdtemp(prefix="pwo-", dir="/tmp")
    other = socket.socket(socket.AF_UNIX)
    other.bind(os.path.join(other_dir, "agent.sock"))
    other.listen(1)
    code = (
        "import socket\n"
        f"for p in ({confine.LINUX_SOCKET!r}, {os.path.join(other_dir, 'agent.sock')!r}):\n"
        "    s = socket.socket(socket.AF_UNIX)\n"
        "    try:\n"
        "        s.connect(p); print('open', p)\n"
        "    except OSError:\n"
        "        print('refused', p)\n")
    argv, fds = confine.gateway_command([sys.executable, "-I", "-c", code], [], [], False,
                                        deny_read=[str(hpc["home"] / ".ssh")],
                                        socket=os.path.realpath(hpc["sock"]))
    try:
        r = subprocess.run(argv, capture_output=True, text=True, pass_fds=fds, cwd="/", timeout=30)
    finally:
        for fd in fds:
            os.close(fd)
        other.close()
        shutil.rmtree(other_dir, ignore_errors=True)
    assert f"open {confine.LINUX_SOCKET}" in r.stdout, r.stdout + r.stderr
    assert "refused" in r.stdout and "agent.sock" in r.stdout.split("refused")[1], r.stdout


@pytest.mark.skipif(sys.platform != "darwin" or CONFINE_WHY is not None, reason="macOS confinement")
def test_the_one_socket_profile_can_look_up_the_user(tree, hpc):
    # the first run on HPC: real ssh said "No user exists for uid" (the fake ssh never
    # asked); the profile must answer user lookups
    import pwd
    import subprocess
    prof = confine.seatbelt_gateway_profile([], [], False, deny_read=[str(hpc["home"] / ".ssh")],
                                            socket=os.path.realpath(hpc["sock"]))
    r = subprocess.run([confine.SANDBOX_EXEC, "-p", prof, "/usr/bin/id", "-un"],
                       capture_output=True, text=True, timeout=30)
    assert r.stdout.strip() == pwd.getpwuid(os.getuid()).pw_name, r.stderr
    r = subprocess.run([confine.SANDBOX_EXEC, "-p", prof, "/usr/bin/ssh", "-G", "-F", "/dev/null",
                        "example.invalid"], capture_output=True, text=True, timeout=30)
    assert "No user exists" not in r.stderr and r.returncode == 0, r.stderr


@needs_confine
def test_a_pull_never_shows_the_names_tar_prints(tree, hpc):
    # tar errors name members relative to the pulled folder,
    # which no mask knows; a read-only destination makes the local tar print them
    fake_visible(tree)
    (tree / "pub" / "outbox" / "res" / "Smith_John_tumor.txt").write_text("x\n")
    dest = tree / "phi" / "ro"
    dest.mkdir()
    os.chmod(dest, 0o555)
    try:
        out = io.StringIO()
        copying.execute(["hpc-test:/work/me/res", str(dest)], str(tree / "repo"),
                        dict(os.environ), out)
    finally:
        os.chmod(dest, 0o755)
    text = out.getvalue()
    assert "Smith_John" not in text and "summary.tsv" not in text, text
    assert "withheld" in text, text


@needs_confine
def test_a_late_stderr_reader_does_not_touch_the_next_pull(tree, hpc, monkeypatch):
    # the first remote keeps its stderr open past the reader's join: its late line must not
    # count as a message from the second remote (which prints none)
    fake_visible(tree)
    (tree / "pub" / "outbox" / "res2").mkdir()
    (tree / "pub" / "outbox" / "res2" / "b.tsv").write_text("count\t4\n")
    fake = tree / "pub" / "fake-ssh"
    outbox = tree / "pub" / "outbox"
    text = fake.read_text().replace(
        '  *"tar -c"*)',
        f'  *"-- res "*) (sleep 1; echo late >&2) >/dev/null &\n'
        f'    cd {outbox} && exec tar -c -f - res;;\n'
        f'  *"-- res2 "*) sleep 3; cd {outbox} && exec tar -c -f - res2;;\n'
        '  *"tar -c"*)')
    fake.write_text(text)
    import threading
    real_join = threading.Thread.join
    monkeypatch.setattr(threading.Thread, "join",
                        lambda self, timeout=None: real_join(self, 0.2 if timeout else None))
    out = io.StringIO()
    code = copying.execute(["hpc-test:/work/me/res", "hpc-test:/work/me/res2",
                            str(tree / "phi" / "pulled")], str(tree / "repo"),
                           dict(os.environ), out)
    assert code == 0, out.getvalue()
    assert (tree / "phi" / "pulled" / "res2" / "b.tsv").read_text() == "count\t4\n"
    assert "from the remote withheld" not in out.getvalue(), out.getvalue()
