"""A launch inside a `phiward launch` session: a wrapped MCP server (`launch --entry ID --`).

On macOS a launch inside phiward's profile runs its command directly. On Linux it used to wrap
itself again, and the new session's carry-over had to write ~/.phiward, which the outer session
holds read-only: the wrapped server never started (found by scripts/sandbox-check, Mode B).

Now the tool's seccomp filter answers one unassigned syscall number with an errno nothing else
returns (the fingerprint). A launch that sees exactly that errno is inside phiward's session and
runs the command directly, as on macOS. No filter (ENOSYS), another filter (EPERM, another
errno), or a Mode A-shaped bubblewrap builds the full profile as before. Made-up trees only."""

import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import confine, wholetool
from helpers import needs_confine

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")

PROBE_NR, PROBE_ERRNO = 360, 3917
ID = "0123456789abcdef"

# prints PROBE-<errno> for the fingerprint syscall (PROBE-0 when it did not fail)
PROBE = (f"import ctypes\nlibc = ctypes.CDLL(None, use_errno=True)\n"
         f"libc.syscall.restype = ctypes.c_long\nctypes.set_errno(0)\n"
         f"r = libc.syscall(ctypes.c_long({PROBE_NR}))\n"
         f"print('PROBE-%d' % (ctypes.get_errno() if r == -1 else 0))\n")


# --- the filter: a small classic-BPF reader, so both architectures are checked anywhere --------

def _run_bpf(prog: bytes, arch: int, nr: int, args=(0,) * 6) -> int:
    data = struct.pack("<iI", nr, arch) + struct.pack("<Q", 0) + \
        b"".join(struct.pack("<Q", a) for a in args)
    ins = [struct.unpack("<HBBI", prog[i:i + 8]) for i in range(0, len(prog), 8)]
    pc, acc = 0, 0
    while True:
        code, jt, jf, k = ins[pc]
        if code == 0x20:
            acc = struct.unpack("<I", data[k:k + 4])[0]
            pc += 1
        elif code == 0x15:
            pc += 1 + (jt if acc == k else jf)
        elif code == 0x35:
            pc += 1 + (jt if acc >= k else jf)
        elif code == 0x06:
            return k
        else:
            raise AssertionError(f"unknown instruction {code:#x}")


@pytest.mark.parametrize("machine", ["x86_64", "aarch64"])
def test_the_tool_filter_answers_the_probe_with_the_fingerprint(machine):
    prog = wholetool.tool_seccomp_program(machine)
    arch = confine._AUDIT_ARCH[machine]
    col = 0 if machine == "x86_64" else 1
    assert _run_bpf(prog, arch, PROBE_NR) == 0x00050000 | PROBE_ERRNO
    # the rest of the filter is unchanged
    assert _run_bpf(prog, arch, confine._DENY["keyctl"][col]) == 0x00050001
    getpid = (39, 172)[col]
    assert _run_bpf(prog, arch, getpid) == 0x7FFF0000
    assert _run_bpf(prog, arch ^ 1, PROBE_NR) == 0x80000000


@pytest.mark.parametrize("machine", ["x86_64", "aarch64"])
def test_the_gateway_filter_has_no_fingerprint(machine):
    prog = confine.seccomp_program(machine)
    assert _run_bpf(prog, confine._AUDIT_ARCH[machine], PROBE_NR) == 0x7FFF0000


def test_the_fingerprint_numbers():
    assert (wholetool.FINGERPRINT_SYSCALL, wholetool.FINGERPRINT_ERRNO) == (PROBE_NR, PROBE_ERRNO)
    # unassigned on both: x86_64 335-423 and aarch64 295-402 are gaps; new calls start at 424
    assert 335 <= PROBE_NR <= 386 and 295 <= PROBE_NR <= 402
    assert all(PROBE_NR not in nums for nums in confine._DENY.values())
    assert 0 < PROBE_ERRNO < 4096  # the C library reports it as an errno


# --- already_confined on Linux ---------------------------------------------------------------

@linux
def test_outside_a_session_is_not_confined():
    assert wholetool.already_confined(dict(os.environ)) is False


def _filter(errno_value: int, machine: str) -> bytes:
    """A filter that answers the probe syscall with `errno_value` and allows the rest."""
    ld, jeq, ret = 0x20, 0x15, 0x06
    prog = [(ld, 0, 0, 4), (jeq, 1, 0, confine._AUDIT_ARCH[machine]), (ret, 0, 0, 0x80000000),
            (ld, 0, 0, 0), (jeq, 0, 1, PROBE_NR), (ret, 0, 0, 0x00050000 | errno_value),
            (ret, 0, 0, 0x7FFF0000)]
    return b"".join(struct.pack("<HBBI", *i) for i in prog)


def _under_filter(prog: bytes, argv, cwd=None):
    """Run argv in a bubblewrap that shares the whole file system, under the filter `prog`."""
    bwrap = shutil.which("bwrap")
    r, w = os.pipe()
    os.write(w, prog)
    os.close(w)
    try:
        p = subprocess.run([bwrap, "--dev-bind", "/", "/", "--seccomp", str(r), "--"] + argv,
                           pass_fds=[r], capture_output=True, text=True, timeout=120, cwd=cwd,
                           env=dict(os.environ, PYTHONPATH=SRC))
    finally:
        os.close(r)
    out = p.stdout + p.stderr
    if "create a new namespace" in out or "No permissions to create" in out:
        pytest.skip("no user namespaces here")
    return p.returncode, out


CONFINED = ("import os; from phiward import wholetool; "
            "print('CONFINED-%s' % wholetool.already_confined(dict(os.environ)))")


@linux
@needs_confine
@pytest.mark.parametrize("value,expect", [
    (PROBE_ERRNO, True), (PROBE_ERRNO - 1, False), (1, False), (38, False)])
def test_only_the_exact_errno_counts(value, expect):
    _, out = _under_filter(_filter(value, confine._machine()), [PY, "-c", CONFINED])
    assert f"CONFINED-{expect}" in out, out


@linux
@needs_confine
def test_another_filter_that_denies_keyctl_does_not_count():
    """The gateway's filter (Mode A) denies keyctl with EPERM too, but has no fingerprint."""
    _, out = _under_filter(confine.seccomp_program(), [PY, "-c", CONFINED])
    assert "CONFINED-False" in out, out


@linux
@needs_confine
def test_a_launch_in_a_mode_a_shaped_bubblewrap_still_builds_the_profile(tree):
    """Inside a bubblewrap with another filter, launch never runs its command directly: either
    the command runs in phiward's own profile (it sees the fingerprint) or nothing runs."""
    code, out = _under_filter(confine.seccomp_program(), [
        PY, "-m", "phiward", "launch", "--entry", ID, "--", PY, "-c", PROBE],
        cwd=str(tree / "repo"))
    assert "PROBE-" not in out or f"PROBE-{PROBE_ERRNO}" in out, out
    if f"PROBE-{PROBE_ERRNO}" not in out:
        assert code != 0, out


# --- launch inside launch ----------------------------------------------------------------------

def _launch(tree, code):
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([PY, "-m", "phiward", "launch", "--", PY, "-c", code],
                       cwd=str(tree / "repo"), capture_output=True, text=True, env=env,
                       timeout=120)
    return r.returncode, r.stdout + r.stderr


def _inner(args):
    """The outer tool's code: start `phiward launch ARGS` and print its pid, output and exit."""
    return (f"import subprocess, os\n"
            f"p = subprocess.Popen([{PY!r}, '-m', 'phiward', 'launch'] + {list(args)!r}, "
            f"stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, "
            f"env=dict(os.environ, PYTHONPATH={SRC!r}))\n"
            f"out = p.communicate()[0]\n"
            f"print('CHILD-%d' % p.pid)\nprint(out)\nprint('INNER-EXIT-%d' % p.returncode)\n")


WHO = "import os; print('INNER-RAN-%d' % os.getpid())"


@needs_confine
def test_a_wrapped_server_inside_a_session_runs_directly(tree):
    """The Linux Mode B bug: the inner `launch --entry ID --` never started its command."""
    _, out = _launch(tree, _inner(["--entry", ID, "--", PY, "-c", WHO]))
    child = [ln for ln in out.splitlines() if ln.startswith("CHILD-")]
    assert child, out
    # the command replaced the inner launcher: no second session around it
    assert f"INNER-RAN-{child[0][6:]}" in out, out
    assert "INNER-EXIT-0" in out, out


@linux
@needs_confine
def test_the_command_inside_runs_under_the_outer_filter(tree):
    _, out = _launch(tree, _inner(["--entry", ID, "--", PY, "-c", PROBE]))
    assert f"PROBE-{PROBE_ERRNO}" in out, out


@needs_confine
def test_a_report_inside_a_session_is_handled_as_on_macos(tree):
    """--report inside a session: the report says the outer profile holds and the command runs
    directly, or, where the report cannot be written there, nothing runs (exit 2)."""
    report = "/tmp/phiward-nested-FAKE-PT-0001.json"
    show = f"import json; print('REPORT-' + json.dumps(json.load(open({report!r}))))"
    _, out = _launch(tree, _inner(["--report", report, "--entry", ID, "--", PY, "-c", show]))
    if "INNER-EXIT-2" in out:
        # only where the session cannot write the report's place (not the case here: /tmp)
        pytest.fail("the report should be writable in the session's /tmp: " + out)
    assert "INNER-EXIT-0" in out, out
    line = next(ln for ln in out.splitlines() if ln.startswith("REPORT-"))
    data = json.loads(line[len("REPORT-"):])
    assert any("launch inside launch" in n for n in data["notes"]), data
    assert data["exit"] is None, data


@needs_confine
def test_no_fingerprint_and_a_read_only_tools_folder_still_refuse(tree):
    """No fallback: outside a session, a ~/.phiward that cannot be written stops the launch."""
    base = tree / "home" / ".phiward"
    base.mkdir(exist_ok=True)
    base.chmod(0o555)
    try:
        code, out = _launch(tree, "print('OUTER-RAN')")
    finally:
        base.chmod(0o755)
    assert code != 0 and "OUTER-RAN" not in out, out
