"""Kernel confinement, tested by running real commands on the made-up tree.

Each finding of the first security review is here as a command that runs for real; the test
reads its output.
(The AGENT profile, `phiward exec`, is gone: Claude Code's sandbox confines the agent's shell.)
- The GATEWAY (`phiward run -- CMD`, a client of the broker): it reads protected data, but it
  writes only inside the protected roots, has no network, and its output never holds the name of
  a protected entry. Every test here has a running broker with no terminal (grants refused).

Without a backend (macOS sandbox-exec, Linux bubblewrap) the tests skip, unless
PHIWARD_REQUIRE_CONFINE=1 (CI sets it), when they fail.
"""

import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from helpers import CONFINE_WHY

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
pytestmark = [pytest.mark.skipif(CONFINE_WHY is not None, reason=f"no confinement: {CONFINE_WHY}"),
              pytest.mark.usefixtures("broker")]

NAMES = ("FAKE-PT-0001", "FAKE-PT-0002", "FAKE-PT-0003")


LAUNCH = ("import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; "
          "from phiward.cli import main; sys.exit(main())")


def ag(args, cwd, timeout=60):
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([PY, "-c", LAUNCH] + args, cwd=str(cwd), capture_output=True,
                       text=True, env=env, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def agent(t, cmd, cwd="repo"):
    """A command in the agent's own shell (unconfined here: these tests are about the gateway)."""
    r = subprocess.run(["/bin/sh", "-c", cmd], cwd=str(t / cwd), capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=SRC), timeout=60)
    return r.returncode, r.stdout + r.stderr


def gate(t, args, cwd="repo"):
    return ag(["run"] + args, t / cwd)


def grant(t, body):
    cfg = Path(os.environ["PHIWARD_CONFIG"])
    cfg.write_text(cfg.read_text() + "[broker]\n" + body.format(t=t))


# --- the agent profile: class A of the first review -----------------------------------------------

def test_a_shell_passes_a_gateway_call_to_the_broker(tree):
    code, out = agent(tree, f"{PY} -m phiward run -- ls ../phi")
    assert code == 0 and "<ENTRY>" in out and "FAKE-PT" not in out


def test_grants_are_refused_without_the_user_config(tree):
    code, out = agent(tree, f"{PY} -m phiward run --net -- ls ../phi")
    assert code == 2 and "not granted" in out


# --- the gateway: classes B and C of the first review ---------------------------------------------

def test_gateway_reads_protected_data(tree):
    code, out = gate(tree, ["--", "cat", "../phi/FAKE-PT-0001.bam"])
    assert code == 0 and "SECRET-CONTENT-0001" in out  # content is the script's business


@pytest.mark.parametrize("args", [
    ["--", "ls", "../phi"],
    ["--", "ls", "-R", "../phi"],
    ["--", "find", "../phi"],
    ["--", "du", "-a", "../phi"],
    ["--", "find", "{t}/repo/../phi"],
    ["--", "find", "{t}//phi"],
    ["--", "ls", "../runs/run1/panel"],
    ["--", "mv", "../phi/FAKE-PT-0001.bam", "../pub/"],
    ["--", "cat", "../phi/FAKE-PT-0001.bam.missing"],
    ["--", "sh", "-c", "ls ../phi >&2"],
])
def test_gateway_output_never_names_a_protected_entry(tree, args):
    _, out = gate(tree, [a.format(t=tree) for a in args])
    assert not any(n in out for n in NAMES), out


@pytest.mark.parametrize("cmd", [
    "cp -R ../phi ../pub/copy",
    "ln ../phi/FAKE-PT-0001.bam ../pub/hard",
    "tar -cf ../pub/x.tar ../phi",
    "sort -o ../pub/sorted ../phi/FAKE-PT-0001.bam",
    "rsync -a ../phi/ ../pub/r/",
    "mv ../phi/FAKE-PT-0001.bam ../pub/",
    "cat ../phi/FAKE-PT-0001.bam > ../pub/out.txt",
])
def test_gateway_cannot_write_outside_the_roots(tree, cmd):
    gate(tree, ["--", "sh", "-c", cmd])
    found = [str(p) for p in (tree / "pub").rglob("*")]
    assert found == [], found
    assert (tree / "phi" / "FAKE-PT-0001.bam").exists()


def test_gateway_writes_only_its_scratch_and_its_grants(tree, broker):
    # roots are read only for the gateway; a grant may sit inside one
    code, out = gate(tree, ["--", "sh", "-c", 'echo t > "$TMPDIR/t" && cat "$TMPDIR/t"'])
    assert code == 0
    assert list((tree / "home" / ".cache" / "phiward").glob("run-*")) == []  # removed
    copy = ["sh", "-c", "cp ../phi/FAKE-PT-0001.bam ../phi/sub/copy.bam"]
    code, out = gate(tree, ["--"] + copy)
    assert code != 0 and not (tree / "phi" / "sub" / "copy.bam").exists()
    (tree / "phi" / "sub").mkdir(exist_ok=True)
    grant(tree, 'write_to = ["{t}/phi/sub"]\n')
    broker()  # a changed config takes effect when the operator restarts the broker
    code, out = gate(tree, ["--write-to", str(tree / "phi" / "sub"), "--"] + copy)
    assert code == 0 and (tree / "phi" / "sub" / "copy.bam").exists(), out


def test_gateway_write_grant(tree, broker):
    grant(tree, 'write_to = ["{t}/pub"]\n')
    broker()  # a changed config takes effect when the operator restarts the broker
    code, _ = gate(tree, ["--write-to", str(tree / "pub"), "--", "sh", "-c",
                          "echo aggregate > ../pub/summary.txt"])
    assert code == 0 and (tree / "pub" / "summary.txt").read_text() == "aggregate\n"


@pytest.fixture()
def listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                c.sendall(b"PONG\n")
                c.close()
            except OSError:
                pass

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    yield srv.getsockname()[1]
    stop.set()
    srv.close()


def _connect(port):
    return ("import socket;s=socket.create_connection(('127.0.0.1',%d),timeout=3);"
            "print(s.recv(5).decode())" % port)


def test_gateway_has_no_network(tree, listener):
    _, out = gate(tree, ["--", PY, "-c", _connect(listener)])
    assert "PONG" not in out


def test_gateway_network_grant(tree, listener, broker):
    if sys.platform.startswith("linux"):
        pytest.skip("bubblewrap --unshare-net is all or nothing; with --net the host network is used")
    grant(tree, "net = true\n")
    broker()  # a changed config takes effect when the operator restarts the broker
    code, out = gate(tree, ["--net", "--", PY, "-c", _connect(listener)])
    assert code == 0 and "PONG" in out


def test_gateway_refuses_when_the_inventory_is_too_large(tree):
    cfg = Path(os.environ["PHIWARD_CONFIG"])
    cfg.write_text(cfg.read_text() + "[sanitize]\ninventory_limit = 2\n")
    code, out = gate(tree, ["--", "ls", "../phi"])
    assert code == 3 and "FAKE-PT" not in out


def test_gateway_needs_the_double_dash(tree):
    code, out = gate(tree, ["ls", "../phi"])
    assert code == 2 and "FAKE-PT" not in out


def test_copy_runs_in_the_gateway(tree):
    (tree / "phi" / "copies").mkdir()  # a folder inside a root (a pattern match is not a destination)
    code, out = ag(["copy", str(tree / "phi" / "FAKE-PT-0001.bam"), str(tree / "phi/copies/")],
                   tree / "repo")
    assert code == 0 and (tree / "phi/copies/FAKE-PT-0001.bam").exists()
    assert "FAKE-PT" not in out
