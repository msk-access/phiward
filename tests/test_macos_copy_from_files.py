"""`phiward copy` runs no inline code: its parts are programs or files in the installed package.

- a pull's extractor is `<python> -I <PKG>/phiward/tar_extract.py DEST`, not `python -c`;
- a local copy makes its folder with the system `mkdir`, as its own confined step, not `sh -c`;
- a dry run without rsync runs the system `true`, not `python -c pass`.

Each failure path refuses: a missing extractor file, a `mkdir` that fails. Static: the
confinement is stood in for (it records the argv, then starts it as the kernel would). Made-up
trees only (FAKE-PT-0001); the fake ssh of test_v2_push.
"""

import io
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from phiward import config, confine, copying, remote, run
from test_v2_push import hpc, user_cfg  # noqa: F401 - the fixture

PKG = Path(remote.__file__).resolve().parent


def _recorder(seen, fail=None):
    """Stands for run.run_confined: records the argv and its grants, then starts it unconfined
    (with the request's stdin feed, as the gateway would). `fail(cmd)` true: refused, not run."""
    def run_confined(cmd, cfg, san, write_to, net, out, **k):
        seen.append({"cmd": list(cmd), "write_to": list(write_to), "net": net,
                     "deny_read": list(k.get("deny_read", ()))})
        if fail and fail(cmd):
            return 1
        feed = k.get("stdin_feed")
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE if feed else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             cwd=k.get("cwd"), env=k.get("env"))
        t = None
        if feed:
            def go():
                try:
                    feed(p.stdin)
                except OSError:
                    pass  # the command ended first
                finally:
                    try:
                        p.stdin.close()
                    except OSError:
                        pass
            t = threading.Thread(target=go, daemon=True)
            t.start()
        p.stdout.read()
        p.wait(timeout=60)
        if t:
            t.join(timeout=60)
        return p.returncode
    return run_confined


def _no_inline(cmd):
    return not any(w in ("-c", "-e", "-p") for w in cmd) and \
        not any(os.path.basename(w) in ("sh", "bash") for w in cmd)


@pytest.fixture()
def unconfined_ssh(monkeypatch):
    """The ssh of a pull starts unconfined (static: no sandbox is started)."""
    monkeypatch.setattr(confine, "gateway_command", lambda cmd, *a, **k: (list(cmd), []))
    monkeypatch.setattr(confine, "release_profile", lambda argv: None)


def _pull(tree, dest):
    out = io.StringIO()
    code = copying.execute(["hpc-test:/work/me/res", str(dest)], str(tree / "repo"),
                           dict(os.environ), out)
    return code, out.getvalue()


# --- the pull's extractor ----------------------------------------------------------------------

def test_the_extractor_is_a_file_in_the_package_not_inline_code():
    assert not hasattr(remote, "EXTRACT_PY")
    assert Path(remote.EXTRACTOR) == PKG / "tar_extract.py"
    assert Path(remote.EXTRACTOR).is_file()


def test_a_pull_runs_the_extractor_from_its_file(tree, hpc, unconfined_ssh, monkeypatch):  # noqa: F811
    seen = []
    monkeypatch.setattr(run, "run_confined", _recorder(seen))
    user_cfg("")
    dest = tree / "phi" / "pulled"
    code, out = _pull(tree, dest)
    assert code == 0, out
    assert [s["cmd"] for s in seen] == [[sys.executable, "-I", str(PKG / "tar_extract.py"),
                                         str(dest)]], seen
    assert seen[0]["net"] is False
    assert seen[0]["deny_read"] == run.gateway_hidden(config.load(str(tree / "repo")))
    assert (dest / "res" / "summary.tsv").read_text() == "count\t3\n"


def test_a_pull_without_its_extractor_file_fails_and_writes_nothing(tree, hpc, unconfined_ssh,  # noqa: F811
                                                                    monkeypatch):
    seen = []
    monkeypatch.setattr(run, "run_confined", _recorder(seen))
    monkeypatch.setattr(remote, "EXTRACTOR", str(tree / "pub" / "gone" / "tar_extract.py"),
                        raising=False)
    user_cfg("")
    dest = tree / "phi" / "pulled"
    code, out = _pull(tree, dest)
    assert code != 0, out
    assert not (dest / "res").exists()


# --- the local copy ----------------------------------------------------------------------------

def _local(tree, monkeypatch, *args, fail=None, rsync=True):
    seen = []
    monkeypatch.setattr(run, "run_confined", _recorder(seen, fail))
    if not rsync:
        monkeypatch.setattr(copying, "rsync_command", lambda a, d: None)
    out = io.StringIO()
    code = copying.execute(list(args), str(tree / "repo"), dict(os.environ), out)
    return code, out.getvalue(), seen


def test_a_local_copy_makes_its_folder_with_mkdir_then_copies(tree, monkeypatch):
    src = tree / "phi" / "FAKE-PT-0001.bam"
    folder = tree / "phi" / "copies" / "new"
    code, out, seen = _local(tree, monkeypatch, str(src), str(folder) + "/")
    assert code == 0, out
    assert len(seen) == 2, seen
    mkdir, copy = seen
    assert mkdir["cmd"] == [copying.system_program("mkdir"), "-p", "--", str(folder) + "/"]
    assert os.path.dirname(mkdir["cmd"][0]) in copying.SYSTEM_DIRS
    assert os.path.basename(copy["cmd"][0]) in ("rsync", "cp"), copy
    # the same profile: the same write place, no network, the same hidden list
    assert mkdir["write_to"] == copy["write_to"] and mkdir["deny_read"] == copy["deny_read"]
    assert mkdir["net"] is False and copy["net"] is False
    assert all(_no_inline(s["cmd"]) for s in seen), seen
    assert (folder / "FAKE-PT-0001.bam").exists()


def test_a_local_copy_whose_mkdir_fails_copies_nothing(tree, monkeypatch):
    src = tree / "phi" / "FAKE-PT-0001.bam"
    folder = tree / "phi" / "copies" / "new"
    code, out, seen = _local(tree, monkeypatch, str(src), str(folder) + "/",
                             fail=lambda cmd: os.path.basename(cmd[0]) == "mkdir")
    assert code != 0, out
    assert len(seen) == 1 and os.path.basename(seen[0]["cmd"][0]) == "mkdir", seen
    assert not (folder / "FAKE-PT-0001.bam").exists()


@pytest.mark.parametrize("rsync", [True, False])
def test_a_local_dry_run_runs_no_inline_code(tree, monkeypatch, rsync):
    src = tree / "phi" / "FAKE-PT-0001.bam"
    folder = tree / "phi" / "copies"
    code, out, seen = _local(tree, monkeypatch, "--dry-run", str(src), str(folder) + "/",
                             rsync=rsync)
    assert code == 0, out
    assert len(seen) == 1 and _no_inline(seen[0]["cmd"]), seen
    if not rsync:
        assert seen[0]["cmd"] == [copying.system_program("true")], seen
    assert not folder.exists()
