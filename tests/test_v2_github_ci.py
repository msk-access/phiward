"""Fixes from the first CI runs on GitHub's own machines.

A hidden path whose parent folder is a link (`/var/run/docker.sock`, with `/var/run` -> `/run`
on most Linux systems) must be hidden at its real place: bubblewrap cannot make a mount point
through a link, and before this fix every gateway command failed on a machine with Docker
("bwrap: Can't create file at /var/run/docker.sock"), found by the first CI run on GitHub's
Ubuntu runners. Made-up folders only."""

import contextlib
import inspect
import os
import shutil
import subprocess
import sys

import pytest

from phiward import confine


def _linked_secret(tmp_path):
    real = tmp_path / "run"
    real.mkdir()
    (real / "sock").write_text("SECRET-LINKED\n")
    (tmp_path / "varrun").symlink_to(real, target_is_directory=True)
    return str(tmp_path / "varrun" / "sock"), os.path.realpath(str(real / "sock"))


def _mount_targets(args):
    out = []
    for i, a in enumerate(args):
        if a in ("--ro-bind", "--bind") and i + 2 < len(args):
            out.append(args[i + 2])
        elif a == "--tmpfs" and i + 1 < len(args):
            out.append(args[i + 1])
    return out


def test_a_hidden_path_under_a_linked_folder_is_mounted_at_its_real_place(tmp_path):
    written, real = _linked_secret(tmp_path)
    args = confine.bwrap_gateway_args([], [], False, deny_read=[written])
    targets = _mount_targets(args)
    assert real in targets, targets
    for t in targets:
        parent = os.path.dirname(t)
        assert os.path.realpath(parent) == parent, f"a mount point through a link: {t}"


def test_each_hidden_place_is_mounted_once(tmp_path):
    written, real = _linked_secret(tmp_path)
    args = confine.bwrap_gateway_args([], [], False, deny_read=[written, real])
    assert _mount_targets(args).count(real) == 1


@pytest.mark.skipif(not sys.platform.startswith("linux") or not shutil.which("bwrap"),
                    reason="needs Linux and bubblewrap")
def test_bubblewrap_runs_and_the_linked_secret_is_hidden(tmp_path):
    written, real = _linked_secret(tmp_path)
    args = ["bwrap"] + confine.bwrap_gateway_args([], [], False, deny_read=[written])
    r = subprocess.run(args + ["cat", written], capture_output=True, text=True, timeout=60)
    if "create a new namespace" in r.stderr:
        pytest.skip("no user namespaces here")
    assert "Can't create" not in r.stderr, r.stderr
    assert "SECRET-LINKED" not in r.stdout


# --- the first CI run on GitHub, macOS: two launches at once (two wrapped MCP servers) -----------

def test_a_canary_made_by_another_launch_at_the_same_moment_is_fine(tmp_path):
    """Two launches both see no canary, both create it; the second must not fail
    (`[Errno 17] File exists ... launch-canary; nothing runs`)."""
    from phiward import wholetool
    canary = tmp_path / "launch-canary"
    canary.write_text("made by the other launch\n")
    wholetool._make_canary(str(canary))  # the losing side of the race: no error
    assert canary.read_text() == "made by the other launch\n"
    fresh = tmp_path / "fresh-canary"
    wholetool._make_canary(str(fresh))
    assert fresh.is_file() and not fresh.is_symlink()


# --- the second CI run on GitHub: Python 3.10 and 3.11 -------------------------------------------
# shutil.rmtree recurses before Python 3.12, and ignore_errors does not catch RecursionError, so a
# scratch folder the agent's command made deep enough stopped its request and stayed behind, and
# the next broker start (sweep_scratch) failed on it.

DEPTH = 600  # macOS takes about 0.5 s for 600 levels and 15 s for 1500


def _deep(root, depth=DEPTH):
    """A folder `depth` levels deep, made one level at a time by descriptor, as an agent's command
    can make it. Its path is longer than macOS allows (PATH_MAX 1024) and longer than the
    900 characters below which `carryover._remove` works by name; Linux allows 4096."""
    assert len(str(root)) + 2 * depth > 1024
    root.mkdir(parents=True)
    fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    for _ in range(depth):
        os.mkdir("d", dir_fd=fd)
        nfd = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
        os.close(fd)
        fd = nfd
    f = os.open("f", os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=fd)
    os.close(f)
    os.close(fd)


def _no_recursive_rmtree(monkeypatch):
    import shutil as _sh

    def boom(*a, **k):
        raise RecursionError("maximum recursion depth exceeded (as Python 3.9-3.11)")
    monkeypatch.setattr(_sh, "rmtree", boom)


@contextlib.contextmanager
def _low_recursion_limit(headroom=150):
    """A recursion limit `headroom` frames above the current stack, restored after: a remover
    that recurses once per level fails well before `DEPTH`, on every Python version (the default
    limit, 1000, is above `DEPTH`)."""
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(len(inspect.stack(0)) + headroom)
    try:
        yield
    finally:
        sys.setrecursionlimit(old)


def test_a_deep_scratch_folder_is_removed_at_the_broker_start(tmp_path, monkeypatch):
    from phiward import run
    _no_recursive_rmtree(monkeypatch)
    cache = tmp_path / "cache"
    scratch = cache / (run.SCRATCH_PREFIXES[0] + "left")
    _deep(scratch)
    with _low_recursion_limit():
        assert run.sweep_scratch(str(cache)) == 1
    assert not scratch.exists()


def test_remove_tree_takes_any_depth_and_never_follows_a_link(tmp_path):
    from phiward import safeio
    keep = tmp_path / "keep"
    keep.mkdir()
    (keep / "k").write_text("kept\n")
    t = tmp_path / "t"
    _deep(t)
    (t / "link").symlink_to(keep, target_is_directory=True)
    with _low_recursion_limit():
        assert safeio.remove_tree(str(t)) is True
    assert not t.exists() and (keep / "k").read_text() == "kept\n"
    assert safeio.remove_tree(str(tmp_path / "absent")) is True


def test_no_module_of_phiward_uses_shutil_rmtree():
    import pathlib
    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "phiward"
    users = [p.name for p in src.rglob("*.py") if "rmtree(" in p.read_text(encoding="utf-8")]
    assert users == [], users


# --- the CI run on develop after the merge: macOS, Python 3.10 ------------------------------------
# git's background maintenance (after a commit) made and removed .git/objects/maintenance.lock while
# a test removed .git: "No such file or directory: 'maintenance.lock'".

def test_the_test_repositories_run_no_background_maintenance(tmp_path):
    import subprocess
    from helpers import git_repo
    git_repo(tmp_path / "r")

    def get(key):
        return subprocess.run(["git", "config", "--get", key], cwd=tmp_path / "r",
                              capture_output=True, text=True).stdout.strip()
    assert get("maintenance.auto") == "false"
    assert get("gc.auto") == "0"
