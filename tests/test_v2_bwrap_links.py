"""A hidden path whose parent folder is a link (`/var/run/docker.sock`, with `/var/run` -> `/run`
on most Linux systems) must be hidden at its real place: bubblewrap cannot make a mount point
through a link, and before this fix every gateway command failed on a machine with Docker
("bwrap: Can't create file at /var/run/docker.sock"), found by the first CI run on GitHub's
Ubuntu runners. Made-up folders only."""

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
