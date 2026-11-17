"""Fixes to the path identity model, third set.

The hook fails closed on any path it cannot resolve all the way (findings 1, 5); every `.git`
from a root up to `/` is derived (finding 2); aliases are found for mounts inside a root and for
overlay lower folders in every spelling (findings 3, 4, 8); bugs 6, 7.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import config, core, fsinfo, pathid, paths
from phiward.guards import protected_paths
from helpers import git_repo

SRC = str(Path(__file__).resolve().parents[1] / "src")
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")


def _read_verdict(tree, path):
    cfg = config.load(str(tree / "repo"))
    act = core.Action(kind=core.FILE_READ, cwd=str(tree / "repo"), paths=(path,), tool="Read")
    return protected_paths.check(act, cfg).verdict


# --- findings 1 and 5: fail closed on what the walk cannot resolve ----------------------------

@macos
def test_f1_a_volfs_path_to_a_protected_file_is_denied(tree):
    st = os.stat(tree / "phi" / "FAKE-PT-0001.bam")
    spelled = f"/.vol/{st.st_dev}/{st.st_ino}"
    with open(spelled) as fh:
        assert "SECRET-CONTENT" in fh.read()
    assert paths.ProtectedSet([str(tree / "phi")], []).relation(spelled) == paths.INSIDE
    assert _read_verdict(tree, spelled) == core.DENY


@macos
def test_f1_an_unresolvable_volfs_path_counts_as_inside(tree):
    assert paths.ProtectedSet([str(tree / "phi")], []).relation("/.vol/1/2/3") == paths.INSIDE


def test_f5_a_proc_magic_link_path_counts_as_inside(tree):
    if not os.path.isdir("/proc/self/fd"):
        pytest.skip("no /proc")
    with open(tree / "pub" / "x.txt", "w") as fh:
        p = f"/proc/self/fd/{fh.fileno()}"
        assert paths.ProtectedSet([str(tree / "phi")], []).relation(p) == paths.INSIDE


def test_f5_walk_reports_whether_it_resolved_everything(tree):
    ok = pathid.walk_full(str(tree / "phi" / "FAKE-PT-0001.bam"))
    assert ok.complete
    missing = pathid.walk_full(str(tree / "phi" / "no" / "such"))
    assert missing.complete  # a missing tail is a normal answer, not a failure


# --- finding 2: every .git up to / ------------------------------------------------------------

def _only_root(monkeypatch, base, root):
    cfgf = base / "c.toml"
    cfgf.write_text(f'[protected_paths]\nroots = ["{root}"]\n')
    monkeypatch.setenv("PHIWARD_CONFIG", str(cfgf))
    monkeypatch.setenv("HOME", str(base / "home"))
    (base / "home").mkdir(exist_ok=True)


def test_f2_a_planted_nearer_git_never_hides_the_real_one_even_without_pins(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    git_repo(base / "repo")
    (base / "repo" / "data" / "phi").mkdir(parents=True)
    _only_root(monkeypatch, base, base / "repo" / "data" / "phi")
    (base / "repo" / "data" / ".git").mkdir()  # planted, no pins anywhere
    cfg = config.load(str(base))
    assert str(base / "repo" / ".git") in cfg.derived_roots, cfg.derived_roots


def test_f2_a_worktree_git_file_is_a_derived_root(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    git_repo(base / "main")
    subprocess.run(["git", "worktree", "add", "-q", str(base / "wt")], cwd=base / "main",
                   check=True, capture_output=True)
    (base / "wt" / "phi").mkdir()
    _only_root(monkeypatch, base, base / "wt" / "phi")
    cfg = config.load(str(base))
    assert str(base / "wt" / ".git") in cfg.derived_roots
    assert str(base / "main" / ".git") in cfg.derived_roots


def test_f2_doctor_says_when_no_pins_exist(tree):
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([sys.executable, "-m", "phiward", "doctor"], cwd=str(tree / "repo"),
                       capture_output=True, text=True, env=env)
    assert "pin" in r.stdout


# --- findings 3, 4, 8: aliases ------------------------------------------------------------------

MI = """\
30 1 8:1 / / rw - ext4 /dev/sda1 rw
40 30 8:1 / /data rw - ext4 /dev/sda1 rw
50 40 0:60 / /data/phi/sub rw - nfs4 filer:/scratch rw
51 30 0:60 / /mnt/elsewhere rw - nfs4 filer:/scratch rw
60 30 0:70 / /merged rw - overlay overlay rw,lowerdir=/data/p\\054hi:/x,upperdir=/u,workdir=/w
"""


def test_f3_a_separate_mount_inside_a_root_bound_elsewhere_is_an_alias():
    assert "/mnt/elsewhere" in fsinfo.alias_paths("/data/phi", MI)


def test_f4_overlay_options_are_split_before_unescaping():
    assert "/merged" in fsinfo.alias_paths("/data/p,hi", MI)


def test_f4_a_relative_overlay_lower_is_unknown():
    mi = "30 1 8:1 / / rw - ext4 /dev/sda1 rw\n61 30 0:71 / /m rw - overlay overlay rw,lowerdir=phi,upperdir=/u,workdir=/w\n"
    assert fsinfo.unknown_overlays(mi) == ["/m"]


@linux
def test_f3_real_nested_mount_bound_elsewhere(tmp_path):
    if not shutil.which("unshare"):
        pytest.skip("no unshare")
    base = tmp_path.resolve()
    (base / "phi" / "sub").mkdir(parents=True)
    (base / "mnt").mkdir()
    code = (f"import sys; sys.path.insert(0, {SRC!r}); from phiward import fsinfo; "
            f"print(fsinfo.alias_paths({str(base / 'phi')!r}))")
    r = subprocess.run(["unshare", "-rm", "sh", "-c",
                        f"mount -t tmpfs none {base}/phi/sub && mount --bind {base}/phi/sub {base}/mnt"
                        f" && {sys.executable} -c \"{code}\""], capture_output=True, text=True)
    if r.returncode != 0 and "Operation not permitted" in r.stderr:
        pytest.skip("no user namespaces here")
    assert str(base / "mnt") in r.stdout, r.stdout + r.stderr


# --- bugs 6 and 7 -------------------------------------------------------------------------------

def test_b6_a_dangling_root_does_not_protect_its_parent(tree):
    os.symlink(tree / "nowhere", tree / "dangling")
    pset = paths.ProtectedSet([str(tree / "dangling")], [])
    assert pset.relation(str(tree / "pub")) != paths.INSIDE


def test_b7_a_planted_gitdir_cannot_name_the_spool_or_the_project(tree):
    git_repo(tree / "outer")
    (tree / "outer" / "phi").mkdir()
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text().replace('roots = ["', f'roots = ["{tree}/outer/phi", "'))
    shutil.rmtree(tree / "outer" / ".git")
    (tree / "outer" / ".git").write_text(f"gitdir: {tree}/repo\n")
    cfg = config.load(str(tree / "repo"))
    assert str(tree / "repo") not in cfg.derived_roots
