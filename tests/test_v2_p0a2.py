"""Fixes to the path identity model, second set.

Holes: 1 `/.vol` + `..` passes the hook; 2 a planted nearer `.git` hides the real gitdir;
3 a bind mount of a folder inside a root is not found. Bugs 4-12 of the same set.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import config, core, fsinfo, pathid, pathmatch, paths
from phiward.guards import protected_paths
from helpers import git_repo

SRC = str(Path(__file__).resolve().parents[1] / "src")
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")


def _cfg_text(extra=""):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + extra)


# --- hole 1: `..` is resolved by the file system, not by text ---------------------------------

@macos
def test_hole1_volfs_with_dotdot_is_inside(tree):
    (tree / "sibling").mkdir()
    st = os.stat(tree / "sibling")
    spelled = f"/.vol/{st.st_dev}/{st.st_ino}/../phi/FAKE-PT-0001.bam"
    with open(spelled) as fh:  # the kernel resolves it to the protected file
        assert "SECRET-CONTENT" in fh.read()
    pset = paths.ProtectedSet([str(tree / "phi")], [])
    assert pset.relation(spelled) == paths.INSIDE
    cfg = config.load(str(tree / "repo"))
    act = core.Action(kind=core.FILE_READ, cwd=str(tree / "repo"), paths=(spelled,), tool="Read")
    assert protected_paths.check(act, cfg).verdict == core.DENY


def test_hole1_link_then_dotdot_follows_the_kernel(tree):
    # repo/runlink -> runs/run1/public; runlink/../panel is the protected pattern match
    pset = paths.ProtectedSet([], [str(tree / "runs" / "*" / "panel")])
    assert pset.relation(str(tree / "repo" / "runlink" / ".." / "panel" / "x.maf")) == paths.INSIDE


def test_hole1_inside_by_identity(tree):
    pset = paths.ProtectedSet([str(tree / "phi")], [])
    # a spelling no string rule knows: a hard-to-spell alias of the same folder (a bind on Linux,
    # a /.vol path on macOS) is still inside, because the walk meets the root's (dev, ino)
    assert pset.inside_by_identity(str(tree / "phi" / "sub" / "FAKE-PT-0002.bam"))
    assert not pset.inside_by_identity(str(tree / "pub"))


def test_hole1_canon_never_opens_a_device():
    assert pathid.canon("/dev/tty") == "/dev/tty"  # looked up in /dev, not opened


# --- hole 2: pinned derived roots -------------------------------------------------------------

def test_hole2_a_planted_nearer_git_does_not_remove_a_pinned_root(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    git_repo(base / "repo")
    (base / "repo" / "data" / "phi").mkdir(parents=True)
    cfgf = base / "home" / ".config" / "phiward" / "config.toml"
    cfgf.parent.mkdir(parents=True)
    cfgf.write_text(f'[protected_paths]\nroots = ["{base}/repo/data/phi"]\n')
    monkeypatch.setenv("HOME", str(base / "home"))
    monkeypatch.delenv("PHIWARD_CONFIG", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    from phiward import pin
    assert pin.write_pins(config.load(str(base))) == 0
    (base / "repo" / "data" / ".git").write_text("gitdir: /nonexistent\n")  # planted by the agent
    cfg = config.load(str(base))
    assert str(base / "repo" / ".git") in cfg.derived_roots, cfg.derived_roots
    assert pin.pins_path() in config.guard_files()


def test_hole2_pin_is_an_operator_only_command(tree):
    act = core.Action(kind=core.SHELL, cwd=str(tree / "repo"), command="phiward pin")
    assert protected_paths.check(act, config.load(str(tree / "repo"))).verdict == core.DENY


@pytest.mark.parametrize("target", ["/", "{home}", "{tree}", "\x00"])
def test_bug5_a_bad_gitdir_is_refused_and_never_crashes(tree, target):
    git_repo(tree / "outer")
    (tree / "outer" / "phi").mkdir()
    (tree / "outer" / "phi" / "x").write_text("x\n")
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text().replace('roots = ["', f'roots = ["{tree}/outer/phi", "'))
    shutil.rmtree(tree / "outer" / ".git")
    (tree / "outer" / ".git").write_text("gitdir: " + target.format(home=tree / "home", tree=tree) + "\n")
    cfg = config.load(str(tree / "repo"))  # never raises
    home = str(tree / "home")
    assert all(d not in ("/", home, str(tree)) for d in cfg.derived_roots), cfg.derived_roots


# --- hole 3 and bug 4: alias mounts ------------------------------------------------------------

MI = """\
30 1 8:1 / / rw - ext4 /dev/sda1 rw
40 30 0:50 / /data rw - nfs4 filer:/export rw
44 30 0:50 /proj/phi/sub /mnt/sub2 rw - nfs4 filer:/export rw
45 30 0:60 / /dev/shm rw - tmpfs tmpfs rw
46 30 0:61 / /run rw - tmpfs tmpfs rw
47 30 0:70 / /merged rw - overlay overlay rw,lowerdir=/data/proj/phi:/x,upperdir=/u,workdir=/w
"""


def test_hole3_a_mount_of_a_folder_inside_the_root_is_an_alias():
    assert "/mnt/sub2" in fsinfo.alias_paths("/data/proj/phi", MI)


def test_bug4_generic_sources_are_not_aliases():
    assert fsinfo.alias_paths("/dev/shm/phi", MI) == []


def test_bug4_an_overlay_lower_folder_is_an_alias():
    assert "/merged" in fsinfo.alias_paths("/data/proj/phi", MI)


@linux
def test_hole3_a_real_bind_mount_inside_a_root_is_found(tmp_path):
    if not shutil.which("unshare"):
        pytest.skip("no unshare")
    base = tmp_path.resolve()
    (base / "phi" / "sub").mkdir(parents=True)
    (base / "mnt").mkdir()
    code = (f"import sys; sys.path.insert(0, {SRC!r}); from phiward import fsinfo; "
            f"print(fsinfo.alias_paths({str(base / 'phi')!r}))")
    r = subprocess.run(["unshare", "-rm", "sh", "-c",
                        f"mount --bind {base}/phi/sub {base}/mnt && {sys.executable} -c \"{code}\""],
                       capture_output=True, text=True)
    if r.returncode != 0 and "Operation not permitted" in r.stderr:
        pytest.skip("no user namespaces here")
    assert str(base / "mnt") in r.stdout, r.stdout + r.stderr


# --- bug 6, 7: real paths, patterns, .snap ------------------------------------------------------

def test_bug6_snapshots_are_found_for_a_root_written_through_a_link(tree):
    real = tree / "fs" / "proj" / "phi2"
    real.mkdir(parents=True)
    (tree / "fs" / ".snapshots" / "s1").mkdir(parents=True)
    os.symlink(real, tree / "linkphi")
    _cfg_text("")
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text().replace('roots = ["', f'roots = ["{tree}/linkphi", "'))
    cfg = config.load(str(tree / "repo"))
    assert str(tree / "fs" / ".snapshots") in cfg.derived_roots


def test_bug6_snapshots_are_found_above_a_pattern(tree):
    (tree / ".snap" / "s1").mkdir(parents=True)  # CephFS spelling, above runs/*/panel
    cfg = config.load(str(tree / "repo"))
    assert str(tree / ".snap") in cfg.derived_roots


# --- bug 9, 10, 12 -----------------------------------------------------------------------------

@pytest.mark.parametrize("pat", ["/a/*/../b", "/a/./b*", "/a//b*", "/a/b/.."])
def test_bug9_dot_and_empty_parts_are_refused(pat):
    assert pathmatch.problem(pat)


@macos
def test_bug12_folding_follows_the_volume():
    assert pathid.case_sensitive("/") is False  # the default APFS volume


def test_bug12_doctor_warns_when_a_root_is_not_written_canonically(tree):
    if sys.platform != "darwin":
        pytest.skip("case spellings: macOS")
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text().replace(f'"{tree}/phi"', f'"{str(tree / "phi").upper()}"'))
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([sys.executable, "-m", "phiward", "doctor"], cwd=str(tree / "repo"),
                       capture_output=True, text=True, env=env)
    assert "spelling" in r.stdout and "WARNING" in r.stdout, r.stdout
