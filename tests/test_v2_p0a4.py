"""The generic hook rule, kernel-layer coverage by identity, and the denial-of-service and
over-blocking fixes to the path identity model."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import config, core, fsinfo, paths, pin
from phiward.guards import protected_paths

SRC = str(Path(__file__).resolve().parents[1] / "src")
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")


def _verdict(tree, kind, path):
    cfg = config.load(str(tree / "repo"))
    act = core.Action(kind=kind, cwd=str(tree / "repo"), paths=(path,), tool="Read")
    return protected_paths.check(act, cfg).verdict


# --- the generic hook rule ------------------------------------------------------------------------

@macos
@pytest.mark.parametrize("prefix", ["/.nofollow", "/.resolve/1"])
def test_g1_a_prefix_the_walk_cannot_find_but_the_kernel_resolves_is_inside(tree, prefix):
    spelled = prefix + str(tree / "phi" / "FAKE-PT-0001.bam")
    assert os.path.exists(spelled)  # the kernel resolves it
    assert _verdict(tree, core.FILE_READ, spelled) == core.DENY


def test_g1_a_really_missing_path_is_still_a_normal_answer(tree):
    assert paths.ProtectedSet([str(tree / "phi")], []).relation(str(tree / "pub" / "nope")) is None


# --- procfs (findings 2, 5) -------------------------------------------------------------------

@linux
@pytest.mark.parametrize("path", ["/proc/self/status", "/etc/mtab", "/proc/mounts"])
def test_g5_ordinary_proc_paths_are_not_blocked(tree, path):
    assert paths.ProtectedSet([str(tree / "phi")], []).relation(path) is None


@linux
@pytest.mark.parametrize("cmd", ["echo hi > /dev/stderr", "tee /dev/stderr < /dev/null",
                                 "ls /proc/self/fd"])
def test_g5_ordinary_proc_use_in_a_confined_shell_is_allowed(tree, cmd):
    cfg = config.load(str(tree / "repo"))
    act = core.Action(kind=core.SHELL, cwd=str(tree / "repo"), command=cmd, confined=True)
    assert protected_paths.check(act, cfg).verdict != core.DENY


@linux
def test_g5_a_magic_link_is_judged_by_where_it_really_leads(tree):
    pset = paths.ProtectedSet([str(tree / "phi")], [])
    child = subprocess.Popen(["sleep", "30"])
    try:
        other = f"/proc/{child.pid}/root"
        assert pset.relation(other + str(tree / "phi" / "FAKE-PT-0001.bam")) == paths.INSIDE
        assert pset.relation(other + "/etc/hostname") is None
    finally:
        child.kill()
    # the hook's own /proc/self is not the agent tool's: fail closed
    assert pset.relation("/proc/self/root/etc/hostname") == paths.INSIDE


@linux
def test_g2_procfs_at_a_second_path_is_recognised(tmp_path):
    if not shutil.which("unshare"):
        pytest.skip("no unshare")
    base = tmp_path.resolve()
    (base / "hostproc").mkdir()
    (base / "phi").mkdir()
    code = (f"import sys; sys.path.insert(0, {SRC!r}); from phiward import paths; "
            f"print(paths.ProtectedSet([{str(base / 'phi')!r}], []).relation("
            f"{str(base / 'hostproc')!r} + '/self/root/etc/hostname'))")
    r = subprocess.run(["unshare", "-rm", "sh", "-c",
                        f"mount --rbind /proc {base}/hostproc && {sys.executable} -c \"{code}\""],
                       capture_output=True, text=True)
    if r.returncode != 0 and "Operation not permitted" in r.stderr:
        pytest.skip("no user namespaces here")
    assert "inside" in r.stdout, r.stdout + r.stderr


# --- overlays and aliases by identity (findings 3, 6, 7) --------------------------------------

def test_g7_split_follows_the_kernel_escaping():
    assert fsinfo._split_unescaped("/a\\134:b:/c", ":") == ["/a\\134:b", "/c"]


def test_g6_an_unknown_overlay_protects_its_mount_point_not_everything(tree, monkeypatch):
    mi = "30 1 8:1 / / rw - ext4 /dev/sda1 rw\n61 30 0:71 / /m rw - overlay overlay rw,lowerdir=rel,upperdir=/u,workdir=/w\n"
    monkeypatch.setattr(fsinfo, "read_mountinfo", lambda: mi)
    monkeypatch.setattr(sys, "platform", "linux")
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem and "/m" in cfg.derived_roots


@linux
def test_g3_an_overlay_whose_lower_links_to_the_root_is_an_alias(tmp_path):
    if not shutil.which("unshare"):
        pytest.skip("no unshare")
    base = tmp_path.resolve()
    for d in ("phi", "u", "w", "m"):
        (base / d).mkdir()
    os.symlink(base / "phi", base / "l")
    code = (f"import sys; sys.path.insert(0, {SRC!r}); from phiward import fsinfo; "
            f"print(fsinfo.alias_paths({str(base / 'phi')!r}))")
    r = subprocess.run(["unshare", "-rm", "sh", "-c",
                        f"mount -t overlay overlay -o lowerdir={base}/l,upperdir={base}/u,"
                        f"workdir={base}/w {base}/m && {sys.executable} -c \"{code}\""],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("no overlay in a user namespace here: " + r.stderr.strip()[-80:])
    assert str(base / "m") in r.stdout, r.stdout + r.stderr


# --- git folders and pins (findings 4, 8, 9, 11) ----------------------------------------------

def _cfg_root(tree, root):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text().replace('roots = ["', f'roots = ["{root}", "'))


@pytest.mark.parametrize("how", ["symlink", "gitfile"])
@pytest.mark.parametrize("target", ["/usr", "{tree}/repo", "{tree}/home"])
def test_g4_a_planted_git_cannot_protect_a_non_git_folder(tree, how, target):
    (tree / "outer" / "phi").mkdir(parents=True)
    _cfg_root(tree, tree / "outer" / "phi")
    t = target.format(tree=tree)
    if how == "symlink":
        os.symlink(t, tree / "outer" / ".git")
    else:
        (tree / "outer" / ".git").write_text(f"gitdir: {t}\n")
    cfg = config.load(str(tree / "repo"))
    assert all(os.path.realpath(d) != os.path.realpath(t) for d in cfg.derived_roots), cfg.derived_roots


def test_g4_pin_can_drop_an_entry(tree, monkeypatch):
    cfg = config.load(str(tree / "repo"))
    pin.write_pins(cfg)
    pin.write_pins(cfg, add=["/usr/local/fake-planted"])
    assert "/usr/local/fake-planted" in pin.read_pins()
    pin.write_pins(cfg, drop=["/usr/local/fake-planted"])
    assert "/usr/local/fake-planted" not in pin.read_pins()


def test_g9_doctor_reports_pins_that_are_no_longer_found(tree):
    cfg = config.load(str(tree / "repo"))
    pin.write_pins(cfg, add=[str(tree / "pub")])
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([sys.executable, "-m", "phiward", "doctor"], cwd=str(tree / "repo"),
                       capture_output=True, text=True, env=env)
    assert "pinned but not found" in r.stdout, r.stdout


def test_g11_the_derived_set_does_not_depend_on_the_working_folder(tree):
    a = config.load(str(tree / "repo")).derived_roots
    b = config.load(str(tree / "pub")).derived_roots
    assert sorted(a) == sorted(b)
