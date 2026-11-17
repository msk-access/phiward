"""One path identity model. Each step's red tests.

Step 1: the pattern syntax is `*` only, with ASCII literal parts, so every back-end
(Python matcher, Seatbelt regex, Python text regex, glob walk) agrees by construction.
"""

import re
import subprocess
import sys

import pytest

from phiward import config, pathmatch

macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")


# --- step 1: the pattern syntax ------------------------------------------------------------

@pytest.mark.parametrize("pat", [
    "/a/FAKE-PT-?", "/a/[0-9]*", "/a/[!x]b", "/a/[b-a]", "/a/[*-^]", "/a/*[![.].",
    "/a/café/*", "/a/x́*", "/a/K*", "/a/x\ty/*", "/a/x]y*",
])
def test_step1_only_star_and_ascii_are_accepted(pat):
    why = pathmatch.problem(pat)
    assert why, pat


@pytest.mark.parametrize("pat", ["/a/*/panel", "/a/FAKE-PT-*", "/a/*.bam", "/a/b-c_d.e/*", "/a/*x*"])
def test_step1_star_patterns_are_accepted(pat):
    assert pathmatch.problem(pat) is None


def test_step1_a_config_with_a_class_is_a_problem_that_suggests_a_rewrite(tree):
    import os
    from pathlib import Path
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text().replace("/runs/*/panel", "/runs/[0-9]*/panel"))
    cfg = config.load(str(tree / "repo"))
    assert cfg.problem and "*" in cfg.problem and "root" in cfg.problem


def _names():
    """Random paths of 1 to 3 non-empty parts."""
    import random
    rnd = random.Random(1234)
    alpha = "abcXYZ019.-_*"
    for _ in range(400):
        yield "/" + "/".join("".join(rnd.choice(alpha) for _ in range(rnd.randint(1, 6)))
                             for _ in range(rnd.randint(1, 3)))


def test_step1_every_back_end_agrees_on_random_patterns():
    import random
    from fnmatch import fnmatchcase
    rnd = random.Random(99)
    parts = ["*", "a", "b*", "*c", "a*b", "x.y", "-", "_", "*.*"]
    for _ in range(300):
        pat = "/" + "/".join(rnd.choice(parts) for _ in range(rnd.randint(1, 3)))
        assert pathmatch.problem(pat) is None, pat
        rx = re.compile(pathmatch.regex(pat) + "$")
        for path in _names():
            want = len(path.split("/")) == len(pat.split("/")) and all(
                fnmatchcase(pathmatch.fold(x), pathmatch.fold(y))
                for x, y in zip(path.split("/")[1:], pat.split("/")[1:]))
            assert pathmatch.match_path(pat, path) is want, (pat, path)
            assert bool(rx.match(pathmatch.fold(path) if pathmatch.FOLD_CASE else path)) is want, (pat, path)


# --- step 2: canonical paths and identity (pathid) -----------------------------------------

import os
import unicodedata
from pathlib import Path

from phiward import core, paths, pathid
from phiward.guards import protected_paths


def _spellings(p: Path):
    """Other spellings of the same existing path that the file system accepts."""
    out = {"as written": str(p)}
    if sys.platform == "darwin":
        out["upper case"] = str(p).upper() if str(p).upper() != str(p) else str(p)
        st = os.stat(p)
        out["volfs"] = f"/.vol/{st.st_dev}/{st.st_ino}"
        if str(p).startswith("/private/") or str(p).startswith("/Users/"):
            out["firmlink"] = "/System/Volumes/Data" + str(p)
    out["dot-dot"] = str(p.parent / ".." / p.parent.name / p.name)
    out["double slash"] = str(p).replace("/", "//", 1)
    return out


@pytest.mark.parametrize("kind", ["as written", "upper case", "volfs", "firmlink", "dot-dot",
                                  "double slash"])
def test_step2_every_spelling_of_a_root_is_inside(tree, kind):
    sp = _spellings(tree / "phi")
    if kind not in sp:
        pytest.skip("not on this system")
    pset = paths.ProtectedSet([str(tree / "phi")], [])
    for target in (sp[kind], sp[kind] + "/FAKE-PT-0001.bam"):
        assert pset.relation(target) == paths.INSIDE, target


@pytest.mark.parametrize("kind", ["upper case", "volfs", "firmlink"])
def test_step2_the_hook_refuses_every_spelling_for_file_tools(tree, kind):
    sp = _spellings(tree / "phi")
    if kind not in sp:
        pytest.skip("not on this system")
    cfg = config.load(str(tree / "repo"))
    act = core.Action(kind=core.FILE_READ, cwd=str(tree / "repo"),
                      paths=(sp[kind] + "/FAKE-PT-0001.bam",), tool="Read")
    assert protected_paths.check(act, cfg).verdict == core.DENY


def test_step2_an_nfd_spelling_of_an_accented_root_is_inside(tmp_path):
    root = tmp_path.resolve() / unicodedata.normalize("NFC", "Café-FAKE")
    root.mkdir()
    pset = paths.ProtectedSet([str(root)], [])
    nfd = unicodedata.normalize("NFD", str(root))
    want = paths.INSIDE if sys.platform == "darwin" else None  # Linux: different bytes, different name
    assert pset.relation(nfd + "/x") == want


def test_step2_canon_of_a_missing_path_keeps_the_written_tail(tmp_path):
    base = tmp_path.resolve()
    c = pathid.canon(str(base / "no" / "such" / "file"))
    assert c.endswith("/no/such/file") and pathid.canon(str(base)) in c


# --- step 3: grant checks by canonical spelling ---------------------------------------------------

def _user_cfg(extra):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + extra)


@macos
@pytest.mark.parametrize("which", ["home dot-folder", "root"])  # inside a root may be granted
def test_step3_a_case_twin_of_a_forbidden_place_is_refused(tree, which):
    home = tree / "home"
    (home / ".ssh").mkdir()
    (tree / "phi" / "sub").mkdir(exist_ok=True)
    target = {"home dot-folder": str(home / ".ssh").replace("/.ssh", "/.SSH"),
              "root": str(tree / "PHI"),
              "inside root": str(tree / "Phi" / "sub")}[which]
    _user_cfg(f'[broker]\nwrite_to = ["{target}"]\n')
    assert config.load(str(tree / "repo")).problem, target


def test_step3_write_to_is_stored_in_canonical_spelling(tree):
    out = tree / "pub" / "out"
    out.mkdir(parents=True)
    spelled = str(out).upper() if sys.platform == "darwin" else str(out)
    _user_cfg(f'[broker]\nwrite_to = ["{spelled}"]\n')
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem and cfg.write_to == [pathid.canon(str(out))]


@macos
def test_step3_a_write_to_given_in_another_case_still_matches_the_grant(tree):
    from phiward import run
    out = tree / "pub" / "out"
    out.mkdir(parents=True)
    _user_cfg(f'[broker]\nwrite_to = ["{out}"]\n')
    cfg = config.load(str(tree / "repo"))
    assert run.resolve_grant(str(out).upper(), str(tree / "repo"), cfg) == pathid.canon(str(out))


# --- step 4: sanitizer spellings, non-UTF-8 names, the real gitdir ---------------------------

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")


def test_step4_a_root_written_nfd_is_masked_in_nfc_output(tmp_path, monkeypatch):
    from phiward.sanitize import Sanitizer
    base = tmp_path.resolve()
    nfc = unicodedata.normalize("NFC", "Café-FAKE-ROOT")
    (base / nfc).mkdir()
    cfgf = base / "c.toml"
    nfd_path = unicodedata.normalize("NFD", str(base / nfc))
    cfgf.write_text(f'[protected_paths]\nroots = ["{nfd_path}"]\n')
    monkeypatch.setenv("PHIWARD_CONFIG", str(cfgf))
    monkeypatch.setenv("HOME", str(base))
    cfg = config.load(str(base))
    san = Sanitizer.from_config(cfg, entries=False)
    line = f"error opening {base / nfc}/FAKE-PT-0001.bam"
    assert "Caf" not in san.clean(line), san.clean(line)


@linux
def test_step4_a_non_utf8_entry_name_is_masked(tree):
    from phiward.sanitize import Sanitizer
    raw = os.fsencode(str(tree / "phi")) + b"/FAKE\xffPT0001X.bam"
    with open(raw, "wb") as fh:
        fh.write(b"x\n")
    cfg = config.load(str(tree / "repo"))
    san = Sanitizer.from_config(cfg, entries=True)
    shown = (b"ls: FAKE\xffPT0001X.bam").decode("utf-8", "replace")  # as run.py decodes output
    assert "PT0001X" not in san.clean(shown), san.clean(shown)


def test_step4_the_real_gitdir_behind_a_git_file_is_a_derived_root(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    main = base / "main"
    main.mkdir()
    def git(*a, cwd=main):
        subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True)
    git("init", "-q")
    (main / "f").write_text("x\n")
    git("add", "f")
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "i")
    git("worktree", "add", "-q", str(base / "wt"))
    (base / "wt" / "phi").mkdir()
    cfgf = base / "c.toml"
    cfgf.write_text(f'[protected_paths]\nroots = ["{base}/wt/phi"]\n')
    monkeypatch.setenv("PHIWARD_CONFIG", str(cfgf))
    monkeypatch.setenv("HOME", str(base))
    cfg = config.load(str(base))
    roots = [os.path.realpath(r) for r in cfg.derived_roots]
    assert os.path.realpath(str(main / ".git")) in roots, roots


# --- step 5: file-system behaviours (snapshots, alias mounts, hard links) --------------------

from phiward import fsinfo


@pytest.mark.parametrize("name", [".snapshot", ".snapshots", ".zfs", "~snapshot"])
def test_step5_a_snapshot_folder_above_a_root_is_a_derived_root(tree, name):
    snap = tree / name / "daily-1" / "phi"
    snap.mkdir(parents=True)
    (snap / "FAKE-PT-0001.bam").write_text("SECRET-CONTENT-OLD\n")
    cfg = config.load(str(tree / "repo"))
    assert str(tree / name) in cfg.derived_roots


def test_step5_a_site_snapshot_name_from_the_config(tree):
    (tree / ".weka-snaps" / "s1" / "phi").mkdir(parents=True)
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text().replace("[protected_paths]\n", '[protected_paths]\nsnapshot_names = [".weka-snaps"]\n'))
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem, cfg.problem
    assert str(tree / ".weka-snaps") in cfg.derived_roots


MOUNTINFO = """\
22 1 0:21 / /proc rw - proc proc rw
30 1 8:1 / / rw - ext4 /dev/sda1 rw
40 30 0:50 / /data rw - nfs4 filer:/export rw
41 30 0:51 /projects /mnt/proj rw - nfs4 filer:/export rw
42 30 0:50 /projects/study /home/u/study rw - nfs4 filer:/export rw
43 30 0:52 / /scratch rw - wekafs wekafs0 rw
"""


def test_step5_alias_mounts_of_a_root_are_found():
    got = sorted(fsinfo.alias_paths("/data/projects/study/phi", MOUNTINFO))
    assert got == ["/home/u/study/phi", "/mnt/proj/study/phi"], got
    assert fsinfo.alias_paths("/scratch/phi", MOUNTINFO) == []


def test_step5_mount_type_is_found():
    assert fsinfo.mount_of("/scratch/x/y", MOUNTINFO)["fstype"] == "wekafs"
    assert fsinfo.mount_of("/data/a", MOUNTINFO)["fstype"] == "nfs4"


def test_step5_hard_linked_protected_files_are_counted(tree):
    os.link(tree / "phi" / "FAKE-PT-0001.bam", tree / "pub" / "other-name")
    assert fsinfo.hardlinked_count([str(tree / "phi")], 1000) == 1


def test_step5_doctor_warns_about_hard_links(tree):
    os.link(tree / "phi" / "FAKE-PT-0001.bam", tree / "pub" / "other-name")
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    r = subprocess.run([sys.executable, "-m", "phiward", "doctor"], cwd=str(tree / "repo"),
                       capture_output=True, text=True, env=env)
    assert "hard link" in r.stdout and "WARNING" in r.stdout
