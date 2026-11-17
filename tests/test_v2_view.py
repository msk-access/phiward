"""On Linux the session sees a snapshot view. Every folder
above a hidden path is an empty tmpfs with the entries of the start bound back, except the
hidden ones; a hidden path is never mounted over. So a protected path renamed or replaced on the
host, or a match or credential made after the start, is not in the view."""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from phiward import wholetool
from helpers import CONFINE_WHY

SRC = str(Path(__file__).resolve().parents[1] / "src")
linux_confined = pytest.mark.skipif(not sys.platform.startswith("linux") or CONFINE_WHY is not None,
                                    reason=f"Linux confinement: {CONFINE_WHY}")


def ops_of(literal, patterns=(), replaced=()):
    ops, split, _whole = wholetool.hidden_view(literal, patterns, replaced)
    return ops, split, {o[-1] for o in ops if o[0] == "bind"}, {o[1] for o in ops if o[0] == "tmpfs"}


def test_a_hidden_path_is_left_out_and_its_neighbours_are_bound(tree):
    t = str(tree)
    ops, split, binds, tmpfs = ops_of([t + "/phi"])
    assert t + "/phi" not in binds and not any(b.startswith(t + "/phi/") for b in binds)
    assert t + "/repo" in binds and t + "/pub" in binds
    assert t in tmpfs and "/" in split
    # never a mount on the hidden path itself
    assert all(o[-1] != t + "/phi" for o in ops)


def test_links_are_made_again_as_links(tree):
    t = str(tree)
    os.symlink(t + "/phi", t + "/to_phi")
    ops, *_ = ops_of([t + "/phi"])
    assert ("symlink", t + "/phi", t + "/to_phi") in ops


def test_every_folder_where_a_pattern_match_could_be_made_is_split(tree):
    t = str(tree)
    ops, split, binds, tmpfs = ops_of([], [t + "/runs/*/panel"])
    assert t + "/runs" in split and t + "/runs/run1" in split and t + "/runs/run2" in split
    assert t + "/runs/run1/public" in binds
    assert not any("/panel" in b for b in binds)


def test_a_missing_credential_splits_its_nearest_folder(tree):
    t = str(tree)
    ops, split, binds, _ = ops_of([t + "/home/.aws/credentials"])
    assert t + "/home" in split and t + "/home/.aws" not in binds


def test_paths_under_a_replaced_folder_are_left_to_the_caller(tree):
    t = str(tree)
    ops, split, binds, _ = ops_of([t + "/phi"], replaced=[t])
    assert t not in split and not any(b.startswith(t) for b in binds)


def test_too_many_mounts_are_refused(tree):
    with pytest.raises(wholetool.LaunchError):
        wholetool.hidden_view([str(tree / "phi")], [], (), limit=3)


def _crowded(tree, n=4000, holder=""):
    """A folder of `n` entries (bwrap takes at most 9000 arguments), with a protected folder
    `phi2` in it, or in its subfolder `holder`."""
    data = tree / "data"
    data.mkdir()
    for i in range(n):
        (data / f"s{i:05d}").mkdir()
    (data / holder / "phi2").mkdir(parents=True)
    (data / holder / "phi2" / "FAKE-PT-0007.bam").write_text("SECRET-CONTENT-0007\n")
    return data


def test_a_protected_folder_below_many_entries_fits_the_view(tree):
    data = _crowded(tree, holder="study")
    ops, split, whole = wholetool.hidden_view([str(data / "study" / "phi2")], [], ())
    cost = sum(wholetool._OP_ARGS[o[0]] for o in ops)
    assert cost <= wholetool.VIEW_ARGS, cost
    assert str(data) in whole  # shown whole: the crowded folder (and the test folder's own
    # parent when a full run has made thousands of test folders there)
    assert ("tmpfs", str(data / "study")) in ops  # the root's own folder is rebuilt
    assert not any(o[-1] == str(data / "study" / "phi2") for o in ops)
    assert str(tree) not in whole  # the folders that fit are still rebuilt


def test_a_protected_folder_among_many_entries_is_refused_not_shown(tree):
    # shown whole, a folder lists its masked entries by name, and a root's name may be a
    # person's (pathmatch: such a name is given as a root)
    data = _crowded(tree)
    with pytest.raises(wholetool.LaunchError, match="protect that folder as a root"):
        wholetool.hidden_view([str(data / "phi2")], [], ())


def test_a_crowded_folder_with_pattern_matches_is_refused_not_shown(tree):
    # shown whole, a folder lists its masked entries by name: a wildcard match's name may be a
    # person's, so such a folder is never shown whole
    data = _crowded(tree)
    for i in range(3):
        (data / f"phi_Fake Person {i}").mkdir()
    with pytest.raises(wholetool.LaunchError, match="protect that folder as a root"):
        wholetool.hidden_view([], [str(data) + "/phi_*"], ())


@linux_confined
def test_launch_starts_next_to_thousands_of_entries_and_hides_the_root(tree):
    if str(tree).startswith("/tmp/"):
        pytest.skip("the tree is under /tmp, which the session replaces; run with --basetemp")
    data = _crowded(tree, holder="study")
    cfg = Path(os.environ["PHIWARD_CONFIG"])
    cfg.write_text(cfg.read_text().replace(f'roots = ["{tree}/phi"]',
                                           f'roots = ["{tree}/phi", "{data}/study/phi2"]'))
    code = (f"import os\ntry:\n    print('READ', open({str(data / 'study' / 'phi2' / 'FAKE-PT-0007.bam')!r}).read())\n"
            "except OSError as e:\n    print('REFUSED', type(e).__name__)\n"
            f"print('SIBLINGS', len(os.listdir({str(data)!r})))\n"
            f"print('STUDY', os.listdir({str(data / 'study')!r}))\n")
    r = subprocess.run([sys.executable, "-m", "phiward", "launch", "--", sys.executable, "-c", code],
                       cwd=str(tree / "repo"), env=dict(os.environ, PYTHONPATH=SRC),
                       capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    assert "REFUSED" in r.stdout and "SECRET" not in r.stdout, (r.stdout, r.stderr)
    assert "SIBLINGS 4001" in r.stdout, r.stdout  # the crowded folder, shown whole
    assert "STUDY []" in r.stdout, r.stdout  # the root's own folder is rebuilt: no name
    assert "shown whole" in r.stderr, r.stderr


# --- Linux, end to end: the host changes things while the session runs --------------------------

@linux_confined
def test_changes_on_the_host_after_the_start_stay_out_of_the_view(tree):
    if str(tree).startswith("/tmp/"):
        pytest.skip("the tree is under /tmp, which the session replaces; run with --basetemp")
    t = tree
    code = (
        "import os, time, glob\n"
        f"open({str(t / 'repo' / 'ready')!r}, 'w').close()\n"
        f"while not os.path.exists({str(t / 'repo' / 'go')!r}): time.sleep(0.05)\n"
        "seen = []\n"
        f"for p in glob.glob({str(t)!r} + '/**', recursive=True) + "
        f"glob.glob({str(t / 'home')!r} + '/.*/**', recursive=True):\n"
        "    try:\n"
        "        if os.path.isfile(p): seen.append(open(p).read())\n"
        "    except OSError: pass\n"
        "print('READ', ' '.join(seen).count('SECRET'))\n"
        f"print('NAMES', sorted(os.listdir({str(t)!r})))\n"
    )
    env = dict(os.environ, PYTHONPATH=SRC)
    p = subprocess.Popen([sys.executable, "-m", "phiward", "launch", "--", sys.executable, "-c", code],
                         cwd=str(t / "repo"), env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True)
    for _ in range(400):
        if (t / "repo" / "ready").exists():
            break
        time.sleep(0.05)
    assert (t / "repo" / "ready").exists(), p.communicate(timeout=30)[0]
    # B1: the root renamed and replaced; B2: a new pattern match and a new credential
    os.rename(t / "phi", t / "phi-old")
    (t / "phi").mkdir()
    (t / "phi" / "FAKE-PT-0009.bam").write_text("SECRET-CONTENT-0009\n")
    (t / "runs" / "run3" / "panel").mkdir(parents=True)
    (t / "runs" / "run3" / "panel" / "y.maf").write_text("SECRET-CONTENT-0010\n")
    (t / "home" / ".ssh").mkdir(exist_ok=True)
    (t / "home" / ".ssh" / "id_new").write_text("SECRET-KEY-0011\n")
    (t / "repo" / "go").write_text("")
    out = p.communicate(timeout=60)[0]
    assert "READ 0" in out, out
    assert "phi-old" not in out and "'phi'" not in out, out


# --- more view fixes ------------------------------------------------------------------------------

def test_a_pattern_through_a_linked_folder_hides_the_real_matches(tree):
    t = str(tree)
    os.symlink(t + "/runs", t + "/lnk")
    ops, split, binds, _ = ops_of([], [t + "/lnk/*/panel"])
    assert t + "/runs/run1" in split and not any("/panel" in b for b in binds), binds


def test_a_hidden_name_in_another_case_is_left_out(tree):
    t = str(tree)
    ops, split, binds, _ = ops_of([t + "/PHI"])
    assert t + "/phi" not in binds and all(o[-1] != t + "/phi" for o in ops)


@pytest.mark.skipif(os.geteuid() == 0, reason="root lists any folder")
def test_a_folder_that_cannot_be_listed_is_bound_whole_and_masked(tree):
    t = str(tree)
    grp = tree / "group"
    (grp / "phi").mkdir(parents=True)
    (grp / "work").mkdir()
    os.chmod(grp, 0o311)
    try:
        ops, split, binds, tmpfs = ops_of([t + "/group/phi"])
    finally:
        os.chmod(grp, 0o755)
    assert ("bind", t + "/group") in ops and ("mask", t + "/group/phi") in ops
    assert t + "/group" not in tmpfs


def test_kerberos_caches_by_name_in_var_tmp(tmp_path):
    ops, split, _whole = wholetool.hidden_view([], ["/var/tmp/krb5cc*"])
    assert os.path.realpath("/var/tmp") in split
    assert not any(o[-1].startswith("/var/tmp/krb5cc") for o in ops if o[0] != "tmpfs")


@pytest.mark.skipif(os.geteuid() == 0, reason="root lists any folder")
def test_a_pattern_over_a_folder_that_cannot_be_listed_is_refused(tree):
    grp = tree / "grp"
    (grp / "run1" / "panel").mkdir(parents=True)
    os.chmod(grp, 0o311)
    try:
        with pytest.raises(wholetool.LaunchError):
            wholetool.hidden_view([], [str(grp) + "/*/panel"])
        # the Kerberos cache names are skipped there, not refused
        wholetool.hidden_view([], [], soft_patterns=[str(grp) + "/krb5cc*"])
    finally:
        os.chmod(grp, 0o755)


def test_a_protected_root_is_never_skipped(tree, monkeypatch):
    # unreadable_to_us applies only to the credential files the caller names in may_skip
    monkeypatch.setattr(os, "access", lambda p, m: False)
    t = str(tree)
    ops, split, binds, _ = ops_of([t + "/phi"])
    assert t + "/phi" not in binds and t in split


def test_a_token_at_the_home_folder_does_not_hide_the_home(tree):
    home = str(tree / "home")
    (tree / "home" / "hpc").write_text("k")
    out = wholetool._token_paths(home + "/%h", home)
    assert home not in out and home + "/hpc" in out
