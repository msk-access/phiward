"""`phiward copy`: each local path is resolved once, and the checks and the programs the copy runs
(rsync, cp, mkdir, the pull's tar) get that same string. A local path with a `..` part, or one that
starts with `~`, is refused: give the full path. Made-up trees only (conftest `tree`)."""

import io
import os

import pytest

from phiward import copying
from helpers import CONFINE_WHY


def _copy(tree, *args, cwd=None):
    out = io.StringIO()
    code = copying.execute(list(args), str(cwd or tree / "repo"), dict(os.environ), out)
    return code, out.getvalue()


def _linked(tree):
    """T/pub/lnk -> T/else/a/b: `lnk/../..` is T/pub as text, T/else for the kernel."""
    (tree / "else" / "a" / "b").mkdir(parents=True)
    os.symlink(tree / "else" / "a" / "b", tree / "pub" / "lnk")


def _nothing_under(folder):
    return not folder.exists() or not any(p.is_file() for p in folder.rglob("*"))


def test_a_destination_through_a_link_and_dotdot_is_refused(tree):
    _linked(tree)
    src = tree / "phi" / "FAKE-PT-0001.bam"
    code, out = _copy(tree, str(src), str(tree / "pub" / "lnk" / ".." / ".." / "phi" / "x.bam"))
    assert code == 2 and "`..`" in out, out
    assert _nothing_under(tree / "else") and not (tree / "phi" / "x.bam").exists()


@pytest.mark.parametrize("how", ["dst", "src", "pull"])
def test_a_local_path_with_dotdot_is_refused(tree, how):
    phi = tree / "phi"
    if how == "dst":
        args = [str(phi / "FAKE-PT-0001.bam"), str(phi / "sub" / ".." / "x.bam")]
    elif how == "src":
        args = [str(phi / "sub" / ".." / "FAKE-PT-0001.bam"), str(phi / "copies") + "/"]
    else:
        args = ["hpc-test:/work/me/res", str(phi / "sub" / ".." / "pulled")]
    code, out = _copy(tree, *args)
    assert code == 2 and "`..`" in out, out
    assert not (phi / "x.bam").exists() and not (phi / "copies").exists()
    assert not (phi / "pulled").exists()


def test_a_destination_starting_with_tilde_is_refused(tree):
    # a folder named `~` in the working folder, leading elsewhere: the copy must not follow it
    (tree / "repo" / "~").mkdir()
    (tree / "else").mkdir()
    os.symlink(tree / "else", tree / "repo" / "~" / "phi")
    code, out = _copy(tree, str(tree / "phi" / "FAKE-PT-0001.bam"), "~/phi/")
    assert code == 2 and "`~`" in out, out
    assert _nothing_under(tree / "else")


def test_a_source_starting_with_tilde_is_refused(tree):
    proj = tree / "repo" / "~" / "proj" / ".Claude"
    proj.mkdir(parents=True)
    (proj / "settings.json").write_text("{}")
    (tree / "phi" / "copies").mkdir()
    code, out = _copy(tree, "~/proj/", str(tree / "phi" / "copies") + "/")
    assert code == 2 and "`~`" in out, out
    assert _nothing_under(tree / "phi" / "copies")


@pytest.mark.skipif(CONFINE_WHY is not None, reason="no confinement backend")
@pytest.mark.parametrize("spec", ["proj/", "proj/.", "."])
def test_a_relative_source_keeps_its_contents_marker(tree, spec):
    proj = tree / "repo" / "proj"
    proj.mkdir()
    (proj / "result.txt").write_text("made-up result\n")
    dst = tree / "phi" / "copies"
    cwd = proj if spec == "." else tree / "repo"
    code, out = _copy(tree, spec, str(dst) + "/", cwd=cwd)
    assert code == 0, out
    # the folder's contents, not the folder: as rsync reads `src/`, `src/.` and `.`
    assert (dst / "result.txt").read_text() == "made-up result\n"
    assert not (dst / "proj").exists()


@pytest.mark.skipif(CONFINE_WHY is not None, reason="no confinement backend")
def test_a_relative_path_without_dotdot_still_copies(tree):
    (tree / "repo" / "notes.txt").write_text("made-up note\n")
    code, out = _copy(tree, "notes.txt", str(tree / "phi" / "copies") + "/")
    assert code == 0, out
    assert (tree / "phi" / "copies" / "notes.txt").read_text() == "made-up note\n"
