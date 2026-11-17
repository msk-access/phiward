"""Round 13: one definition of the standard library's own packages folder (`_own_packages`: the
names on disk, real folders by identity), which the walk (`_below`), what a root covers
(`_covers`), the tree line (`_aside`), install's compile and the step all follow; choosing the
roots takes no identity of its own. Made-up trees only."""

import os
import re
import subprocess

import pytest

from phiward import selfcheck
from helpers import write_file


CFG = "home = /x/bin\ninclude-system-site-packages = false\n"


def _ignores_case(path):
    return os.path.isdir(os.path.join(os.path.dirname(str(path)),
                                      os.path.basename(str(path)).swapcase()))


def _layout(tree, kind):
    std = tree / kind / "std"
    write_file(std / "os.py")
    out = tree / kind / "out"
    write_file(out / "x.py")
    if kind == "real":
        write_file(std / "site-packages" / "sub" / "a.py")
    elif kind == "link_and_dist":
        os.symlink(out, std / "site-packages")
        write_file(std / "dist-packages" / "y.py")
    elif kind == "link_only":
        os.symlink(out, std / "site-packages")
    elif kind == "link_inside":
        write_file(std / "inner" / "z.py")
        os.symlink(std / "inner", std / "site-packages")
    elif kind == "other_case":
        write_file(std / "Site-Packages" / "w.py")
    elif kind == "file_and_broken":
        write_file(std / "dist-packages")
        os.symlink(tree / kind / "nowhere", std / "site-packages")
    return std, out


LAYOUTS = ["real", "link_and_dist", "link_only", "link_inside", "other_case", "file_and_broken"]


@pytest.mark.parametrize("kind", LAYOUTS)
def test_the_walk_what_a_root_covers_and_the_step_agree(tree, kind):
    std, out = _layout(tree, kind)
    s = str(std)
    below = list(selfcheck._below(s, s))
    reached = {os.path.realpath(p) for p in below if os.path.isdir(p) and not os.path.islink(p)}
    reached.add(os.path.realpath(s))
    folders = [out] + [os.path.join(h, d) for h, ds, _n in os.walk(s) for d in ds
                       if not os.path.islink(os.path.join(h, d))] + [s]
    for p in folders:
        assert selfcheck._covers(s, str(p), s) == (os.path.realpath(p) in reached), (kind, p)
    # the step's find selects what the walk judges (links are skipped by both)
    step = selfcheck._tree_step(s, selfcheck._aside(s, s))
    prune = re.search(r"find \. (.*?)! -type l", step).group(1)
    found = subprocess.run(["sh", "-c", f"cd '{s}' && find . {prune}! -type l -print"],
                           capture_output=True, text=True, check=True).stdout.split()
    want = {os.path.relpath(p, s) for p in below if not os.path.islink(p)}
    assert {f[2:] for f in found if f != "."} == want, kind


def test_a_differently_cased_packages_folder_is_walked_not_left_out(tree):
    std, _out = _layout(tree, "other_case")
    s = str(std)
    assert not selfcheck._aside(s, s)
    assert selfcheck._covers(s, str(std / "Site-Packages"), s)


def test_a_venv_in_the_packages_folder_through_another_case_is_walked(tree, home):
    std = home / "base" / "lib" / "python3.12"
    write_file(std / "os.py")
    venv = std / "site-packages" / "vx"
    write_file(venv / "bin" / "python", mode=0o755, text="#!fake\n")
    (venv / "pyvenv.cfg").write_text(CFG)
    write_file(venv / "lib" / "python3.12" / "site-packages" / "evil.py", mode=0o666)
    if not _ignores_case(std / "site-packages"):
        pytest.skip("this disk tells the cases apart")
    for spelled in ("site-packages", "Site-Packages"):
        exe = std / spelled / "vx" / "bin" / "python"
        places = selfcheck.python_places(str(exe), stdlib=str(std), dynload="", libpython="")
        assert len(places.walk) == 2, (spelled, places.walk)
        problems = selfcheck.check_python(places)
        assert any("evil.py" in p for p in problems), (spelled, problems)


def test_choosing_the_roots_survives_a_folder_that_vanishes(tree, monkeypatch):
    venv = tree / "v"
    write_file(venv / "bin" / "python", mode=0o755, text="#!fake\n")
    (venv / "pyvenv.cfg").write_text(CFG)
    std = tree / "std"
    write_file(std / "os.py")
    real = selfcheck._ident

    def flaky(path):
        if os.path.realpath(path) == os.path.realpath(std):
            raise FileNotFoundError(path)
        return real(path)
    monkeypatch.setattr(selfcheck, "_ident", flaky)
    places = selfcheck.python_places(str(venv / "bin" / "python"), stdlib=str(std), dynload="",
                                     libpython="")
    assert str(venv) in places.walk
