"""Round 12: one rule for what the full check walks. Only the standard library leaves out its own
packages folder (the base Python's, which a venv's Python does not read), by identity; every
folder phiward's Python reads is walked, however a .pth line spells it. The step prunes exactly
what the check left out. The check never waits on the install record, pyvenv.cfg or a .pth.
Made-up trees only: nothing outside the test's own tree is written."""

import os
import re
import stat
import subprocess
import sys
import time

import pytest

from phiward import selfcheck
from helpers import write_file


CFG = "home = /x/bin\ninclude-system-site-packages = false\n"


def _std(base):
    """A made-up standard library with the base Python's own packages folder."""
    std = base / "lib" / "python3.12"
    write_file(std / "os.py")
    write_file(std / "site-packages" / "base_pkg.py", mode=0o666)
    return std


def _venv(home, lines):
    venv = home / "v"
    write_file(venv / "bin" / "python", mode=0o755, text="#!fake\n")
    (venv / "pyvenv.cfg").write_text(CFG)
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (site / "a.pth").write_text("".join(ln + "\n" for ln in lines))
    return venv, site


def _places(venv, std):
    return selfcheck.python_places(str(venv / "bin" / "python"), stdlib=str(std), dynload="",
                                   libpython="")


def _run_tree_steps(text):
    for cmd in re.findall(r"`(\(cd [^`]+)`", text):
        subprocess.run(["sh", "-c", cmd], check=True)


# --- M: a folder a venv .pth adds is walked, however it is spelled


@pytest.mark.parametrize("line", ["../../../site-packages", "../../../splink"])
def test_a_venv_site_folder_a_pth_adds_is_walked(tree, home, line):
    std = _std(tree / "base")
    venv, _site = _venv(home, [line, "../../../dist-packages"])
    evil = write_file(venv / "site-packages" / "evil.py", mode=0o666)
    write_file(venv / "dist-packages" / "evil2.py", mode=0o666)
    os.symlink(venv / "site-packages", venv / "splink")
    places = _places(venv, std)
    problems = selfcheck.check_python(places)
    assert "~/v/site-packages/evil.py: writable by others" in problems, problems
    assert "~/v/dist-packages/evil2.py: writable by others" in problems, problems
    assert not any("base_pkg" in p for p in problems), problems
    selfcheck.fix_modes(places, scripts=(), package_dir=str(home / "nope"))
    assert stat.S_IMODE(os.stat(evil).st_mode) == 0o644
    assert not any("evil" in p for p in selfcheck.check_python(places))


def test_a_venv_that_holds_the_standard_library_walks_its_own_site_folder(home):
    # pyvenv.cfg beside the base prefix: the venv is the prefix; its site folder is the stdlib's
    venv = home / "prefix"
    write_file(venv / "bin" / "python", mode=0o755, text="#!fake\n")
    (venv / "pyvenv.cfg").write_text(CFG)
    std = _std(venv)
    places = _places(venv, std)
    assert places.walk == [str(venv)], places.walk
    problems = selfcheck.check_python(places)
    assert "~/prefix/lib/python3.12/site-packages/base_pkg.py: writable by others" in problems


def test_two_spellings_of_one_folder_are_one_root(tree, home):
    pipx = home / "pipx"
    shared = pipx / "shared" / "lib" / "python3.12" / "site-packages"
    shared.mkdir(parents=True)
    venv = pipx / "venvs" / "phiward"
    write_file(venv / "bin" / "python", mode=0o755, text="#!fake\n")
    (venv / "pyvenv.cfg").write_text(CFG)
    os.symlink(shared, venv / "shlink")
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (site / "p.pth").write_text(f"{shared}\n{venv / 'shlink'}\n")
    places = _places(venv, _std(tree / "base"))
    assert places.walk.count(str(shared)) == 1, places.walk
    assert str(venv / "shlink") not in places.walk, places.walk


# --- the stdlib root: the check and the step leave out the same, and only there


def test_the_standard_library_leaves_out_its_packages_folder_and_link_not_a_file(tree, home):
    std = _std(tree / "opt")
    os.symlink(std / "site-packages", std / "dist-packages")
    places = selfcheck.Places("", [str(std)], [], "", str(std))
    assert selfcheck.check_python(places) == []
    os.remove(std / "dist-packages")
    odd = write_file(std / "dist-packages", mode=0o664)  # a file of that name is judged
    problems = selfcheck.check_python(places)
    assert len(problems) == 1 and "its own packages folder aside" in problems[0], problems
    text = selfcheck.fix_text(problems, "")
    assert "-type d -prune" in text, text
    _run_tree_steps(text)
    assert stat.S_IMODE(os.stat(odd).st_mode) == 0o644
    assert stat.S_IMODE(os.stat(std / "site-packages" / "base_pkg.py").st_mode) == 0o666
    assert selfcheck.check_python(places) == []


def test_another_root_prunes_nothing(tree, home):
    root = tree / "opt" / "lib2"
    f = write_file(root / "site-packages" / "x.py", mode=0o664)
    places = selfcheck.Places("", [str(root)], [], "", "")
    problems = selfcheck.check_python(places)
    assert problems and "aside" not in problems[0], problems
    text = selfcheck.fix_text(problems, "")
    assert "-prune" not in text and " -x " not in text, text
    _run_tree_steps(text)
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o644


# --- the invariant: every folder of a real venv's path, inside the tree, is walked


def test_every_folder_a_real_venv_reads_is_walked(tree, home):
    venv = home / "realvenv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
    site = next(venv.glob("lib/python*/site-packages"))
    (venv / "site-packages").mkdir()
    (venv / "nested" / "deep").mkdir(parents=True)
    os.symlink(venv / "nested", venv / "nlink")
    (site / "a.pth").write_text("../../../site-packages\n../../../nlink/deep\n")
    out = subprocess.run([str(venv / "bin" / "python"), "-I", "-c",
                          "import sys; print('\\n'.join(sys.path))"],
                         capture_output=True, text=True, check=True).stdout.split("\n")
    inside = os.path.realpath(tree)
    planted = []
    for p in out:
        real = os.path.realpath(p) if p else ""
        if real.startswith(inside + "/") and os.path.isdir(real):
            planted.append(write_file(type(tree)(real) / "planted_x.py", mode=0o666))
    assert len(planted) >= 3, out
    std = _std(tree / "base")
    places = selfcheck.python_places(str(venv / "bin" / "python"), stdlib=str(std),
                                     dynload="", libpython="")
    problems = "\n".join(selfcheck.check_python(places))
    for f in planted:
        assert selfcheck._shown(os.path.realpath(f), str(home)) in problems, (f, problems)


# --- L2: never waiting


def test_the_record_pyvenv_cfg_and_a_pth_are_read_without_waiting(tree):
    fifo = tree / "fifo"
    os.mkfifo(fifo)
    start = time.monotonic()
    assert selfcheck._system_site(str(fifo)) is True
    assert selfcheck._pth_lines(str(fifo))[0] == "not a regular file"
    assert selfcheck._record_check(str(fifo)) == (True, ["the install record cannot be read"])
    assert time.monotonic() - start < 5
    bad = tree / "RECORD"
    bad.write_bytes(b"phiward/x.py,sha256=a\x00b,1\n\xff\n")
    assert selfcheck._record_check(str(bad)) == (True, ["the install record cannot be read"])


def test_a_linked_pyvenv_cfg_is_read_where_it_leads(tree):
    real = tree / "real.cfg"
    real.write_text(CFG)
    os.symlink(real, tree / "pyvenv.cfg")
    assert selfcheck._system_site(str(tree / "pyvenv.cfg")) is False


# --- L3


def test_a_full_kind_says_at_least_how_many_more():
    full = [f"~/f{i}: writable by others" for i in range(selfcheck.MAX_PROBLEMS)]
    assert selfcheck._listed(full + [selfcheck.MORE]).endswith(
        f"; and at least {selfcheck.MAX_PROBLEMS - 3} more")
