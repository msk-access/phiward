"""Round 9: the tree step fixes the modes before it runs anything; one wording of the refusal
for every caller; the package check names every fault of yours outside home in one round;
doctor's two lists are not filtered against each other; a duplicate never says there are more;
a folder is always named with its `/`; the venv's pyvenv.cfg has one source. Made-up trees
only."""

import os
import stat
import subprocess
import sys

import pytest

from phiward import doctor, selfcheck, session_note
from helpers import write_file


def _writable(root):
    out = []
    for here, dirs, names in os.walk(root):
        for n in dirs + names:
            st = os.lstat(os.path.join(here, n))
            if not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022:
                out.append(os.path.join(here, n))
    return out


# --- L1: modes first, then compile; no .pth of the venv runs


def test_the_tree_step_fixes_modes_before_it_runs_python(tree, home):
    root = tree / "opt" / "lib"
    write_file(root / "pkg" / "x.py", mode=0o664)
    os.chmod(root / "pkg", 0o775)
    step = selfcheck._tree_step(str(root), False)
    assert step.index("find .") < step.index("compileall"), step
    subprocess.run(["sh", "-c", "umask 002; " + step], check=True)
    assert (root / "pkg" / "__pycache__").is_dir()
    assert _writable(root) == []


def test_the_tree_step_runs_no_pth_of_the_venv(tree, home, monkeypatch):
    venv = tree / "opt" / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
    site = next(venv.glob("lib/python*/site-packages"))
    marker = tree / "ran"
    (site / "evil.pth").write_text(f"import os; open({str(marker)!r}, 'w').close()\n")
    monkeypatch.setattr(selfcheck.sys, "executable", str(venv / "bin" / "python"))
    subprocess.run(["sh", "-c", selfcheck._tree_step(str(venv), False)], check=True)
    assert not marker.exists()


# --- L2: one wording of the refusal


def test_a_check_with_no_answer_is_worded_so_by_every_caller(monkeypatch):
    head = selfcheck.refusal([selfcheck.CHECK_SLOW])
    assert head.startswith("phiward's self-check gave no answer"), head
    assert selfcheck.refusal(["cli.py: changed since install"]).startswith(
        "phiward's own files fail its self-check (cli.py: changed since install")
    monkeypatch.setattr(selfcheck, "check_isolated", lambda: (True, [selfcheck.CHECK_SLOW]))
    note = session_note._selfcheck_line()
    assert "gave no answer" in note and "fail its self-check" not in note, note
    import inspect
    from phiward import wholetool
    assert "selfcheck.refusal(problems)" in inspect.getsource(wholetool)


# --- L3: every fault of yours outside home, in one round


def test_the_package_check_names_every_folder_of_yours_on_the_way(tree, home):
    a = tree / "opt" / "a"
    f = write_file(a / "b" / "phiward" / "cli.py")
    os.chmod(a, 0o775)
    os.chmod(a / "b", 0o775)
    _ok, problems = selfcheck.check([(str(f), "sha256=x")])
    real = os.path.realpath(a)
    assert f"{real}/: writable by others {selfcheck.OUTSIDE_MINE}" in problems, problems
    assert f"{real}/b/: writable by others {selfcheck.OUTSIDE_MINE}" in problems, problems
    text = selfcheck.fix_text(problems, "")
    assert real in text and f"{real}/b" in text, text


# --- L4: doctor's lists are not filtered against each other; each its own step


def test_the_full_check_keeps_the_lines_the_package_check_has(monkeypatch):
    monkeypatch.setattr(selfcheck, "_record_check",
                        lambda r: (True, [selfcheck.HOME_PROBLEM]))
    monkeypatch.setattr(selfcheck, "python_places", lambda *a, **k: None)
    monkeypatch.setattr(selfcheck, "check_python",
                        lambda p: [selfcheck.HOME_PROBLEM, "~/x.py: writable by others",
                                   selfcheck.MORE])
    out = selfcheck._main(["--full", "RECORD"])
    assert out["python"] == [selfcheck.HOME_PROBLEM, "~/x.py: writable by others",
                             selfcheck.MORE]


def test_doctor_shows_a_shared_line_once_and_the_same_step(monkeypatch):
    monkeypatch.setattr(selfcheck, "check_full_isolated", lambda: (
        True, [selfcheck.HOME_PROBLEM],
        [selfcheck.HOME_PROBLEM, "~/x.py: writable by others"]))
    # the same step as the package WARNING: no second WARNING repeats it (round 10)
    lines = doctor.selfcheck_lines()
    assert len(lines) == 1 and "chmod go-w ~" in lines[0], lines
    # nothing of its own: no second WARNING
    monkeypatch.setattr(selfcheck, "check_full_isolated", lambda: (
        True, [selfcheck.HOME_PROBLEM], [selfcheck.HOME_PROBLEM, selfcheck.MORE]))
    assert len(doctor.selfcheck_lines()) == 1


# --- L5: a duplicate never says there are more


def test_a_file_judged_twice_does_not_say_there_are_more(home):
    venv = home / "v"
    for i in range(selfcheck.MAX_PROBLEMS - 1):
        write_file(venv / f"f{i}.py", mode=0o664)
    dup = write_file(venv / "z" / "dup.py", mode=0o664)
    problems = selfcheck.check_python(selfcheck.Places(str(venv), [str(venv)], [str(dup)], "", ""))
    assert len(problems) == selfcheck.MAX_PROBLEMS and selfcheck.MORE not in problems, problems


# --- L6: a folder is named with its `/`, as a root and as a way folder alike


def test_a_root_on_the_way_of_a_file_is_one_line(tree, home):
    root = tree / "opt" / "r"
    f = write_file(root / "f.py")
    os.chmod(root, 0o775)
    problems = selfcheck.check_python(selfcheck.Places("", [str(root)], [str(f)], "", ""))
    real = os.path.realpath(root)
    assert problems == [f"{real}/: writable by others {selfcheck.OUTSIDE_MINE}"], problems


# --- L7: one source for the cfg


def test_the_places_carry_the_cfg_python_reads(tree):
    venv = tree / "v"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("include-system-site-packages = false\n")
    places = selfcheck.python_places(str(venv / "bin" / "python"), stdlib="", dynload="",
                                     libpython="")
    assert places.cfg == str(venv / "pyvenv.cfg")
    with pytest.raises(TypeError):
        selfcheck.Places(str(venv), [], [], "")  # pylint: disable=no-value-for-parameter
