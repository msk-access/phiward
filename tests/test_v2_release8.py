"""The self-check's lines have one kind each, read by one function (round 8): the order, the cap
and the step all use it, for the package check and the full check alike; the check stays linear
on a huge tree; the tree step runs no file of the tree and nothing when its `cd` fails;
pyvenv.cfg is read as site.py reads it; a missing path keeps its name; the reinstall tool is read
from its own file. Made-up trees only."""

import os
import stat
import subprocess


from phiward import doctor, selfcheck
from helpers import write_file


CFG = "home = /x/bin\ninclude-system-site-packages = false\n"


def _venv(home, cfg=CFG):
    venv = home / "v"
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (venv / "bin").mkdir()
    (venv / "pyvenv.cfg").write_text(cfg)
    return venv, site


# --- M, R1: linear on a huge tree; the lines of a full kind are not even worded


def test_a_huge_tree_words_only_the_lines_it_keeps(home, monkeypatch):
    venv, _site = _venv(home)
    for i in range(1500):
        write_file(venv / f"d{i // 100}" / f"f{i}.py", mode=0o664)
    calls = []
    real = selfcheck._shown
    monkeypatch.setattr(selfcheck, "_shown", lambda *a: calls.append(a) or real(*a))
    problems = selfcheck.check_python(selfcheck.Places(str(venv), [str(venv)], [], str(venv / "pyvenv.cfg"), ""))
    assert problems[-1] == "and more" and len(problems) == selfcheck.MAX_PROBLEMS + 1
    assert len(calls) <= 3 * selfcheck.MAX_PROBLEMS, len(calls)


# --- L6: a line of a lower kind is never pushed out by mode lines


def test_a_reinstall_line_is_kept_past_many_mode_lines(home):
    venv, site = _venv(home)
    for i in range(80):
        write_file(venv / f"f{i}.py", mode=0o664)
    write_file(site / "sitecustomize.py")
    problems = selfcheck.check_python(selfcheck.Places(str(venv), [str(venv)], [], str(venv / "pyvenv.cfg"), ""))
    assert any("sitecustomize.py" in p for p in problems), problems
    assert "reinstall" in selfcheck.fix_text(problems, "")


def test_a_duplicate_does_not_say_there_are_more(home):
    keep = selfcheck._Lines()
    for i in range(selfcheck.MAX_PROBLEMS):
        keep.add(f"~/f{i}: writable by others")
    keep.add("~/f0: writable by others")
    assert keep.lines()[-1] != "and more"


# --- L1, M2: the package check words a placed fault as it is, once, in kind order


def test_the_package_check_names_a_placed_fault_once(tree, home):
    folder = tree / "opt" / "pkg"
    a, b = write_file(folder / "a.py"), write_file(folder / "b.py")
    os.chmod(folder, 0o775)
    _ok, problems = selfcheck.check([(str(a), "sha256=x"), (str(b), "sha256=x")])
    placed = [p for p in problems if p.endswith(selfcheck.OUTSIDE_MINE)]
    assert placed == [f"{folder}/: writable by others {selfcheck.OUTSIDE_MINE}"], problems
    assert problems[0] == placed[0], problems


def test_a_home_of_another_account_gets_its_step_from_the_package_check(tree, monkeypatch):
    f = write_file(tree / "pkg" / "cli.py")
    monkeypatch.setattr(selfcheck, "_owner_or_mode_faults", lambda p: [(selfcheck.HOME_OWNER, "")])
    _ok, problems = selfcheck.check([(str(f), "sha256=x")])
    # first, as its step reads it (the file is read too since round 11: its hash is made up)
    assert problems[0] == selfcheck.HOME_OWNER, problems
    text = selfcheck.fix_text(problems, "")
    assert "another account" in text and "reinstall" not in text, text


# --- L2, L3: the tree step


def test_the_tree_step_runs_no_file_of_the_tree(tree, home):
    root = tree / "opt" / "lib"
    write_file(root / "x.py", mode=0o664)
    marker = tree / "ran"
    write_file(root / "compileall.py", text=f"open({str(marker)!r}, 'w').close()\n")
    subprocess.run(["sh", "-c", selfcheck._tree_step(str(root), False)], check=False)
    assert not marker.exists()
    assert stat.S_IMODE(os.stat(root / "x.py").st_mode) == 0o644


def test_a_failing_cd_runs_nothing(tree):
    here = tree / "here"
    f = write_file(here / "x.py", mode=0o664)
    step = selfcheck._tree_step(str(tree / "gone"), False)
    r = subprocess.run(["sh", "-c", step], cwd=str(here), capture_output=True)
    assert r.returncode != 0
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o664


# --- L4, R3: pyvenv.cfg as site.py reads it


def test_a_venv_config_without_the_key_reads_the_base_site_folders(home):
    venv, _site = _venv(home, cfg="home = /x/bin\n")
    cfg = selfcheck._venv_cfg(str(venv / "bin" / "python"))
    assert cfg == str(venv / "pyvenv.cfg")
    assert selfcheck._system_site(cfg)


def test_a_config_next_to_the_interpreter_comes_first(home):
    venv, _site = _venv(home)
    (venv / "bin" / "pyvenv.cfg").write_text("include-system-site-packages = true\n")
    exe = str(venv / "bin" / "python")
    assert selfcheck._venv_cfg(exe) == str(venv / "bin" / "pyvenv.cfg")
    assert selfcheck._system_site(selfcheck._venv_cfg(exe))
    places = selfcheck.python_places(exe, stdlib="", dynload="", libpython="")
    assert places.venv == str(venv)
    assert str(venv / "bin" / "pyvenv.cfg") in places.files


def test_only_a_config_next_to_the_interpreter_makes_a_venv(home):
    venv, _site = _venv(home)
    os.rename(venv / "pyvenv.cfg", venv / "bin" / "pyvenv.cfg")
    places = selfcheck.python_places(str(venv / "bin" / "python"), stdlib="", dynload="",
                                     libpython="")
    assert places.venv == str(venv)


def test_lines_are_split_as_python_splits_them(home):
    # Python iterates lines: a form feed does not end one
    venv, _site = _venv(home, cfg="include-system-site-packages = true\n"
                                  "a = 1\x0cinclude-system-site-packages = false\n")
    assert selfcheck._system_site(str(venv / "pyvenv.cfg"))


def test_case_and_line_ends_as_python_reads_them(home):
    venv, _site = _venv(home, cfg="Include-System-Site-Packages = TRUE\r\n")
    assert selfcheck._system_site(str(venv / "pyvenv.cfg"))
    (venv / "pyvenv.cfg").write_text("include-system-site-packages = false\r\n")
    assert not selfcheck._system_site(str(venv / "pyvenv.cfg"))


def test_a_python_that_is_no_venv_has_nothing_to_refuse(tree):
    exe = write_file(tree / "base" / "bin" / "python", mode=0o755)
    assert selfcheck._venv_cfg(str(exe)) == ""
    assert selfcheck.python_places(str(exe), stdlib="", dynload="", libpython="").venv == ""


# --- L5: a missing path keeps its name


def test_a_missing_path_is_named(tree, home):
    gone = home / "gone" / "python"
    problems = selfcheck.check_python(selfcheck.Places("", [], [str(gone)], "", ""))
    assert problems == ["~/gone/python: missing"], problems


# --- L7: the reinstall tool from its own file


def test_the_reinstall_tool_is_read_from_its_file(home):
    changed = ["cli.py: changed since install"]
    for name, tool, want in (("venvs", None, "the way you installed it"),
                             ("venvs", "pipx_metadata.json", "pipx reinstall"),
                             ("elsewhere", "uv-receipt.toml", "uv tool install"),
                             ("tools", None, "the way you installed it")):
        venv = home / name / f"phiward-{tool}"
        pkg = venv / "lib/python3.12/site-packages/phiward"
        pkg.mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text(CFG)
        if tool:
            (venv / tool).write_text("{}\n")
        assert want in selfcheck.fix_text(changed, str(pkg)), (name, tool)


# --- R4: a check that could not run has its own step and its own doctor line


def test_a_check_that_could_not_finish_has_its_own_step(monkeypatch):
    for line in (selfcheck.CHECK_FAILED, selfcheck.CHECK_SLOW):
        text = selfcheck.fix_text([line], "")
        assert text.startswith("start again"), text
        assert "reinstall" in text
    # a package file named like the line is an ordinary line
    assert selfcheck._kind(f"x: {selfcheck.CHECK_FAILED}") != selfcheck._kind(
        selfcheck.CHECK_FAILED)
    monkeypatch.setattr(selfcheck, "check_full_isolated",
                        lambda: (True, [selfcheck.CHECK_SLOW], []))
    lines = doctor.selfcheck_lines()
    assert len(lines) == 1 and "refuse to start" not in lines[0], lines


def test_a_timeout_says_so(monkeypatch, tmp_path):
    record = tmp_path / "RECORD"
    record.write_text("")
    monkeypatch.setattr(selfcheck, "_record_path", lambda: str(record))
    monkeypatch.setattr(selfcheck, "_running_package",
                        lambda: os.path.join(str(tmp_path.parent), "phiward"))

    def slow(*a, **k):
        raise subprocess.TimeoutExpired("x", 1)
    monkeypatch.setattr(selfcheck.subprocess, "run", slow)
    assert selfcheck.check_isolated() == (True, [selfcheck.CHECK_SLOW])
    assert selfcheck.check_full_isolated() == (True, [selfcheck.CHECK_SLOW], [])
