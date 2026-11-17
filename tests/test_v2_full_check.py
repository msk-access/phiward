"""The full check of phiward's own Python (round 4), in `doctor` and `install`: the interpreter
and each link to it, `pyvenv.cfg`, `libpython`, the venv, the standard library and
`lib-dynload`, and the folders a .pth path line adds. Every folder and file there, and each
folder above them, must pass the one rule (`selfcheck.safe_path`). `install` first compiles
those folders (so another program on the same Python makes no group-writable `__pycache__`
later), then makes what you own there writable by you alone, with the folders above up to the
home folder (never the home folder itself). A base Python's own site-packages and the rest of
its prefix (conda's `pkgs/`, `envs/`) are never walked. Made-up trees only."""

import os
import stat
import sys
import time
import types

import pytest

from phiward import selfcheck
from helpers import write_file

INSTALL = "phiward install claude --user --write"


def _python(home, venv=None):
    """A fake uv tool venv (or the venv at `venv`) on a fake uv-managed Python, both in the home
    folder."""
    base = home / ".local" / "share" / "uv" / "python" / "cpython-3.12"
    stdlib = base / "lib" / "python3.12"
    write_file(base / "bin" / "python3.12", mode=0o755, text="#!fake\n")
    write_file(stdlib / "os.py")
    write_file(stdlib / "json" / "__init__.py")
    write_file(stdlib / "lib-dynload" / "_x.so", text="fake")
    write_file(stdlib / "site-packages" / "big" / "mod.py", mode=0o664)  # never walked
    write_file(base / "pkgs" / "other.py", mode=0o664)  # conda's pkgs/: never walked
    venv = venv or home / ".local" / "share" / "uv" / "tools" / "phiward"
    (venv / "bin").mkdir(parents=True)
    os.symlink(base / "bin" / "python3.12", venv / "bin" / "python")
    write_file(venv / "pyvenv.cfg", text=f"home = {base / 'bin'}\ninclude-system-site-packages = false\n")
    site = venv / "lib" / "python3.12" / "site-packages"
    write_file(site / "phiward" / "__init__.py")
    places = selfcheck.python_places(str(venv / "bin" / "python"), stdlib=str(stdlib),
                                     dynload=str(stdlib / "lib-dynload"), libpython="")
    return types.SimpleNamespace(base=base, stdlib=stdlib, venv=venv, site=site, places=places)


# --- what is checked -----------------------------------------------------------------------------

def test_the_places_are_the_venv_the_stdlib_and_the_interpreters_links(home):
    py = _python(home)
    p = py.places
    assert p.venv == str(py.venv)
    assert str(py.venv) in p.walk and str(py.stdlib) in p.walk
    assert str(py.venv / "bin" / "python") in p.files
    assert str(py.base / "bin" / "python3.12") in p.files
    assert str(py.venv / "pyvenv.cfg") in p.files
    assert not any("site-packages" in w and w.startswith(str(py.base)) for w in p.walk)


def test_a_clean_python_passes(home):
    py = _python(home)
    assert selfcheck.check_python(py.places) == []


@pytest.mark.parametrize("rel", ["pyvenv.cfg", "lib/python3.12/site-packages/phiward/__init__.py"])
def test_a_group_writable_file_of_the_venv_is_found(home, rel):
    py = _python(home)
    os.chmod(py.venv / rel, 0o664)
    problems = selfcheck.check_python(py.places)
    assert problems and all(p.endswith("writable by others") for p in problems), problems
    assert any(os.path.basename(rel) in p for p in problems), problems


def test_a_group_writable_stdlib_file_is_found_the_conda_case(home):
    py = _python(home)
    os.chmod(py.stdlib / "os.py", 0o664)
    assert any("os.py: writable by others" in p for p in selfcheck.check_python(py.places))


def test_a_new_group_writable_pycache_in_the_stdlib_is_found(home):
    py = _python(home)
    (py.stdlib / "json" / "__pycache__").mkdir()
    os.chmod(py.stdlib / "json" / "__pycache__", 0o775)
    assert any("__pycache__/: writable by others" in p
               for p in selfcheck.check_python(py.places))


def test_a_group_writable_folder_above_the_venv_is_found(home):
    py = _python(home)
    os.chmod(home / ".local" / "share", 0o775)
    problems = selfcheck.check_python(py.places)
    assert any("~/.local/share/: writable by others" in p for p in problems), problems


def test_the_base_pythons_site_packages_and_pkgs_are_not_walked(home):
    py = _python(home)
    problems = selfcheck.check_python(py.places)
    assert not any("mod.py" in p or "other.py" in p for p in problems), problems


def test_a_pth_in_the_venv_is_judged(home):
    py = _python(home)
    (py.site / "evil.pth").write_text("import os\n")
    assert any("evil.pth: runs code at start" in p for p in selfcheck.check_python(py.places))


def test_an_allowed_pth_folder_is_walked_too(home):
    shared = home / ".local" / "share" / "pipx" / "shared" / "lib" / "python3.12" / \
        "site-packages"
    write_file(shared / "pip" / "__init__.py", mode=0o664)
    py = _python(home, home / ".local" / "share" / "pipx" / "venvs" / "phiward")
    (py.site / "pipx_shared.pth").write_text(str(shared) + "\n")
    places = selfcheck.python_places(str(py.venv / "bin" / "python"), stdlib=str(py.stdlib),
                                     dynload=str(py.stdlib / "lib-dynload"), libpython="")
    assert str(shared) in places.walk
    assert any("__init__.py: writable by others" in p for p in selfcheck.check_python(places))


def test_many_problems_are_cut_short(home):
    py = _python(home)
    for i in range(80):
        write_file(py.stdlib / "many" / f"m{i}.py", mode=0o664)
    problems = selfcheck.check_python(py.places)
    assert len(problems) <= selfcheck.MAX_PROBLEMS + 1, len(problems)


# --- what install fixes --------------------------------------------------------------------------

def test_fix_modes_compiles_then_makes_it_writable_by_you_alone(home):
    py = _python(home)
    old = os.umask(0o002)
    try:
        os.chmod(py.stdlib / "os.py", 0o664)
        os.chmod(py.venv / "pyvenv.cfg", 0o664)
        os.chmod(home / ".local", 0o775)
        changed = selfcheck.fix_modes(py.places, scripts=(), package_dir=str(py.site / "phiward"))
    finally:
        os.umask(old)
    cache = py.stdlib / "json" / "__pycache__"
    assert cache.is_dir(), "the stdlib was not compiled"
    assert stat.S_IMODE(os.stat(cache).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(py.stdlib / "os.py").st_mode) == 0o644
    assert stat.S_IMODE(os.stat(py.venv / "pyvenv.cfg").st_mode) == 0o644
    assert stat.S_IMODE(os.stat(home / ".local").st_mode) == 0o755
    assert changed and all(isinstance(c, str) for c in changed)
    assert selfcheck.check_python(py.places) == []


def test_fix_modes_never_changes_the_home_folder(home):
    py = _python(home)
    os.chmod(home, 0o775)
    try:
        selfcheck.fix_modes(py.places, scripts=(), package_dir=str(py.site / "phiward"))
        assert stat.S_IMODE(os.stat(home).st_mode) == 0o775
        assert selfcheck.check_python(py.places) == [selfcheck.HOME_PROBLEM]
        assert "chmod go-w ~" in selfcheck.fix_text(selfcheck.check_python(py.places), "")
    finally:
        os.chmod(home, 0o755)


def test_fix_modes_does_not_follow_a_link_out_of_its_places(tree, home):
    py = _python(home)
    outside = write_file(tree / "pub" / "keep.txt", mode=0o666)
    os.symlink(outside, py.stdlib / "evil")
    selfcheck.fix_modes(py.places, scripts=(), package_dir=str(py.site / "phiward"))
    assert stat.S_IMODE(os.stat(outside).st_mode) == 0o666


def test_fix_modes_leaves_a_file_you_do_not_own(home, monkeypatch):
    py = _python(home)
    f = py.stdlib / "os.py"
    os.chmod(f, 0o664)
    real = os.lstat

    def fake(p, *a, **k):
        st = real(p, *a, **k)
        if os.fspath(p) == str(f):
            return types.SimpleNamespace(st_mode=st.st_mode, st_uid=os.getuid() + 12345,
                                         st_gid=st.st_gid, st_ino=st.st_ino, st_dev=st.st_dev)
        return st
    monkeypatch.setattr(os, "lstat", fake)
    selfcheck.fix_modes(py.places, scripts=(), package_dir=str(py.site / "phiward"))
    monkeypatch.setattr(os, "lstat", real)
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o664


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs")
def test_fix_modes_does_not_wait_on_a_fifo(home):
    py = _python(home)
    fifo = py.stdlib / "pipe"
    os.mkfifo(fifo)
    os.chmod(fifo, 0o662)
    started = time.monotonic()
    selfcheck.fix_modes(py.places, scripts=(), package_dir=str(py.site / "phiward"))
    assert time.monotonic() - started < 30


def test_fix_modes_fixes_the_path_folder_that_holds_the_launcher_link(home, monkeypatch):
    py = _python(home)
    script = write_file(py.venv / "bin" / "phiward", mode=0o755, text="#!/bin/sh\n")
    localbin = home / ".local" / "bin"
    localbin.mkdir()
    os.chmod(localbin, 0o775)
    os.symlink(script, localbin / "phiward")
    monkeypatch.setenv("PATH", f"/usr/bin:{localbin}")
    selfcheck.fix_modes(py.places, scripts=(str(script),), package_dir=str(py.site / "phiward"))
    assert stat.S_IMODE(os.stat(localbin).st_mode) == 0o755


# --- the real interpreter ------------------------------------------------------------------------

def test_the_running_pythons_places_exist_and_are_checked_in_time():
    places = selfcheck.python_places()
    assert places.walk and all(os.path.isdir(w) for w in places.walk), places
    assert sys.executable in places.files or os.path.abspath(sys.executable) in places.files
    started = time.monotonic()
    selfcheck.check_python(places)
    assert time.monotonic() - started < 20


# --- doctor, the session note and the script -----------------------------------------------------

def test_doctor_uses_the_full_check_with_one_step(monkeypatch):
    from phiward import doctor
    monkeypatch.setattr(selfcheck, "check_full_isolated",
                        lambda timeout=120: (True, [], ["~/.local/: writable by others"]))
    lines = doctor.selfcheck_lines()
    assert len(lines) == 1 and lines[0].startswith("WARNING") and INSTALL in lines[0], lines
    monkeypatch.setattr(selfcheck, "check_full_isolated", lambda timeout=120: (True, [], []))
    assert doctor.selfcheck_lines() == []


def test_the_session_note_names_a_failed_self_check(tree, monkeypatch):
    from phiward import config, session_note
    cfg = config.load(str(tree / "repo"))
    monkeypatch.setattr(selfcheck, "check_isolated",
                        lambda timeout=60: (True, ["cli.py: writable by others"]))
    text = session_note.note(cfg)
    assert "ask the operator" in text and INSTALL in text, text
    monkeypatch.setattr(selfcheck, "check_isolated", lambda timeout=60: (True, []))
    assert INSTALL not in session_note.note(cfg)
    monkeypatch.setattr(selfcheck, "check_isolated", lambda timeout=60: (False, []))
    assert INSTALL not in session_note.note(cfg)


def test_the_full_check_finds_a_writable_pyvenv_cfg(home, monkeypatch):
    py = _python(home)
    os.chmod(py.venv / "pyvenv.cfg", 0o664)
    monkeypatch.setattr(selfcheck, "_home", lambda: str(home))
    places = selfcheck.python_places(str(py.venv / "bin" / "python"), stdlib=str(py.stdlib),
                                     dynload=str(py.stdlib / "lib-dynload"), libpython="")
    python = selfcheck.check_python(places)
    assert any("pyvenv.cfg: writable by others" in p for p in python), python


def test_the_full_check_runs_this_file_as_a_script(home, monkeypatch):
    # the child itself (`-I -S`, this file standalone, the argv `--full RECORD EXE`) answers
    py = _python(home)
    import base64
    import hashlib
    src = py.site / "phiward" / "__init__.py"
    h = base64.urlsafe_b64encode(hashlib.sha256(src.read_bytes()).digest()).rstrip(b"=").decode()
    info = py.site / "phiward-0.2.0b1.dist-info"
    info.mkdir()
    (info / "RECORD").write_text(f"phiward/__init__.py,sha256={h},6\n")
    monkeypatch.setattr(selfcheck, "_record_path", lambda: str(info / "RECORD"))
    monkeypatch.setattr(selfcheck, "_running_package", lambda: str(py.site / "phiward"))
    ok, package, python = selfcheck.check_full_isolated()
    assert ok and package == [] and isinstance(python, list), (package, python)
    assert selfcheck.CHECK_FAILED not in python + package, (package, python)


def test_install_fixes_phiwards_own_python_and_names_what_it_cannot(monkeypatch, capsys):
    from phiward import install
    called = []
    monkeypatch.setattr(selfcheck, "launcher_scripts", lambda *a: None)
    monkeypatch.setattr(selfcheck, "fix_modes", lambda *a, **k: called.append(1) or [])
    install.fix_own_modes()
    assert not called  # a source checkout: not phiward's own installed copy to change
    monkeypatch.setattr(selfcheck, "launcher_scripts", lambda *a: frozenset())
    monkeypatch.setattr(selfcheck, "python_places",
                        lambda *a, **k: selfcheck.Places("", [], [], "", ""))
    monkeypatch.setattr(selfcheck, "fix_modes", lambda *a, **k: ["/x/a", "/x/b"])
    monkeypatch.setattr(selfcheck, "check_python", lambda places: [selfcheck.HOME_PROBLEM])
    install.fix_own_modes()
    out = capsys.readouterr().out
    assert "writable by you alone" in out and "/x/a" in out, out
    assert "chmod go-w ~" in out, out


def test_a_linked_libpython_is_fixed_and_checked_where_it_leads(home):
    # found by the quickstart check (pipx on a Python the user owns): libpython3.12.so is a link
    # to libpython3.12.so.1.0, and only the link was on the list, so install fixed nothing
    py = _python(home)
    lib = py.base / "lib"
    real = write_file(lib / "libpython3.12.so.1.0", mode=0o775, text="fake")
    os.symlink(real.name, lib / "libpython3.12.so")
    places = selfcheck.python_places(str(py.venv / "bin" / "python"), stdlib=str(py.stdlib),
                                     dynload=str(py.stdlib / "lib-dynload"),
                                     libpython=str(lib / "libpython3.12.so"))
    assert str(real) in places.files
    assert any("libpython3.12.so" in p for p in selfcheck.check_python(places))
    selfcheck.fix_modes(places, scripts=(), package_dir=str(py.site / "phiward"))
    assert stat.S_IMODE(os.stat(real).st_mode) == 0o755
    assert selfcheck.check_python(places) == []


# --- round 5: fix_modes changes only what the check covers, inside the home folder --------------

def test_fix_modes_leaves_a_root_outside_home_and_names_the_chmod(tree, home):
    py = _python(home)
    outside = tree / "labshare" / "py"
    write_file(outside / "os.py", mode=0o664)
    os.chmod(outside, 0o775)
    places = py.places._replace(walk=py.places.walk + [str(outside)])
    selfcheck.fix_modes(places, scripts=(), package_dir=str(py.site / "phiward"))
    assert stat.S_IMODE(os.stat(outside).st_mode) == 0o775
    assert stat.S_IMODE(os.stat(outside / "os.py").st_mode) == 0o664
    assert not (outside / "__pycache__").exists(), "compiled outside the home folder"
    problems = selfcheck.check_python(places)
    assert problems and all(p.endswith(selfcheck.OUTSIDE_MINE) for p in problems), problems
    assert f"chmod go-w {outside}" in selfcheck.fix_text(problems, "")  # the fault alone (round 6)


def test_fix_modes_leaves_the_standard_librarys_own_site_packages(home):
    py = _python(home)
    sp = py.stdlib / "site-packages"
    os.chmod(sp, 0o775)
    selfcheck.fix_modes(py.places, scripts=(), package_dir=str(py.site / "phiward"))
    assert stat.S_IMODE(os.stat(sp).st_mode) == 0o775
    assert stat.S_IMODE(os.stat(sp / "big" / "mod.py").st_mode) == 0o664
    assert not (sp / "big" / "__pycache__").exists(), "compiled the base site-packages"


def test_fix_modes_leaves_a_launcher_folder_outside_home_and_the_home_folder(tree, home,
                                                                           monkeypatch):
    py = _python(home)
    script = write_file(py.venv / "bin" / "phiward", mode=0o755, text="#!/bin/sh\n")
    away = tree / "usrlocalbin"
    away.mkdir()
    os.chmod(away, 0o775)
    os.symlink(script, away / "phiward")
    os.symlink(script, home / "phiward")
    os.chmod(home, 0o775)
    try:
        for path in (f"/usr/bin:{away}", f"/usr/bin:{home}"):
            monkeypatch.setenv("PATH", path)
            selfcheck.fix_modes(py.places, scripts=(str(script),),
                                package_dir=str(py.site / "phiward"))
        assert stat.S_IMODE(os.stat(away).st_mode) == 0o775
        assert stat.S_IMODE(os.stat(home).st_mode) == 0o775
    finally:
        os.chmod(home, 0o755)


def test_a_root_whose_name_has_regex_characters_is_compiled(tree, home):
    base = home / "py+3[x]" / "lib" / "python3.12"
    write_file(base / "mod.py")
    write_file(base / "site-packages" / "skip.py")
    places = selfcheck.Places("", [str(base)], [], "", str(base))
    selfcheck.fix_modes(places, scripts=(), package_dir=str(home / "nope"))
    assert (base / "__pycache__").is_dir()
    assert not (base / "site-packages" / "__pycache__").exists()


def test_doctor_gives_the_package_and_the_python_their_own_warnings(monkeypatch):
    from phiward import doctor
    monkeypatch.setattr(selfcheck, "check_full_isolated",
                        lambda timeout=120: (True, ["cli.py: changed since install"],
                                             ["~/.local/: writable by others"]))
    lines = doctor.selfcheck_lines()
    assert len(lines) == 2, lines
    assert "refuse to start" in lines[0] and "reinstall" in lines[0], lines
    assert "another account" in lines[1] and INSTALL in lines[1], lines
