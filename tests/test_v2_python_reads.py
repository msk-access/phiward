"""The full check follows what Python reads at start (round 6): a link inside phiward's Python is
judged by where it leads (the way there and the target), and `install` fixes what that names
inside the home folder; a `sitecustomize.py` in a folder that a .pth line adds is refused, with
the step to remove it; a .pth file is excluded from the walk by its name, whatever its name
holds. Made-up trees only."""

import os
import stat


from phiward import selfcheck


def _venv(home):
    venv = home / ".local" / "share" / "uv" / "tools" / "phiward"
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /x/bin\ninclude-system-site-packages = false\n")
    (site / "ok.py").write_text("x = 1\n")
    return venv, site


def _places(venv):
    return selfcheck.Places(str(venv), [str(venv)], [], str(venv / "pyvenv.cfg"), "")


def test_a_link_into_an_open_folder_outside_home_is_found(tree, home):
    venv, site = _venv(home)
    w = tree / "W"
    (w / "pkg").mkdir(parents=True)
    os.chmod(w, 0o777)
    os.symlink(w / "pkg", site / "evilpkg")
    problems = selfcheck.check_python(_places(venv))
    assert any("/W/: writable by others" in p for p in problems), problems


def test_a_dangling_link_into_an_open_folder_is_found(tree, home):
    venv, site = _venv(home)
    w = tree / "W"
    w.mkdir()
    os.chmod(w, 0o777)
    os.symlink(w / "later", site / "laterpkg")
    problems = selfcheck.check_python(_places(venv))
    # the deepest folder that exists is the last entry judged, named as a folder: `/.../W/: ...`
    assert any("/W/: writable by others" in p for p in problems), problems


def test_a_link_to_a_folder_inside_home_is_found_and_fixed_by_install(home):
    venv, site = _venv(home)
    cache = home / "cache"
    (cache / "pkg").mkdir(parents=True)
    os.chmod(cache, 0o775)
    os.symlink(cache / "pkg", site / "pkg")
    assert "~/cache/: writable by others" in selfcheck.check_python(_places(venv))
    selfcheck.fix_modes(_places(venv), scripts=(), package_dir=str(site / "phiward"))
    assert stat.S_IMODE(os.stat(cache).st_mode) == 0o755
    assert selfcheck.check_python(_places(venv)) == []


def test_a_linked_file_inside_home_is_fixed_by_install(home):
    venv, site = _venv(home)
    target = home / "store" / "mod.py"
    target.parent.mkdir()
    target.write_text("x = 1\n")
    os.chmod(target, 0o664)
    os.symlink(target, site / "mod.py")
    assert selfcheck.check_python(_places(venv)), "the linked file is not judged"
    selfcheck.fix_modes(_places(venv), scripts=(), package_dir=str(site / "phiward"))
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644
    assert selfcheck.check_python(_places(venv)) == []


def test_a_sitecustomize_in_a_folder_a_pth_adds_is_refused_with_its_step(home):
    pipx = home / ".local" / "share" / "pipx"
    venv = pipx / "venvs" / "phiward"
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /x/bin\ninclude-system-site-packages = false\n")
    shared = pipx / "shared" / "lib" / "python3.12" / "site-packages"
    shared.mkdir(parents=True)
    (site / "pipx_shared.pth").write_text(str(shared) + "\n")
    (shared / "sitecustomize.py").write_text("print('hi')\n")
    places = selfcheck.python_places(str(venv / "bin" / "python"), stdlib="", dynload="",
                                     libpython="")
    problems = selfcheck.check_python(places)
    want = ("~/.local/share/pipx/shared/lib/python3.12/site-packages/sitecustomize.py: "
            "a start-up file in a folder a .pth adds")
    assert want in problems, problems
    text = selfcheck.fix_text(problems, "")
    assert "remove ~/.local/share/pipx/shared/lib/python3.12/site-packages/sitecustomize.py" in \
        text and "reinstall" not in text, text


def test_a_pth_name_with_a_colon_is_excluded_from_the_walk(tree, home):
    venv, site = _venv(home)
    outside = tree / "elsewhere"
    outside.mkdir()
    (site / "a:b.pth").write_text(str(outside) + "\n")
    assert selfcheck._startup_files(str(site)) == ["a:b.pth: adds a folder outside phiward's Python"]
    assert selfcheck._pth_targets(str(site)) == []
