"""The self-check's steps fix what the check names, in one round (round 7): a Python of yours
outside the home folder gets one `chmod go-w` for the single faults and one `find` per tree,
whatever the umask made; `install` fixes what the check names of a link (every folder of a chain,
the deepest folder of a dangling one); start-up code in any importable form, a zip on a .pth line
and a venv that reads the base Python's site folders are refused; the reinstall step names the
tool that installed phiward; the broker's PATH leaves out a temp folder inside the home folder.
Made-up trees only."""

import os
import pathlib
import re
import stat
import subprocess

import pytest

from phiward import __version__, claude_settings, mcp_config, selfcheck, service
from helpers import write_file


def _outside_python(tree, n=120):
    """A Python of yours outside the home folder, as umask 002 makes it: a stdlib root with n
    group-writable files, its own site-packages (not phiward's), and the interpreter."""
    top = tree / "opt" / "py"
    std = top / "lib" / "python3.12"
    for i in range(n):
        write_file(std / f"m{i // 10}" / f"f{i}.py", mode=0o664)
    write_file(std / "site-packages" / "other.py", mode=0o664)
    exe = write_file(top / "bin" / "python3.12", mode=0o775, text="#!fake\n")
    for d in (top, top / "bin", top / "lib", std) + tuple(std.glob("m*")):
        os.chmod(d, 0o775)
    return top, std, exe


def _run_step(text):
    """Run every command in backticks of a step, as the operator would."""
    cmds = [c for c in re.findall(r"`([^`]+)`", text) if c.startswith(("chmod ", "(cd "))]
    assert cmds, text
    for cmd in cmds:
        subprocess.run(["sh", "-c", cmd], check=True)


# --- M: one round for a Python of yours outside home


def test_a_tree_of_yours_outside_home_is_one_line_and_one_round(tree, home):
    top, std, exe = _outside_python(tree)
    places = selfcheck.Places("", [str(std)], [str(exe)], "", str(std))
    problems = selfcheck.check_python(places)
    assert "and more" not in problems, problems
    assert any(p.startswith(f"{std}/: ") and selfcheck.TREE_WHY in p for p in problems), problems
    # the way folders above the root and the interpreter come in the same round
    assert any(p.startswith(f"{top}/: writable by others") for p in problems), problems
    assert any(p.startswith(f"{exe}: writable by others") for p in problems), problems
    text = selfcheck.fix_text(problems, "")
    assert "-R" not in text and "find ." in text, text
    _run_step(text)
    assert selfcheck.check_python(places) == []
    # the base Python's own site-packages is not phiward's, and the step left it as it was
    assert stat.S_IMODE(os.stat(std / "site-packages" / "other.py").st_mode) == 0o664


def test_the_tree_step_reads_a_root_with_glob_characters_and_spaces(tree, home):
    std = tree / "opt" / "a [b]*" / "lib"
    write_file(std / "x.py", mode=0o664)
    write_file(std / "site-packages" / "keep.py", mode=0o664)
    places = selfcheck.Places("", [str(std)], [], "", str(std))
    _run_step(selfcheck.fix_text(selfcheck.check_python(places), ""))
    assert selfcheck.check_python(places) == []
    assert stat.S_IMODE(os.stat(std / "site-packages" / "keep.py").st_mode) == 0o664


def test_the_tree_step_follows_a_linked_root(tree, home):
    real = tree / "opt" / "venv-1.2"
    write_file(real / "lib" / "x.py", mode=0o664)
    link = tree / "opt" / "venv"
    os.symlink(real, link)
    places = selfcheck.Places(str(link), [str(link)], [], "", "")
    problems = selfcheck.check_python(places)
    assert problems, "the linked root's tree is not judged"
    _run_step(selfcheck.fix_text(problems, ""))
    assert selfcheck.check_python(places) == []


def test_the_tree_step_names_your_uid_without_a_substitution(tree, home):
    _top, std, _exe = _outside_python(tree, n=3)
    text = selfcheck.fix_text(selfcheck.check_python(selfcheck.Places("", [str(std)], [], "", str(std))), "")
    assert f"-user {os.getuid()}" in text and "$(" not in text, text


def test_a_failing_root_and_its_tree_come_in_one_round(tree, home):
    std = tree / "opt" / "lib2"
    write_file(std / "a.py", mode=0o664)
    os.chmod(std, 0o775)
    places = selfcheck.Places("", [str(std)], [], "", str(std))
    problems = selfcheck.check_python(places)
    assert any(selfcheck.TREE_WHY in p for p in problems), problems
    _run_step(selfcheck.fix_text(problems, ""))
    assert selfcheck.check_python(places) == []


def test_safe_path_still_stops_at_the_first_fault(tree, home):
    _top, std, _exe = _outside_python(tree, n=1)
    assert selfcheck.safe_path(str(std)) is not None


# --- L1: start-up code in any importable form


def _bare_venv(home):
    venv = home / "v"
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /x/bin\ninclude-system-site-packages = false\n")
    return venv, site


@pytest.mark.parametrize("name", ["sitecustomize.pyc", "sitecustomize", "usercustomize.abi3.so",
                                  "sitecustomize.cpython-312-darwin.so", "sitecustomize.py"])
def test_start_up_code_in_any_form_is_refused_in_a_site_folder(home, name):
    _venv, site = _bare_venv(home)
    p = site / name
    if "." in name:
        p.write_text("x")
    else:
        p.mkdir()
        (p / "__init__.py").write_text("x")
    assert [n for n, _why in selfcheck._startup_problems(str(site))] == [name]


def test_start_up_code_in_a_pth_target_is_refused_in_any_form(home):
    pipx = home / ".local" / "share" / "pipx"
    venv = pipx / "venvs" / "phiward"
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /x/bin\ninclude-system-site-packages = false\n")
    shared = pipx / "shared" / "lib" / "python3.12" / "site-packages"
    (shared / "sitecustomize").mkdir(parents=True)
    (site / "pipx_shared.pth").write_text(str(shared) + "\n")
    places = selfcheck.Places(str(venv), [str(venv)], [], str(venv / "pyvenv.cfg"), "")
    problems = selfcheck.check_python(places)
    assert any(p.endswith("sitecustomize: " + selfcheck.PTH_STARTUP) for p in problems), problems


def test_a_pth_line_to_a_zip_is_refused(home):
    _venv, site = _bare_venv(home)
    (site / "lib.zip").write_bytes(b"PK\x05\x06" + b"\0" * 18)
    (site / "a.pth").write_text("lib.zip\n")
    assert [n for n, _why in selfcheck._startup_problems(str(site))] == ["a.pth"]


def test_a_venv_that_reads_the_base_site_folders_is_refused(home):
    venv, _site = _bare_venv(home)
    places = selfcheck.Places(str(venv), [str(venv)], [], str(venv / "pyvenv.cfg"), "")
    (venv / "pyvenv.cfg").write_text("home = /x/bin\ninclude-system-site-packages = True\n")
    problems = selfcheck.check_python(places)
    assert any("pyvenv.cfg" in p for p in problems), problems
    assert "reinstall" in selfcheck.fix_text(problems, "")
    (venv / "pyvenv.cfg").write_text("home = /x/bin\ninclude-system-site-packages = false\n")
    assert selfcheck.check_python(places) == []


# --- L2, L3: install fixes what the check names of a link


def _site(home):
    venv = home / ".local" / "share" / "uv" / "tools" / "phiward"
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /x/bin\ninclude-system-site-packages = false\n")
    return selfcheck.Places(str(venv), [str(venv)], [], str(venv / "pyvenv.cfg"), ""), site


def test_install_fixes_every_folder_of_a_link_chain(home):
    places, site = _site(home)
    target = write_file(home / "t" / "f.py")
    (home / "l1").mkdir()
    os.symlink(target, home / "l1" / "b")
    os.symlink(home / "l1" / "b", site / "a.py")
    os.chmod(home / "l1", 0o775)
    assert selfcheck.check_python(places)
    selfcheck.fix_modes(places, scripts=(), package_dir=str(site / "phiward"))
    assert selfcheck.check_python(places) == []


def test_install_fixes_the_folder_a_dangling_link_would_land_in(home):
    places, site = _site(home)
    (home / "cache").mkdir()
    os.chmod(home / "cache", 0o775)
    os.symlink(home / "cache" / "later" / "x", site / "x.py")
    problems = selfcheck.check_python(places)
    assert problems == ["~/cache/: writable by others"], problems
    selfcheck.fix_modes(places, scripts=(), package_dir=str(site / "phiward"))
    assert selfcheck.check_python(places) == []


def test_a_linked_file_is_named_by_where_it_leads(home):
    places, site = _site(home)
    target = write_file(home / "store" / "mod.py", mode=0o664)
    os.symlink(target, site / "mod.py")
    assert selfcheck.check_python(places) == ["~/store/mod.py: writable by others"]


def test_a_group_writable_venv_folder_is_named_once(home):
    places, _site_ = _site(home)
    venv = places.venv
    os.chmod(venv, 0o775)
    places = selfcheck.Places(venv, [venv], [os.path.join(venv, "pyvenv.cfg")],
                              os.path.join(venv, "pyvenv.cfg"), "")
    problems = selfcheck.check_python(places)
    assert problems == ["~/.local/share/uv/tools/phiward/: writable by others"], problems


# --- L4: the reinstall step names the tool


def test_the_reinstall_step_names_the_tool_that_installed_phiward(home):
    v = __version__
    changed = ["cli.py: changed since install"]
    uv = home / ".local/share/uv/tools/phiward/lib/python3.12/site-packages/phiward"
    pipx = home / ".local/share/pipx/venvs/phiward/lib/python3.12/site-packages/phiward"
    for pkg in (uv, pipx):
        pkg.mkdir(parents=True)
        (pkg.parents[3] / "pyvenv.cfg").write_text("home = /x\ninclude-system-site-packages = false\n")
    # each tool's own file in its venv (round 8: the folder name alone is not read)
    (uv.parents[3] / "uv-receipt.toml").write_text("[tool]\n")
    (pipx.parents[3] / "pipx_metadata.json").write_text("{}\n")
    text = selfcheck.fix_text(changed, str(uv))
    assert f"`uv tool install --force --reinstall phiward=={v}`" in text, text
    text = selfcheck.fix_text(changed, str(pipx))
    assert f"`pipx reinstall phiward && pipx install --force phiward=={v}`" in text, text
    assert "the way you installed it" in selfcheck.fix_text(changed, "/elsewhere/phiward")


# --- L5


def test_a_home_folder_of_another_account_has_its_own_step():
    text = selfcheck.fix_text(["~/: owned by another user"], "")
    assert "reinstall" not in text and "another account" in text, text


def test_a_path_under_a_linked_home_is_shown_from_home(tree):
    real = tree / "realhome"
    (real / "x").mkdir(parents=True)
    link = tree / "linkhome"
    os.symlink(real, link)
    assert selfcheck._shown(str(real / "x" / "f.py"), str(link)) == "~/x/f.py"
    assert selfcheck._shown(str(link / "x" / "f.py"), str(link)) == "~/x/f.py"
    assert selfcheck._shown(str(pathlib.Path(tree) / "elsewhere"), str(link)) == \
        str(pathlib.Path(tree) / "elsewhere")


def test_a_temp_folder_inside_home_is_not_searched(tree, monkeypatch):
    home = tree / "home"
    monkeypatch.chdir(home)
    monkeypatch.setenv("HOME", str(home))
    tmp = home / "tmp"
    (tmp / "bin").mkdir(parents=True)
    local = home / ".local" / "bin"
    local.mkdir(parents=True)
    monkeypatch.setattr(claude_settings, "_temp_roots", lambda: [str(tmp)])
    assert service._safe_path_entries(f"{tmp / 'bin'}:{local}") == [str(local)]
    # TMPDIR=$HOME: the home folder's own PATH folders stay
    monkeypatch.setattr(claude_settings, "_temp_roots", lambda: [str(home)])
    assert service._safe_path_entries(str(local)) == [str(local)]


def test_the_launcher_cache_sees_a_new_allow_write(tree, monkeypatch):
    home = tree / "home"
    monkeypatch.chdir(home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    tools = home / "tools"
    exe = write_file(tools / "phiward", mode=0o755, text="#!/bin/sh\n")
    mcp_config._launcher_exes.cache_clear()
    try:
        assert os.path.realpath(exe) in mcp_config._launcher_exes(str(tools))
        (home / ".claude").mkdir(exist_ok=True)
        (home / ".claude" / "settings.json").write_text(
            '{"sandbox": {"filesystem": {"allowWrite": ["~/tools"]}}}')
        assert os.path.realpath(exe) not in mcp_config._launcher_exes(str(tools))
    finally:
        mcp_config._launcher_exes.cache_clear()


def test_many_faults_inside_home_do_not_hide_the_step_outside_it(tree, home):
    # umask 002 with a pipx venv in home on a Python of yours outside it: the venv's many
    # group-writable files (install fixes them) come after the lines the step needs first
    _top, std, exe = _outside_python(tree, n=5)
    venv = home / "venv"
    for i in range(80):
        write_file(venv / f"f{i}.py", mode=0o664)
    places = selfcheck.Places(str(venv), [str(venv), str(std)], [str(exe)], "", str(std))
    problems = selfcheck.check_python(places)
    assert problems[-1] == "and more" and len(problems) == selfcheck.MAX_PROBLEMS + 1
    assert any(selfcheck.TREE_WHY in p for p in problems), problems
    assert "find ." in selfcheck.fix_text(problems, "")
