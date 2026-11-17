"""Every problem of the self-check names where the fault is, and whether that place is inside the
home folder, from the walk itself (round 6). A folder inside home that a venv's linked
interpreter passes through is inside home, whatever the interpreter leads to; a fault outside
home always carries its path and its marker, so the step is right: install inside home, uv's own
Python for something another account owns or can write, `chmod go-w` on exactly the faults that
are yours. Made-up trees only."""

import base64
import hashlib
import os
import shlex
import types


from phiward import selfcheck
from helpers import write_file

INSTALL = "phiward install claude --user --write"


def _patch_lstat(monkeypatch, path, **changes):
    real = os.lstat

    def fake(p, *a, **k):
        st = real(p, *a, **k)
        if os.fspath(p) == str(path):
            vals = {"st_mode": st.st_mode, "st_uid": st.st_uid, "st_gid": st.st_gid,
                    "st_dev": st.st_dev, "st_ino": st.st_ino}
            vals.update(changes)
            return types.SimpleNamespace(**vals)
        return st
    monkeypatch.setattr(os, "lstat", fake)


def _venv_on_outside_python(tree, home):
    """A pipx-like venv inside home whose interpreter links to a Python outside home."""
    outside_py = write_file(tree / "usr" / "bin" / "python3.12", mode=0o755, text="#!fake\n")
    venv = home / ".local" / "pipx" / "venvs" / "phiward"
    (venv / "bin").mkdir(parents=True)
    os.symlink(outside_py, venv / "bin" / "python")
    write_file(venv / "pyvenv.cfg", text=f"home = {outside_py.parent}\ninclude-system-site-packages = false\n")
    write_file(venv / "lib" / "python3.12" / "site-packages" / "phiward" / "__init__.py")
    return selfcheck.Places(str(venv), [str(venv)], [str(venv / "bin" / "python"),
                                                     str(outside_py), str(venv / "pyvenv.cfg")],
                            str(venv / "pyvenv.cfg"), "")


def test_a_folder_inside_home_is_inside_home_whatever_the_interpreter_leads_to(tree, home):
    places = _venv_on_outside_python(tree, home)
    os.chmod(home / ".local", 0o775)
    problems = selfcheck.check_python(places)
    assert problems == ["~/.local/: writable by others"], problems
    text = selfcheck.fix_text(problems, "")
    assert INSTALL in text and "chmod" not in text, text


def test_a_link_outside_home_owned_by_another_user_says_so_once(tree, home, monkeypatch):
    target = write_file(tree / "opt" / "x" / "python3", mode=0o755)
    link = tree / "opt" / "x" / "l"
    os.symlink(target, link)
    real = os.path.realpath(link.parent) + "/l"
    _patch_lstat(monkeypatch, real, st_uid=os.getuid() + 12345)
    why = selfcheck.safe_path(real)
    assert why == f"{real}: owned by another user {selfcheck.OUTSIDE}", why
    problems = selfcheck.check_python(selfcheck.Places("", [], [real], "", ""))
    assert problems == [why], problems
    assert "--python-preference only-managed" in selfcheck.fix_text(problems, "")


def test_a_last_entry_outside_home_owned_by_another_user_gets_uvs_own_python(tree, home,
                                                                           monkeypatch):
    f = write_file(tree / "opt" / "py" / "bin" / "python3", mode=0o755)
    real = os.path.realpath(f)
    _patch_lstat(monkeypatch, real, st_uid=os.getuid() + 12345)
    why = selfcheck.safe_path(real)
    assert why == f"{real}: owned by another user {selfcheck.OUTSIDE}", why
    assert "--python-preference only-managed" in selfcheck.fix_text([why], "")


def test_a_last_entry_outside_home_of_yours_gets_chmod_on_it_alone(tree, home):
    f = write_file(tree / "opt" / "mine" / "python3", mode=0o775)
    real = os.path.realpath(f)
    why = selfcheck.safe_path(real)
    assert why == f"{real}: writable by others {selfcheck.OUTSIDE_MINE}", why
    text = selfcheck.fix_text([why], "")
    assert f"chmod go-w {shlex.quote(real)}" in text and "-R" not in text, text


def test_a_folder_outside_home_of_yours_gets_chmod_on_the_folder_alone(tree, home):
    d = tree / "work" / "proj1"
    f = write_file(d / "envs" / "py" / "python3")
    os.chmod(d, 0o2775)
    real = os.path.realpath(d)
    why = selfcheck.safe_path(str(f))
    assert why == f"{real}/: writable by others {selfcheck.OUTSIDE_MINE}", why
    text = selfcheck.fix_text([selfcheck._named("python3", why)], "")
    assert f"chmod go-w {shlex.quote(real)}" in text and "-R" not in text, text


def test_a_package_file_outside_home_names_its_path_not_its_name(tree, home):
    site = tree / "opt" / "site"
    f = write_file(site / "phiward" / "cli.py", mode=0o664)
    real = os.path.realpath(f)
    digest = base64.urlsafe_b64encode(hashlib.sha256(f.read_bytes()).digest()).rstrip(b"=")
    _installed, problems = selfcheck.check([(str(f), "sha256=" + digest.decode())])
    # a line that names its place is not prefixed with the file's name (round 8)
    assert problems == [f"{real}: writable by others {selfcheck.OUTSIDE_MINE}"], problems
    text = selfcheck.fix_text(problems, "")
    assert f"chmod go-w {shlex.quote(real)}" in text and INSTALL not in text, text


def test_a_path_with_a_colon_and_a_space_is_named_whole_and_quoted(tree, home):
    d = tree / "My Tools: v2"
    f = write_file(d / "lib" / "x.py")
    os.chmod(d, 0o775)
    real = os.path.realpath(d)
    why = selfcheck.safe_path(str(f))
    text = selfcheck.fix_text([selfcheck._named("x.py", why)], "")
    assert f"chmod go-w {shlex.quote(real)}" in text, text


def test_every_fault_of_yours_is_in_the_one_chmod(tree, home):
    a = os.path.realpath(write_file(tree / "o1" / "a.py", mode=0o664))
    b = os.path.realpath(write_file(tree / "o2" / "b.py", mode=0o664))
    problems = [selfcheck.safe_path(a), selfcheck.safe_path(b)]
    text = selfcheck.fix_text(problems, "")
    assert f"chmod go-w {shlex.quote(a)} {shlex.quote(b)}" in text, text


def test_one_line_per_fault_inside_home(tree, home):
    py = _venv_on_outside_python(tree, home)
    extra = write_file(home / ".local" / "other" / "x.py")
    os.chmod(home / ".local", 0o775)
    places = py._replace(files=py.files + [str(extra)])
    assert selfcheck.check_python(places) == ["~/.local/: writable by others"]


def test_an_entry_outside_home_under_a_walked_root_carries_its_place(tree, home):
    root = tree / "lab" / "py"
    write_file(root / "os.py", mode=0o664)
    problems = selfcheck.check_python(selfcheck.Places("", [str(root)], [], "", ""))
    # the entries of yours below a root outside home: one line for the tree (round 7)
    assert problems == [f"{root}/: 1 entry {selfcheck.TREE_WHY} {selfcheck.OUTSIDE_MINE}"], \
        problems


def test_inside_home_texts_are_unchanged(home):
    f = write_file(home / "x.py", mode=0o664)
    assert selfcheck.safe_path(str(f)) == "writable by others"
    (home / "d").mkdir()
    os.chmod(home / "d", 0o775)
    g = write_file(home / "d" / "y.py")
    assert selfcheck.safe_path(str(g)) == "~/d/: writable by others"
