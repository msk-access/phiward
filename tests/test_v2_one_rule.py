"""One rule for "another account can change it", used by phiward's self-check, the broker's PATH
and the launcher lookup (round 4): a path is safe when it, and each folder above it, is owned by
the user or root and not writable by group or other. Inside the home folder the walk stops at the
home folder; outside it, it goes up to `/`, where a sticky folder (`/tmp`) is fine when the entry
below it is the user's or root's. A link is judged by the folder it is in, then by its target.
The one exception: Homebrew's own folders of the macOS `admin` group. The private-group guesses
(ACLs, other accounts of the group) are gone: they could not be made reliable. Made-up trees
only."""

import base64
import hashlib
import os
import stat
import types

import pytest

from phiward import selfcheck, service
from helpers import write_file


def _st(mode, gid=4242, uid=None, kind=stat.S_IFDIR):
    return types.SimpleNamespace(st_mode=kind | mode, st_gid=gid,
                                 st_uid=os.getuid() if uid is None else uid)


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


# --- the bits ------------------------------------------------------------------------------------

def test_the_group_bit_counts_even_for_the_users_own_primary_group(monkeypatch):
    import grp
    import pwd
    me = types.SimpleNamespace(pw_name="tester", pw_gid=4242, pw_dir="/x")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: me)
    monkeypatch.setattr(grp, "getgrgid", lambda g: types.SimpleNamespace(gr_name="tester",
                                                                          gr_mem=[]))
    assert selfcheck.foreign_writable(_st(0o775))
    assert selfcheck.foreign_writable(_st(0o757))
    assert not selfcheck.foreign_writable(_st(0o755))


def test_the_guesses_about_a_private_group_are_gone():
    for name in ("_private_group", "_sole_group", "_extended_acl"):
        assert not hasattr(selfcheck, name), name


# --- the folders above ---------------------------------------------------------------------------

def test_a_group_writable_folder_above_inside_home_is_refused(home):
    f = write_file(home / ".local" / "share" / "x.py")
    os.chmod(home / ".local", 0o775)
    why = selfcheck.safe_path(str(f))
    assert why and ".local/" in why and why.endswith("writable by others"), why
    os.chmod(home / ".local", 0o755)
    assert selfcheck.safe_path(str(f)) is None


def test_the_walk_stops_at_the_home_folder(home):
    f = write_file(home / "x.py")
    above = home.parent
    os.chmod(above, 0o775)
    try:
        assert selfcheck.safe_path(str(f)) is None
    finally:
        os.chmod(above, 0o755)


def test_a_group_writable_home_folder_is_named_as_such(home):
    f = write_file(home / ".local" / "x.py")
    os.chmod(home, 0o775)
    try:
        assert selfcheck.safe_path(str(f)) == selfcheck.HOME_PROBLEM
    finally:
        os.chmod(home, 0o755)


def test_outside_home_a_sticky_folder_is_fine_and_an_open_one_is_not(tree, home):
    sticky = tree / "tmpish"
    sticky.mkdir()
    os.chmod(sticky, 0o1777)
    f = write_file(sticky / "mine" / "f.py")
    os.chmod(sticky / "mine", 0o755)
    assert selfcheck.safe_path(str(f)) is None
    opened = tree / "open"
    opened.mkdir()
    os.chmod(opened, 0o777)
    g = write_file(opened / "g.py")
    why = selfcheck.safe_path(str(g))
    # round 5: a folder of yours outside home gets its own marker and the chmod step
    assert why and "open/" in why and why.endswith(selfcheck.OUTSIDE_MINE), why
    assert f"chmod go-w {opened}" in selfcheck.fix_text([why], "")  # the folder alone (round 6)


def test_a_parent_owned_by_another_user_is_refused(home, monkeypatch):
    f = write_file(home / "a" / "f.py")
    _patch_lstat(monkeypatch, home / "a", st_uid=os.getuid() + 12345 or 1)
    why = selfcheck.safe_path(str(f))
    assert why and "a/" in why and "owned by another user" in why, why


def test_a_file_owned_by_another_user_is_refused(home, monkeypatch):
    f = write_file(home / "f.py")
    _patch_lstat(monkeypatch, f, st_uid=os.getuid() + 12345 or 1)
    assert selfcheck.safe_path(str(f)) == "owned by another user"


def test_a_link_is_judged_by_its_folder_then_by_its_target(home, monkeypatch):
    target = write_file(home / "real" / "python3")
    (home / "bin").mkdir()
    link = home / "bin" / "python"
    os.symlink(target, link)
    assert selfcheck.safe_path(str(link)) is None
    # a link's own mode never counts (on Linux every link shows 0777)
    _patch_lstat(monkeypatch, link, st_mode=stat.S_IFLNK | 0o777)
    assert selfcheck.safe_path(str(link)) is None


def test_a_link_into_an_open_folder_is_refused(home):
    target = write_file(home / "open" / "python3")
    os.chmod(home / "open", 0o775)
    link = home / "python"
    os.symlink(target, link)
    why = selfcheck.safe_path(str(link))
    assert why and "open/" in why, why


def test_a_link_in_an_open_folder_is_refused(home):
    target = write_file(home / "real" / "python3")
    (home / "bin").mkdir()
    os.chmod(home / "bin", 0o775)
    link = home / "bin" / "python"
    os.symlink(target, link)
    why = selfcheck.safe_path(str(link))
    assert why and "bin/" in why, why


def test_homebrews_admin_folders_are_the_one_exception(monkeypatch):
    import grp
    import sys
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(grp, "getgrgid", lambda g: types.SimpleNamespace(gr_name="admin",
                                                                          gr_mem=[]))
    st = _st(0o775)
    assert selfcheck._homebrew_admin("/opt/homebrew/bin", st)
    assert selfcheck._homebrew_admin("/opt/homebrew", st)
    assert selfcheck._homebrew_admin("/usr/local/lib", st)
    assert not selfcheck._homebrew_admin("/opt/homebrewx/bin", st)
    assert not selfcheck._homebrew_admin("/opt/other/bin", st)
    assert not selfcheck._homebrew_admin("/opt/homebrew/bin", _st(0o777))
    assert not selfcheck._homebrew_admin("/opt/homebrew/bin", _st(0o775, uid=os.getuid() + 7))
    monkeypatch.setattr(grp, "getgrgid", lambda g: types.SimpleNamespace(gr_name="staff",
                                                                          gr_mem=[]))
    assert not selfcheck._homebrew_admin("/opt/homebrew/bin", st)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(grp, "getgrgid", lambda g: types.SimpleNamespace(gr_name="admin",
                                                                          gr_mem=[]))
    assert not selfcheck._homebrew_admin("/opt/homebrew/bin", st)


# --- the files that run at start -----------------------------------------------------------------

def _site(home):
    venv = home / ".local" / "share" / "uv" / "tools" / "phiward"
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /x/bin\ninclude-system-site-packages = false\n")
    return venv, site


def test_a_pth_that_runs_code_is_refused_unless_it_is_a_known_one(home):
    _venv, site = _site(home)
    (site / "evil.pth").write_text("import os; os.system('x')\n")
    (site / "_virtualenv.pth").write_text("import _virtualenv\n")
    assert selfcheck._startup_files(str(site)) == ["evil.pth: runs code at start"]


def test_a_record_that_lists_a_pth_does_not_make_it_trusted(home):
    _venv, site = _site(home)
    body = b"import os\n"
    (site / "x.pth").write_bytes(body)
    info = site / "x-1.0.dist-info"
    info.mkdir()
    h = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
    (info / "RECORD").write_text(f"x.pth,sha256={h},{len(body)}\n")
    assert selfcheck._startup_files(str(site)) == ["x.pth: runs code at start"]


def test_path_lines_must_stay_inside_phiwards_python(tree, home):
    venv, site = _site(home)
    (venv / "extra").mkdir()
    # round 5: pipx's shared folder counts only for a pipx venv (its own test below)
    (site / "a.pth").write_text(str(venv / "extra") + "\n")
    (site / "rel.pth").write_text("../../../extra\n")
    (site / "b.pth").write_text("# a comment\n\n" + str(tree / "repo") + "\n")
    assert selfcheck._startup_files(str(site)) == [
        "b.pth: adds a folder outside phiward's Python"]


def test_a_sitecustomize_in_the_site_folder_is_refused(home):
    _venv, site = _site(home)
    (site / "sitecustomize.py").write_text("x = 1\n")
    assert selfcheck._startup_files(str(site)) == ["sitecustomize.py: a start-up file"]


# --- one step for each kind of problem -----------------------------------------------------------

INSTALL = "phiward install claude --user --write"


def test_a_mode_problem_is_fixed_by_install():
    text = selfcheck.fix_text(["cli.py: writable by others"], "/x/site-packages/phiward")
    assert INSTALL in text and "reinstall" not in text and "chmod" not in text, text


def test_a_group_writable_home_folder_gets_chmod():
    text = selfcheck.fix_text([selfcheck.HOME_PROBLEM], "/x")
    assert "chmod go-w ~" in text and INSTALL not in text, text


def test_an_open_folder_outside_home_gets_install_under_home():
    text = selfcheck.fix_text([f"/opt/tools/: writable by others {selfcheck.OUTSIDE}"], "/x")
    assert "--python-preference only-managed" in text and INSTALL not in text, text


def test_a_changed_file_gets_reinstall():
    assert "reinstall" in selfcheck.fix_text(["cli.py: changed since install"], "/x")
    assert "reinstall" in selfcheck.fix_text(["evil.pth: runs code at start"], "/x")


def test_several_kinds_give_one_step_the_home_folder_first():
    problems = ["cli.py: writable by others", "x.py: changed since install",
                selfcheck.HOME_PROBLEM, f"/opt/t/: writable by others {selfcheck.OUTSIDE}"]
    text = selfcheck.fix_text(problems, "/x")
    assert "chmod go-w ~" in text
    assert INSTALL not in text and "reinstall" not in text and "only-managed" not in text
    text = selfcheck.fix_text(problems[:2] + problems[3:], "/x")
    assert "only-managed" in text and "reinstall" not in text
    assert "reinstall" in selfcheck.fix_text(problems[:2], "/x")


# --- the broker's PATH ---------------------------------------------------------------------------

def test_the_broker_drops_a_path_folder_below_an_open_folder_and_keeps_it_once_fixed(
        home, monkeypatch):
    b = home / ".local" / "bin"
    b.mkdir(parents=True)
    os.chmod(home / ".local", 0o775)
    monkeypatch.chdir(home)
    assert str(b) not in service._safe_path_entries(str(b))
    os.chmod(home / ".local", 0o755)
    assert str(b) in service._safe_path_entries(str(b))


def test_the_broker_drops_a_group_writable_path_folder(home, monkeypatch):
    b = home / "bin"
    b.mkdir()
    os.chmod(b, 0o775)
    monkeypatch.chdir(home)
    assert str(b) not in service._safe_path_entries(str(b))


def test_the_self_check_refuses_a_group_writable_package_file(tree, home):
    f = write_file(home / "site" / "phiward" / "cli.py", mode=0o664)
    assert [w for w, _p in selfcheck._owner_or_mode_faults(str(f))] == ["writable by others"]
    os.chmod(f, 0o644)
    assert selfcheck._owner_or_mode_faults(str(f)) == []


# --- round 5: the walk follows the path as the kernel does, and knows home by identity ----------

def _pw(monkeypatch, pw_dir):
    import pwd
    real = pwd.getpwuid

    def fake(uid):
        e = real(uid)
        return types.SimpleNamespace(pw_name=e.pw_name, pw_gid=e.pw_gid, pw_dir=str(pw_dir))
    monkeypatch.setattr(pwd, "getpwuid", fake)


def test_a_home_folder_reached_through_a_link_is_still_home(tree, monkeypatch):
    real = tree / "realhome"
    real.mkdir()
    os.chmod(real, 0o755)
    link = tree / "linkhome"
    os.symlink(real, link)
    _pw(monkeypatch, link)
    f = write_file(link / ".local" / "x.py")
    os.chmod(real / ".local", 0o775)
    assert selfcheck.safe_path(str(f)) == "~/.local/: writable by others"
    os.chmod(real / ".local", 0o755)
    os.chmod(real, 0o775)
    try:
        why = selfcheck.safe_path(str(f))
        assert why == selfcheck.HOME_PROBLEM, why
        assert "chmod go-w ~" in selfcheck.fix_text([why], "")
    finally:
        os.chmod(real, 0o755)


def test_a_folder_above_home_owned_by_another_user_is_skipped_only_on_the_way_home(
        tree, monkeypatch):
    lab = tree / "lab"
    (lab / "u").mkdir(parents=True)
    _pw(monkeypatch, lab / "u")
    mine = write_file(lab / "u" / "bin" / "x")
    other = write_file(lab / "tools" / "bin" / "x")
    _patch_lstat(monkeypatch, lab, st_uid=os.getuid() + 12345)
    assert selfcheck.safe_path(str(mine)) is None
    why = selfcheck.safe_path(str(other))
    assert why and "lab/" in why and "owned by another user" in why, why


def test_a_group_writable_folder_above_home_counts_off_the_way_home(tree, monkeypatch):
    lab = tree / "lab"
    (lab / "u").mkdir(parents=True)
    _pw(monkeypatch, lab / "u")
    mine = write_file(lab / "u" / "x")
    other = write_file(lab / "tools" / "x")
    os.chmod(lab, 0o2775)
    try:
        assert selfcheck.safe_path(str(mine)) is None
        why = selfcheck.safe_path(str(other))
        assert why and "lab/" in why and "writable by others" in why, why
    finally:
        os.chmod(lab, 0o755)


def test_the_folder_of_a_middle_link_is_judged(home):
    real = write_file(home / "real" / "prog", mode=0o755)
    w = home / "W"
    w.mkdir()
    os.symlink(real, w / "link2")
    (home / "ok").mkdir()
    os.symlink(w / "link2", home / "ok" / "link1")
    os.symlink(home / "real", w / "dlink")
    os.symlink(w / "dlink", home / "ok" / "dl")
    assert selfcheck.safe_path(str(home / "ok" / "link1")) is None
    os.chmod(w, 0o777)
    try:
        for p in (home / "ok" / "link1", home / "ok" / "dl" / "prog"):
            why = selfcheck.safe_path(str(p))
            assert why and "W/" in why, (p, why)
    finally:
        os.chmod(w, 0o755)


def test_a_deep_path_is_not_too_many_links_but_a_long_chain_is(home):
    d = home
    for i in range(80):
        d = d / f"d{i}"
    f = write_file(d / "x.py")
    assert selfcheck.safe_path(str(f)) is None
    target = write_file(home / "t.py")
    prev = target
    for i in range(41):
        ln = home / f"l{i}"
        os.symlink(prev, ln)
        prev = ln
    assert selfcheck.safe_path(str(prev)) == "too many links"


def test_dot_dot_after_a_link_is_judged_where_the_kernel_goes(home):
    # x -> a/b/c; x/../y is a/b/y for the kernel, not ./y
    (home / "a" / "b" / "c").mkdir(parents=True)
    os.symlink(home / "a" / "b" / "c", home / "x")
    y = write_file(home / "a" / "b" / "y")
    write_file(home / "y")
    os.chmod(home / "a" / "b", 0o775)
    try:
        why = selfcheck.safe_path(str(home / "x") + "/../y")
        assert why and "a/b/" in why, why
    finally:
        os.chmod(home / "a" / "b", 0o755)
    assert y.exists()


def test_a_sticky_folder_itself_is_refused_and_tmp_is_not_on_the_broker_path(tree, home,
                                                                             monkeypatch):
    sticky = tree / "tmpish"
    sticky.mkdir()
    os.chmod(sticky, 0o1777)
    assert selfcheck.safe_path(str(sticky)) is not None
    monkeypatch.chdir(home)
    assert service._safe_path_entries(str(sticky)) == []
    assert service._safe_path_entries("/tmp") == []


# --- round 5: .pth files are plain ASCII, read as site.py reads them, judged where they lead -----

@pytest.mark.parametrize("body", [
    b"\xef\xbb\xbfimport os\n",          # a byte-order mark hides the import line from a utf-8 read
    b"#x\x0cimport os\n",                # splitlines() makes \x0c a line break on 3.12.16 and 3.13
    "/café\n".encode(),             # not ASCII
])
def test_a_pth_python_could_read_differently_is_refused(home, body):
    _venv, site = _site(home)
    (site / "x.pth").write_bytes(body)
    problems = selfcheck._startup_files(str(site))
    assert problems and problems[0].startswith("x.pth:"), problems


def test_a_pth_over_the_size_limit_is_refused(home):
    _venv, site = _site(home)
    (site / "big.pth").write_bytes(b"# x\n" * (300 * 1024))
    assert selfcheck._startup_files(str(site)) == ["big.pth: too large to be checked"]


def test_a_link_then_dot_dot_in_a_pth_is_judged_where_python_goes(tree, home):
    venv, site = _site(home)
    deep = venv / "a" / "b" / "c" / "d" / "e" / "f"
    deep.mkdir(parents=True)
    os.symlink(deep, site / "L")
    # Python puts abspath(join(site, line)) on sys.path, lexically: here ~/.local/share/uv/tools/
    # evil, outside the venv. Following L first (realpath) would land in venv/a/evil, inside
    (venv.parent / "evil").mkdir()
    (venv / "a" / "evil").mkdir()
    (site / "x.pth").write_text("L/../../../../../evil\n")
    problems = selfcheck._startup_files(str(site))
    assert problems == ["x.pth: adds a folder outside phiward's Python"], problems
    assert selfcheck._pth_targets(str(site)) == []


def test_a_pipx_shaped_folder_elsewhere_is_not_pipxs(tree, home):
    _venv, site = _site(home)
    fake = tree / "repo" / "pipx" / "shared" / "lib" / "python3.12" / "site-packages"
    fake.mkdir(parents=True)
    (site / "x.pth").write_text(str(fake) + "\n")
    assert selfcheck._startup_files(str(site)) == ["x.pth: adds a folder outside phiward's Python"]


def test_pipxs_own_shared_folder_is_accepted_and_walked(home):
    pipx = home / ".local" / "share" / "pipx"
    venv = pipx / "venvs" / "phiward"
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /x/bin\ninclude-system-site-packages = false\n")
    shared = pipx / "shared" / "lib" / "python3.12" / "site-packages"
    shared.mkdir(parents=True)
    (site / "pipx_shared.pth").write_text(str(shared) + "\n")
    assert selfcheck._startup_files(str(site)) == []
    assert selfcheck._pth_targets(str(site)) == [str(shared)]
