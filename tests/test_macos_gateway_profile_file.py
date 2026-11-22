"""macOS: the gateway's profile is a file, `sandbox-exec -f FILE`, never `-p TEXT`.

The file is written to `~/.phiward/profiles`, which no session can write or read: a fresh name
per request, made with O_EXCL and O_NOFOLLOW, mode 0600, and removed when the request ends. The
folder is refused when `~/.phiward` is writable by other accounts, is a link or is another
account's; `profiles` is made private (0700). Static: the backend is set to Seatbelt and
`sandbox-exec` is a made-up recorder, so these run on every platform and start no real
sandbox. Made-up names only.
"""

import io
import os
import re
import stat
import time
from pathlib import Path

import pytest

import helpers
from phiward import config, confine, doctor, hidden, install, run
from phiward.sanitize import Sanitizer

NAME = re.compile(r"[0-9a-f]{32}\.sb")


@pytest.fixture()
def seatbelt(monkeypatch):
    monkeypatch.setattr(confine, "backend", lambda: "seatbelt")


@pytest.fixture()
def recorder(tree, monkeypatch, seatbelt):
    """A made-up `sandbox-exec`: it copies the profile file it is given to $REC, then runs the
    command (no sandbox)."""
    fake = tree / "bin-fake" / "sandbox-exec"
    fake.parent.mkdir()
    fake.write_text('#!/bin/sh\n[ "$1" = -f ] || exit 99\ncp "$2" "$REC" || exit 98\n'
                    'shift 2\nexec "$@"\n')
    fake.chmod(0o755)
    monkeypatch.setattr(confine, "SANDBOX_EXEC", str(fake))
    monkeypatch.setenv("REC", str(tree / "recorded.sb"))
    return tree / "recorded.sb"


def _folder(tree) -> Path:
    return tree / "home" / ".phiward" / "profiles"


def _argv(argv=("/usr/bin/true",)):
    return confine.gateway_command(list(argv), [], [], False)


# --- the argv and the file ---------------------------------------------------------------------

def test_the_gateway_names_a_profile_file_not_its_text(tree, seatbelt):
    argv, fds = _argv(["/usr/bin/true", "made-up"])
    assert fds == []
    assert argv[:2] == [confine.SANDBOX_EXEC, "-f"], argv
    assert argv[3:] == ["/usr/bin/true", "made-up"], argv
    assert "-p" not in argv
    p = Path(argv[2])
    assert p.parent == _folder(tree) and NAME.fullmatch(p.name), p
    st = os.lstat(p)
    assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
    assert st.st_uid == os.getuid() and st.st_nlink == 1
    assert p.read_text() == confine.seatbelt_gateway_profile([], [], False)


def test_each_request_gets_a_fresh_name(tree, seatbelt):
    a, _ = _argv()
    b, _ = _argv()
    assert a[2] != b[2]


def test_existing_0755_folders_work_and_profiles_ends_private(tree, seatbelt):
    base = tree / "home" / ".phiward"
    (base / "profiles").mkdir(parents=True)
    base.chmod(0o755)
    (base / "profiles").chmod(0o755)
    argv, _ = _argv()
    assert Path(argv[2]).exists()
    assert stat.S_IMODE(os.lstat(base / "profiles").st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(base).st_mode) == 0o755  # the operator's folder is not changed


def test_a_missing_folder_is_made_private(tree, seatbelt):
    argv, _ = _argv()
    assert stat.S_IMODE(os.lstat(_folder(tree)).st_mode) == 0o700
    assert stat.S_IMODE(os.lstat(_folder(tree).parent).st_mode) == 0o700


# --- refused -----------------------------------------------------------------------------------

@pytest.mark.parametrize("mode", [0o775, 0o757, 0o777])
def test_a_phiward_folder_others_can_write_is_refused(tree, seatbelt, mode):
    base = tree / "home" / ".phiward"
    base.mkdir()
    base.chmod(mode)
    try:
        with pytest.raises(confine.ConfineError, match="other accounts can write"):
            _argv()
    finally:
        base.chmod(0o700)
    assert not (base / "profiles").exists() or not os.listdir(base / "profiles")


def test_a_linked_phiward_folder_is_refused(tree, seatbelt):
    elsewhere = tree / "pub" / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, tree / "home" / ".phiward")
    with pytest.raises(confine.ConfineError, match="a link"):
        _argv()
    assert not os.listdir(elsewhere)


def test_a_linked_profiles_folder_is_refused(tree, seatbelt):
    base = tree / "home" / ".phiward"
    base.mkdir(mode=0o700)
    elsewhere = tree / "pub" / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, base / "profiles")
    with pytest.raises(confine.ConfineError, match="a link"):
        _argv()
    assert not os.listdir(elsewhere)


def _other_owner(monkeypatch, path):
    """fstat says `path` is another account's (made up: the test cannot chown)."""
    want = os.lstat(path)
    real = os.fstat

    def fake(fd):
        st = real(fd)
        if (st.st_dev, st.st_ino) == (want.st_dev, want.st_ino):
            fields = list(st)
            fields[4] = os.getuid() + 1
            return os.stat_result(fields)
        return st
    monkeypatch.setattr(os, "fstat", fake)


def test_a_phiward_folder_of_another_account_is_refused(tree, seatbelt, monkeypatch):
    base = tree / "home" / ".phiward"
    base.mkdir(mode=0o700)
    _other_owner(monkeypatch, base)
    with pytest.raises(confine.ConfineError, match="another account"):
        _argv()


def test_a_profiles_folder_of_another_account_is_refused(tree, seatbelt, monkeypatch):
    (tree / "home" / ".phiward" / "profiles").mkdir(parents=True, mode=0o700)
    _other_owner(monkeypatch, _folder(tree))
    with pytest.raises(confine.ConfineError, match="another account"):
        _argv()


@pytest.mark.parametrize("plant", ["file", "link", "fifo"])
def test_a_planted_name_is_refused_not_used(tree, seatbelt, monkeypatch, plant):
    _folder(tree).mkdir(parents=True, mode=0o700)
    name = "ab" * 16 + ".sb"
    monkeypatch.setattr(confine, "_profile_name", lambda: name)
    target = tree / "pub" / "target.sb"
    at = _folder(tree) / name
    if plant == "file":
        at.write_text("(version 1)(allow default)\n")
    elif plant == "link":
        os.symlink(target, at)
    else:
        os.mkfifo(at)
    with pytest.raises(confine.ConfineError, match="profile"):
        _argv()
    assert not target.exists()
    if plant == "file":
        assert at.read_text() == "(version 1)(allow default)\n"


# --- removed when the request ends -------------------------------------------------------------

def test_the_file_is_gone_after_a_request(tree, recorder):
    cfg = config.load(str(tree / "repo"))
    out = io.StringIO()
    code = run.run_confined(["/bin/echo", "made-up"], cfg, Sanitizer.from_config(cfg), [],
                            False, out)
    assert code == 0, out.getvalue()
    assert "(version 1)" in recorder.read_text()  # the recorder was given the profile file
    assert os.listdir(_folder(tree)) == []


def test_the_file_is_gone_when_the_command_cannot_start(tree, seatbelt, monkeypatch):
    monkeypatch.setattr(confine, "SANDBOX_EXEC", str(tree / "missing" / "sandbox-exec"))
    cfg = config.load(str(tree / "repo"))
    out = io.StringIO()
    code = run.run_confined(["/bin/echo", "made-up"], cfg, Sanitizer.from_config(cfg), [],
                            False, out)
    assert code == 127, out.getvalue()
    assert os.listdir(_folder(tree)) == []


def test_the_self_test_removes_its_file(tree, recorder):
    assert confine.self_test() is None
    assert recorder.exists()
    assert os.listdir(_folder(tree)) == []


def test_release_removes_only_a_profile_it_names(tree, seatbelt):
    argv, _ = _argv()
    keep = _folder(tree) / "notes.txt"
    keep.write_text("x\n")
    confine.release_profile(argv)
    assert os.listdir(_folder(tree)) == ["notes.txt"]
    confine.release_profile([confine.SANDBOX_EXEC, "-f", str(keep), "true"])
    assert keep.exists()


def test_old_files_are_pruned(tree, seatbelt):
    d = _folder(tree)
    d.mkdir(parents=True, mode=0o700)
    old = time.time() - 2 * 86400
    names = {"old": "1" * 32 + ".sb", "new": "2" * 32 + ".sb", "other": "notes.txt",
             "link": "3" * 32 + ".sb", "dir": "4" * 32 + ".sb"}
    (d / names["old"]).write_text("x")
    (d / names["new"]).write_text("x")
    (d / names["other"]).write_text("x")
    os.symlink(tree / "pub", d / names["link"])
    (d / names["dir"]).mkdir()
    for k in ("old", "other", "dir"):
        os.utime(d / names[k], (old, old))
    os.utime(d / names["link"], (old, old), follow_symlinks=False)
    confine.prune_profiles()
    assert sorted(os.listdir(d)) == sorted(n for k, n in names.items() if k != "old")


def test_prune_without_the_folder_does_nothing(tree, seatbelt):
    confine.prune_profiles()
    assert not (tree / "home" / ".phiward").exists()


# --- hidden from every session and gateway command ---------------------------------------------

def test_the_profiles_folder_is_on_the_hidden_list(tree):
    folder = os.path.join(os.environ["HOME"], ".phiward", "profiles")
    cfg = config.load(str(tree / "repo"))
    assert folder in hidden.paths(dict(os.environ), cfg)        # the gateway
    assert folder in hidden.paths(None, cfg, session=True)     # the hook and install
    assert folder in run.gateway_hidden(cfg)


def test_the_wiring_denies_reads_and_writes_of_the_profiles_folder(tree):
    cfg = config.load(str(tree / "repo"))
    w = install.wiring(cfg)
    fs = w["sandbox"]["filesystem"]
    assert any(d.endswith("/.phiward/profiles") for d in fs["denyRead"]), fs["denyRead"]
    assert any(d.endswith("/.phiward/profiles") for d in fs["denyWrite"]), fs["denyWrite"]
    deny = w["permissions"]["deny"]
    for rule in ("Read(~/.phiward/profiles)", "Read(~/.phiward/profiles/**)",
                 "Edit(~/.phiward/profiles)", "Edit(~/.phiward/profiles/**)"):
        assert rule in deny, rule


def test_doctor_warns_when_the_wiring_predates_the_profiles_folder(tree):
    cfg = config.load(str(tree / "repo"))
    w = install.wiring(cfg)
    fs = w["sandbox"]["filesystem"]
    fs["denyRead"] = [d for d in fs["denyRead"] if "/.phiward/profiles" not in d]
    w["permissions"]["deny"] = [r for r in w["permissions"]["deny"]
                                if ".phiward/profiles" not in r]
    helpers.user_settings(tree, w)
    _folder(tree).mkdir(parents=True, mode=0o700)
    text = "\n".join(doctor.mode_report(str(tree / "repo"), str(tree / "home"), cfg))
    assert "hidden list in the sandbox" in text
    line = [ln for ln in text.splitlines() if "hidden list in the sandbox" in ln][0]
    assert "WARNING" in line and "install claude --user" in line, line
    rules = [ln for ln in text.splitlines() if "permission rules for the hidden list" in ln][0]
    assert "WARNING" in rules, rules
