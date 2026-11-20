"""The Linux session's view while the host changes it during the start. Each test makes one
change at a fixed point between the listing of a folder and the start of bwrap, through a
patched function (a seam), never by timing. bwrap resolves each bind source to a name and mounts
that name, so a removed entry must be left out, and what is mounted must be what was checked.
Made-up trees only (conftest.py)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import config, wholetool
from helpers import CONFINE_WHY

SRC = str(Path(__file__).resolve().parents[1] / "src")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="bwrap's view: Linux")
linux_confined = pytest.mark.skipif(not sys.platform.startswith("linux") or CONFINE_WHY is not None,
                                    reason=f"Linux confinement: {CONFINE_WHY}")

# A child Python runs `phiward launch` with one change made at a seam:
#   listing: after the view is listed (hidden_view), before its entries are opened;
#   built:   after the command is built, before the launcher's last checks (project_state);
#   exec:    right before bwrap starts (Popen).
RUNNER = r"""
import json, os, subprocess, sys
from phiward import wholetool
seam, acts, code = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3]
done = []
def act():
    if done:
        return
    done.append(1)
    for a in acts:
        if a[0] == "rmdir":
            os.rmdir(a[1])
        elif a[0] == "unlink":
            os.unlink(a[1])
        elif a[0] == "rename":
            os.rename(a[1], a[2])
        elif a[0] == "symlink":
            os.symlink(a[1], a[2])
        elif a[0] == "mkdir":
            os.mkdir(a[1])
if seam == "listing":
    real_view = wholetool.hidden_view
    def view(*a, **k):
        out = real_view(*a, **k)
        act()
        return out
    wholetool.hidden_view = view
elif seam == "checks":
    def failing(*a, **k):
        raise UnicodeEncodeError("utf-8", "x", 0, 1, "seam")
    wholetool._write_checks = failing
elif seam == "built":
    real_state = wholetool.carryover.project_state
    def state(*a, **k):
        act()
        return real_state(*a, **k)
    wholetool.carryover.project_state = state
else:
    real_popen = subprocess.Popen
    def popen(cmd, *a, **k):
        if isinstance(cmd, list) and cmd and os.path.basename(cmd[0]) == "bwrap":
            act()
        return real_popen(cmd, *a, **k)
    subprocess.Popen = popen
sys.exit(wholetool.main(sys.argv[4:] + ["--", sys.executable, "-c", code]))
"""


def launch_with(tree, seam, acts, code, opts=()):
    r = subprocess.run([sys.executable, "-c", RUNNER, seam, json.dumps(acts), code, *opts],
                       cwd=str(tree / "repo"), env=dict(os.environ, PYTHONPATH=SRC),
                       capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout, r.stderr


def probe(*paths):
    """Tool code: RAN, then for each path whether it exists (not followed) and what it holds."""
    return ("import os\nprint('RAN')\n"
            f"for p in {[str(p) for p in paths]!r}:\n"
            "    out = None\n"
            "    if os.path.isdir(p):\n"
            "        out = sorted(os.listdir(p))\n"
            "        for n in out:\n"
            "            try:\n"
            "                print(open(os.path.join(p, n)).read())\n"
            "            except OSError:\n"
            "                pass\n"
            "    elif os.path.lexists(p):\n"
            "        try:\n"
            "            out = open(p).read()\n"
            "        except OSError as e:\n"
            "            out = 'unreadable'\n"
            "    print('SEEN', p, out)\n")


# --- an entry removed while the session starts: left out, the tool runs ---------------------------

@linux_confined
def test_r1_an_entry_removed_right_before_bwrap_starts_is_left_out(tree):
    (tree / "vanish").mkdir()
    code, out, err = launch_with(tree, "exec", [["rmdir", str(tree / "vanish")]],
                                 probe(tree / "vanish", tree / "pub"))
    assert "RAN" in out, err
    assert f"SEEN {tree / 'vanish'} None" in out and f"SEEN {tree / 'pub'} []" in out, out


@linux_confined
def test_r3_an_entry_removed_between_the_listing_and_the_build_is_left_out(tree):
    (tree / "vanish").mkdir()
    code, out, err = launch_with(tree, "listing", [["rmdir", str(tree / "vanish")]],
                                 probe(tree / "vanish"))
    assert "RAN" in out, err
    assert f"SEEN {tree / 'vanish'} None" in out, out


# --- an entry replaced by a link: never followed --------------------------------------------------

@linux_confined
def test_r4_an_entry_replaced_by_a_link_after_the_listing_is_left_out(tree):
    swap = tree / "swap.txt"
    swap.write_text("plain\n")
    code, out, err = launch_with(tree, "listing",
                                 [["unlink", str(swap)],
                                  ["symlink", str(tree / "phi" / "FAKE-PT-0001.bam"), str(swap)]],
                                 probe(swap))
    assert "SECRET" not in out + err, out
    assert "RAN" in out and f"SEEN {swap} None" in out, (out, err)


@linux_confined
def test_r5_an_entry_replaced_by_a_link_right_before_bwrap_starts_never_shows_its_target(tree):
    # bwrap mounts by name: a link put at the name after the last check would be followed
    pub = tree / "pub"
    (pub / "MARK.txt").write_text("mark\n")
    code, out, err = launch_with(tree, "exec",
                                 [["rename", str(pub), str(tree / "pub.old")],
                                  ["symlink", str(tree / "phi"), str(pub)]],
                                 probe(pub))
    assert "SECRET" not in out + err and "FAKE-PT" not in out, out
    # the helper's own refusal, not any other failed start
    assert "RAN" not in out and code == 126 and REFUSAL in err, (code, out, err)


@linux_confined
def test_r9_a_split_folder_replaced_by_a_link_before_the_check_never_shows_its_target(tree):
    # T/runs/run1 is rebuilt (the pattern T/runs/*/panel); its entry `public` is bound back.
    # The folder above it is replaced by a link to a protected folder that holds a `public`
    hidden = tree / "phi" / "public"
    hidden.mkdir()
    (hidden / "FAKE-PT-0009.txt").write_text("SECRET-CONTENT-0009\n")
    run1 = tree / "runs" / "run1"
    code, out, err = launch_with(tree, "built",
                                 [["rename", str(run1), str(tree / "runs" / "run1.old")],
                                  ["symlink", str(tree / "phi"), str(run1)]],
                                 probe(run1 / "public"))
    assert "SECRET" not in out + err and "FAKE-PT" not in out, out
    assert "RAN" not in out and code == 126 and REFUSAL in err, (code, out, err)


@linux_confined
def test_r7_pin_a_read_only_file_removed_before_bwrap_starts_still_stops_the_start(tree):
    # pinning (as before the fix): a read-only bind over the project is never left out
    mcp = tree / "repo" / ".mcp.json"
    mcp.write_text("{}\n")
    code, out, err = launch_with(tree, "exec", [["unlink", str(mcp)]], probe(mcp))
    # bwrap's own refusal of the missing source (not the helper's, not another failure)
    assert "RAN" not in out and code != 0 and "bwrap: Can't find source path" in err, (out, err)


# --- unit level: the command line and the strict binds -------------------------------------------

def _args(tree):
    cfg = config.load(str(tree / "repo"))
    run = tree / "run"
    (run / "tmp").mkdir(parents=True, exist_ok=True)
    return wholetool.bwrap_tool_args(cfg, [str(tree / "repo")], str(tree / "repo"),
                                     dict(os.environ), str(tree / "toolfolder"), str(run))


@linux
def test_r6_a_read_only_file_replaced_by_a_link_before_its_open_stops_launch(tree, monkeypatch):
    mcp = tree / "repo" / ".mcp.json"
    mcp.write_text("{}\n")
    real = wholetool._open_no_follow

    def swapping(path):
        if path == str(mcp) and not os.path.islink(path):
            os.unlink(path)
            os.symlink(str(tree / "phi" / "FAKE-PT-0001.bam"), path)
        return real(path)
    monkeypatch.setattr(wholetool, "_open_no_follow", swapping)
    with pytest.raises(wholetool.LaunchError, match="link"):
        _args(tree)


@linux
def test_r8_the_view_names_its_entries_and_lets_bwrap_skip_a_missing_one(tree):
    out = _args(tree)
    args, fds = out[0], out[1]
    try:
        pub = str(tree / "pub")
        trips = [args[i:i + 3] for i in range(len(args) - 2)]
        assert ["--ro-bind-try", pub, pub] in trips, args
        # the view's entries hold no descriptor: only the places and the read-only files do
        assert not any(t[2] == pub and t[1].startswith("/proc/self/fd/") for t in trips)
    finally:
        for fd in fds:
            os.close(fd)


# --- the helper's check: anything it cannot read or compare stops the start ----------------------

def helper_with(records_text, prelude=""):
    """HELPER on its own, outside bwrap, with these records; the tool prints RAN."""
    import tempfile
    with tempfile.TemporaryFile() as fh:
        fh.write(records_text.encode("utf-8"))
        fh.flush()
        fd = os.dup(fh.fileno())
    try:
        r = subprocess.run([sys.executable, "-I", "-S", "-c", prelude + wholetool.HELPER, str(fd),
                            "0", sys.executable, "-c", "print('RAN')"], pass_fds=[fd],
                           capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    finally:
        os.close(fd)
    return r.returncode, r.stdout, r.stderr


REFUSAL = "the session's view is not what was checked before the start"


@pytest.mark.parametrize("records", ["null", "{}", "[]", "[null]", '[["2f"]]', '[{"a": 1}]',
                                     '[["/x\\u0000y", 1, 2, true]]', '[["2f00", 1, 2, true]]',
                                     '[["2f", "1", 2, false]]', '[["2f", 1, 2, 1]]', "not json"])
def test_r10_garbled_records_stop_the_start(records):
    code, out, err = helper_with(records)
    assert "RAN" not in out and code == 126 and REFUSAL in err, (code, out, err)


def test_r11_an_error_while_comparing_stops_the_start(tree):
    # a seam for an lstat that cannot encode a name (a launcher in UTF-8, a helper in Latin-1)
    name = os.fsencode(str(tree))
    rec = json.dumps([[name.hex(), os.lstat(str(tree)).st_dev, os.lstat(str(tree)).st_ino, False]])
    # only for the recorded path (as bytes, or as its hex text in an older format)
    prelude = ("import os\n_real = os.lstat\n"
               "def _boom(p, *a, **k):\n"
               f"    if p in ({name!r}, {name.hex()!r}):\n"
               "        raise UnicodeEncodeError('latin-1', 'x', 0, 1, 'seam')\n"
               "    return _real(p, *a, **k)\n"
               "os.lstat = _boom\n")
    code, out, err = helper_with(rec, prelude)
    assert "RAN" not in out and code == 126 and REFUSAL in err, (code, out, err)


def test_r12_a_utf8_name_is_compared_as_bytes(tree):
    d = tree / "日a"
    d.mkdir()
    st = os.lstat(str(d))
    good = [[os.fsencode(str(d)).hex(), st.st_dev, st.st_ino, False]]
    code, out, err = helper_with(json.dumps(good))
    assert "RAN" in out and code == 0, (code, out, err)
    wrong = [[os.fsencode(str(d)).hex(), st.st_dev, st.st_ino + 1, True]]
    code, out, err = helper_with(json.dumps(wrong))
    assert "RAN" not in out and code == 126 and REFUSAL in err, (code, out, err)


@linux
def test_r13_a_name_that_is_not_utf8_is_compared_as_bytes(tree):
    d = os.fsencode(str(tree)) + b"/caf\xe9"
    os.mkdir(d)
    st = os.lstat(d)
    code, out, err = helper_with(json.dumps([[d.hex(), st.st_dev, st.st_ino, False]]))
    assert "RAN" in out and code == 0, (code, out, err)
    code, out, err = helper_with(json.dumps([[d.hex(), st.st_dev, st.st_ino + 1, True]]))
    assert "RAN" not in out and code == 126 and REFUSAL in err, (code, out, err)


@linux_confined
def test_r14_an_entry_named_in_no_encoding_is_checked_end_to_end(tree):
    # an entry of the view whose name is not UTF-8, replaced right before bwrap starts
    name = os.fsdecode(os.fsencode(str(tree)) + b"/caf\xe9")
    os.mkdir(name)
    code, out, err = launch_with(tree, "exec", [["rename", name, str(tree / "moved")],
                                                ["mkdir", name]], "print('RAN')")
    assert "RAN" not in out and code == 126 and REFUSAL in err, (code, out, err)
    os.rmdir(name)
    code, out, err = launch_with(tree, "exec", [], "print('RAN')")  # unchanged: it runs
    assert "RAN" in out, err


@linux_confined
def test_r15_checks_that_cannot_be_written_end_the_launch_cleanly(tree):
    code, out, err = launch_with(tree, "checks", [], "print('RAN')", ("--tool", "claude"))
    assert "RAN" not in out and code == 126, (code, out, err)
    assert "Traceback" not in err and "nothing runs" in err, err
    runs = tree / "home" / ".phiward" / "tools" / "claude" / "runs"
    assert not runs.exists() or os.listdir(runs) == [], os.listdir(runs)  # the session ended
