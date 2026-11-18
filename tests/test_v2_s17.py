"""What a session leaves behind cannot steer the launcher, and anything kept may
be deleted at any time (rule D). Nothing is ever killed."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from phiward import carryover
from helpers import needs_confine, ready_line

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
CFG = "os.environ['CLAUDE_CONFIG_DIR']"


def base(tree):
    return tree / "home" / ".phiward" / "tools" / "claude"


def st(tree):
    return tree / "home" / ".phiward" / "carryover" / "claude"


def env():
    return dict(os.environ, PYTHONPATH=SRC)


def launch(tree, code, tool="claude", recursion_limit=None):
    """`phiward launch` running `code` as the tool. With `recursion_limit`, launch's own process
    (which removes what the session left at its end) gets that recursion limit; the tool is a
    child of it and keeps the default."""
    start = ["-m", "phiward"]
    if recursion_limit:
        start = ["-c", f"import runpy, sys; sys.setrecursionlimit({recursion_limit}); "
                       "runpy.run_module('phiward', run_name='__main__', alter_sys=True)"]
    r = subprocess.run([PY, *start, "launch", "--tool", tool, "--", PY, "-c", code],
                       cwd=str(tree / "repo"), capture_output=True, text=True, env=env(),
                       timeout=120, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout, r.stderr


def ag(tree, *args):
    stdin = subprocess.DEVNULL
    if args[:1] == ("carryover",) and args[1:2] in (("add",), ("accept",), ("reset",)):
        import pty  # the operator's own terminal: these refuse without one
        master, slave = pty.openpty()
        stdin = slave
    try:
        r = subprocess.run([PY, "-m", "phiward", *args], cwd=str(tree / "repo"), stdin=stdin,
                           capture_output=True, text=True, env=env(), timeout=60)
    finally:
        if stdin is not subprocess.DEVNULL:
            os.close(master)
            os.close(slave)
    return r.returncode, r.stdout, r.stderr


def sees(tree, rel):
    _, out, err = launch(tree, f"import os\np = os.path.join({CFG}, {rel!r})\n"
                               "print('SEES', repr(open(p, 'rb').read()) if os.path.isfile(p) else None)\n")
    line = [x for x in out.splitlines() if x.startswith("SEES ")]
    assert line, out + err
    return line[0][5:]


def accept_note(tree, text="accepted note"):
    launch(tree, f"import os\nopen(os.path.join({CFG}, 'CLAUDE.md'), 'w').write({text!r})")
    _, out, _ = ag(tree, "carryover", "show", "--tool", "claude")
    ag(tree, "carryover", "accept", out.split()[0], "--tool", "claude")


# --- a process left behind changes nothing a later session reads ---------------------------------

@needs_confine
def test_18_a_left_behind_writer_does_not_reach_the_next_session(tree):
    stop, done = tree / "repo" / "STOP", tree / "repo" / "DONE"
    child = tree / "repo" / "writer.py"
    child.write_text("import os, sys, time\np = os.path.join(sys.argv[1], 'CLAUDE.md')\n"
                     f"for _ in range(600):\n    if os.path.exists({str(stop)!r}):\n        break\n    try:\n"
                     "        open(p, 'w').write('planted')\n    except OSError:\n        pass\n"
                     f"    time.sleep(0.1)\nopen({str(done)!r}, 'w').close()\n")
    code = (f"import os, subprocess, sys\nsubprocess.Popen([sys.executable, {str(child)!r}, {CFG}],"
            " start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "import time; time.sleep(0.3)\n")
    try:
        launch(tree, code)
        assert sees(tree, "CLAUDE.md") == "None"
    finally:
        stop.touch()  # also when the check fails: the writer never outlives the test
    if sys.platform == "darwin":  # it outlives its session there; it stops at STOP
        for _ in range(100):
            if done.exists():
                break
            time.sleep(0.05)
        assert done.exists(), "the left-behind writer did not stop"
    # on Linux the session's process namespace ends it with the session (--die-with-parent)


@needs_confine
def test_18_old_run_folders_are_removed(tree):
    launch(tree, "print('first')")
    launch(tree, "print('second')")
    assert os.listdir(base(tree) / "runs") == []


@needs_confine
def test_18_an_older_layout_is_moved_aside_and_never_trusted(tree):
    b = base(tree)
    (b / "state" / "files").mkdir(parents=True)
    (b / "CLAUDE.md").write_text("EVIL\n")
    (b / "state" / "files" / ".claude.json").write_text(json.dumps({"mcpServers": {"evil": {}}}))
    _, _, err = launch(tree, "print('setup')")
    assert "older layout" in err, err
    assert sees(tree, "CLAUDE.md") == "None"
    assert "evil" not in sees(tree, ".claude.json")  # only the onboarding default


# --- links are never trusted ----------------------------------------------------------------------

@needs_confine
def test_17_5_a_link_cannot_be_accepted_and_show_names_it(tree):
    target = tree / "repo" / "myskills"
    launch(tree, f"import os\nos.makedirs({str(target)!r})\nos.symlink({str(target)!r}, os.path.join({CFG}, 'skills'))")
    _, out, _ = ag(tree, "carryover", "show", "--tool", "claude")
    assert "link" in out, out
    code, out, err = ag(tree, "carryover", "accept", out.split()[0], "--tool", "claude")
    assert code != 0 and "link" in err, out + err


# --- failures warn, never a traceback, never a blocked start --------------------------------------

@needs_confine
@macos
def test_17_6_a_locked_file_does_not_break_later_launches(tree):
    launch(tree, f"import os\np = os.path.join({CFG}, 'CLAUDE.md')\nopen(p, 'w').write('x')\n"
                 "os.chflags(p, 0o2)")  # UF_IMMUTABLE
    code, out, err = launch(tree, "print('AGAIN')")
    assert "AGAIN" in out and "Traceback" not in err, err


@pytest.mark.slow
@needs_confine
def test_17_7_a_deep_tree_does_not_break_the_end(tree):
    # 600 levels under a recursion limit of 300: a remover that recurses once per level fails, on
    # every Python version (macOS takes about 0.5 s for 600 levels and 15 s for 1500)
    code, out, err = launch(tree, f"import os\nos.mkdir(os.path.join({CFG}, 'skills'))\n"
                                  f"os.chdir(os.path.join({CFG}, 'skills'))\n"
                                  "for i in range(600):\n    os.mkdir('d')\n    os.chdir('d')\nprint('MADE')",
                            recursion_limit=300)
    # the end of this session removes the tree, not only the next start
    assert "MADE" in out and "Traceback" not in err, err
    assert "did not finish" not in err and "could not be removed" not in err, err
    code, out, err = launch(tree, "print('AGAIN')", recursion_limit=300)
    assert "AGAIN" in out and "could not be removed" not in err, err


@needs_confine
def test_17_7_a_folder_made_unreadable_does_not_block_later_starts(tree):
    launch(tree, f"import os\nos.chmod(os.path.dirname({CFG}), 0)")
    code, out, err = launch(tree, "print('AGAIN')")
    assert code == 0 and "AGAIN" in out, err


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the read-only mode")
def test_17_8_accept_is_all_or_nothing(tree):
    b = base(tree)
    store = carryover.Store("claude", str(tree / "home"))
    run = b / "runs" / "one"
    store.start(str(b), str(run))
    (run / "config" / "rules").mkdir()
    (run / "config" / "rules" / "a.md").write_text("a")
    store.end(str(b))
    qid = store.entries()[0][0]
    os.makedirs(store.trusted, exist_ok=True)
    os.chmod(store.trusted, 0o500)  # the trusted copy cannot be written: accept fails
    try:
        with pytest.raises((carryover.CarryoverError, OSError)):
            store.accept(qid)
    finally:
        os.chmod(store.trusted, 0o700)
    assert not (Path(store.trusted) / "rules").exists()
    assert store.entries()[0][0] == qid  # still in quarantine


@needs_confine
def test_17_9_a_corrupt_record_stops_launch_and_reset_repairs_it(tree):
    accept_note(tree)
    (st(tree) / "manifest.json").write_text("{not json")
    code, out, err = launch(tree, "print('RAN')")
    assert code != 0 and "RAN" not in out and "carryover reset" in err, err
    code, out, err = ag(tree, "carryover", "reset", "--tool", "claude")
    assert code == 0, out + err
    assert "accepted note" in sees(tree, "CLAUDE.md")


def test_17_10_quarantine_is_bounded_without_dropping_unread_entries(tree, monkeypatch):
    monkeypatch.setattr(carryover, "QUARANTINE_MAX", 3)
    b = base(tree)
    for i in range(6):
        store = carryover.Store("claude", str(tree / "home"))
        run = b / "runs" / f"r{i}"
        store.start(str(b), str(run))
        (run / "config" / "CLAUDE.md").write_text(str(i))
        msgs = store.end(str(b))
    assert len(store.entries()) == 3
    assert any("quarantine is full" in m for m in msgs), msgs


@needs_confine
def test_17_settings_damaged_on_disk_are_made_again_with_only_the_hook(tree):
    launch(tree, "print('first')")
    s = st(tree) / "trusted" / "settings.json"
    d = json.loads(s.read_text())
    d["permissions"] = {"allow": ["Bash(*)"]}
    s.write_text(json.dumps(d))  # changed on disk, not through accept
    _, _, err = launch(tree, "print('again')")
    assert "missing or damaged" in err, err
    got = sees(tree, "settings.json")
    assert "Bash(*)" not in got and "phiward" in got, got


# --- the project report ---------------------------------------------------------------------------

def test_17_11_instructions_are_listed_in_full():
    after = {f".claude/a{i:02d}.md": ("f", i, 1, 1, 1, 0o644, "") for i in range(40)}
    after["CLAUDE.md"] = ("f", 99, 1, 1, 1, 0o644, "")
    text = "\n".join(carryover.project_report(carryover.project_changes({}, after)))
    assert "    CLAUDE.md (new)" in text, text


@needs_confine
def test_17_12_code_in_formerly_skipped_folders_is_reported(tree):
    (tree / "repo" / ".venv" / "lib").mkdir(parents=True)
    _, _, err = launch(tree, f"open({str(tree / 'repo' / '.venv' / 'lib' / 'evil.pth')!r}, 'w').write('import os')",
                       tool="generic")
    assert "evil.pth" in err and "files that run later" in err, err


def test_17_13_past_the_bound_nothing_is_called_removed(tmp_path):
    for i in range(30):
        (tmp_path / f"f{i}").write_text("x")
    before = carryover.project_state(str(tmp_path), limit=10)
    after = carryover.project_state(str(tmp_path), limit=10)
    assert not any("removed" in line for line in carryover.project_report(carryover.project_changes(before, after)))


# --- the launcher never writes through what a session planted -------------------------------------

@needs_confine
def test_18a_a_hard_link_is_never_copied(tree):
    secret = tree / "repo" / "secret.txt"
    secret.write_text("SECRET-TOKEN\n")
    launch(tree, f"import os\np = os.path.join({CFG}, 'CLAUDE.md')\ntry:\n    os.link({str(secret)!r}, p)\n"
                 "except OSError:\n    pass\n")
    qfiles = list((st(tree) / "quarantine").rglob("CLAUDE.md"))
    assert not any("SECRET" in q.read_text() for q in qfiles if q.is_file())


@needs_confine
def test_18a_the_session_cannot_plant_into_the_tool_folder(tree):
    launch(tree, "print('first')")
    target = base(tree) / "skills"
    _, out, _ = launch(tree, f"import os\ntry:\n    os.makedirs({str(target)!r})\n    print('WROTE')\n"
                             "except OSError as e:\n    print('REFUSED', e.errno)\n")
    assert not target.exists(), out


# --- rule D: anything kept may be deleted at any time ---------------------------------------------

@needs_confine
@pytest.mark.parametrize("gone", ["carryover", "trusted-item", "manifest", "runs", "trash", "quarantine",
                                  "tool-folder"])
def test_D_a_deleted_part_is_rebuilt_and_nothing_is_adopted(tree, gone):
    import shutil
    accept_note(tree)
    target = {"carryover": st(tree), "trusted-item": st(tree) / "trusted" / "CLAUDE.md",
              "manifest": st(tree) / "manifest.json", "runs": base(tree) / "runs",
              "trash": base(tree) / "trash", "quarantine": st(tree) / "quarantine",
              "tool-folder": base(tree)}[gone]
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()
    code, out, err = launch(tree, "print('RAN')")
    assert code == 0 and "RAN" in out and "Traceback" not in err, err
    note = sees(tree, "CLAUDE.md")
    if gone in ("carryover", "trusted-item"):
        assert note == "None", note
        if gone == "trusted-item":
            assert "missing or damaged" in err, err
    else:
        assert "accepted note" in note, note


@needs_confine
def test_D_the_session_folder_deleted_while_it_runs(tree):
    code, out, err = launch(tree, f"import shutil, os\nshutil.rmtree(os.path.dirname({CFG}), ignore_errors=True)\n"
                                  "print('RAN')")
    assert "RAN" in out and "Traceback" not in err, err
    code, out, err = launch(tree, "print('AGAIN')")
    assert "AGAIN" in out, err


@needs_confine
def test_D_the_carry_over_folder_deleted_while_a_session_runs(tree):
    import shutil
    accept_note(tree)
    # the first session waits (on its stdin) until the folder is gone and a second one ran
    first = subprocess.Popen([PY, "-m", "phiward", "launch", "--tool", "claude", "--", PY, "-c",
                              "import os, sys\nprint('READY', flush=True)\nsys.stdin.read()\n"
                              "print('FIRST', os.path.isdir(os.environ['CLAUDE_CONFIG_DIR']))"],
                             cwd=str(tree / "repo"), env=env(), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ready_line(first)
    shutil.rmtree(st(tree))
    code, out, err = launch(tree, "print('SECOND')")
    o1, e1 = first.communicate(timeout=60)
    assert "SECOND" in out, err
    assert "FIRST True" in o1, o1 + e1
    assert "Traceback" not in e1, e1


# --- more carry-over fixes ------------------------------------------------------------------------

def test_r19_1_the_trash_sweep_skips_a_folder_its_launcher_still_reads(tree):
    import fcntl
    b = base(tree)
    a = carryover.Store("claude", str(tree / "home"))
    a.start(str(b), str(b / "runs" / "A"))
    (b / "runs" / "A" / "config" / "CLAUDE.md").write_text("A's note")
    t = carryover._to_trash(str(b), "A")  # A's launcher has moved it and holds its lock
    assert t
    fcntl.flock(a._run_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    other = carryover.Store("claude", str(tree / "home"))
    other.start(str(b), str(b / "runs" / "B"))  # B's start sweeps trash
    assert os.path.isdir(os.path.join(t, "config")), "B removed A's folder while A read it"


@needs_confine
def test_r19_2_the_session_can_resolve_and_enter_its_own_folders(tree):
    code, out, err = launch(tree, "import os, subprocess\nt = os.environ['TMPDIR']\n"
                                  "print('REAL', os.path.realpath(t) == t)\n"
                                  "r = subprocess.run(['/bin/sh', '-c', 'cd \"$TMPDIR\" && pwd'], capture_output=True, text=True)\n"
                                  "print('CD', r.returncode)\n")
    assert "CD 0" in out, out + err


@needs_confine
def test_r19_3_a_session_cannot_reach_another_sessions_socket(tree):
    # bound by a short relative name: the full path is longer than macOS's 104-byte socket limit;
    # the server waits (on its stdin) until the other session has tried to connect
    srv = ("import os, socket, sys\nos.chdir(os.environ['TMPDIR'])\n"
           "s = socket.socket(socket.AF_UNIX)\ns.bind('s')\ns.listen(1)\n"
           "print('READY', os.path.join(os.environ['TMPDIR'], 's'), flush=True)\nsys.stdin.read()\n")
    first = subprocess.Popen([PY, "-m", "phiward", "launch", "--tool", "claude", "--", PY, "-c", srv],
                             cwd=str(tree / "repo"), env=env(), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    path = ready_line(first).split(" ", 1)[1].strip()
    code, out, err = launch(tree, f"import os, socket\ns = socket.socket(socket.AF_UNIX)\ntry:\n"
                                  f"    os.chdir({os.path.dirname(path)!r})\n    s.connect('s')\n"
                                  "    print('CONNECTED')\nexcept OSError as e:\n    print('REFUSED', e.errno)\n")
    alive = first.poll() is None  # the server still listened while the other session tried
    first.communicate(timeout=60)
    assert alive and "REFUSED" in out and "CONNECTED" not in out, out + err


def test_r19_6_add_refuses_protected_data(tree):
    f = tree / "phi" / "notes.md"
    f.write_text("FAKE-PT-0001\n")
    code, out, err = ag(tree, "carryover", "add", str(f), "--as", "CLAUDE.md", "--tool", "claude")
    assert code != 0 and "protected" in err, out + err


@needs_confine
@macos
def test_r19_4_a_locked_folder_inside_the_run_does_not_block_removal(tree):
    launch(tree, f"import os\nd = os.path.join({CFG}, 'skills', 'x')\nos.makedirs(d)\n"
                 "open(os.path.join(d, 'f'), 'w').write('x')\nos.chflags(d, 0o2)")  # UF_IMMUTABLE
    code, out, err = launch(tree, "print('AGAIN')")
    assert "AGAIN" in out and "remove them by hand" not in err, err


# --- Kerberos: the operator's ticket is never readable in a session (HPC setup) -------------------

@needs_confine
@pytest.mark.parametrize("where", ["tmp", "named"])
def test_k_a_kerberos_ticket_file_cannot_be_read(tree, where):
    import secrets as _s
    if where == "tmp":
        f = Path(f"/private/tmp/krb5cc_agtest_{_s.token_hex(4)}" if sys.platform == "darwin"
                 else f"/tmp/krb5cc_agtest_{_s.token_hex(4)}")
        extra_env = {}
    else:
        f = tree / "home" / "tickets" / "mycc"
        f.parent.mkdir(parents=True)
        extra_env = {"KRB5CCNAME": f"FILE:{f}"}
    f.write_text("FAKE-TICKET\n")
    try:
        r = subprocess.run([PY, "-m", "phiward", "launch", "--tool", "claude", "--", PY, "-c",
                            f"try:\n    print('READ', open({str(f)!r}).read())\nexcept OSError as e:\n"
                            "    print('REFUSED', e.errno)\n"], cwd=str(tree / "repo"),
                           capture_output=True, text=True, env=dict(env(), **extra_env), timeout=120)
        assert "FAKE-TICKET" not in r.stdout, r.stdout + r.stderr
    finally:
        f.unlink()
