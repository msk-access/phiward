"""`phiward pseudonymize`: the operator's own command that makes a pseudonymized copy of one
CSV/TSV table. Named ID columns get codes (`S` + 4 digits) drawn with `secrets`; the key stays in
`~/.phiward/backups/keys`, which no session, launch or gateway command can read or write; the
output is a new file inside a user protected root. Made-up data only (`FAKE-PT-0001`,
`P-9990001-T01-IM6`, MRNs from 9990001), in a scratch HOME."""

import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from phiward import config, gateway
from phiward.adapters import claude
from phiward.sanitize import Sanitizer
from helpers import Tty, needs_confine

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
SECRETS = ("9990001", "FAKE-PT-0001", "P-9990001-T01-IM6")


class TtyOut(io.StringIO):
    def isatty(self):
        return True


def mrns(n, start=9990001):
    return [str(start + i) for i in range(n)]


def write_table(path, header, rows, delim="\t"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(delim.join(r) + "\n" for r in [header] + rows))
    return path


def read_table(path, delim="\t"):
    lines = path.read_text().splitlines()
    return [ln.split(delim) for ln in lines]


def key_lines(home, name):
    p = home / ".phiward" / "backups" / "keys" / f"{name}.tsv"
    return p.read_text().splitlines()


def key_map(home, name):
    return dict(ln.split("\t") for ln in key_lines(home, name)[1:])


@pytest.fixture()
def ps(tree, monkeypatch):
    """The module, with the scratch home as the account's home, `~/.phiward/backups` made as
    install makes it, the working folder in the home, and a table of 20 made-up MRNs."""
    from phiward import pseudonymize
    home = tree / "home"
    config.make_state_dirs(str(home))
    monkeypatch.setattr(pseudonymize, "_account_home", lambda: str(home))
    monkeypatch.chdir(home)
    write_table(tree / "data" / "labs.tsv", ["mrn", "site", "value"],
                [[m, "lab", str(i)] for i, m in enumerate(mrns(20))])
    return pseudonymize


def run(tree, args, extra=(), tty=True):
    """Run the command in-process; every message is checked for what it may never hold."""
    from phiward import pseudonymize
    fin = Tty() if tty else io.StringIO()
    fout, ferr = (TtyOut() if tty else io.StringIO()), io.StringIO()
    code = pseudonymize.main([str(a) for a in args], fin=fin, fout=fout, ferr=ferr)
    text = fout.getvalue() + ferr.getvalue()
    print(text)  # shown when a test fails
    for s in SECRETS + tuple(extra) + (str(tree),):
        assert s not in text, (s, text)
    return code, text


def base(tree, key="labs", new=True, inp=None, out=None, cols="mrn", more=()):
    return ["--new-key" if new else "--key", key, "--columns", cols, *more,
            inp or tree / "data" / "labs.tsv", out or tree / "phi" / "out.tsv"]


def nothing_written(tree, name="labs"):
    assert not (tree / "phi" / "out.tsv").exists()
    assert not (tree / "home" / ".phiward" / "backups" / "keys" / f"{name}.tsv").exists()


# --- 1. without a terminal nothing is read or written (inv. 10) -------------------------------

def test_without_a_terminal_it_refuses_and_writes_nothing(tree, ps):
    code, text = run(tree, base(tree), tty=False)
    assert code == 2 and "terminal" in text, text
    nothing_written(tree)
    r = subprocess.run([PY, "-m", "phiward", "pseudonymize"] + [str(a) for a in base(tree)],
                       cwd=str(tree / "home"), capture_output=True, text=True, timeout=60,
                       stdin=subprocess.PIPE, env=dict(os.environ, PYTHONPATH=SRC))
    assert r.returncode == 2 and "terminal" in r.stderr, r.stderr
    assert not (tree / "home" / ".phiward" / "backups" / "keys").exists()
    nothing_written(tree)


# --- 2. the hook refuses it as an agent command (inv. 4) --------------------------------------

@pytest.mark.parametrize("cmd", ["phiward pseudonymize --new-key k --columns mrn a.tsv b.tsv",
                                 "sh -c 'phiward pseudonymize --key k'",
                                 "python -m phiward pseudonymize --help",
                                 "agent-guards pseudonymize"])
def test_the_hook_refuses_it_in_every_spelling(tree, cmd):
    assert gateway.is_operator_command(cmd)
    for tool, inp in (("Bash", {"command": cmd}),
                      ("mcp__terminal__run_in_terminal", {"command": cmd})):
        p = {"session_id": "fake", "hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
             "permission_mode": "default", "tool_name": tool, "tool_input": inp}
        ferr = io.StringIO()
        code = claude.main(io.StringIO(json.dumps(p)), io.StringIO(), ferr)
        assert code == 2 and "pseudonymize" in ferr.getvalue(), (tool, ferr.getvalue())


# --- 3. where the key lives (inv. 4, 11) ------------------------------------------------------

def test_the_key_lands_in_the_keys_folder_private(tree, ps):
    code, text = run(tree, base(tree))
    assert code == 0, text
    keys = tree / "home" / ".phiward" / "backups" / "keys"
    assert os.stat(keys).st_mode & 0o777 == 0o700
    assert os.stat(keys / "labs.tsv").st_mode & 0o777 == 0o600
    assert key_lines(tree / "home", "labs")[0] == "#phiward-key\t1\tS"
    assert os.stat(tree / "phi" / "out.tsv").st_mode & 0o777 == 0o600


def test_without_the_backups_folder_it_refuses_and_makes_nothing(tree, ps):
    os.rmdir(tree / "home" / ".phiward" / "backups")
    code, text = run(tree, base(tree))
    assert code == 2 and "phiward install claude" in text, text
    assert not (tree / "home" / ".phiward" / "backups").exists()
    nothing_written(tree)


@pytest.mark.parametrize("kind", ["link", "open", "file"])
def test_a_keys_folder_that_is_not_a_private_folder_is_refused(tree, ps, kind):
    keys = tree / "home" / ".phiward" / "backups" / "keys"
    if kind == "link":
        (tree / "elsewhere").mkdir(mode=0o700)
        os.symlink(tree / "elsewhere", keys)
    elif kind == "open":
        keys.mkdir()
        os.chmod(keys, 0o755)
    else:
        keys.write_text("x\n")
    code, text = run(tree, base(tree))
    assert code == 2, text
    assert not (tree / "phi" / "out.tsv").exists()
    if kind == "link":
        assert os.listdir(tree / "elsewhere") == []


@pytest.mark.parametrize("kind", ["link", "open"])
def test_a_backups_folder_that_is_not_private_is_refused(tree, ps, kind):
    b = tree / "home" / ".phiward" / "backups"
    if kind == "link":
        os.rmdir(b)
        (tree / "elsewhere").mkdir(mode=0o700)
        os.symlink(tree / "elsewhere", b)
    else:
        os.chmod(b, 0o755)
    code, text = run(tree, base(tree))
    assert code == 2, text
    nothing_written(tree)


def test_a_home_other_than_the_accounts_is_refused(tree, ps, monkeypatch):
    other = tree / "other-home"
    other.mkdir()
    monkeypatch.setattr(ps, "_account_home", lambda: str(other))
    code, text = run(tree, base(tree))
    assert code == 2 and "HOME" in text, text
    nothing_written(tree)


def test_mcp_wrap_still_works_with_a_keys_folder(tree, ps, monkeypatch):
    from phiward import mcp_config
    assert run(tree, base(tree))[0] == 0
    before = (tree / "home" / ".phiward" / "backups" / "keys" / "labs.tsv").read_bytes()
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(sys, "stdin", Tty())
    mcp_config._launcher_exes.cache_clear()
    (tree / "repo" / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"a": {"command": "npx", "args": ["-y", "some-server"]}}}))
    assert mcp_config.main(["wrap", "a", "--yes"]) == 0
    assert (tree / "home" / ".phiward" / "backups" / "keys" / "labs.tsv").read_bytes() == before


# --- the key folder is hidden from the kernel profiles, also when made later ------------------

def _out_of_tmp(tree):
    if sys.platform.startswith("linux") and str(tree).startswith("/tmp/"):
        pytest.skip("Linux: the tree is under the session's own /tmp; run with --basetemp")


WAIT = ("import os, sys, time\n"
        "go, key = sys.argv[1], sys.argv[2]\n"
        "{ready}"
        "end = time.time() + 60\n"
        "while not os.path.exists(go) and time.time() < end:\n"
        "    time.sleep(0.1)\n"
        "try:\n"
        "    print('READ', open(key).read())\n"
        "except OSError as e:\n"
        "    print('REFUSED', e.errno)\n"
        "try:\n"
        "    print('LISTED', os.listdir(os.path.dirname(key)))\n"
        "except OSError as e:\n"
        "    print('NOLIST', e.errno)\n"
        "# {marker}\n")


def _make_key_later(tree):
    keys = tree / "home" / ".phiward" / "backups" / "keys"
    keys.mkdir(mode=0o700)
    (keys / "late.tsv").write_text("#phiward-key\t1\tS\nSECRET-KEY-LINE\tS0042\n")
    return keys / "late.tsv"


@needs_confine
def test_a_key_made_after_a_launch_started_is_hidden_from_it(tree):
    _out_of_tmp(tree)
    config.make_state_dirs(str(tree / "home"))
    key = tree / "home" / ".phiward" / "backups" / "keys" / "late.tsv"
    go, ready = tree / "pub" / "go", tree / "repo" / "ready"
    code = WAIT.format(ready=f"open({str(ready)!r}, 'w').close()\n", marker="launch")
    env = dict(os.environ, PYTHONPATH=SRC)
    p = subprocess.Popen([PY, "-m", "phiward", "launch", "--", PY, "-c", code, str(go), str(key)],
                         cwd=str(tree / "repo"), stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, env=env)
    try:
        end = time.time() + 60
        while not ready.exists() and time.time() < end and p.poll() is None:
            time.sleep(0.1)
        assert ready.exists(), p.communicate(timeout=10)[0]
        _make_key_later(tree)
        go.write_text("")
        out = p.communicate(timeout=90)[0]
    finally:
        if p.poll() is None:
            p.kill()
    assert "SECRET-KEY-LINE" not in out and "late.tsv" not in out, out
    assert "REFUSED" in out, out


def _running(marker):
    if sys.platform.startswith("linux"):
        for pid in os.listdir("/proc"):
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as fh:
                    if marker.encode() in fh.read():
                        return True
            except OSError:
                continue
        return False
    r = subprocess.run(["ps", "-axww", "-o", "command"], capture_output=True, text=True)
    return marker in r.stdout


@needs_confine
def test_a_key_made_after_a_gateway_command_started_is_hidden_from_it(tree, broker):
    _out_of_tmp(tree)
    config.make_state_dirs(str(tree / "home"))
    key = tree / "home" / ".phiward" / "backups" / "keys" / "late.tsv"
    go = tree / "pub" / "go"
    marker = f"PSEUDO-WAIT-{os.getpid()}-{time.time_ns()}"
    code = WAIT.format(ready="", marker=marker)
    launch = ("import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; "
              "from phiward.cli import main; sys.exit(main())")
    env = dict(os.environ, PYTHONPATH=SRC)
    p = subprocess.Popen([PY, "-c", launch, "run", "--", PY, "-c", code, str(go), str(key)],
                         cwd=str(tree / "repo"), stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, env=env)
    try:
        end = time.time() + 60
        while not _running(marker) and time.time() < end and p.poll() is None:
            time.sleep(0.1)
        assert _running(marker), p.communicate(timeout=10)[0]
        _make_key_later(tree)
        go.write_text("")
        out = p.communicate(timeout=90)[0]
    finally:
        if p.poll() is None:
            p.kill()
    assert "SECRET-KEY-LINE" not in out and "late.tsv" not in out, out
    assert "REFUSED" in out, out


@needs_confine
def test_inside_launch_a_script_that_fakes_a_terminal_cannot_read_or_make_a_key(tree):
    """The tty check is not the boundary: a Python file that imports the module and fakes a
    terminal (as a pty would) still cannot make a key or read one."""
    _out_of_tmp(tree)
    home = tree / "home"
    config.make_state_dirs(str(home))
    keys = home / ".phiward" / "backups" / "keys"
    keys.mkdir(mode=0o700)
    old = keys / "old.tsv"
    old.write_text("#phiward-key\t1\tS\nSECRET-KEY-LINE\tS0042\n")
    os.chmod(old, 0o600)
    write_table(tree / "data" / "labs.tsv", ["mrn", "site"], [[m, "lab"] for m in mrns(3)])
    code = (
        "import io, sys\n"
        "from phiward import pseudonymize as p\n"
        f"p._account_home = lambda: {str(home)!r}\n"
        "class T(io.StringIO):\n"
        "    def isatty(self): return True\n"
        "for args in (['--new-key', 'made'], ['--key', 'old']):\n"
        "    err = T()\n"
        f"    rc = p.main(args + ['--columns', 'mrn', {str(tree / 'data' / 'labs.tsv')!r}, "
        f"{str(tree / 'phi' / 'o.tsv')!r}], fin=T(), fout=T(), ferr=err)\n"
        "    print('RC', rc)\n"
        "try:\n"
        f"    print('READ', open({str(old)!r}).read())\n"
        "except OSError as e:\n"
        "    print('REFUSED', e.errno)\n"
        "try:\n"
        f"    open({str(keys / 'planted.tsv')!r}, 'w').write('x')\n"
        "except OSError as e:\n"
        "    print('NOWRITE', e.errno)\n")
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([PY, "-m", "phiward", "launch", "--", PY, "-c", code],
                       cwd=str(tree / "repo"), capture_output=True, text=True, env=env,
                       timeout=120)
    out = r.stdout + r.stderr
    assert "SECRET-KEY-LINE" not in out and "S0042" not in out, out
    assert "RC 0" not in out and "REFUSED" in out, out
    assert sorted(os.listdir(keys)) == ["old.tsv"]
    assert old.read_text() == "#phiward-key\t1\tS\nSECRET-KEY-LINE\tS0042\n"
    assert not (tree / "phi" / "o.tsv").exists()


# --- 4. codes come from the draw (inv. 1, 2) ---------------------------------------------------

def test_codes_are_the_drawn_ones_not_in_id_order(tree, ps, monkeypatch):
    write_table(tree / "data" / "labs.tsv", ["mrn", "site"], [[m, "lab"] for m in mrns(60)])
    # always the last free code: S9999, S9998, ... while the IDs go up
    monkeypatch.setattr(ps.secrets, "randbelow", lambda n: n - 1)
    assert run(tree, base(tree, more=["--keep-order"]))[0] == 0
    got = key_map(tree / "home", "labs")
    assert [got[m] for m in mrns(60)] == [f"S{9999 - i:04d}" for i in range(60)]
    out = read_table(tree / "phi" / "out.tsv")
    assert out[0] == ["pseudonym", "site"]
    assert [r[0] for r in out[1:]] == [f"S{9999 - i:04d}" for i in range(60)]


def test_two_new_keys_over_the_same_table_differ(tree, ps):
    assert run(tree, base(tree, key="a", out=tree / "phi" / "a.tsv"))[0] == 0
    assert run(tree, base(tree, key="b", out=tree / "phi" / "b.tsv"))[0] == 0
    a, b = key_map(tree / "home", "a"), key_map(tree / "home", "b")
    assert sorted(a) == sorted(b) == sorted(mrns(20))
    assert [a[m] for m in mrns(20)] != [b[m] for m in mrns(20)]
    codes = sorted(a.values())
    assert [a[m] for m in mrns(20)] != codes  # not handed out in ID order


# --- 5. rows ---------------------------------------------------------------------------------

def test_rows_are_shuffled_by_default_and_kept_with_keep_order(tree, ps, monkeypatch):
    monkeypatch.setattr(ps, "_shuffle", lambda rows: rows.reverse())
    assert run(tree, base(tree))[0] == 0
    got = key_map(tree / "home", "labs")
    out = read_table(tree / "phi" / "out.tsv")
    assert [r[0] for r in out[1:]] == [got[m] for m in reversed(mrns(20))]
    assert run(tree, base(tree, new=False, out=tree / "phi" / "kept.tsv",
                          more=["--keep-order"]))[0] == 0
    kept = read_table(tree / "phi" / "kept.tsv")
    assert [r[0] for r in kept[1:]] == [got[m] for m in mrns(20)]
    assert [r[2] for r in kept[1:]] == [str(i) for i in range(20)]


def test_the_real_shuffle_moves_the_rows(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "site", "value"],
                [[m, "lab", str(i)] for i, m in enumerate(mrns(200))])
    assert run(tree, base(tree))[0] == 0
    out = read_table(tree / "phi" / "out.tsv")
    assert [r[2] for r in out[1:]] != [str(i) for i in range(200)]
    assert sorted(int(r[2]) for r in out[1:]) == list(range(200))


# --- 6. one ID, one code, for ever (inv. 3) ----------------------------------------------------

def test_the_same_id_gets_the_same_code_in_one_table_and_the_next(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "site"],
                [["9990001", "a"], ["9990002", "b"], ["9990001", "c"]])
    assert run(tree, base(tree, more=["--keep-order"]))[0] == 0
    out = read_table(tree / "phi" / "out.tsv")
    assert out[1][0] == out[3][0] != out[2][0]
    assert len(key_lines(tree / "home", "labs")) == 3
    keyfile = tree / "home" / ".phiward" / "backups" / "keys" / "labs.tsv"
    before = keyfile.read_bytes()
    write_table(tree / "data" / "more.tsv", ["mrn", "x"],
                [["9990002", "1"], ["9990003", "2"], ["9990001", "3"]])
    assert run(tree, base(tree, new=False, inp=tree / "data" / "more.tsv",
                          out=tree / "phi" / "more.tsv", more=["--keep-order"]))[0] == 0
    after = keyfile.read_bytes()
    assert after.startswith(before) and len(after.splitlines()) == 4
    got = key_map(tree / "home", "labs")
    more = read_table(tree / "phi" / "more.tsv")
    assert [r[0] for r in more[1:]] == [got["9990002"], got["9990003"], got["9990001"]]
    assert out[1][0] == got["9990001"]
    assert len(set(got.values())) == 3


def test_an_empty_cell_stays_empty_and_spaces_are_stripped(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "site"],
                [["9990001", "a"], ["", "b"], [" 9990001 ", "c"]])
    assert run(tree, base(tree, more=["--keep-order"]))[0] == 0
    out = read_table(tree / "phi" / "out.tsv")
    assert out[2][0] == "" and out[1][0] == out[3][0] != ""
    assert len(key_lines(tree / "home", "labs")) == 2


# --- 7. a code the sanitizer would touch is skipped (inv. 6) ----------------------------------

def test_a_drawn_code_that_would_be_masked_or_is_in_the_input_is_skipped(tree, ps, monkeypatch):
    (tree / "phi" / "S9999").write_text("x\n")  # an entry name under a root
    cfg = Path(os.environ["PHIWARD_CONFIG"])
    cfg.write_text(cfg.read_text() + "[sanitize]\npatterns = ['S999[78] => <SUBJ>']\n")
    write_table(tree / "data" / "labs.tsv", ["mrn", "note"],
                [["9990001", "S9996"], ["9990002", "ok"]])
    monkeypatch.setattr(ps.secrets, "randbelow", lambda n: n - 1)
    assert run(tree, base(tree, more=["--keep-order"]))[0] == 0
    got = key_map(tree / "home", "labs")
    assert got == {"9990001": "S9995", "9990002": "S9994"}


def test_every_code_passes_the_sanitizer_with_the_packs_and_a_names_file(tree, ps):
    names = tree / "names.txt"
    names.write_text("1\t/data/FAKE-PT-0001/x.bam\n")  # index, a tab, a path
    cfg = Path(os.environ["PHIWARD_CONFIG"])
    cfg.write_text(cfg.read_text() + "[sanitize]\npacks = [\"genomics\", \"msk\", \"dates\"]\n"
                   f"names_from = [\"{names}\"]\n")
    write_table(tree / "data" / "labs.tsv", ["mrn", "site"], [[m, "lab"] for m in mrns(300)])
    assert run(tree, base(tree))[0] == 0
    san = Sanitizer.from_config(config.load(str(tree / "home")), entries=True)
    for r in read_table(tree / "phi" / "out.tsv")[1:]:
        assert san.clean(r[0]) == r[0] and san.clean(r[0], table=True) == r[0], r[0]
        assert len(r[0]) == 5 and r[0][0] == "S" and r[0][1:].isdigit()


def test_a_prefix_is_fixed_in_the_key(tree, ps):
    assert run(tree, base(tree, more=["--prefix", "QX"]))[0] == 0
    assert key_lines(tree / "home", "labs")[0] == "#phiward-key\t1\tQX"
    assert all(c.startswith("QX") for c in key_map(tree / "home", "labs").values())
    assert run(tree, base(tree, new=False, out=tree / "phi" / "o2.tsv",
                          more=["--prefix", "S"]))[0] == 2
    for bad in ("s", "ABCD", "S1", ""):
        assert run(tree, base(tree, key="k2", out=tree / "phi" / "o3.tsv",
                              more=["--prefix", bad]))[0] == 2, bad


# --- 8. the key is checked before use; refusals write nothing ---------------------------------

def _good_key(tree, name="labs"):
    assert run(tree, base(tree, key=name, out=tree / "phi" / f"{name}-0.tsv"))[0] == 0
    return tree / "home" / ".phiward" / "backups" / "keys" / f"{name}.tsv"


@pytest.mark.parametrize("damage", ["link", "mode", "first", "dup_code", "dup_id", "no_newline",
                                    "bad_line"])
def test_a_damaged_key_is_refused_and_nothing_changes(tree, ps, damage):
    k = _good_key(tree)
    text = k.read_text()
    lines = text.splitlines(keepends=True)
    if damage == "link":
        real = tree / "home" / ".phiward" / "backups" / "keys" / "real.tsv"
        os.rename(k, real)
        os.symlink(real, k)
    elif damage == "mode":
        os.chmod(k, 0o644)
    elif damage == "first":
        k.write_text("#other\t1\tS\n" + "".join(lines[1:]))
    elif damage == "dup_code":
        k.write_text(text + "9999999\t" + lines[1].split("\t")[1])
    elif damage == "dup_id":
        k.write_text(text + lines[1].split("\t")[0] + "\tS0001\n")
    elif damage == "no_newline":
        k.write_text(text.rstrip("\n"))
    else:
        k.write_text(text + "just-one-field\n")
    if damage != "link":
        os.chmod(k, 0o644 if damage == "mode" else 0o600)
    before = os.readlink(k) if damage == "link" else k.read_bytes()
    code, out = run(tree, base(tree, new=False))
    assert code == 2, out
    assert not (tree / "phi" / "out.tsv").exists()
    assert (os.readlink(k) if damage == "link" else k.read_bytes()) == before


def test_new_key_on_an_existing_name_and_key_on_a_missing_one_are_refused(tree, ps):
    k = _good_key(tree)
    before = k.read_bytes()
    assert run(tree, base(tree))[0] == 2
    assert k.read_bytes() == before
    assert run(tree, base(tree, key="missing", new=False))[0] == 2
    assert not (k.parent / "missing.tsv").exists()
    assert not (tree / "phi" / "out.tsv").exists()


@pytest.mark.parametrize("name", ["../x", "a/b", "..", "", "x" * 65, "a.tsv", "a b"])
def test_a_key_name_is_never_a_path(tree, ps, name):
    assert run(tree, base(tree, key=name))[0] == 2
    assert not (tree / "home" / ".phiward" / "backups" / "keys").exists() or \
        os.listdir(tree / "home" / ".phiward" / "backups" / "keys") == []
    assert not (tree / "phi" / "out.tsv").exists()


# --- 9. the output is a new file inside a user root (inv. 5) ----------------------------------

def test_an_existing_output_is_never_replaced(tree, ps):
    (tree / "phi" / "out.tsv").write_text("KEEP-ME\n")
    assert run(tree, base(tree))[0] == 2
    assert (tree / "phi" / "out.tsv").read_text() == "KEEP-ME\n"
    assert not (tree / "home" / ".phiward" / "backups" / "keys" / "labs.tsv").exists()


def test_an_output_outside_every_user_root_is_refused(tree, ps):
    assert run(tree, base(tree, out=tree / "pub" / "out.tsv"))[0] == 2
    assert not (tree / "pub" / "out.tsv").exists()
    nothing_written(tree)


def test_an_output_in_a_root_only_a_repo_config_adds_is_refused(tree, ps, monkeypatch):
    (tree / "repo" / "extra").mkdir()
    (tree / "repo" / ".phiward.toml").write_text(
        f'[protected_paths]\nroots = ["{tree}/repo/extra"]\n')
    monkeypatch.chdir(tree / "repo")
    assert run(tree, base(tree, out=tree / "repo" / "extra" / "out.tsv"))[0] == 2
    assert not (tree / "repo" / "extra" / "out.tsv").exists()
    nothing_written(tree)


def test_an_output_through_a_link_or_in_a_claude_folder_is_refused(tree, ps):
    os.symlink(tree / "phi" / "sub", tree / "phi" / "lnk")
    assert run(tree, base(tree, out=tree / "phi" / "lnk" / "out.tsv"))[0] == 2
    assert not (tree / "phi" / "sub" / "out.tsv").exists()
    (tree / "phi" / ".claude").mkdir()
    assert run(tree, base(tree, out=tree / "phi" / ".claude" / "out.tsv"))[0] == 2
    assert not (tree / "phi" / ".claude" / "out.tsv").exists()
    os.symlink(tree / "pub" / "x.tsv", tree / "phi" / "dangling.tsv")
    assert run(tree, base(tree, out=tree / "phi" / "dangling.tsv"))[0] == 2
    assert not (tree / "pub" / "x.tsv").exists()
    nothing_written(tree)


def test_an_output_of_another_kind_is_refused(tree, ps):
    assert run(tree, base(tree, out=tree / "phi" / "out.csv"))[0] == 2
    assert not (tree / "phi" / "out.csv").exists()


# --- 10. ID columns are coded, dropped or kept by name (inv. 7) -------------------------------

def test_an_id_column_not_named_is_refused(tree, ps):
    for extra in ("dob", "sample_id"):
        write_table(tree / "data" / "labs.tsv", ["mrn", extra, "site"],
                    [["9990001", "x", "lab"]])
        code, text = run(tree, base(tree), extra=[extra])
        assert code == 2 and "column 2" in text, text
        nothing_written(tree)
        assert run(tree, base(tree, more=["--drop", extra]))[0] == 0
        out = read_table(tree / "phi" / "out.tsv")
        assert out[0] == ["pseudonym", "site"]
        os.unlink(tree / "phi" / "out.tsv")
        assert run(tree, base(tree, new=False, more=["--keep", extra]))[0] == 0
        out = read_table(tree / "phi" / "out.tsv")
        assert out[0] == ["pseudonym", extra, "site"] and out[1][1] == "x"
        os.unlink(tree / "phi" / "out.tsv")
        os.unlink(tree / "home" / ".phiward" / "backups" / "keys" / "labs.tsv")


def test_an_id_from_the_user_config_id_columns_must_be_named(tree, ps):
    cfg = Path(os.environ["PHIWARD_CONFIG"])
    cfg.write_text(cfg.read_text() + "[sanitize]\nid_columns = [\"tube\"]\n")
    write_table(tree / "data" / "labs.tsv", ["mrn", "tube"], [["9990001", "x"]])
    assert run(tree, base(tree), extra=["tube"])[0] == 2
    nothing_written(tree)


def test_a_header_the_sanitizer_would_change_is_refused(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "P-9990001-T01-IM6"], [["9990001", "1"]])
    assert run(tree, base(tree))[0] == 2
    nothing_written(tree)


@pytest.mark.parametrize("new", ["mrn_code", "sample", "P-9990001-T01-IM6", "site", ""])
def test_a_new_header_that_names_an_id_or_repeats_one_is_refused(tree, ps, new):
    assert run(tree, base(tree, cols=f"mrn={new}"))[0] == 2
    nothing_written(tree)


def test_two_coded_columns_get_their_own_headers(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "patient", "site"],
                [["9990001", "FAKE-PT-0001", "lab"]])
    assert run(tree, base(tree, cols="mrn,patient"))[0] == 0
    out = read_table(tree / "phi" / "out.tsv")
    assert out[0] == ["pseudonym", "pseudonym_2", "site"]
    assert run(tree, base(tree, key="k2", cols="mrn=a,patient=a",
                          out=tree / "phi" / "o2.tsv"))[0] == 2
    assert not (tree / "phi" / "o2.tsv").exists()


def test_a_named_column_that_is_missing_or_named_twice_is_refused(tree, ps):
    assert run(tree, base(tree, cols="nope"))[0] == 2
    assert run(tree, base(tree, cols="mrn,mrn"))[0] == 2
    assert run(tree, base(tree, more=["--drop", "mrn"]))[0] == 2
    assert run(tree, base(tree, more=["--keep", "nope"]))[0] == 2
    write_table(tree / "data" / "labs.tsv", ["mrn", "MRN"], [["9990001", "9990002"]])
    assert run(tree, base(tree))[0] == 2
    nothing_written(tree)


# --- 11. the input (inv. 11) ------------------------------------------------------------------

def _raw(tree, data, name="labs.tsv"):
    p = tree / "data" / name
    p.write_bytes(data)
    return p


@pytest.mark.parametrize("data", [b"mrn\tsite\n9990001\tlab\textra\n",
                                  b"mrn\tsite\n9990001\t\xff\n",
                                  b"mrn\tsite\n9990001\tl\x00b\n",
                                  b"",
                                  b"mrn\tsite\n9990001\tl\tb\n",
                                  b"mrn\tsite\n\n9990001\tlab\n"])
def test_an_input_that_cannot_be_read_as_one_table_is_refused(tree, ps, data):
    assert run(tree, base(tree, inp=_raw(tree, data)))[0] == 2
    nothing_written(tree)


def test_an_input_of_another_kind_is_refused(tree, ps):
    assert run(tree, base(tree, inp=_raw(tree, b"mrn\tsite\n9990001\tlab\n", "labs.xlsx")))[0] == 2
    nothing_written(tree)


def test_an_input_that_is_a_link_or_a_fifo_or_has_a_link_on_its_path_is_refused(tree, ps):
    os.symlink(tree / "data" / "labs.tsv", tree / "data" / "l.tsv")
    assert run(tree, base(tree, inp=tree / "data" / "l.tsv"))[0] == 2
    os.symlink(tree / "data", tree / "dl")
    assert run(tree, base(tree, inp=tree / "dl" / "labs.tsv"))[0] == 2
    os.mkfifo(tree / "data" / "f.tsv")
    assert run(tree, base(tree, inp=tree / "data" / "f.tsv"))[0] == 2
    nothing_written(tree)


def test_an_input_where_an_agent_writes_is_refused(tree, ps):
    home = tree / "home"
    w = tree / "w"
    w.mkdir()
    cfg = Path(os.environ["PHIWARD_CONFIG"])
    cfg.write_text(cfg.read_text() + f'[broker]\nwrite_to = ["{w}"]\n')
    (tree / "proj" / ".git").mkdir(parents=True)
    places = [w / "in.tsv", home / ".phiward-spool" / "in.tsv", tree / "proj" / "sub" / "in.tsv",
              home / ".phiward" / "in.tsv"]
    for p in places:
        write_table(p, ["mrn", "site"], [["9990001", "lab"]])
        assert run(tree, base(tree, inp=p))[0] == 2, p
        nothing_written(tree)


def test_an_input_in_the_working_folders_git_tree_is_refused(tree, ps, monkeypatch):
    (tree / "work" / ".git").mkdir(parents=True)
    (tree / "work" / "deep").mkdir()
    monkeypatch.chdir(tree / "work" / "deep")
    p = write_table(tree / "work" / "in.tsv", ["mrn", "site"], [["9990001", "lab"]])
    assert run(tree, base(tree, inp=p))[0] == 2
    nothing_written(tree)


def test_a_quoted_csv_cell_with_a_comma_round_trips(tree, ps):
    p = _raw(tree, b'mrn,site,note\n9990001,lab,"a, b"\r\n9990002,lab,"say ""hi"""\n',
             "labs.csv")
    assert run(tree, base(tree, inp=p, out=tree / "phi" / "out.csv",
                          more=["--keep-order"]))[0] == 0
    text = (tree / "phi" / "out.csv").read_text()
    import csv
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == ["pseudonym", "site", "note"]
    assert [r[2] for r in rows[1:]] == ["a, b", 'say "hi"']
    assert "\r" not in text


def test_a_bom_is_allowed(tree, ps):
    p = _raw(tree, "\ufeffmrn\tsite\n9990001\tlab\n".encode())
    assert run(tree, base(tree, inp=p))[0] == 0
    assert read_table(tree / "phi" / "out.tsv")[0] == ["pseudonym", "site"]


# --- 12. messages (inv. 8) ---------------------------------------------------------------------

def test_known_and_new_ids_print_the_same_text_but_the_row_count(tree, ps):
    code, first = run(tree, base(tree), extra=["mrn", "labs.tsv", "out.tsv"])
    assert code == 0 and "20" in first, first
    code, again = run(tree, base(tree, new=False, out=tree / "phi" / "o2.tsv"),
                      extra=["mrn", "labs.tsv"])
    assert code == 0 and again == first, (first, again)
    write_table(tree / "data" / "new.tsv", ["mrn", "site", "value"],
                [[m, "lab", "1"] for m in mrns(20, 9990101)])
    code, new = run(tree, base(tree, new=False, inp=tree / "data" / "new.tsv",
                               out=tree / "phi" / "o3.tsv"), extra=["mrn", "new.tsv"])
    assert code == 0 and new == first, (first, new)


# --- 13. a failure leaves no output (inv. 9) --------------------------------------------------

def test_a_failure_after_the_key_append_leaves_no_output(tree, ps, monkeypatch):
    k = _good_key(tree)
    before = k.read_bytes()
    write_table(tree / "data" / "new.tsv", ["mrn", "site"], [["9990001", "a"], ["9990500", "b"]])

    def fail(*a, **kw):
        raise OSError("disk full")
    monkeypatch.setattr(ps, "_write_out", fail)
    code, text = run(tree, base(tree, new=False, inp=tree / "data" / "new.tsv"))
    assert code != 0, text
    assert not (tree / "phi" / "out.tsv").exists()
    after = k.read_bytes()
    assert after.startswith(before)
    assert [ln.split(b"\t")[0] for ln in after[len(before):].splitlines()] == [b"9990500"]


def test_a_failure_before_the_key_append_leaves_the_key_as_it_was(tree, ps):
    k = _good_key(tree)
    before = k.read_bytes()
    bad = _raw(tree, b"mrn\tsite\n9990777\tlab\n9990778\n", "bad.tsv")
    assert run(tree, base(tree, new=False, inp=bad))[0] == 2
    assert k.read_bytes() == before
    assert not (tree / "phi" / "out.tsv").exists()


def test_the_help_names_the_rules(ps):
    out = TtyOut()
    assert ps.main(["--help"], fin=Tty(), fout=out, ferr=io.StringIO()) == 0
    for w in ("--new-key", "--columns", "--drop", "--keep", "--keep-order", "--prefix",
              "~/.phiward/backups/keys", "phiward run"):
        assert w in out.getvalue(), w


# --- review round 1 ---------------------------------------------------------------------------

def test_an_id_in_another_column_is_refused(tree, ps):
    """A coded ID left in a kept or plain column would link its code to the real ID."""
    for note in ("9990002", "see 9990002 again", "x/9990002.bam", "PT:9990001",
                 "P-9990001-T01", "see FAKE-PT-0001 again", "FAKE-PT-0001"):
        write_table(tree / "data" / "labs.tsv", ["mrn", "sample_id", "note", "value"],
                    [["9990001", "x", "a", "1"], ["9990002", "y", note, "2"],
                     ["FAKE-PT-0001", "z", "b", "3"]])
        code, text = run(tree, base(tree, more=["--keep", "sample_id"]), extra=["note"])
        assert code == 2 and "column 3" in text, (note, text)
        nothing_written(tree)
    # an ID of digits only counts as a whole run of digits: a longer number is no match
    for note in ("19990001", "199900012", "x19990001y"):
        write_table(tree / "data" / "labs.tsv", ["mrn", "note"],
                    [["9990001", note], ["9990002", "ok"]])
        assert run(tree, base(tree))[0] == 0, note
        os.unlink(tree / "phi" / "out.tsv")
        os.unlink(tree / "home" / ".phiward" / "backups" / "keys" / "labs.tsv")


def test_an_id_of_the_key_in_another_column_is_refused(tree, ps):
    assert run(tree, base(tree, out=tree / "phi" / "o1.tsv"))[0] == 0
    write_table(tree / "data" / "more.tsv", ["mrn", "note"], [["9990500", "was 9990003"]])
    assert run(tree, base(tree, new=False, inp=tree / "data" / "more.tsv"))[0] == 2
    assert not (tree / "phi" / "out.tsv").exists()


@pytest.mark.parametrize("where", ["temp", "allow_write", "additional", "cwd"])
def test_an_input_where_the_agents_sandbox_writes_is_refused(tree, ps, monkeypatch, where):
    from phiward import claude_settings
    place = tree / "agentw"
    place.mkdir()
    if where == "temp":
        monkeypatch.setattr(claude_settings, "_temp_roots", lambda: [str(place)])
    elif where in ("allow_write", "additional"):
        d = tree / "home" / ".claude"
        d.mkdir(exist_ok=True)
        data = ({"sandbox": {"filesystem": {"allowWrite": [str(place)]}}} if where == "allow_write"
                else {"permissions": {"additionalDirectories": [str(place)]}})
        (d / "settings.json").write_text(json.dumps(data))
    else:
        monkeypatch.chdir(place)  # the working folder, not a git repository
    p = write_table(place / "sub" / "in.tsv", ["mrn", "site"], [["9990001", "lab"]])
    assert run(tree, base(tree, inp=p))[0] == 2, where
    nothing_written(tree)


@pytest.mark.parametrize("cmd", ["python3 -mphiward pseudonymize --help",
                                 "python3 -mphiward.cli setup",
                                 "a=pseudo; b=nymize; phiward $a$b",
                                 "phiward pseudonymi[z]e", "phiward pseudonym?ze",
                                 "phiward `echo pseudonymize`", "phiward $(echo broker)",
                                 "phiward \"$X\"", "phiward ${X:-setup}", "phiward pseudo{nymize,}"])
def test_the_hook_catches_operator_commands_built_at_run_time(cmd):
    assert gateway.is_operator_command(cmd), cmd


@pytest.mark.parametrize("cmd", ["phiward run -- wc -l README.md", "phiward copy a ~/data/b",
                                 "phiward doctor", "phiward check -- ls $HOME",
                                 "python3 -m phiward run -- ls", "echo $X phiward"])
def test_ordinary_phiward_commands_are_not_operator_commands(cmd):
    assert not gateway.is_operator_command(cmd), cmd


def test_a_key_with_another_link_is_refused(tree, ps):
    k = _good_key(tree)
    os.link(k, tree / "home" / "hard.tsv")
    before = k.read_bytes()
    assert run(tree, base(tree, new=False))[0] == 2
    assert k.read_bytes() == before
    assert not (tree / "phi" / "out.tsv").exists()


def test_a_key_linked_after_it_was_read_is_not_appended(tree, ps, monkeypatch):
    k = _good_key(tree)
    before = k.read_bytes()
    real = ps._read_key

    def read_then_link(*a, **kw):
        key = real(*a, **kw)
        os.link(k, tree / "home" / "hard.tsv")
        return key
    monkeypatch.setattr(ps, "_read_key", read_then_link)
    write_table(tree / "data" / "new.tsv", ["mrn", "site"], [["9990900", "a"]])
    assert run(tree, base(tree, new=False, inp=tree / "data" / "new.tsv"))[0] == 2
    assert k.read_bytes() == before
    assert not (tree / "phi" / "out.tsv").exists()


def test_the_key_folder_is_opened_part_by_part_without_links(tree, ps):
    """`~/.phiward` a link to a folder of ours that holds a private backups folder: refused."""
    home = tree / "home"
    alt = tree / "alt"
    os.rename(home / ".phiward", alt)
    os.symlink(alt, home / ".phiward")
    assert run(tree, base(tree))[0] == 2
    assert not (alt / "backups" / "keys").exists()
    nothing_written(tree)


def test_an_output_in_a_write_to_folder_is_refused(tree, ps):
    w = tree / "phi" / "w"
    w.mkdir()
    cfg = Path(os.environ["PHIWARD_CONFIG"])
    cfg.write_text(cfg.read_text() + f'[broker]\nwrite_to = ["{w}"]\n')
    assert run(tree, base(tree, out=w / "out.tsv"))[0] == 2
    assert not (w / "out.tsv").exists()
    nothing_written(tree)


def test_the_output_folder_is_opened_without_links(tree, ps, monkeypatch):
    """The folder checked is the folder written: a link put in its place after the check is
    not followed."""
    real = ps._out_place

    def swap(*a, **kw):
        got = real(*a, **kw)
        os.rename(tree / "phi" / "sub", tree / "phi" / "sub-moved")
        os.symlink(tree / "pub", tree / "phi" / "sub")
        return got
    monkeypatch.setattr(ps, "_out_place", swap)
    assert run(tree, base(tree, out=tree / "phi" / "sub" / "out.tsv"))[0] == 2
    assert not (tree / "pub" / "out.tsv").exists()
    assert not (tree / "home" / ".phiward" / "backups" / "keys" / "labs.tsv").exists()


def test_the_shuffle_is_the_systems_random(ps, monkeypatch):
    import random
    calls = []
    monkeypatch.setattr(random.SystemRandom, "shuffle", lambda self, x: calls.append(type(self)))
    ps._shuffle([1, 2, 3])
    assert calls == [random.SystemRandom]


@pytest.mark.parametrize("ch", ["​", "﻿", "‍", "⁠", "‮"])
def test_a_format_character_in_a_coded_cell_is_refused(tree, ps, ch):
    write_table(tree / "data" / "labs.tsv", ["site", "mrn"],
                [["lab", "9990001"], ["lab", f"99900{ch}02"]])
    code, text = run(tree, base(tree))
    assert code == 2 and "column 2" in text, text
    nothing_written(tree)


# --- review round 2 ---------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", ['phiward run -- grep -c phiward "$f"', 'grep -rn phiward "$dir"',
                                 "pip show phiward $Q", "echo phiward $HOME",
                                 "pytest -k phiward $ARGS", "uv pip install phiward ${V}",
                                 "phiward run -- grep -l phiward *.md",
                                 "git log --grep phiward $(git rev-parse HEAD)",
                                 "env FOO=1 phiward doctor", "timeout 10 phiward run -- ls",
                                 "uv run phiward check -- ls", "phiward"])
def test_ordinary_commands_that_name_phiward_are_allowed(cmd):
    assert not gateway.is_operator_command(cmd), cmd


@pytest.mark.parametrize("cmd", ["xargs phiward", "xargs -n 1 phiward < f",
                                 "find . -name x -exec phiward {} \\;",
                                 "find . -execdir phiward $X \\;",
                                 "env phiward $X", "FOO=1 phiward $X", "command phiward *",
                                 "exec phiward ${X}", "timeout 10 phiward $(cat f)",
                                 "nice -n 5 phiward $X", "nohup phiward $X", "time phiward $X",
                                 "uvx phiward $X", "uv run phiward $X", "pipx run phiward $X",
                                 "python3 -m phiward $X", "python3 -mphiward $X",
                                 "ls; phiward $X", "true && /usr/bin/phiward $X",
                                 "echo $(phiward $X)"])
def test_phiward_in_command_position_with_a_run_time_or_missing_subcommand_is_refused(cmd):
    assert gateway.is_operator_command(cmd), cmd


def test_a_kept_cell_with_a_format_character_is_refused(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "note"],
                [["9990001", "a\u200bb"], ["9990002", "ok"]])
    code, text = run(tree, base(tree))
    assert code == 2 and "column 2" in text, text
    nothing_written(tree)


def test_an_id_written_in_other_unicode_forms_in_another_column_is_refused(tree, ps):
    # fullwidth digits read as the MRN after NFKC
    write_table(tree / "data" / "labs.tsv", ["mrn", "note"],
                [["9990001", "\uff19\uff19\uff19\uff10\uff10\uff10\uff11"], ["9990002", "ok"]])
    assert run(tree, base(tree))[0] == 2
    nothing_written(tree)


def test_a_short_id_refuses_only_a_whole_cell(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "note"],
                [["12", "0.12"], ["13", "2020-12-01"], ["14", "12 mg"], ["15", "x"]])
    assert run(tree, base(tree))[0] == 0
    os.unlink(tree / "phi" / "out.tsv")
    write_table(tree / "data" / "labs.tsv", ["mrn", "note"], [["12", " 12 "], ["15", "x"]])
    assert run(tree, base(tree, new=False))[0] == 2


@pytest.mark.parametrize("marker", [".claude", ".phiward.toml"])
def test_an_input_inside_another_project_is_refused(tree, ps, marker):
    """A project the agent may work in (its `.claude` settings can let it write anywhere in
    it): an input below its top is refused, whatever the working folder."""
    top = tree / "otherproj"
    top.mkdir()
    (top / marker).mkdir() if marker == ".claude" else (top / marker).write_text("")
    p = write_table(top / "deep" / "in.tsv", ["mrn", "site"], [["9990001", "lab"]])
    assert run(tree, base(tree, inp=p))[0] == 2
    nothing_written(tree)


# --- review round 3 ---------------------------------------------------------------------------

@pytest.mark.parametrize("ident,cell", [("FAKE PT 0001", "seen FAKE PT 0001 today"),
                                        ("FAKE:0001", "ref=FAKE:0001"),
                                        ("FAKE-PT-0001", "FAKE-\u200bPT-0001"),
                                        ("FAKE-PT-0001", "\uff26\uff21\uff2b\uff25-PT-0001"),
                                        ("FAKE-PT-0001", "fake-pt-0001.bam")])
def test_a_long_id_anywhere_in_a_kept_cell_is_refused(tree, ps, ident, cell):
    write_table(tree / "data" / "labs.tsv", ["mrn", "note"], [[ident, cell], ["FAKE-PT-0009", "ok"]])
    code, text = run(tree, base(tree), extra=["note"])
    assert code == 2 and "column 2" in text, text
    nothing_written(tree)


def test_a_drawn_code_that_holds_a_long_id_is_skipped(tree, ps, monkeypatch):
    # an ID that is a code itself: the code is never given to another ID
    write_table(tree / "data" / "labs.tsv", ["mrn", "site"], [["S9999", "lab"], ["9990002", "lab"]])
    monkeypatch.setattr(ps.secrets, "randbelow", lambda n: n - 1)
    assert run(tree, base(tree, more=["--keep-order"]))[0] == 0
    assert "S9999" not in key_map(tree / "home", "labs").values()
