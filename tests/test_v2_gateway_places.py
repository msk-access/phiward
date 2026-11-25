"""The Linux gateway's binds, checked inside before the command runs. bwrap resolves each bind
source to a name and mounts that name, so the helper confirms, for every bind with a host source,
that the object at its name in the view is the one recorded before the start, and that it is a
mount there. Each test makes one change at a fixed point, never by timing: a shim stands for
bwrap's lookup (it hands bwrap the names it read back, after the test's change), and an optional
pause holds the command until the host acted after the mounts. Made-up trees only (conftest.py)."""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile

import pytest

from phiward import confine
from helpers import CONFINE_WHY

linux_confined = pytest.mark.skipif(not sys.platform.startswith("linux") or CONFINE_WHY is not None,
                                    reason=f"Linux confinement: {CONFINE_WHY}")

# argv: ACTS BWRAP ARGS...   ACTS (json): changes made after the names are read back:
#   ["rename", a, b], ["symlink", target, name], ["mkdir", p],
#   ["srcto", name, other]: the first word `name` (a bind's source) becomes `other`.
# With SHIM_SYNC=W,R the command waits inside, after every mount, until the test acted.
SHIM = r"""
import json, os, sys
acts, bwrap, args = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3:]
named = [os.readlink(a) if a.startswith("/proc/self/fd/") else a for a in args]
for a in acts:
    if a[0] == "rename":
        os.rename(a[1], a[2])
    elif a[0] == "symlink":
        os.symlink(a[1], a[2])
    elif a[0] == "mkdir":
        os.mkdir(a[1])
    elif a[0] == "srcto":
        named[named.index(a[1])] = a[2]
if os.environ.get("SHIM_SYNC"):
    w, r = os.environ["SHIM_SYNC"].split(",")
    i = named.index("--")
    pause = ("import os, sys; os.write(%s, b'r'); os.read(%s, 1); "
             "os.execv(sys.argv[1], sys.argv[1:])" % (w, r))
    named[i + 1:i + 1] = [sys.executable, "-I", "-S", "-c", pause]
os.execv(bwrap, [bwrap] + named)
"""

HELPER_MSG = "phiward gateway: "
OPEN = "cannot be opened"
CHANGED = "is not what was checked before the start"
MOUNT = "is not a mount at its name"
MALFORMED = "the list of binds is malformed"
TWICE = "a bind is listed twice"


def gateway(writable, cmd, acts=(), after=(), deny_read=(), allow_read=(), sock=""):
    """Run `cmd` through confine.gateway_command's own argv, bwrap's lookup made by the shim.
    `after`: changes the test makes once every mount is made, before the helper runs."""
    argv, fds = confine.gateway_command(list(cmd), [str(w) for w in writable], [], False,
                                        deny_read=[str(d) for d in deny_read], socket=str(sock),
                                        allow_read=[str(a) for a in allow_read])
    argv = [sys.executable, "-I", "-c", SHIM, json.dumps(list(acts)), argv[0]] + argv[1:]
    env = dict(os.environ)
    extra = []
    if after:
        rr, rw = os.pipe()
        gr, gw = os.pipe()
        extra = [rw, gr]
        env["SHIM_SYNC"] = f"{rw},{gr}"
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                             pass_fds=fds + extra, cwd="/")
    finally:
        for fd in fds:
            os.close(fd)
    if after:
        os.close(rw)
        os.close(gr)
        got = os.read(rr, 10)
        if got:  # the command reached the pause: every mount is made
            for a in after:
                if a[0] == "rename":
                    os.rename(a[1], a[2])
                elif a[0] == "mkdir":
                    os.mkdir(a[1])
        try:
            os.write(gw, b"go\n")
        except BrokenPipeError:  # the start ended before the pause (bwrap refused)
            pass
        os.close(gw)
        os.close(rr)
    out = p.communicate(timeout=120)[0].decode("utf-8", "replace")
    return p.returncode, out


@pytest.fixture
def places(tree):
    """T/pub/proj/out: a write place in a folder others write; T/hid/id_fake: hidden."""
    out = tree / "pub" / "proj" / "out"
    out.mkdir(parents=True)
    hid = tree / "hid"
    hid.mkdir()
    (hid / "id_fake").write_text("FAKE-KEY-0001\n")
    scratch = tree / "scratch"
    scratch.mkdir()
    return tree, scratch, out, hid


def _sh(script):
    return ["/bin/sh", "-c", script]


def _refused(code, out, reason):
    assert code == 126 and HELPER_MSG in out and reason in out, (code, out)


# --- a place ------------------------------------------------------------------------------------

@linux_confined
def test_t1_a_hidden_folder_mounted_at_a_place_whose_name_then_moved_stops_the_start(places):
    tree, scratch, out, hid = places
    moved = f"{out}.moved"
    code, text = gateway([scratch, out], _sh(f"cat {moved}/id_fake; true"),
                         acts=[["srcto", str(out), str(hid)]],
                         after=[["rename", str(out), moved]], deny_read=[hid])
    assert "FAKE-KEY-0001" not in text, text
    _refused(code, text, OPEN)


@linux_confined
def test_t2_a_place_put_back_at_its_name_but_not_mounted_there_stops_the_start(places):
    tree, scratch, out, hid = places
    old, moved = f"{out}.old", f"{out}.moved"
    code, text = gateway([scratch, out], _sh(f"cat {moved}/id_fake; true"),
                         acts=[["rename", str(out), old], ["mkdir", str(out)],
                               ["srcto", str(out), str(hid)]],
                         after=[["rename", str(out), moved], ["rename", old, str(out)]],
                         deny_read=[hid])
    assert "FAKE-KEY-0001" not in text, text
    _refused(code, text, MOUNT)


@linux_confined
def test_t3_a_root_folder_mounted_at_a_moved_place_is_never_written(places):
    tree, scratch, out, hid = places
    moved = f"{out}.moved"
    code, text = gateway([scratch, out], _sh(f"echo x > {moved}/written.txt; true"),
                         acts=[["srcto", str(out), str(tree / "phi")]],
                         after=[["rename", str(out), moved]])
    assert not (tree / "phi" / "written.txt").exists()
    _refused(code, text, OPEN)


@linux_confined
def test_t4_a_place_whose_source_resolves_elsewhere_stops_the_start(places):
    # pinning: today's helper already refused this, with another message
    tree, scratch, out, hid = places
    code, text = gateway([scratch, out], _sh(f"cat {out}/id_fake; true"),
                         acts=[["srcto", str(out), str(hid)]], deny_read=[hid])
    assert "FAKE-KEY-0001" not in text, text
    _refused(code, text, CHANGED)


@linux_confined
def test_t5_control_a_place_unchanged_is_written(places):
    tree, scratch, out, hid = places
    code, text = gateway([scratch, out], _sh(f"echo x > {out}/ok.txt && echo wrote"))
    assert code == 0 and "wrote" in text, text
    assert (out / "ok.txt").exists()


@linux_confined
def test_t6_a_place_that_cannot_be_opened_at_its_name_stops_the_start(places):
    tree, scratch, out, hid = places
    code, text = gateway([scratch, out], ["true"], after=[["rename", str(out), f"{out}.moved"]])
    _refused(code, text, OPEN)


# --- the helper's own input ---------------------------------------------------------------------

def _helper(entries):
    return subprocess.run([sys.executable, "-I", "-S", "-c", confine.LANDLOCK_HELPER,
                           str(len(entries))] + entries + ["0", "true"],
                          capture_output=True, text=True, timeout=60)


@linux_confined
@pytest.mark.parametrize("entry", ["", "abc", "x|1|2", "/nonexistent|1|2", "2f746d70:1:2",
                                   "2f746d70:a:2:w", "zz:1:2:w", "2f00:1:2:w", "2f746d70:1:2:q",
                                   "2f746d70:-:-:w", "2f746d70:1:2:w:x"],
                         ids=["empty", "word", "old-form", "old-form-missing", "three-fields",
                              "dev-not-a-number", "not-hex", "nul", "unknown-kind",
                              "place-without-identity", "five-fields"])
def test_t8_a_malformed_entry_stops_the_start(entry):
    r = _helper([entry])
    assert r.returncode == 126 and MALFORMED in r.stderr, (r.returncode, r.stderr)


@linux_confined
def test_t8_a_count_that_is_not_a_number_stops_the_start():
    r = subprocess.run([sys.executable, "-I", "-S", "-c", confine.LANDLOCK_HELPER, "x", "true"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 126 and HELPER_MSG in r.stderr, (r.returncode, r.stderr)


@linux_confined
def test_t16_a_bind_listed_twice_stops_the_start(tmp_path):
    st = os.stat("/dev/null")
    e = f"{os.fsencode('/dev/null').hex()}:-:-:d"
    r = _helper([e, e])
    assert r.returncode == 126 and TWICE in r.stderr, (r.returncode, r.stderr, st)


# --- the read-only binds ------------------------------------------------------------------------

@linux_confined
def test_t9_a_claude_folder_put_back_but_not_mounted_stops_the_start(places):
    tree, scratch, out, hid = places
    c = out / ".claude"
    c.mkdir()
    (c / "settings.json").write_text("{}\n")
    old, moved = f"{c}.old", str(out / "moved")
    code, text = gateway([scratch, out], _sh(f"cat {moved}/id_fake; true"),
                         acts=[["rename", str(c), old], ["mkdir", str(c)],
                               ["srcto", str(c), str(hid)]],
                         after=[["rename", str(c), moved], ["rename", old, str(c)]],
                         deny_read=[hid])
    assert "FAKE-KEY-0001" not in text, text
    _refused(code, text, MOUNT)


@linux_confined
def test_t10_control_a_claude_folder_in_a_place_stays_read_only(places):
    tree, scratch, out, hid = places
    c = out / ".claude"
    c.mkdir()
    code, text = gateway([scratch, out], _sh(f"echo x > {c}/settings.json; echo x > {out}/ok.txt"
                                             " && echo wrote"))
    assert code == 0 and "wrote" in text, text
    assert not (c / "settings.json").exists() and (out / "ok.txt").exists()


@linux_confined
def test_t12_an_allow_read_file_swapped_for_a_hidden_file_stops_the_start(places):
    tree, scratch, out, hid = places
    conf = tree / "home" / "fake-ssh-config"
    conf.write_text("FAKE-CONFIG-0001\n")
    code, text = gateway([scratch], _sh(f"cat {conf}; true"),
                         acts=[["srcto", str(conf), str(hid / "id_fake")]],
                         deny_read=[hid], allow_read=[conf])
    assert "FAKE-KEY-0001" not in text, text
    _refused(code, text, CHANGED)


@pytest.fixture
def sockets():
    """Two unix sockets with short names (a socket path has a length limit)."""
    d = tempfile.mkdtemp(prefix="pw-", dir="/tmp")
    out = []
    for n in ("a", "b"):
        s = socket.socket(socket.AF_UNIX)
        s.bind(os.path.join(d, n))
        out.append(s)
    yield os.path.join(d, "a"), os.path.join(d, "b")
    for s in out:
        s.close()
    shutil.rmtree(d)


@linux_confined
def test_t11_a_socket_swapped_for_another_stops_the_start(places, sockets):
    tree, scratch, out, hid = places
    a, b = sockets
    code, text = gateway([scratch], _sh(f"test -S {confine.LINUX_SOCKET} && echo seen"),
                         acts=[["srcto", a, b]], sock=a)
    _refused(code, text, CHANGED)


@linux_confined
def test_t13_control_allow_read_and_the_socket_unchanged(places, sockets):
    tree, scratch, out, hid = places
    a, b = sockets
    conf = tree / "home" / "fake-ssh-config"
    conf.write_text("FAKE-CONFIG-0001\n")
    code, text = gateway([scratch], _sh(f"cat {conf} && test -S {confine.LINUX_SOCKET} && "
                                        "echo seen"), allow_read=[conf], sock=a)
    assert code == 0 and "FAKE-CONFIG-0001" in text and "seen" in text, text


# --- controls -----------------------------------------------------------------------------------

@linux_confined
def test_t14_control_nested_places_given_deepest_first_are_both_written(places):
    tree, scratch, out, hid = places
    sub = out / "sub"
    sub.mkdir()
    code, text = gateway([scratch, sub, out], _sh(f"echo x > {sub}/a.txt && echo x > {out}/b.txt"
                                                  " && echo wrote"))
    assert code == 0 and "wrote" in text, text
    assert (sub / "a.txt").exists() and (out / "b.txt").exists()


@linux_confined
@pytest.mark.parametrize("name", ["with space", "with\ttab", "with\nnewline", "with\\backslash",
                                  os.fsdecode(b"not-utf8-\xff\xfe")],
                         ids=["space", "tab", "newline", "backslash", "not-utf8"])
def test_t15_control_a_place_with_an_unusual_name_is_written(places, name):
    tree, scratch, out, hid = places
    p = out / name
    p.mkdir()
    code, text = gateway([scratch, p], [sys.executable, "-I", "-c",
                                        "import os, sys; open(os.path.join(sys.argv[1], 'ok.txt'),"
                                        " 'w').write('x'); print('wrote')", str(p)])
    assert code == 0 and "wrote" in text, (code, text)
    assert (p / "ok.txt").exists()


# --- a read-only bind's name changed after the binds were listed, before they were recorded -----

def _refused_by_bwrap_or_helper(code, text):
    """The destination is the same name as the source, so bwrap itself refuses the link (0.10+:
    "Can't mount on symlink destination"; 0.9: it cannot mount there); or the helper does."""
    if text.startswith("bwrap: "):
        assert code == 1, (code, text)
    else:
        _refused(code, text, CHANGED)


def _swap_after_args(monkeypatch, name, target):
    """Seam: right after the binds are listed (bwrap_gateway_args), `name` becomes a link to
    `target`; the records are taken after this, then bwrap runs."""
    real = confine.bwrap_gateway_args

    def listed(*a, **k):
        out = real(*a, **k)
        os.rename(name, f"{name}.old")
        os.symlink(target, name)
        return out
    monkeypatch.setattr(confine, "bwrap_gateway_args", listed)


@linux_confined
def test_t17_a_socket_turned_into_a_link_after_the_listing_stops_the_start(places, sockets,
                                                                           monkeypatch):
    tree, scratch, out, hid = places
    a, b = sockets
    _swap_after_args(monkeypatch, a, b)
    code, text = gateway([scratch], _sh(f"test -S {confine.LINUX_SOCKET} && echo seen"), sock=a)
    assert "seen" not in text, text
    _refused(code, text, CHANGED)


@linux_confined
def test_t18_an_allow_read_file_turned_into_a_link_after_the_listing_stops_the_start(
        places, monkeypatch):
    # pinning: nothing runs, before and after the fix
    tree, scratch, out, hid = places
    conf = tree / "home" / "fake-ssh-config"
    conf.write_text("FAKE-CONFIG-0001\n")
    _swap_after_args(monkeypatch, str(conf), str(hid / "id_fake"))
    code, text = gateway([scratch], _sh(f"cat {conf}; echo ran"), deny_read=[hid],
                         allow_read=[conf])
    assert "FAKE-KEY-0001" not in text and "ran" not in text, text
    _refused_by_bwrap_or_helper(code, text)


@linux_confined
def test_t19_a_claude_folder_turned_into_a_link_after_the_listing_stops_the_start(
        places, monkeypatch):
    # pinning, as t18
    tree, scratch, out, hid = places
    c = out / ".claude"
    c.mkdir()
    _swap_after_args(monkeypatch, str(c), str(hid))
    code, text = gateway([scratch, out], _sh(f"cat {c}/id_fake; echo ran"), deny_read=[hid])
    assert "FAKE-KEY-0001" not in text and "ran" not in text, text
    _refused_by_bwrap_or_helper(code, text)


@linux_confined
def test_t20_a_pattern_match_that_appears_while_the_request_starts_is_not_a_traceback(
        places, monkeypatch):
    # the places are listed once: a match made after that is not bound, and nothing raises
    tree, scratch, out, hid = places
    calls = []
    real = confine.gateway_places

    def places_(*a, **k):
        calls.append(1)
        got = real(*a, **k)
        if len(calls) > 1:
            got = got + [str(tree / "pub")]
        return got
    monkeypatch.setattr(confine, "gateway_places", places_)
    code, text = gateway([scratch, out], _sh("echo ran"))
    assert code == 0 and "ran" in text and len(calls) == 1, (code, text, calls)
