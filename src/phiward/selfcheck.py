"""The trusted runtime checks itself: before `launch` starts a tool, phiward's
own installed files must match the hashes its installer recorded (pip and uv write them to the
distribution's RECORD), and must not be writable by anyone but their owner, who must be the
operator or root. A file changed since install (by an earlier session that ran without
`launch`, for example) makes `launch` refuse.

The check runs in a separate interpreter (`-I -S -B`, its bytecode prefix a path that cannot
exist: `-B` only stops writing, so a prefix in a folder another program can write would let it
plant a `.pyc` that runs), from this file as a script, so no compiled file changes the check. It
also finds:
- a compiled file (`__pycache__/*.pyc`) whose code is not the code of its source: Python runs a
  `.pyc` whose header matches the source, and an unchecked hash-based one always;
- a file in the package that the record does not list: an extension module (`cli.*.so`) is
  imported before `cli.py`.

Limits: the check is phiward's own code. Code that changes the launcher so that it skips the
check is not found by it; reinstall when in doubt. An install without a record (a source
checkout, an editable install) has nothing to check against: `launch` refuses it unless
PHIWARD_DEV=1 is set.

Standard library only: this file runs with no site folder."""

import base64
import contextlib
import csv
import hashlib
import io
import json
import marshal
import os
import re
import stat
import subprocess
import sys
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

DIST = "phiward"
PACKAGE = "phiward"


class _NotRegular(OSError):
    """A file phiward reads (`_open_regular`) is not a regular file."""


def _open_regular(path: str) -> int:
    """Open a file to read it, never through a link and never waiting (a FIFO): O_NOFOLLOW and
    O_NONBLOCK, then fstat; `_NotRegular` when it is not a regular file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _NotRegular(path)
    except OSError:
        os.close(fd)
        raise
    return fd


def _read_regular(path: str) -> bytes:
    fd = _open_regular(path)
    try:
        chunks = []
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                return b"".join(chunks)
            chunks.append(b)
    finally:
        os.close(fd)


def _sha256_b64(path: str) -> str:
    h = hashlib.sha256()
    fd = _open_regular(path)
    try:
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            h.update(b)
    finally:
        os.close(fd)
    return base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode("ascii")


HOME_PROBLEM = "your home folder can be written by your group"
OUTSIDE = "(outside your home folder)"
OUTSIDE_MINE = "(outside your home folder; yours)"
# the rule's two whys (the texts tests, doctor and fix_text read)
WRITABLE = "writable by others"
NOT_MINE = "owned by another user"
# the home folder itself, owned by another account (`_where`)
HOME_OWNER = "~/: " + NOT_MINE
# what `check_isolated` and `check_full_isolated` say when the check's child gives no answer
CHECK_FAILED = "the self-check could not run"
CHECK_SLOW = "the self-check did not finish in time"


def _home() -> str:
    """The user's home folder, from the account database and never `$HOME` (the check runs with
    an empty environment), as a real path; "" when the account is not known."""
    try:
        import pwd
        return os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError):
        return ""


def foreign_writable(st: Any) -> bool:
    """Whether another account could write a file with this `os.stat` result: its group or its
    other write bit is set. phiward does not try to tell the user's own private group from a
    shared one: ACLs, accounts it cannot list (LDAP, sssd) and NFS homes made every such guess
    unreliable, and clearing the group bit costs a private group nothing."""
    return bool(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


_BREW = ("/opt/homebrew", "/usr/local")


def _homebrew_admin(path: str, st: Any) -> bool:
    """The one exception to the rule: on macOS, one of Homebrew's own folders, which the `admin`
    group may write (its members can use sudo already): group `admin`, owned by the user or root,
    not writable by others, its real path one of Homebrew's two prefixes or below one."""
    if sys.platform != "darwin" or st.st_mode & stat.S_IWOTH or not _mine(st):
        return False
    try:
        import grp
        if grp.getgrgid(st.st_gid).gr_name != "admin":
            return False
    except (ImportError, KeyError):
        return False
    real = os.path.realpath(path)
    return any(real == b or real.startswith(b + "/") for b in _BREW)


def _inside(path: str, folder: str) -> bool:
    """`pathid.inside`, written out: this file runs as a script with the standard library only
    (the self-check's child), so it cannot import it. No folder (no venv, no stdlib) holds
    nothing here."""
    if not folder:
        return False
    return path == folder or path.startswith(folder.rstrip("/") + "/") or folder == "/"


def _entry_problem(path: str, st: Any) -> Optional[str]:
    """The rule for one entry, without the folders above it. A link's own mode never counts (on
    Linux every link shows 0777): its folder and its target are judged instead."""
    if not _mine(st):
        return NOT_MINE
    if not stat.S_ISLNK(st.st_mode) and foreign_writable(st) and not _homebrew_admin(path, st):
        return WRITABLE
    return None


def _shown(path: str, home: str) -> str:
    """`path` from the home folder (`~/REL`) when it is inside it, as spelled or as its folder
    really is (a linked `/home`); else as it is."""
    if not home:
        return path
    real = os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))
    for p, h in ((path, home), (real, os.path.realpath(home))):
        if _inside(p, h) and os.path.normpath(p) != os.path.normpath(h):
            return "~/" + os.path.relpath(p, h)
    return path


# the folders already judged, within one check (`_cached`); None outside one, where nothing is
# kept (the broker asks again and again, and a folder's mode can change)
_CACHE: Optional[Dict[Any, Optional[str]]] = None


@contextlib.contextmanager
def _cached() -> Any:
    global _CACHE
    old = _CACHE
    _CACHE = {} if old is None else old
    try:
        yield
    finally:
        _CACHE = old


def _home_ids() -> Tuple[Optional[Tuple[int, int]], frozenset]:
    """(the home folder's (st_dev, st_ino), those of each folder above it). Home is known by
    identity, not by its spelling: `/home -> var/home`, macOS's case-insensitive names and
    `/System/Volumes/Data` all lead to the same folder."""
    key = ("home-ids",)
    if _CACHE is not None and key in _CACHE:
        return _CACHE[key]  # type: ignore[return-value]
    home = _home()
    out: Tuple[Optional[Tuple[int, int]], frozenset] = (None, frozenset())
    if home:
        try:
            st = os.stat(home)
            above = set()
            d = home
            while os.path.dirname(d) != d:
                d = os.path.dirname(d)
                s = os.stat(d)
                above.add((s.st_dev, s.st_ino))
            out = ((st.st_dev, st.st_ino), frozenset(above))
        except OSError:
            pass
    if _CACHE is not None:
        _CACHE[key] = out  # type: ignore[assignment]
    return out


def _mine(st: Any) -> bool:
    return st.st_uid in (os.getuid(), 0)


def _ids(st: Any) -> Tuple[int, int]:
    return (st.st_dev, st.st_ino)


def _folder_on_way(stack: List[Tuple[str, Any]], child: Any, home_id: Any,
                   above: frozenset) -> Optional[str]:
    """The rule for the folder at the top of `stack` (from `/` down: (name, lstat)), as the walk
    steps into its entry `child` (an lstat): owned by the user or root, and no group or other
    write (Homebrew's admin folders aside). A folder above the home folder is skipped when the
    walk goes on towards home (a lab folder a PI owns, above `/data/lab/u`), and judged when it
    leaves that way. A sticky folder outside home is fine for an entry that is the user's or
    root's (the last entry never gets that: `_walk`)."""
    here = stack[-1][1]
    hid = _ids(here)
    toward_home = hid in above and (_ids(child) == home_id or _ids(child) in above)
    inside = _in_home(stack, home_id)
    key = (hid, toward_home, _mine(child), inside)
    if _CACHE is not None and key in _CACHE:
        return _CACHE[key]
    why: Optional[str] = None
    if not toward_home:
        folder = "/" + "/".join(n for n, _st in stack[1:])
        bad = ""
        if not _mine(here):
            bad = NOT_MINE
        elif foreign_writable(here) and not _homebrew_admin(folder, here) and \
                not (not inside and here.st_mode & stat.S_ISVTX and _mine(child)):
            bad = WRITABLE
        if bad:
            why = _where(stack, home_id, inside, bad, here)
    if _CACHE is not None:
        _CACHE[key] = why
    return why


def _where(stack: List[Tuple[str, Any]], home_id: Any, inside: bool, bad: str,
           here: Any, entry: str = "") -> str:
    """A fault as the operator reads it, from the walk, which knows where it is: the folder at
    the top of `stack` (`here` its lstat), or with `entry` that entry of it (`here` the entry's
    lstat). The home folder: its own text; inside home: `~/REL/: why` for a folder, `~/REL: why`
    for an entry; outside home: `PATH/: why MARKER` or `PATH: why MARKER`, the marker saying
    whether the fault is yours (its step differs: `fix_text`)."""
    if not entry and home_id is not None and _ids(here) == home_id:
        return _home_text(bad)
    names = [n for n, _st in stack[1:]] + ([os.path.basename(entry)] if entry else [])
    names = [n for n in names if n]
    # a folder is named with its `/`, whether it is the walk's last entry or a folder on the way
    slash = "/" if (not entry or stat.S_ISDIR(here.st_mode)) and names else ""
    if inside:
        at = max(i for i, (_n, st) in enumerate(stack) if _ids(st) == home_id)
        return "~/" + "/".join(names[at:]) + f"{slash}: {bad}"
    tail = OUTSIDE_MINE if here.st_uid == os.getuid() else OUTSIDE
    return "/" + "/".join(names) + f"{slash}: {bad} {tail}"


def _home_text(why: str) -> str:
    """The fault of the home folder itself, as the operator reads it."""
    return HOME_PROBLEM if why == WRITABLE else f"~/: {why}"


def _in_home(stack: List[Tuple[str, Any]], home_id: Any) -> bool:
    return home_id is not None and any(_ids(st) == home_id for _n, st in stack)


def _last_problem(stack: List[Tuple[str, Any]], home_id: Any, entry: str,
                  st: Any) -> Optional[str]:
    """The rule for the last entry of a walk: inside home the bare why (the caller names the
    file; the steps there need no place), outside home the entry and its marker."""
    why = _entry_problem(entry, st)
    if why is None:
        return None
    if home_id is not None and _ids(st) == home_id:
        return _home_text(why)
    if _in_home(stack, home_id):
        return why
    return _where(stack, home_id, False, why, st, entry)


MAX_LINKS = 40


def _walk(path: str, collect: Optional[List[Tuple[str, str]]] = None) -> Optional[Tuple[str, str]]:
    """`safe_path`: walk `path` from `/` as the kernel resolves it, one entry and one link at a
    time (never `abspath` first: it would collapse `link/..` before the kernel does). Every
    folder on the way is judged as the walk steps through it (`_folder_on_way`), so the folder
    of every link in a chain is judged; a link's own mode never counts, its owner does; only
    links count towards MAX_LINKS. The last entry: owned by the user or root, and no group or
    other write (no sticky exception). The first problem as (text, place): `place` the folder or
    entry judged, as the kernel resolved it (no link in it), "" when nothing is there. With
    `collect`, a fault that is yours and outside the home folder (its step is a `chmod go-w`) is
    added to it and the walk goes on, so one round names them all."""
    p = path if path.startswith("/") else os.path.join(os.getcwd(), path)
    home_id, above = _home_ids()
    try:
        stack: List[Tuple[str, Any]] = [("", os.lstat("/"))]
    except OSError:
        return "missing", ""

    def at(names: List[str]) -> str:
        return "/" + "/".join(names)

    def fault(why: str, place: str) -> Optional[Tuple[str, str]]:
        if collect is not None and why.endswith(OUTSIDE_MINE):
            if (why, place) not in collect:
                collect.append((why, place))
            return None
        return why, place

    todo = [c for c in p.split("/") if c]
    hops = 0
    while todo:
        c = todo.pop(0)
        if c == ".":
            continue
        if c == "..":
            if len(stack) > 1:
                stack.pop()
            continue
        names = [n for n, _st in stack[1:]]
        entry = at(names + [c])
        try:
            st = os.lstat(entry)
        except OSError:
            return "missing", ""
        why = _folder_on_way(stack, st, home_id, above)
        if why and fault(why, at(names)):
            return why, at(names)
        if stat.S_ISLNK(st.st_mode):
            hops += 1
            if hops > MAX_LINKS:
                return "too many links", ""
            if not _mine(st):
                return _where(stack, home_id, _in_home(stack, home_id),
                              NOT_MINE, st, entry), entry
            try:
                target = os.readlink(entry)
            except OSError:
                return "missing", ""
            if target.startswith("/"):
                stack = stack[:1]
            todo = [t for t in target.split("/") if t] + todo
            continue
        if todo:
            if not stat.S_ISDIR(st.st_mode):
                return "missing", ""  # the kernel says ENOTDIR
            stack.append((c, st))
            continue
        why = _last_problem(stack, home_id, entry, st)
        return fault(why, entry) if why else None
    # the path ends at a folder of the stack (`a/..`, or `/`)
    here = stack[-1][1]
    place = at([n for n, _st in stack[1:]])
    why = _last_problem(stack[:-1] or stack, home_id, place, here)
    return fault(why, place) if why else None


def safe_path(path: str) -> Optional[str]:
    """The rule for "another account can change it", the one used by the self-check, the
    broker's PATH and the launcher lookup: `path`, and each folder on the way to it, are owned
    by the user or root and not writable by group or other (`_walk`). Folders above the home
    folder are judged only where the way leaves the way home; a sticky folder outside home is
    fine for the user's own entry; a link is judged by its folder and owner, then its target.
    The first problem, or None."""
    found = _walk(path)
    return found[0] if found else None


def _faults(path: str) -> List[Tuple[str, str]]:
    """Every fault of `path` that one step can fix together, as (text, place): those that are
    yours outside the home folder (`_walk`'s `collect`), then the first other one."""
    out: List[Tuple[str, str]] = []
    last = _walk(path, out)
    return out + ([last] if last else [])


class Places(NamedTuple):
    """phiward's own Python, as the full check and `install` see it (`python_places`)."""
    venv: str  # the venv root, or ""
    walk: List[str]  # folders checked with everything in them
    files: List[str]  # single files: the interpreter and each link to it, pyvenv.cfg, libpython
    cfg: str  # the pyvenv.cfg Python reads (`_venv_cfg`), or "": the one source for the venv's
    stdlib: str  # the standard library, the one root that leaves out its own packages (`_below`)


def _link_chain(path: str) -> List[str]:
    """`path` and each link on the way to what it leads to, the last one included."""
    out: List[str] = []
    p = os.path.abspath(path)
    for _ in range(40):
        out.append(p)
        if not os.path.islink(p):
            break
        p = os.path.normpath(os.path.join(os.path.dirname(p), os.readlink(p)))
    return out


def _libpython() -> str:
    import sysconfig
    ld = sysconfig.get_config_var("LDLIBRARY") or ""
    for d in (sysconfig.get_config_var("PYTHONFRAMEWORKPREFIX"),
              sysconfig.get_config_var("LIBDIR")):
        if d and ld and os.path.isfile(os.path.join(d, ld)):
            return os.path.join(d, ld)
    return ""


def python_places(executable: Optional[str] = None, stdlib: Optional[str] = None,
                  dynload: Optional[str] = None,
                  libpython: Optional[str] = None) -> Places:
    """What phiward's Python reads and runs at start, worked out without `site` (the checker runs
    with `-I -S`): the interpreter and each link to it, the venv (with pyvenv.cfg), the standard
    library and lib-dynload, libpython, and the folders that the venv's .pth path lines add (those
    `_startup_files` accepts). Never a base Python's own site-packages or the rest of its prefix
    (conda's pkgs/ and envs/). The arguments are for tests."""
    import sysconfig
    exe = os.path.abspath(executable or sys.executable)
    cfg = _venv_cfg(exe)
    venv = os.path.dirname(os.path.dirname(exe)) if cfg else ""
    stdlib = sysconfig.get_path("stdlib") if stdlib is None else stdlib
    dynload = (sysconfig.get_config_var("DESTSHARED") or "") if dynload is None else dynload
    libpython = _libpython() if libpython is None else libpython
    stdlib = os.path.normpath(stdlib) if stdlib else ""
    # the roots: every folder Python reads is covered by one (`_covers`, by identity), however a
    # .pth line spells it; no root is covered by another (whatever the order of the lines)
    cands = ([venv] if venv else []) + [stdlib, os.path.normpath(dynload) if dynload else ""]
    for site in _venv_sites(venv):
        cands += _pth_targets(site)
    walk: List[str] = []
    for w in cands:
        if w and os.path.isdir(w) and not any(_covers(x, w, stdlib) for x in walk):
            walk.append(w)
    # after the first pass no two roots are the same folder: drop a root another one covers
    walk = [w for i, w in enumerate(walk)
            if not any(j != i and _covers(x, w, stdlib) for j, x in enumerate(walk))]
    files = _link_chain(exe)
    if cfg:
        files.append(cfg)
    if libpython:
        files += _link_chain(libpython)  # libpython3.12.so is often a link to the .so.1.0
    return Places(venv, walk, files, cfg, stdlib)


def _first_cfg(exe_dir: str) -> str:
    """The pyvenv.cfg that site.py reads for an interpreter in `exe_dir`: the first of
    `exe_dir/pyvenv.cfg` and the one in the folder above that is a file; "" when none is (not a
    venv)."""
    for d in (exe_dir, os.path.dirname(exe_dir)):
        cfg = os.path.join(d, "pyvenv.cfg")
        if os.path.isfile(cfg):
            return cfg
    return ""


def _venv_cfg(exe: str) -> str:
    """`_first_cfg` for the interpreter `exe`, from its folder as spelled (site.py: `abspath`,
    not `realpath`)."""
    return _first_cfg(os.path.dirname(os.path.abspath(exe)))


def _venv_sites(venv: str) -> List[str]:
    if not venv:
        return []
    out = []
    for lib in ("lib", "lib64"):
        try:
            names = sorted(os.listdir(os.path.join(venv, lib)))
        except OSError:
            continue
        for n in names:
            site = os.path.join(venv, lib, n, "site-packages")
            if n.startswith("python") and os.path.isdir(site) and \
                    os.path.realpath(site) not in [os.path.realpath(o) for o in out]:
                out.append(site)
    return out


def _pth_targets(site: str) -> List[str]:
    """The folders that a site folder's accepted .pth path lines add, as Python makes them
    (`_pth_dir`): `check_python` then judges each with `safe_path`, every link on the way."""
    out: List[str] = []
    bad = {n for n, _why in _startup_problems(site)}
    try:
        names = sorted(n for n in os.listdir(site) if n.endswith(".pth") and n not in bad)
    except OSError:
        return []
    for n in names:
        _problem, lines, _text = _pth_lines(os.path.join(site, n))
        for kind, ln in lines:
            d = _pth_dir(site, ln)
            if kind == "path" and os.path.isdir(d) and d not in out:
                out.append(d)
    return out


MAX_PROBLEMS = 50
# names a walk of the standard library leaves out: a base Python's own packages, which phiward's
# venv does not put on its path
_NOT_WALKED = ("site-packages", "dist-packages")


def _inside_home(path: str, strict: bool = True) -> bool:
    """Whether `path` (where it leads) is inside the home folder, by identity (`_home_ids`);
    `strict`: not the home folder itself."""
    home_id, _above = _home_ids()
    if home_id is None:
        return False
    d = os.path.realpath(path)
    first = True
    while True:
        try:
            st = os.stat(d)
        except OSError:
            return False
        if _ids(st) == home_id:
            return not (strict and first)
        parent = os.path.dirname(d)
        if parent == d:
            return False
        d, first = parent, False


def _ident(path: str) -> Tuple[int, int]:
    st = os.stat(path)
    return (st.st_dev, st.st_ino)


def _is_stdlib(root: str, stdlib: str) -> bool:
    """Whether `root` is the standard library, by identity (a root given through a link too)."""
    try:
        return bool(stdlib) and _ident(root) == _ident(stdlib)
    except OSError:
        return False


def _own_packages(root: str, stdlib: str) -> Dict[str, Optional[Tuple[int, int]]]:
    """The one definition of what a walk leaves out: nothing, unless `root` is the standard
    library; then its top-level entries named site-packages or dist-packages on disk (the base
    Python's own packages, which a venv's Python does not read) that os.walk lists as folders
    (`is_dir()`, a link too), each with its identity when it is a real folder (None for a link).
    As os.walk reads the folder: a listing that fails gives nothing; an entry it cannot stat is
    not a folder."""
    if not _is_stdlib(root, stdlib):
        return {}
    out: Dict[str, Optional[Tuple[int, int]]] = {}
    try:
        entries = list(os.scandir(root))
    except OSError:
        return {}
    for e in entries:
        if e.name not in _NOT_WALKED:
            continue
        try:
            if not e.is_dir():
                continue
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue
        out[e.name] = (st.st_dev, st.st_ino) if stat.S_ISDIR(st.st_mode) else None
    return out


def _aside(root: str, stdlib: str) -> bool:
    """Whether the walk of `root` leaves out a real folder (`_own_packages`): its tree line and
    its step say so."""
    return any(i is not None for i in _own_packages(root, stdlib).values())


def _covers(root: str, path: str, stdlib: str) -> bool:
    """Whether the walk of `root` (`_below`) reaches `path`: climbing from where `path` really
    is, by identity, `root` is reached, and not through one of the real folders it leaves out
    (`_own_packages`, compared by identity: never by a spelled name). The one rule for what a
    root covers, with `_below`."""
    try:
        rid = _ident(root)
    except OSError:
        return False
    d, prev = os.path.realpath(path), None
    while True:
        try:
            here = _ident(d)
        except OSError:
            return False
        if here == rid:
            # the root reached: through what it leaves out? (listed only now, and only below it)
            return prev is None or prev not in {
                i for i in _own_packages(root, stdlib).values() if i is not None}
        parent = os.path.dirname(d)
        if parent == d:
            return False
        d, prev = parent, here


def _below(root: str, stdlib: str) -> Any:
    """Every folder and file below a walk root, as `check_python` judges them and `fix_modes`
    changes them (links are not followed: a link is judged where it leads), but what
    `_own_packages` leaves out (only for the standard library)."""
    own = _own_packages(root, stdlib)
    for here, dirs, names in os.walk(root):
        if here == root and own:
            dirs[:] = [d for d in dirs if d not in own]
        for n in dirs + names:
            yield os.path.join(here, n)


def check_python(places: Places) -> List[str]:
    """The full check of phiward's own Python: every file in `places`, and every folder and file
    in its folders (`_below`), with the folders above them, pass `safe_path`; a link is judged
    where it leads; the venv reads no base site folder (`_system_site`); and its start-up files
    pass `_startup_problems`, with no start-up module in a folder a .pth adds. One line per
    fault, `FAULT: why`, the place said by the walk (`_where`, `_faults`: every fault of yours
    outside the home folder in one round): outside the home folder with its marker, and the
    entries of yours below a root there as one line for the tree (TREE_WHY). Kept by `_Lines`:
    in the order the step reads them, at most MAX_PROBLEMS, then one line that there are
    more."""
    home = _home()
    keep = _Lines()

    def put(why: str, place: str, asked: str) -> None:
        # a fault the walk placed names itself; a bare one (the last entry, inside home) is
        # named by the place the walk judged (a link: where it leads; nothing there: the path
        # asked), a folder with `/`. Its kind is the why's: a full kind words nothing more
        key = (why, place or asked)
        if why == HOME_PROBLEM or why.startswith(("/", "~/")):
            keep.add(why)
        elif key in keep.at:
            pass  # worded and kept already: a duplicate says nothing more
        elif keep.full(_kind(why)):
            keep.more = True
        else:
            keep.at.add(key)
            if not place:
                keep.add(f"{_shown(asked, home)}: {why}")
            else:
                slash = "/" if os.path.isdir(place) and not os.path.islink(place) else ""
                keep.add(f"{_shown(place, home)}{slash}: {why}")

    def judged(found: List[Tuple[str, str]], asked: str) -> None:
        for why, place in found:
            put(why, place, asked)

    with _cached():
        for f in places.files:
            judged(_faults(f), f)
        for root in places.walk:
            # the root's own faults, and still everything below it: one round names them all
            judged(_faults(root), root)
            # os.walk does not follow links: every entry is where its root is
            outside = not _inside_home(root, strict=False)
            mine = 0
            for full in _below(root, places.stdlib):
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    # Python reads where a link leads: the way there and the target
                    judged(_link_faults(full), full)
                    continue
                why = _entry_problem(full, st)
                if why and outside and st.st_uid == os.getuid():
                    mine += 1  # yours, outside home: one line for the tree (`fix_text`)
                elif why:
                    put(f"{full}: {why} {OUTSIDE}" if outside else why, full, full)
            if mine:
                keep.add(_tree_line(root, mine, _aside(root, places.stdlib)))
        if _system_site(places.cfg):
            keep.add(f"{_shown(places.cfg, home)}: {SYSTEM_SITE}")
        for site in _venv_sites(places.venv):
            for n, why in _startup_problems(site):
                keep.add(f"{_shown(os.path.join(site, n), home)}: {why}")
            # `import sitecustomize` searches the folders the .pth lines added too
            for target in _pth_targets(site):
                try:
                    names = sorted(os.listdir(target))
                except OSError:
                    continue
                for n in names:
                    if _is_startup(n):
                        keep.add(f"{_shown(os.path.join(target, n), home)}: {PTH_STARTUP}")
    return keep.lines()


(K_HOME, K_HOME_OWNER, K_OUTSIDE, K_OUTSIDE_MINE, K_PTH, K_NO_ANSWER, K_REINSTALL,
 K_MODES) = range(8)
KINDS = 8


def _kind(problem: str) -> int:
    """A line's kind, in the order `fix_text` reads them (its step is the lowest kind's): the
    home folder writable by the group (0) or owned by another account (1); a fault outside it
    that another account owns or can write (2), or that is yours (3); a start-up file in a
    folder a .pth adds (4); a check that gave no answer (5); anything a reinstall fixes (6);
    a mode `install` fixes (7). Read from the end of the line only (a path may hold `: `), the
    whole line where it has no place."""
    if problem.endswith(HOME_PROBLEM):
        return K_HOME
    if problem == HOME_OWNER:
        return K_HOME_OWNER
    if problem.endswith(OUTSIDE):
        return K_OUTSIDE
    if problem.endswith(OUTSIDE_MINE):
        return K_OUTSIDE_MINE
    if problem.endswith(": " + PTH_STARTUP):
        return K_PTH
    if problem in (CHECK_FAILED, CHECK_SLOW):
        return K_NO_ANSWER
    if not problem.endswith(WRITABLE):
        return K_REINSTALL
    return K_MODES


MORE = "and more"


class _Lines:
    """The lines of a check, as the step reads them: each once, at most MAX_PROBLEMS of each
    kind (`_kind`), so a line of a lower kind is never pushed out by many of a higher one; a new
    line of a full kind only says there are more. `lines()`: the kinds in order, at most
    MAX_PROBLEMS, then MORE when there are more."""

    def __init__(self) -> None:
        self.kept: set = set()
        self.at: set = set()  # (why, place) of the lines `check_python` worded and kept
        self.by: List[List[str]] = [[] for _ in range(KINDS)]
        self.more = False

    def full(self, kind: int) -> bool:
        return len(self.by[kind]) >= MAX_PROBLEMS

    def add(self, text: str) -> None:
        if text == MORE:
            self.more = True
            return
        if text in self.kept:
            return
        kind = _kind(text)
        if self.full(kind):
            self.more = True
            return
        self.kept.add(text)
        self.by[kind].append(text)

    def lines(self) -> List[str]:
        out = [t for b in self.by for t in b]
        if self.more or len(out) > MAX_PROBLEMS:
            return out[:MAX_PROBLEMS] + [MORE]
        return out


# the tree line of `check_python` and `_check`: entries of yours below a root outside the home
# folder, which one `find` fixes (`_tree_step`)
TREE_WHY = "in it " + WRITABLE


# the standard library's tree line, when it holds its own packages folder: the step leaves it out
TREE_ASIDE = TREE_WHY + ", its own packages folder aside"


def _tree_line(root: str, n: int, aside: bool = False) -> str:
    """The one line for `n` entries of yours below `root`, outside the home folder; `aside`:
    the standard library's own packages folder is left out (`_below`, `_tree_step`)."""
    count = "1 entry" if n == 1 else f"{n} entries"
    return f"{root.rstrip('/')}/: {count} {TREE_ASIDE if aside else TREE_WHY} {OUTSIDE_MINE}"
SYSTEM_SITE = "lets Python read the base Python's and your own site folders"


def _system_site(cfg: str) -> bool:
    """Whether a venv's pyvenv.cfg (`_first_cfg`; "" for no venv) lets Python read the base
    site folders, as site.venv reads it (3.9 to 3.14): line by line, `key.strip().lower()` and
    `value.strip()`, the last line wins, and with no such line it does. A file that cannot be
    read as utf-8 counts as reading them (Python would not start)."""
    if not cfg:
        return False
    value = "true"
    try:
        # where a link leads (`places.files` judges the chain); never waiting on a FIFO; lines as
        # `for line in open(cfg)` gives them (universal newlines)
        text = _read_regular(os.path.realpath(cfg)).decode("utf-8")
        for line in io.StringIO(text, newline=None):
            if "=" in line:
                key, _, v = line.partition("=")
                if key.strip().lower() == "include-system-site-packages":
                    value = v.strip().lower()
    except (OSError, ValueError):
        return True
    return value == "true"


PTH_STARTUP = "a start-up file in a folder a .pth adds"


def _link_faults(link: str) -> List[Tuple[str, str]]:
    """A link inside phiward's Python, judged where it leads (`_faults`); a link that leads
    nowhere yet, by the deepest folder that exists on its way (another account could make the
    target there)."""
    found = _faults(link)
    if not found or found[-1][0] != "missing":
        return found
    d = os.path.dirname(os.path.realpath(link))
    while d != "/" and not os.path.isdir(d):
        d = os.path.dirname(d)
    return found[:-1] + _faults(d)


def _clear(path: str) -> bool:
    """Remove group and other write from one file or folder you own, never through a link and
    never waiting on a FIFO: opened with O_NOFOLLOW and O_NONBLOCK, then fstat and fchmod (the
    open file is what is changed, whatever happens to the name). Whether it was changed."""
    try:
        before = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(before.st_mode) or before.st_uid != os.getuid() or \
            not before.st_mode & 0o022:
        return False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return False
    try:
        st = os.fstat(fd)
        if st.st_uid != os.getuid() or (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino):
            return False
        mode = stat.S_IMODE(st.st_mode)
        if not mode & 0o022:
            return False
        os.fchmod(fd, mode & ~0o022)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def _launcher_link_folder(scripts: Any) -> str:
    """The PATH folder of the first `phiward` that leads to one of the launcher `scripts`, when it
    is inside the home folder (phiward never changes `/usr/local/bin`, nor the home folder)."""
    want = {os.path.realpath(sc) for sc in scripts}
    for e in os.environ.get("PATH", "").split(":"):
        cand = os.path.join(e, "phiward")
        if e.startswith("/") and os.path.lexists(cand) and os.path.realpath(cand) in want:
            return e if _inside_home(e) else ""
    return ""


def fix_modes(places: Optional[Places] = None, scripts: Optional[Any] = None,
              package_dir: Optional[str] = None) -> List[str]:
    """What `install` does for the full check, and only inside the home folder (never the home
    folder itself): compile the folders of `places` there that you own (leaving out a base
    Python's own site-packages, as the check does), so no other program on the same Python makes
    a group-writable `__pycache__` there later; then remove group and other write from what you
    own of them (`_below`), of the package, the launcher scripts and `places.files`, of the
    folders above them up to the home folder, and of the PATH folder that holds the `phiward`
    link. What is outside the home folder is left as it is: the check names it with its step.
    The folders where something was changed."""
    places = python_places() if places is None else places
    scripts = (launcher_scripts() or ()) if scripts is None else scripts
    package_dir = _running_package() if package_dir is None else package_dir
    import compileall
    roots = [r for r in places.walk if _inside_home(r)]
    for root in roots:
        try:
            if os.lstat(root).st_uid != os.getuid():
                continue
            # what the check judges (`_below`: what `_own_packages` leaves out, no link), and
            # only regular files: opening a FIFO named like a module would wait for ever
            for full in _below(root, places.stdlib):
                if full.endswith(".py") and stat.S_ISREG(os.lstat(full).st_mode):
                    compileall.compile_file(full, quiet=2)
        except Exception:  # noqa: BLE001 - a folder it cannot compile is checked as it is
            pass
    changed: List[str] = []

    seen: set = set()

    def note(path: str) -> None:
        d = path if os.path.isdir(path) and not os.path.islink(path) else os.path.dirname(path)
        if d not in seen:
            seen.add(d)
            changed.append(d)

    tops = roots + ([package_dir] if _inside_home(package_dir) else [])
    links: List[str] = []
    for root in tops:
        # inside the home folder, and os.walk does not follow links: everything below is too
        for full in [root] + list(_below(root, places.stdlib)):
            if os.path.islink(full):
                links.append(full)
            elif _clear(full):
                note(full)
    singles = [f for f in list(places.files) + list(scripts) if _inside_home(f)]
    for f in singles:
        if _clear(f):
            note(f)
    link_folder = _launcher_link_folder(scripts)
    if link_folder and _clear(link_folder):
        note(link_folder)
    for p in tops + singles + ([link_folder] if link_folder else []):
        d = os.path.dirname(os.path.realpath(p))
        while _inside_home(d):
            if _clear(d):
                note(d)
            d = os.path.dirname(d)
    # a link: what the check names of it (`_link_faults`: every folder of the chain, the
    # target, the deepest folder of a dangling one), judged again after each change, never
    # with a cache (a folder just changed must be judged anew)
    for link in links:
        for _ in range(MAX_LINKS * 2):
            found = _link_faults(link)
            place = next((pl for _why, pl in found if pl and _inside_home(pl)), "")
            if not place or not _clear(place):
                break
            note(place)
    return changed


_WHYS = (WRITABLE, NOT_MINE)
_TREE = re.compile(r": \d+ entr(?:y|ies) (" + re.escape(TREE_ASIDE) + "|" + re.escape(TREE_WHY)
                   + ")$")


def _fault(problem: str) -> Tuple[str, str]:
    """(the place a problem names as its fault, its tree kind: "" for no tree line, "all", or
    "aside" for the standard library's line that leaves out its own packages folder): the
    problem without its marker and its why, read from the end only (a path may hold `: `)."""
    body = problem
    for marker in (OUTSIDE_MINE, OUTSIDE):
        if body.endswith(marker):
            body = body[:-len(marker)].rstrip()
            break
    tree = _TREE.search(body)
    if tree:
        return body[:tree.start()], "aside" if tree.group(1) == TREE_ASIDE else "all"
    for why in _WHYS:
        if body.endswith(": " + why):
            body = body[:-len(": " + why)]
            break
    return body, ""


def _tree_step(root: str, aside: bool) -> str:
    """The one command for the entries of yours below a walk root outside the home folder, from
    inside the root (a linked root is followed; the patterns hold no part of its name), with
    umask 022: first what `_below` judges there (links skipped; with `aside`, what
    `_own_packages` leaves out, by its names on disk, a folder only: a file of that name is
    judged) loses group and other write, so nothing of the tree runs before its modes are fixed;
    then phiward's Python compiles it, as `install` does inside the home folder, so no later
    start writes a group-writable `__pycache__` there (`-I -S`: no folder of the tree on its path
    beyond its own standard library, no .pth runs; with `aside`, `-x` leaves out the same
    folder); then the same `find` again (a default ACL can make a new `__pycache__`
    group-writable). The user id is written out (no `$(...)`: tcsh). A `cd` that fails runs
    nothing."""
    import shlex
    prune = ("-path ./site-packages -type d -prune -o -path ./dist-packages -type d -prune -o "
             if aside else "")
    skip = "-x '^\\./(site|dist)-packages/' " if aside else ""
    find = (f"find . {prune}! -type l -user {os.getuid()} "
            "\\( -perm -020 -o -perm -002 \\) -exec chmod go-w {} +")
    return (f"(cd {shlex.quote(root)} && (umask 022 ; {find} ; "
            f"{shlex.quote(sys.executable)} -I -S -m compileall -qq {skip}. ; {find}))")


def _reinstall(package_dir: str) -> str:
    """The reinstall step for the tool that installed phiward, read from the file that tool
    keeps in its venv (pipx: pipx_metadata.json; uv: uv-receipt.toml), at the running version:
    what restores a changed file and removes a planted one (uv: `--force --reinstall`; pipx:
    `reinstall`, then `install --force`, which also restores a file edited in a cache that
    uv hard-links)."""
    from phiward import __version__
    venv = _venv_of(os.path.dirname(package_dir)) if package_dir else ""
    if venv and os.path.isfile(os.path.join(venv, "pipx_metadata.json")):
        return f"`pipx reinstall phiward && pipx install --force phiward=={__version__}`"
    if venv and os.path.isfile(os.path.join(venv, "uv-receipt.toml")):
        return f"`uv tool install --force --reinstall phiward=={__version__}`"
    return f"the way you installed it (phiward {__version__})"


def fix_text(problems: List[str], package_dir: str) -> str:
    """The one step for the self-check's problems, the same in `doctor`, `launch` and every
    wrapped server: the step of the lowest kind among them (`_kind`): the home folder first
    (phiward never changes it), then a fault outside the home folder that another account owns
    or can write (not phiward's to change), then the faults outside the home folder that are
    yours (`chmod go-w` on exactly those, and one `find` per tree of yours), then a start-up
    file a .pth folder holds, a check that gave no answer, anything a reinstall fixes (a changed
    file, start-up code), else the modes, which `install` fixes."""
    import shlex
    kinds = [(_kind(p), p) for p in problems if p != MORE]
    kind = min((k for k, _p in kinds), default=K_MODES)
    of = [p for k, p in kinds if k == kind]
    if kind == K_HOME:
        return ("make your home folder writable by you alone: `chmod go-w ~`, then start again")
    if kind == K_HOME_OWNER:
        return ("your home folder belongs to another account: phiward cannot keep its own files "
                "safe there; ask your administrator to give it back to you")
    if kind == K_OUTSIDE:
        from phiward import __version__
        venv = _venv_of(os.path.dirname(package_dir)) if package_dir else ""
        pipx = bool(venv) and os.path.isfile(os.path.join(venv, "pipx_metadata.json"))
        cmd = (("pipx uninstall phiward && " if pipx else "")
               + "uv tool install --force --python-preference only-managed "
               f"phiward=={__version__}")
        return (f"install phiward on uv's own Python, inside your home folder (`{cmd}`): "
                f"another account can change {_fault(of[0])[0]}")
    if kind == K_OUTSIDE_MINE:
        faults = [_fault(p) for p in of]
        singles = list(dict.fromkeys(f.rstrip("/") or "/" for f, tree in faults if not tree))
        trees = list(dict.fromkeys((f.rstrip("/") or "/", tree == "aside")
                                   for f, tree in faults if tree))
        cmds = ([f"chmod go-w {' '.join(map(shlex.quote, singles))}"] if singles else []) + \
            [_tree_step(t, aside) for t, aside in trees]
        more = ", then run `phiward doctor` again" if MORE in problems else ""
        return ("make it writable by you alone (phiward does not change files outside your home "
                f"folder): {', then '.join(f'`{c}`' for c in cmds)}{more}, then start again")
    if kind == K_PTH:
        return (f"remove {of[0][:-len(': ' + PTH_STARTUP)]} (phiward did not install it, "
                "and Python runs it at every start), then start again")
    if kind == K_NO_ANSWER:
        return (f"start again; if it says this again, reinstall phiward {_reinstall(package_dir)}")
    if kind == K_REINSTALL:
        return f"reinstall phiward {_reinstall(package_dir)}, then start again"
    return ("run `(cd ~ && phiward install claude --user --write)` (it makes phiward's own files "
            "writable by you alone), then start again")


def _owner_or_mode_faults(path: str) -> List[Tuple[str, str]]:
    """`_faults` as (why, place) (every fault of yours outside the home folder, then the first
    other one, as `check_python` finds them), and a link is a problem: a file phiward installed
    is never one."""
    try:
        st = os.lstat(path)
    except OSError:
        return [("missing", "")]
    if stat.S_ISLNK(st.st_mode):
        return [("a link", "")]
    return _faults(path)


def _same_code(a: Any, b: Any) -> bool:
    """Two code objects do the same (the file name and line numbers aside)."""
    if type(a) is not type(b):
        return False
    if not hasattr(a, "co_code"):
        if isinstance(a, (tuple, frozenset)):
            if len(a) != len(b):
                return False
            sa = sorted(a, key=repr) if isinstance(a, frozenset) else a
            sb = sorted(b, key=repr) if isinstance(b, frozenset) else b
            return all(_same_code(x, y) for x, y in zip(sa, sb))
        if isinstance(a, (float, complex)):
            return repr(a) == repr(b)  # -0.0 == 0.0, and a NaN is never == itself
        return a == b
    for attr in ("co_code", "co_names", "co_varnames", "co_freevars", "co_cellvars", "co_flags",
                 "co_argcount", "co_posonlyargcount", "co_kwonlyargcount", "co_name",
                 "co_nlocals", "co_stacksize", "co_exceptiontable"):
        if getattr(a, attr, None) != getattr(b, attr, None):
            return False
    return _same_code(a.co_consts, b.co_consts)


def _opt_level(pyc: str) -> int:
    """The optimization level a compiled file's name says (`x.cpython-312.opt-2.pyc`)."""
    parts = os.path.basename(pyc).split(".")
    for p in parts:
        if p.startswith("opt-") and p[4:].isdigit():
            return int(p[4:])
    return 0


def _pyc_problem(pyc: str, source: str) -> Optional[str]:
    """Why Python could run code from `pyc` other than `source`'s, or None."""
    try:
        data = _read_regular(pyc)
        src = _read_regular(source)
    except _NotRegular:
        return "not a regular file"
    except OSError:
        return "cannot be read"
    if len(data) < 16:
        return None  # Python ignores it
    flags = int.from_bytes(data[4:8], "little")
    if flags == 0:  # timestamp-based: used only when the header matches the source
        try:
            st = os.stat(source)
        except OSError:
            return None
        mtime = int.from_bytes(data[8:12], "little")
        size = int.from_bytes(data[12:16], "little")
        if mtime != (int(st.st_mtime) & 0xFFFFFFFF) or size != (st.st_size & 0xFFFFFFFF):
            return None  # stale: Python compiles the source again
    try:
        code = marshal.loads(data[16:])
        want = compile(src, source, "exec", dont_inherit=True, optimize=_opt_level(pyc))
    except Exception:  # noqa: BLE001 - anything unreadable is a problem
        return "cannot be read as code"
    return None if _same_code(code, want) else "does not match its source"


def check(files: Optional[List[Tuple[str, str]]] = None,
          package_dir: str = "") -> Tuple[bool, List[str]]:
    """(installed, problems), in this process. `files` is a list of (path, "sha256=<b64>");
    with `package_dir`, files there that the list does not name are problems too."""
    if files is None:
        return _installed_files_check()
    with _cached():
        return _check(files, package_dir)


def _lowest(problems: List[str]) -> List[str]:
    """The lines of the lowest kind, which the step (`fix_text`) fixes: a tree line first (it
    covers a whole folder: the package, a root of phiward's Python)."""
    kinds = [(_kind(p), p) for p in problems if p != MORE]
    low = min((k for k, _p in kinds), default=None)
    return sorted((p for k, p in kinds if k == low), key=lambda p: not _fault(p)[1])


def shown(problems: List[str]) -> List[str]:
    """The lines a refusal shows: at most three of `_lowest`."""
    return _lowest(problems)[:3]


def _listed(problems: List[str]) -> str:
    """`shown`, joined, and how many more lines of that kind there are (a full kind: more than
    it kept). MORE from another kind is not this kind's."""
    of = _lowest(problems)
    text = "; ".join(of[:3])
    if len(of) >= MAX_PROBLEMS and MORE in problems:
        return text + f"; and at least {len(of) - 3} more"
    if len(of) > 3:
        return text + f"; and {len(of) - 3} more"
    return text


def refusal(problems: List[str]) -> str:
    """What failed, in the words every caller uses (`launch`, the session note, `doctor`): a
    check that gave no answer says so; else the lines its step fixes (`shown`)."""
    if problems and _kind(problems[0]) == K_NO_ANSWER:
        return f"phiward's self-check gave no answer ({problems[0]})"
    return f"phiward's own files fail its self-check ({_listed(problems)})"


def _named(name: str, why: str) -> str:
    """A line of the package check: `NAME: why`, or the why alone when it names its own place
    (the walk's `_where`: the home folder, a path)."""
    return why if why == HOME_PROBLEM or why.startswith(("/", "~/")) else f"{name}: {why}"


def _check(files: List[Tuple[str, str]], package_dir: str) -> Tuple[bool, List[str]]:
    problems = _Lines()
    dirs = set()
    listed = set()
    # the faults of yours outside the home folder inside the package folder: one tree line, as
    # `check_python` gives for a root there, so the step is one command (`_tree_step`)
    real_pkg = os.path.realpath(package_dir) if package_dir else ""
    folded: set = set()

    def add(name: str, found: List[Tuple[str, str]]) -> None:
        for why, place in found:
            if real_pkg and place and why.endswith(OUTSIDE_MINE) and _inside(place, real_pkg):
                folded.add(place)
            else:
                problems.add(_named(name, why))

    for path, want in files:
        listed.add(os.path.normpath(path))
        found = _owner_or_mode_faults(path)
        if found:
            add(os.path.basename(path), found)
            if any(why in ("missing", "a link", "too many links") for why, _p in found):
                continue  # nothing there to read
        else:
            dirs.add(os.path.dirname(path))
        # read even with a mode fault: a changed file is named in the same round
        mode, _, value = want.partition("=")
        if mode == "sha256":
            try:
                if _sha256_b64(path) != value:
                    problems.add(f"{os.path.basename(path)}: changed since install")
            except _NotRegular:
                problems.add(f"{os.path.basename(path)}: not a regular file")
                continue
            except OSError:
                problems.add(f"{os.path.basename(path)}: cannot be read")
                continue
        if path.endswith(".py"):
            cache = os.path.join(os.path.dirname(path), "__pycache__")
            stem = os.path.basename(path)[:-3] + "."
            try:
                names = [n for n in os.listdir(cache) if n.startswith(stem) and n.endswith(".pyc")]
            except OSError:
                names = []
            for n in names:
                why = _pyc_problem(os.path.join(cache, n), path)
                if why:
                    problems.add(f"{n}: {why}")
    for d in sorted(dirs):
        add(f"{os.path.basename(d)}/", _owner_or_mode_faults(d))
    if folded:
        problems.add(_tree_line(real_pkg, len(folded)))
    if package_dir:
        for here, subdirs, names in os.walk(package_dir):
            for n in subdirs:
                # a linked folder is imported as a package before a module of the same name, and
                # os.walk does not enter it
                if os.path.islink(os.path.join(here, n)):
                    problems.add(f"{n}/: a link in the package")
            for n in names:
                full = os.path.normpath(os.path.join(here, n))
                if full in listed:
                    continue
                if os.path.basename(here) == "__pycache__" and n.endswith(".pyc"):
                    continue  # compared with their sources above; an orphan is never imported
                problems.add(f"{n}: not in the install record")
    return True, problems.lines()


def _record_check(record: str) -> Tuple[bool, List[str]]:
    site = os.path.dirname(os.path.dirname(record))
    files: List[Tuple[str, str]] = []
    try:
        text = _read_regular(record).decode("utf-8")
        for row in csv.reader(io.StringIO(text, newline="")):
            if len(row) >= 2 and row[0].startswith(PACKAGE + "/") and row[1]:
                files.append((os.path.normpath(os.path.join(site, row[0])), row[1]))
    except (OSError, ValueError, csv.Error):
        return True, ["the install record cannot be read"]
    if not files:
        return False, []  # an editable install: the record lists no package files
    with _cached():
        installed, problems = check(files, os.path.join(site, PACKAGE))
        keep = _Lines()
        for p in problems + _startup_files(site):
            keep.add(p)
        return installed, keep.lines()


# files the interpreter runs at start, before any check: a .pth line that starts with `import`
# runs code; sitecustomize and usercustomize are imported
STARTUP = ("sitecustomize", "usercustomize")


def _is_startup(name: str) -> bool:
    """Whether `name` in a folder on Python's path could be imported as a start-up module: the
    module name alone (a package folder) or with any suffix (`.py`, `.pyc`, an extension
    module); a name that is not importable is refused too (simpler than the import system)."""
    return any(name == m or name.startswith(m + ".") for m in STARTUP)
# what virtual environment tools write themselves (the whole file)
KNOWN_STARTUP = {"_virtualenv.pth": "import _virtualenv"}
# a .pth file Python reads whole; phiward reads it only when it is no larger than this
PTH_LIMIT = 1 << 20
# the only bytes a .pth may hold: then no Python version decodes or splits it differently from
# phiward (3.12.16 and 3.13 decode utf-8-sig and split on \x0c and friends; 3.9 does not)
_PTH_BYTES = frozenset(b"\t\n\r") | frozenset(range(0x20, 0x7F))


def _venv_of(site: str) -> str:
    """The venv a site folder (`VENV/lib/pythonX.Y/site-packages`) belongs to (its pyvenv.cfg as
    site.py finds it: `_first_cfg`), or ""."""
    d = os.path.dirname(os.path.dirname(os.path.dirname(site)))
    return d if _first_cfg(os.path.join(d, "bin")) else ""


def _allowed_places(site: str) -> List[str]:
    """Where a .pth path line may lead, as real paths: the venv, and for a pipx venv
    (`PIPX_HOME/venvs/NAME`) pipx's shared libraries (`PIPX_HOME/shared`), from the venv's own
    place; nothing else."""
    venv = _venv_of(site)
    if not venv:
        return []
    out = [os.path.realpath(venv)]
    if os.path.basename(os.path.dirname(venv)) == "venvs":
        out.append(os.path.realpath(os.path.join(os.path.dirname(os.path.dirname(venv)),
                                                 "shared")))
    return out


def _pth_lines(path: str) -> Tuple[str, List[Tuple[str, str]], str]:
    """(problem, [(kind, line)], text) of a .pth file, its lines taken as site.addpackage takes
    them: `#` at the start, skipped; blank, skipped; `import ` or `import\t` (after any leading
    whitespace: stricter than site), code; anything else, rstripped, a path. A file that is not
    plain ASCII, or larger than PTH_LIMIT, is a problem: phiward does not guess how Python
    reads it."""
    try:
        fd = _open_regular(path)
        try:
            data = os.read(fd, PTH_LIMIT + 1)
        finally:
            os.close(fd)
    except _NotRegular:
        return "not a regular file", [], ""
    except OSError:
        return "cannot be read", [], ""
    if len(data) > PTH_LIMIT:
        return "too large to be checked", [], ""
    if set(data) - _PTH_BYTES:
        return "not plain ASCII (Python may read it differently)", [], ""
    text = data.decode("ascii")
    out: List[Tuple[str, str]] = []
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if line.lstrip().startswith(("import ", "import\t")):
            out.append(("code", line))
        else:
            out.append(("path", line.rstrip()))
    return "", out, text


def _pth_dir(site: str, line: str) -> str:
    """The folder Python adds for a .pth path line: site.makepath, abspath(join(site, line)),
    which is lexical (it does not follow a link before `..`)."""
    return os.path.abspath(os.path.join(site, line))


def _startup_files(site: str, places: Optional[List[str]] = None) -> List[str]:
    """`_startup_problems` as `NAME: why` lines."""
    return [f"{n}: {why}" for n, why in _startup_problems(site, places)]


def _startup_problems(site: str, places: Optional[List[str]] = None) -> List[Tuple[str, str]]:
    """The start-up files of a site folder that phiward does not accept, as (name, why): a
    sitecustomize or usercustomize; a .pth phiward cannot read as Python does (`_pth_lines`); one
    with a line that runs code, unless the whole file is a known one (an install record that lists
    it proves nothing); one with a path line whose folder (as Python makes it) leads outside the
    venv and pipx's shared libraries."""
    places = _allowed_places(site) if places is None else places
    try:
        names = os.listdir(site)
    except OSError:
        return []
    out: List[Tuple[str, str]] = []
    for n in sorted(names):
        if _is_startup(n):
            out.append((n, "a start-up file"))
            continue
        if not n.endswith(".pth"):
            continue
        problem, lines, text = _pth_lines(os.path.join(site, n))
        if problem:
            out.append((n, problem))
            continue
        if KNOWN_STARTUP.get(n) == text.strip():
            continue
        if any(kind == "code" for kind, _ln in lines):
            out.append((n, "runs code at start"))
            continue
        for _kind, ln in lines:
            d = _pth_dir(site, ln)
            real = os.path.realpath(d)
            if not any(_inside(real, p) for p in places):
                out.append((n, "adds a folder outside phiward's Python"))
                break
            if os.path.exists(d) and not os.path.isdir(d):
                # Python adds what exists: a zip on the path can hold start-up code
                out.append((n, "adds a file to Python's path"))
                break
    return out


def _record_path() -> str:
    try:
        from importlib import metadata
        dist = metadata.distribution(DIST)
    except Exception:  # noqa: BLE001
        return ""
    for f in dist.files or []:
        s = str(f)
        if s.endswith(".dist-info/RECORD"):
            return str(f.locate())
    return ""


LAUNCHERS = ("phiward", "agent-guards")


def launcher_scripts(record: Optional[str] = None,
                     package_dir: Optional[str] = None) -> Optional[frozenset]:
    """The console scripts (`phiward`, `agent-guards`) that the install record of the running
    package lists, as real paths: the launcher Claude Code must start for a wrapped MCP server.
    None when there is no such record: a source checkout, an editable install (its record lists
    no package files), or a record of another copy than the running one."""
    record = _record_path() if record is None else record
    package_dir = _running_package() if package_dir is None else package_dir
    if not record:
        return None
    try:
        st = os.stat(record)
        key = (record, package_dir, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    except OSError:
        return None
    if key in _SCRIPTS_CACHE:
        return _SCRIPTS_CACHE[key]
    got = _launcher_scripts(record, package_dir)
    _SCRIPTS_CACHE.clear()
    _SCRIPTS_CACHE[key] = got
    return got


_SCRIPTS_CACHE: Dict[tuple, Optional[frozenset]] = {}


def _launcher_scripts(record: str, package_dir: str) -> Optional[frozenset]:
    site = os.path.dirname(os.path.dirname(record))
    if os.path.realpath(os.path.join(site, PACKAGE)) != os.path.realpath(package_dir):
        return None
    scripts, package_files = set(), False
    try:
        text = _read_regular(record).decode("utf-8")
        for row in csv.reader(io.StringIO(text, newline="")):
            if not row:
                continue
            if row[0].startswith(PACKAGE + "/"):
                package_files = True
            elif os.path.basename(row[0]) in LAUNCHERS:
                path = os.path.normpath(os.path.join(site, row[0]))
                if os.path.isfile(path):
                    scripts.add(os.path.realpath(path))
    except (OSError, ValueError, csv.Error):
        return None
    return frozenset(scripts) if package_files else None


def _installed_files_check() -> Tuple[bool, List[str]]:
    record = _record_path()
    return _record_check(record) if record else (False, [])


def _running_package() -> str:
    return os.path.dirname(os.path.abspath(__file__))


# the self-check child's bytecode prefix: below /dev/null, which is no folder, so Python finds no
# compiled file there to read (and `-B` writes none)
NO_PYCACHE = "/dev/null/phiward"


def check_isolated(timeout: float = 60) -> Tuple[bool, List[str]]:
    """The check, in a separate interpreter that reads no site folder, no environment and no
    compiled file (`launch` uses this). An install whose package is not the one running (a
    source checkout on the path in front of it) counts as no install."""
    record = _record_path()
    if not record:
        return False, []
    site = os.path.dirname(os.path.dirname(record))
    if os.path.realpath(os.path.join(site, PACKAGE)) != os.path.realpath(_running_package()):
        return False, []
    cmd = [sys.executable, "-I", "-S", "-B", "-X", f"pycache_prefix={NO_PYCACHE}",
           os.path.abspath(__file__), record]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={"PATH": "/usr/bin:/bin"})
        out: Dict[str, Any] = json.loads(r.stdout)
        return bool(out["installed"]), [str(p) for p in out["problems"]]
    except subprocess.TimeoutExpired:
        return True, [CHECK_SLOW]
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        return True, [CHECK_FAILED]


def check_full_isolated(timeout: float = 120) -> Tuple[bool, List[str], List[str]]:
    """(installed, the package's problems as `check_isolated` finds them, the rest of the full
    check of phiward's own Python), in a separate interpreter (`-I -S -B`), for `doctor`."""
    record = _record_path()
    if not record:
        return False, [], []
    site = os.path.dirname(os.path.dirname(record))
    if os.path.realpath(os.path.join(site, PACKAGE)) != os.path.realpath(_running_package()):
        return False, [], []
    cmd = [sys.executable, "-I", "-S", "-B", "-X", f"pycache_prefix={NO_PYCACHE}",
           os.path.abspath(__file__), "--full", record, sys.executable]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={"PATH": "/usr/bin:/bin"})
        out: Dict[str, Any] = json.loads(r.stdout)
        return (bool(out["installed"]), [str(p) for p in out["problems"]],
                [str(p) for p in out["python"]])
    except subprocess.TimeoutExpired:
        return True, [CHECK_SLOW], []
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        return True, [CHECK_FAILED], []


def _main(argv: List[str]) -> Dict[str, Any]:
    if argv[:1] != ["--full"]:
        ok, found = _record_check(argv[0])
        return {"installed": ok, "problems": found}
    record, exe = (argv[1:] + ["", ""])[:2]
    ok, found = _record_check(record)
    places = python_places(exe or None)
    return {"installed": ok, "problems": found,
            "python": check_python(places)}


if __name__ == "__main__":
    sys.stdout.write(json.dumps(_main(sys.argv[1:])))
