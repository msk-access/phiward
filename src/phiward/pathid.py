"""The canonical spelling and the identity of a path, from the file system itself.

A path can be written many ways that name the same file: through links, with `..`, in another
letter case or Unicode form (macOS), through the `/System/Volumes/Data` firmlink or as
`/.vol/<device>/<inode>` (macOS), through a bind mount (Linux). A check that computes the answer
from the written string misses some of them.

`walk(path)` asks the file system instead: it resolves the path part by part from folder
descriptors, as the kernel does, and returns the canonical spelling (macOS `F_GETPATH`, the form
Seatbelt matches; Linux `/proc/self/fd`) and the (device, inode) of every folder on the way.
`canon()` is its spelling; `fold()` is the key for deny comparisons (on macOS NFD and
case-folded; on Linux the path itself). A walk that blocks on a stale network mount blocks the
caller (a known limit: docs/threat-model.md).
"""

import os
import stat
import sys
import unicodedata
from typing import List, NamedTuple, Optional, Tuple

_F_GETPATH = 50  # <sys/fcntl.h>
_O_EVTONLY = 0x8000  # macOS: open for event notification only (no read access needed)
MACOS = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")


def inside(path: str, folder: str, strict: bool = False) -> bool:
    """Whether `path` is `folder` or below it, as text (both absolute, in the same spelling);
    `strict`: below it only. The one lexical rule for "inside": an empty or relative `folder` is
    a caller's mistake (as text, "" would hold every absolute path), so it raises ValueError and
    each caller says what a missing folder means for it."""
    if not folder or not folder.startswith("/"):
        raise ValueError(f"not an absolute folder: {folder!r}")
    if path == folder:
        return not strict
    return path.startswith(folder.rstrip("/") + "/") or folder == "/" and path.startswith("/")


def fold(path: str) -> str:
    if MACOS:
        return unicodedata.normalize("NFD", path).casefold()
    return path


def _from_fd(fd: int) -> Optional[str]:
    if MACOS:
        import fcntl
        try:
            raw = fcntl.fcntl(fd, _F_GETPATH, b"\0" * 1024)
        except OSError:
            return None
        return raw.split(b"\0", 1)[0].decode("utf-8", "surrogateescape") or None
    if LINUX:
        try:
            return os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            return None
    return None


def _dir_flags() -> int:
    f = os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK
    if MACOS:
        f |= _O_EVTONLY
    elif LINUX:
        f |= os.O_PATH  # type: ignore[attr-defined]
    return f


MAX_LINKS = 40


class Walk(NamedTuple):
    canon: str
    ids: List[Tuple[int, int]]  # (dev, ino) of every folder on the way, and of the last part
    complete: bool  # False: some part could not be resolved (callers fail closed)


def _file_flags() -> int:
    f = os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK | os.O_NOFOLLOW
    if MACOS:
        f |= _O_EVTONLY
    elif LINUX:
        f |= os.O_PATH  # type: ignore[attr-defined]
    return f


def walk_full(path: str) -> Walk:
    """Resolve an absolute path the way the kernel does, part by part:
    each folder is opened from its parent's descriptor (`..` from the folder itself, links read
    and followed in place), the last part is only looked up, never opened as a device. A part
    that does not exist ends the walk normally: the rest is kept as text (with `.` and `..`
    applied), and the walk is complete. Anything else that stops the walk (no permission, a
    `/.vol` name that does not resolve, a magic link under `/proc`, too many links) makes it
    incomplete: callers then treat the path as protected."""
    if not (MACOS or LINUX):
        return Walk(os.path.realpath(path), [], True)
    flags = _dir_flags()
    ids: List[Tuple[int, int]] = []
    todo = [p for p in path.split("/") if p and p != "."]
    fd = os.open("/", flags)
    st = os.fstat(fd)
    ids.append((st.st_dev, st.st_ino))
    links = 0
    tail: List[str] = []
    last_name = ""
    base_override = ""
    complete = True
    try:
        while todo:
            part = todo.pop(0)
            if part == "..":
                try:
                    nxt = os.open("..", flags, dir_fd=fd)
                except OSError:
                    complete = False
                    break
                os.close(fd)
                fd = nxt
                st = os.fstat(fd)
                ids.append((st.st_dev, st.st_ino))
                continue
            try:
                st = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                st = None
            except OSError:
                complete = False
                break
            if st is None:
                # some folders resolve a name only by full path (macOS /.vol/<dev>/<inode>):
                # try longer prefixes of the rest, as a folder, then as anything else
                here = _from_fd(fd)
                opened = -1
                if here and (here == "/.vol" or here.startswith("/.vol/")):
                    for k in range(0, min(len(todo), 3) + 1):
                        if any(x == ".." for x in todo[:k]):
                            break
                        full = os.path.join(here, part, *todo[:k])
                        for fl in (flags, _file_flags()):
                            try:
                                opened = os.open(full, fl)
                                break
                            except OSError:
                                opened = -1
                        if opened >= 0:
                            del todo[:k]
                            break
                    if opened < 0:
                        complete = False  # an inode name we cannot follow: fail closed
                        break
                    os.close(fd)
                    fd = opened
                    st = os.fstat(fd)
                    ids.append((st.st_dev, st.st_ino))
                    if not stat.S_ISDIR(st.st_mode):
                        base_override = _from_fd(fd) or ""
                        if not base_override:
                            complete = False
                        tail = todo
                        todo = []
                        break
                    continue
                # the generic rule: a name the walk cannot find, but
                # that the kernel resolves as part of the whole path (macOS /.nofollow,
                # /.resolve/N, ...), is not a missing tail: fail closed
                here = _from_fd(fd) or "/"
                try:
                    os.lstat(os.path.join(here, part, *todo))
                    complete = False
                    break
                except OSError:
                    pass
                tail = [part] + todo
                todo = []
                break
            if stat.S_ISLNK(st.st_mode):
                links += 1
                if links > MAX_LINKS:
                    complete = False  # a loop: fail closed
                    break
                target = os.readlink(part, dir_fd=fd)
                if _on_procfs(fd):
                    kind = _proc_link_kind(_from_fd(fd) or "", part, target)
                    if kind == "magic":
                        # its text is not where it leads: let the kernel follow it, ask the
                        # kernel where it really is, and walk that; use the answer only if the
                        # identities agree, else fail closed
                        resolved = _follow_magic(fd, part, todo)
                        if resolved is None:
                            complete = False
                            break
                        os.close(fd)
                        fd = os.open("/", flags)
                        return resolved
                    if kind == "not-a-path":  # pipe:, socket:, anon_inode:
                        last_name = part
                        tail = []
                        todo = []
                        break
                more = [p for p in target.split("/") if p and p != "."]
                if target.startswith("/"):
                    os.close(fd)
                    fd = os.open("/", flags)
                todo = more + todo
                continue
            if stat.S_ISDIR(st.st_mode):
                try:
                    nxt = os.open(part, flags | os.O_NOFOLLOW, dir_fd=fd)
                except OSError:
                    complete = False
                    break
                os.close(fd)
                fd = nxt
                st = os.fstat(fd)
                ids.append((st.st_dev, st.st_ino))
                continue
            # a file, device, FIFO or socket: looked up only
            ids.append((st.st_dev, st.st_ino))
            last_name = part
            tail = todo
            todo = []
        base = base_override or _from_fd(fd) or "/"
    finally:
        os.close(fd)
    out: List[str] = []
    for p in ([last_name] if last_name else []) + tail:
        if p == "..":
            if out:
                out.pop()
        elif p and p != ".":
            out.append(p)
    return Walk(os.path.join(base, *out) if out else base, ids, complete)


_PROC_SUPER_MAGIC = 0x9FA0


def _on_procfs(fd: int) -> bool:
    """Linux: whether the folder `fd` is on procfs, asked of the file system (fstatfs), not
    guessed from its path (procfs can be mounted at a second path)."""
    if not LINUX:
        return False
    import ctypes
    import ctypes.util

    class _StatFs(ctypes.Structure):
        _fields_ = [("f_type", ctypes.c_long), ("_rest", ctypes.c_byte * 120)]

    libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    buf = _StatFs()
    if libc.fstatfs(fd, ctypes.byref(buf)) != 0:
        return True  # unknown: treat as procfs (fail closed on its links)
    return (buf.f_type & 0xFFFFFFFF) == _PROC_SUPER_MAGIC


def _follow_magic(fd: int, part: str, rest: List[str]) -> Optional["Walk"]:
    """A magic link of another process, followed by the kernel and checked by identity; None
    (fail closed) for this process's own links: /proc/self in the hook is the hook, not the
    agent tool whose path this is."""
    if not LINUX:
        return None
    here = _from_fd(fd)
    if not here:
        return None
    mine = {str(os.getpid()), str(getattr(os, "gettid", os.getpid)())}
    if any(c in mine for c in here.split("/")):
        return None
    full = os.path.join(here, part, *rest)
    try:
        tfd = os.open(full, os.O_PATH | os.O_CLOEXEC)  # type: ignore[attr-defined]
    except OSError:
        return None
    try:
        real = os.readlink(f"/proc/self/fd/{tfd}")
        st = os.fstat(tfd)
    except OSError:
        return None
    finally:
        os.close(tfd)
    if not real.startswith("/") or real.startswith("/proc/"):
        return None
    try:
        w = walk_full(real)
    except OSError:
        return None
    if w.complete and w.ids and w.ids[-1] == (st.st_dev, st.st_ino):
        return w
    return None


_MAGIC_NAMES = ("root", "cwd", "exe")


def _proc_link_kind(folder: str, name: str, target: str) -> str:
    """'plain' (follow it as text: /proc/self, /proc/thread-self, /proc/mounts), 'not-a-path'
    (an fd link to a pipe, socket or anon inode), or 'magic' (root, cwd, exe, fd/*, map_files/*,
    also under task/*: their text is not where they lead)."""
    if re_not_a_path(target):
        return "not-a-path"
    last = os.path.basename(folder)
    if name in _MAGIC_NAMES or last in ("fd", "map_files"):
        return "magic"  # also a tty-named one: checked by identity
    return "plain"


def re_not_a_path(target: str) -> bool:
    return any(target.startswith(p) for p in ("pipe:", "socket:", "anon_inode:", "net:", "mnt:"))


def walk(path: str) -> Tuple[str, List[Tuple[int, int]]]:
    w = walk_full(path)
    return w.canon, w.ids


def canon(path: str) -> str:
    """The canonical spelling of an absolute path (see `walk`). When the walk cannot finish,
    the spelling it reached is a prefix of the path, not the path: use `realpath` then."""
    try:
        w = walk_full(path)
    except (OSError, ValueError):
        return os.path.realpath(path)
    return w.canon if w.complete else os.path.realpath(path)



def canon_new(path: str) -> str:
    """The canonical spelling of a path that may not exist yet: its nearest existing folder in
    the file system's own spelling (macOS firmlinks such as /System/Volumes/Data undone), with
    the rest of the path after it."""
    head, rest = path, ""
    while not os.path.exists(head):
        up = os.path.dirname(head)
        if up == head:
            return path
        rest = os.path.join(os.path.basename(head), rest) if rest else os.path.basename(head)
        head = up
    c = canon(head)
    return os.path.join(c, rest) if rest else c

def spellings(path: str) -> List[str]:
    """The path as written (normalized), resolved, and canonical, without duplicates."""
    out: List[str] = []
    for v in (os.path.normpath(path), os.path.realpath(path), canon(path)):
        if v not in out:
            out.append(v)
    return out


def home(env=None) -> str:
    """The home folder: `HOME` of `env` (os.environ by default), else the account's. The one
    lookup (selfcheck, a standalone child, keeps its own; the user config's base uses the real
    home on purpose: config.user_config_path)."""
    env = os.environ if env is None else env
    return env.get("HOME") or os.path.expanduser("~")


def identity(path: str) -> Optional[Tuple[int, int]]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_dev, st.st_ino


def case_sensitive(path: str) -> bool:
    """Whether the volume that holds `path` tells letter case apart (macOS asks the volume;
    Linux: yes, except in a casefold folder, see `casefold_folder`)."""
    if MACOS:
        here = path
        while here and not os.path.exists(here):
            here = os.path.dirname(here)
        try:
            return bool(os.pathconf(here or "/", 11))  # _PC_CASE_SENSITIVE
        except (OSError, ValueError):
            return False  # unknown: fold (stricter for deny decisions)
    return not casefold_folder(path)


def casefold_folder(path: str) -> bool:
    """Linux: whether a folder on the way has the casefold attribute (ext4, f2fs)."""
    if not LINUX:
        return False
    import fcntl
    import struct
    here = path
    while here and here != "/":
        try:
            fd = os.open(here, os.O_RDONLY | os.O_DIRECTORY | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            here = os.path.dirname(here)
            continue
        try:
            buf = fcntl.ioctl(fd, 0x80086601, struct.pack("l", 0))  # FS_IOC_GETFLAGS
            if struct.unpack("l", buf)[0] & 0x40000000:  # FS_CASEFOLD_FL
                return True
        except OSError:
            pass
        finally:
            os.close(fd)
        here = os.path.dirname(here)
    return False
