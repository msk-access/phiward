"""A process's parent and start time, without starting a program: Linux reads `/proc/<pid>/stat`,
macOS asks the kernel (`proc_pidinfo`, the call `ps` makes). The start time tells a live process
from a later one that got the same number. None when it cannot tell: callers then trust
nothing."""

import os
import sys
from typing import List, Optional, Tuple

# (parent pid, start time in the system's own unit)
Info = Tuple[int, int]


def _linux(pid: int) -> Optional[Info]:
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read().decode("ascii", "replace")
    except OSError:
        return None
    # the name (field 2) may hold spaces and parentheses: the fields after it follow the last ')'
    rest = data[data.rfind(")") + 2:].split()
    try:
        return int(rest[1]), int(rest[19])  # field 4 ppid, field 22 starttime
    except (IndexError, ValueError):
        return None


_PROC_PIDTBSDINFO = 3
_BSDINFO_SIZE = 136  # struct proc_bsdinfo


def _darwin(pid: int) -> Optional[Info]:
    import ctypes
    import struct
    try:
        lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    except OSError:
        return None
    buf = ctypes.create_string_buffer(_BSDINFO_SIZE)
    n = lib.proc_pidinfo(ctypes.c_int(pid), ctypes.c_int(_PROC_PIDTBSDINFO), ctypes.c_uint64(0),
                         buf, ctypes.c_int(_BSDINFO_SIZE))
    if n != _BSDINFO_SIZE:
        return None
    got_pid, ppid = struct.unpack_from("=II", buf.raw, 12)
    sec, usec = struct.unpack_from("=QQ", buf.raw, 120)
    if got_pid != pid:
        return None
    return int(ppid), int(sec) * 1_000_000 + int(usec)


def info(pid: int) -> Optional[Info]:
    """(parent pid, start time) of a live process, or None."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    if sys.platform.startswith("linux"):
        return _linux(pid)
    if sys.platform == "darwin":
        return _darwin(pid)
    return None


def ancestors(pid: Optional[int] = None, depth: int = 4) -> List[int]:
    """The parent, grandparent, ... of `pid` (this process by default), nearest first, at most
    `depth`, never pid 1 (every orphan's parent) or 0."""
    out: List[int] = []
    cur = os.getpid() if pid is None else pid
    for _ in range(depth):
        got = info(cur)
        if got is None or got[0] <= 1:
            break
        cur = got[0]
        out.append(cur)
    return out
