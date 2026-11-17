"""File-system behaviours that matter for protected folders, found without naming a vendor.

- `snapshot_dirs(root, names)`: snapshot folders next to the root or above it (`.snapshot`,
  `.snapshots`, `.zfs`, `~snapshot`, and names from `[protected_paths] snapshot_names`). Each one
  holds old copies of protected files under another path, so it becomes a derived root.
- `alias_paths(root, mountinfo)`: on Linux, other mount points that show the same part of the
  same file system (bind mounts, a second mount of one export), from `/proc/self/mountinfo`.
- `mount_of(path, mountinfo)`: the mount that holds a path, with its file-system type.
- `hardlinked_count(roots, limit)`: protected files that have other hard links. Path rules
  cannot cover those other names; `doctor` warns.
"""

import os
import stat
from typing import Dict, List, Optional, Sequence

SNAPSHOT_NAMES = (".snapshot", ".snapshots", ".zfs", "~snapshot", ".snap")


def snapshot_dirs(root: str, names: Sequence[str] = ()) -> List[str]:
    out: List[str] = []
    want = list(SNAPSHOT_NAMES) + [n for n in names if n not in SNAPSHOT_NAMES]
    here = os.path.dirname(os.path.realpath(root))  # the real place
    while True:
        for n in want:
            cand = os.path.join(here, n)
            try:
                st = os.lstat(cand)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode) and cand not in out:
                out.append(cand)
        parent = os.path.dirname(here)
        if parent == here:
            return out
        here = parent


def _unescape(field: str) -> str:
    # mountinfo escapes space, tab, newline and backslash as octal
    out, i = "", 0
    while i < len(field):
        if field[i] == "\\" and i + 3 < len(field) and field[i + 1:i + 4].isdigit():
            out += chr(int(field[i + 1:i + 4], 8))
            i += 4
        else:
            out += field[i]
            i += 1
    return out


def read_mountinfo() -> str:
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _mounts(mountinfo: str) -> List[Dict[str, str]]:
    out = []
    for line in mountinfo.splitlines():
        if " - " not in line:
            continue
        left, right = line.split(" - ", 1)
        lf, rf = left.split(), right.split()
        if len(lf) < 5 or len(rf) < 2:
            continue
        out.append({"dev": lf[2], "root": _unescape(lf[3]), "point": _unescape(lf[4]),
                    "fstype": rf[0], "source": _unescape(rf[1]),
                    "superopts_raw": rf[2] if len(rf) > 2 else ""})
    return out


def _inside(p: str, folder: str) -> bool:
    from phiward import pathid
    return pathid.inside(p, folder)


def mount_of(path: str, mountinfo: Optional[str] = None) -> Optional[Dict[str, str]]:
    mi = read_mountinfo() if mountinfo is None else mountinfo
    best = None
    for m in _mounts(mi):
        if _inside(path, m["point"]) and (best is None or len(m["point"]) >= len(best["point"])):
            best = m
    return best


# sources that name no particular data: two tmpfs mounts are not the same file system
_GENERIC_SOURCES = {"none", "tmpfs", "overlay", "proc", "sysfs", "devtmpfs", "cgroup", "cgroup2",
                    "devpts", "mqueue", "shm", "fuse", "autofs", "nsfs", "bpf", "tracefs",
                    "securityfs", "debugfs", "configfs", "pstore", "efivarfs", "ramfs",
                    "hugetlbfs", "binfmt_misc", "rpc_pipefs", "portal", "fusectl"}


def _same_data(a: Dict[str, str], b: Dict[str, str]) -> bool:
    """Whether two mounts show the same file system: the same device numbers, or (network and
    block file systems only) the same source and type."""
    if a["dev"] == b["dev"]:  # one superblock: the same data, whatever the type
        return True
    generic = (a["source"] in _GENERIC_SOURCES or a["fstype"] in _GENERIC_SOURCES or
               a["fstype"].startswith("fuse."))
    return a["source"] == b["source"] and a["fstype"] == b["fstype"] and not generic


def _split_unescaped(text: str, seps: str) -> List[str]:
    """Split on separators that are not escaped (mountinfo writes `,` and `:` in a path as
    `\\054`, a backslash as `\\134`; a raw split before unescaping cuts the path)."""
    # the kernel writes `,` in a path as \054 and a user's backslash as \134, so a separator
    # right after \134 is part of the path
    out, cur, i = [], "", 0
    while i < len(text):
        if text[i] in seps and not cur.endswith("\\134"):
            out.append(cur)
            cur = ""
        else:
            cur += text[i]
        i += 1
    out.append(cur)
    return out


def _overlay_lowers(m: Dict[str, str]) -> Optional[List[str]]:
    """The lower and upper folders of an overlay mount, unescaped; None when one cannot be
    read as an absolute path (then it is unknown)."""
    out: List[str] = []
    for kv in _split_unescaped(m.get("superopts_raw", ""), ","):
        key, _, val = kv.partition("=")
        if key in ("lowerdir", "upperdir", "lowerdir+", "datadir+"):
            for part in _split_unescaped(val, ":"):
                part = _unescape(part)
                if not part:
                    continue
                if not part.startswith("/"):
                    return None
                out.append(os.path.normpath(part))
    return out


def unknown_overlays(mountinfo: Optional[str] = None) -> List[str]:
    """Mount points of overlays whose lower or upper folders cannot be read; phiward
    cannot tell whether they show a protected folder, so the config refuses (fail closed)."""
    mi = read_mountinfo() if mountinfo is None else mountinfo
    return [m["point"] for m in _mounts(mi) if m["fstype"] == "overlay" and
            _overlay_lowers(m) is None]


def _relation_by_identity(root: str, other: str) -> Optional[str]:
    """'lower-inside' when `other` is the root or inside it, 'root-inside' when the root is
    inside `other`, by (dev, ino) of the walked chains, not by spelling (an overlay
    lower may be a link to the root, or a bind mount of it)."""
    from phiward import pathid
    try:
        r = pathid.walk_full(root)
        o = pathid.walk_full(other)
    except OSError:
        return "lower-inside"  # cannot tell: treat as showing the root (fail closed)
    if not (r.ids and o.ids):
        return None
    if r.ids[-1] in o.ids:
        return "lower-inside"
    if o.ids[-1] in r.ids:
        return "root-inside"
    return None


def _alias_against(in_fs: str, m: Dict[str, str], mounts: List[Dict[str, str]],
                   skip: str) -> List[str]:
    out: List[str] = []
    for n in mounts:
        if n["point"] == skip:
            continue
        alias = None
        if _same_data(n, m):
            if _inside(in_fs, n["root"]):  # the mount shows the whole path
                alias = os.path.join(n["point"], os.path.relpath(in_fs, n["root"]))
            elif _inside(n["root"], in_fs):  # the mount shows a folder inside it
                alias = n["point"]
        if alias:
            out.append(os.path.normpath(alias))
    return out


def alias_paths(root: str, mountinfo: Optional[str] = None) -> List[str]:
    """Other mount points that show the root or any part of it (both
    directions), including through a separate mount inside the root, and
    overlay mounts that use it, or a folder inside it, as a lower or upper folder."""
    mi = read_mountinfo() if mountinfo is None else mountinfo
    root = os.path.realpath(root) if mountinfo is None else os.path.normpath(root)
    mounts = _mounts(mi)
    m = mount_of(root, mi)
    if m is None:
        return []
    out: List[str] = []
    rel = os.path.relpath(root, m["point"])
    out += _alias_against(os.path.normpath(os.path.join(m["root"], rel)), m, mounts, m["point"])
    # separate mounts inside the root: whatever shows their data elsewhere shows the root's
    for inner in mounts:
        if inner["point"] != m["point"] and inner["point"] != root and _inside(inner["point"], root):
            out += _alias_against(inner["root"], inner, mounts, inner["point"])
        elif inner["point"] == root and inner is not m:
            out += _alias_against(inner["root"], inner, mounts, inner["point"])
    for n in mounts:
        if n["fstype"] != "overlay":
            continue
        for lower in _overlay_lowers(n) or []:
            rel = _relation_by_identity(root, lower) if mountinfo is None else \
                ("lower-inside" if _inside(lower, root) else
                 "root-inside" if _inside(root, lower) else None)
            if rel == "root-inside":
                real_lower = os.path.realpath(lower) if mountinfo is None else lower
                real_root = os.path.realpath(root) if mountinfo is None else root
                sub = os.path.relpath(real_root, real_lower) if _inside(real_root, real_lower) \
                    else ""
                out.append(os.path.normpath(os.path.join(n["point"], sub)) if sub else n["point"])
            elif rel == "lower-inside":
                out.append(n["point"])
    seen: List[str] = []
    for a in out:
        if a != root and a not in seen:
            seen.append(a)
    return seen


def hardlinked_count(roots: Sequence[str], limit: int) -> int:
    n = seen = 0
    for r in roots:
        if not os.path.isdir(r):
            continue
        for dirpath, _dirs, files in os.walk(r, followlinks=False):
            for f in files:
                seen += 1
                if seen > limit:
                    return n
                try:
                    st = os.lstat(os.path.join(dirpath, f))
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                    n += 1
    return n
