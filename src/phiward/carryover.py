"""Carry-over: what a session leaves behind for later.

Under `launch` the whole tool runs in the profile, so what a session writes matters only for
what reads it later. Each session therefore runs in a config folder of its own
(`runs/<id>/config`), built at start from a trusted copy that no session can read or write
(`~/.phiward/carryover/<tool>/`), and thrown away at exit. Nothing is shared between
sessions (stateless). No process is ever ended.

- Instructions: files the tool loads as instructions or settings (the adapter's list) that the
  session changed, and the notable keys of `.claude.json`, go to quarantine; the operator reads
  them and accepts them (`phiward carryover show | accept ID`), or adds files of their own
  (`carryover add PATH`). Links are never trusted. Everything else the session made is thrown
  away with its folder.
- The project: every changed, new or removed file is reported, instructions for models first.

The launcher writes into a folder a session can write only by descriptor, and reads or removes
what a session wrote only after renaming it into `trash/`. Anything kept may be deleted at any
time; a start rebuilds from
what is left and never adopts anything from a folder a session can write. Sessions may run in
parallel: each holds a lock on its own run folder, which cleaners respect."""

import errno
import fcntl
import fnmatch
import hashlib
import json
import os
import secrets
import stat
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

from phiward import claude_settings, safeio

MAX_ENTRIES = 20_000
MAX_BYTES = 500 * 1024 * 1024
QUARANTINE_MAX = 200


class CarryoverError(Exception):
    pass


@dataclass
class Spec:
    """An adapter's carry-over data (stateless). `instructions`: top-level names in the
    config folder that the tool loads as instructions or settings; they come from the trusted
    copy, and the session's changes go to quarantine. `json_main`: a JSON file the tool keeps
    its own state in (it comes from the trusted copy too); only changes to the `json_notable`
    keys go to quarantine. Everything else a session writes is thrown away with its folder.
    `memory_setting`, `memory_rel`: the setting that moves auto memory into the session's
    folder, and that folder's name (an instruction)."""
    instructions: List[str] = field(default_factory=list)
    json_main: str = ""
    json_notable: List[List[str]] = field(default_factory=list)
    memory_setting: str = ""
    memory_rel: str = ""
    # inside the instruction folders: downloads the tool makes in every fresh folder, never
    # loaded as instructions by themselves; dropped without a quarantine entry
    downloads: List[str] = field(default_factory=list)
    # keys of json_main set in every session unless the trusted copy says otherwise: UI state
    # only, never instructions (a fresh folder otherwise shows the first-run screens)
    json_defaults: Dict[str, object] = field(default_factory=dict)

    @property
    def enabled(self) -> bool:
        return bool(self.instructions or self.json_main)

    def trusted_names(self) -> List[str]:
        return self.instructions + ([self.json_main] if self.json_main else [])


_MCP_KEYS = ["mcpServers", "enableAllProjectMcpServers", "enabledMcpjsonServers",
             "disabledMcpjsonServers"]
SPECS: Dict[str, Spec] = {
    "claude": Spec(
        # what Claude Code loads as instructions or settings (memory and claude-directory docs):
        # what it runs as code (the one list, claude_settings), and its instruction files
        instructions=list(dict.fromkeys(
            list(claude_settings.CODE_DIRS) + list(claude_settings.CODE_FILES)
            + list(claude_settings.SETTINGS_NAMES)
            + ["CLAUDE.md", "rules", "output-styles", "agent-memory", "keybindings.json",
               "auto-memory"])),
        json_main=".claude.json",
        json_notable=[[k] for k in _MCP_KEYS + ["autoConnectIde", "claudeInChromeDefaultEnabled",
                                                "customApiKeyResponses", "primaryApiKey"]] +
            [["projects", "*", k] for k in _MCP_KEYS + ["allowedTools", "hasTrustDialogAccepted",
                                                       "hasClaudeMdExternalIncludesApproved",
                                                       "hasClaudeMdExternalIncludesWarningShown"]],
        memory_setting="autoMemoryDirectory",
        memory_rel="auto-memory",
        # the plugin catalog Claude Code fetches into a fresh folder (~14 MB); a plugin becomes
        # active only when installed or enabled (installed_plugins.json, plugins/cache,
        # enabledPlugins in settings.json), and those still go to quarantine
        # also the records of built-in plugins; remote-settings.json and
        # policy-limits.json are fetched from the server at each start, so they are not
        # instruction names at all: a session's copy is thrown away with its folder
        downloads=["plugins/marketplaces", "plugins/known_marketplaces.json",
                   "plugins/store/*_builtin-*.json"],
        json_defaults={"hasCompletedOnboarding": True}),
}


# -- signatures -----------------------------------------------------------------------------------

def _hash_file(path: str) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        h = hashlib.sha256()
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                return h.hexdigest()
            h.update(b)
    finally:
        os.close(fd)


class _Budget:
    def __init__(self) -> None:
        self.entries = 0
        self.bytes = 0

    def take(self, size: int) -> bool:
        self.entries += 1
        self.bytes += size
        return self.entries <= MAX_ENTRIES and self.bytes <= MAX_BYTES


TOO_LARGE = "\0too large"


def signature(path: str, budget: Optional[_Budget] = None) -> Optional[Dict[str, str]]:
    """The content of a file, link or folder tree, by relative name; None when missing; links
    recorded, never followed. Past the budget the result is marked, so it never equals a
    recorded one. Walks without recursion, so a deep tree cannot stop it."""
    budget = budget or _Budget()
    try:
        st0 = os.lstat(path)
    except FileNotFoundError:
        return None
    out: Dict[str, str] = {}
    stack: List[Tuple[str, str, os.stat_result]] = [(path, ".", st0)]
    while stack:
        p, rel, st = stack.pop()
        if not budget.take(st.st_size if stat.S_ISREG(st.st_mode) else 0):
            out[TOO_LARGE] = "x"
            return out
        mode = f"{stat.S_IMODE(st.st_mode):o}"
        if stat.S_ISLNK(st.st_mode):
            out[rel] = "l:" + os.readlink(p)
        elif stat.S_ISREG(st.st_mode):
            try:
                out[rel] = f"f:{mode}:" + _hash_file(p)
            except OSError:
                out[rel] = "f:?"
        elif stat.S_ISDIR(st.st_mode):
            out[rel] = f"d:{mode}"
            try:
                entries = sorted(os.scandir(p), key=lambda e: e.name)
            except OSError:
                out[rel] = "d:?"
                continue
            for e in reversed(entries):
                r = f"{rel}/{e.name}" if rel != "." else e.name
                try:
                    stack.append((e.path, r, e.stat(follow_symlinks=False)))
                except OSError:
                    out[r] = "?"
        else:
            out[rel] = "s:special"
    return out


def _has_link(sig: Optional[Dict[str, str]]) -> bool:
    return bool(sig) and any(v.startswith("l:") for v in sig.values())


# -- moving and copying (rules P1) ------------------------------
#
# These run in the unconfined launcher. They are used only on things that no session can change
# any more: the trusted copy, quarantine, `state/files/`, and a run folder after it has been
# renamed into `trash/`. Folders a session can still write are touched only through descriptors
# (`_opendir`, renames with dir_fd), never by path.

MAX_FILE = 64 * 1024 * 1024  # a kept file or a JSON file larger than this is not read
QUARANTINE_ENTRY_BYTES = 50 * 1024 * 1024
_UF = getattr(stat, "UF_IMMUTABLE", 0) | getattr(stat, "UF_APPEND", 0)


def _opendir(name: str, dir_fd: Optional[int] = None) -> int:
    """A folder opened without following a link, owned by the operator."""
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
    if os.fstat(fd).st_uid != os.getuid():
        os.close(fd)
        raise CarryoverError("a folder is not owned by you")
    return fd


def _movable(parent_fd: int, name: str) -> None:
    """A folder a session made unreadable (chmod 000) cannot move to another parent: its owner
    bits are given back first, by descriptor, never through a link. On Linux the session's
    processes have ended, so the entry checked is the entry changed."""
    try:
        st = os.lstat(name, dir_fd=parent_fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
            return
        mode = stat.S_IMODE(st.st_mode) | 0o700
        try:
            os.chmod(name, mode, dir_fd=parent_fd, follow_symlinks=False)
        except (NotImplementedError, ValueError):  # Linux: no chmod without following links
            # (ValueError with an older C library, RHEL 8); the entry was checked as a real
            # folder above and no longer changes
            os.chmod(name, mode, dir_fd=parent_fd)
    except OSError:
        pass


def _unlock_at(dir_fd: int, name: str) -> None:
    """`_unlock` for an entry named relative to a folder descriptor: the process changes into the
    folder for the one call (the tree no longer changes: trash), so no path length limits it."""
    if not _UF or not hasattr(os, "chflags"):
        return
    here = os.open(".", os.O_RDONLY)
    try:
        os.fchdir(dir_fd)
        _unlock(name)
    except OSError:
        pass
    finally:
        os.fchdir(here)
        os.close(here)


def _unlock(p: str) -> None:
    """Only the immutable and append flags (a session can set them to stop removal), only on an
    entry that no longer changes, never on a hard-linked file."""
    if not _UF or not hasattr(os, "chflags"):
        return
    try:
        st = os.lstat(p)
        if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
            return  # a hard link: the file is not only ours
        if st.st_flags & _UF:
            os.chflags(p, st.st_flags & ~_UF, follow_symlinks=False)
    except (OSError, AttributeError):
        pass


def _copy(src: str, dst: str, budget: Optional[_Budget] = None,
          skip: Sequence[str] = ()) -> None:
    """Copy a file, link or folder tree into `dst` (which must not exist, in a folder only the
    launcher writes). The source is read through descriptors only, never following a link, so a
    folder swapped for a link while it is copied is never entered. Links
    are copied as links; a hard-linked file, a special file, or a tree past the budget is
    refused."""
    budget = budget or _Budget()
    st = os.lstat(src)

    def take(st: os.stat_result) -> None:
        if not budget.take(st.st_size if stat.S_ISREG(st.st_mode) else 0):
            raise CarryoverError("too large to copy")

    def file_at(dir_fd: Optional[int], name: str, out: str) -> None:
        fi = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        try:
            fst = os.fstat(fi)
            if not stat.S_ISREG(fst.st_mode):
                raise CarryoverError(f"{_esc(name)} is not a regular file")
            if fst.st_nlink > 1:
                raise CarryoverError(f"{_esc(name)} is a hard link")
            fo = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                while True:
                    b = os.read(fi, 1 << 20)
                    if not b:
                        break
                    _write_all(fo, b)
            finally:
                os.close(fo)
            os.chmod(out, stat.S_IMODE(fst.st_mode) | 0o600)
        finally:
            os.close(fi)

    take(st)
    if stat.S_ISLNK(st.st_mode):
        os.symlink(os.readlink(src), dst)
        return
    if stat.S_ISREG(st.st_mode):
        file_at(None, src, dst)
        return
    if not stat.S_ISDIR(st.st_mode):
        raise CarryoverError(f"{_esc(src)} is not a regular file or folder")
    top = os.open(src, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    skipped = set(skip)
    stack: List[Tuple[int, str, int, str]] = [(top, dst, stat.S_IMODE(st.st_mode), "")]
    opened = [top]
    try:
        while stack:
            dfd, out, mode, rel = stack.pop()
            os.mkdir(out, 0o700)
            for e in sorted(os.scandir(dfd), key=lambda x: x.name):
                erel = f"{rel}/{e.name}" if rel else e.name
                if erel in skipped or (e.is_file(follow_symlinks=False) and any(
                        any(c in g for c in "*?[") and len(g.split("/")) == len(erel.split("/")) and
                        all(fnmatch.fnmatchcase(a, b) for a, b in zip(erel.split("/"), g.split("/")))
                        for g in skipped)):
                    continue
                est = e.stat(follow_symlinks=False)
                take(est)
                target = os.path.join(out, e.name)
                if stat.S_ISLNK(est.st_mode):
                    os.symlink(os.readlink(e.name, dir_fd=dfd), target)
                elif stat.S_ISREG(est.st_mode):
                    file_at(dfd, e.name, target)
                elif stat.S_ISDIR(est.st_mode):
                    cfd = os.open(e.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
                    opened.append(cfd)
                    stack.append((cfd, target, stat.S_IMODE(est.st_mode), erel))
                else:
                    raise CarryoverError(f"{_esc(e.name)} is not a regular file or folder")
            os.chmod(out, mode | 0o700)
    finally:
        for fd in opened:
            try:
                os.close(fd)
            except OSError:
                pass


def _remove(p: str) -> None:
    """Remove an entry that no longer changes (trash, trusted, quarantine). It works through
    folder descriptors only, one open at a time, going down by name and back up by "..": no
    recursion, no path-length limit, no open-file limit, and never through a link (a link is
    unlinked as a link). Folders get u+rwx first; the two blocking flags are cleared where the
    path is short enough to name, never on a hard-linked file."""
    if not os.path.lexists(p):
        return
    _unlock(p)
    if not _is_real_dir(p):
        os.unlink(p)
        return
    me = os.getuid()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def writable(name: str, dir_fd: int) -> None:
        try:
            st = os.lstat(name, dir_fd=dir_fd)
            if stat.S_ISDIR(st.st_mode) and st.st_uid == me:
                try:
                    os.chmod(name, stat.S_IMODE(st.st_mode) | 0o700, dir_fd=dir_fd,
                             follow_symlinks=False)
                except (NotImplementedError, ValueError):  # Linux (ValueError: an older C
                    # library, RHEL 8): the entry no longer changes (trash)
                    os.chmod(name, stat.S_IMODE(st.st_mode) | 0o700, dir_fd=dir_fd)
        except OSError:
            pass

    parent = os.open(os.path.dirname(p) or ".", flags)
    try:
        writable(os.path.basename(p), parent)
    finally:
        os.close(parent)
    fd = os.open(p, flags)
    names: List[str] = []
    ids: List[Tuple[int, int]] = []  # (device, inode) of each folder on the way down
    path = p  # only used while short enough to name
    try:
        while True:
            down = None
            here = os.fstat(fd)
            try:
                named = len(path) < 900 and os.lstat(path)[1:3] == (here.st_ino, here.st_dev)
            except OSError:
                named = False  # the path no longer names this folder: flags are left alone
            for e in list(os.scandir(fd)):
                if e.is_dir(follow_symlinks=False):
                    if e.stat(follow_symlinks=False).st_dev != here.st_dev:
                        raise CarryoverError(f"{_esc(p)} holds a mount point; it is left as it is")
                    down = e.name
                    break
                if named:
                    _unlock(os.path.join(path, e.name))
                else:
                    _unlock_at(fd, e.name)  # deep: by descriptor
                os.unlink(e.name, dir_fd=fd)
            if down is not None:
                if named:
                    _unlock(os.path.join(path, down))  # a folder's own flags
                else:
                    _unlock_at(fd, down)
                writable(down, fd)
                st = os.fstat(fd)
                nfd = os.open(down, flags, dir_fd=fd)
                os.close(fd)
                fd = nfd
                ids.append((st.st_dev, st.st_ino))
                names.append(down)
                path = os.path.join(path, down)
                continue
            if not names:
                break
            up = os.open("..", flags, dir_fd=fd)
            ust = os.fstat(up)
            if (ust.st_dev, ust.st_ino) != ids[-1]:  # moved while removed: stop
                os.close(up)
                raise CarryoverError(f"{_esc(p)} changed while it was removed; it is left as it is")
            os.close(fd)
            fd = up
            ids.pop()
            os.rmdir(names.pop(), dir_fd=fd)
            path = os.path.dirname(path)
    finally:
        os.close(fd)
    os.rmdir(p)


def _move(src: str, dst: str) -> None:
    """Rename an entry; a rename takes a link, not its target. Never copy-then-delete: a rename
    that fails stops with a message."""
    os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
    _unlock(src)
    try:
        os.rename(src, dst)
    except OSError as exc:
        raise CarryoverError(f"{_esc(src)} could not be moved aside ({exc.strerror}); fix it by "
                             "hand, then start again")


def _write_all(fd: int, data: bytes) -> None:
    """Every byte or an error: a short write (a full disk) never truncates silently (rule D)."""
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        if n <= 0:
            raise OSError(errno.ENOSPC, "short write")
        view = view[n:]


def _is_real_dir(p: str) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(p).st_mode)
    except OSError:
        return False


def _expand(folder: str, pattern: str) -> List[str]:
    """The concrete relative paths of a pattern that exist now; only real folders are entered."""
    rels = [""]
    for part in pattern.split("/"):
        nxt = []
        for r in rels:
            base = os.path.join(folder, r) if r else folder
            if part == "*":
                if _is_real_dir(base):
                    nxt += [os.path.join(r, n) if r else n for n in sorted(os.listdir(base))]
            else:
                nxt.append(os.path.join(r, part) if r else part)
        rels = nxt
    return [r for r in rels if os.path.lexists(os.path.join(folder, r))]


# -- JSON ---------------------------------------------------------------------------------------------

def _json_paths(data: object, keypath: Sequence[str], pre: Tuple[str, ...] = ()) -> List[Tuple[str, ...]]:
    if not keypath:
        return [pre]
    if not isinstance(data, dict):
        return []
    k = keypath[0]
    keys = sorted(data) if k == "*" else ([k] if k in data else [])
    out: List[Tuple[str, ...]] = []
    for key in keys:
        out += _json_paths(data[key], keypath[1:], pre + (key,))
    return out


# keys of the tool's JSON file that `add` never takes, though a session's change to them is
# quarantined: login secrets
JSON_NOT_ADDED = ("primaryApiKey", "customApiKeyResponses")
SHOW_VALUE = 2000


def _shown_value(v: object, whole: bool = False) -> str:
    text = json.dumps(v, sort_keys=True, ensure_ascii=True)
    return _esc(text if whole or len(text) <= SHOW_VALUE else text[:SHOW_VALUE] + " ...(cut)")


def _get(data: object, path: Sequence[str]) -> object:
    for k in path:
        if not isinstance(data, dict) or k not in data:
            return None
        data = data[k]
    return data


def _set(data: dict, path: Sequence[str], value: object) -> None:
    for k in path[:-1]:
        nxt = data.get(k)
        if not isinstance(nxt, dict):
            if value is None:
                return
            nxt = data[k] = {}
        data = nxt
    if value is None:
        data.pop(path[-1], None)
    else:
        data[path[-1]] = value


_MISSING = object()


def _read_json(path: str) -> object:
    """A JSON object; None when the file is missing; _MISSING when it cannot be read as one (a
    file the tool may still read)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        return _MISSING
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1 or st.st_size > MAX_FILE:
            os.close(fd)
            return _MISSING
        with os.fdopen(fd, "rb") as fh:
            raw = fh.read(MAX_FILE + 1)
        if len(raw) > MAX_FILE:
            return _MISSING
        d = json.loads(raw.decode("utf-8"))  # strict: what Python cannot read is not trusted
    except (OSError, ValueError, RecursionError):
        return _MISSING
    return d if isinstance(d, dict) else _MISSING


def _write_json(path: str, data: object) -> None:
    safeio.write_new(path, json.dumps(data, indent=2) + "\n")


def _esc(s: str) -> str:
    return s.encode("unicode_escape").decode("ascii")


# -- the trusted state ------------------------------------------------------------------------------

RUNS, TRASH = "runs", "trash"
OURS = {RUNS, TRASH}  # the tool folder's own entries; anything else is from an older layout


class Store:
    """The trusted copy of one tool's instructions and settings, in
    `~/.phiward/carryover/<tool>/` (no session can read or write it), and the session
    folders built from it. The tool folder `<base>` holds `runs/<id>/` (one session's
    config, temp and caches, each locked by its launcher while it runs) and `trash/` (run folders
    being read or removed). Nothing else is kept. Rule D: any of it may be deleted at any time."""

    VERSION = 5

    def __init__(self, tool: str, home: str, spec: Optional[Spec] = None) -> None:
        self.tool = tool
        self.spec = spec if spec is not None else SPECS.get(tool, Spec())
        self.dir = os.path.join(home, ".phiward", "carryover", tool)
        self.trusted = os.path.join(self.dir, "trusted")
        self.qroot = os.path.join(self.dir, "quarantine")
        self.sessions = os.path.join(self.dir, "sessions")  # what each session was built with
        self.manifest_path = os.path.join(self.dir, "manifest.json")
        self._run_fd: Optional[int] = None
        self.run = ""

    # the record: {"version": 5, "paths": {name: sig|None}}; a session's record, in sessions/<id>:
    # {"config": path, "built": {name: sig}, "json_built": object}
    def _load(self) -> Tuple[Optional[dict], str]:
        m = _read_json(self.manifest_path)
        if m is None:
            return None, "missing"
        if isinstance(m, dict) and isinstance(m.get("paths"), dict):
            return m, ("ok" if m.get("version") == self.VERSION else "old")
        raise CarryoverError(f"the carry-over record ({_esc(self.manifest_path)}) cannot be read; "
                             f"run: phiward carryover reset --tool {self.tool}")

    def _save(self, m: dict) -> None:
        m["version"] = self.VERSION
        _write_json(self.manifest_path, m)

    def _prepare(self) -> None:
        for d in (self.dir, self.sessions):
            os.makedirs(d, mode=0o700, exist_ok=True)
        if os.path.realpath(self.dir) != os.path.normpath(self.dir):
            raise CarryoverError("the carry-over folder has a link on its path")

    def _locked(self):
        """The trusted copy is locked only while it is read and changed, so sessions can run in
        parallel."""
        store = self

        class _L:
            def __enter__(self):
                store._prepare()
                self.fd = _opendir(store.dir)
                fcntl.flock(self.fd, fcntl.LOCK_EX)
                return self

            def __exit__(self, *a):
                os.close(self.fd)
        return _L()

    def _resign(self) -> dict:
        """A record made from the trusted copy, which no session can write (rule D)."""
        m: dict = {"paths": {}}
        if _is_real_dir(self.trusted):
            for n in sorted(os.listdir(self.trusted)):
                if n in self.spec.trusted_names():
                    m["paths"][n] = signature(os.path.join(self.trusted, n))
        return m

    def _record(self) -> Tuple[dict, List[str]]:
        """The trusted record, checked against the trusted copy: an item missing or changed on
        disk is not used, and is reported (rule D)."""
        msgs: List[str] = []
        m, kind = self._load()
        if kind != "ok" or m is None:
            m = self._resign()
            if kind == "missing" and m["paths"]:
                msgs.append("phiward launch: the carry-over record was missing; it was made "
                            "again from the trusted copy")
            self._save(m)
            return m, msgs
        bad = []
        for rel, sig in list(m["paths"].items()):
            if rel not in self.spec.trusted_names():
                m["paths"].pop(rel)
            elif sig is not None and signature(os.path.join(self.trusted, rel)) != sig:
                m["paths"][rel] = None
                bad.append(rel)
        if bad:
            msgs.append(f"phiward launch: the trusted copy of {', '.join(_esc(b) for b in bad)} "
                        "is missing or damaged; it is not used (add or accept it again)")
        return m, msgs

    # -- start ----------------------------------------------------------------------------------------

    def start(self, base: str, run: str, memory: bool = False, edit=None) -> List[str]:
        """Make and lock this session's run folder, finish any session whose launcher is gone,
        and build `<run>/config` from the trusted copy."""
        msgs = _layout(base)
        # made and locked under the lock of runs/, which every cleaner takes too, so no other
        # launcher can finish a folder between its making and its lock
        with _runs_lock(base) as rfd:
            os.mkdir(os.path.basename(run), 0o700, dir_fd=rfd)
            self._run_fd = _opendir(os.path.basename(run), rfd)
            fcntl.flock(self._run_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.run = run
        config = os.path.join(run, "config")
        if not self.spec.enabled:
            msgs += _clean_runs(base, run, lambda _n: [])
            os.makedirs(config, mode=0o700)
            return msgs
        self._prepare()
        msgs += self._move_legacy(base)
        msgs += _clean_runs(base, run, lambda n: self._finish(base, n, "the last session did not "
                                                                       "finish"))
        with self._locked():
            m, warn = self._record()
            msgs += warn
            if edit is not None:
                bad = os.path.join(self.trusted, "settings.json")
                if m["paths"].get("settings.json") is None and os.path.lexists(bad):
                    qid, qdir = self._new_qid()  # damaged: kept for the operator, made again
                    _move(bad, os.path.join(qdir, "files", "settings.json"))
                    msgs += self._finish_entry(qid, qdir, "the trusted settings.json was changed on "
                                               "disk; a new one was made with only the launcher's "
                                               "hook", ["settings.json"], [], [], copied=["settings.json"])
                os.makedirs(self.trusted, mode=0o700, exist_ok=True)
                dfd = _opendir(self.trusted)
                try:
                    edit(dfd)  # the launcher's own hook entry, made on the trusted copy
                finally:
                    os.close(dfd)
                m["paths"]["settings.json"] = signature(os.path.join(self.trusted, "settings.json"))
                self._save(m)
            try:
                rec = self._build(config, m, memory)
            except OSError as exc:
                if _nospace(exc):
                    raise CarryoverError("not enough disk space to start; see `phiward "
                                         f"carryover status --tool {self.tool}`")
                raise
        _write_json(os.path.join(self.sessions, os.path.basename(run) + ".json"), rec)
        return msgs

    def _move_legacy(self, base: str) -> List[str]:
        """Entries of an older layout (state, caches, a shared temp folder, the old config
        files) are never trusted: they move, as they are, into `legacy-<time>` once (rule D)."""
        legacy = [n for n in sorted(os.listdir(base)) if n not in OURS and not n.startswith("legacy-")
                  and n != ".DS_Store"]
        if not legacy:
            return []
        aside = os.path.join(base, "legacy-" + time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3))
        for n in legacy:
            _move(os.path.join(base, n), os.path.join(aside, n))
        return [f"phiward launch: the tool folder had entries from an older layout; they were "
                f"moved to {_esc(aside)} and are not used. To keep an instruction file from there, "
                f"read it, then: phiward carryover add PATH --tool {self.tool}. If a session of an "
                "older phiward is still running, quit it."]

    def _build(self, config: str, m: dict, memory: bool) -> dict:
        """The run folder is new and no session runs in it yet: built by path."""
        os.makedirs(config, mode=0o700)
        for rel, sig in sorted(m["paths"].items()):
            if sig is not None:
                _copy(os.path.join(self.trusted, rel), os.path.join(config, rel))
        if self.spec.json_main and self.spec.json_defaults:
            jp = os.path.join(config, self.spec.json_main)
            data = _read_json(jp)
            data = data if isinstance(data, dict) else {}
            for k, v in self.spec.json_defaults.items():
                data.setdefault(k, v)
            _write_json(jp, data)
        if self.spec.memory_setting:
            s = os.path.join(config, "settings.json")
            data = _read_json(s)
            data = data if isinstance(data, dict) else {}
            if memory:
                data[self.spec.memory_setting] = os.path.join(config, self.spec.memory_rel)
                os.makedirs(os.path.join(config, self.spec.memory_rel), mode=0o700, exist_ok=True)
            else:
                data.pop(self.spec.memory_setting, None)
            _write_json(s, data)
        main_json = _read_json(os.path.join(config, self.spec.json_main)) if self.spec.json_main else None
        built_json = {}
        for n in os.listdir(config):
            if n in self.spec.instructions and n.endswith(".json"):
                d = _read_json(os.path.join(config, n))
                if isinstance(d, dict):
                    built_json[n] = d
        return {"config": config,
                "built_json": built_json,
                "built": {n: signature(os.path.join(config, n)) for n in os.listdir(config)
                          if n in self.spec.instructions},
                "json_built": main_json if isinstance(main_json, dict) else {}}

    # -- end ------------------------------------------------------------------------------------------

    def end(self, base: str, run: str = "") -> List[str]:
        """At exit: the run folder is renamed into `trash/` first; then what the session
        changed in its instructions is copied to quarantine, and the folder is removed."""
        if not self.spec.enabled:
            return []
        run = run or self.run
        if not run:
            return []
        try:
            return self._finish(base, os.path.basename(run), "changed by the session")
        finally:
            if self._run_fd is not None:  # released only after the move
                os.close(self._run_fd)
                self._run_fd = None

    def _finish(self, base: str, name: str, why: str) -> List[str]:
        rec_path = os.path.join(self.sessions, name + ".json")
        rec = _read_json(rec_path)
        t = _to_trash(base, name)
        msgs: List[str] = []
        if not t:
            return msgs  # another launcher finished it, or it could not be moved (it stays)
        if isinstance(rec, dict):
            msgs += self._compare(t, rec, why)
        else:  # rule D: never lost without a word
            msgs.append("phiward launch: a session's record was missing or could not be read "
                        "(the carry-over folder may have been deleted); its changes were not kept")
        try:
            os.unlink(rec_path)
        except FileNotFoundError:
            pass
        if t:
            try:
                _remove(t)
            except (OSError, RecursionError, CarryoverError):
                msgs.append(f"phiward launch: {_esc(t)} could not be removed; it stays in trash "
                            "and is tried again at the next start")
        return msgs

    def _compare(self, t: str, rec: dict, why: str) -> List[str]:
        qid, qdir = self._new_qid()
        moved: List[str] = []
        copied: List[str] = []
        details: List[str] = []
        json_changes: List[dict] = []
        tc = os.path.join(t, "config") if t else ""
        if not (t and _is_real_dir(t) and _is_real_dir(tc)):
            return ["phiward launch: the session's folder was missing or replaced by a link; "
                    "nothing was read from it"]
        built = rec.get("built", {})
        budget = _Budget()
        names = {n for n in set(built) | set(os.listdir(tc)) if n in self.spec.instructions}
        for rel in sorted(names):
            p = os.path.join(tc, rel)
            skip = [d[len(rel) + 1:] for d in self.spec.downloads if d.startswith(rel + "/")]
            cur = _without(signature(p), skip)
            if cur == _without(built.get(rel), skip):
                continue
            old = _without(built.get(rel), skip) or {}
            for k in sorted(set(cur or {}) | set(old)):
                v = (cur or {}).get(k)
                if v != old.get(k) and k != TOO_LARGE:
                    how = "new" if k not in old else "removed" if v is None else "changed"
                    if v and v.startswith("l:"):
                        how += f", a link to {v[2:]}"
                    details.append(f"{rel if k == '.' else rel + '/' + k} ({how})")
            if rel.endswith(".json") and cur and built.get(rel):
                keys = _json_key_diff(os.path.join(tc, rel), rec.get("built_json", {}).get(rel))
                if keys:
                    details.append(f"{rel}: {', '.join(keys)} (changed)")
            moved.append(rel)
            if cur is None:
                continue
            if budget.bytes > QUARANTINE_ENTRY_BYTES or not self._room():
                details.append(f"{rel} (not copied: quarantine is full or the entry too large)")
                continue
            qf = os.path.join(qdir, "files")
            tmp = os.path.join(qf, f".phiward-{secrets.token_hex(6)}")
            try:
                os.makedirs(qf, mode=0o700, exist_ok=True)
                _copy(p, tmp, budget, skip)  # whole or nothing
                os.rename(tmp, os.path.join(qf, rel))
                copied.append(rel)
            except (OSError, CarryoverError, RecursionError) as exc:
                details.append(f"{rel} (not copied: {exc})")
                if os.path.lexists(tmp):
                    _remove(tmp)
        if self.spec.json_main:
            data = _read_json(os.path.join(tc, self.spec.json_main))
            want = rec.get("json_built", {})
            if isinstance(data, dict):
                for kp in self.spec.json_notable:
                    for p in sorted(set(_json_paths(data, kp)) | set(_json_paths(want, kp))):
                        cur = _get(data, p)
                        if cur != _get(want, p) and (cur or _get(want, p)):  # not empty defaults
                            details.append(f"{self.spec.json_main}: {'.'.join(p)} (changed)")
                            json_changes.append({"file": self.spec.json_main, "key": list(p),
                                                 "value": cur})
        return self._finish_entry(qid, qdir, why, moved, details, json_changes, copied=copied)

    def _room(self) -> bool:
        return not os.path.isdir(self.qroot) or len(os.listdir(self.qroot)) < QUARANTINE_MAX

    def _new_qid(self) -> Tuple[str, str]:
        qid = time.strftime("%Y%m%d-%H%M%S") + f"-{time.time_ns() % 10**9:09d}-" + secrets.token_hex(2)
        return qid, os.path.join(self.qroot, qid)

    def _finish_entry(self, qid: str, qdir: str, why: str, moved: List[str], details: List[str],
                      json_changes: List[dict], copied: Sequence[str] = ()) -> List[str]:
        if not moved and not json_changes:
            if _is_real_dir(qdir):
                _remove(qdir)
            return []
        self._bound_quarantine()
        if not _is_real_dir(qdir) and not self._room():
            return [f"phiward launch: {len(moved) + len(json_changes)} item(s) a later session "
                    f"would read as instructions were not kept ({why}); quarantine is full, so no "
                    f"copy was made (phiward carryover status --tool {self.tool})"]
        os.makedirs(qdir, mode=0o700, exist_ok=True)
        _write_json(os.path.join(qdir, "changes.json"),
                    {"why": why, "paths": moved[:5000], "copied": list(copied)[:5000],
                     "truncated": len(moved) > 5000,
                     "json": json_changes[:1000], "details": details[:1000]})
        items = details or moved
        lines = [f"phiward launch: {len(items)} item(s) that a later session would read as "
                 f"instructions were not kept ({why}); in quarantine as {qid}:"]
        lines += ["  " + _esc(i) for i in items[:30]]
        if len(items) > 30:
            lines.append(f"  ... and {len(items) - 30} more")
        lines.append(f"  read them: phiward carryover show --tool {self.tool}; keep them: "
                     f"phiward carryover accept {qid} --tool {self.tool}")
        return lines

    def _bound_quarantine(self) -> None:
        """Only entries the operator has dealt with (accepted) are removed automatically, the
        oldest first; unread ones stay, and a full quarantine stops new copies (_room)."""
        if not os.path.isdir(self.qroot):
            return
        done = sorted(q for q in os.listdir(self.qroot) if q.endswith(".accepted"))
        while done and len(os.listdir(self.qroot)) >= QUARANTINE_MAX:
            try:
                _remove(os.path.join(self.qroot, done.pop(0)))
            except FileNotFoundError:
                pass

    # -- the operator's commands ----------------------------------------------------------------------

    def entries(self) -> List[Tuple[str, dict]]:
        if not os.path.isdir(self.qroot):
            return []
        out = []
        for q in sorted(os.listdir(self.qroot), reverse=True):
            c = _read_json(os.path.join(self.qroot, q, "changes.json"))
            if isinstance(c, dict):
                out.append((q, c))
        return out

    def _put_trusted(self, items: List[Tuple[str, str]], m: dict) -> None:
        """Copy each (name, source) into the trusted copy, all or nothing; links and hard links
        are never trusted. A source of "" removes the name."""
        for name, _src in items:
            if name not in self.spec.trusted_names():
                raise CarryoverError(f"{_esc(name)} is not an instruction or settings name of "
                                     f"{self.tool} ({', '.join(self.spec.trusted_names())})")
        os.makedirs(self.trusted, mode=0o700, exist_ok=True)
        staged: List[Tuple[str, str]] = []
        try:
            for name, src in items:
                tmp = ""
                if src:
                    tmp = os.path.join(self.trusted, f".phiward-{secrets.token_hex(6)}")
                    staged.append((name, tmp))
                    _copy(src, tmp)  # by descriptor; refuses hard links, special files, huge trees
                    sig = signature(tmp)
                    if _has_link(sig) or (sig and TOO_LARGE in sig):
                        raise CarryoverError(f"{_esc(name)} is or holds a link, or is too large; it "
                                             "is never trusted")
                else:
                    staged.append((name, ""))
        except (OSError, CarryoverError, RecursionError):
            for _, tmp in staged:
                if tmp and os.path.lexists(tmp):
                    _remove(tmp)
            raise
        for name, tmp in staged:
            dst = os.path.join(self.trusted, name)
            # download paths are not copied to quarantine: what the trusted copy holds there
            # stays
            for d in self.spec.downloads:
                if tmp and d.startswith(name + "/") and not any(c in d for c in "*?["):
                    old, new = os.path.join(self.trusted, d), os.path.join(tmp, d[len(name) + 1:])
                    if os.path.lexists(old) and not os.path.lexists(new):
                        os.makedirs(os.path.dirname(new), mode=0o700, exist_ok=True)
                        _copy(old, new)
            if os.path.lexists(dst):
                _remove(dst)
            if tmp:
                os.rename(tmp, dst)
            m["paths"][name] = signature(dst) if tmp else None

    def accept(self, qid: str, only: Sequence[str] = ()) -> List[str]:
        """The operator keeps a quarantined change: it is written into the trusted copy (all or
        nothing), and every later session is built with it. `only` limits it to the named items
        (instruction names such as `settings.json`, or `.claude.json` keys such as
        `projects./path.hasTrustDialogAccepted`)."""
        if os.path.basename(qid) != qid or qid in ("", ".", "..") or qid.endswith(".accepted"):
            raise CarryoverError("not a quarantine id")
        qdir = os.path.join(self.qroot, qid)
        c = _read_json(os.path.join(qdir, "changes.json"))
        if not isinstance(c, dict):
            raise CarryoverError(f"no quarantine entry {qid}")
        if c.get("truncated"):
            raise CarryoverError("this entry has too many items to accept; read it and add what you "
                                 "need with: phiward carryover add PATH")
        with self._locked():
            m, _ = self._record()
            rels = [r for r in c.get("paths", []) if isinstance(r, str) and r in self.spec.instructions
                    and (not only or r in only)]
            copied = set(c.get("copied", []))
            items = []
            for r in rels:
                f = os.path.join(qdir, "files", r)
                if r in copied and os.path.lexists(f):
                    items.append((r, f))
                elif not os.path.lexists(f) and any(d.startswith(f"{r} (removed") for d in c.get("details", [])):
                    items.append((r, ""))  # the session removed it: accepting removes it
                else:
                    raise CarryoverError(f"{_esc(r)} was not copied to quarantine whole; it cannot be "
                                         "accepted (read the details; add what you need by hand)")
            changes = [ch for ch in c.get("json", []) if isinstance(ch, dict) and
                       ch.get("file") == self.spec.json_main and isinstance(ch.get("key"), list)
                       and (not only or ".".join(ch["key"]) in only)]
            known = set(c.get("paths", [])) | {".".join(ch["key"]) for ch in c.get("json", [])
                                               if isinstance(ch, dict) and isinstance(ch.get("key"), list)}
            unknown = [o for o in only if o not in known]
            if unknown:
                raise CarryoverError(f"not in this entry: {', '.join(_esc(u) for u in unknown)}")
            if changes:
                obj = _read_json(os.path.join(self.trusted, self.spec.json_main))
                obj = obj if isinstance(obj, dict) else {}
                for ch in changes:
                    _set(obj, ch["key"], ch.get("value"))
                tmpj = os.path.join(self.dir, f".phiward-{secrets.token_hex(6)}.json")
                _write_json(tmpj, obj)
                items.append((self.spec.json_main, tmpj))
            try:
                self._put_trusted(items, m)
            finally:
                if changes and os.path.lexists(tmpj):
                    os.unlink(tmpj)
            self._save(m)
        if only:  # what was not named stays in quarantine
            rest_paths = [r for r in c.get("paths", []) if r not in only]
            rest_json = [ch for ch in c.get("json", []) if ".".join(ch.get("key", [])) not in only]
            if rest_paths or rest_json:
                c["paths"], c["json"] = rest_paths, rest_json
                c["copied"] = [r for r in c.get("copied", []) if r in rest_paths]
                c["details"] = [d for d in c.get("details", [])
                                if not any(d == o or d.startswith(o + "/") or d.startswith(o + " ")
                                           or d.startswith(o + ":") for o in only)]
                _write_json(os.path.join(qdir, "changes.json"), c)
                return [n for n, _ in items]
        os.rename(qdir, qdir + ".accepted")
        return [n for n, _ in items if n != self.spec.json_main] + [
            ".".join(ch["key"]) for ch in changes]

    def add(self, src: str, name: str = "") -> str:
        """The operator puts an instruction file or folder of their own into the trusted copy.
        The tool's own JSON file (`json_main`, Claude Code's `.claude.json`) is never copied
        whole: only its JSON_ADD keys (MCP servers, trust and allowed tools), merged into the
        trusted copy's; the return value then names the keys taken."""
        name = name or os.path.basename(os.path.normpath(src))
        if self.spec.json_main and name == self.spec.json_main:
            return self._add_json(src)
        if not os.path.lexists(src):
            raise CarryoverError(f"{_esc(src)} does not exist")
        ag_home = os.path.realpath(os.path.dirname(os.path.dirname(self.dir)))
        real = os.path.realpath(src)
        if real == ag_home or real.startswith(ag_home + os.sep) or ag_home.startswith(real + os.sep):
            raise CarryoverError("a source inside or above ~/.phiward cannot be added")
        with self._locked():
            m, _ = self._record()
            self._put_trusted([(name, src)], m)
            self._save(m)
        return name

    def _add_json(self, src: str) -> str:
        data = _read_json(src)
        if not isinstance(data, dict):
            raise CarryoverError(f"{_esc(src)} cannot be read as a JSON object")
        with self._locked():
            m, _ = self._record()
            obj = _read_json(os.path.join(self.trusted, self.spec.json_main))
            obj = obj if isinstance(obj, dict) else {}
            taken: List[str] = []
            for kp in self.spec.json_notable:
                if kp[-1] in JSON_NOT_ADDED:
                    continue
                for p in _json_paths(data, kp):
                    v = _get(data, p)
                    if v is not None:
                        _set(obj, list(p), v)
                        taken.append(".".join(p))
            tmpj = os.path.join(self.dir, f".phiward-{secrets.token_hex(6)}.json")
            _write_json(tmpj, obj)
            try:
                self._put_trusted([(self.spec.json_main, tmpj)], m)
            finally:
                if os.path.lexists(tmpj):
                    os.unlink(tmpj)
            self._save(m)
        return ", ".join(taken) or "nothing"

    def show_lines(self) -> List[str]:
        """What `carryover show` prints: each quarantine entry, its items, and for a change to
        the tool's JSON file the value `accept` would write (escaped, cut at SHOW_VALUE)."""
        out: List[str] = []
        trusted = _read_json(os.path.join(self.trusted, self.spec.json_main)) \
            if self.spec.json_main else None
        for qid, c in self.entries():
            if qid.endswith(".accepted"):
                continue
            items = c.get("details") or list(c.get("paths", []))
            out.append(f"{qid}  {_esc(str(c.get('why', '')))}  {len(items)} item(s)")
            out += [f"    {_esc(str(i))}" for i in items]
            for ch in c.get("json", []):
                if not isinstance(ch, dict) or not isinstance(ch.get("key"), list):
                    continue
                key = ".".join(str(k) for k in ch["key"])
                old = _get(trusted, ch["key"]) if isinstance(trusted, dict) else None
                new = ch.get("value")
                if isinstance(old, dict) and isinstance(new, dict) or \
                        old is None and isinstance(new, dict):
                    # entry by entry (a server added last is never cut away)
                    before = old if isinstance(old, dict) else {}
                    for k in sorted(set(before) | set(new), key=str):
                        if before.get(k) == new.get(k):
                            continue
                        what = ("removed" if k not in new else "added" if k not in before
                                else "changed to")
                        if k in new and isinstance(new[k], dict):
                            # a server: each of its keys on a line of its own (`command` and
                            # `env` are never cut away behind a long `args`)
                            out.append(f"    {_esc(key)}.{_esc(str(k))}: {what}")
                            for sk in sorted(new[k], key=str):
                                sv = new[k][sk]
                                if isinstance(sv, dict):  # `env`: each variable whole
                                    out.append(f"      {_esc(str(sk))}:")
                                    out += [f"        {_esc(str(a))}={_shown_value(b, True)}"
                                            for a, b in sorted(sv.items(), key=lambda x: str(x[0]))]
                                elif isinstance(sv, list):  # `args`: each word whole
                                    out.append(f"      {_esc(str(sk))}:")
                                    out += [f"        {_shown_value(b, True)}" for b in sv]
                                else:
                                    out.append(f"      {_esc(str(sk))}: {_shown_value(sv, True)}")
                            continue
                        shown = "" if k not in new else " " + _shown_value(new[k])
                        out.append(f"    {_esc(key)}.{_esc(str(k))}: {what}{shown}")
                else:
                    out.append(f"    {_esc(key)}: now {_shown_value(old)}")
                    out.append(f"    {_esc(key)}: accept writes {_shown_value(new)}")
            out.append(f"    files: {_esc(os.path.join(self.qroot, qid, 'files'))}")
        return out or ["nothing in quarantine"]

    def reset(self) -> None:
        """The record cannot be read: it is made again from the trusted copy."""
        with self._locked():
            self._save(self._resign())

    def status(self, base: str) -> List[str]:
        """Sizes, and what each deletion costs (rule D): everything here may be deleted."""
        def size(p: str) -> Tuple[int, int]:
            n = b = 0
            if _is_real_dir(p):  # never a link at the top; bounded
                stack = [p]
                while stack and n < 1_000_000:
                    try:
                        it = list(os.scandir(stack.pop()))
                    except OSError:
                        continue
                    for e in it:
                        try:
                            st = e.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        n += 1
                        b += st.st_size if stat.S_ISREG(st.st_mode) else 0
                        if stat.S_ISDIR(st.st_mode):
                            stack.append(e.path)
            return n, b
        rows = [
            (os.path.join(base, RUNS), "session folders; delete when no session runs: costs nothing"),
            (os.path.join(base, TRASH), "being removed; delete when no session runs: costs nothing"),
            (self.qroot, "quarantine; delete: you lose copies you have not read"),
            (self.trusted, "the trusted copy; delete: sessions start with no instructions or settings "
                           "of yours, and you add or accept them again"),
        ]
        out = []
        for p, what in rows:
            n, b = size(p)
            out.append(f"{b / (1 << 20):10.1f} MB  {n:7d} entries  {_esc(p)}\n    {what}")
        legacy = [x for x in (os.listdir(base) if _is_real_dir(base) else []) if x.startswith("legacy-")]
        if legacy:
            out.append(f"  {len(legacy)} legacy folder(s) in {_esc(base)}: entries of an older layout, "
                       "not used; delete them when you have kept what you need")
        return out


def _without(sig: Optional[Dict[str, str]], skip: Sequence[str]) -> Optional[Dict[str, str]]:
    """A signature without the entries under the skipped relative paths."""
    if sig is None or not skip:
        return sig
    gone = {k for k in sig if any(_skip_match(k, s, sig.get(k, "")) for s in skip)}
    if not gone:
        return sig
    out = {k: v for k, v in sig.items() if k not in gone}
    # a folder left empty by dropped downloads counts as no folder, at any depth
    for k in sorted((k for k, v in out.items() if v.startswith("d:") and k != "."),
                    key=lambda x: -x.count("/")):
        if not any(o.startswith(k + "/") for o in out) and any(g.startswith(k + "/") for g in gone):
            out.pop(k)
    if list(out) == ["."] and out["."].startswith("d:"):
        return None
    return out


def _skip_match(k: str, s: str, v: str) -> bool:
    """A literal skip covers its subtree; a glob matches one path segment per part, and a file
    only (`*` must not cross "/", and a glob never hides a folder's contents)."""
    if not any(c in s for c in "*?["):
        return k == s or k.startswith(s + "/")
    kp, sp = k.split("/"), s.split("/")
    return len(kp) == len(sp) and v.startswith("f:") and \
        all(fnmatch.fnmatchcase(a, b) for a, b in zip(kp, sp))


def _json_key_diff(path: str, before: object) -> List[str]:
    """The top-level keys that differ between a JSON file and what it was built with."""
    now = _read_json(path)
    if not isinstance(now, dict):
        return []
    was = before if isinstance(before, dict) else {}
    return sorted(k for k in set(now) | set(was) if now.get(k) != was.get(k))


def _nospace(exc: OSError) -> bool:
    return exc.errno in (errno.ENOSPC, errno.EDQUOT)


def _layout(base: str) -> List[str]:
    """The tool folder's own folders, made again when missing (rule D); only the launcher
    writes them (a session writes only inside its own run folder)."""
    for sub in (RUNS, TRASH):
        p = os.path.join(base, sub)
        os.makedirs(p, mode=0o700, exist_ok=True)
        if not _is_real_dir(p) or os.path.realpath(p) != os.path.normpath(p):
            raise CarryoverError(f"{_esc(p)} is not a real folder")
    return []


def _to_trash(base: str, name: str) -> str:
    """P2: rename `runs/<name>` into `trash/` in one step, by descriptor; the rename takes a link
    as a link. Returns the new path, or "" when it could not be moved (it stays in runs/, where
    nothing reads it)."""
    rfd = _opendir(os.path.join(base, RUNS))
    tfd = _opendir(os.path.join(base, TRASH))
    target = f"{name}-{secrets.token_hex(4)}"
    try:
        # a flag or mode a session set on its own run folder would stop the rename; runs/ is
        # written only by the launcher, so the entry is changed by name there without following
        # a link (on Linux the session's processes have ended, so the entry checked is the one
        # changed)
        try:
            st = os.lstat(name, dir_fd=rfd)
            if stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid():
                if _UF and getattr(st, "st_flags", 0) & _UF:
                    os.chflags(os.path.join(base, RUNS, name), st.st_flags & ~_UF, follow_symlinks=False)
                _movable(rfd, name)
        except (OSError, NotImplementedError):
            pass
        os.rename(name, target, src_dir_fd=rfd, dst_dir_fd=tfd)
    except OSError:
        return ""
    finally:
        os.close(rfd)
        os.close(tfd)
    return os.path.join(base, TRASH, target)


def _plain_finish(base: str, name: str) -> List[str]:
    t = _to_trash(base, name)
    if t:
        try:
            _remove(t)
        except (OSError, RecursionError, CarryoverError):
            return [f"phiward launch: {_esc(t)} could not be removed; it is tried again at the "
                    "next start"]
    return []


class _runs_lock:
    """The lock of runs/: held while a run folder is made and locked, and while a cleaner tests a
    run folder's lock and moves it."""

    def __init__(self, base: str) -> None:
        self.base = base

    def __enter__(self) -> int:
        self.fd = _opendir(os.path.join(self.base, RUNS))
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self.fd

    def __exit__(self, *a) -> None:
        os.close(self.fd)


def _clean_runs(base: str, current: str, finish) -> List[str]:
    """Every run folder but the current one whose launcher no longer holds its lock is finished
    (`finish(name)`: read, then moved to trash and removed). A locked one is a live session and
    is left alone (parallel sessions). Trash is emptied; what cannot be removed stays and is
    reported."""
    msgs: List[str] = []
    runs = os.path.join(base, RUNS)
    with _runs_lock(base) as rfd:
        for n in sorted(os.listdir(rfd)):
            if os.path.join(runs, n) == current:
                continue
            try:
                st = os.lstat(n, dir_fd=rfd)
            except OSError:
                continue
            if not stat.S_ISDIR(st.st_mode):  # a link or a file: nothing to read, only moved away
                msgs += _plain_finish(base, n)
                continue
            _movable(rfd, n)  # a session may have made its own folder unreadable
            try:
                fd: Optional[int] = _opendir(n, rfd)
            except (OSError, CarryoverError):
                continue  # still not openable: its lock cannot be tested, so it counts as live
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                continue  # a live session
            try:
                msgs += finish(n)  # the lock is held through the move
            finally:
                os.close(fd)
    trash = os.path.join(base, TRASH)
    left = 0
    tfd = _opendir(trash)
    try:
        for n in sorted(os.listdir(tfd)):
            try:
                fd: Optional[int] = _opendir(n, tfd)
            except (OSError, CarryoverError):
                fd = None  # a link or a file
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    os.close(fd)
                    continue  # its launcher is still reading it
            try:
                _remove(os.path.join(trash, n))  # the lock is held until it is gone
            except (OSError, RecursionError, CarryoverError):
                left += 1
            finally:
                if fd is not None:
                    os.close(fd)
    finally:
        os.close(tfd)
    if left:
        msgs.append(f"phiward launch: {left} old session folder(s) in {_esc(trash)} could not be "
                    "removed (a file may be locked); remove them by hand")
    return msgs


# -- the project report -----------------------------------------------------------------------------

SKIP = {".git"}  # objects are not walked; its control entries are (GIT_CONTROL_REPORT)
# the git control entries that run code or point git elsewhere: walked inside every `.git`, so a
# repository the session made, or changed, is reported (a new
# .git/config with core.fsmonitor runs when the operator's prompt calls `git status`)
GIT_CONTROL_REPORT = ("config", "HEAD", "commondir", "gitdir", "hooks", "info", "modules",
                      "worktrees")
INSTRUCTION_NAMES = {"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules",
                     ".windsurfrules", "copilot-instructions.md"}
RUNS_LATER_NAMES = {"Makefile", "makefile", "GNUmakefile", "package.json", "pyproject.toml",
                    "setup.py", "setup.cfg", "tox.ini", "noxfile.py", "conftest.py",
                    ".pre-commit-config.yaml", "lefthook.yml", ".envrc", "Justfile", "justfile",
                    "Rakefile", "build.gradle", "pom.xml", "Cargo.toml", "CMakeLists.txt",
                    "Dockerfile", "docker-compose.yml", ".gitattributes", ".gitmodules",
                    ".gitlab-ci.yml", "Snakefile", "nextflow.config", "sitecustomize.py",
                    "usercustomize.py", ".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs",
                    # read from the current folder by R, IPython, pdb, pytest and task runners
                    ".Rprofile", ".Renviron", "activate.R", ".pdbrc", "ipython_config.py",
                    "jupyter_notebook_config.py", "jupyter_server_config.py",
                    "jupyter_lab_config.py", "pytest.ini", "mise.toml", ".mise.toml",
                    "Taskfile.yml", "Taskfile.yaml"}
RUNS_LATER_SUFFIXES = (".sh", ".bash", ".pth")
SETTINGS_PREFIXES = (".vscode/", ".idea/", ".mcp.json", ".claude/settings")
TRUNCATED = "\0truncated"


def project_state(project: str, limit: int = 200_000, scan_limit: int = 2_000_000) -> Dict[str, tuple]:
    """Metadata of every entry in the project (inode, size, times, mode, link target), bounded;
    the change time cannot be set by a program, so a reset modification time is still seen.
    Past the bound the result says so, and nothing is reported as removed."""
    import collections
    out: Dict[str, tuple] = {}
    # breadth first, dot-folders first: instructions and settings live near the top and in dot
    # folders, so a flood of files deep in the tree is visited last
    stack: "collections.deque[str]" = collections.deque([""])
    seen = 0
    while stack:
        rel = stack.popleft()
        try:
            it = sorted(os.scandir(os.path.join(project, rel) if rel else project),
                        key=lambda e: (not e.name.startswith("."), e.name))
        except OSError:
            continue
        for e in it:
            seen += 1
            if seen > scan_limit:
                out[TRUNCATED] = ("t", len(stack) + 1)
                return out
            r = f"{rel}/{e.name}" if rel else e.name
            full = len(out) >= limit
            if full and TRUNCATED not in out:
                out[TRUNCATED] = ("t", 0)
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            link = os.readlink(e.path) if stat.S_ISLNK(st.st_mode) else ""
            if stat.S_ISDIR(st.st_mode):
                out[r] = ("d", st.st_ino, st.st_mode)
                if e.name not in SKIP:
                    # dot-folder trees (.claude, .vscode, .github, .husky) first and whole:
                    # they hold instructions and settings, and a flood elsewhere waits
                    if any(part.startswith(".") for part in r.split("/")):
                        stack.appendleft(r)
                    else:
                        stack.append(r)
                else:
                    stack += [f"{r}/{c}" for c in GIT_CONTROL_REPORT
                              if os.path.isdir(os.path.join(project, r, c)) and
                              not os.path.islink(os.path.join(project, r, c))]
                    for c in GIT_CONTROL_REPORT:
                        q = os.path.join(project, r, c)
                        try:
                            cst = os.lstat(q)
                        except OSError:
                            continue
                        if not stat.S_ISDIR(cst.st_mode):
                            ln = os.readlink(q) if stat.S_ISLNK(cst.st_mode) else ""
                            out[f"{r}/{c}"] = ("f", cst.st_ino, cst.st_size, cst.st_mtime_ns,
                                               cst.st_ctime_ns, cst.st_mode, ln)
            else:
                ent = ("f", st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, link)
                # past the bound, the walk goes on and keeps what matters most: instructions,
                # files that run later, settings (a flood of files must not hide
                # them)
                if not full or _rank(r, ent, project) < 3:
                    out[r] = ent
    return out


def _rank(rel: str, entry: Optional[tuple] = None, project: str = "") -> int:
    name = os.path.basename(rel)
    if rel.startswith(".git/") or "/.git/" in rel or name == ".git":
        return 1  # git control files run code (hooks, fsmonitor) or point git elsewhere; a `.git`
        # file (`gitdir: ...`) points git at a folder the session chose
    if project and (name in ("config", "HEAD", "packed-refs", "commondir") or
                    rel.startswith("hooks/") or "/hooks/" in rel):
        if rel.startswith("hooks/"):
            repo_rel = ""
        elif "/hooks/" in rel:
            repo_rel = rel.split("/hooks/")[0]
        else:
            repo_rel = os.path.dirname(rel)
        repo = os.path.join(project, repo_rel) if repo_rel else project
        if os.path.isdir(os.path.join(repo, "objects")) and (
                os.path.isfile(os.path.join(repo, "HEAD")) or os.path.isdir(os.path.join(repo, "refs"))):
            return 1  # a folder laid out as a git repository (a bare one, or a gitdir target)
    if rel.startswith(SETTINGS_PREFIXES) or "/.vscode/" in rel:
        return 2
    if name in INSTRUCTION_NAMES or rel.startswith((".claude/", ".cursor/rules/", ".github/instructions/")) \
            or "/.claude/" in rel:
        return 0
    if name in RUNS_LATER_NAMES or name.endswith(RUNS_LATER_SUFFIXES) or \
            rel.startswith((".github/workflows/", ".husky/", ".githooks/", ".devcontainer/",
                            ".cargo/")) or "/.husky/" in rel:
        return 1
    if entry is not None and entry[0] == "f" and entry[5] & 0o111:
        return 1  # an executable file: a program on a PATH, a script run by name
    return 3


# the kinds of changed project files, by `_rank`: the first three are for a person to read
KINDS = ("instructions", "runs_later", "settings", "other")


class Changes(NamedTuple):
    """The project files a session changed, as (path, how) grouped by `_rank`, and whether the
    scan was cut short (the project has more entries than it compares)."""
    groups: Dict[int, List[Tuple[str, str]]]
    truncated: bool


def project_changes(before: Dict[str, tuple], after: Dict[str, tuple],
                    project: str = "") -> Changes:
    """`Changes` between two `project_state`s."""
    truncated = TRUNCATED in before or TRUNCATED in after
    changed = []
    for r in set(before) | set(after):
        if r == TRUNCATED:
            continue
        b, a = before.get(r), after.get(r)
        if b == a or (b and a and b[0] == a[0] == "d"):
            continue
        if a is None and truncated:
            continue  # past the bound, an entry not seen is not known to be removed
        if (a or b)[0] == "d" and (b is None or a is None):
            continue  # a folder made or removed: its files are listed
        changed.append((r, "new" if b is None else "removed" if a is None else "changed"))
    groups: Dict[int, List[Tuple[str, str]]] = {0: [], 1: [], 2: [], 3: []}
    for r, how in sorted(changed):
        groups[_rank(r, after.get(r) or before.get(r), project)].append((r, how))
    return Changes(groups, truncated)


def project_report(changes: Changes) -> List[str]:
    """The lines `launch` prints about the project files a session changed
    (`project_changes`)."""
    groups, truncated = changes
    changed = [c for k in sorted(groups) for c in groups[k]]
    lines: List[str] = []
    if changed:
        lines.append(f"phiward launch: the session changed {len(changed)} file(s) in the "
                     "project; read them before you run anything outside launch:")
        # instructions for models in full (up to 500), so other files cannot push them out of
        # sight
        # instructions, files that run later and settings are never folded into a count
        for k, title, show in ((0, "instructions for models", 500), (1, "files that run later", 500),
                               (2, "settings", 500)):
            if groups[k]:
                lines.append(f"  {title} ({len(groups[k])}):")
                lines += [f"    {_esc(r)} ({how})" for r, how in groups[k][:show]]
                if len(groups[k]) > show:
                    lines.append(f"    ... and {len(groups[k]) - show} more")
        rest = groups[3]
        if rest:
            if len(rest) <= 10:
                lines.append("  other: " + "; ".join(_esc(r) for r, _ in rest))
            else:
                lines.append(f"  and {len(rest)} other file(s)")
    if truncated:
        lines.append("phiward launch: WARNING: the project has more entries than the report "
                     "compares; past that point only instructions, files that run later and "
                     "settings were checked, and other files are not listed. Read the project "
                     "before you run anything outside launch.")
    return lines


# -- the command ---------------------------------------------------------------------------------------

USAGE = ("usage: phiward carryover status [--tool NAME]\n"
         "       phiward carryover add PATH [--as NAME] [--tool NAME]\n"
         "       phiward carryover show [--tool NAME]\n"
         "       phiward carryover accept ID [ITEM...] [--tool NAME]\n"
         "       phiward carryover reset [--tool NAME]\n")
HELP = USAGE + """
Commands:
  status            show the size of each carry-over folder (sessions, trash, quarantine,
                    the trusted copy) and what it costs to delete it
  add PATH          put an instruction file or folder of your own into the trusted copy
                    (--as NAME: the name it gets there)
  show              list the changes in quarantine, each with its ID and items
  accept ID [ITEM...]  keep a change from quarantine (all of it, or only the named items);
                    every later session starts with it
  reset             make the record again from the trusted copy, when it cannot be read

Options:
  --tool NAME       the agent tool (default: claude)
  -h, --help        show this help

Each `phiward launch` session runs in a config folder of its own. It is built from a trusted
copy that no session can read or write, and it is thrown away at exit. When a session changes
the tool's instructions or settings, the change goes to quarantine. Read it with `show`, and
keep it with `accept`. These commands are yours: run them in your own terminal, not through
an agent tool.
"""


def main(argv: List[str]) -> int:
    from phiward import wholetool
    args = list(argv)
    if args[:1] in (["-h"], ["--help"]):
        sys.stdout.write(HELP)
        return 0
    tool = "claude"
    if "--tool" in args:
        i = args.index("--tool")
        if i + 1 >= len(args):
            sys.stderr.write(USAGE)
            return 2
        tool = args[i + 1]
        del args[i:i + 2]
    if tool not in wholetool.ADAPTERS:
        sys.stderr.write(f"phiward carryover: no adapter for '{tool}'\n")
        return 2
    env = dict(os.environ)
    store = Store(tool, wholetool._real_home(env))
    if args == ["status"]:
        base = wholetool.tool_folder(wholetool.ADAPTERS[tool], env)
        sys.stdout.write("\n".join(store.status(base)) + "\n")
        return 0
    if args == ["show"]:
        sys.stdout.write("\n".join(store.show_lines()) + "\n")
        return 0
    if args[:1] in (["accept"], ["add"], ["reset"]):
        # these change what every later `launch` session trusts: the operator's, in a terminal
        # (an agent could otherwise reach them through another spelling of the command)
        try:
            tty = sys.stdin.isatty()
        except (AttributeError, ValueError):
            tty = False
        if not tty:
            sys.stderr.write("phiward carryover: `add`, `accept` and `reset` change what every "
                             "later session trusts; run them in your own terminal, not through "
                             "an agent tool. Nothing was changed.\n")
            return 2
    try:
        if args[:1] == ["accept"] and len(args) >= 2:
            done = store.accept(args[1], args[2:])
            sys.stdout.write(f"accepted {len(done)} item(s); they are now the trusted state\n")
            return 0
        if args[:1] == ["add"] and len(args) in (2, 4) and (len(args) == 2 or args[2] == "--as"):
            from phiward import config, paths
            cfg = config.load(os.getcwd(), env=env)
            src = os.path.abspath(args[1])
            if cfg.problem:
                raise CarryoverError("the phiward config cannot be used (run phiward doctor)")
            rel = paths.ProtectedSet(cfg.all_roots, cfg.patterns).relation(os.path.realpath(src))
            if rel in (paths.INSIDE, paths.ABOVE):  # priority 1: the model reads this copy
                raise CarryoverError("that path is inside or above protected data; it is never put "
                                     "into the trusted copy, which every session's model reads")
            # copied from the resolved path that was checked
            as_name = args[3] if len(args) == 4 else os.path.basename(src)
            name = store.add(os.path.realpath(src), as_name)
            if store.spec.json_main and as_name == store.spec.json_main:
                sys.stdout.write(f"added these keys of {as_name} to the trusted copy: {name}. "
                                 "Every later session starts with them; the `env` and header "
                                 "values of an MCP server there are readable by the agent.\n")
            else:
                sys.stdout.write(f"added {name} to the trusted copy; every later session starts "
                                 "with it\n")
            return 0
        if args == ["reset"]:
            store.reset()
            sys.stdout.write("the record was made again from the trusted copy\n")
            return 0
    except (CarryoverError, OSError) as exc:
        sys.stderr.write(f"phiward carryover: {exc}\n")
        return 1
    sys.stderr.write(USAGE)
    return 2
