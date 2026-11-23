"""The project scan: subject and sample identifiers in the project's own files and file names,
outside the protected roots (PLAN-PHI-TESTS step 3). Such a file reaches the model with no
gateway: the hook decides by path, and Claude Code sends `CLAUDE.md` and the file list itself.

- The rules: subject identifiers only (`sanitize.subject_sanitizer`): no positions, numbers,
  file or read names, dates, roots or entry names, which a project holds everywhere.
- The walk: one `os.scandir` walk of the project, the instruction files first, sorted by name,
  never through a link. It runs no program: git would read the project's `.git/config`
  (`core.fsmonitor`) and run what it names. It skips `wholetool.SKIP_TREES`, the protected and
  hidden paths, the `[sanitize] scan_allow` paths, and more than ENTRY_CAP entries of a folder.
- Each entry's path is one line. A regular file's first HEAD bytes are read (of its
  decompressed form for gzip and BGZF; UTF-16 with a BOM is decoded), unless it is binary (a
  NUL in its first 8 KiB); a line over MAX_LINE is not read. Each skip is counted.
- What it says: placeholders, counts and paths as the scan's sanitizer masks them, never the
  text it matched.
"""

import os
import stat
import time
import zlib
from collections import Counter
from typing import Dict, List, NamedTuple, Optional, Set, Tuple

from phiward import config, sanitize

BUDGET = 2.0  # seconds: launch, `doctor --headless` and the SessionStart note
HEAD = 1 << 20  # bytes of a file's content read (after gzip)
MAX_LINE = 64 * 1024  # as run.MAX_LINE: a longer line (minified code) is not read
ENTRY_CAP = 10000  # entries read in one folder
SHOWN = 50  # files `doctor --show-paths` lists
FIRST = ("CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".claude")  # sent at the start
# the skip counts, by reason
BINARY, LONG, UNREADABLE, HEAD_ONLY = "binary files", "long lines", "unreadable", "files past 1 MiB"
SKIPPED, PROTECTED, ALLOWED, CAPPED = ("skipped folders", "protected", "allowed by [sanitize] "
                                       "scan_allow", "folders over the entry cap")
_GZIP = b"\x1f\x8b"
_GZIP_INPUT = 8 * HEAD  # compressed bytes read at most for one file's head
_WITHHELD = "<WITHHELD>"  # the kind of a line the sanitizer withholds and no rule names


class Result(NamedTuple):
    hits: List[Tuple[str, int, Tuple[str, ...]]]  # (masked relative path, line or 0, kinds)
    skipped: Dict[str, int]  # counts by reason
    files: int  # regular files looked at
    complete: bool  # False when the deadline came first
    error: str  # non-empty: the scan could not run (fail closed)
    off: bool = False  # no subject rule: nothing to look for


def deadline() -> float:
    return time.monotonic() + BUDGET


class _Stop(Exception):
    pass


class _Scan:
    def __init__(self, san: sanitize.Sanitizer, top: str, cfg: config.Config,
                 until: Optional[float]):
        from phiward import claude_settings, hidden, paths, pathid, wholetool
        self.san, self.top, self.until = san, top, until
        self.rules = san.path_rules + san.id_rules
        self.pset = paths.ProtectedSet(list(cfg.all_roots) + hidden.paths(None, cfg, session=True),
                                       cfg.patterns)
        self.fold, self.inside = pathid.fold, paths.INSIDE
        self.allow = [os.path.realpath(a) for a in cfg.sanitize_scan_allow]
        self.skip_tree = lambda p: claude_settings._skipped(p, wholetool.SKIP_TREES)
        self.hits: List[Tuple[str, int, Tuple[str, ...]]] = []
        self.skipped: Counter = Counter()
        self.files = 0

    def over(self) -> None:
        if self.until is not None and time.monotonic() > self.until:
            raise _Stop()

    def kinds(self, line: str) -> Set[str]:
        """The placeholders of what the scan's rules mask in `line` (empty: nothing)."""
        if not line:
            return set()
        norm = sanitize.normalize(line)
        out = self.san.clean(norm)
        if out == norm:
            return set()
        if out == sanitize.WITHHELD:  # a form the masks cannot rewrite (an escape): its rules
            plain = sanitize.normalize(sanitize.unescape(norm))
            return {r for rx, r in self.rules if rx.search(norm) or rx.search(plain)} or \
                {_WITHHELD}
        found = set(sanitize._PLACEHOLDER.findall(out))
        return {p for p in found if out.count(p) > norm.count(p)} or {_WITHHELD}

    def listing(self, folder: str, top: bool = False) -> List[os.DirEntry]:
        """The folder's entries, at most ENTRY_CAP, sorted by name (the instruction files first
        at the top), last first (a stack)."""
        ents: List[os.DirEntry] = []
        try:
            with os.scandir(folder) as it:
                for e in it:
                    if len(ents) == ENTRY_CAP:
                        self.skipped[CAPPED] += 1
                        break
                    ents.append(e)
        except OSError:
            self.skipped[UNREADABLE] += 1
            return []
        key = (lambda e: (FIRST.index(e.name) if e.name in FIRST else len(FIRST), e.name)) \
            if top else (lambda e: e.name)
        return sorted(ents, key=key, reverse=True)

    def walk(self) -> None:
        stack = [self.listing(self.top, top=True)]
        while stack:
            if not stack[-1]:
                stack.pop()
                continue
            e = stack[-1].pop()
            self.over()
            path = e.path
            if any(path == a or path.startswith(a.rstrip("/") + "/") for a in self.allow):
                self.skipped[ALLOWED] += 1
                continue
            if self.pset and self.pset._relation_one(self.fold(path)) == self.inside:
                self.skipped[PROTECTED] += 1
                continue
            try:
                is_dir = e.is_dir(follow_symlinks=False)
                is_file = e.is_file(follow_symlinks=False)
            except OSError:
                self.skipped[UNREADABLE] += 1
                continue
            if is_dir and self.skip_tree(path):
                self.skipped[SKIPPED] += 1
                continue
            rel = os.path.relpath(path, self.top)
            found = self.kinds(rel)
            if found:
                self.hits.append((self.shown(rel), 0, tuple(sorted(found))))
            if is_dir:
                stack.append(self.listing(path))
            elif is_file:  # links, sockets and pipes: the name only
                self.files += 1
                self.content(path, rel)

    def shown(self, rel: str) -> str:
        return self.san.clean(rel)

    def content(self, path: str, rel: str) -> None:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                         | getattr(os, "O_CLOEXEC", 0))
        except OSError:  # gone, or no permission: the agent cannot read it either
            self.skipped[UNREADABLE] += 1
            return
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                self.skipped[UNREADABLE] += 1
                return
            data, more = self.head(fd)
        except (OSError, zlib.error):
            self.skipped[UNREADABLE] += 1
            return
        finally:
            os.close(fd)
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = data.decode("utf-16", "replace")
        elif b"\0" in data[:8192]:
            self.skipped[BINARY] += 1
            return
        else:
            text = data.decode("utf-8", "replace")
        if more:
            self.skipped[HEAD_ONLY] += 1
        first, kinds = 0, set()
        for n, line in enumerate(text.split("\n"), 1):
            if n % 4096 == 0:
                self.over()
            if len(line) > MAX_LINE:
                self.skipped[LONG] += 1
                continue
            got = self.kinds(line)
            if got:
                first = first or n
                kinds |= got
        if kinds:
            self.hits.append((self.shown(rel), first, tuple(sorted(kinds))))

    def head(self, fd: int) -> Tuple[bytes, bool]:
        """The first HEAD bytes of the file (decompressed, for gzip), and whether it goes on."""
        data = _read(fd, HEAD + 1)
        if data[:2] != _GZIP:
            return data[:HEAD], len(data) > HEAD
        out = bytearray()
        d = zlib.decompressobj(31)
        pending, used = data, len(data)
        while len(out) <= HEAD:
            self.over()
            if not pending:
                if used >= _GZIP_INPUT:
                    break
                pending = os.read(fd, 1 << 16)
                used += len(pending)
                if not pending:
                    break
            out += d.decompress(pending, HEAD + 1 - len(out))
            pending = d.unconsumed_tail
            if d.eof:  # the next member (BGZF), or the end
                pending = d.unused_data + pending
                if pending[:2] != _GZIP:
                    break
                d = zlib.decompressobj(31)
        return bytes(out[:HEAD]), len(out) > HEAD


def _read(fd: int, n: int) -> bytes:
    parts, got = [], 0
    while got < n:
        b = os.read(fd, min(1 << 16, n - got))
        if not b:
            break
        parts.append(b)
        got += len(b)
    return b"".join(parts)


def scan(cfg: config.Config, project: str, until: Optional[float] = None) -> Result:
    """The project scan of `project` under `cfg`, until the `time.monotonic()` value `until`
    (None: no limit). Never raises: anything it cannot decide is an error."""
    try:
        san = sanitize.subject_sanitizer(cfg)
        if not (san.path_rules or san.id_rules):
            return Result([], {}, 0, True, "", off=True)
        s = _Scan(san, os.path.realpath(project), cfg, until)
        complete = True
        try:
            s.walk()
        except _Stop:
            complete = False
        return Result(s.hits, dict(s.skipped), s.files, complete, "")
    except Exception:  # noqa: BLE001 - fail closed on anything
        return Result([], {}, 0, False, "the project scan could not run")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def found_text(r: Result) -> str:
    """What was found, as kinds and counts: `<SUBJECT> in 3 files, <SAMPLEID> in 1 file name`."""
    files: Counter = Counter()
    names: Counter = Counter()
    for _path, line, kinds in r.hits:
        (files if line else names).update(kinds)
    return ", ".join([f"{k} in {_plural(n, 'file')}" for k, n in sorted(files.items())]
                     + [f"{k} in {_plural(n, 'file name')}" for k, n in sorted(names.items())])


def skipped_text(r: Result) -> str:
    return ", ".join(f"{n} {why}" for why, n in sorted(r.skipped.items()) if n)


def place_problem(cfg: config.Config, project: str) -> str:
    """Why `project` is not a folder to scan (doctor, the note): `/`, the home folder or above
    it, and the rest of launch's rules, or inside or above a protected path; "" when it is."""
    from phiward import paths, wholetool
    real = os.path.realpath(project)
    if paths.ProtectedSet(cfg.all_roots, cfg.patterns).relation(real):
        return "inside or above a protected path"
    return wholetool._project_problem(real, dict(os.environ))
