"""The project scan: subject and sample identifiers in the project's own files and file names,
outside the protected roots (PLAN-PHI-TESTS step 3). Such a file reaches the model with no
gateway: the hook decides by path, and Claude Code sends `CLAUDE.md` and the file list itself.

- The rules: subject identifiers only (`sanitize.subject_sanitizer`): no positions, numbers,
  file or read names, dates, roots or entry names, which a project holds everywhere.
- The walk: one `os.scandir` walk of the project, never through a link: the instruction files
  (names and content) first; then every other name, breadth first; then the other files'
  content, the smallest first.
  It runs no program: git would read the project's `.git/config` (`core.fsmonitor`) and run
  what it names. It skips `wholetool.SKIP_TREES`, the protected and hidden paths, the
  `[sanitize] scan_allow` paths, and more than ENTRY_CAP entries of a folder.
- Each entry's name is checked (and its path, below no folder that held one). A regular file's
  first HEAD bytes are read (HEAD_BUDGET under a time budget; of its decompressed form for gzip
  and BGZF; UTF-16 with a BOM is decoded), unless it is binary (a NUL in its first 8 KiB); a
  line over MAX_LINE is not read. Each skip is counted.
- The speed: the rules' regexes are most of the cost. A `plain` line that no rule matches is
  skipped without the sanitizer's other steps (exact: see `plain`).
- What it says: placeholders, counts and paths as the scan's sanitizer masks them, never the
  text it matched.
"""

import os
import stat
import time
import zlib
import collections
from collections import Counter
from typing import Dict, List, NamedTuple, Optional, Set, Tuple

from phiward import config, sanitize

BUDGET = 2.0  # seconds: launch, `doctor --headless` and the SessionStart note
HEAD = 1 << 20  # bytes of a file's content read (after gzip), by doctor
HEAD_BUDGET = 64 * 1024  # the same, under a time budget: a table's IDs are in its first rows
MAX_LINE = 64 * 1024  # as run.MAX_LINE: a longer line (minified code) is not read
ENTRY_CAP = 10000  # entries read in one folder
SHOWN = 50  # files `doctor --show-paths` lists
FIRST = ("CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".claude")  # sent at the start
# the skip counts, by reason
BINARY, LONG, UNREADABLE = "binary files", "long lines", "unreadable"
HEAD_ONLY = "files read only to their head"
SKIPPED, PROTECTED, ALLOWED, CAPPED = ("skipped folders", "protected", "allowed by [sanitize] "
                                       "scan_allow", "folders over the entry cap")
_GZIP = b"\x1f\x8b"
_GZIP_INPUT = 8  # compressed bytes read at most for one file's head, in heads
_WITHHELD = "<WITHHELD>"  # the kind of a line the sanitizer withholds and no rule names


def plain(line: str) -> bool:
    """Whether masking reads `line` as it is: ASCII, no control character but a tab, no `\\`
    and no `%`. Then `normalize`, `fold` and `unescape` change nothing, so `clean` changes the
    line only where a rule matches it as written (the exact skip of `_Scan.kinds`)."""
    return line.isascii() and "\\" not in line and "%" not in line and \
        line.replace("\t", " ").isprintable()


class Result(NamedTuple):
    hits: List[Tuple[str, int, Tuple[str, ...]]]  # (masked relative path, line or 0, kinds)
    skipped: Dict[str, int]  # counts by reason
    files: int  # regular files whose content was looked at
    complete: bool  # False when the deadline came first
    error: str  # non-empty: the scan could not run (fail closed)
    off: bool = False  # no subject rule: nothing to look for
    # regular files the walk found (all of them, when it finished). No src code reads it; it stays
    # for the timing report in tests/test_projectscan.py, which prints it beside `files`.
    listed: int = 0


def deadline() -> float:
    return time.monotonic() + BUDGET


class _Stop(Exception):
    pass


class _Scan:
    def __init__(self, san: sanitize.Sanitizer, top: str, cfg: config.Config,
                 until: Optional[float]):
        from phiward import claude_settings, hidden, paths, pathid, wholetool
        self.san, self.top, self.until = san, top, until
        self.head_size = HEAD if until is None else HEAD_BUDGET
        self.rules = san.path_rules + san.id_rules
        self.searches = [rx.search for rx, _r in self.rules]
        self.pset = paths.ProtectedSet(list(cfg.all_roots) + hidden.paths(None, cfg, session=True),
                                       cfg.patterns)
        self.fold, self.inside = pathid.fold, paths.INSIDE
        self.allow = [os.path.realpath(a) for a in cfg.sanitize_scan_allow]
        self.skip_tree = lambda p: claude_settings._skipped(p, wholetool.SKIP_TREES)
        # (the place of its top folder in FIRST, masked path, line or 0, kinds)
        self.hits: List[Tuple[int, str, int, Tuple[str, ...]]] = []
        self.skipped: Counter = Counter()
        self.files = 0
        self.found: List[Tuple[int, int, str, str]] = []  # (rank, size, path, rel) of files
        self._top: Optional[List[os.DirEntry]] = None

    def over(self) -> None:
        if self.until is not None and time.monotonic() > self.until:
            raise _Stop()

    def kinds(self, line: str) -> Set[str]:
        """The placeholders of what the scan's rules mask in `line` (empty: nothing)."""
        if not line:
            return set()
        if plain(line) and not any(s(line) for s in self.searches):
            return set()  # exact: no rule matches, and no form of the line differs from it
        norm = sanitize.normalize(line)
        out = self.san.clean(norm)
        if out == norm:
            return set()
        if out == sanitize.WITHHELD:  # a form the masks cannot rewrite (an escape): its rules
            unesc = sanitize.normalize(sanitize.unescape(norm))
            return {r for rx, r in self.rules if rx.search(norm) or rx.search(unesc)} or \
                {_WITHHELD}
        found = set(sanitize._PLACEHOLDER.findall(out))
        return {p for p in found if out.count(p) > norm.count(p)} or {_WITHHELD}

    def listing(self, folder: str) -> List[os.DirEntry]:
        """The folder's entries, at most ENTRY_CAP, sorted by name."""
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
        return sorted(ents, key=lambda e: e.name)

    def walk(self) -> None:
        """The instruction files Claude Code sends at the start (FIRST), names and content,
        before anything else; then every other name, breadth first; then the other files'
        content, the smallest first (a copied table is small or medium; a large head is
        slow)."""
        self.walk_first()
        self.walk_rest()

    def top_entries(self) -> List[os.DirEntry]:
        if self._top is None:
            self._top = self.listing(self.top)
        return self._top

    def walk_first(self) -> None:
        """The instruction files (FIRST), names and content."""
        self.names([e for e in self.top_entries() if e.name in FIRST])
        self.contents()

    def walk_rest(self) -> None:
        """Everything else, names first."""
        self.names([e for e in self.top_entries() if e.name not in FIRST])
        self.contents()

    def names(self, entries: List[os.DirEntry]) -> None:
        queue: collections.deque = collections.deque()
        for e in entries:
            self.over()
            self.entry(e, FIRST.index(e.name) if e.name in FIRST else len(FIRST), False, queue)
        while queue:
            folder, rank, held = queue.popleft()
            for e in self.listing(folder):
                self.over()
                self.entry(e, rank, held, queue)

    def contents(self) -> None:
        self.found.sort(reverse=True)  # read from the end: the smallest first
        while self.found:
            self.over()
            rank, _size, path, rel = self.found.pop()
            self.files += 1
            self.content(path, rel, rank)

    def entry(self, e: os.DirEntry, rank: int, held: bool, queue: "collections.deque") -> None:
        path = e.path
        if any(path == a or path.startswith(a.rstrip("/") + "/") for a in self.allow):
            self.skipped[ALLOWED] += 1
            return
        if self.pset and self.pset._relation_one(self.fold(path)) == self.inside:
            self.skipped[PROTECTED] += 1
            return
        try:
            is_dir = e.is_dir(follow_symlinks=False)
            is_file = e.is_file(follow_symlinks=False)
            size = e.stat(follow_symlinks=False).st_size if is_file else 0
        except OSError:
            self.skipped[UNREADABLE] += 1
            return
        if is_dir and self.skip_tree(path):
            self.skipped[SKIPPED] += 1
            return
        rel = os.path.relpath(path, self.top)
        # a name counts once: its own, or the path once no folder above it held one (a rule
        # that spans a `/`); a file below a folder named after an ID is that folder's finding
        found = self.kinds(e.name) or (set() if held or rel == e.name else self.kinds(rel))
        if found:
            self.hits.append((rank, self.san.clean(rel), 0, tuple(sorted(found))))
        if is_dir:
            queue.append((path, rank, held or bool(found)))
        elif is_file:  # links, sockets and pipes: the name only
            self.found.append((rank, size, path, rel))

    def content(self, path: str, rel: str, rank: int) -> None:
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
            # a CRLF line: masking removes the CR wherever it is, so this changes no finding
            got = self.kinds(line[:-1] if line.endswith("\r") else line)
            if got:
                first = first or n
                kinds |= got
        if kinds:
            self.hits.append((rank, self.san.clean(rel), first, tuple(sorted(kinds))))

    def head(self, fd: int) -> Tuple[bytes, bool]:
        """The file's first `head_size` bytes (decompressed, for gzip), and whether it goes
        on."""
        size = self.head_size
        data = _read(fd, size + 1)
        if data[:2] != _GZIP:
            return data[:size], len(data) > size
        out = bytearray()
        d = zlib.decompressobj(31)
        pending, used = data, len(data)
        while len(out) <= size:
            self.over()
            if not pending:
                if used >= _GZIP_INPUT * size:
                    break
                pending = os.read(fd, 1 << 16)
                used += len(pending)
                if not pending:
                    break
            out += d.decompress(pending, size + 1 - len(out))
            pending = d.unconsumed_tail
            if d.eof:  # the next member (BGZF), or the end
                pending = d.unused_data + pending
                if pending[:2] != _GZIP:
                    break
                d = zlib.decompressobj(31)
        return bytes(out[:size]), len(out) > size


def _read(fd: int, n: int) -> bytes:
    parts, got = [], 0
    while got < n:
        b = os.read(fd, min(1 << 16, n - got))
        if not b:
            break
        parts.append(b)
        got += len(b)
    return b"".join(parts)


def scan(cfg: config.Config, project: str, until: Optional[float] = None,
         part: Optional[str] = None) -> Result:
    """The project scan of `project` under `cfg`, until the `time.monotonic()` value `until`
    (None: no limit). `part`: "first" reads only the instruction files (FIRST), "rest" all the
    others, None both (launch reads the first part of every folder before any rest, under one
    budget). Never raises: anything it cannot decide is an error."""
    try:
        san = sanitize.subject_sanitizer(cfg)
        if not (san.path_rules or san.id_rules):
            return Result([], {}, 0, True, "", off=True)
        s = _Scan(san, os.path.realpath(project), cfg, until)
        walk = {None: s.walk, "first": s.walk_first, "rest": s.walk_rest}[part]
        complete = True
        try:
            walk()
        except _Stop:
            complete = False
        hits = [h[1:] for h in sorted(s.hits)]  # the instruction files first, then by path
        return Result(hits, dict(s.skipped), s.files, complete, "", listed=s.files + len(s.found))
    except Exception:  # noqa: BLE001 - fail closed on anything
        return Result([], {}, 0, False, "the project scan could not run")


def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def found_text(r: Result) -> str:
    """What was found, as kinds and counts: `<SUBJECT> in 3 files, <SAMPLEID> in 1 file name`."""
    files: Counter = Counter()
    names: Counter = Counter()
    for _path, line, kinds in r.hits:
        (files if line else names).update(kinds)
    return ", ".join([f"{k} in {plural(n, 'file')}" for k, n in sorted(files.items())]
                     + [f"{k} in {plural(n, 'file name')}" for k, n in sorted(names.items())])


def skipped_text(r: Result, reasons: Optional[Tuple[str, ...]] = None) -> str:
    return ", ".join(f"{n} {why}" for why, n in sorted(r.skipped.items())
                     if n and (reasons is None or why in reasons))


# the skips that leave part of the project unread (the others are by choice: binary files,
# installed code, protected and allowed paths)
PARTIAL = (HEAD_ONLY, CAPPED, LONG, UNREADABLE)


def place_problem(cfg: config.Config, project: str) -> str:
    """Why `project` is not a folder to scan (doctor, the note): `/`, the home folder or above
    it, and the rest of launch's rules, or inside or above a protected path; "" when it is."""
    from phiward import paths, wholetool
    real = os.path.realpath(project)
    if paths.ProtectedSet(cfg.all_roots, cfg.patterns).relation(real):
        return "inside or above a protected path"
    env = dict(os.environ)
    entry = wholetool._path_entry_inside(real, env)
    return wholetool._project_problem(real, env) or (
        wholetool._path_reason(entry) if entry else "")
