"""Which paths are protected, and how a written path resolves to real ones.

A path is in one of three relations to the protected set:
- INSIDE: it is a protected root, or below one, or it matches a pattern (or is below a match);
- ABOVE: a protected root or a pattern match sits below it (an ancestor), so a recursive tool
  started there reaches protected data;
- None: neither.

Every check runs on two spellings of a path: the normalized one and the one with symlinks
resolved (`realpath`), so a link into a protected folder counts as protected.
"""

import os
import re
import stat
import sys
import unicodedata
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple

from phiward import pathid, pathmatch

INSIDE = "inside"
ABOVE = "above"

_GLOB_CHARS = re.compile(r"[*?\[]")
# macOS volumes ignore letter case by default: compare folded there (a case-sensitive volume
# only makes the check stricter).
FOLD_CASE = sys.platform == "darwin"


def _fold(p: str) -> str:
    # NFD and case-folded on macOS (pathid.fold): its volumes treat both as equal
    return pathid.fold(p)
_PATH_CHAR = r"[^\s'\"`<>|;&()]"  # a character that can continue a path in free text


def _components(path: str) -> List[str]:
    return [c for c in path.split("/") if c]


class ProtectedSet:
    def __init__(self, roots: Sequence[str], patterns: Sequence[str]):
        rs: List[str] = []
        for r in roots:
            # as written, resolved, and canonical (firmlinks, case, Unicode form: pathid)
            for v in pathid.spellings(r):
                if v not in rs:
                    rs.append(v)
        self.roots = rs
        ps: List[str] = []
        for p in patterns:
            for v in (os.path.normpath(p), _realpath_prefix(p), canon_prefix(p)):
                if v not in ps:
                    ps.append(v)
        self.patterns = ps
        # the roots and patterns whose names are secret (set by the hook; None: all of these).
        # A glob may be listed above a path that is only hidden (a credential), not above one
        # of these
        self.secret: Optional["ProtectedSet"] = None
        # where the glob is decided (`glob_relation`): "confined", "shell" or "file"
        self.mode = "shell"
        self._roots_f = [_fold(r) for r in rs]
        # for `_relation_one`: the folded roots, and every folder above one, as sets
        self._roots_set = set(self._roots_f)
        # a root has at most this many parts: a longer prefix of a path is never one, nor above
        # one (a path of thousands of parts is checked in linear time)
        self._root_depth = max((len(_components(r)) for r in self._roots_f), default=0)
        self._above_set = {"/"} | {"/" + "/".join(_components(r)[:i]) for r in self._roots_f
                                   for i in range(1, len(_components(r)))}
        # the identity of every existing root: a path whose walk meets one
        # of these is inside, whatever its spelling
        self._root_ids = set()
        for r in roots:
            if not os.path.exists(r):  # a dangling link or a missing root: no identity
                continue               # (it must not protect its parent)
            try:
                w = pathid.walk_full(r)
                st = os.stat(r)
            except OSError:
                continue
            if w.complete and w.ids and w.ids[-1] == (st.st_dev, st.st_ino):
                self._root_ids.add(w.ids[-1])
        self._patterns_f = [_fold(p) for p in ps]

    def __bool__(self) -> bool:
        return bool(self.roots or self.patterns)

    # False for shell commands that run in the kernel profile: there the kernel decides about a
    # path the walk cannot resolve, and failing closed would only over-block
    fail_closed = True

    def inside_by_identity(self, path: str) -> bool:
        """Whether the walk of `path` meets a root's identity, or cannot finish (fail closed:
        a path the walk cannot resolve all the way counts as inside)."""
        if not self:
            return False
        try:
            w = pathid.walk_full(path)
        except (OSError, ValueError):
            return self.fail_closed
        if not w.complete:
            return self.fail_closed
        return any(i in self._root_ids for i in w.ids)

    def relation(self, path: str) -> Optional[str]:
        """INSIDE, ABOVE or None for one absolute path (checked as written and as resolved).

        `realpath` runs on the path as written, so `link/..` resolves the way the kernel does;
        `normpath` alone would collapse it lexically to another folder.
        """
        if self.inside_by_identity(path):
            return INSIDE
        found = None
        for spelling in pathid.spellings(path):  # also /.vol, firmlink and case spellings
            rel = self._relation_one(_fold(spelling))
            if rel == INSIDE:
                return INSIDE
            found = found or rel
        return found

    def _relation_one(self, path: str) -> Optional[str]:
        """INSIDE, ABOVE or None for one folded path, as text."""
        pc = _components(path)
        prefix = ""
        for c in pc[:self._root_depth]:
            prefix += "/" + c
            if prefix in self._roots_set:
                return INSIDE
        found = ABOVE if (self._roots_set and len(pc) <= self._root_depth and
                          ("/" + "/".join(pc)) in self._above_set) else None
        for pat in self._patterns_f:
            comps = _components(pat)
            n = min(len(pc), len(comps))
            if all(pathmatch.match_part(comps[i], pc[i]) for i in range(n)):
                if len(pc) >= len(comps):
                    return INSIDE
                found = ABOVE
        return found

    def passes_through(self, path: str) -> bool:
        """Whether the path as written passes through a protected path on its way, before a
        wildcard (`../phi/x/../../repo`): as text, so the answer does not depend on whether
        the names on the way exist.

        The names on the way are a stack, so every prefix of it was once the whole stack, and
        was checked then. A stack deeper than every root and pattern is not checked again: its
        prefixes of those depths were (a path of many parts is checked in linear time)."""
        depth = max([self._root_depth] + [len(_components(p)) for p in self._patterns_f])
        prefixes: List[str] = []  # prefixes[i]: the first i + 1 names, joined
        for c in path.split("/"):
            if not c or c == ".":
                continue
            if _GLOB_CHARS.search(c):
                break
            if c == "..":
                if prefixes:
                    prefixes.pop()
                continue
            if len(prefixes) >= depth:
                prefixes.append("")  # too deep to be a root or a match, nor to start one
                continue
            prefixes.append((prefixes[-1] if prefixes else "") + "/" + c)
            if self._relation_one(_fold(prefixes[-1])) == INSIDE:
                return True
        return False

    def _text_finder(self) -> "_TextFinder":
        finder = getattr(self, "_finder", None)
        if finder is None:
            finder = self._finder = _TextFinder(self.roots, self.patterns)
        return finder

    def text_search(self, text: str) -> Optional[Tuple[int, int]]:
        """A protected path (inside, not above) written in `text`, as (start, end), or None:
        the hook's form (`_TextFinder`)."""
        return self._text_finder().search(text)

    def text_spans(self, text: str) -> List[Tuple[int, int, bool]]:
        """Every protected root or pattern match written in `text`, as (start, end, open), in
        order of start: the sanitizer's form (`_TextFinder`)."""
        return self._text_finder().spans(text)


# ---- protected paths written in free text ------------------------------------------------------

# The hook refuses a command that names a protected path anywhere in its text (code, heredocs,
# strings), and the sanitizer masks one anywhere in a line. A name in free text has no clear end:
# a wildcard may hold spaces, quotes and shell characters (`Zed (B)`, `O'Brien`, `R&D`). So:
# - roots (and patterns with no wildcard) are found as text, and every match counts;
# - a pattern is found by its literal start, then compared one part at a time. A part before the
#   last ends at the next `/`, so it has one possible text. The last part can end at several
#   places before the next `/`, tab or line end; each is tried with the pattern's own glob.
# - the hook takes a match at the first place it can end. A match whose wildcards hold `;`, `&`
#   or `|` (`ls phi_a.txt; echo x_raw` is two commands, `R&D` is one folder) counts only when
#   that path exists on disk; past DISK_CHECKS such checks in one text, it counts (fail closed).
# - the sanitizer takes the longest match: masking too much is the safe side. A last wildcard
#   that meets a quote or a shell character makes the match "open": the name may go on there.
# Every step works inside one part of the text, so a long text is checked in linear time.

DISK_CHECKS = 256
_TEXT_STOP = re.compile(r"[/\t\n]")  # where a part of a path written in free text ends
_NOT_NAME = re.compile(r"[^\w.\-]")  # a character after which a name may have ended
WILDCARD_STOPS = "'\"`<>|;&()"  # where a last wildcard may have ended (an "open" match)
_WILDCARD_STOP = re.compile("[" + re.escape(WILDCARD_STOPS) + "]")
_SEPARATORS = ";&|"


def _fold_full(s: str) -> str:
    """A pattern's text folded where the volume ignores case, as `pathmatch` folds it."""
    return s.casefold() if FOLD_CASE else s


def _fold_text(text: str) -> Tuple[str, Optional[List[int]]]:
    """`text` folded as `pathmatch` folds names (`casefold`) where the volume ignores case, and,
    when a letter folds to more than one character (`İ`, `ß`), the position in `text` of each
    folded character (one more at the end); None when the positions are the same."""
    if not FOLD_CASE:
        return text, None
    folded = text.casefold()
    if len(folded) == len(text):  # a fold never shortens a letter: each folds to one
        return folded, None
    pos: List[int] = []
    for i, c in enumerate(text):
        pos.extend([i] * len(c.casefold()))
    pos.append(len(text))
    return folded, pos


# other spellings of the same path, made plain in this order: a backslash-newline (bash and
# Python join the lines), a JSON-escaped slash (`\\/`), then `//`, `/./`, `/.//` (one `/` for the
# kernel)
_PLAIN_STEPS = ((re.compile(r"\\\n"), ""), (re.compile(r"\\/"), "/"),
                (re.compile(r"/(?:\.?/)+"), "/"))


def plain_spelling(text: str) -> str:
    """`text` with other spellings of the same path made plain (_PLAIN_STEPS)."""
    for rx, repl in _PLAIN_STEPS:
        text = rx.sub(repl, text)
    return text


def plain_spelling_map(text: str) -> Tuple[str, List[int]]:
    """plain_spelling(text), and for each of its characters the index in `text` it comes from
    (a replacement's characters: where the text it replaces starts)."""
    pos = list(range(len(text)))
    for rx, repl in _PLAIN_STEPS:
        out: List[str] = []
        new: List[int] = []
        last = 0
        for m in rx.finditer(text):
            out.append(text[last:m.start()])
            new += pos[last:m.start()] + [pos[m.start()]] * len(repl)
            out.append(repl)
            last = m.end()
        out.append(text[last:])
        text, pos = "".join(out), new + pos[last:]
    return text, pos


def _start_in(pos: Optional[List[int]], x: int) -> int:
    return x if pos is None else pos[x]


def _end_in(pos: Optional[List[int]], x: int) -> int:
    """The end in the text of the folded text up to `x` (the whole letter `x` falls in)."""
    return x if pos is None or x == 0 else pos[x - 1] + 1


class _TextPattern(NamedTuple):
    head: str  # the folded literal start, up to the `/` before the first part with a `*`
    parts: List[List[str]]  # every later part, folded, split at its `*`s
    seps: List[Dict[str, int]]  # for each later part, how many `;`, `&`, `|` it holds itself


class _Disk:
    """The disk checks of one text, at most DISK_CHECKS of them."""

    def __init__(self) -> None:
        self.left = DISK_CHECKS

    def exists(self, path: str) -> bool:
        if self.left <= 0 or "\x00" in path:
            return True  # fail closed
        self.left -= 1
        return os.path.lexists(path)


def _boundary(ft: str, e: int) -> bool:
    """Whether a name may end at `e`: the text's end, a `/`, or a character no name goes on with."""
    return e >= len(ft) or ft[e] == "/" or _NOT_NAME.match(ft, e) is not None


def _prefix_end(segs: List[str], ft: str, pos: int, lim: int) -> int:
    """Where the part's text before its last `*` can end at the earliest, for a part written
    from `pos` and ending by `lim`, or -1. The first piece must start at `pos`; each piece after
    it is taken where it first occurs: no other choice ends earlier."""
    q = pos + len(segs[0])
    if q > lim or not ft.startswith(segs[0], pos):
        return -1
    for seg in segs[1:-1]:
        j = ft.find(seg, q, lim)
        if j < 0:
            return -1
        q = j + len(seg)
    return q


def _matches_to(segs: List[str], ft: str, q: int, e: int) -> bool:
    """Whether the part's text, with its earliest prefix end `q`, matches when it ends at `e`."""
    if len(segs) == 1:
        return e == q
    last = segs[-1]
    return e - len(last) >= q and ft.startswith(last, e - len(last))


def _end_places(segs: List[str], ft: str, q: int, lim: int) -> Iterable[int]:
    """Every place, first to last, where the last part matches and a name may end."""
    if len(segs) == 1:
        if _boundary(ft, q):
            yield q
        return
    last = segs[-1]
    if not last:  # the part ends with `*`: each place a name may end
        e = q
        while e <= lim:
            m = _NOT_NAME.search(ft, e, lim)
            e = m.start() if m else lim
            yield e
            e += 1
        return
    j = ft.find(last, q, lim)
    while j >= 0:
        if _boundary(ft, j + len(last)):
            yield j + len(last)
        j = ft.find(last, j + 1, lim)


def _longest(segs: List[str], ft: str, q: int, lim: int) -> Optional[Tuple[int, bool]]:
    """The last place the last part matches and a name may end, and whether the match is open."""
    if len(segs) == 1:
        return (q, False) if _boundary(ft, q) else None
    last = segs[-1]
    if not last:
        m = _WILDCARD_STOP.search(ft, q, lim)
        return (m.start(), True) if m else (lim, False)
    j = ft.rfind(last, q, lim)
    while j >= 0:
        if _boundary(ft, j + len(last)):
            return j + len(last), False
        j = ft.rfind(last, q, j + len(last) - 1)
    return None


def _first_separator(text: str, pos: int, lim: int, own: Dict[str, int]) -> int:
    """Where, from `pos`, the text holds more `;`, `&` or `|` than the part itself (so a
    wildcard holds one), or `lim` when it does not before `lim`."""
    first = lim
    for c in _SEPARATORS:
        j = pos - 1
        for _ in range(own.get(c, 0) + 1):
            j = text.find(c, j + 1, lim)
            if j < 0:
                break
        if j >= 0:
            first = min(first, j)
    return first


class _TextFinder:
    def __init__(self, roots: Sequence[str], patterns: Sequence[str]):
        literals = list(roots)
        self.patterns: List[_TextPattern] = []
        for p in patterns:
            comps = pathmatch.parts(p)
            first = next((k for k, c in enumerate(comps) if "*" in c), None)
            if first is None:
                literals.append("/" + "/".join(comps))
                continue
            later = comps[first:]
            self.patterns.append(_TextPattern(
                _fold_full("/" + "".join(c + "/" for c in comps[:first])),
                [_fold_full(c).split("*") for c in later],
                [{s: c.count(s) for s in _SEPARATORS} for c in later]))
        # every root also in the Unicode form the sanitizer puts lines in (NFKC), and NFC and
        # NFD: a root written in another form is found all the same; longer first, so a root
        # inside another one is matched whole
        # (folded as names are, `ß` as `ss`, and found in the folded text)
        forms: List[str] = []
        for r in literals:
            for f in (r, unicodedata.normalize("NFKC", r), unicodedata.normalize("NFC", r),
                      unicodedata.normalize("NFD", r)):
                f = _fold_full(f)
                if f not in forms:
                    forms.append(f)
        forms.sort(key=len, reverse=True)
        self.roots_rx = re.compile(
            "|".join(re.escape(f) + r"(?=$|/|[^\w.\-])" for f in forms)) if forms else None

    def search(self, text: str) -> Optional[Tuple[int, int]]:
        found = self._search(text)
        plain = plain_spelling(text)
        if found is None and plain != text:
            found = self._search(plain)  # the hook needs no positions
        return found

    def _search(self, text: str) -> Optional[Tuple[int, int]]:
        ft, at = _fold_text(text)
        if self.roots_rx is not None:
            m = self.roots_rx.search(ft)
            if m is not None:
                return _start_in(at, m.start()), _end_in(at, m.end())
        if not self.patterns:
            return None
        disk = _Disk()
        for pat in self.patterns:
            a = ft.find(pat.head)
            while a >= 0:
                e = self._walk(pat, text, ft, at, a, disk)
                if e is not None:
                    return _start_in(at, a), _end_in(at, e[0])
                a = ft.find(pat.head, a + 1)
        return None

    def spans(self, text: str) -> List[Tuple[int, int, bool]]:
        out: List[Tuple[int, int, bool]] = []
        ft, at = _fold_text(text)
        if self.roots_rx is not None:
            m = self.roots_rx.search(ft)
            while m is not None:
                out.append((_start_in(at, m.start()), _end_in(at, m.end()), False))
                m = self.roots_rx.search(ft, m.start() + 1)
        if self.patterns:
            for pat in self.patterns:
                a = ft.find(pat.head)
                while a >= 0:
                    e = self._walk(pat, text, ft, at, a, None)
                    if e is not None:
                        out.append((_start_in(at, a), _end_in(at, e[0]), e[1]))
                    a = ft.find(pat.head, a + 1)
        out.sort()
        return out

    @staticmethod
    def _walk(pat: _TextPattern, text: str, ft: str, at: Optional[List[int]], a: int,
              disk: Optional[_Disk]) -> Optional[Tuple[int, bool]]:
        """The end (in `ft`) of the pattern's match whose literal start is at `a` (in `ft`, the
        folded text; `at` maps it back to `text`), and whether it is open: the first end that
        counts for the hook (`disk` given), the longest for the sanitizer."""
        pos = a + len(pat.head)
        n = len(ft)
        last = len(pat.parts) - 1
        for k, segs in enumerate(pat.parts):
            stop = _TEXT_STOP.search(ft, pos)
            lim = stop.start() if stop else n
            q = _prefix_end(segs, ft, pos, lim)
            if q < 0:
                return None
            if k < last:  # a part before the last ends at the next `/`
                if lim == n or ft[lim] != "/" or not _matches_to(segs, ft, q, lim):
                    return None
                if disk is not None and _first_separator(ft, pos, lim, pat.seps[k]) < lim \
                        and not disk.exists(text[_start_in(at, a):_end_in(at, lim)]):
                    return None
                pos = lim + 1
                continue
            if disk is None:
                return _longest(segs, ft, q, lim)
            sep = _first_separator(ft, pos, lim, pat.seps[k])
            for e in _end_places(segs, ft, q, lim):
                if e <= sep or disk.exists(text[_start_in(at, a):_end_in(at, e)]):
                    return e, False
            return None
        return None


def canon_prefix(pattern: str) -> str:
    """The pattern with its literal leading part in canonical spelling (pathid)."""
    comps = pattern.split("/")
    for i, c in enumerate(comps):
        if _GLOB_CHARS.search(c):
            head = "/".join(comps[:i]) or "/"
            return os.path.join(pathid.canon(head), "/".join(comps[i:]))
    return pathid.canon(pattern)


def _realpath_prefix(pattern: str) -> str:
    """The pattern with the symlinks of its literal leading part resolved."""
    comps = pattern.split("/")
    for i, c in enumerate(comps):
        if _GLOB_CHARS.search(c):
            head = "/".join(comps[:i]) or "/"
            rest = "/".join(comps[i:])
            return os.path.join(os.path.realpath(head), rest)
    return os.path.realpath(pattern)


def expand_braces(word: str, limit: int = 256) -> List[str]:
    """Bash brace expansion of an unquoted word: `a{b,c}d`, `{1..3}`, `{a..c}`, nested.

    Raises ValueError when the expansion would give more than `limit` words.
    """
    out = _braces(word)
    if len(out) > limit:
        raise ValueError("too many brace expansions")
    return out


def _braces(word: str) -> List[str]:
    depth = 0
    start = -1
    for i, ch in enumerate(word):
        if ch == "\\":
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0:
                inner = word[start + 1:i]
                options = _split_top(inner)
                if options is None:
                    seq = _sequence(inner)
                    if seq is None:
                        # not a brace expression: keep "{...}" literally, expand the rest
                        return [word[:i + 1] + w for w in _braces(word[i + 1:])] if start == 0 \
                            else [word[:start] + "{" + w for w in _braces(word[start + 1:])]
                    options = seq
                pre, post = word[:start], word[i + 1:]
                result = []
                for opt in options:
                    for o in _braces(opt):
                        for p in _braces(post):
                            result.append(pre + o + p)
                return result
    return [word]


def _split_top(inner: str) -> Optional[List[str]]:
    parts, depth, cur = [], 0, ""
    for ch in inner:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if not parts:
        return None
    parts.append(cur)
    return parts


def _sequence(inner: str) -> Optional[List[str]]:
    m = re.fullmatch(r"(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?", inner)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        step = abs(int(m.group(3) or 1)) or 1
        rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        if len(rng) > 256:
            raise ValueError("too many brace expansions")
        return [str(x) for x in rng]
    m = re.fullmatch(r"([A-Za-z])\.\.([A-Za-z])", inner)
    if m:
        a, b = ord(m.group(1)), ord(m.group(2))
        rng = range(a, b + 1) if a <= b else range(a, b - 1, -1)
        return [chr(x) for x in rng]
    return None


def candidates(word: str, bases: Iterable[str]) -> List[str]:
    """The absolute paths a written path can mean: as written when absolute, else joined to
    each base folder (a glob base stays a glob base). A glob is not expanded here."""
    out: List[str] = []
    seen = set()
    for base in ([None] if word.startswith("/") else list(bases)):
        full = word if base is None else os.path.join(base, word)
        if isinstance(base, GlobBase):
            full = GlobBase(full)
        # a glob base and a plain one can spell the same text: keep both kinds
        key = (type(full), str(full))
        if key not in seen:
            seen.add(key)
            out.append(full)
    return out


class GlobBase(str):
    """A `cd` target that is a glob: a base folder that is a pattern, so a relative word joined
    to it is judged as one longer glob."""


# the shell and the file tools' globs beyond `* ? [`: an extglob or zsh group (`@(a)`, `!(a)`,
# `(a|b)`), read as `*`
_GROUP = re.compile(r"[@!+*?]?\([^()]*\)")


_GROUP_DEPTH = 32  # groups nested deeper are refused, not read


def _ungroup(form: str) -> str:
    """Every group as `*`, the innermost first, until none is left (`@(@(a)|b)`); a group
    that holds `/` (zsh `(a/b|c)`) names more than one level, so it is refused."""
    for _ in range(_GROUP_DEPTH):
        if any("/" in m.group(0) for m in _GROUP.finditer(form)):
            raise GlobUnchecked("A group here spans folders (`(a/b|c)`), which the guard "
                                "cannot check; write each path out.")
        flat = _GROUP.sub("*", form)
        if flat == form:
            return flat
        form = flat
    raise GlobUnchecked("Groups here are nested deeper than the guard reads; write each path "
                        "out.")


def loose_variants(word: str) -> List[str]:
    """The spellings a file tool's glob can mean, each a plain glob: braces expanded,
    backslash escapes dropped, groups read as `*` (a superset of what the tool matches)."""
    try:
        forms = expand_braces(word)
    except ValueError:
        raise GlobUnchecked("A brace group here expands to more patterns than the guard "
                            "checks; write each path out.") from None
    return [_ungroup(re.sub(r"\\(.)", r"\1", f)) for f in forms]


def word_relation(word: str, bases: Iterable[str], pset: "ProtectedSet",
                  glob: bool = False) -> Optional[str]:
    """INSIDE, ABOVE or None for a written path (relative ones joined to each base): a path
    whose written form passes through a protected path is INSIDE at once; a glob is decided by
    `glob_relation`, never by expanding it."""
    rel: Optional[str] = None
    for full in candidates(word, bases):
        if pset.passes_through(full):
            return INSIDE
        as_glob = (glob or isinstance(full, GlobBase)) and bool(_GLOB_CHARS.search(full))
        rel = worst(rel, glob_relation(full, pset) if as_glob else pset.relation(full))
        if rel == INSIDE:
            break
    return rel


class GlobUnchecked(Exception):
    """A glob the guard cannot check (too many entries, `..` after a wildcard outside the
    sandbox, a group across folders): the call is refused with this reason, never guessed or
    cut short."""


GLOB_BUDGET = 200_000  # names the link scan may list for one glob, then GlobUnchecked
# a shell bracket expression, with POSIX classes inside: `[!P]`, `[^x]`, `[[:alpha:]]`, `[]a]`
_BRACKET = re.compile(r"\[[!^]?\]?(?:\[:[a-z]+:\]|[^\]])*\]")


def _loose(part: str) -> str:
    """A pattern that matches at least what the shell matches, folded: a bracket expression
    and `?` become `*` (fnmatch and the shell read classes differently, and one character in
    one Unicode form can be two in another)."""
    return _fold(_BRACKET.sub("*", part).replace("?", "*"))


def _ends(part: str) -> Tuple[str, str]:
    """The literal text before the first wildcard and after the last one (loose and folded);
    an unclosed `[` gives ("", ""), which meets anything."""
    p = _loose(part)
    first, last = p.find("*"), p.rfind("*")
    if first < 0:
        return "", ""
    return p[:first], p[last + 1:]


def _match(pattern: str, name: str) -> bool:
    """A glob part against an entry name, loose and folded on both sides."""
    return pathmatch.match_part(_loose(pattern), _fold(name))


def _may_meet(a: str, b: str) -> bool:
    """Whether two path parts (globs or names) can name the same entry. Errs toward yes."""
    if a == "**" or b == "**":
        return True
    wild_a, wild_b = bool(_GLOB_CHARS.search(a)), bool(_GLOB_CHARS.search(b))
    if not wild_a and not wild_b:
        return _fold(a) == _fold(b)
    if not wild_a:
        return _match(b, a)
    if not wild_b:
        return _match(a, b)
    (pa, sa), (pb, sb) = _ends(a), _ends(b)
    return (pa.startswith(pb) or pb.startswith(pa)) and (sa.endswith(sb) or sb.endswith(sa))


def _names_into(rest: List[str], below: List[str], dots: bool) -> Optional[str]:
    """Whether glob parts `rest` can name the path `below` (or something in it: INSIDE), only
    a folder above it (ABOVE), or neither (None). `**` may stand for any depth. Without
    `dots`, a part that does not start with `.` does not name a dot entry (the shell's rule)."""
    if not below:
        return INSIDE
    if not rest:
        return ABOVE
    if rest[0] == "**":
        return INSIDE
    if not dots and below[0].startswith(".") and not rest[0].startswith("."):
        return None
    if _may_meet(rest[0], below[0]):
        return _names_into(rest[1:], below[1:], dots)
    return None


def _lexical(comps: List[str]) -> List[str]:
    """Path parts with `.` dropped and `..` taking back the part before it, as text."""
    out: List[str] = []
    for c in comps:
        if c == "..":
            if out:
                out.pop()
        elif c != ".":
            out.append(c)
    return out


def glob_relation(pattern: str, pset: "ProtectedSet") -> Optional[str]:
    """INSIDE, ABOVE or None for an absolute glob, in the place `pset.mode` names
    (docs/threat-model.md, "A wildcard gets one verdict"):

    - "confined", a shell in Claude Code's sandbox: from the pattern alone, against the roots
      and patterns (`pset.secret`), with the shell's own dot rule; `..` is taken as text. The
      disk is not listed and links are not followed: the kernel stops a read of a protected
      path or credential.
    - "shell" (no sandbox) and "file" (a file tool): the same against the roots, patterns and
      the hidden list, `*` naming dot entries too; then `_link_scan` finds links the agent
      made. `..` after a wildcard is refused (a link can take it anywhere).

    The answer never depends on what a protected folder holds: no folder that is, or can lead
    the glob into, a protected path is listed."""
    if not pattern.startswith("/"):
        raise ValueError("glob_relation takes an absolute glob")
    confined = pset.mode == "confined"
    comps = [c for c in pattern.split("/") if c and c != "."]
    first = next((i for i, c in enumerate(comps) if _GLOB_CHARS.search(c)), len(comps))
    if ".." in comps[first:]:
        if not confined:
            raise GlobUnchecked("A wildcard followed by `..` cannot be checked; write the path "
                                "without the `..`.")
        # as text, over the whole path: a `..` may take back the parts before the wildcard
        comps = _lexical(comps)
        first = next((i for i, c in enumerate(comps) if _GLOB_CHARS.search(c)), len(comps))
    if first >= len(comps) or not any(_GLOB_CHARS.search(c) for c in comps[first:]):
        return pset.relation("/" + "/".join(comps))
    rel_up = _as_dotdot(comps, first, pset) if pset.mode == "shell" else None
    if rel_up == INSIDE:
        return INSIDE
    prefix, rest = "/" + "/".join(comps[:first]), comps[first:]
    dots = not confined
    folder = os.path.realpath(prefix)
    rel = worst(rel_up, _static(folder, rest, pset, dots, pset.relation(folder)))
    if rel == INSIDE or confined:
        return rel
    return worst(rel, _link_scan(folder, rest, pset, dots))


def _as_dotdot(comps: List[str], first: int, pset: "ProtectedSet") -> Optional[str]:
    """Bash before 5.2 lets a dot glob (`.*`, `.?`) match `..`: the relation of the glob with
    its first such part read as `..` (a `..` after an earlier wildcard is GlobUnchecked)."""
    for i in range(first, len(comps)):
        if comps[i].startswith(".") and _GLOB_CHARS.search(comps[i]) and _match(comps[i], ".."):
            return glob_relation("/" + "/".join(comps[:i] + [".."] + comps[i + 1:]), pset)
    return None


def _static(folder: str, rest: List[str], pset: "ProtectedSet", dots: bool,
            rel: Optional[str]) -> Optional[str]:
    """From the resolved folder `folder` (its relation `rel`), can the glob parts `rest` name
    a protected path (INSIDE) or only a folder above one (ABOVE)? From the patterns alone. In
    the sandbox only the roots and patterns count (`pset.secret`); elsewhere the hidden list
    too."""
    if rel == INSIDE:
        return INSIDE
    if rel != ABOVE:
        return None
    targets = pset.secret if (pset.mode == "confined" and pset.secret is not None) else pset
    found: Optional[str] = None
    for spelling in pathid.spellings(folder):
        fc = _components(_fold(spelling))
        for target in targets._roots_f + targets._patterns_f:
            tc = _components(target)
            if len(tc) < len(fc) or not all(_may_meet(t, f) for t, f in zip(tc, fc)):
                continue
            got = _names_into(rest, tc[len(fc):], dots)
            if got == INSIDE:
                return INSIDE
            found = found or got
    return found


class _Entry(NamedTuple):
    """A folder entry as the link scan needs it: its path, whether it is a link or a folder,
    and its identity (device, inode)."""
    path: str
    link: bool
    folder: bool
    ident: Tuple[int, int]


_Listing = Optional[Tuple[int, List["os.DirEntry[str]"]]]  # (the folder's device, entries)


def _entries(folder: str, part: str, dots: bool,
             listings: Dict[str, _Listing]) -> List[_Entry]:
    """The entries of `folder` that the glob part `part` names. A literal part is looked up
    by name (the file system's own case and Unicode rules; the folder need not be listable);
    a wildcard part lists the folder, once per scan (`listings`); a folder that cannot be
    listed names nothing, as in the shell."""
    out: List[_Entry] = []
    if part != "**" and not _GLOB_CHARS.search(part):
        path = os.path.join(folder, part)
        try:
            st = os.lstat(path)
        except OSError:
            return out
        out.append(_Entry(path, stat.S_ISLNK(st.st_mode), stat.S_ISDIR(st.st_mode),
                          (st.st_dev, st.st_ino)))
        return out
    if folder not in listings:
        try:
            dev = os.stat(folder).st_dev
            with os.scandir(folder) as it:
                listings[folder] = (dev, list(it))
        except OSError:
            listings[folder] = None
    got = listings[folder]
    if got is None:
        return out
    dev, listing = got
    for e in listing:
        if not dots and e.name.startswith(".") and not part.startswith("."):
            continue
        if part != "**" and not _match(part, e.name):
            continue
        try:
            link, sub = e.is_symlink(), e.is_dir(follow_symlinks=False)
            # a folder may be a mount (another device): stat it; a file's device is the
            # folder's (a hard link stays on one device)
            if sub:
                st = e.stat(follow_symlinks=False)
                ident = (st.st_dev, st.st_ino)
            else:
                ident = (dev, e.inode())
        except OSError:
            continue  # gone since the listing: names nothing now
        out.append(_Entry(e.path, link, sub, ident))
    return out


def _link_scan(top: str, rest: List[str], pset: "ProtectedSet", dots: bool) -> Optional[str]:
    """Outside the sandbox: walk where the glob can go, as the shell would, and check every
    entry a glob part names: a link's target (`_target_relation`, then the rest of the glob
    from there; a link to a folder is followed, once per real folder) and the identity of
    folders and files (a root mounted or linked a second time). Each folder is listed once;
    past GLOB_BUDGET names listed and entries looked at, GlobUnchecked."""
    todo = [(top, rest)]
    seen = {(top, len(rest))}
    listings: Dict[str, _Listing] = {}
    count = 0
    found: Optional[str] = None
    ids: Dict[str, bool] = {}  # folder -> it or a folder above it is a root (identity)

    while todo:
        folder, parts = todo.pop()
        if not parts:
            continue
        part, after = parts[0], parts[1:]
        if part == "**":
            todo.append((folder, after))  # `**` names no folder too
        new = folder not in listings
        entries = _entries(folder, part, dots, listings)
        # the names a folder lists, the first time it is listed; on every later pass, the
        # entries that pass looks at (a glob of many `**` parts passes a folder many times)
        got = listings.get(folder)
        count += len(got[1]) if new and got else len(entries) + 1
        if count > GLOB_BUDGET:
            raise GlobUnchecked("A wildcard here names more entries than the guard checks, so "
                                "it is refused. Name fewer files, or a folder deeper down.")
        nxt = parts if part == "**" else after  # `**` goes on below
        for e in entries:
            if e.ident in pset._root_ids:
                return INSIDE  # a root under another name (a mount, a hard link)
            if e.link:
                real = os.path.realpath(e.path)
                rel = _target_relation(real, pset, ids)
                if rel != INSIDE and nxt and os.path.isdir(real):
                    rel = _static(real, nxt, pset, dots, rel)
                    if rel != INSIDE and (real, len(nxt)) not in seen:
                        seen.add((real, len(nxt)))
                        todo.append((real, nxt))
                if rel == INSIDE:
                    return INSIDE
                found = found or rel
            elif e.folder and nxt and (e.path, len(nxt)) not in seen:
                seen.add((e.path, len(nxt)))
                todo.append((e.path, nxt))
    return found


def _target_relation(real: str, pset: "ProtectedSet", ids: Dict[str, bool]) -> Optional[str]:
    """The relation of a resolved link target, quickly: by its text (folded, against every
    spelling of the roots and patterns), then by the identity of it and each folder above it
    (cached for one scan). The text check covers case, Unicode form and firmlinks; the
    identity check covers a root reached by another path (a bind mount)."""
    rel = pset._relation_one(_fold(real))
    if rel == INSIDE:
        return INSIDE
    if real.startswith("/.vol/"):  # macOS: a path by volume and inode id
        return pset.relation(real)
    path = real
    chain: List[str] = []
    while True:
        if path in ids:
            hit = ids[path]
            break
        try:
            st = os.stat(path)
            hit = (st.st_dev, st.st_ino) in pset._root_ids
        except OSError:
            hit = False
        chain.append(path)
        if hit or path == "/":
            break
        path = os.path.dirname(path)
    for c in chain:
        ids[c] = ids.get(c, False) or hit
    return INSIDE if hit else rel


def worst(rel_a: Optional[str], rel_b: Optional[str]) -> Optional[str]:
    order = {None: 0, ABOVE: 1, INSIDE: 2}
    return rel_a if order[rel_a] >= order[rel_b] else rel_b


