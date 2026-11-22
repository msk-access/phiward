"""The names of every entry under the protected roots, so the sanitizer masks a file however a
tool spells or wraps its name (`ls` prints bare names, `ls -F` adds `*`, a diff adds `+`).

A name gives two strings to mask: the whole name and its stem (the part before the first dot).
A string is kept when it has 4 or more characters (6 or more when it is only digits) and is not a
stop word. Each one is masked **wherever it appears in a line**, without regard to letter case;
spaces inside a name are part of it. Names under 4 characters are not masked (a stated limit).
Lines and names are compared in one form (`normalize`: NFKC, every dash as `-`; and, for the
match only, every decimal digit as ASCII). A string of 5 or more letters and digits, with a letter, is also matched with
its separators (`-`, `_`, `.`, a space) changed or left out: `FAKE-PT-0001` matches
`FAKE_PT_0001`, `FAKE PT 0001` and `FAKEPT0001` (`Matcher`). Shorter strings and digits-only
ones are matched only as written (`20240115` must not match the date `2024-01-15`).

The list is built fresh for each gateway run: every folder is listed again, so a new file is
masked at once. Only pure results are kept between runs in the broker (each name's mask
strings, the compiled matcher for a set of names), so nothing stored can go stale or be
poisoned. The walk is bounded: more than `limit` entries raises
InventoryError, and the caller fails closed (a cut-off list would leave names unmasked).
"""

import bisect
import os
import re
import unicodedata
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Pattern, Sequence, Set, Tuple

from phiward import pathmatch


class InventoryError(Exception):
    pass


# Terminal escape sequences (CSI, OSC, other ESC forms) and the other control characters except TAB.
_ESCAPES = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-_]?"
                      r"|\x9b[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f-\x9f]")


# every dash (Unicode category Pd, as of Unicode 16) and the look-alikes outside it, as `-`.
# Listed, not computed: a scan of every code point costs a tenth of a second at each import (the
# hook imports this). A test checks that the running Python knows no Pd character more
_PD = (0x2D, 0x58A, 0x5BE, 0x1400, 0x1806, 0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015,
       0x2E17, 0x2E1A, 0x2E3A, 0x2E3B, 0x2E40, 0x2E5D, 0x301C, 0x3030, 0x30A0, 0xFE31, 0xFE32,
       0xFE58, 0xFE63, 0xFF0D, 0x10D6E, 0x10EAD)
DASHES = dict.fromkeys(_PD + (0x2212, 0x2043, 0x02D7, 0x30FC), "-")
# the space separators (Unicode category Zs, as of Unicode 16; checked by the same test)
_ZS = (0x20, 0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007,
       0x2008, 0x2009, 0x200A, 0x202F, 0x205F, 0x3000)


def ascii_digits(text: str) -> str:
    """Every Unicode decimal digit as its ASCII digit (`٩` -> `9`)."""
    if text.isascii() or _OTHER_DIGIT.search(text) is None:
        return text
    return _OTHER_DIGIT.sub(lambda m: str(unicodedata.decimal(m.group(0))), text)


_OTHER_DIGIT = re.compile(r"(?![0-9])\d")  # `\d` in a str pattern: every decimal digit (Nd)


def normalize(text: str) -> str:
    """Text as masking sees it: escape sequences and control characters removed, an escaped
    space (`\\ `) as a plain space, Unicode in NFKC
    form (full-width and other look-alike letters become plain ones, a decomposed accent is
    composed), format characters (zero-width spaces, direction marks) removed, every dash as
    `-` (`DASHES`: U+2010, U+2013, U+2212...). Lines and entry names both go through it, so
    they meet in the same form (the sanitizer reads and prints a line `unfolded`, and reads it
    with `fold` for other spellings). Other decimal digits stay as they are here."""
    text = unfolded(text)
    return text if text.isascii() else text.translate(DASHES)


def fold(text: str) -> str:
    """`text` with every dash as `-` and other decimal digits as ASCII digits, one character
    for one (places do not move): how other spellings of a name are read."""
    if text.isascii():
        return text
    return ascii_digits(_DASH.sub("-", text))


_DASH = re.compile("[" + "".join(re.escape(chr(c)) for c in sorted(DASHES) if c != 0x2D) + "]")


def unfolded(text: str) -> str:
    """`normalize` without the fold of dashes: the form lines were read in before other
    spellings were matched (one character for one with `normalize`: places do not move)."""
    text = _ESCAPES.sub("", text)
    text = text.replace("\\ ", " ")  # `ls -b`, `printf %q`: an escaped space is a space
    if text.isascii():
        return text  # NFKC leaves ASCII text as it is
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def _strings_of(name: str, stop: Set[str]) -> List[str]:
    out = []
    if any(0xDC80 <= ord(c) <= 0xDCFF for c in name):
        # a name that is not valid UTF-8 (Linux): output is decoded with "replace", so mask it
        # in that form too
        name = name.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    name = unfolded(name)
    pieces = [p for p in re.split(r"[\x00-\x1f\x7f]", name) if p]
    if len(pieces) > 1:
        # a name with a line break or a tab: tools print it split, escaped (`\n`) or with `?`,
        # so each piece is masked too
        for p in pieces:
            out += _strings_of(p, stop)
    for t in {name, name.split(".")[0]}:
        f = t.casefold()
        if len(t) < 4 or (t.isdigit() and len(t) < 6) or f in stop or not t.strip():
            continue
        out.append(f)
        if t.lower() != f:  # re.IGNORECASE folds simply (it does not turn "ß" into "ss")
            out.append(t.lower())
    return out


# Kept between calls in a long-lived process (the broker):
# only what cannot go stale. Every folder is listed on every call (that is how a new name is
# seen; listing is cheap); what is cached is each name's mask strings, a pure function of the
# name, and the compiled matcher for a set of names. No times, no stamps.
_NAMES: Dict[str, List[str]] = {}
_NAMES_MAX = 500_000  # names; cleared when passed


def _strings_cached(name: str, stop: Set[str], skey: int) -> List[str]:
    k = f"{skey}\0{name}"
    got = _NAMES.get(k)
    if got is None:
        if len(_NAMES) > _NAMES_MAX:
            _NAMES.clear()
        got = _strings_of(name, stop)
        _NAMES[k] = got
    return got


def build(roots: Sequence[str], patterns: Sequence[str], limit: int, stop: Set[str]) -> Set[str]:
    found: Set[str] = set()
    count = 0
    skey = hash(frozenset(stop))
    # start folders resolved: a root or pattern match written through a link is listed as the
    # folder it names
    starts = [os.path.realpath(r) for r in roots if os.path.isdir(r)]
    for p in patterns:
        # a name the pattern's last part leaves open is protected too (`phi_*` matches
        # `phi_Doe Jane`); a literal last part (`runs/*/panel`) is pattern text, not a name
        last = pathmatch.parts(p)[-1:]
        named = bool(last and pathmatch.WILD.search(last[0]))
        for m in pathmatch.matches(p):
            if named:
                found.update(_strings_cached(os.path.basename(m), stop, skey))
            if os.path.isdir(m):
                starts.append(os.path.realpath(m))
    for r in roots:
        if os.path.isfile(r):
            found.update(_strings_cached(os.path.basename(r), stop, skey))
    for start in starts:
        todo = [start]
        while todo:
            d = todo.pop()
            try:
                entries = list(os.scandir(d))
            except OSError:
                continue
            count += len(entries)
            if count > limit:
                raise InventoryError(
                    f"more than {limit} entries under the protected roots; raise "
                    "[sanitize] inventory_limit in the user config, or protect a narrower root")
            for e in entries:
                found.update(_strings_cached(e.name, stop, skey))
                if e.is_dir(follow_symlinks=False):
                    todo.append(e.path)
    return found


def _trie_regex(words: Iterable[str]) -> str:
    """One regex that matches any of `words`, as a trie, so a long list stays fast."""
    trie: Dict[str, dict] = {}
    for w in words:
        node = trie
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = {}

    def emit(node: Dict[str, dict]) -> str:
        ends = "" in node
        subs = [(ch, sub) for ch, sub in sorted(node.items()) if ch]
        if len(subs) > 1 and all(sub == {"": {}} for _ch, sub in subs):
            # one character that ends every word here: one class (`[0-9]` for the last digit
            # of numbered names), so a long list compiles in less time; it matches the same
            alts = ["[" + "".join(re.escape(ch) for ch, _sub in subs) + "]"]
        else:
            alts = [re.escape(ch) + emit(sub) for ch, sub in subs]
        if not alts:
            return ""
        body = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        if ends:
            return "(?:" + body + ")?"
        return body

    return emit(trie)


# what a name's separators may be written as, or left out: `-` (every dash, after `normalize`),
# `_`, `.` and the space separators (Zs). Not `/`, a tab, `<` or `>`
_SEP_RUN = re.compile("[-_." + "".join(chr(c) for c in _ZS) + "]+")


def _glue(line: str) -> str:
    """`line` with its separators left out (`_SEP_RUN`)."""
    if line.isascii():  # the separators an ASCII line can hold: `-`, `_`, `.` and a space
        return line.replace(" ", "").replace("-", "").replace("_", "").replace(".", "")
    return _SEP_RUN.sub("", line)


def _glued(s: str) -> Optional[str]:
    """`s` with its separators left out, when it is matched that way: 5 or more letters and
    digits with a letter, and no separator at either end (such a string is matched as written,
    so its separators stay masked)."""
    if s.isascii():  # the same, faster: an ASCII string's separators are `-`, `_`, `.`, a space
        if s[0] in "-_. " or s[-1] in "-_. ":
            return None
        key = _glue(s)
        if key.isalnum():
            return key if len(key) >= 5 and not key.isdigit() else None
    else:
        key = _SEP_RUN.sub("", s)
        if _SEP_RUN.match(s[0]) or _SEP_RUN.match(s[-1]):
            return None
    alnum = len(key) if key.isalnum() else sum(c.isalnum() for c in key)
    if alnum < 5 or not any(c.isalpha() for c in key):
        return None
    return key


def _all_starts(rx: Pattern[str], text: str) -> List[Tuple[int, int]]:
    """The longest match of `rx` at every place one starts, overlapping ones too: a hit never
    hides a name that starts inside it."""
    out: List[Tuple[int, int]] = []
    m = rx.search(text)
    while m is not None:
        if m.end() > m.start():
            out.append((m.start(), m.end()))
        m = rx.search(text, m.start() + 1)
    return out


def _line_places(line: str) -> Callable[[int], int]:
    """A function from a place in `line` with its separators left out to the same character's
    place in `line` (built per separator run)."""
    in_proj: List[int] = [0]
    in_line: List[int] = [0]
    p = last = 0
    for m in _SEP_RUN.finditer(line):
        p += m.start() - last
        last = m.end()
        in_proj.append(p)
        in_line.append(last)

    def at(i: int) -> int:
        k = bisect.bisect_right(in_proj, i) - 1
        return in_line[k] + i - in_proj[k]
    return at


class Matcher:
    """The entry names of one inventory: every string as written (`finditer`: the masking's own
    steps read a line with it), and for other spellings (`spans`) the strings as `fold` writes
    them that differ, and the long strings (`_glued`) by their separator-free keys, searched in
    the line with its separators left out (a hit maps back to the line from its first to its
    last character, separators inside included)."""

    def __init__(self, literal: Pattern[str], folded: Optional[Pattern[str]],
                 glued: Optional[Pattern[str]]):
        self.literal = literal
        self.folded = folded
        self.glued = glued

    def finditer(self, line: str) -> Iterator["re.Match[str]"]:
        return self.literal.finditer(line)

    def other(self, line: str) -> bool:
        """Whether `line` (with no dash or digit that `fold` changes) may hold a name in another
        spelling than as written: a separator-free key whose text in the line is not a string
        as written, or a folded string (one search of the line with its separators left out)."""
        if self.glued is not None:
            hits = _all_starts(self.glued, _glue(line))
            if hits:
                at = _line_places(line)
                if any(not self.literal.fullmatch(line, at(a), at(b - 1) + 1) for a, b in hits):
                    return True
        return self.folded is not None and self.folded.search(line) is not None

    def spans(self, line: str) -> List[Tuple[int, int]]:
        """Every hit in `line` read as `fold` writes it, as (start, end) in `line` (one
        character for one), in order of start, overlapping ones too."""
        line = fold(line)
        out = _all_starts(self.literal, line)
        if self.folded is not None:
            out += _all_starts(self.folded, line)
        if self.glued is not None:
            hits = _all_starts(self.glued, _glue(line))
            if hits:
                at = _line_places(line)
                out += [(at(a), at(b - 1) + 1) for a, b in hits]
        return sorted(out)

    def search(self, text: str) -> bool:
        return bool(self.spans(text))


_MATCHER: Dict[str, Optional[Matcher]] = {}


def matcher(strings: Iterable[str], stop: Iterable[str] = (),
            inside: Iterable[str] = ()) -> Optional[Matcher]:
    """The matcher for a set of mask strings. A separator-free key equal to a `stop` word, or
    inside one of the `inside` words (the placeholders' words: `SAM_PLE` would match the
    `SAMPLE` of `<SAMPLEID>`), is not matched that way: its string is matched as written only."""
    words = sorted(set(strings))
    if not words:
        return None
    stops = sorted({w.casefold() for w in stop})
    parts = sorted({w.casefold() for w in inside})
    # compiled once per set of names (compiling is most of the cost for a large root)
    import hashlib
    key = hashlib.sha256("\0".join(words + ["\1"] + stops + ["\1"] + parts)
                         .encode("utf-8", "surrogatepass")).hexdigest()
    got = _MATCHER.get(key)  # one look: another worker may clear it between two
    if got is not None:
        return got
    # every piece of 5 or more characters of an `inside` word, so a key is looked up in a set
    pieces = {w[i:j] for w in parts for i in range(len(w)) for j in range(i + 5, len(w) + 1)}
    pieces.update(stops)
    keys: Dict[str, Optional[str]] = {}

    def key_of(w: str) -> Optional[str]:
        if w not in keys:
            k = _glued(w)
            keys[w] = None if k is None or k.casefold() in pieces else k
        return keys[w]

    folded = [fold(w) for w in words]  # as `spans` reads a line
    present = set(folded)
    glued: Set[str] = set()
    for w in folded:
        k = key_of(w)
        stem = w.split(".")[0]
        if k is not None and stem != w and stem in present and key_of(stem) is not None:
            # the stem is matched in other spellings; the whole name only as written
            k = None
        if k is not None:
            glued.add(k)
    # A trie regex prefers the longest match at each place, because every optional part is
    # greedy; masking the longest name first keeps a stem from leaving the rest of a name.
    other = sorted(present - set(words))
    got = Matcher(re.compile(_trie_regex(words), re.IGNORECASE),
                  re.compile(_trie_regex(other), re.IGNORECASE) if other else None,
                  re.compile(_trie_regex(sorted(glued)), re.IGNORECASE) if glued else None)
    _MATCHER.clear()  # keep only the latest set: memory stays one matcher's worth
    _MATCHER[key] = got
    return got
