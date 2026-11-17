"""The names of every entry under the protected roots, so the sanitizer masks a file however a
tool spells or wraps its name (`ls` prints bare names, `ls -F` adds `*`, a diff adds `+`).

A name gives two strings to mask: the whole name and its stem (the part before the first dot).
A string is kept when it has 4 or more characters (6 or more when it is only digits) and is not a
stop word. Each one is masked **wherever it appears in a line**, without regard to letter case;
spaces inside a name are part of it. Names under 4 characters are not masked (a stated limit).

The list is built fresh for each gateway run: every folder is listed again, so a new file is
masked at once. Only pure results are kept between runs in the broker (each name's mask
strings, the compiled matcher for a set of names), so nothing stored can go stale or be
poisoned. The walk is bounded: more than `limit` entries raises
InventoryError, and the caller fails closed (a cut-off list would leave names unmasked).
"""

import os
import re
import unicodedata
from typing import Dict, Iterable, List, Optional, Pattern, Sequence, Set

from phiward import pathmatch


class InventoryError(Exception):
    pass


# Terminal escape sequences (CSI, OSC, other ESC forms) and the other control characters except TAB.
_ESCAPES = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-_]?"
                      r"|\x9b[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def normalize(text: str) -> str:
    """Text as masking sees it: escape sequences and control characters removed, an escaped
    space (`\\ `) as a plain space, Unicode in NFKC
    form (full-width and other look-alike letters become plain ones, a decomposed accent is
    composed), format characters (zero-width spaces, direction marks) removed. Lines and entry
    names both go through it, so they meet in the same form."""
    text = _ESCAPES.sub("", text)
    text = text.replace("\\ ", " ")  # `ls -b`, `printf %q`: an escaped space is a space
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def _strings_of(name: str, stop: Set[str]) -> List[str]:
    out = []
    if any(0xDC80 <= ord(c) <= 0xDCFF for c in name):
        # a name that is not valid UTF-8 (Linux): output is decoded with "replace", so mask it
        # in that form too
        name = name.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    name = normalize(name)
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
        alts = [re.escape(ch) + emit(sub) for ch, sub in sorted(node.items()) if ch]
        if not alts:
            return ""
        body = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        if ends:
            return "(?:" + body + ")?"
        return body

    return emit(trie)


_MATCHER: Dict[str, Optional[Pattern[str]]] = {}


def matcher(strings: Iterable[str]) -> Optional[Pattern[str]]:
    words = sorted(set(strings))
    if not words:
        return None
    # compiled once per set of names (compiling is most of the cost for a large root)
    import hashlib
    key = hashlib.sha256("\0".join(words).encode("utf-8", "surrogatepass")).hexdigest()
    got = _MATCHER.get(key)  # one look: another worker may clear it between two
    if got is not None:
        return got
    # A trie regex prefers the longest match at each place, because every optional part is
    # greedy; masking the longest name first keeps a stem from leaving the rest of a name.
    rx = re.compile(_trie_regex(words), re.IGNORECASE)
    _MATCHER.clear()  # keep only the latest set: memory stays one matcher's worth
    _MATCHER[key] = rx
    return rx


def mask(line: str, rx: Optional[Pattern[str]], placeholder: str = "<ENTRY>") -> str:
    if rx is None:
        return line
    return rx.sub(placeholder, line)
