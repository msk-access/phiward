"""One meaning for a protected pattern, used by every part.

A pattern is an absolute path whose parts may hold `*`: any run of characters inside one path
part (never `/`), matching a name that starts with a dot too. Nothing else is a wildcard: `?` and
`[...]` are refused, and so is any character outside printable ASCII (Seatbelt matches
case-folded NFD bytes, Python matches code points, and the two disagree on classes, `?` and
non-ASCII names). With only `*` and ASCII literals, every back-end agrees by construction.
On macOS, letter case is folded (its volumes ignore case by default).

- `problem(pattern)`: why a pattern cannot be used, with a suggested rewrite, or None;
- `match_path(pattern, path)`: whether `path` is a match (not below one);
- `matches(pattern)`: the paths on disk that match, dot-names included, never through a link;
- `regex(pattern)`: an anchored-at-start regular expression for the same set, in the syntax that
  both Python `re` and Seatbelt accept.
"""

import os
import re
import sys
from fnmatch import fnmatchcase
from typing import List, Optional

FOLD_CASE = sys.platform == "darwin"
WILD = re.compile(r"[*?\[]")


def fold(p: str) -> str:
    return p.casefold() if FOLD_CASE else p


def parts(path: str) -> List[str]:
    return [c for c in path.split("/") if c]


def match_part(pattern_part: str, name: str) -> bool:
    return fnmatchcase(fold(name), fold(pattern_part))


def match_path(pattern: str, path: str) -> bool:
    pp, xp = parts(pattern), parts(path)
    return len(pp) == len(xp) and all(match_part(a, b) for a, b in zip(pp, xp))


_LITERAL = re.compile(r"[ -~]")  # printable ASCII, space included


def problem(pattern: str) -> Optional[str]:
    """Why a pattern cannot be used (with a suggested rewrite), or None."""
    if any(p in ("", ".", "..") for p in pattern.split("/")[1:]):
        # the matcher and the kernel would read such a part differently
        return "a pattern may not hold empty, `.` or `..` parts; write the folder as it is"
    for ch in pattern:
        if ch in "?[]":
            return ("only `*` is a wildcard (`?` and `[...]` are not accepted, so that every part "
                    "of phiward reads the pattern the same way); use `*` there, or list the "
                    "folders as roots")
        if ch == "\\":
            return "a backslash is not accepted in a pattern"
        if not _LITERAL.fullmatch(ch):
            return ("a pattern may hold only printable ASCII; give a folder with other characters "
                    "in its name as a root")
    return None


def _part_regex(part: str) -> str:
    return "".join("[^/]*" if ch == "*" else ("\\" + ch if ch in ".^$+(){}|\\" else ch)
                   for ch in part)


def regex(pattern: str) -> str:
    """`^` and the pattern, as a regex for whole paths (add your own end)."""
    return "^/" + "/".join(_part_regex(p) for p in parts(pattern))


def matches(pattern: str) -> List[str]:
    """Paths on disk that match, dot-names included. A folder on the way is entered only when it
    is a real folder (not a link), so a match is never reached through a link the agent put
    there. The literal leading part is taken as written."""
    pp = parts(pattern)
    out = ["/"]
    for k, part in enumerate(pp):
        nxt: List[str] = []
        for base in out:
            if not WILD.search(part):
                cand = os.path.join(base, part)
                if os.path.lexists(cand):
                    nxt.append(cand)
                continue
            try:
                names = os.listdir(base)
            except OSError:
                continue
            nxt += [os.path.join(base, n) for n in names if match_part(part, n)]
        if k < len(pp) - 1:  # enter only real folders, except along the literal prefix
            literal = not any(WILD.search(p) for p in pp[:k + 1])
            nxt = [p for p in nxt if os.path.isdir(p) and (literal or not os.path.islink(p))]
        out = nxt
    return sorted(out)
