"""A small TOML reader for the config files (Python 3.9 and 3.10 have no tomllib).

It reads a subset: comments, `[table]` and `[a.b]` headers, `key = value` lines, and values that
are strings (basic or literal), integers, booleans, or arrays of these (over several lines too).
It uses the same parser on every Python version, so a file reads the same everywhere. Anything
outside the subset raises `TomlError`; the caller then fails closed.
"""

import re
from typing import Any, Dict, List, Tuple


class TomlError(ValueError):
    pass


_KEY = re.compile(r"[A-Za-z0-9_-]+")
_INT = re.compile(r"[+-]?(0|[1-9][0-9_]*)")
_ESC = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}


def loads(text: str) -> Dict[str, Any]:
    root: Dict[str, Any] = {}
    table = root
    seen_tables = set()
    p = _Parser(text)
    while True:
        p.skip_blank_lines()
        if p.at_end():
            return root
        line_no = p.line
        if p.peek() == "[":
            p.pos += 1
            if p.peek() == "[":
                raise TomlError(f"line {line_no}: arrays of tables are not supported")
            names = p.dotted_key()
            p.skip_ws()
            p.expect("]")
            p.end_of_line()
            if tuple(names) in seen_tables:
                raise TomlError(f"line {line_no}: table [{'.'.join(names)}] appears twice")
            seen_tables.add(tuple(names))
            table = root
            for n in names:
                nxt = table.setdefault(n, {})
                if not isinstance(nxt, dict):
                    raise TomlError(f"line {line_no}: '{n}' is not a table")
                table = nxt
            continue
        names = p.dotted_key()
        p.skip_ws()
        p.expect("=")
        p.skip_ws()
        value = p.value()
        p.end_of_line()
        target = table
        for n in names[:-1]:
            target = target.setdefault(n, {})
            if not isinstance(target, dict):
                raise TomlError(f"line {line_no}: '{n}' is not a table")
        if names[-1] in target:
            raise TomlError(f"line {line_no}: key '{names[-1]}' appears twice")
        target[names[-1]] = value


class _Parser:
    def __init__(self, text: str):
        self.s = text.replace("\r\n", "\n")
        self.pos = 0

    @property
    def line(self) -> int:
        return self.s.count("\n", 0, self.pos) + 1

    def at_end(self) -> bool:
        return self.pos >= len(self.s)

    def peek(self) -> str:
        return self.s[self.pos] if self.pos < len(self.s) else ""

    def expect(self, ch: str) -> None:
        if self.peek() != ch:
            raise TomlError(f"line {self.line}: expected '{ch}'")
        self.pos += 1

    def skip_ws(self) -> None:
        while self.peek() in (" ", "\t") and self.peek():
            self.pos += 1

    def skip_comment(self) -> None:
        if self.peek() == "#":
            while self.peek() and self.peek() != "\n":
                self.pos += 1

    def skip_blank_lines(self) -> None:
        while not self.at_end():
            self.skip_ws()
            self.skip_comment()
            if self.peek() == "\n":
                self.pos += 1
            else:
                return

    def end_of_line(self) -> None:
        self.skip_ws()
        self.skip_comment()
        if self.peek() not in ("\n", ""):
            raise TomlError(f"line {self.line}: unexpected text after the value")
        if self.peek() == "\n":
            self.pos += 1

    def key(self) -> str:
        if self.peek() in ('"', "'"):
            return self.string()
        m = _KEY.match(self.s, self.pos)
        if not m:
            raise TomlError(f"line {self.line}: expected a key")
        self.pos = m.end()
        return m.group(0)

    def dotted_key(self) -> List[str]:
        self.skip_ws()
        names = [self.key()]
        while True:
            self.skip_ws()
            if self.peek() != ".":
                return names
            self.pos += 1
            self.skip_ws()
            names.append(self.key())

    def string(self) -> str:
        q = self.peek()
        if self.s.startswith(q * 3, self.pos):
            raise TomlError(f"line {self.line}: multi-line strings are not supported")
        self.pos += 1
        out = []
        while True:
            ch = self.peek()
            if ch in ("", "\n"):
                raise TomlError(f"line {self.line}: a string is not closed")
            self.pos += 1
            if ch == q:
                return "".join(out)
            if ch == "\\" and q == '"':
                e = self.peek()
                self.pos += 1
                if e in _ESC:
                    out.append(_ESC[e])
                elif e in ("u", "U"):
                    n = 4 if e == "u" else 8
                    hexs = self.s[self.pos:self.pos + n]
                    if not re.fullmatch(r"[0-9A-Fa-f]{%d}" % n, hexs):
                        raise TomlError(f"line {self.line}: bad unicode escape")
                    out.append(chr(int(hexs, 16)))
                    self.pos += n
                else:
                    raise TomlError(f"line {self.line}: bad escape '\\{e}'")
            else:
                out.append(ch)

    def value(self) -> Any:
        ch = self.peek()
        if ch in ('"', "'"):
            return self.string()
        if ch == "[":
            return self.array()
        for word, val in (("true", True), ("false", False)):
            if self.s.startswith(word, self.pos):
                self.pos += len(word)
                return val
        m = _INT.match(self.s, self.pos)
        if m:
            end = m.end()
            if end < len(self.s) and self.s[end] not in " \t\n#,]":
                raise TomlError(f"line {self.line}: only whole numbers are supported")
            self.pos = end
            return int(m.group(0).replace("_", ""))
        raise TomlError(f"line {self.line}: unsupported value")

    def array(self) -> List[Any]:
        self.expect("[")
        items: List[Any] = []
        while True:
            self._skip_array_space()
            if self.peek() == "]":
                self.pos += 1
                return items
            items.append(self.value())
            self._skip_array_space()
            if self.peek() == ",":
                self.pos += 1
            elif self.peek() != "]":
                raise TomlError(f"line {self.line}: expected ',' or ']' in an array")

    def _skip_array_space(self) -> None:
        while True:
            self.skip_ws()
            self.skip_comment()
            if self.peek() == "\n":
                self.pos += 1
            else:
                return


def load_file(path: str, follow: bool = True) -> Tuple[Dict[str, Any], str]:
    """Parse a file, read safely (safeio: no blocking, a regular file, bounded; with
    `follow=False`, not a link)."""
    from phiward import safeio
    text = safeio.read_text(path, limit=1024 * 1024, follow=follow)
    return loads(text), text
