"""Split a shell command into words and operators, the way a POSIX shell (bash, zsh) would.

This is not a full shell parser and does not try to be. It does what the guard needs:
- every word, with its quotes removed and its variables expanded where the value is known;
- every operator (`|`, `&&`, `;`, redirections), so the guard can match its two allowed forms;
- the text of every command substitution, process substitution and unquoted heredoc, so the
  guard can check those commands too;
- whether some word holds a variable whose value the guard cannot know (`unresolved`).

It over-approximates on purpose: when in doubt it gives more candidate paths, never fewer.
"""

import os
import re
from dataclasses import dataclass, field
from typing import List, Mapping, Optional, Set, Tuple, Union

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ASSIGNMENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(\[[^\]]*\])?\+?=")
_SPECIAL = set("?#$!@*-_0123456789")
_REDIR = re.compile(r"(\d*|&)(>>|>&|>\||<<<|<<-|<<|<&|<>|>|<)")
_CONTROL = ("&&", "||", ";;", "|&", "|", "&", ";", "(", ")")


class ShellSyntaxError(ValueError):
    pass


@dataclass
class Word:
    raw: str = ""
    # segments: (kind, text, quoted) with kind in lit, ansi ($'...', escapes kept as written),
    # var, varx (${NAME} with a modifier, as in ${NAME:-x}: its value is not known), special,
    # sub, tilde; `text()` keeps only lit and tilde
    segs: List[Tuple[str, str, bool]] = field(default_factory=list)
    has_glob: bool = False  # an unquoted * ? [
    has_brace: bool = False  # an unquoted { with , or ..
    has_sub: bool = False  # $( ), backticks, <( ), >( )
    has_dollar: bool = False  # any $ expansion
    redirect_target: bool = False

    def text(self) -> str:
        """The literal text, quotes removed, expansions dropped."""
        return "".join(t for k, t, _ in self.segs if k in ("lit", "tilde"))


@dataclass
class Op:
    text: str  # "|", "&&", ";", "\n", "(", or a redirection such as "2>&", ">", "<<"
    target: Optional[Word] = None  # the word after a redirection

    @property
    def is_redirect(self) -> bool:
        return self.target is not None or self.text in ("<<", "<<-")


Item = Union[Word, Op]


@dataclass
class Parsed:
    items: List[Item] = field(default_factory=list)
    subs: List[str] = field(default_factory=list)  # inner command texts to check as commands
    vars: Set[str] = field(default_factory=set)  # names of $NAME / ${NAME...} used
    heredocs: List[str] = field(default_factory=list)  # bodies (data, not words)
    # a parenthesis glued to a word outside quotes, comments and heredocs: a zsh or extglob
    # group (`d/(a|b)/x`, `@(a)`), which this lexer reads as syntax
    groups: bool = False

    def words(self) -> List[Word]:
        out: List[Word] = []
        for it in self.items:
            if isinstance(it, Word):
                out.append(it)
            elif it.target is not None:
                out.append(it.target)
        return out


def parse(s: str) -> Parsed:
    p = _Lexer(s)
    p.run()
    return p.out


def bound_names(parsed: Parsed) -> Set[str]:
    """Names the command itself gives a value: assignments, and bare words such as the NAME of
    `for NAME in`, `read NAME`, `export NAME`. Their values come from the command's own (checked)
    sources at run time."""
    names: Set[str] = set()
    for w in parsed.words():
        t = w.text()
        m = ASSIGNMENT.match(t)
        if m:
            names.add(m.group(1))
        if not w.has_dollar and NAME.fullmatch(t):
            names.add(t)
    return names


def expand(word: Word, env: Mapping[str, str], bound: Set[str], home: str) -> Tuple[List[str], bool]:
    """The possible values of a word, and whether a variable in it is unknown.

    Known variables take their value from `env`; variables the command binds and special
    parameters expand to nothing (their sources are checked separately); command substitutions
    expand to nothing (their commands are checked separately).
    """
    unknown = False
    parts: List[str] = []
    for kind, text, quoted in word.segs:
        if kind in ("lit", "ansi"):  # $'...' keeps its escapes as written
            parts.append(text)
        elif kind == "tilde":
            if text == "~+":
                parts.append(".")  # the working folder: resolved against each base
            elif text == "~-":
                unknown = True  # the previous working folder: not known here
            else:
                parts.append(home if text == "~" else os.path.expanduser(text))
        elif kind == "varx":
            unknown = True
        elif kind == "var":
            if text in env:
                parts.append(env[text])
            elif text not in bound:
                unknown = True
        # special, sub: nothing
    value = "".join(parts)
    return [value], unknown


class _Lexer:
    def __init__(self, s: str):
        self.s = s
        self.i = 0
        self.out = Parsed()
        self.pending_heredocs: List[Tuple[str, bool, bool]] = []  # (delimiter, quoted, strip)

    # -- helpers ---------------------------------------------------------------------------
    def peek(self, n: int = 0) -> str:
        j = self.i + n
        return self.s[j] if j < len(self.s) else ""

    def run(self) -> None:
        s = self.s
        while self.i < len(s):
            ch = s[self.i]
            if ch in " \t":
                self.i += 1
                continue
            if ch == "\\" and self.peek(1) == "\n":
                self.i += 2
                continue
            if ch == "\n":
                self.i += 1
                self.out.items.append(Op("\n"))
                self._read_heredocs()
                continue
            if ch == "#":
                while self.i < len(s) and s[self.i] != "\n":
                    self.i += 1
                continue
            if ch in "<>" and self.peek(1) == "(":
                self.out.items.append(self._word())
                continue
            m = _REDIR.match(s, self.i)
            if m and (m.group(1) == "" or m.group(1) == "&" or self._redir_number_ok()):
                self._redirect(m)
                continue
            op = next((o for o in _CONTROL if s.startswith(o, self.i)), None)
            if op:
                if self._glued(op):
                    self.out.groups = True
                self.i += len(op)
                self.out.items.append(Op(op))
                continue
            self.out.items.append(self._word())
        if self.pending_heredocs:
            raise ShellSyntaxError("a heredoc has no end line")

    def _glued(self, op: str) -> bool:
        """Whether the `(` or `)` at self.i is glued to a word: not `name()`, `a=(...)`, a
        subshell or the end of one."""
        s, i = self.s, self.i
        if op == "(":
            before = s[i - 1] if i else ""
            return bool(before) and before not in " \t\n;|&$<>(=" and self.peek(1) != ")"
        if op == ")":
            if i and s[i - 1] == "(":
                return False  # `name()` before a body: `f(){ ...; }`
            after = self.peek(1)
            return bool(after) and after not in " \t\n;|&)<>"
        return False

    def _redir_number_ok(self) -> bool:
        # "2>" is a redirection only when the digits start a word
        return self.i == 0 or self.s[self.i - 1] in " \t\n;&|()"

    def _redirect(self, m: "re.Match[str]") -> None:
        fd, op = m.group(1), m.group(2)
        self.i = m.end()
        while self.peek() in (" ", "\t"):
            self.i += 1
        if op in ("<<", "<<-"):
            target = self._word()
            delim = target.text()
            quoted = any(q for _, _, q in target.segs) or "\\" in target.raw
            self.pending_heredocs.append((delim, quoted, op == "<<-"))
            self.out.items.append(Op(fd + op, target))
            return
        if self.i >= len(self.s) or self.s[self.i] in "\n;&|()":
            raise ShellSyntaxError("a redirection has no target")
        target = self._word()
        target.redirect_target = True
        self.out.items.append(Op(fd + op, target))

    def _read_heredocs(self) -> None:
        for delim, quoted, strip in self.pending_heredocs:
            body: List[str] = []
            while True:
                if self.i >= len(self.s):
                    raise ShellSyntaxError("a heredoc has no end line")
                end = self.s.find("\n", self.i)
                end = len(self.s) if end < 0 else end
                line = self.s[self.i:end]
                self.i = min(end + 1, len(self.s))
                if (line.lstrip("\t") if strip else line) == delim:
                    break
                body.append(line)
            text = "\n".join(body)
            self.out.heredocs.append(text)
            if not quoted:
                # an unquoted heredoc expands $VAR, $( ) and backticks
                inner = _Lexer(text)
                inner._scan_expansions_only()
                self.out.subs.extend(inner.out.subs)
                self.out.vars |= inner.out.vars
        self.pending_heredocs = []

    def _scan_expansions_only(self) -> None:
        w = Word()
        while self.i < len(self.s):
            if self.s[self.i] == "$":
                self._dollar(w, quoted=True)
            elif self.s[self.i] == "`":
                self._backtick(w)
            elif self.s[self.i] == "\\":
                self.i += 2
            else:
                self.i += 1

    # -- words -----------------------------------------------------------------------------
    def _word(self) -> Word:
        s = self.s
        w = Word()
        start = self.i
        if self.i >= len(s):  # `<<` or `>` at the very end: no word where one must be (fuzz)
            raise ShellSyntaxError("a word is missing")
        if s[self.i] in "<>" and self.peek(1) == "(":
            inner = self._balanced(self.i + 2, "(", ")")
            self.out.subs.append(inner)
            w.has_sub = True
            w.segs.append(("sub", inner, False))
        first = True
        while self.i < len(s):
            ch = s[self.i]
            if ch in " \t\n;&|()<>":
                if ch in "<>" and self.peek(1) == "(" and not first:
                    break
                break
            if ch == "'":
                end = s.find("'", self.i + 1)
                if end < 0:
                    raise ShellSyntaxError("a single quote is not closed")
                w.segs.append(("lit", s[self.i + 1:end], True))
                self.i = end + 1
            elif ch == '"':
                self._double(w)
            elif ch == "\\":
                if self.i + 1 < len(s):
                    if s[self.i + 1] != "\n":
                        w.segs.append(("lit", s[self.i + 1], True))
                    self.i += 2
                else:
                    self.i += 1
            elif ch == "$":
                self._dollar(w, quoted=False)
            elif ch == "`":
                self._backtick(w)
            elif ch == "~" and first:
                m = re.match(r"~[+-](?=$|[/\s:;&|)])|~[A-Za-z0-9_.-]*", s[self.i:])
                tilde = m.group(0)
                nxt = s[self.i + len(tilde):self.i + len(tilde) + 1]
                if nxt in ("", "/", " ", "\t", "\n", ":", ";", "&", "|", ")"):
                    w.segs.append(("tilde", tilde, False))
                else:
                    w.segs.append(("lit", tilde, False))
                self.i += len(tilde)
            else:
                if ch in "*?[":
                    w.has_glob = True
                if ch == "{":
                    w.has_brace = True
                w.segs.append(("lit", ch, False))
                self.i += 1
            first = False
        w.raw = s[start:self.i]
        if w.has_brace and not re.search(r"\{[^{}]*(,|\.\.)[^{}]*\}", w.text()):
            w.has_brace = False
        return w

    def _double(self, w: Word) -> None:
        s = self.s
        self.i += 1
        buf = ""
        while True:
            if self.i >= len(s):
                raise ShellSyntaxError("a double quote is not closed")
            ch = s[self.i]
            if ch == '"':
                self.i += 1
                break
            if ch == "\\" and self.peek(1) in ('"', "\\", "$", "`", "\n"):
                if self.peek(1) != "\n":
                    buf += self.peek(1)
                self.i += 2
                continue
            if ch in "$`":
                if buf:
                    w.segs.append(("lit", buf, True))
                    buf = ""
                if ch == "$":
                    self._dollar(w, quoted=True)
                else:
                    self._backtick(w)
                continue
            buf += ch
            self.i += 1
        w.segs.append(("lit", buf, True))

    def _backtick(self, w: Word) -> None:
        s = self.s
        j = self.i + 1
        inner = ""
        while True:
            if j >= len(s):
                raise ShellSyntaxError("a backtick is not closed")
            if s[j] == "\\" and j + 1 < len(s):
                inner += s[j + 1]
                j += 2
                continue
            if s[j] == "`":
                break
            inner += s[j]
            j += 1
        self.i = j + 1
        self.out.subs.append(inner)
        w.has_sub = True
        w.segs.append(("sub", inner, False))

    def _dollar(self, w: Word, quoted: bool) -> None:
        s = self.s
        nxt = self.peek(1)
        w.has_dollar = True
        if nxt == "(" and self.peek(2) == "(":
            inner = self._balanced(self.i + 3, "(", ")")
            # arithmetic: $(( ... )); the extra ")" closes it
            if self.peek() == ")":
                self.i += 1
            for name in NAME.findall(inner):
                self.out.vars.add(name)
            w.segs.append(("special", "", quoted))
            return
        if nxt == "[":
            # $[ ... ]: old bash arithmetic, a number like $(( ... ))
            inner = self._balanced(self.i + 2, "[", "]")
            for name in NAME.findall(inner):
                self.out.vars.add(name)
            w.segs.append(("special", "", quoted))
            return
        if nxt == "(":
            inner = self._balanced(self.i + 2, "(", ")")
            self.out.subs.append(inner)
            w.has_sub = True
            w.segs.append(("sub", inner, quoted))
            return
        if nxt == "{":
            inner = self._balanced(self.i + 2, "{", "}")
            m = re.match(r"([#!]?)([A-Za-z_][A-Za-z0-9_]*|[?#$!@*\-_0-9])(.*)", inner, re.S)
            if not m:
                raise ShellSyntaxError("a ${...} expansion is not understood")
            mod, name, rest = m.group(1), m.group(2), m.group(3)
            if name[0] in _SPECIAL or mod == "#":
                # a special parameter, or a length (${#X}, ${#arr[@]}): text the guard does not
                # know (special), never a variable's value
                if name[0] not in _SPECIAL:
                    self.out.vars.add(name)
                w.segs.append(("special", "", quoted))
                if mod == "#":
                    return  # a length: `[@]` and the like are part of it, not text
            else:
                self.out.vars.add(name)
                # ${#X}, ${!X}, ${X:-y}, ${X%/}: a value the guard does not compute
                w.segs.append(("varx" if mod or rest else "var", name, quoted))
            if rest:
                # ${VAR:-word} and the like: the word part may hold paths and expansions
                sub = _Lexer(rest.lstrip(":-=?+#%/^,"))
                try:
                    sub._scan_expansions_only()
                except ShellSyntaxError:
                    pass
                self.out.subs.extend(sub.out.subs)
                self.out.vars |= sub.out.vars
                w.segs.append(("lit", rest, True))
            return
        if nxt == "'" and not quoted:
            # $'...' ANSI-C quoting: keep the text literally (escapes stay as written); a
            # backslash escapes the next character, `\'` included
            end = self.i + 2
            while end < len(s) and s[end] != "'":
                end += 2 if s[end] == "\\" else 1
            if end >= len(s):
                raise ShellSyntaxError("a $'...' quote is not closed")
            w.segs.append(("ansi", s[self.i + 2:end], True))
            self.i = end + 1
            return
        if nxt == '"' and not quoted:
            self.i += 1
            self._double(w)
            return
        m = NAME.match(s, self.i + 1)
        if m and m.group(0) == "_":
            w.segs.append(("special", "_", quoted))  # $_: the last word of the last command
            self.i += 2
            return
        if m:
            self.out.vars.add(m.group(0))
            w.segs.append(("var", m.group(0), quoted))
            self.i = m.end()
            return
        if nxt and nxt in _SPECIAL:
            w.segs.append(("special", nxt, quoted))
            self.i += 2
            return
        # a lone "$"
        w.has_dollar = False
        w.segs.append(("lit", "$", quoted))
        self.i += 1

    def _balanced(self, start: int, open_ch: str, close_ch: str) -> str:
        """The text from `start` to the matching close character (quotes respected)."""
        s = self.s
        depth = 1
        j = start
        heredocs: List[Tuple[str, bool]] = []
        while j < len(s):
            ch = s[j]
            if ch == "\\":
                j += 2
                continue
            if ch == "<" and s.startswith("<<", j) and not s.startswith("<<<", j):
                m = re.match(r"<<(-?)\s*(['\"]?)([A-Za-z0-9_.-]+)\2", s[j:])
                if m:
                    heredocs.append((m.group(3), m.group(1) == "-"))
                    j += m.end()
                    continue
            if ch == "\n" and heredocs:
                # skip heredoc bodies: they are data, and may hold quotes and parentheses
                j += 1
                for delim, strip in heredocs:
                    while j < len(s):
                        end = s.find("\n", j)
                        end = len(s) if end < 0 else end
                        line = s[j:end]
                        j = end + 1
                        if (line.lstrip("\t") if strip else line) == delim:
                            break
                heredocs = []
                continue
            if ch == "'" and open_ch == "(":
                end = s.find("'", j + 1)
                if end < 0:
                    raise ShellSyntaxError("a single quote is not closed")
                j = end + 1
                continue
            if ch == '"':
                k = j + 1
                while k < len(s) and s[k] != '"':
                    k += 2 if s[k] == "\\" else 1
                if k >= len(s):
                    raise ShellSyntaxError("a double quote is not closed")
                j = k + 1
                continue
            if ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    self.i = j + 1
                    return s[start:j]
            j += 1
        raise ShellSyntaxError(f"a '{open_ch}' is not closed")


