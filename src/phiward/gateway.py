"""Recognize a gateway call: `phiward run ...` or `phiward copy ...` as the whole command.

The hook allows such a command although it names protected paths: it is a client that hands
argv to the broker (broker.py), it runs in the agent's sandbox like any command, and the broker
checks grants against the user config. The form is strict all the same: one simple command with the bare
head `phiward`, no operators (only trailing newlines), no redirections, no command or
process substitution, no variable other than $HOME. Globs, braces and `~` are allowed: the shell
expands them into the client's arguments. Any other spelling (a path, `python -m`) is an
ordinary command, and the guard checks it as one.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from phiward import shell
from phiward.names import MODULES, PROGRAMS


@dataclass
class Call:
    name: str  # "run" or "copy"
    args: List[str]  # the words after the subcommand, as written (quotes removed)


def _only_home(w: shell.Word) -> bool:
    return all(k != "var" or n == "HOME" for k, n, _ in w.segs) and \
        not any(k in ("special", "sub", "varx") for k, _, _ in w.segs)


def parse_call(command: str) -> Optional[Call]:
    words = whole_command(command)
    if not words or words[0] not in ("run", "copy"):
        return None
    return Call(words[0], words[1:])


def whole_command(command: str) -> Optional[List[str]]:
    """The words after `phiward` of a phiward command written as the whole command (the bare
    name, then words fixed as written: no substitution, no variable but `~` and `$HOME`, one
    simple command), or None."""
    try:
        parsed = shell.parse(command)
    except (shell.ShellSyntaxError, ValueError, RecursionError):
        return None
    items = list(parsed.items)
    while items and isinstance(items[-1], shell.Op) and items[-1].text == "\n":
        items.pop()  # only trailing newlines; one between words would start a second command
    if not items or not all(isinstance(it, shell.Word) for it in items):
        return None
    if parsed.subs or parsed.heredocs:
        return None
    words: List[shell.Word] = items  # type: ignore[assignment]
    if any(w.has_sub or not _only_home(w) for w in words):
        return None
    texts = [w.text() for w in words]
    if texts[0] != "phiward" or words[0].raw != "phiward":
        return None
    return texts[1:]


# programs that run the words after them as a command: before a gateway call, a prefix to remove
_PREFIXES = frozenset({"sudo", "doas", "time", "nohup", "exec", "command", "builtin", "nice",
                       "ionice", "env", "stdbuf", "timeout", "caffeinate", "chrt", "taskset",
                       "xargs", "!"})


def not_whole(command: str) -> Optional[str]:
    """For a command that holds a gateway call (`phiward run|copy`) but is not that call written
    whole (`whole_command`): what to change, in a few words; None when it holds none or is
    whole. The extra part is quoted as written, so the agent knows what to remove."""
    if whole_command(command) is not None:
        return None
    try:
        parsed = shell.parse(command)
    except (shell.ShellSyntaxError, ValueError, RecursionError):
        return None
    items = list(parsed.items)
    start = next((i for i in range(len(items) - 1)
                  if isinstance(items[i], shell.Word) and isinstance(items[i + 1], shell.Word)
                  and items[i].raw == "phiward" and items[i + 1].text() in ("run", "copy")), None)
    if start is None:
        return None

    def cut(text: str) -> str:
        text = " ".join(text.split())
        return text if len(text) <= 60 else text[:57] + "..."

    # where each item is in the text, in order
    pos, at = 0, []
    for it in items:
        raw = it.raw if isinstance(it, shell.Word) else it.text
        i = command.find(raw, pos)
        at.append(i if i >= 0 else pos)
        pos = (i + len(raw)) if i >= 0 else pos
    before = command[:at[start]].strip()
    # the words since the last operator before `phiward`: when one of them is not a variable
    # assignment, `phiward` is that command's argument (`echo phiward run ...`), not a command
    lead = []
    for it in reversed(items[:start]):
        if isinstance(it, shell.Op):
            break
        lead.insert(0, it)
    cmd_word = next((w for w in lead if isinstance(w, shell.Word) and
                     not re.match(r"[A-Za-z_][A-Za-z0-9_]*=", w.raw)), None)
    if cmd_word is not None and cmd_word.raw.rsplit("/", 1)[-1] in _PREFIXES:
        # a program that runs the rest as its command: the gateway call itself, with a prefix
        return (f"A gateway call must be the whole command: remove `{cut(before)}` (it runs "
                "outside the gateway, with no prefix).")
    if cmd_word is not None:
        return (f"Here `phiward` is an argument of `{cut(cmd_word.raw)}`, not the command: a "
                "gateway call must be the whole command, starting with `phiward`.")
    # the first operator after it, a line break too unless only space follows it
    op = next((j for j in range(start, len(items)) if isinstance(items[j], shell.Op)
               and (items[j].text != "\n" or command[at[j]:].strip())), None)
    after = command[at[op]:].strip() if op is not None else ""
    if op is not None and items[op].text == "\n":
        return (f"A gateway call must be the whole command, one gateway call per command: run "
                f"`{cut(after)}` as its own call.")
    parts = [f"`{cut(x)}`" for x in (before, after) if x]
    if parts:
        return ("A gateway call must be the whole command: remove " + " and ".join(parts) +
                " (run each step as its own call; the script `phiward run` runs may pipe or "
                "redirect inside it).")
    if parsed.subs or parsed.heredocs or any(isinstance(w, shell.Word) and
                                             (w.has_sub or not _only_home(w)) for w in items):
        return ("A gateway call is written with fixed words: no `$(...)`, backquotes, heredocs "
                "or variables but `~` and `$HOME`.")
    return None


# carryover: accepting a quarantined change makes it trusted
# broker: once a config exists, the broker is the operator's (a service file the
# agent wrote could run it, outside every sandbox, with a config of the agent's choosing)
# pseudonymize: its key folder is hidden from every agent path; a run on the agent's file or
# key name would confirm guessed IDs
OPERATOR_ONLY = ("setup", "pin", "carryover", "broker", "pseudonymize")


def _names_program(word: str) -> bool:
    """Whether a word runs phiward: its name or path, a module name, or `-m` glued to a module
    (`-mphiward`, `-mphiward.cli`)."""
    base = word.rsplit("/", 1)[-1]
    if base in PROGRAMS + MODULES:
        return True
    if word.startswith("-m"):
        return word[2:].split(".", 1)[0] in MODULES
    return False


# Words after which the next word is a command: shell reserved words and grouping
_RESERVED = ("do", "then", "else", "elif", "if", "while", "until", "{", "!", "coproc")
# Wrappers that run a later word as a command: their options that take a value, and how many
# plain words (a mask, a file) come before the command
_WRAPPERS = {
    "env": ({"-u", "--unset", "-C", "--chdir", "-S", "--split-string", "-P"}, 0),
    "command": (set(), 0), "builtin": (set(), 0), "nohup": (set(), 0), "time": (set(), 0),
    "unbuffer": (set(), 0), "arch": (set(), 0),
    "exec": ({"-a"}, 0),
    "timeout": ({"-s", "--signal", "-k", "--kill-after"}, 0),
    "nice": ({"-n", "--adjustment"}, 0),
    "xargs": ({"-I", "-a", "--arg-file", "-n", "--max-args", "-L", "--max-lines", "-P",
               "--max-procs", "-s", "--max-chars", "-d", "--delimiter", "-E", "-e"}, 0),
    "sudo": ({"-u", "--user", "-g", "--group", "-C", "-h", "--host", "-p", "--prompt", "-r",
              "--role", "-t", "--type", "-U", "--other-user", "-D", "--chdir", "-R",
              "--chroot", "-T", "--command-timeout"}, 0),
    "doas": ({"-u", "-C"}, 0),
    "stdbuf": ({"-i", "-o", "-e", "--input", "--output", "--error"}, 0),
    "taskset": (set(), 1), "chrt": (set(), 1),
    "caffeinate": ({"-w", "-t"}, 0),
    "script": ({"-c", "--command", "-t", "--timing", "-F", "-T"}, 1),
    "uvx": ({"--with", "--from", "--python", "-p", "--index", "--index-url", "--directory",
             "--project", "--env-file"}, 0),
}
_RUNNERS = {("uv", "run"): "uvx", ("uv", "tool", "run"): "uvx", ("pipx", "run"): "uvx"}
_PY_VALUE = {"-X", "-W", "-Q"}
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_PYTHON = re.compile(r"python[0-9.]*")
_NUMBER = re.compile(r"[0-9][0-9.]*[smhd]?|0x[0-9A-Fa-f]+")


def _built_at_run_time(w: "shell.Word") -> bool:
    return w.has_sub or w.has_dollar or w.has_glob or w.has_brace or \
        any(k not in ("lit", "tilde") for k, _, _ in w.segs)


def _simple_commands(parsed: "shell.Parsed") -> "List[List[shell.Word]]":
    out: List[List[shell.Word]] = [[]]
    for it in parsed.items:
        if isinstance(it, shell.Word):
            if not it.redirect_target:
                out[-1].append(it)
        elif not it.is_redirect:
            out.append([])
    return [c for c in out if c]


def _skip_options(words: "List[shell.Word]", i: int, value: "set", plain: int) -> int:
    """The index after a wrapper's options (and the values of those that take one), its
    assignments, counts and durations, and `plain` other words."""
    while i < len(words):
        t = words[i].text()
        if t in value:
            i += 2
        elif t.startswith("-") or _ASSIGN.match(words[i].raw):
            i += 1
        elif plain > 0:  # a mask, a priority, a file: the first plain word
            plain -= 1
            i += 1
        elif _NUMBER.fullmatch(t):
            i += 1
        else:
            break
    return i


def _program_at(words: "List[shell.Word]", i: int) -> "Tuple[int, bool]":
    """(the index of the subcommand word when the command at `i` runs phiward, else -1; whether
    a wrapper adds words of its own after it: xargs, find -exec)."""
    adds = False
    while i < len(words):
        t = words[i].text()
        base = t.rsplit("/", 1)[-1]
        if _ASSIGN.match(words[i].raw) or (t in _RESERVED and all(
                k == "lit" and not q for k, _, q in words[i].segs)):
            i += 1
            continue
        runner = next((r for r in sorted(_RUNNERS, key=len, reverse=True)
                       if tuple(w.text() for w in words[i:i + len(r)]) == r), None)
        if runner is not None:
            value, plain = _WRAPPERS[_RUNNERS[runner]]
            i = _skip_options(words, i + len(runner), value, plain)
            continue
        if base in _WRAPPERS:
            adds = adds or base == "xargs"
            value, plain = _WRAPPERS[base]
            i = _skip_options(words, i + 1, value, plain)
            continue
        if base == "find":
            for j in range(i + 1, len(words) - 1):
                if words[j].text() in ("-exec", "-execdir", "-ok", "-okdir"):
                    sub, _ = _program_at(words, j + 1)
                    if sub >= 0:
                        return sub, True
            return -1, False
        if _PYTHON.fullmatch(base):
            j = i + 1
            while j < len(words) and words[j].text().startswith("-"):
                m = words[j].text()
                if m == "-m" and j + 1 < len(words):
                    mod = words[j + 1].text().split(".", 1)[0]
                    return (j + 2, adds) if mod in MODULES else (-1, False)
                if m.startswith("-m") and len(m) > 2:
                    return (j + 1, adds) if m[2:].split(".", 1)[0] in MODULES else (-1, False)
                if m == "-c":
                    return -1, False
                j += 2 if m in _PY_VALUE else 1
            return -1, False
        if base in PROGRAMS + MODULES:
            return i + 1, adds
        return -1, False
    return -1, False


def is_operator_command(command: str) -> bool:
    """Whether some simple command in `command` runs an operator-only subcommand
    (`phiward setup`), in any spelling of the program the guard can see.

    A tripwire for honest mistakes, not the boundary: a program can always build the words
    (`python -c`, `sh -c` strings). The operator commands refuse without a terminal, and
    pseudonymize's keys sit in a folder no session or gateway command can read or write."""
    try:
        parsed = shell.parse(command)
    except (shell.ShellSyntaxError, ValueError, RecursionError):
        return any(op in command for op in OPERATOR_ONLY) and \
            any(n in command for n in PROGRAMS + MODULES)
    items = [it for it in parsed.items if isinstance(it, shell.Word)]
    words = [it.text() for it in items]
    for i, w in enumerate(words):
        if _names_program(w) and i + 1 < len(words) and words[i + 1] in OPERATOR_ONLY:
            return True
    # phiward in command position (first word, after assignments or a wrapper): its
    # subcommand must be a word as written, and must be there when a wrapper adds words
    for cmd in _simple_commands(parsed):
        sub, adds = _program_at(cmd, 0)
        if sub < 0:
            continue
        if sub >= len(cmd):
            if adds:
                return True
            continue
        if _built_at_run_time(cmd[sub]) or (adds and cmd[sub].text() in ("{}", ";", "+")):
            return True
    if any(is_operator_command(inner) for inner in parsed.subs):
        return True
    # any other spelling that names the program and an operator-only word together
    # (`sh -c 'phiward broker'`, `$p broker`, `xargs phiward`): refused unless it is a plain
    # gateway call
    if parse_call(command) is None and \
            re.search(r"\b(?:phiward|agent[-_]guards)\b", command) and \
            re.search(r"\b(?:" + "|".join(OPERATOR_ONLY) + r")\b", command):
        return True
    return False
