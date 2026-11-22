"""Every place in phiward's source that starts or writes a command with inline code.

The rule (macOS): no interpreter gets its program in argv (`python -c`, `sh -c`, `awk '...'`,
`perl -e`, ...), `sandbox-exec` only with `-f FILE`, never `-p`, no shell (`shell=True`,
`os.system`, `os.popen`), and no `ctypes`. A `-c`, `-e` or `-p` (also joined, `-Ic`) in a list
whose program is not a known one, or added to an argv later, is a site too. A static scan of
`src/phiward` and `plugin/` lists each site by file, scope and kind. The set must equal ALLOWED.
ALLOWED holds the sites that run on Linux only and the listed exceptions (each named on
docs/endpoint-security.md); no macOS site is left to convert. A new site anywhere fails the test.
Static: it starts no process; test_macos_processes.py records what phiward starts.
"""

import ast
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "phiward"
PLUGIN = ROOT / "plugin"

LINUX = "Linux only"
EXCEPTION = "a listed exception"
KEPT = "kept: libproc's proc_pidinfo"
MESSAGE = "a refusal's text (it shows the agent `phiward run -- sh -c ...`); nothing runs it"

# (file, scope, kind): why it is allowed. Scope is the function (Class.method) or the
# module-level name that holds the site.
ALLOWED = {
    # Linux only: bubblewrap's Landlock helper and launch's helper (with its seccomp probe),
    # Landlock and procfs calls
    ("src/phiward/confine.py", "gateway_command", "python -c"): LINUX,
    # `wholetool.build`: the helper's `-c` runs inside bubblewrap only; on macOS launch runs
    # `sandbox-exec -f FILE TOOL` with no helper
    ("src/phiward/wholetool.py", "build", "python -c"): LINUX,
    ("src/phiward/wholetool.py", "landlock_abi", "ctypes"): LINUX,
    ("src/phiward/wholetool.py", "_fingerprint_errno", "ctypes"): LINUX,
    ("src/phiward/pathid.py", "_on_procfs", "ctypes"): LINUX,
    # exceptions: the remote shell's command after ssh's `--`; the project hook, committed to
    # repositories that also run on Linux (its clean-up of the variables, CLEAN_ENV, with it)
    ("src/phiward/remote.py", "receive_script", "sh -c"): EXCEPTION,
    ("src/phiward/install.py", "PROJECT_HOOK", "sh -c"): EXCEPTION,
    ("src/phiward/install.py", "PROJECT_PROMPT_HOOK", "sh -c"): EXCEPTION,  # the same form as PROJECT_HOOK
    ("src/phiward/install.py", "PROJECT_NOTE", "sh -c"): EXCEPTION,
    ("src/phiward/install.py", "CLEAN_ENV", "awk program"): EXCEPTION,
    ("src/phiward/procinfo.py", "_darwin", "ctypes"): KEPT,
    ("src/phiward/guards/protected_paths.py", "_check_shell", "sh -c"): MESSAGE,
}

# the inline-code flag of each kind of interpreter
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish"}
_E_PROGRAMS = {"perl", "ruby", "node", "osascript", "awk"}


def _kind(word: str):
    """The kind of interpreter a program word names, or None."""
    base = word.rsplit("/", 1)[-1]
    if base == "sandbox-exec":
        return "sandbox-exec"
    if base in _SHELLS:
        return "sh"
    if re.fullmatch(r"python[0-9.]*", base):
        return "python"
    if base in _E_PROGRAMS:
        return base
    return None


_FLAG = {"sandbox-exec": ("-p", "sandbox-exec -p"), "sh": ("-c", "sh -c"),
         "python": ("-c", "python -c"), "perl": ("-e", "perl -e"), "ruby": ("-e", "ruby -e"),
         "node": ("-e", "node -e"), "osascript": ("-e", "osascript -e"),
         "awk": ("-e", "awk -e")}


def _word(node):
    """A list element as a program word: a string, `sys.executable`, `SANDBOX_EXEC`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Attribute) and node.attr == "executable":
        return "python"
    if isinstance(node, (ast.Name, ast.Attribute)) and \
            (getattr(node, "id", "") or getattr(node, "attr", "")) == "SANDBOX_EXEC":
        return "/usr/bin/sandbox-exec"
    return None


_INLINE_FLAGS = ("c", "e", "p")


def _flag_letter(w: str):
    """The inline-code letter a short option word ends in (`-c`, `-Ic`, `-Sc`), or None."""
    m = re.fullmatch(r"-([A-Za-z]*)([cep])", w)
    return m.group(2) if m else None


# program words that take `-c`, `-e` or `-p` as an ordinary option (no code)
_SAFE_PROGRAMS = {"tar", "ssh", "cp", "rsync", "mkdir", "git", "getconf", "launchctl",
                  "systemctl", "id", "tabix", "bwrap"}


def _safe_program(w) -> bool:
    return isinstance(w, str) and w.rsplit("/", 1)[-1] in _SAFE_PROGRAMS


def _argv_kinds(words, whole_list: bool = True):
    """The kinds of inline code in one argv (a list of words, None for an unknown word). With
    `whole_list`, a list whose first word is not a known program and that holds an inline-code
    flag is a site too (its program is chosen elsewhere)."""
    out = set()
    interp = None
    seen_interp = False
    for w in words:
        if w is None:
            continue
        k = _kind(w)
        if k:
            interp = k
            seen_interp = True
            continue
        if interp and _flag_letter(w) == _FLAG[interp][0][1]:
            out.add(_FLAG[interp][1])
    if whole_list and not seen_interp and words and not _safe_program(words[0]) and \
            any(isinstance(w, str) and _flag_letter(w) for w in words):
        out.add("flag, program unknown")
    return out


_TEXT_INLINE = re.compile(
    r"^\s*(?:\S*/)?(sh|bash|zsh|dash|python[0-9.]*)\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*c\b")
_TEXT_SH_ANYWHERE = re.compile(r"(?:^|[^\w-])(?:\S*/)?(?:sh|bash)\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*c\b")
_TEXT_E = re.compile(r"^\s*(?:\S*/)?(perl|ruby|node|osascript)\s+(?:-\S+\s+)*-e\b")
_TEXT_SANDBOX = re.compile(r"sandbox-exec\s+-p\b")
_TEXT_AWK = re.compile(r"\bawk\s+[\"']")


def _text_kinds(text: str):
    out = set()
    m = _TEXT_INLINE.search(text)
    if m:
        out.add("python -c" if m.group(1).startswith("python") else "sh -c")
    elif _TEXT_SH_ANYWHERE.search(text):
        out.add("sh -c")
    m = _TEXT_E.search(text)
    if m:
        out.add(f"{m.group(1)} -e")
    if _TEXT_SANDBOX.search(text):
        out.add("sandbox-exec -p")
    if _TEXT_AWK.search(text):
        out.add("awk program")
    return out


def _joined(node) -> str:
    """The text of a string or an f-string; a part that is not text is `X`,
    `sys.executable` (also quoted) is `python`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_joined(v) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return _joined(node.value)
    if isinstance(node, ast.Call) and node.args and \
            getattr(node.func, "attr", "") == "quote":
        return _joined(node.args[0])
    if isinstance(node, ast.Attribute) and node.attr == "executable":
        return "python"
    return "X"


class _Scan(ast.NodeVisitor):
    def __init__(self, rel: str):
        self.rel = rel
        self.scope = ["<module>"]
        self.found = set()
        self.skip = set()  # docstrings, and lists that are compared (recognisers)

    def _add(self, kind: str) -> None:
        self.found.add((self.rel, ".".join(self.scope[1:]) or "<module>", kind))

    def _body(self, node, name):
        body = getattr(node, "body", [])
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            self.skip.add(id(body[0].value))
        self.scope.append(name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_Module(self, node):
        body = node.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            self.skip.add(id(body[0].value))
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._body(node, node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._body(node, node.name)

    def visit_Assign(self, node):
        if len(self.scope) == 1 and len(node.targets) == 1 and \
                isinstance(node.targets[0], ast.Name):
            self.scope.append(node.targets[0].id)
            self.generic_visit(node)
            self.scope.pop()
        else:
            self.generic_visit(node)

    def visit_Compare(self, node):
        for n in [node.left] + list(node.comparators):
            if isinstance(n, (ast.List, ast.Tuple)):
                self.skip.add(id(n))
        self.generic_visit(node)

    def _list(self, node):
        if id(node) not in self.skip:
            for k in _argv_kinds([_word(e) for e in node.elts]):
                self._add(k)
        self.generic_visit(node)

    visit_List = _list
    visit_Tuple = _list

    def _text(self, node):
        if id(node) not in self.skip:
            for k in _text_kinds(_joined(node)):
                self._add(k)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            self._text(node)

    def visit_JoinedStr(self, node):
        self._text(node)  # its parts are not scanned on their own

    def visit_AugAssign(self, node):
        # `argv += ["-c", code]`
        if isinstance(node.op, ast.Add) and isinstance(node.value, (ast.List, ast.Tuple)):
            self.skip.add(id(node.value))
            if any(isinstance(w, str) and _flag_letter(w)
                   for w in (_word(e) for e in node.value.elts)):
                self._add("flag added to an argv")
        self.generic_visit(node)

    def visit_Call(self, node):
        f = node.func
        name = getattr(f, "attr", "") or getattr(f, "id", "")
        if name in ("append", "extend", "insert"):
            words = []
            for a in node.args:
                if isinstance(a, (ast.List, ast.Tuple)):
                    self.skip.add(id(a))
                    words += [_word(e) for e in a.elts]
                else:
                    words.append(_word(a))
            if any(isinstance(w, str) and _flag_letter(w) for w in words):
                self._add("flag added to an argv")
        if any(k.arg == "shell" and not (isinstance(k.value, ast.Constant) and
                                         k.value.value is False) for k in node.keywords):
            self._add("shell=True")
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and \
                (f.value.id, f.attr) in (("os", "system"), ("os", "popen"),
                                         ("subprocess", "getoutput"),
                                         ("subprocess", "getstatusoutput")):
            self._add(f"{f.value.id}.{f.attr}")
        self.generic_visit(node)

    def visit_Import(self, node):
        if any(a.name.split(".")[0] == "ctypes" for a in node.names):
            self._add("ctypes")

    def visit_ImportFrom(self, node):
        if (node.module or "").split(".")[0] == "ctypes":
            self._add("ctypes")


def _scan_python(path: Path):
    s = _Scan(str(path.relative_to(ROOT)))
    s.visit(ast.parse(path.read_text(), str(path)))
    return s.found


def _scan_json(path: Path):
    """Each `command` (with its `args`) in a JSON file; the scope is the first two keys."""
    rel = str(path.relative_to(ROOT))
    found = set()

    def walk(v, keys):
        if isinstance(v, dict):
            cmd = v.get("command")
            if isinstance(cmd, str):
                args = v.get("args")
                words = [cmd] + ([a for a in args if isinstance(a, str)]
                                 if isinstance(args, list) else [])
                kinds = _argv_kinds(words)
                for w in words:
                    kinds |= _text_kinds(w)
                for k in kinds:
                    found.add((rel, ".".join(keys[:2]), k))
            for key, sub in v.items():
                walk(sub, keys + [key])
        elif isinstance(v, list):
            for sub in v:
                walk(sub, keys)
    walk(json.loads(path.read_text()), [])
    return found


def scan():
    found = set()
    for p in sorted(SRC.rglob("*.py")):
        found |= _scan_python(p)
    for p in sorted(PLUGIN.rglob("*.json")):
        found |= _scan_json(p)
    return found


def test_the_inline_code_sites_are_exactly_the_listed_ones():
    found = scan()
    new = sorted(found - set(ALLOWED))
    gone = sorted(set(ALLOWED) - found)
    assert not new, "inline code that is not listed (convert it, or list it with a reason):\n" \
        + "\n".join(map(str, new))
    assert not gone, "listed sites that are gone (remove them from ALLOWED):\n" \
        + "\n".join(map(str, gone))


def test_the_scan_finds_each_kind_of_site():
    """The scan itself: each shape it must see, in made-up code."""
    code = '''
import ctypes
def a():
    return ["/usr/bin/sandbox-exec", "-p", prof, "true"]
def b():
    return [sys.executable, "-I", "-S", "-c", CODE]
def c():
    return f"{shlex.quote(sys.executable)} -I -S -c {shlex.quote(x)} hook"
def d():
    return "/bin/sh -c " + shlex.quote(inner)
def e():
    return 'V=$(/usr/bin/awk "BEGIN{print}")'
def f():
    return ["/usr/bin/perl", "-e", "print 1"]
def g():
    return [confine.SANDBOX_EXEC, "-f", path, "true"]
def h():
    """`sh -c "..."` in a docstring is text."""
    return words[:2] != ["/bin/sh", "-c"]
'''
    tree = ast.parse(code)
    s = _Scan("x.py")
    s.visit(tree)
    assert s.found == {("x.py", "<module>", "ctypes"), ("x.py", "a", "sandbox-exec -p"),
                       ("x.py", "b", "python -c"), ("x.py", "c", "python -c"),
                       ("x.py", "d", "sh -c"), ("x.py", "e", "awk program"),
                       ("x.py", "f", "perl -e")}, s.found


def test_the_scan_finds_the_shapes_that_got_past_it():
    """Made-up code: each shape the first scan missed, and lists that are not code."""
    code = '''
def s1():
    return [prog, "-c", code]
def s2():
    return [sys.executable, "-Ic", code]
def s3():
    argv += ["-c", code]
def s4():
    argv.extend(["-e", code])
def s5():
    argv.append("-p")
def s6():
    subprocess.run(cmd, shell=True)
def s7():
    os.system(cmd)
def s8():
    os.popen(cmd)
def s9():
    return "exec env X=1 sh -c " + q
def ok1():
    return ["tar", "-c", "-f", "-", "--", name]
def ok2():
    return ["/usr/bin/ssh", "-p", "22", host]
def ok3():
    subprocess.run(cmd, shell=False)
'''
    s = _Scan("x.py")
    s.visit(ast.parse(code))
    want = {"s1": "flag, program unknown", "s2": "python -c", "s3": "flag added to an argv",
            "s4": "flag added to an argv", "s5": "flag added to an argv", "s6": "shell=True",
            "s7": "os.system", "s8": "os.popen", "s9": "sh -c"}
    missed = [(fn, kind) for fn, kind in want.items() if ("x.py", fn, kind) not in s.found]
    assert not missed, (missed, sorted(s.found))
    assert not [f for f in s.found if f[1].startswith("ok")], sorted(s.found)


# --- launchctl by its full path ----------------------------------------------------------------

def test_the_login_service_runs_launchctl_by_its_full_path(monkeypatch):
    from phiward import service
    seen = []

    def runner(cmd, **k):
        seen.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 1 if cmd[1:2] == ["print"] else 0, "", "")
    monkeypatch.setattr(service.sys, "platform", "darwin")
    service.load("/made/up/org.phiward.broker.plist", runner=runner)
    assert seen and all(c[0] == "/bin/launchctl" for c in seen), seen
