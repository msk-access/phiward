"""macOS: every process phiward starts, recorded, meets the rule; the security page lists them.

An audit hook in this test process only (`sys.addaudithook`; phiward's own code has none)
records each argv that phiward starts (`subprocess.Popen`, `os.exec*`, `os.posix_spawn`,
`os.spawn*`) while the test drives the real paths: install, a gateway request, a pull and a
local copy, the Mode A hook and session note, the plugin's hook, launch up to the tool's start
(and a launch inside a session, whose exec of a wrapped server is stopped here), doctor's and
setup's checks. The commands phiward writes for Claude Code, launchd or git to start are read
from what it writes, and the hook scripts' own starts (awk, the exec) from a trace of the
script (`sh -x`).

The rule, on phiward's words (the user's words are cut off first): no `-c`, `-e` or `-p` code
argument and no `sh -c` of phiward's own; `sandbox-exec` only as `/usr/bin/sandbox-exec -f
<profile>`; awk only with `-f FILE`; word 0 is a system program by its full path, phiward's
Python with a file in the package (or `-m phiward`), a script in the package, phiward's
launcher, or the user's own tool. A wrapped MCP server's own `sh -c` passes through unchanged,
reported as the user's. The project hook's fixed line is the one named exception. Then each
argv is written as a shape (placeholders in `<>`), and the set equals the block on
docs/endpoint-security.md, both ways.

Nothing real is confined: `sandbox-exec` is a made-up recorder that runs the command, ssh is the
fake of test_v2_push, the tool is a made-up script. `launchctl`, `claude` and the self-check
are recorded but not started (the hook stops them). Made-up names only (FAKE-PT-0001).
"""

import io
import json
import os
import plistlib
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import (broker, claude_settings, cli, confine, copying, doctor, githooks,
                     install, mcp_config, selfcheck, service, wholetool)
from test_docs_endpoint_security import PAGE, all_shapes
from test_macos_inline_code import _argv_kinds, _kind
from test_v2_push import hpc  # noqa: F401 - the fixture: a fake shared connection and ssh

ROOT = Path(__file__).resolve().parents[1]
PKG = str(Path(install.__file__).resolve().parent.parent)  # the folder that holds `phiward/`
PLUGIN = str(ROOT / "plugin")
PROFILE = re.compile(r".*/\.phiward/profiles/[0-9a-f]{32}\.sb")
SYSTEM_DIRS = copying.SYSTEM_DIRS
ENTRY = "0123456789abcdef"
# the real `claude --version` question (the suite replaces it in every test: conftest.py)
REAL_CLAUDE_VERSION = claude_settings.claude_version

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS: the shapes are its own")


# --- the recorder -------------------------------------------------------------------------------

class NotStarted(OSError):
    """What the hook raises to stop a start it records (phiward takes it as a start that
    failed)."""


class Stopped(Exception):
    """What the hook raises to stop an exec, which would replace this test process."""


_STATE = {"rec": None, "installed": False}


def _words(argv):
    if isinstance(argv, (str, bytes)):
        return [os.fsdecode(argv)]
    return [os.fsdecode(w) for w in argv]


def _never_start(words) -> bool:
    base = os.path.basename(words[0])
    return base in ("launchctl", "claude") or \
        any(w.endswith("/phiward/selfcheck.py") for w in words[1:])


def _audit(event, args):
    rec = _STATE["rec"]
    if rec is None:
        return
    if event == "subprocess.Popen":
        words = _words(args[1])
    elif event in ("os.exec", "os.posix_spawn"):
        words = _words(args[1])
    elif event == "os.spawn":
        words = _words(args[2])
    else:
        return
    rec.append(words)
    if event == "os.exec":
        raise Stopped(words)
    if event == "subprocess.Popen" and _never_start(words):
        raise NotStarted(f"recorded, not started: {words[0]}")


class _Recording:
    def __init__(self, out):
        self.out = out

    def __enter__(self):
        if not _STATE["installed"]:
            sys.addaudithook(_audit)
            _STATE["installed"] = True
        _STATE["rec"] = []
        return self

    def __exit__(self, *exc):
        got, _STATE["rec"] = _STATE["rec"], None
        for w in got:  # a Popen and its own posix_spawn are one start
            if w not in self.out:
                self.out.append(w)
        return False


def _trace(argv, env, stdin=""):
    """The programs a hook script starts: `/bin/sh -x` prints each command; the awk the script
    runs and the program it execs are kept."""
    r = subprocess.run(["/bin/sh", "-x"] + argv, input=stdin, capture_output=True, text=True,
                       env=env, timeout=60)
    out = []
    for line in r.stderr.splitlines():
        m = re.match(r"^\++ (.*)$", line)
        if not m:
            continue
        try:
            words = shlex.split(m.group(1))
        except ValueError:
            continue
        if words[:1] == ["exec"]:
            out.append(words[1:])
        elif words[:1] == ["/usr/bin/awk"]:
            out.append(words)
    return out


def _entries(hooks):
    """Each hook of a settings `hooks` object as the argv Claude Code starts."""
    out = []
    for groups in hooks.values():
        for g in groups:
            for h in g["hooks"]:
                if "args" in h:
                    out.append([h["command"]] + list(h["args"]))
                else:
                    out.append(shlex.split(h["command"]))
    return out


# --- the run ------------------------------------------------------------------------------------

class _Spool:
    def exists(self, name):
        return False


def _record(tree, hpc_home, monkeypatch):  # noqa: C901 - one scenario after another
    """[(argv, user tail label or "")] for each process phiward starts or writes, and the
    context the shapes need."""
    started, written = [], []  # argv lists
    home = str(tree / "home")
    monkeypatch.setenv("HOME", home)
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(confine, "backend", lambda: "seatbelt")
    fake_sx = tree / "bin-fake" / "sandbox-exec"
    fake_sx.parent.mkdir()
    fake_sx.write_text('#!/bin/sh\n[ "$1" = -f ] || exit 99\n[ -f "$2" ] || exit 98\n'
                       'shift 2\nexec "$@"\n')
    fake_sx.chmod(0o755)
    monkeypatch.setattr(confine, "SANDBOX_EXEC", str(fake_sx))
    # phiward's launcher (a Python script, as uv and pipx write it), first on PATH
    bindir = tree / "made-up-bin"
    bindir.mkdir()
    launcher = bindir / "phiward"
    launcher.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n")
    launcher.chmod(0o755)
    claude = tree / "made-up-claude" / "claude"
    claude.parent.mkdir()
    claude.write_bytes(b"MADE-UP native build, never started\n")
    claude.chmod(0o755)
    tool = tree / "made-up-tools" / "fake-agent"
    tool.parent.mkdir()
    tool.write_text("#!/bin/sh\nexit 0\n")
    tool.chmod(0o755)
    server = ["/bin/sh", "-c", "echo made-up-server"]
    command = ["/bin/echo", "FAKE-PT-0001"]
    src, dst = str(tree / "phi" / "FAKE-PT-0001.bam"), str(tree / "phi" / "copies" / "new") + "/"
    tails = [(command, "<command> ..."), ([src, dst], "<source> ... <dest>"),
             ([str(tool)], "<tool> ..."), (server, "<server> ...")]
    from helpers import Tty

    # install: the user wiring (and its check that the isolated Python sees the package)
    with monkeypatch.context() as m:
        m.setattr(sys, "stdin", Tty())
        with _Recording(started):
            assert install.main(["claude", "--user", "--write", "--yes"]) == 0
            # outside a source checkout (no PHIWARD_DEV) install asks this first
            assert install._isolated_import_problem() == ""
    monkeypatch.setenv("PATH", f"{bindir}:{claude.parent}:/usr/bin:/bin:/usr/sbin:/sbin")
    settings = json.loads((tree / "home" / ".claude" / "settings.json").read_text())
    wiring = _entries(settings["hooks"])
    written += wiring
    # what Claude Code then starts: each entry's script (its awk and its exec)
    payload = {"PreToolUse": {"session_id": "fake", "hook_event_name": "PreToolUse",
                              "cwd": str(tree / "repo"), "tool_name": "Read",
                              "tool_input": {"file_path": str(tree / "repo" / "README.md")}},
               "SessionStart": {"cwd": str(tree / "repo"), "hook_event_name": "SessionStart"},
               "UserPromptSubmit": {"cwd": str(tree / "repo"), "session_id": "fake",
                                    "hook_event_name": "UserPromptSubmit",
                                    "prompt": "count the made-up lines"}}
    for argv in wiring:
        written += _trace(argv, dict(os.environ), json.dumps(payload["PreToolUse"]))
    # the Mode A hook, the session note and the prompt check, in this process
    for what, ev in (("hook", "PreToolUse"), ("session-note", "SessionStart"),
                     ("prompt-scan", "UserPromptSubmit")):
        with monkeypatch.context() as m:
            m.setattr(sys, "stdin", io.StringIO(json.dumps(payload[ev])))
            m.setattr(sys, "stdout", io.StringIO())
            m.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
            with _Recording(started):
                cli.main([what, "claude"])
    # a project's committed wiring: the one named exception, and what its line starts
    proj = install.wiring(config_load(tree), True, str(tree / "repo"))
    for argv in _entries(proj["hooks"]):
        written.append(argv)
        written += _trace(argv[1:], dict(os.environ), json.dumps(payload["PreToolUse"]))

    # the plugin: its hooks (the script, its awk, `phiward` by name) and its MCP server
    hooks = json.loads((ROOT / "plugin" / "hooks" / "hooks.json").read_text())["hooks"]
    for argv in _entries(hooks):
        argv = [argv[0].replace("${CLAUDE_PLUGIN_ROOT}", PLUGIN)] + argv[1:]
        written.append(argv)
        written += _trace(argv, dict(os.environ), json.dumps(payload["PreToolUse"]))
    mcp = json.loads((ROOT / "plugin" / ".mcp.json").read_text())["mcpServers"]["phiward"]
    written.append([mcp["command"]] + mcp["args"])

    # a gateway request and the copies, as the broker runs them
    b = broker.Broker(_Spool(), io.StringIO())
    with _Recording(started):
        assert b.execute("r1", {"cmd": "run", "args": ["--"] + command,
                                "cwd": str(tree / "repo")}, io.StringIO()) == 0
    with _Recording(started):
        assert b.execute("r2", {"cmd": "copy", "args": [src, dst],
                                "cwd": str(tree / "repo")}, io.StringIO()) == 0
    with monkeypatch.context() as m:
        m.setenv("HOME", hpc_home)
        b = broker.Broker(_Spool(), io.StringIO())
        out = io.StringIO()
        with _Recording(started):
            code = b.execute("r3", {"cmd": "copy",
                                    "args": ["hpc-test:/work/me/res", str(tree / "phi" / "pulled")],
                                    "cwd": str(tree / "repo")}, out)
        assert code == 0, out.getvalue()

    # launch, up to the tool's start, and the hooks it writes for a session
    with monkeypatch.context() as m:
        m.setattr(wholetool, "already_confined", lambda env: False)
        with _Recording(started):
            assert wholetool.main(["--", str(tool)]) == 0
    folder = tree / "made-up-session"
    folder.mkdir()
    fd = os.open(str(folder), os.O_RDONLY)
    try:
        wholetool.ADAPTERS["claude"].turn_own_sandbox_off(fd)
    finally:
        os.close(fd)
    written += _entries(json.loads((folder / "settings.json").read_text())["hooks"])
    # --tool claude: the floor asks a native build its version (recorded, not started)
    with _Recording(started):
        assert wholetool.claude_version_problem(str(claude), [], dict(os.environ))
    # a wrapped MCP server: the entry `mcp wrap` writes, and a launch inside a session, which
    # execs the server's own argv (stopped here)
    written.append(mcp_config._wrapped_spec({"command": server[0], "args": server[1:]},
                                            str(launcher)))
    written[-1] = [written[-1]["command"]] + written[-1]["args"]
    with monkeypatch.context() as m:
        m.setattr(wholetool, "already_confined", lambda env: True)
        with pytest.raises(Stopped), _Recording(started):
            wholetool.main(["--entry", ENTRY, "--"] + server)

    # the self-check (as launch, wrapped servers and doctor run it), stopped before it starts
    with monkeypatch.context() as m:
        site = str(tree / "made-up-site")
        m.setattr(selfcheck, "_record_path",
                  lambda: os.path.join(site, "phiward-0.0.dist-info", "RECORD"))
        m.setattr(selfcheck, "_running_package", lambda: os.path.join(site, "phiward"))
        with _Recording(started):
            selfcheck.check_isolated()
            selfcheck.check_full_isolated()
    # doctor's checks and setup's login service
    with _Recording(started):
        assert confine.self_test() is None
        doctor.clean_start_problem()
        REAL_CLAUDE_VERSION()
    written.append(plist_argv(service.render(str(launcher))))
    plist = os.path.join(home, "Library", "LaunchAgents", service.LABEL + ".plist")
    with monkeypatch.context() as m:
        m.delenv("PHIWARD_SERVICE_RUNNER")
        with _Recording(started):
            service.load(plist)  # print, then bootstrap (both recorded, not started)

        def runner(cmd, **k):  # a loaded service: print works, then kickstart
            started.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        service.load(plist, runner=runner)
    # git, from PATH, for the git hooks; and the hook files git starts
    with _Recording(started):
        try:
            githooks._toplevel(str(tree / "repo"))
        except githooks.GitError:
            pass
    hookdir = tree / "repo" / ".git" / "hooks"
    hookdir.mkdir(parents=True)
    for name in githooks.HOOKS:
        f = hookdir / name
        f.write_text(githooks._script(name))
        f.chmod(0o755)
        written.append([str(f)])
        written += _trace([str(f)], dict(os.environ))
    ctx = {"tree": str(tree), "homes": [home, hpc_home], "launcher": str(launcher),
           "claude": str(claude), "fake_sx": str(fake_sx), "tool": str(tool),
           "ssh_cfg": str(tree / "home" / "phiward-ssh"), "host": "hpc-test",
           "socket": os.path.join(hpc_home, ".ssh", "cm"), "record": os.path.join(
               str(tree / "made-up-site"), "phiward-0.0.dist-info", "RECORD"),
           "repo": str(tree / "repo")}
    return [(w, _tail(w, tails)) for w in started + written], ctx


def config_load(tree):
    from phiward import config
    return config.load(str(tree / "repo"))


def plist_argv(text):
    return list(plistlib.loads(text.encode())["ProgramArguments"])


def _tail(words, tails):
    """The label of the user's words at the end of `words`, or ""."""
    for tail, label in tails:
        n = len(tail)
        if len(words) >= n and [os.path.realpath(w) if i == 0 else w
                                for i, w in enumerate(words[-n:])] == \
                [os.path.realpath(w) if i == 0 else w for i, w in enumerate(tail)]:
            return label
    return ""


# --- the rule -----------------------------------------------------------------------------------

_N = {"<command> ...": 2, "<source> ... <dest>": 2, "<tool> ...": 1, "<server> ...": 3}


def _as_real(words, ctx):
    """The made-up stand-ins as the programs they stand for."""
    return [("/usr/bin/sandbox-exec" if w == ctx["fake_sx"] else
             "/usr/bin/ssh" if w.endswith("/fake-ssh") else w) for w in words]


def _in_package(p) -> bool:
    return p.startswith((PKG + "/phiward/", PLUGIN + "/hooks/"))


def _segment_breaks(words, ctx):
    """Why phiward's own words in one argv break the rule ([] when they do not)."""
    out = []
    w0 = words[0]
    kinds = _argv_kinds(words)
    if kinds:
        out.append(f"inline code: {sorted(kinds)}")
    k = _kind(w0)
    if w0 == sys.executable:
        i, first = 1, ""
        while i < len(words):  # the options, then the program: a file, or `-m phiward`
            w = words[i]
            if w == "-m":
                first = "-m " + (words[i + 1] if i + 1 < len(words) else "")
                break
            if w in ("-X", "-W"):
                i += 2
                continue
            if not w.startswith("-"):
                first = w
                break
            i += 1
        if not (first == "-m phiward" or _in_package(first)):
            out.append("phiward's Python without a file in the package")
    elif os.path.dirname(w0) in SYSTEM_DIRS:
        if k == "sh" and not (len(words) > 1 and _in_package(words[1])):
            out.append("a shell without a file in the package")
        if k == "awk" and not (words[1:2] == ["-f"] and _in_package(words[2])):
            out.append("awk without -f FILE")
        if k in ("perl", "ruby", "node", "osascript", "python"):
            out.append(f"{k} with no file")
    elif _in_package(w0):
        pass  # a script of the package (its interpreter is its #! line)
    elif w0 in ("phiward", ctx["launcher"]):
        pass  # phiward's launcher, by name (the plugin) or by its path
    elif w0.startswith(ctx["repo"] + "/.git/hooks/"):
        pass  # a git hook file phiward writes (git starts it)
    elif w0 == "git" or os.path.realpath(w0) == os.path.realpath(ctx["claude"]):
        pass  # the user's own tools: git from PATH, Claude Code
    else:
        out.append(f"word 0 ({w0}) is no system path, package file, launcher or user tool")
    return out


def _project_exception(words) -> bool:
    """The one named exception: the project hook's fixed line, and the awk program in it."""
    texts = {shlex.split(t)[2] for t in (install.PROJECT_HOOK, install.PROJECT_PROMPT_HOOK,
                                         install.PROJECT_NOTE)}
    if words[:2] == ["/bin/sh", "-c"] and len(words) == 3 and words[2] in texts:
        return True
    return words[:1] == ["/usr/bin/awk"] and len(words) == 2 and \
        words[1].startswith("BEGIN{for(k in ENVIRON)")


def breaks(words, label, ctx):
    """Why `words` (an argv phiward starts or writes) breaks the rule, or []; "user's" when all
    of it is the user's own."""
    words = _as_real(words, ctx)
    if label:
        words = words[:-_N[label]]
        if not words:
            return ["user's"]
    if _project_exception(words):
        return []
    out = []
    if os.path.basename(words[0]) == "sandbox-exec":
        if words[0] != "/usr/bin/sandbox-exec" or words[1:2] != ["-f"] or \
                not PROFILE.fullmatch(words[2] if len(words) > 2 else ""):
            out.append("sandbox-exec not as /usr/bin/sandbox-exec -f <profile>")
        words = words[3:]
        if not words:
            return out
    if os.path.basename(words[0]) == "ssh" and "--" in words:
        words = words[:words.index("--") + 2]  # the remote command after `--`: an exception
    return out + _segment_breaks(words, ctx)


# --- the shapes ---------------------------------------------------------------------------------

def shape(words, label, ctx):
    """`words` as a shape: the command line the kernel shows (a script's `#!` interpreter first),
    with placeholders for paths, ids and the user's words."""
    words = _as_real(words, ctx)
    if label:
        words = words[:-_N[label]] + [label]
    first = ctx["launcher"] if words[0] == "phiward" else words[0]
    if first.startswith("/") and os.path.isfile(first):
        with open(first, "rb") as fh:
            head = fh.readline()
        if head.startswith(b"#!"):
            words = head[2:].decode().split() + [first] + words[1:]
    texts = {shlex.split(install.PROJECT_HOOK)[2]: "<project-hook>",
             shlex.split(install.PROJECT_PROMPT_HOOK)[2]: "<project-prompt-hook>",
             shlex.split(install.PROJECT_NOTE)[2]: "<project-note>"}
    homes = sorted({h for h0 in ctx["homes"] for h in (h0, os.path.realpath(h0))},
                   key=len, reverse=True)
    out = []
    ssh = "/usr/bin/ssh" in words
    after_dashes = False
    for i, w in enumerate(words):
        prev = words[i - 1] if i else ""
        if w in texts:
            out.append(texts[w])
        elif w.startswith("BEGIN{for(k in ENVIRON)"):
            out.append("<awk-program>")
        elif w == sys.executable:
            out.append("<python>")
        elif w.startswith(PKG + "/"):
            out.append("<PKG>/" + w[len(PKG) + 1:])
        elif w.startswith(PLUGIN + "/"):
            out.append("<plugin>/" + w[len(PLUGIN) + 1:])
        elif w == ctx["launcher"]:
            out.append("<launcher>")
        elif PROFILE.fullmatch(w):
            out.append("<profile>")
        elif w == ctx["ssh_cfg"]:
            out.append("<ssh-config>")
        elif w in (ctx["socket"], os.path.realpath(ctx["socket"])):
            out.append("<socket>")
        elif w == ctx["host"]:
            out.append("<host>")
        elif ssh and after_dashes:
            out.append("<remote>")
        elif prev == "--entry":
            out.append("<entry>")
        elif w == ctx["record"]:
            out.append("<record>")
        elif os.path.realpath(w) == os.path.realpath(ctx["claude"]) and w.startswith("/"):
            out.append("<claude>")
        elif w.startswith(ctx["repo"] + "/.git/hooks/"):
            out.append("<repo>/.git/hooks/" + w.rsplit("/", 1)[1])
        elif re.fullmatch(r"gui/\d+(/.*)?", w):
            out.append(re.sub(r"^gui/\d+", "gui/<uid>", w))
        elif any(w == h or w.startswith(h + "/") for h in homes):
            h = next(h for h in homes if w == h or w.startswith(h + "/"))
            out.append("<home>" + w[len(h):])
        elif w.startswith((ctx["tree"] + "/", "/work/me")):
            out.append("<path>")
        else:
            out.append(w)
        if ssh and w == "--":
            after_dashes = True
    if out[0] == "git":
        out = ["git", "<arguments>"]
    return " ".join(out)


_CACHE: dict = {}


def _recorded(tree, hpc_home, monkeypatch):
    if "got" not in _CACHE:
        _CACHE["got"] = _record(tree, hpc_home, monkeypatch)
    return _CACHE["got"]


def test_every_process_phiward_starts_meets_the_rule(tree, hpc, monkeypatch):  # noqa: F811
    got, ctx = _recorded(tree, str(hpc["home"]), monkeypatch)
    bad, users = [], []
    for words, label in got:
        why = breaks(words, label, ctx)
        if why == ["user's"]:
            users.append(words)
        elif why:
            bad.append((words, why))
    assert not bad, "argv that break the rule:\n" + "\n".join(f"{w}: {y}" for w, y in bad)
    # a wrapped server's own `sh -c` is started unchanged, as the user's
    assert ["/bin/sh", "-c", "echo made-up-server"] in users, users


def test_the_page_lists_exactly_the_shapes_phiward_starts(tree, hpc, monkeypatch):  # noqa: F811
    got, ctx = _recorded(tree, str(hpc["home"]), monkeypatch)
    recorded = {shape(w, label, ctx) for w, label in got}
    page = all_shapes() if PAGE.exists() else set()
    assert recorded == page, ("recorded, not on the page:\n" + "\n".join(sorted(recorded - page))
                              + "\n\non the page, not recorded:\n"
                              + "\n".join(sorted(page - recorded)))
