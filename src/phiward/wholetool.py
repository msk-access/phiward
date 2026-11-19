"""`phiward launch`: run the whole agent tool in the kernel profile.

The tool itself starts inside the profile, so everything it does (its file tools, MCP servers
and hooks), and every child it starts, is decided by the kernel, not by a path check. The text
users see is HELP below; this docstring is for developers.

Writes are denied by default. They are allowed only in the project, this session's own run
folder (`~/.phiward/tools/<tool>/runs/<id>`) and the spool. A write place that is a link, or has
a link on its path, is not used. Inside the project, files that run code later stay read-only:
git's control files, `.git`, `.claude` and `.vscode` themselves, Claude Code's and VS Code's
settings and `.mcp.json`. On Linux, missing settings files are made as read-only `{}`
placeholders, and the git control files are compared after the session.

Carry-over (see carryover): each session runs in its own config folder, built from a trusted
copy and thrown away at exit. Reads of protected data and credentials are denied, and credential
variables are removed. The launcher runs the tool through a helper that closes every descriptor
it holds, writes the tool's settings without following links, and runs "launch inside launch"
directly only when the session's own profile is found: on macOS a canary that only this profile
denies is denied with EPERM; on Linux the tool's seccomp filter gives its fingerprint errno.
"""

import errno
import hashlib
import json
import os
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from phiward import carryover, config, confine, pathid, pathmatch, safeio
from phiward.hidden import (CREDENTIALS, IPC_PATHS, KRB5_CACHE_NAMES,  # noqa: F401 (moved)
                            KRB5_CACHE_PATTERNS, _kerberos_caches, _ssh_identity_files,
                            _token_paths)
from phiward.hidden import credentials as _credentials  # noqa: E402

USAGE = ("Run an agent tool, or one program, in phiward's kernel profile (Mode B), for example "
         "`phiward launch --tool claude`.\n"
         "usage: phiward launch [--tool NAME] [--memory] [--report FILE] [--entry ID] [--] "
         "[PROGRAM [ARG]...]\n")
HELP = USAGE + """
Options:
  --tool NAME   the agent tool: claude, or generic (the default). With claude and no
                PROGRAM, it starts `claude` from your PATH.
  --memory      turn Claude Code's auto memory on (it is off by default). Its changes go
                to quarantine like other instructions.
  --report FILE write a JSON report there when launch ends, for a script that runs it with
                nobody watching (`-- claude -p ...`): exit, ran, needs_review (true when the
                tool did not run, or the session changed instructions, files that run later,
                settings or git control files), project_changed (counts by kind) and the lines
                launch printed. Written on every exit, as a new file moved into place. FILE
                must be outside every place the session can write (the project, the spool,
                the temp folder, ~/.phiward); otherwise nothing runs.
  --entry ID    written by `phiward mcp wrap` into a wrapped MCP server's entry: the
                server's profile (also keeps the project's .git folders, .claude and .vscode
                read-only). Not for you to type.
  --            ends the options. PROGRAM and its arguments follow. With --tool generic,
                PROGRAM is required.
  -h, --help    show this help.

Run a whole agent tool, and everything it starts, in the kernel profile. The tool cannot
read protected data. It works with protected data only through the gateway (`phiward run`,
`phiward copy`), which masks what comes back.

Start it from the project folder, in your own terminal. It refuses to start in /, in your
home or a folder above it, in a dot folder of your home, in a folder that holds a phiward
folder, or in a folder inside or above protected data. It also refuses when the config has a
problem or when no protected paths are configured.

What the session can do:
- Write: only the project, its own session folder (in ~/.phiward/tools/<tool>/runs/) and the
  spool. Files in the project that run code later stay read-only: git control files,
  .claude and .vscode settings, and .mcp.json.
- Read: everything except the protected paths and credentials (~/.ssh, ~/.aws, tool logins,
  Kerberos tickets, and similar). Credential variables such as SSH_AUTH_SOCK are removed.
- Other processes: no keystroke injection, no signals to processes outside, no scripting of
  other apps. The network is open in this release.

When the session ends:
- The session's folder is thrown away. Each session starts from a trusted copy that no session
  can read or write.
- Changes to the tool's instructions and settings go to quarantine. Read and keep them with
  `phiward carryover show` and `phiward carryover accept ID`.
- Every file the session changed in the project is reported.
- No process is ended by phiward.

phiward checks its own installed files before it starts the tool. Set PHIWARD_DEV=1 to start
from a source checkout.
"""
MAX_DEPTH = 3


@dataclass
class Adapter:
    name: str
    program: str = ""  # the tool's command, found on the operator's PATH
    config_env: str = ""  # the variable that moves its config folder
    # state folders under HOME the tool uses; not write places: the operator's plain tool
    # reads them, so XDG_STATE_HOME and XDG_DATA_HOME point into the run folder instead
    home_writes: List[str] = field(default_factory=list)
    extra_env: Dict[str, str] = field(default_factory=dict)

    def turn_own_sandbox_off(self, folder_fd: int) -> None:
        """The tool's settings in its own folder: its sandbox off on macOS (sandboxes do not
        nest; this profile replaces it) and the fast hook as a first layer."""
        if self.name != "claude":
            return
        data = _read_json_at(folder_fd, "settings.json")
        before = json.dumps(data, sort_keys=True)
        if sys.platform == "darwin":
            sb = data.setdefault("sandbox", {})
            if isinstance(sb, dict):
                sb["enabled"] = False
        import shlex
        pkg = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        code = f"import sys; sys.path.insert(0, {pkg!r}); from phiward.cli import main; sys.exit(main())"
        cmd = f"{shlex.quote(sys.executable)} -I -S -c {shlex.quote(code)} hook claude --launched"
        hooks = data.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            hooks = data["hooks"] = {}
        pre = hooks.get("PreToolUse") if isinstance(hooks.get("PreToolUse"), list) else []
        # our entry replaced each time (phiward may have moved; a decoy left by a session
        # is dropped); other entries kept
        pre = [g for g in pre if not (isinstance(g, dict) and any(
            isinstance(h, dict) and "hook claude" in str(h.get("command", ""))
            and any(n in str(h.get("command", "")) for n in config.PROGRAMS)
            for h in g.get("hooks", []) if isinstance(g.get("hooks"), list)))]
        pre.append({"matcher": "Read|Grep|Glob|Bash|Edit|Write|NotebookEdit|MultiEdit",
                    "hooks": [{"type": "command", "command": cmd, "timeout": 5}]})
        hooks["PreToolUse"] = pre
        if json.dumps(data, sort_keys=True) != before:
            _write_at(folder_fd, "settings.json", json.dumps(data, indent=2) + "\n")


ADAPTERS: Dict[str, Adapter] = {
    "generic": Adapter("generic"),
    "claude": Adapter("claude", "claude", "CLAUDE_CONFIG_DIR",
                      [".local/state/claude", "Library/Caches/claude-cli-nodejs"],
                      # no auto-update; no download of the official plugin catalog into each fresh
                      # folder (~14 MB and 830 files every session)
                      {"DISABLE_AUTOUPDATER": "1",
                       "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1"}),
}

# the tool's environment is an allow-list (a deny pattern always misses some secret);
# the operator adds more with [launch] pass_env in the user config
PASS_ENV = {"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TERM_PROGRAM",
            "TERM_PROGRAM_VERSION", "COLORTERM", "LANG", "TZ", "EDITOR", "VISUAL", "PAGER", "LESS",
            "COLUMNS", "LINES", "NO_COLOR", "FORCE_COLOR", "SHLVL", "PWD", "HTTP_PROXY",
            "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy",
            "all_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS", "JAVA_HOME", "GOPATH", "GOROOT", "CONDA_PREFIX",
            "CONDA_DEFAULT_ENV", "VIRTUAL_ENV", "__CF_USER_TEXT_ENCODING",
            # module systems on HPC (Lmod, Environment Modules) and build paths
            "LD_LIBRARY_PATH", "MODULEPATH", "MODULESHOME", "LOADEDMODULES", "PKG_CONFIG_PATH",
            "MANPATH", "CPATH", "LIBRARY_PATH", "_LMFILES_"}
PASS_PREFIXES = ("LC_", "ANTHROPIC_", "CLAUDE_", "PHIWARD_", "LMOD_", "__LMOD_")


def _keep_env(k: str, extra: Sequence[str] = ()) -> bool:
    if k == "PHIWARD_HOOK_ROOTS":  # the v1 hook's list of protected roots
        return False
    return k in PASS_ENV or k.startswith(PASS_PREFIXES) or k in extra
# package caches, redirected into the session's own run folder and thrown away with it:
# a cache a session can write is code a later session runs
SESSION_CACHE_ENV = {"XDG_CACHE_HOME": "cache", "npm_config_cache": "cache/npm",
                     "BUN_INSTALL_CACHE_DIR": "cache/bun", "UV_CACHE_DIR": "cache/uv",
                     "PIP_CACHE_DIR": "cache/pip", "GOCACHE": "cache/go-build",
                     "GOMODCACHE": "cache/go-mod", "CARGO_HOME": "cache/cargo",
                     "GRADLE_USER_HOME": "cache/gradle", "YARN_CACHE_FOLDER": "cache/yarn",
                     "PRE_COMMIT_HOME": "cache/pre-commit", "POETRY_CACHE_DIR": "cache/poetry",
                     "XDG_STATE_HOME": "state", "XDG_DATA_HOME": "data"}
GIT_CONTROL = ("config", "commondir", "gitdir", "hooks", "info", "modules", "worktrees",
               "config.worktree", "shallow", "objects/info/alternates")
# .claude/settings.local.json can hold hooks too, which run later outside launch: read-only
#; the tool keeps its permission answers in its own folder
# a wrapped MCP server's profile: the project's folders that Claude Code, an editor or git runs
# code from, read-only as a whole (with every `.git` folder and entry in the project)
SERVER_READ_ONLY = (".claude", ".vscode", ".idea", ".gitmodules", ".ripgreprc")
PROJECT_SETTINGS = (".mcp.json", ".claude/settings.json", ".claude/settings.local.json",
                    ".vscode/settings.json", ".vscode/tasks.json", ".vscode/launch.json")
MACH_ALLOW = (
    "com.apple.SecurityServer", "com.apple.securityd.xpc", "com.apple.trustd",
    "com.apple.trustd.agent", "com.apple.ocspd", "com.apple.SystemConfiguration.configd",
    "com.apple.SystemConfiguration.DNSConfiguration", "com.apple.dnssd.service",
    "com.apple.system.opendirectoryd.libinfo", "com.apple.system.DirectoryService.libinfo_v1",
    "com.apple.system.notification_center", "com.apple.system.logger", "com.apple.logd",
    "com.apple.diagnosticd", "com.apple.cfprefsd.daemon", "com.apple.cfprefsd.agent",
    "com.apple.bsd.dirhelper", "com.apple.FSEvents", "com.apple.CoreServices.coreservicesd",
    "com.apple.lsd.mapdb", "com.apple.analyticsd", "com.apple.networkd",
    "com.apple.nsurlsessiond", "com.apple.nesessionmanager.content-filter",
)
_TIOCSTI_MACOS = 0x80017472
CANARY = "launch-canary"


class LaunchError(Exception):
    pass


# -- safe file work in agent-writable folders -----------------------------------


def _read_json_at(dfd: int, name: str) -> dict:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except FileNotFoundError:
        return {}
    except OSError:
        raise LaunchError(f"the tool's {name} is not a plain file (a link?)")
    try:
        st = os.fstat(fd)
        if (st.st_mode & 0o170000) != 0o100000 or st.st_nlink != 1:
            raise LaunchError(f"the tool's {name} is not a plain file with one link")
        data = json.loads(os.read(fd, 1 << 20).decode("utf-8") or "{}")
    except ValueError:
        data = {}
    finally:
        os.close(fd)
    return data if isinstance(data, dict) else {}


def _write_at(dfd: int, name: str, text: str) -> None:
    tmp = f".{name}.{secrets.token_hex(6)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                 dir_fd=dfd)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)


def _project_problem(project: str, env: Dict[str, str]) -> str:
    """The project folder is writable as a whole: it may not be `/`, the home folder or above
    it, a dot-folder in it, or hold a phiward folder."""
    home = os.path.realpath(pathid.home(env))
    if project == "/":
        return "it is /"
    if not project.startswith("/"):
        return "it is not an absolute folder"
    if _inside(home, project):
        return "it is the home folder or above it"
    if _inside(project, home) and os.path.relpath(project, home).split("/")[0].startswith("."):
        return "it is a dot-folder in the home folder"
    for g in config.guard_files(env) + [os.path.join(home, ".phiward"),
                                        os.path.join(home, config.LEGACY_STATE),
                                        os.path.dirname(config.legacy_user_config_path(env))]:
        if _inside(os.path.realpath(g), project):
            return "it holds a phiward file or folder"
    if sys.platform == "darwin" and _inside(project, os.path.join(home, "Library")):
        return "it is in ~/Library (LaunchAgents and preferences run later)"
    for e in (env.get("PATH") or "").split(":"):
        if e and os.path.isabs(e) and _inside(os.path.realpath(e), project):
            return "it holds a folder on PATH (programs there run later, outside launch)"
    return ""


def _fixed_folders(folder: str) -> None:
    """The tool folder's own subfolders: made when missing; a link a session put there is
    removed (unlink takes the link, not its target) and the folder made again."""
    if os.path.islink(folder):  # the operator's link, maybe: refused, never removed
        raise LaunchError("the tool folder is a link; make it a real folder")
    # the caches are made by carryover._layout, by descriptor (cache/ is a write place)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    if not _no_link_on_path(folder) or not os.path.isdir(folder):
        raise LaunchError("the tool folder is not a real folder")


def _inside(p: str, folder: str) -> bool:
    return pathid.inside(p, folder)


def _no_link_on_path(p: str) -> bool:
    return os.path.realpath(p) == os.path.normpath(p)


# -- places ------------------------------------------------------------------------------------

def _real_home(env: Dict[str, str]) -> str:
    """The home folder with the links above it resolved: those are the system's (HPC homes are
    often links); links below it are what a session could plant, and those are refused."""
    return os.path.realpath(pathid.home(env))


def tool_folder(adapter: Adapter, env: Dict[str, str]) -> str:
    return os.path.join(_real_home(env), ".phiward", "tools", adapter.name)


def _darwin_user_dir(name: str) -> str:
    try:
        r = subprocess.run(["/usr/bin/getconf", name], capture_output=True, text=True, timeout=5)
        return os.path.realpath(r.stdout.strip()) if r.returncode == 0 and r.stdout.strip() else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def write_places(project: str, env: Dict[str, str], run: str = "") -> List[str]:
    """The folders the tool may write; each one a real folder with no link on its path. In the
    tool folder only this session's run folder: not the folder itself, not `trash/`, not
    an earlier session's run folder."""
    spool = config.spool_dir(env)
    spool = os.path.join(os.path.realpath(os.path.dirname(spool)), os.path.basename(spool))
    want = [project] + ([run] if run else []) + [spool]
    # the adapter's HOME state folders are not write places (the operator's
    # plain tool reads them); XDG_STATE_HOME and XDG_DATA_HOME point into the run folder
    if sys.platform == "darwin":  # D16: the per-user temp folder (clang and Apple tools use it,
        t = _darwin_user_dir("DARWIN_USER_TEMP_DIR")  # whatever TMPDIR says); xcrun's cache in
        want += [t] if t else []                       # it stays denied (seatbelt_tool_profile)
    out: List[str] = []
    for p in want:
        p = os.path.normpath(p)
        if os.path.lexists(p) and not _no_link_on_path(p):
            sys.stderr.write("phiward launch: a write place is a link or has a link on its "
                             "path, so it is not used\n")
            continue
        if p not in out:
            out.append(p)
    return out


# -- macOS -------------------------------------------------------------------------------------

def _own_ttys() -> List[str]:
    out = []
    for fd in (0, 1, 2):
        try:
            if os.isatty(fd):
                out.append(os.path.realpath(os.ttyname(fd)))
        except OSError:
            pass
    return sorted(set(out))


def _rx(path: str) -> str:
    out = ""
    for ch in path:
        out += "\\" + ch if ch in ".^$+(){}[]|\\*?" else ch
    return out.replace('"', '\\"')


def seatbelt_tool_profile(cfg: config.Config, places: Sequence[str], project: str,
                          env: Dict[str, str], folder: str, canary: str,
                          server: bool = False) -> str:
    s = confine._sb_str
    rules = confine._sb_paths(cfg.all_roots, cfg.patterns)
    allow = [f"(subpath {s(p)})" for p in places]  # exactly as given: no resolved spellings
    allow += [f"(literal {s(d)})" for d in ("/dev/null", "/dev/zero", "/dev/dtracehelper",
                                              "/dev/tty", "/dev/ptmx", "/dev/stdout",
                                              "/dev/stderr")]
    allow.append('(regex #"^/dev/fd/[0-9]+$")')

    allow += [f"(literal {s(t)})" for t in _own_ttys()]
    ctl = "|".join(c.replace(".", "\\.").replace("/", "\\/") for c in GIT_CONTROL)
    ro: List[str] = []
    for gd, entry in git_dirs_in(project):
        ro.append(f'(regex #"^{_rx(gd)}/({ctl})(/.*)?$")')
        ro.append(f"(literal {s(entry)})")  # the .git entry itself: no rename or replacement
    # .claude is made at start (build); a missing .vscode cannot be made, so neither can become a
    # link to settings elsewhere
    ro += [f"(literal {s(os.path.join(project, t))})" for t in (".claude", ".vscode")]
    ro += [f"(literal {s(os.path.join(project, r))})" for r in PROJECT_SETTINGS]
    if server:
        # a wrapped MCP server (`--entry`) runs inside a Mode A session that is not confined:
        # what Claude Code, an editor or git later runs from the project is read-only as a
        # whole, made before the server starts or not (SERVER_READ_ONLY)
        ro += [f"(subpath {s(os.path.join(project, t))})" for t in SERVER_READ_ONLY]
        ro += [f"(subpath {s(gd)})" for gd, _entry in git_dirs_in(project)]
        ro.append(f'(regex #"^{_rx(project)}/(.*/)?\\.git(/.*)?$")')
    creds = [f"(subpath {s(c)})" for c in confine._spellings(_credentials(env, cfg))]
    tdir = _darwin_user_dir("DARWIN_USER_TEMP_DIR")
    for d in ["/private/tmp", "/private/var/tmp"] + ([tdir] if tdir else []):
        creds.append(f'(regex #"^{_rx(d)}/{KRB5_CACHE_NAMES}")')
    guards = [f"(subpath {s(g)})" for g in confine._spellings(config.guard_files(env))]
    above = list(cfg.all_roots) + [confine._pattern_prefix(p) for p in cfg.patterns]
    anc = [f"(literal {s(a)})" for a in confine._ancestors(above)]
    p = "(version 1)(allow default)"
    # the tool folder is not readable except this session's own run folder
    # (sessions cannot read each other or the trusted copy's neighbours)
    own = [q for q in places if q.startswith(os.path.join(folder, "runs") + os.sep)]
    p += f"(deny file-read* (subpath {s(folder)}))"
    p += "".join(f"(allow file-read* (subpath {s(q)}))" for q in own)
    # the folders above the run folder may be looked at (not listed), or path resolution fails
    # (Node's realpath, a shell's cd)
    p += (f"(allow file-read-metadata (literal {s(folder)}) "
          f"(literal {s(os.path.join(folder, 'runs'))}))")
    if rules:
        p += "(deny file* " + " ".join(rules) + ")"
    p += f"(deny file* (literal {s(canary)}))"
    p += "(deny file-read* file-write* " + " ".join(creds) + ")"
    p += "(deny file-write* (require-not (require-any " + " ".join(allow) + ")))"
    t = _darwin_user_dir("DARWIN_USER_TEMP_DIR")
    if t:  # xcrun's cache maps tool names to paths that /usr/bin shims use later: never written
        ro.append(f'(regex #"^{_rx(t)}/xcrun_db")')
    p += "(deny file-write* " + " ".join(ro + guards) + ")"
    if anc:
        p += "(deny file-write* " + " ".join(anc) + ")"
    p += "(deny process-info* (require-not (target same-sandbox)))"
    p += "(deny signal (require-not (target same-sandbox)))"
    p += f"(deny file-ioctl (ioctl-command #x{_TIOCSTI_MACOS:x}))"
    p += "(deny network-outbound (remote unix-socket))"
    # unix sockets only under this session's own run folder, never another run's (its tmux
    # server, for one)
    p += "".join(f"(allow network-outbound (remote unix-socket (subpath {s(q)})))" for q in own)
    # name lookups go through mDNSResponder's socket
    p += '(allow network-outbound (remote unix-socket (subpath "/private/var/run/mDNSResponder")))'
    p += "(deny lsopen)(deny appleevent-send)(deny user-preference-write)"
    p += "(deny mach-lookup)(allow mach-lookup " + " ".join(
        f"(global-name {s(m)})" for m in MACH_ALLOW) + ")"
    # terminals: only the session's own can be read or written (another terminal's
    # keystrokes could be read); new ptys need the pty relay
    p += '(deny file-read* file-write* (regex #"^/dev/ttys[0-9]+$"))'
    own = _own_ttys()
    if own:
        p += "(allow file-read* file-write* " + " ".join(f"(literal {s(t)})" for t in own) + ")"
    return p


def _sandbox_check_self() -> bool:
    """macOS: whether this process is already in any sandbox."""
    import ctypes
    for lib in ("/usr/lib/libSystem.B.dylib", "/usr/lib/system/libsystem_sandbox.dylib"):
        try:
            fn = ctypes.CDLL(lib).sandbox_check
        except (OSError, AttributeError):
            continue
        fn.restype = ctypes.c_int
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        return bool(fn(os.getpid(), None, 0))
    return True  # cannot tell: refuse (fail closed)


# -- Linux -------------------------------------------------------------------------------------

# The session's fingerprint: the tool's filter answers one unassigned syscall number with an
# errno that no kernel and no common filter returns. A filter is set by the kernel, inherited and
# never removed, so only an ancestor can make a process see it; a launch that sees it is inside
# phiward's session (already_confined). 360 is unassigned on x86_64 (335-423) and aarch64
# (295-402), and new syscalls take numbers from 424 up on every architecture. The errno is
# below 4096, so the C library reports it as errno.
FINGERPRINT_SYSCALL = 360
FINGERPRINT_ERRNO = 3917


def tool_seccomp_program(machine: Optional[str] = None) -> bytes:
    """No keystroke injection (ioctl TIOCSTI, TIOCLINUX: compared on the low 32 bits) and no
    kernel keyrings (keyctl, add_key, request_key: Kerberos KEYRING tickets); the x32 ABI is
    refused on x86_64; the fingerprint syscall fails with FINGERPRINT_ERRNO."""
    machine = machine or confine._machine()
    if machine not in confine._AUDIT_ARCH:
        raise confine.ConfineError(f"no seccomp filter for the {machine} architecture")
    col = 0 if machine == "x86_64" else 1
    ioctl = 16 if machine == "x86_64" else 29
    keys = [confine._DENY[k][col] for k in ("keyctl", "add_key", "request_key")]
    allow, kill, eperm = 0x7FFF0000, 0x80000000, 0x00050001
    ld, jeq, jge, ret = 0x20, 0x15, 0x35, 0x06
    prog = [(ld, 0, 0, 4), (jeq, 1, 0, confine._AUDIT_ARCH[machine]), (ret, 0, 0, kill),
            (ld, 0, 0, 0)]
    if machine == "x86_64":
        prog += [(jge, 0, 1, 0x40000000), (ret, 0, 0, eperm)]
    prog += [(jeq, 0, 1, FINGERPRINT_SYSCALL), (ret, 0, 0, 0x00050000 | FINGERPRINT_ERRNO)]
    for k in keys:
        prog += [(jeq, 0, 1, k), (ret, 0, 0, eperm)]
    prog += [(jeq, 0, 4, ioctl), (ld, 0, 0, 24), (jeq, 1, 0, 0x5412), (jeq, 0, 1, 0x541C),
             (ret, 0, 0, eperm), (ret, 0, 0, allow)]
    return b"".join(struct.pack("<HBBI", *i) for i in prog)


# system name-service sockets stay reachable (user and group lookups on clusters: sssd, nscd)
_NSS_SOCKETS = ("/var/lib/sss/pipes", "/var/run/nscd", "/run/nscd", "/run/systemd/userdb")


def _outside_sockets(places: Sequence[str]) -> List[str]:
    """Path unix sockets bound outside the tool's places (from /proc/net/unix; the path is the
    rest of the line after seven fields, so it may hold spaces)."""
    out: List[str] = []
    try:
        with open("/proc/net/unix", encoding="utf-8", errors="replace") as fh:
            next(fh, None)
            for line in fh:
                parts = line.rstrip("\n").split(None, 7)
                if len(parts) == 8 and parts[7].startswith("/") and \
                        not any(_inside(parts[7], n) for n in _NSS_SOCKETS):
                    p = parts[7]
                    if not any(_inside(p, pl) for pl in places) and os.path.lexists(p) and \
                            p not in out:
                        out.append(p)
    except OSError:
        pass
    return out


def git_dirs_in(project: str, limit: int = 50000) -> List[Tuple[str, str]]:
    """Every git folder in the project at launch: (the folder that holds the control files, the
    `.git` entry), for the top `.git`, nested repositories and the `.git` files of submodules and
    worktrees (their gitdir when it is inside the project). Links are never followed; the walk
    is bounded. Repositories made during the session are not covered (docs/threat-model.md:
    files that run later)."""
    out: List[Tuple[str, str]] = []
    seen = 0
    stack = [project]
    skip = {"node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache"}
    while stack and seen < limit:
        d = stack.pop()
        try:
            it = list(os.scandir(d))
        except OSError:
            continue
        for e in it:
            seen += 1
            if e.name == ".git":
                if e.is_dir(follow_symlinks=False):
                    out.append((e.path, e.path))
                elif e.is_file(follow_symlinks=False):
                    gd = _gitdir_of(e.path)
                    real = gd and _no_link_on_path(gd) and _inside(gd, project) and os.path.isdir(gd)
                    # a gitdir with a link on its path is never used: it is agent-written;
                    # the .git file itself is still covered
                    out.append((gd if real else e.path, e.path))
                continue
            if e.is_dir(follow_symlinks=False) and e.name not in skip:
                stack.append(e.path)
    return out


def _gitdir_of(dot_git: str) -> str:
    try:
        fd = os.open(dot_git, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            line = os.read(fd, 4096).decode("utf-8", "replace").strip().splitlines()[0]
        finally:
            os.close(fd)
    except (OSError, IndexError):
        return ""
    if not line.startswith("gitdir:"):
        return ""
    return os.path.normpath(os.path.join(os.path.dirname(dot_git), line[7:].strip()))


def _placeholders(project: str) -> List[str]:
    """D15: settings files that do not exist yet are made as read-only `{}` placeholders, so
    bubblewrap can cover them."""
    made = []
    rels = [".mcp.json", ".claude/settings.json", ".claude/settings.local.json"]
    if os.path.isdir(os.path.join(project, ".vscode")):
        rels += [".vscode/settings.json", ".vscode/tasks.json", ".vscode/launch.json"]
    nofollow = os.O_NOFOLLOW | os.O_CLOEXEC
    for rel in rels:
        sub, name = os.path.split(rel)
        # by descriptor, never through a link, and a file another launch made meanwhile is
        # simply there already (two wrapped MCP servers start at once)
        try:
            top = os.open(project, os.O_RDONLY | os.O_DIRECTORY | nofollow)
        except OSError:
            continue
        try:
            dfd = top
            if sub:
                try:
                    os.mkdir(sub, 0o755, dir_fd=top)
                except FileExistsError:
                    pass
                try:
                    dfd = os.open(sub, os.O_RDONLY | os.O_DIRECTORY | nofollow, dir_fd=top)
                except OSError:
                    continue  # a link or not a folder: not covered here
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o644,
                             dir_fd=dfd)
            except FileExistsError:
                continue
            except OSError:
                continue
            finally:
                if dfd != top:
                    os.close(dfd)
            with os.fdopen(fd, "w") as fh:
                fh.write("{}\n")
            made.append(rel)
        finally:
            os.close(top)
    return made


def _open_no_follow(path: str) -> int:
    """An O_PATH descriptor of a file or folder reached part by part without following a link:
    what is checked is what gets mounted."""
    if os.path.isdir(path) and not os.path.islink(path):
        return confine.open_place(path)
    parent = confine.open_place(os.path.dirname(path))
    try:
        return os.open(os.path.basename(path), os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,  # type: ignore[attr-defined]
                       dir_fd=parent)
    finally:
        os.close(parent)


# bwrap takes at most 9000 arguments; the snapshot view may use this many, the rest of the command
# line needs the others (counted in full before bwrap runs)
BWRAP_MAX_ARGS = 9000
VIEW_ARGS = 7500
_OP_ARGS = {"tmpfs": 4, "bind": 3, "symlink": 3, "mask": 3}  # a tmpfs is also made read-only


def hidden_view(literal: Sequence[str], patterns: Sequence[str], replaced: Sequence[str] = (),
                limit: int = VIEW_ARGS, may_skip: Sequence[str] = (),
                soft_patterns: Sequence[str] = (), named: Optional[Sequence[str]] = None
                ) -> Tuple[List[Tuple[str, ...]], List[str], List[str]]:
    """The Linux session's view of the file system, as mount operations; the folders made for
    it; and the folders shown whole because they hold too many entries.

    Every folder above a hidden path is "split": in the view it is an empty tmpfs, and each
    entry it held at the start is bound back (a link is made again as a link), except the hidden
    ones. A hidden path is never mounted over, so a protected path replaced, or a match made
    after the start, is not in the view. For a pattern, every folder where a match could be
    made is split, for the pattern as written and with its literal part resolved (a pattern
    through a linked folder). Names are compared case-folded, so a
    case-insensitive file system cannot show a hidden name in another case; on a
    case-sensitive one this hides a little more, never less.

    A split folder that can be entered but not listed (mode 711, common on HPC) cannot be
    rebuilt: it is bound whole, and the hidden paths in it that exist are masked in place
    ("mask"). There, a match made later is not hidden. The same is done for split folders when
    the view would not fit in `limit` bwrap arguments (a folder of thousands of entries above a
    protected one), those that save the most arguments first. Shown whole, a folder lists its
    masked entries by name, so this is never done for `/`, for a folder where a wildcard names a
    hidden entry, or for the folder that holds a `named` hidden path (a protected root, whose
    name may be a person's; default: every literal path not in `may_skip`): launch refuses
    then. The cost elsewhere: what the host adds to a split folder after the start is not seen
    until the next session, and a file the host replaces in it stays as it was.

    Protection follows the path, as on macOS: a protected folder that the host moves into a
    folder the session sees is readable there.

    A pattern whose wildcard part falls on a folder that cannot be listed cannot be covered:
    launch refuses (protect that folder as a root). A link at a wildcard level is not followed:
    its target is not hidden by the pattern.

    `may_skip`: credential files that need no hiding when they belong to another user and
    cannot be read (a system keytab); never protected paths. `soft_patterns`: patterns that
    are skipped where a folder cannot be listed, instead of refused (the Kerberos cache names).

    Operations: ("tmpfs", dir), ("bind", path), ("symlink", target, path), ("mask", path).
    Paths under `replaced` (the session's own /tmp, the hidden tool folder) are left to the
    caller."""
    import unicodedata

    def fold(x: str) -> str:  # case and Unicode form: ext4 casefold treats both as equal
        return unicodedata.normalize("NFD", x).casefold()
    skippable = {os.path.normpath(x) for x in may_skip}
    split: Dict[str, str] = {}   # folded -> as found
    hidden: Dict[str, str] = {}  # folded -> as written
    wild: Set[str] = set()  # folded folders where a wildcard names a hidden entry

    def under_replaced(x: str) -> bool:
        return any(x == r or _inside(x, r) for r in replaced)

    def chain(d: str) -> None:
        while True:
            split.setdefault(fold(d), d)
            if d == "/":
                return
            d = os.path.dirname(d)

    def real_dir(d: str) -> bool:
        return os.path.isdir(d) and not os.path.islink(d)

    def unreadable_to_us(p: str) -> bool:
        # another user's file we cannot read (a system keytab in /etc): hiding it would only
        # split its folder, and a split folder shows host changes late
        try:  # a file only: a folder that cannot be listed may still be entered (mode 711)
            st = os.lstat(p)
        except OSError:
            return False
        return (st.st_uid != os.getuid() and not stat.S_ISDIR(st.st_mode) and
                not os.access(p, os.R_OK))

    keep_names = {os.path.normpath(x) for x in
                  (named if named is not None else [h for h in literal if h not in may_skip])}
    named_dirs: Set[str] = set()  # folded folders that hold a hidden path whose name must not show
    for h in literal:
        h = os.path.normpath(h)
        for p in {os.path.join(os.path.realpath(os.path.dirname(h)), os.path.basename(h)),
                  os.path.realpath(h)}:
            if p == "/" or under_replaced(p) or (h in skippable and unreadable_to_us(p)):
                continue
            d = os.path.dirname(p)
            while d != "/" and not real_dir(d):
                d = os.path.dirname(d)
            chain(d)
            hidden.setdefault(fold(p), p)
            if h in keep_names:
                named_dirs.add(fold(os.path.dirname(p)))
    soft = set(confine._pattern_spellings(list(soft_patterns)))
    for pat in confine._pattern_spellings(list(patterns) + list(soft_patterns)):
        pp = pathmatch.parts(pat)
        level = ["/"]
        for k, part in enumerate(pp):
            last, nxt = k == len(pp) - 1, []
            for base in level:
                if under_replaced(base):
                    continue
                chain(base)
                try:
                    names = [n for n in os.listdir(base) if pathmatch.match_part(part, n) or
                             fold(n) == fold(part)]
                except OSError:
                    if pathmatch.WILD.search(part) and pat not in soft:
                        raise LaunchError("a folder where a protected pattern could match cannot "
                                          "be listed, so the pattern cannot cover it; protect that "
                                          "folder as a root instead")
                    names = []  # not listable: the literal name is still hidden below
                if not pathmatch.WILD.search(part):
                    names.append(part)
                for n in set(names):
                    c = os.path.join(base, n)
                    if not last and real_dir(c):
                        nxt.append(c)
                    else:
                        hidden.setdefault(fold(c), c)  # a match, or a link where its folder would be
                        if pathmatch.WILD.search(part):
                            wild.add(fold(base))  # a hidden name a wildcard chose
            level = nxt
    whole: Set[str] = set()  # folded split folders shown whole: too many entries to rebuild
    ops = _view_ops(split, hidden, whole, under_replaced, fold)
    total = sum(_OP_ARGS[o[0]] for o in ops)
    if total > limit:
        whole = _shrink(split, hidden, under_replaced, fold, wild | named_dirs, total, limit)
        ops = _view_ops(split, hidden, whole, under_replaced, fold)
        if sum(_OP_ARGS[o[0]] for o in ops) > limit:
            crowded = any(f in named_dirs or f in wild for f in split)
            raise LaunchError(f"the protected paths need more than {limit} mount arguments in the "
                              "session's view; protect fewer, larger folders" + (
                                  " (a folder that holds a protected root or pattern matches "
                                  "among many entries cannot be shown whole, since it would list "
                                  "their names: protect that folder as a root instead)"
                                  if crowded else ""))
    return (ops, sorted(set(split.values()), key=lambda x: (x.count("/"), x)),
            sorted(split[f] for f in whole))


def _shrink(split: Dict[str, str], hidden: Dict[str, str], under_replaced: Callable[[str], bool],
            fold: Callable[[str], str], never: Set[str], total: int, limit: int) -> Set[str]:
    """The split folders to show whole so the view fits in `limit` arguments: those that save
    the most first. A folder's own mounts depend only on whether it and its parent are shown
    whole (`_view_ops`), so each choice changes the savings of its parent and children only."""
    import heapq
    own: Dict[str, int] = {}    # entries rebuilt: a bind or a link each
    masks: Dict[str, int] = {}  # hidden entries on disk: a mask each when shown whole
    listable: Dict[str, bool] = {}
    kids: Dict[str, List[str]] = {f: [] for f in split}
    parent: Dict[str, Optional[str]] = {}

    def gone(f: str) -> bool:  # hidden, or below a hidden folder: never in the view
        while True:
            if f in hidden:
                return True
            up = os.path.dirname(f)
            if up == f:
                return False
            f = up
    for f, x in split.items():
        if gone(f):
            continue
        p = fold(os.path.dirname(x)) if x != "/" else None
        parent[f] = p if p in split else None
        if parent[f] is not None:
            kids[p].append(f)
        own[f] = masks[f] = 0
        try:
            names = os.listdir(x)
            listable[f] = True
        except OSError:
            listable[f] = False
            continue
        for n in names:
            c = os.path.join(x, n)
            fc = fold(c)
            if fc in hidden:
                masks[f] += 1
            elif not (fc in split or under_replaced(c) or (x == "/" and n in ("proc", "dev"))):
                own[f] += 1
    whole: Set[str] = set()

    def shown_whole(f: Optional[str]) -> bool:
        return f is not None and (f in whole or not listable[f])

    def gain(f: str) -> int:
        rebuilt = _OP_ARGS["tmpfs"] + _OP_ARGS["bind"] * own[f]
        as_whole = (0 if shown_whole(parent[f]) else _OP_ARGS["bind"]) + _OP_ARGS["mask"] * masks[f]
        # a child shown whole needs no bind of its own inside a folder shown whole
        return rebuilt - as_whole + _OP_ARGS["bind"] * sum(1 for k in kids[f] if shown_whole(k))
    open_ = [f for f, x in split.items()
             if x != "/" and f in listable and listable[f] and f not in never]
    heap = [(-gain(f), f) for f in open_]
    heapq.heapify(heap)
    while total > limit and heap:
        g, f = heapq.heappop(heap)
        if f in whole:
            continue
        now = gain(f)
        if now != -g:  # changed since it was queued
            heapq.heappush(heap, (-now, f))
            continue
        if now <= 0:
            break
        whole.add(f)
        total -= now
        for k in [parent[f]] + kids[f]:
            if k is not None and k in listable and split[k] != "/" and listable[k] \
                    and k not in never and k not in whole:
                heapq.heappush(heap, (-gain(k), k))
    return whole


def _view_ops(split: Dict[str, str], hidden: Dict[str, str], whole: Set[str],
              under_replaced: Callable[[str], bool],
              fold: Callable[[str], str]) -> List[Tuple[str, ...]]:
    """The mount operations of `hidden_view`, with the folders in `whole` shown whole."""
    ops: List[Tuple[str, ...]] = []

    def emit(d: str, inside_whole: bool = False) -> None:
        try:
            names = sorted(os.listdir(d))
            listable = fold(d) not in whole
        except OSError:
            names, listable = [], False
        if not listable and d != "/":
            # bound whole (or already visible inside a folder bound whole): rebuild below it
            # only what is known, and mask the hidden entries that exist
            if not inside_whole:
                ops.append(("bind", d))
            for f, x in sorted(split.items()):
                # a hidden folder that is also split (a pattern walks it) is masked below,
                # not rebuilt: nothing of it shows
                if x != d and os.path.dirname(f) == fold(d) and f not in hidden:
                    emit(os.path.join(d, os.path.basename(x)), True)
            # every entry whose folded name is hidden, by the name it has on disk (a case or
            # Unicode form other than the one written): as hidden as in a rebuilt folder
            try:
                on_disk = [os.path.join(d, n) for n in sorted(os.listdir(d))
                           if fold(os.path.join(d, n)) in hidden]
            except OSError:  # cannot be listed: the names as written
                on_disk = [os.path.join(d, os.path.basename(x)) for f, x in sorted(hidden.items())
                           if os.path.dirname(f) == fold(d)
                           and os.path.lexists(os.path.join(d, os.path.basename(x)))]
            ops.extend(("mask", c) for c in on_disk)
            return
        ops.append(("tmpfs", d)) if d != "/" else None
        for n in names:
            c = os.path.join(d, n)
            fc = fold(c)
            if fc in hidden or under_replaced(c) or (d == "/" and n in ("proc", "dev")):
                continue
            if fc in split:
                emit(c)
            elif os.path.islink(c):
                ops.append(("symlink", os.readlink(c), c))
            elif os.path.lexists(c):
                ops.append(("bind", c))

    emit("/")
    return ops


def bwrap_tool_args(cfg: config.Config, places: Sequence[str], project: str,
                    env: Dict[str, str], folder: str, run: str,
                    server: bool = False) -> Tuple[List[str], List[int]]:
    # a root that does not exist is hidden like the others: its folder is split, so a root made
    # later is not in the view either (a launch inside another sandbox may see no root at all)
    args: List[str] = []
    fds: List[int] = []
    hide = (confine._spellings(list(cfg.all_roots)) + _credentials(env, cfg) + list(IPC_PATHS) +
            [os.path.join(_real_home(env), config.LEGACY_STATE)])
    ops, split, whole = hidden_view(hide, list(cfg.patterns), replaced=["/tmp", folder],
                                    may_skip=_credentials(env, cfg) + list(IPC_PATHS),
                                    soft_patterns=KRB5_CACHE_PATTERNS,
                                    named=confine._spellings(list(cfg.all_roots)))
    if whole:
        sys.stderr.write(f"phiward launch: {len(whole)} folder(s) above protected paths hold too "
                         "many entries to rebuild, so they are shown whole with their protected "
                         "entries masked; a protected entry made or replaced in them during the "
                         "session is not hidden\n")
    gits = git_dirs_in(project)
    guards = confine._spellings(config.guard_files(env))
    # a descriptor for every bind: the view's, then the places, the tool's /tmp, the project's
    # .claude and .vscode, the git control files, the settings files and the guard files
    _raise_fd_limit(sum(1 for o in ops if o[0] == "bind") + len(places) + 3 +
                    len(gits) * (len(GIT_CONTROL) + 1) + len(PROJECT_SETTINGS) + len(guards) + 64)

    def bind(path: str, ro: bool, dest: Optional[str] = None) -> None:
        try:
            fd = _open_no_follow(path)
        except (OSError, confine.ConfineError) as exc:
            if os.path.lexists(path) and _no_link_on_path(path):
                # not a link on the way: a read-only bind left out would leave the file
                # writable through the place above it
                why = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
                raise LaunchError(f"{path} cannot be opened to mount it in the session's view "
                                  f"({why}); nothing runs")
            return  # a link on the way: not mounted (and so not reachable through it)
        os.set_inheritable(fd, True)
        fds.append(fd)
        args.extend(["--ro-bind" if ro else "--bind", f"/proc/self/fd/{fd}", dest or path])

    # the snapshot view first: nothing hidden is in it, and every later mount lands on top
    for op in ops:
        if op[0] == "tmpfs":
            args += ["--tmpfs", op[1]]
        elif op[0] == "symlink":
            args += ["--symlink", op[1], op[2]]
        elif op[0] == "mask":
            args += ["--tmpfs", op[1]] if os.path.isdir(op[1]) and not os.path.islink(op[1]) \
                else ["--ro-bind", "/dev/null", op[1]]
        else:
            n = len(args)
            bind(op[1], True)
            if len(args) == n:
                raise LaunchError("an entry of the session's view changed while it was made; "
                                  "start again")
    args += ["--dev", "/dev", "--proc", "/proc", "--unshare-pid", "--unshare-ipc",
             "--die-with-parent"]
    # outside sockets first (before /tmp is replaced), then the tool's own temp folder as /tmp,
    # then the write places on top (a project under /tmp stays visible)
    for sock in _outside_sockets(list(places)):
        args += ["--ro-bind-try", "/dev/null", sock]
    # the tool folder is hidden: a session sees only its own run folder, bound back below
    # (sessions cannot read each other)
    args += ["--tmpfs", folder]
    bind(os.path.join(run, "tmp"), False, "/tmp")
    for p in places:
        if os.path.isdir(p) and _no_link_on_path(p):
            bind(p, False)
    # files that run code later, by descriptor: folders as mount points (no rename), control and
    # settings files read-only
    for top in (".claude", ".vscode"):
        q = os.path.join(project, top)
        if os.path.isdir(q) and _no_link_on_path(q):
            bind(q, server)  # a wrapped MCP server: read-only as a whole
    for gd, entry in gits:
        if _no_link_on_path(entry):
            bind(entry, not os.path.isdir(entry) or server)
        if gd != entry and not _no_link_on_path(gd):
            continue
        if server:
            bind(gd, True)  # the whole git folder: no index, config, commondir or hooks
            continue
        for c in GIT_CONTROL:
            q = os.path.join(gd, c)
            if os.path.lexists(q) and _no_link_on_path(q):
                bind(q, True)
    for rel in PROJECT_SETTINGS:
        q = os.path.join(project, rel)
        if os.path.lexists(q) and _no_link_on_path(q):
            bind(q, True)
    for g in guards:
        if os.path.lexists(g) and _no_link_on_path(g):
            bind(g, True)
    # masks last, for a hidden path under a place bound above (the view cannot leave it out
    # there): nothing mounted above can re-expose it
    rebound = list(places) + [project] + [g for g in guards
                                          if os.path.isdir(g)]
    for r in confine._spellings(hide + confine._pattern_matches(cfg.patterns)):
        if not any(_inside(r, q) for q in rebound):
            continue
        if os.path.isdir(r):
            args += ["--tmpfs", r]
        elif os.path.lexists(r):
            args += ["--ro-bind", "/dev/null", r]
    # the split folders are read-only, like the host they stand for (each one mount only)
    made = {op[1] for op in ops if op[0] == "tmpfs"} | {"/"}
    for d in reversed(split):
        if d in made:
            args += ["--remount-ro", d]
    # with --seccomp, --chdir and `--`, and after it the helper, a descriptor number for each
    # bind and the tool (`_bwrap_command` counts the whole line once it is known)
    need = len(args) + 8 + len(fds) + 8
    if need > BWRAP_MAX_ARGS:
        for fd in fds:
            os.close(fd)
        raise LaunchError(_too_long(need))
    return args, fds


def _too_long(n: int) -> str:
    return (f"the session needs {n} bwrap arguments and bwrap takes at most {BWRAP_MAX_ARGS}; "
            "protect fewer, larger folders (each pattern match inside the project is masked on "
            "its own)")


def _bwrap_command(bwrap: str, seccomp_fd: int, args: Sequence[str], project: str,
                   helper: Sequence[str], held: Sequence[str], argv: Sequence[str]) -> List[str]:
    """The bwrap command line. bwrap counts every word of it, the ones after `--` too, and
    stops above BWRAP_MAX_ARGS: phiward refuses first, and says why."""
    cmd = [bwrap, "--seccomp", str(seccomp_fd)] + list(args) + ["--chdir", project, "--"] + \
        list(helper) + [str(len(held))] + list(held) + list(argv)
    if len(cmd) - 1 > BWRAP_MAX_ARGS:
        raise LaunchError(_too_long(len(cmd) - 1))
    return cmd


def _raise_fd_limit(need: int) -> None:
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft != resource.RLIM_INFINITY and soft < need:
        if hard != resource.RLIM_INFINITY and hard < need:
            raise LaunchError(f"the session's view needs {need} open files; the limit is {hard}")
        resource.setrlimit(resource.RLIMIT_NOFILE, (need, hard))


# the helper the tool starts through: it closes the launcher's descriptors, applies the Landlock
# scope for abstract unix sockets and signals where the kernel has it (ABI 6), and execs the tool
HELPER = r"""
import os, sys, ctypes, struct
n = int(sys.argv[1]); close = sys.argv[2:2 + n]; cmd = sys.argv[2 + n:]
for c in close:
    try:
        os.close(int(c))
    except OSError:
        pass
if sys.platform.startswith("linux"):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1))
    if abi >= 6:
        attr = struct.pack("<QQQ", 0, 0, 3)  # no file rights handled; scope: abstract unix, signals
        buf = ctypes.create_string_buffer(attr, len(attr))
        rs = libc.syscall(444, buf, ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
        ok = rs >= 0 and libc.prctl(38, 1, 0, 0, 0) == 0 and libc.syscall(446, ctypes.c_int(rs), ctypes.c_uint32(0)) == 0
        if rs >= 0:
            os.close(rs)
        if not ok:
            sys.stderr.write("phiward launch: WARNING: the Landlock scope could not be applied: abstract unix sockets outside stay reachable\n")
    else:
        sys.stderr.write("phiward launch: no Landlock scope on this kernel: abstract unix sockets outside stay reachable\n")
try:
    os.execvp(cmd[0], cmd)
except OSError as e:
    sys.stderr.write("phiward launch: the tool could not start (%s)\n" % e.strerror); os._exit(127)
"""


def _git_snapshot(project: str, limit: int = 20000) -> Dict[str, str]:
    """The git control files of every git folder in the project: content hashes, with links
    recorded and never followed, only below folders with no link on their path, at most
    `limit` entries."""
    out: Dict[str, str] = {}
    for gd, entry in git_dirs_in(project):
        for q in [entry] + [os.path.join(gd, c) for c in GIT_CONTROL]:
            if len(out) >= limit or not os.path.lexists(q):
                continue
            if not _no_link_on_path(os.path.dirname(q)):
                out[q] = "link on the path"
                continue
            if os.path.islink(q):
                out[q] = "link:" + os.readlink(q)
                continue
            if os.path.isdir(q) and q != entry:
                for dirpath, dirs, files in os.walk(q, followlinks=False):
                    for n in dirs + files:
                        if len(out) >= limit:
                            break
                        x = os.path.join(dirpath, n)
                        out[x] = _digest(x)
            elif os.path.isfile(q):
                out[q] = _digest(q)
    return out


def _digest(path: str) -> str:
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            return "link:" + os.readlink(path)
        if not stat.S_ISREG(st.st_mode):
            return "dir" if stat.S_ISDIR(st.st_mode) else "special"
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            return hashlib.sha256(os.read(fd, 1 << 20)).hexdigest()
        finally:
            os.close(fd)
    except OSError:
        return "?"


# -- the launcher ------------------------------------------------------------------------------

def _canary_path(env: Dict[str, str]) -> str:
    home = pathid.home(env)
    return os.path.join(home, ".phiward", CANARY)


def _make_canary(canary: str) -> None:
    """Make the canary unless it is there. Another launch may make it at the same moment (two
    wrapped MCP servers start at once): that is fine, its content does not matter;
    already_confined checks what is there."""
    try:
        fd = os.open(canary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except FileExistsError:
        return
    with os.fdopen(fd, "w") as fh:
        fh.write("the agent profile denies this file; launch checks it\n")


def _fingerprint_errno() -> int:
    """Linux: the errno the fingerprint syscall fails with (0 when it does not fail)."""
    import ctypes
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        return 0
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    if libc.syscall(ctypes.c_long(FINGERPRINT_SYSCALL)) != -1:
        return 0
    return ctypes.get_errno()


def already_confined(env: Dict[str, str]) -> bool:
    """macOS: True only when the canary that only this profile denies is denied with EPERM
    (ordinary permissions give EACCES and do not count). Linux: True only when the fingerprint
    syscall fails with exactly FINGERPRINT_ERRNO; no filter (ENOSYS), another filter (EPERM or
    any other errno), or a filter set later inside the session that answers it too, all build
    the full profile."""
    if sys.platform.startswith("linux"):
        return confine._machine() in confine._AUDIT_ARCH and \
            _fingerprint_errno() == FINGERPRINT_ERRNO
    if sys.platform != "darwin":
        return False
    # both must hold: this process is in a sandbox at all, and the canary that only phiward's
    # profile denies is denied. A canary replaced by a link into a folder macOS guards (privacy
    # folders give EPERM too), or another sandbox that denies ~/.phiward, must not let launch
    # skip its own profile
    if not _sandbox_check_self():
        return False
    canary = _canary_path(env)
    try:
        st = os.lstat(canary)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
            return False
    except OSError as exc:
        if exc.errno != errno.EPERM:
            return False
    try:
        fd = os.open(canary, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        os.close(fd)
        return False
    except OSError as exc:
        if exc.errno != errno.EPERM:
            return False
    # and the spool, a write place of phiward's own profile, is readable: another sandbox that
    # denies all of ~/.phiward does not pass for phiward's
    try:
        fd = os.open(config.spool_dir(env), os.O_RDONLY | os.O_DIRECTORY)
        os.close(fd)
    except OSError:
        return False
    return True


def _make_dot_claude(project: str) -> None:
    """`.claude` is made before the tool starts (after every check), so the session cannot make
    it a link."""
    p = os.path.join(project, ".claude")
    try:
        os.mkdir(p, 0o755)
    except FileExistsError:
        pass  # there already, or another launch in this project made it just now
    st = os.lstat(p)
    if not stat.S_ISDIR(st.st_mode):
        raise OSError(errno.ENOTDIR, "the project's .claude is not a folder (a link?)", p)


def build(argv: Sequence[str], cwd: str, env: Dict[str, str], adapter: Adapter,
          memory: bool = False, store: Optional[carryover.Store] = None,
          server: bool = False) -> Tuple[List[str], Dict[str, str], List[int], str]:
    cfg = config.load(cwd, env=env)
    if cfg.problem:
        raise LaunchError("the phiward config cannot be used (run phiward doctor)")
    if not cfg.has_protected_paths:
        raise LaunchError("no protected paths are configured: there is nothing to confine")
    from phiward import paths
    project = os.path.realpath(cwd)
    # only the configured roots count for "above": a derived git folder inside the project
    # must not stop work there
    if paths.ProtectedSet(cfg.all_roots, cfg.patterns).relation(project) == paths.INSIDE or \
            paths.ProtectedSet(cfg.roots, cfg.patterns).relation(project) == paths.ABOVE:
        raise LaunchError("this folder is inside or above a protected path; start the tool in a "
                          "project folder")
    why = _project_problem(project, env)
    if why:
        raise LaunchError(f"this folder cannot be the project ({why}); start the tool in a "
                          "project folder")
    # a settings path that is already a link would carry the session's writes to a file a later
    # plain run reads: refused
    for rel in (".claude", ".vscode") + PROJECT_SETTINGS:
        if os.path.islink(os.path.join(project, rel)):
            raise LaunchError(f"{rel} in the project is a link; replace it with a real file or "
                              "folder")
    folder = tool_folder(adapter, env)
    _fixed_folders(folder)
    # this session's own folder: its config folder, built from the trusted copy, and its
    # temp folder; discarded after it, so nothing a session leaves there is read again
    run = os.path.join(folder, carryover.RUNS, time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(4))
    store = store if store is not None else carryover.Store(adapter.name, _real_home(env))
    try:
        for line in store.start(folder, run, memory, adapter.turn_own_sandbox_off):
            sys.stderr.write(line + "\n")
    except (carryover.CarryoverError, OSError, RecursionError) as exc:
        raise LaunchError(f"carry-over: {exc}")
    if adapter.name == "claude" and not any(env.get(k) for k in (
            "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")):
        sys.stderr.write("phiward launch: each session starts with a fresh config folder, so "
                         "Claude Code asks you to log in every time; to log in once, run `claude "
                         "setup-token` and set CLAUDE_CODE_OAUTH_TOKEN (the agent can read it)\n")
    tmp = os.path.join(run, "tmp")
    os.makedirs(tmp, mode=0o700, exist_ok=True)
    canary = _canary_path(env)
    if sys.platform == "darwin":
        _make_canary(canary)
    child_env = {k: v for k, v in env.items() if _keep_env(k, cfg.launch_pass_env)}
    child_env["TMPDIR"] = tmp
    for k, rel in SESSION_CACHE_ENV.items():
        child_env[k] = os.path.join(run, rel)
        os.makedirs(child_env[k], mode=0o700, exist_ok=True)
    if sys.platform == "darwin":
        # xcrun's cache maps tool names to paths that /usr/bin shims use later: not used and not
        # writable; clang's module cache goes into the tool's folder
        child_env["xcrun_nocache"] = "1"
        child_env["CLANG_MODULE_CACHE_PATH"] = os.path.join(run, "cache", "clang")
    child_env["TMUX_TMPDIR"] = tmp  # tmux's sockets in the session's folder
    child_env.update(adapter.extra_env)
    if adapter.name == "claude":  # auto memory off unless asked
        if memory:
            child_env.pop("CLAUDE_CODE_DISABLE_AUTO_MEMORY", None)
        else:
            child_env["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] = "1"
    if adapter.config_env:
        child_env[adapter.config_env] = os.path.join(run, "config")
        if adapter.name == "claude":
            child_env["CLAUDE_CODE_TMPDIR"] = tmp
    child_env["PHIWARD_HOOK_ROOTS"] = json.dumps(sorted(set(cfg.all_roots)))
    child_env["PHIWARD_LAUNCH_DEPTH"] = str(int(env.get("PHIWARD_LAUNCH_DEPTH", "0") or 0) + 1)
    os.makedirs(config.spool_dir(env), mode=0o700, exist_ok=True)
    places = write_places(project, env, run)
    # phiward's own files as installed, unchanged, owned by the operator or root
    from phiward import selfcheck
    installed, problems = selfcheck.check_isolated()
    if not installed and env.get("PHIWARD_DEV") != "1":
        raise LaunchError("phiward has no install record to check itself against (a source "
                          "checkout or an editable install); install it with uv tool or pipx, "
                          "or set PHIWARD_DEV=1 to start anyway")
    if problems:
        raise LaunchError(selfcheck.refusal(problems) + "; " +
                          selfcheck.fix_text(problems, selfcheck._running_package()))
    backend = confine.backend()
    helper = [sys.executable, "-I", "-S", "-c", HELPER]
    if backend == "seatbelt":
        if _sandbox_check_self():
            raise LaunchError("this process is inside another sandbox; macOS cannot apply a second "
                              "one (start the tool from a plain terminal)")
        _make_dot_claude(project)
        prof = seatbelt_tool_profile(cfg, places, project, env, folder, canary, server)
        return [confine.SANDBOX_EXEC, "-p", prof] + helper + ["0"] + list(argv), child_env, [], \
            project
    if backend == "bwrap":
        if not os.path.isfile(config.user_config_path(env)):
            raise LaunchError("no user config exists, and on Linux the tool could create one; "
                              "run phiward setup first")
        _make_dot_claude(project)
        made = _placeholders(project)
        if made:
            sys.stderr.write("phiward launch: made read-only placeholders in the project: "
                             f"{', '.join(made)}\n")
        args, fds = bwrap_tool_args(cfg, places, project, env, folder, run, server)
        r, w = os.pipe()
        os.write(w, tool_seccomp_program())
        os.close(w)
        os.set_inheritable(r, True)
        held = [str(fd) for fd in fds]
        bwrap = shutil.which("bwrap", path="/usr/bin:/bin") or "bwrap"
        try:
            cmd = _bwrap_command(bwrap, r, args, project, helper, held, argv)
        except LaunchError:
            for fd in fds + [r]:
                os.close(fd)
            raise
        return cmd, child_env, fds + [r], project
    raise LaunchError("no confinement backend on this system")


class _Run:
    """What one `launch` did, for `--report`."""

    def __init__(self) -> None:
        self.ran = False
        self.notes: List[str] = []       # every line launch printed at the end, in order
        self.carryover: List[str] = []   # the session's instructions and folders (quarantine)
        self.groups: Dict[int, List[Tuple[str, str]]] = {}  # changed project files by kind
        self.git: List[str] = []         # changed git control files (Linux)
        self.truncated = False           # the project scan was cut short

    def say(self, line: str) -> None:
        sys.stderr.write(line + "\n")
        self.notes.append(line)

    def data(self, code: Optional[int]) -> Dict[str, object]:
        kinds = {k: len(self.groups.get(i, [])) for i, k in enumerate(carryover.KINDS)}
        return {"exit": code, "ran": self.ran,
                "needs_review": (not self.ran or bool(self.carryover) or bool(self.git)
                                 or self.truncated or any(kinds[k] for k in carryover.KINDS[:3])),
                "carryover": self.carryover, "project_changed": kinds,
                "git_control_changed": self.git, "notes": self.notes}


def main(argv: List[str]) -> int:
    tool = "generic"
    rest = list(argv)
    if rest[:1] in (["-h"], ["--help"]):
        sys.stdout.write(HELP)
        return 0
    memory = False
    report = ""
    server = False
    while rest[:1] in (["--tool"], ["--memory"], ["--report"], ["--entry"]):
        if rest[0] == "--entry" and len(rest) >= 2:
            # the id `phiward mcp wrap` gives an entry: part of this launcher's record, and a
            # wrapped MCP server's profile (SERVER_READ_ONLY)
            rest, server = rest[2:], True
        elif rest[0] == "--memory":
            memory, rest = True, rest[1:]
        elif rest[0] == "--report" and len(rest) >= 2:
            report, rest = rest[1], rest[2:]
        elif len(rest) >= 2:
            tool, rest = rest[1], rest[2:]
        else:
            break
    env = dict(os.environ)
    if report:
        report, why = _report_place(report, env)
        if why:
            sys.stderr.write(f"phiward launch: --report: {why}; nothing runs\n")
            return 2
    run = _Run()
    # this launcher's record, while it runs: the hook trusts an MCP server wrapped in
    # `phiward launch --` only when a live launcher of its command is a child of Claude Code
    from phiward import mcp_config
    record = mcp_config.record_launch(list(argv))
    try:
        code = _launch(tool, memory, rest, env, run, report, server)
    finally:
        mcp_config.end_launch(record)
    if report and not _write_report(report, run.data(code)):
        return code or 2
    return code


def _launch(tool: str, memory: bool, rest: List[str], env: Dict[str, str], run: _Run,
            report: str, server: bool = False) -> int:
    if tool not in ADAPTERS:
        run.say(f"phiward launch: no adapter for '{tool}' (known: {', '.join(sorted(ADAPTERS))})")
        return 2
    adapter = ADAPTERS[tool]
    if rest[:1] == ["--"]:
        rest = rest[1:]
    if not rest:
        if not adapter.program:
            run.say(USAGE.rstrip())
            return 2
        prog = shutil.which(adapter.program)
        if not prog:
            run.say(f"phiward launch: {adapter.program} is not on PATH")
            return 127
        rest = [prog]
    if int(env.get("PHIWARD_LAUNCH_DEPTH", "0") or 0) >= MAX_DEPTH:
        run.say("phiward launch: launched too many times inside itself; nothing runs")
        return 126
    if already_confined(env):
        if report:  # the tool replaces this process: the report says so, without an exit
            run.notes.append("launch inside launch: the outer session's profile holds; "
                             "this launch reports nothing more")
            if not _write_report(report, run.data(None)):
                # an earlier run's report must not stand for this one
                run.say("phiward launch: the --report file cannot be written; nothing runs")
                return 2
        os.execvp(rest[0], rest)  # launch inside launch: this profile already holds
    # until the end, the report says the run needs review (a crash, a signal); a report that
    # cannot be written stops the run, so an earlier report never stands for this one. It is
    # written before the session's view is built: on Linux the view holds the report file by
    # descriptor, which must stay the file that is there until the tool exits
    if report and not _write_report(report, run.data(None)):
        run.say("phiward launch: the report cannot be written; nothing runs")
        return 2
    store = carryover.Store(adapter.name, _real_home(env))
    folder = tool_folder(adapter, env)
    try:
        cmd, child_env, fds, project = build(rest, os.getcwd(), env, adapter, memory, store,
                                             server)
    except (LaunchError, confine.ConfineError, OSError, RecursionError) as exc:
        run.say(f"phiward launch: {exc}; nothing runs")
        if store.run:  # only a session this launcher built: closed, it never ran
            try:
                store.end(folder)
            except (carryover.CarryoverError, OSError):
                pass
        return 126
    # wait for the tool; then carry-over: the session's instruction changes to
    # quarantine and its folder discarded, the project's changes reported, and on Linux git
    # control files outside the project compared too
    import signal
    git_before = _git_snapshot(project) if sys.platform.startswith("linux") else {}
    proj_before = carryover.project_state(project)
    proc = subprocess.Popen(cmd, env=child_env, pass_fds=fds)
    run.ran = True
    for fd in fds:
        os.close(fd)
    old = signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ctrl-C goes to the tool, not to us
    try:
        code = proc.wait()
    finally:
        signal.signal(signal.SIGINT, old)
        # no process is ever ended: on Linux the PID namespace ends them with the tool; on
        # macOS a process left behind can still write the project and the temp folders, but
        # not a run folder a later session reads
        try:
            run.carryover = store.end(folder)
        except Exception as exc:  # the session stays open: the next start tries again
            run.carryover = [f"phiward launch: carry-over did not finish ({exc}); the next "
                             "launch tries again before the tool starts"]
        proj_after = carryover.project_state(project)
        changes = carryover.project_changes(proj_before, proj_after, project)
        run.groups, run.truncated = changes
        for line in run.carryover + carryover.project_report(changes):
            run.say(line)
    git_after = _git_snapshot(project) if sys.platform.startswith("linux") else {}
    run.git = sorted(k for k in set(git_before) | set(git_after)
                     if git_before.get(k) != git_after.get(k))
    for line in _git_lines(run.git):
        run.say(line)
    return code


def _report_place(path: str, env: Dict[str, str]) -> Tuple[str, str]:
    """(the report's full path in its real folder, why it is refused or ""), decided before the
    tool runs. Never a place the session can write (the project, its run folders, the spool,
    the per-user temp folder, ~/.phiward), where it could change the report or plant something
    at its place; never a file that controls the guards (phiward's config and code, Claude
    Code's settings, the hidden list), which the report would replace; never a folder.
    Compared in every spelling the file system treats as equal (case on macOS)."""
    from phiward import claude_settings, hidden
    folder = os.path.realpath(os.path.dirname(os.path.abspath(path)) or ".")
    full = os.path.join(folder, os.path.basename(path))
    if not os.path.basename(path) or not os.path.isdir(folder):
        return full, "its folder does not exist"
    if os.path.isdir(full):
        return full, "it is a folder; give a file name"
    home = _real_home(env)
    project = os.path.realpath(os.getcwd())
    places = write_places(project, env) + [os.path.join(home, ".phiward")]
    if any(config._deny_inside(full, os.path.realpath(p)) for p in places):
        return full, ("it is in a place the session can write (the project, the spool, the "
                      "temp folder or ~/.phiward); give a path outside them")
    cfg = config.load(project, env=env)
    guards = config.guard_files(env) + hidden.paths(None, cfg, session=True) + [
        claude_settings.user_dir(home, env)] + list(claude_settings.MANAGED)
    if any(config._deny_inside(full, os.path.realpath(g)) for g in guards):
        return full, ("it is a file that controls the guards (phiward's config or code, Claude "
                      "Code's settings) or a hidden credential; give another path")
    return full, ""


def _write_report(path: str, data: Dict[str, object]) -> bool:
    """Write the report as a new file next to `path` and move it into place: nothing that is
    at the place (a link, a FIFO, a hard link to another file) is opened or written."""
    try:
        safeio.write_new(path, json.dumps(data, indent=2) + "\n")
        return True
    except OSError as exc:
        sys.stderr.write(f"phiward launch: the report was not written ({type(exc).__name__})\n")
        return False


def _git_lines(changed: List[str]) -> List[str]:
    """The warning about git control files the session changed (Linux)."""
    if not changed:
        return []
    out = [f"phiward launch: WARNING: the session changed {len(changed)} git control file(s); "
           "check them before you run git outside launch:"]
    out += ["  " + c.encode("unicode_escape").decode("ascii") for c in changed[:50]]
    if len(changed) > 50:
        out.append(f"  ... and {len(changed) - 50} more")
    return out
