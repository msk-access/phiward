"""`phiward launch`: run the whole agent tool in the kernel profile.

The tool itself starts inside the profile, so everything it does (its file tools, MCP servers
and hooks), and every child it starts, is decided by the kernel, not by a path check. The text
users see is HELP below; this docstring is for developers.

Writes are denied by default. They are allowed only in the project, this session's own run
folder (`~/.phiward/tools/<tool>/runs/<id>`) and the spool. A write place that is a link, or has
a link on its path, is not used. Inside the project, files that other tools run later stay
read-only: git's control files and `.git` entries, and the one list
(`claude_settings.RUNS_LATER_DIRS`, `RUNS_LATER_FILES`) as a whole, at any depth, with the targets
of the links inside them. The tool and a wrapped MCP server differ only in the whole `.git`
folder. On Linux, `.claude`, `.vscode` and `.idea` are made at start and `.mcp.json` as a
read-only `{}` placeholder; nested ones are bound when they exist at start. The git control files
are compared after the session.

Carry-over (see carryover): each session runs in its own config folder, built from a trusted
copy and thrown away at exit; only this project's transcripts are kept, by a folder name launch
sets (`CLAUDE_CODE_PROJECT_DIR_NAME`). Reads of protected data and credentials are denied, and credential
variables are removed. On Linux the launcher runs the tool through a helper inside bubblewrap
that checks the session's view and closes every descriptor it holds; on macOS it runs
`sandbox-exec -f FILE TOOL` with nothing in between (the profile is a file, as the gateway's).
"Launch inside launch" runs directly only when the session's own profile is found: on macOS a
canary at the account's home that only this profile denies is denied with EPERM, and a file can
be made in the session's own run folder (`PHIWARD_RUN`); on Linux the tool's seccomp filter
gives its fingerprint errno.
"""

import errno
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from phiward import carryover, claude_settings, config, confine, netproxy, pathid, pathmatch, safeio
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
                server's profile (also keeps the project's .git folders read-only as a
                whole). Not for you to type.
  --            ends the options. PROGRAM and its arguments follow. With --tool generic,
                PROGRAM is required.
  -h, --help    show this help.

Run a whole agent tool, and everything it starts, in the kernel profile. The tool cannot
read protected data. It works with protected data only through the gateway (`phiward run`,
`phiward copy`), which masks what comes back.

Start it from the project folder, in your own terminal. It refuses to start in /, in your
home or a folder above it, in a dot folder of your home, in a folder that holds a phiward
folder, or in a folder inside or above protected data. It also refuses when the config has a
problem or when no protected paths are configured. An activated .venv puts a project folder on
PATH, which launch refuses: run `deactivate` first, and in the session use .venv/bin/python or
uv run.

What the session can do:
- Write: only the project, its own session folder (in ~/.phiward/tools/<tool>/runs/) and the
  spool. Files in the project that other tools run later stay read-only, at any depth: git
  control files, the .claude, .vscode, .idea, .cursor, .gemini and .codex folders as a whole,
  .mcp.json, .gitmodules, .ripgreprc, .Rprofile and .Renviron, and what links inside them lead
  to. So skills, agents, hooks and editor settings are not written inside launch (edit them in a
  plain terminal, or `phiward carryover add`), Claude Code's --worktree and /loop tasks do not
  work there, and renv::init() (it writes .Rprofile) runs once outside launch. On Linux, launch
  makes .claude, .vscode and .idea if there are none, and one made in a subfolder during the
  session is reported, not read-only.
- Read: everything except the protected paths and credentials (~/.ssh, ~/.aws, tool logins,
  Kerberos tickets, and similar). Credential variables such as SSH_AUTH_SOCK are removed.
- Other processes: no keystroke injection, no signals to processes outside, no scripting of
  other apps.
- Network: only through phiward's proxy, which launch runs outside the profile, and only to
  public addresses (not this machine, its link or private ranges; private ranges you list in
  [launch] private_networks in the user config). It takes HTTPS (CONNECT) only, and chains to
  the HTTPS_PROXY of your own environment by checked address. Tools that ignore the proxy
  variables, and UDP, have no network. On Linux the session has a network of its own (launch
  refuses where network namespaces are not available); on macOS it cannot reach servers on
  this machine, its own too (use unix sockets or IPC transports). A refusal says why in its
  403 status line, and the refused hosts are listed at exit. With --tool claude, an
  ANTHROPIC_BASE_URL the proxy would refuse (not https://, this machine, a private range not
  listed) stops the start.
- Unix sockets on Linux (the SSH agent, a shared SSH connection, docker): from Linux 7.1
  (Landlock ABI 9) the session reaches only the sockets it made itself. Before it,
  --tool claude relies on Claude Code's own sandbox, which blocks unix sockets for Bash: launch
  turns it on (--settings, always passed last; another --settings or a Claude Code command
  such as `claude mcp` is refused) and refuses to start unless the seccomp filter of the
  program that runs blocks unix sockets in the session (run Claude Code's native binary
  itself, which carries it; a JavaScript build is refused); hooks, MCP servers and Claude Code itself are outside that
  sandbox. Any other tool cannot make unix sockets at all.
- --tool claude: Claude Code 2.1.295 or newer. Before the start, launch asks the native
  binary `TOOL --version`, or reads the npm build's package.json; it never starts a script or
  a program inside the project or the session's folders. The hooks launch writes into the
  session's settings run phiward's entry.py file with arguments and onFailure, which an older
  one would not honour. No Claude Code version (another program, a wrapper, a shim) is
  refused: start Claude Code's own program directly, or use --tool generic.

When the session ends:
- The session's folder is thrown away. Each session starts from a trusted copy that no session
  can read or write. With --tool claude, this project's transcripts are kept for --resume and
  -c, never read by phiward ([launch] keep_transcripts in the user config turns it off).
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
        nest; this profile replaces it), on Linux no retry of a Bash command outside it, the
        fast hook as a first layer, and the prompt scan (the session can remove it: a stated
        limit)."""
        if self.name != "claude":
            return
        data = _read_json_at(folder_fd, "settings.json")
        before = json.dumps(data, sort_keys=True)
        sb = data.setdefault("sandbox", {})
        if not isinstance(sb, dict):
            sb = data["sandbox"] = {}
        if sys.platform == "darwin":
            sb["enabled"] = False
        else:
            sb["allowUnsandboxedCommands"] = False
        # exec form, from a file in the package (entry.py): no inline code. A Claude Code that
        # ignores `args` would run the Python alone, so launch refuses one older than
        # VERSION_HOOK_ARGS on every platform (claude_version_problem)
        entry = os.path.join(os.path.dirname(os.path.abspath(__file__)), "entry.py")

        def launched(words: List[str], timeout: int) -> Dict[str, Any]:
            return {"type": "command", "command": sys.executable,
                    "args": ["-I", "-S", entry] + words, "timeout": timeout,
                    "onFailure": "block"}
        hooks = data.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            hooks = data["hooks"] = {}

        def text(h: Dict[str, Any]) -> str:
            args = h.get("args") if isinstance(h.get("args"), list) else []
            return " ".join([str(h.get("command", ""))] + [str(a) for a in args])

        def others(event: str, what: str) -> list:
            # our entry replaced each time (phiward may have moved; a decoy left by a session
            # is dropped); other entries kept
            groups = hooks.get(event) if isinstance(hooks.get(event), list) else []
            return [g for g in groups if not (isinstance(g, dict) and any(
                isinstance(h, dict) and what in text(h)
                and any(n in text(h) for n in config.PROGRAMS)
                for h in g.get("hooks", []) if isinstance(g.get("hooks"), list)))]

        pre = others("PreToolUse", "hook claude")
        pre.append({"matcher": "Read|Grep|Glob|Bash|Edit|Write|NotebookEdit|MultiEdit",
                    "hooks": [launched(["hook", "claude", "--launched"], 5)]})
        hooks["PreToolUse"] = pre
        prompt = others("UserPromptSubmit", "prompt-scan claude")
        prompt.append({"hooks": [launched(["prompt-scan", "claude"], 10)]})
        hooks["UserPromptSubmit"] = prompt
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
            "COLUMNS", "LINES", "NO_COLOR", "FORCE_COLOR", "SHLVL", "PWD", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS", "JAVA_HOME", "GOPATH", "GOROOT", "CONDA_PREFIX",
            "CONDA_DEFAULT_ENV", "VIRTUAL_ENV", "__CF_USER_TEXT_ENCODING",
            # module systems on HPC (Lmod, Environment Modules) and build paths
            "LD_LIBRARY_PATH", "MODULEPATH", "MODULESHOME", "LOADEDMODULES", "PKG_CONFIG_PATH",
            "MANPATH", "CPATH", "LIBRARY_PATH", "_LMFILES_"}
PASS_PREFIXES = ("LC_", "ANTHROPIC_", "CLAUDE_", "PHIWARD_", "LMOD_", "__LMOD_")
# the tool's proxy variables: all name the session's own proxy (netproxy), and nothing bypasses it
PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")
NO_PROXY_VARS = ("NO_PROXY", "no_proxy")


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
# what other tools run later from the project: read-only as a whole, for the tool and a wrapped
# server alike (the server's profile adds every `.git` folder as a whole)
RUNS_LATER_DIRS = claude_settings.RUNS_LATER_DIRS
RUNS_LATER_FILES = claude_settings.RUNS_LATER_FILES
# made at start when missing on Linux, so a bind covers them (a bind needs a folder that exists);
# on macOS the profile covers a missing one by name, and `.claude` is made there too
MADE_ON_LINUX = (".claude",) + claude_settings.EDITOR_DIRS
# a settings file or folder that is already a link would carry the session's writes to a file a
# later plain run reads: the start refuses
LINK_REFUSED = RUNS_LATER_DIRS + RUNS_LATER_FILES + (
    ".claude/settings.json", ".claude/settings.local.json", ".vscode/settings.json",
    ".vscode/tasks.json", ".vscode/launch.json")
MACH_ALLOW = (
    # certificates: only the user's trustd agent, which reads the OS trust store (Claude Code
    # trusts it by default); the system trustd and ocspd, which fetch certificate URLs outside
    # the profile, are not needed for that
    "com.apple.SecurityServer", "com.apple.securityd.xpc",
    "com.apple.trustd.agent", "com.apple.SystemConfiguration.configd",
    "com.apple.SystemConfiguration.DNSConfiguration", "com.apple.dnssd.service",
    "com.apple.system.opendirectoryd.libinfo", "com.apple.system.DirectoryService.libinfo_v1",
    "com.apple.system.notification_center", "com.apple.system.logger", "com.apple.logd",
    "com.apple.diagnosticd", "com.apple.cfprefsd.daemon", "com.apple.cfprefsd.agent",
    "com.apple.bsd.dirhelper", "com.apple.FSEvents", "com.apple.CoreServices.coreservicesd",
    "com.apple.lsd.mapdb", "com.apple.analyticsd",
    "com.apple.nesessionmanager.content-filter",
)
_TIOCSTI_MACOS = 0x80017472
CANARY = "launch-canary"


class LaunchError(Exception):
    pass


# refusals and notes that `phiward doctor` gives too (doctor.launch_report), each with its step
NO_PATHS = ("no protected paths are configured: there is nothing to confine; run "
            "`(cd ~ && phiward setup)` first")
PROJECT_STEP = "this folder cannot be the project ({}); start the tool in a project folder"
LINK_STEP = "{} in the project is a link; replace it with a real file or folder"
DASH_DASH = ("launch passes --settings to Claude Code as the last arguments, so `--` cannot be "
             "among them: drop the `--` and put the prompt last")
CLAUDE_STEP = ("run Claude Code's own program directly (the native binary, or the npm package's "
               "cli.js), not a wrapper or a shim, or use --tool generic for another tool")
LOGIN_NOTE = ("each session starts with a fresh config folder, so Claude Code asks you to log in "
              "every time; to log in once, run `claude setup-token` and set "
              "CLAUDE_CODE_OAUTH_TOKEN (the agent can read it)")


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
    return ""


PATH_INSIDE = "it holds a folder on PATH (programs there run later, outside launch)"


def _path_entry_inside(project: str, env: Dict[str, str]) -> str:
    """The first PATH entry, as written, that is the project or inside it, or "": the operator's
    own shell runs what is there after the session (an activated `.venv/bin`)."""
    for e in (env.get("PATH") or "").split(":"):
        if e and os.path.isabs(e) and _inside(os.path.realpath(e), project):
            return e
    return ""


def _path_step(entry: str, env: Dict[str, str], shown: str = "") -> str:
    """The refusal for a PATH entry inside the project, with the way out; `shown` is how the
    entry is named (doctor names it relative to the project)."""
    name = shown or entry
    why = (f"PATH holds {name}, inside the project; programs there run in your terminal after "
           "the session. ")
    venv = env.get("VIRTUAL_ENV") or ""
    if venv and os.path.realpath(venv) == os.path.dirname(os.path.realpath(entry)):
        return why + (f"Run `deactivate` (or take {name} off PATH), then start again; in the "
                      "session, use .venv/bin/python or uv run")
    return why + f"Take {name} off PATH (direnv: `direnv deny`), then start again"


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
                          server: bool = False, proxy_port: int = 0) -> str:
    """The tool's Seatbelt profile. Its only IP connection is to `proxy_port` on loopback (the
    session's proxy, which holds that port on 127.0.0.1 and [::1]); 0: none at all."""
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
    # what other tools run later from the project, read-only as a whole at any depth, made before
    # the session or not (so none can be made, or made a link); and where the links among and
    # inside them lead, when that is a place the session writes
    dirs = "|".join(_ci_rx(n) for n in RUNS_LATER_DIRS)
    files = "|".join(_ci_rx(n) for n in RUNS_LATER_FILES)
    # but not inside the trees of installed code (SKIP_TREES; `.claude/worktrees` stays read-only
    # with `.claude`)
    trees = "|".join(_rx(t) for t in SKIP_TREES if t.split("/")[0] not in RUNS_LATER_DIRS)
    inside = f'(require-not (regex #"^{_rx(project)}/(.*/)?({trees})/(.*/)?({dirs}|{files})(/.*)?$"))'
    ro.append(f'(require-all (regex #"^{_rx(project)}/(.*/)?({dirs})(/.*)?$") {inside})')
    ro.append(f'(require-all (regex #"^{_rx(project)}/(.*/)?({files})$") {inside})')
    linked = runs_later_links(runs_later_in(project), places, _real_home(env))
    ro += [f"(subpath {s(t)})" for t in confine._spellings(linked)]
    if server:
        # a wrapped MCP server (`--entry`) runs inside a Mode A session that is not confined:
        # every git folder of the project is read-only as a whole too, made before the server
        # starts or not
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
    # the profile files (confine.write_profile), the gateway's and this session's own: not
    # readable in the session (not a write place either, so not writable)
    p += "".join(f"(deny file-read* (subpath {s(d)}))"
                 for d in confine._spellings([confine.profiles_dir(env)]))
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
    p += "(deny file-mount)(deny job-creation)"
    p += "(deny signal (require-not (target same-sandbox)))"
    p += f"(deny file-ioctl (ioctl-command #x{_TIOCSTI_MACOS:x}))"
    p += "(deny network-outbound (remote unix-socket))"
    # unix sockets only under this session's own run folder, never another run's (its tmux
    # server, for one)
    p += "".join(f"(allow network-outbound (remote unix-socket (subpath {s(q)})))" for q in own)
    # name lookups go through mDNSResponder's socket
    p += '(allow network-outbound (remote unix-socket (subpath "/private/var/run/mDNSResponder")))'
    # no IP connection except TCP to the session's proxy: an allow list (`localhost` here is
    # 127.0.0.1 and ::1, and a deny list of loopback misses ::ffff:127.0.0.1); `tcp`, as the
    # proxy holds only TCP on that port, and UDP to it would reach whoever binds it
    p += '(deny network-outbound (remote ip "*:*"))'
    # binds stay allowed: the profile's `(local ip "localhost:*")` also matches 0.0.0.0 and ::,
    # so loopback cannot be kept alone, and a total deny breaks localhost servers and Claude
    # Code's sign-in (the limit: threat-model.md)
    if proxy_port:
        p += f'(allow network-outbound (remote tcp "localhost:{int(proxy_port)}"))'
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


# -- Linux -------------------------------------------------------------------------------------

# The session's fingerprint: the tool's filter answers one unassigned syscall number with an
# errno that no kernel and no common filter returns; a launch that sees it is inside phiward's
# session (already_confined). The fingerprint is not a secret: any process may install such a
# filter on itself and its children. Forging it needs code running in the launcher or one of its
# ancestors, which could skip `launch` anyway. 360 is unassigned on x86_64 (335-423) and aarch64
# (295-402), and new syscalls take numbers from 424 up on every architecture. The errno is
# below 4096, so the C library reports it as errno.
FINGERPRINT_SYSCALL = 360
FINGERPRINT_ERRNO = 3917

# Landlock ABI 9 (Linux 7.1) limits connect() to pathname unix sockets made outside the session
UNIX_ABI = 9
# what launch gives Claude Code below ABI 9, by --settings (above the project's and the user's
# files; with the unsandboxed retry off there, Claude Code ignores a repository's settings that
# loosen its sandbox)
INNER_SETTINGS = {"sandbox": {"enabled": True, "failIfUnavailable": True,
                              "allowUnsandboxedCommands": False}}
# Claude Code's sandbox has a seccomp filter for these only
INNER_ARCH = ("x86_64", "aarch64")
def _without_launch_settings(argv: List[str]) -> List[str]:
    """argv less a --settings that says just what launch passes (INNER_SETTINGS, as in the file
    `install` writes for `claude --settings`). Claude Code keeps one --settings, the last, so any
    other would be dropped without a word: it stops the start."""
    out, i = [argv[0]], 1
    while i < len(argv):
        a = argv[i]
        if a == "--settings" or a.startswith("--settings="):
            if a == "--settings":
                if i + 1 >= len(argv):
                    raise LaunchError("--settings has no value")
                val, i = argv[i + 1], i + 2
            else:
                val, i = a.split("=", 1)[1], i + 1
            try:
                if val.lstrip().startswith("{"):
                    data = json.loads(val)
                else:
                    with open(val, encoding="utf-8") as fh:
                        data = json.loads(fh.read(1 << 20))
            except (OSError, ValueError):
                data = None
            if data != INNER_SETTINGS:
                raise LaunchError(
                    "launch passes its own --settings to Claude Code, which keeps only one, so "
                    f"these ({val}) would be dropped. Under launch Claude Code reads a config "
                    "folder of its own, not ~/.claude: put them in managed settings, or in the "
                    "settings.json of launch's trusted copy (`phiward carryover add FILE --as "
                    "settings.json --tool claude`)")
            continue
        out.append(a)
        i += 1
    return out


def landlock_abi() -> int:
    """The kernel's Landlock ABI version (0 without Landlock)."""
    import ctypes
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        return 0
    libc.syscall.restype = ctypes.c_long
    return max(0, libc.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1)))


def inner_sandbox_reason(project: str, env: Dict[str, str],
                         machine: Optional[str] = None) -> Optional[str]:
    """Why Claude Code's sandbox would not block unix sockets for Bash below ABI 9, or None:
    an architecture with no filter, or settings (merged under INNER_SETTINGS, as Claude Code
    merges them; `env` is the session's) that open the sandbox. Whether the filter is installed
    and works is checked in the session's view (HELPER)."""
    machine = machine or confine._machine()
    if machine not in INNER_ARCH:
        return (f"Claude Code's sandbox has no seccomp filter for the {machine} architecture, "
                "so it cannot block unix sockets below Linux 7.1")
    return claude_settings.launch_sandbox_reason(project, _real_home(env), env, INNER_SETTINGS)


def tool_seccomp_program(machine: Optional[str] = None, deny_unix: bool = False) -> bytes:
    """No keystroke injection (ioctl TIOCSTI, TIOCLINUX: compared on the low 32 bits) and no
    kernel keyrings (keyctl, add_key, request_key: Kerberos KEYRING tickets); the x32 ABI is
    refused on x86_64; the fingerprint syscall fails with FINGERPRINT_ERRNO. With `deny_unix`
    (below Landlock ABI 9, a tool with no inner sandbox): socket(AF_UNIX) fails with EPERM and
    io_uring with ENOSYS (it could make sockets past the filter); socketpair stays."""
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
    if deny_unix:
        for k in ("io_uring_setup", "io_uring_enter", "io_uring_register"):
            prog += [(jeq, 0, 1, confine._DENY[k][col]), (ret, 0, 0, 0x00050026)]
        prog += [(jeq, 0, 4, confine._SOCKET[col]), (ld, 0, 0, 16), (jeq, 0, 1, 1),
                 (ret, 0, 0, eperm), (ret, 0, 0, allow)]
    prog += [(jeq, 0, 4, ioctl), (ld, 0, 0, 24), (jeq, 1, 0, 0x5412), (jeq, 0, 1, 0x541C),
             (ret, 0, 0, eperm), (ret, 0, 0, allow)]
    return b"".join(struct.pack("<HBBI", *i) for i in prog)


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


# trees of installed or built code, which runs anyway and is not what an editor or agent tool
# reads as a project's settings: the walks for files that run later (runs_later_in and the link
# walk) do not enter them, and on macOS the names of the list inside them stay writable
# (`npm install` unpacks packages that ship a `.vscode`). `.claude/worktrees` is read-only with
# `.claude` as a whole; only its links are not followed. The project scan (projectscan) does not
# read them either
SKIP_TREES = ("node_modules", ".venv", "venv", "site-packages", "renv/library", ".tox", "target",
              ".git", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
              ".claude/worktrees")
RUNS_LATER_WALK = 50000  # entries runs_later_in looks at, past SKIP_TREES
# where runs_later_in stopped at its bound, said at the start and again in the exit report
WALK_NOTES: List[str] = []


def runs_later_in(project: str, limit: Optional[int] = None) -> List[str]:
    """Every entry in the project at launch named in the one list (RUNS_LATER_DIRS,
    RUNS_LATER_FILES), at the top and nested, as names compare case-folded; a link is listed,
    never followed. Not walked: the inside of a listed folder (it is read-only as a whole) and
    SKIP_TREES. Bounded at RUNS_LATER_WALK entries: where it stops is said (WALK_NOTES). Entries
    made during the session are not in it (on Linux a stated limit; macOS covers them by
    name)."""
    limit = RUNS_LATER_WALK if limit is None else limit
    names = {n.casefold() for n in RUNS_LATER_DIRS + RUNS_LATER_FILES}
    out: List[str] = []
    seen = 0
    stack = [project]
    while stack:
        d = stack.pop()
        try:
            it = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        for e in it:
            if seen >= limit:
                note = (f"phiward launch: NOTE: the walk for files that run later stopped at "
                        f"{limit} entries in {d}; below it and in the folders not yet walked, "
                        "they are not read-only on Linux, and links in them are not followed")
                if note not in WALK_NOTES:
                    WALK_NOTES.append(note)
                    sys.stderr.write(note + "\n")
                return out
            seen += 1
            if e.name.casefold() in names:
                out.append(e.path)
            elif e.is_dir(follow_symlinks=False) and not claude_settings._skipped(e.path,
                                                                                 SKIP_TREES):
                stack.append(e.path)
    return out


def runs_later_links(entries: Sequence[str], places: Sequence[str], home: str) -> List[str]:
    """Where the links among and inside `entries` (runs_later_in) really lead, for those that
    lead into a place the session writes: each is made read-only too, so a write through
    `.claude/skills -> ../shared/skills` or to `shared/skills` itself fails. A target outside
    every write place is read-only already. The walk is claude_settings' link walk (each linked
    tree in turn, bounded by TREE_WALK and LINK_WALK). Raises LaunchError where it cannot decide:
    a walk past its bound, a target too wide to be code (`/`, the home folder), or one that holds
    a write place (the project itself)."""
    starts: List[Tuple[str, Optional[int], str]] = []
    out: List[str] = []

    def judge(real: str, via: str) -> None:
        if any(_inside(real, p) for p in places):
            if real not in out:
                out.append(real)
        elif any(_inside(p, real) for p in places):
            raise LaunchError(f"{via} leads to {real}, which holds a place the session writes, so "
                              "it cannot be made read-only; replace the link")
    for e in entries:
        if os.path.islink(e):
            real = os.path.realpath(e)
            if os.path.isdir(real):
                starts.append((real, None, e))
            else:
                judge(real, e)  # a file, or nothing yet
        elif os.path.isdir(e):
            starts.append((os.path.realpath(e), None, ""))
    roots, notes = claude_settings._code_walk(starts, home, SKIP_TREES)
    for why, real, via in notes:
        what = {"wide": "leads to a folder too wide to make read-only"}.get(
            why, f"has more entries than launch walks for links ({claude_settings.TREE_WALK} "
                 f"in one tree, {claude_settings.LINK_WALK} in all)")
        raise LaunchError(f"{via or real} {what}: {real}; replace the link or move files out")
    for real, via in roots:
        if via:
            judge(real, via)
    return out


def _ci_rx(name: str) -> str:
    """`name` as a seatbelt regex that matches it in any letter case (APFS compares names that
    way, so `.VSCode` is the same folder)."""
    return "".join(f"[{c.lower()}{c.upper()}]" if c.isalpha() else _rx(c) for c in name)


def _placeholders(project: str) -> List[str]:
    """D15: a missing `.mcp.json` is made as a read-only `{}` placeholder, so bubblewrap can
    cover it (the folders of the one list are bound as a whole)."""
    nofollow = os.O_NOFOLLOW | os.O_CLOEXEC
    # by descriptor, never through a link, and a file another launch made meanwhile is simply
    # there already (two wrapped MCP servers start at once)
    try:
        top = os.open(project, os.O_RDONLY | os.O_DIRECTORY | nofollow)
    except OSError:
        return []
    try:
        fd = os.open(".mcp.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o644,
                     dir_fd=top)
    except OSError:
        return []
    finally:
        os.close(top)
    with os.fdopen(fd, "w") as fh:
        fh.write("{}\n")
    return [".mcp.json"]


def _open_no_follow(path: str) -> int:
    """An O_PATH descriptor of a file or folder reached part by part without following a link.
    bwrap reads the name back from it and mounts that name, so the helper checks inside the
    session that what got mounted is this file (_write_checks)."""
    if os.path.isdir(path) and not os.path.islink(path):
        return confine.open_place(path)
    parent = confine.open_place(os.path.dirname(path))
    try:
        return os.open(os.path.basename(path), os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,  # type: ignore[attr-defined]
                       dir_fd=parent)
    finally:
        os.close(parent)


def _identities(paths: Sequence[str]) -> Dict[str, Optional[Tuple[int, int]]]:
    """(st_dev, st_ino) of each path, its folder reached part by part without following a
    link and the entry itself not followed; None when it is gone, is a link, or a link is on
    its way."""
    out: Dict[str, Optional[Tuple[int, int]]] = {}
    by_dir: Dict[str, List[str]] = {}
    for p in paths:
        by_dir.setdefault(os.path.dirname(p), []).append(p)
    for d, inside in by_dir.items():
        try:
            pfd = confine.open_place(d)
        except (OSError, confine.ConfineError):
            pfd = -1
        try:
            for p in inside:
                out[p] = None
                if pfd < 0 or not os.path.basename(p):
                    continue
                # a folder is opened (O_DIRECTORY), which mounts an automount point as bwrap's
                # bind will (a plain stat would see the trigger, not the folder mounted there)
                try:
                    fd = os.open(os.path.basename(p), os.O_PATH | os.O_NOFOLLOW |  # type: ignore[attr-defined]
                                 os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=pfd)
                    try:
                        st = os.fstat(fd)
                    finally:
                        os.close(fd)
                except OSError:
                    try:
                        st = os.stat(os.path.basename(p), dir_fd=pfd, follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        continue  # a folder that could not be opened: not what bwrap would bind
                if not stat.S_ISLNK(st.st_mode):
                    out[p] = (st.st_dev, st.st_ino)
        finally:
            if pfd >= 0:
                os.close(pfd)
    return out


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

    An entry the host removes while the session starts is left out of the view; one it replaces
    then stops the start (bwrap_tool_args, the helper's check).

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
                    server: bool = False
                    ) -> Tuple[List[str], List[int], List[Tuple[str, bool, object]]]:
    """The bwrap arguments, the descriptors they name, and what the helper checks inside the
    session before the tool runs: (the path in the view, whether it is an entry of the view
    (named; it may be left out), its name or its descriptor), for every bind no later mount
    covers."""
    # a root that does not exist is hidden like the others: its folder is split, so a root made
    # later is not in the view either (a launch inside another sandbox may see no root at all)
    args: List[str] = []
    fds: List[int] = []
    checks: Dict[str, Tuple[bool, object]] = {}

    def over(dest: str) -> None:  # a later mount covers dest and what is below it
        checks.pop(dest, None)
        for k in [k for k in checks if k.startswith(dest.rstrip("/") + "/")]:
            del checks[k]
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
    later = runs_later_in(project)
    linked = runs_later_links(later, places, _real_home(env))
    guards = confine._spellings(config.guard_files(env))
    # a descriptor for every bind except the view's (those are named, below): the places, the
    # tool's /tmp, what runs later and where its links lead, the git control files and the
    # guard files
    _raise_fd_limit(len(places) + 3 + len(gits) * (len(GIT_CONTROL) + 1) +
                    len(later) + len(linked) + len(guards) + 64)

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
        if stat.S_ISLNK(os.fstat(fd).st_mode):  # checked as no link a moment before
            os.close(fd)
            raise LaunchError(f"{path} became a link while the session's view was made; "
                              "nothing runs")
        os.set_inheritable(fd, True)
        fds.append(fd)
        args.extend(["--ro-bind" if ro else "--bind", f"/proc/self/fd/{fd}", dest or path])
        over(dest or path)
        checks[dest or path] = (False, fd)

    # the snapshot view first: nothing hidden is in it, and every later mount lands on top.
    # Its entries are bound by name: bwrap resolves even a descriptor to a name and mounts that,
    # and a descriptor of an entry the host removes cannot be mounted at all. An entry that is
    # gone, or is a link now, is left out (`-try` also leaves out one removed before bwrap
    # looks); what is bound is checked inside before the tool runs (HELPER)
    now = _identities([op[1] for op in ops if op[0] == "bind"])
    for op in ops:
        if op[0] == "tmpfs":
            args += ["--tmpfs", op[1]]
        elif op[0] == "symlink":
            args += ["--symlink", op[1], op[2]]
        elif op[0] == "mask":
            args += ["--tmpfs", op[1]] if os.path.isdir(op[1]) and not os.path.islink(op[1]) \
                else ["--ro-bind", "/dev/null", op[1]]
        elif now.get(op[1]) is not None:
            args += ["--ro-bind-try", op[1], op[1]]
            checks[op[1]] = (True, op[1])
    # a network of its own: no way to this machine's loopback or any address but through the
    # session's proxy (the relay's socket pair, inherited by the helper)
    args += ["--dev", "/dev", "--proc", "/proc", "--unshare-pid", "--unshare-ipc",
             "--unshare-net", "--die-with-parent"]
    # the tool's own temp folder as /tmp, then the write places on top (a project under /tmp
    # stays visible). Unix sockets are not masked by name (a name in /proc/net/unix is the one
    # a socket was bound with): the kernel limits them (HELPER, tool_seccomp_program)
    # the tool folder is hidden: a session sees only its own run folder, bound back below
    # (sessions cannot read each other)
    args += ["--tmpfs", folder]
    over(folder)
    bind(os.path.join(run, "tmp"), False, "/tmp")
    for p in places:
        if os.path.isdir(p) and _no_link_on_path(p):
            bind(p, False)
    # files that run code later, by descriptor, read-only: what other tools run later, as a whole
    # (top and nested, as they are at the start; one that is a link is not bound, where it leads
    # is), and the git control files (a wrapped MCP server: the whole git folder)
    for q in later:
        if _no_link_on_path(q):
            bind(q, True)
    for t in linked:
        if not os.path.lexists(t):
            raise LaunchError(f"a link in the project leads to {t}, which does not exist, so "
                              "it cannot be made read-only; make it or replace the link")
        bind(t, True)
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
        else:
            continue
        over(r)
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
    return args, fds, [(d, view, x) for d, (view, x) in checks.items()]


def _write_checks(fd: int, checks: Sequence[Tuple[str, bool, object]]) -> None:
    """What the helper compares inside the session, taken right before bwrap starts: for each
    bind, the path in the view (its bytes, as hex: the helper may decode names otherwise), the
    (st_dev, st_ino) it must have there ((-1, -1): it must be
    absent), and whether it may be absent (an entry of the view, left out by `--ro-bind-try`).
    An entry of the view is taken again now, by its name, its folder reached without following
    a link; a bind by descriptor from its descriptor."""
    now = _identities([str(x) for _d, view, x in checks if view])
    recs = []
    for dest, view, x in checks:
        if view:
            ident = now.get(str(x))
            dev, ino = ident if ident is not None else (-1, -1)
        else:
            st = os.fstat(int(x))  # type: ignore[call-overload]
            dev, ino = st.st_dev, st.st_ino
        recs.append([os.fsencode(dest).hex(), dev, ino, view])
    data = json.dumps(recs).encode("ascii")
    os.ftruncate(fd, 0)
    os.lseek(fd, 0, os.SEEK_SET)
    while data:
        data = data[os.write(fd, data):]
    os.lseek(fd, 0, os.SEEK_SET)


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


# the helper the tool starts through: on Linux it first checks that each bind in the session's
# view is what the launcher checked (_write_checks: bwrap mounts by name, and the host may change
# a name in between), then it closes the launcher's descriptors, starts the relay to the proxy on
# the session's own 127.0.0.1 (PHIWARD_PROXY_RELAY, `PORT:FD`: FD is its end of the proxy's socket
# pair; it dies with the tool, PR_SET_PDEATHSIG, and starts before the limits below, which are
# the tool's), limits
# unix sockets as the launcher decided (UNIX: `landlock`, `inner` or `deny`; `none` on macOS), and execs the tool.
# argv: CHK UNIX N FD... CMD [ARG]...
# - landlock (ABI 9 and later): RESOLVE_UNIX for the whole tool (sockets made outside the
#   session are refused, the session's own are not), the name-service folders allowed, REFER
#   granted on / (cross-folder renames), abstract sockets and signals scoped. Any failure: 126.
# - inner (Claude Code below ABI 9): Claude Code's sandbox blocks unix sockets for Bash with
#   apply-seccomp, which the native build carries (run as itself with ARGV0=apply-seccomp). CMD,
#   found on the view's PATH, is judged and then run by its real path: a JavaScript program, one
#   the session could replace, or one that does not make socket(AF_UNIX) fail with EPERM when
#   run as Claude Code runs its filter, stops the start (126).
# - deny and inner: the ABI 6 scope for abstract sockets and signals where the kernel has it.
HELPER = r"""
import os, sys, ctypes, struct
chk = int(sys.argv[1]); unix = sys.argv[2]
n = int(sys.argv[3]); close = sys.argv[4:4 + n]; cmd = sys.argv[4 + n:]; run = cmd[0]
if chk >= 0:
    # each record: [the path in the view as hex bytes, st_dev, st_ino, may it be absent]. The
    # start goes on only when every record was read and compared; anything else stops it
    import json
    where, clean = "the list of checks", False
    try:
        os.lseek(chk, 0, 0)
        with os.fdopen(chk, "rb") as fh:
            recs = json.loads(fh.read().decode("ascii"))
        if type(recs) is not list or not recs:
            raise ValueError("no records")
        for rec in recs:
            if type(rec) is not list or len(rec) != 4:
                raise ValueError("a malformed record")
            name, dev, ino, may_go = rec
            if type(name) is not str or type(dev) is not int or type(ino) is not int or \
                    type(may_go) is not bool:
                raise ValueError("a malformed record")
            path = bytes.fromhex(name)
            where = path.decode("utf-8", "backslashreplace")
            if not path.startswith(b"/") or b"\0" in path:
                raise ValueError("a malformed path")
            try:
                st = os.lstat(path)
            except (FileNotFoundError, NotADirectoryError):
                if may_go:  # an entry of the view, left out by --ro-bind-try
                    continue
                raise
            if (st.st_dev, st.st_ino) != (dev, ino):
                raise ValueError("changed")
        clean = True
    except BaseException:
        clean = False
    if not clean:
        sys.stderr.write("phiward launch: the session's view is not what was checked before the "
                         "start (%s changed while the session started); nothing runs, start "
                         "again\n" % where)
        sys.stderr.flush()
        os._exit(126)
for c in close:
    try:
        os.close(int(c))
    except OSError:
        pass
# RELAY (Linux: the relay to the proxy's socket, RELAY below)
def stop(why):
    sys.stderr.write("phiward launch: %s; nothing runs\n" % why)
    sys.stderr.flush()
    os._exit(126)
if unix == "landlock":
    RESOLVE_UNIX, REFER = 1 << 16, 1 << 13
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        attr = struct.pack("<QQQ", RESOLVE_UNIX | REFER, 0, 3)  # scope: abstract unix, signals
        rs = libc.syscall(444, ctypes.create_string_buffer(attr, len(attr)),
                          ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
        if rs < 0:
            raise OSError(ctypes.get_errno(), "landlock_create_ruleset")
        def allow(fd, access):
            rule = struct.pack("<Qi", access, fd)  # struct landlock_path_beneath_attr (packed)
            if libc.syscall(445, ctypes.c_int(rs), ctypes.c_int(1),
                            ctypes.create_string_buffer(rule, len(rule)), ctypes.c_uint32(0)) != 0:
                raise OSError(ctypes.get_errno(), "landlock_add_rule")
        fds = [os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)]
        allow(fds[0], REFER)
        # the system's name-service sockets (sssd, nscd, userdb): user and group lookups
        for d in ("/var/lib/sss/pipes", "/var/run/nscd", "/run/nscd", "/run/systemd/userdb"):
            try:
                fds.append(os.open(d, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC))
            except (FileNotFoundError, NotADirectoryError):
                continue
            allow(fds[-1], RESOLVE_UNIX | REFER)
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS)")
        if libc.syscall(446, ctypes.c_int(rs), ctypes.c_uint32(0)) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self")
        for fd in fds + [rs]:
            os.close(fd)
    except Exception as e:
        stop("Landlock could not limit unix sockets (%s)" % e)
elif unix in ("inner", "deny"):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    if libc.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1)) >= 6:
        attr = struct.pack("<QQQ", 0, 0, 3)  # no file rights handled; scope: abstract unix, signals
        rs = libc.syscall(444, ctypes.create_string_buffer(attr, len(attr)),
                          ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
        if rs >= 0:
            if libc.prctl(38, 1, 0, 0, 0) == 0:
                libc.syscall(446, ctypes.c_int(rs), ctypes.c_uint32(0))
            os.close(rs)
if unix == "inner":
    import shutil, subprocess
    if os.uname().machine not in ("x86_64", "aarch64"):
        stop("Claude Code's sandbox has no seccomp filter for %s" % os.uname().machine)
    # judged is the program that runs: CMD, found on PATH here as execvp would, then run by its
    # real path. Only the native build (one binary: no JavaScript file, no node line) is
    # accepted: it carries apply-seccomp and runs it as itself with ARGV0=apply-seccomp
    env = dict(os.environ, ARGV0="apply-seccomp")
    run = cmd[0] if "/" in cmd[0] else shutil.which(cmd[0])
    if not run:
        stop("%s is not on the session's PATH" % cmd[0])
    found = run = os.path.realpath(run)
    try:
        with open(run, "rb") as fh:
            head = fh.read(256).split(b"\n")[0]
    except OSError as e:
        stop("Claude Code (%s) cannot be read (%s)" % (run, e.strerror))
    if run.endswith((".js", ".mjs", ".cjs")) or (head.startswith(b"#!") and b"node" in head):
        stop("%s is a JavaScript program, not Claude Code's native build; update Claude Code "
             "to the native build: `claude install`, or `npm install -g "
             "@anthropic-ai/claude-code@latest`" % run)
    p = found
    while True:  # neither the program nor a folder above it may be writable in the session
        if os.access(p, os.W_OK):
            stop("Claude Code (%s) can be changed by the session; install "
                 "Claude Code outside the project and the session's folders" % found)
        if p == "/":
            break
        p = os.path.dirname(p)
    # the probe prints a word only it knows when socket(AF_UNIX) fails with EPERM: a filter
    # that exits 0 without running it does not pass
    word = os.urandom(8).hex()
    probe = ("import errno, socket, sys\ntry:\n    socket.socket(socket.AF_UNIX)\n"
             "except OSError as e:\n    e.errno == errno.EPERM and print(sys.argv[1])\n")
    try:
        r = subprocess.run([found, sys.executable, "-I", "-S", "-c", probe, word],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=60, env=env)
        ok = r.returncode == 0 and r.stdout.split() == [word.encode()]
    except (OSError, subprocess.SubprocessError):
        ok = False
    if not ok:
        stop("Claude Code's seccomp filter (%s, as apply-seccomp) does not block unix sockets "
             "here; run the Claude Code binary directly: a wrapper that adds arguments, or "
             "another program (env, npx, node), is not its filter" % found)
    # a Claude Code command (`claude mcp list`, `claude daemon run`) is no session: some take
    # no --settings, some ignore it and run, and some are hidden from the help. So the binary
    # itself is asked: `claude WORD --help` prints a help of its own for a command (any
    # alias, hidden or not), the root's for a prompt. After -p too: launch does not rely on how
    # Claude Code reads a word there. The root takes positional options: the
    # first word that is neither an option nor an option's value (the arity from the root's
    # help) is WORD; a word that may be an optional value is asked too. Any help that cannot be
    # read stops the start. Cost: the root help, and one more for each word asked
    import re
    del env["ARGV0"]

    def helped(words):
        try:
            r = subprocess.run([found] + words + ["--help"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20,
                               env=env)
        except (OSError, subprocess.SubprocessError):
            r = None
        text = r.stdout.decode("utf-8", "replace") if r is not None and r.returncode == 0 else ""
        if not text.strip():
            stop("`%s %s--help` cannot be read; launch cannot tell a Claude Code command from a "
                 "prompt" % (found, "".join(w + " " for w in words)))
        return text

    text = helped([])
    if not any(ln.startswith("Usage:") for ln in text.splitlines()):
        stop("`%s --help` has no Usage line; launch cannot tell a Claude Code command from a "
             "prompt" % found)
    arity, part = {}, None
    for ln in text.splitlines():
        if ln and not ln[0].isspace():
            part = ln.strip()
            continue
        m = re.match(r"  (-\S.*?)(?:  |$)", ln)
        if part == "Options:" and m:
            spec = m.group(1)
            kind = ("many" if re.search(r"\.\.\.[>\]]", spec) else "one" if "<" in spec else
                    "maybe" if "[" in spec else "none")
            for flag in re.findall(r"(?:^|, )(-[-\w]+)", spec):
                arity[flag] = kind

    def command(word):  # a help other than the root's, in any way, is a command's
        if helped([word]) != text:
            stop("`claude %s` is a Claude Code command, not a session, and does not take "
                 "--settings: run it outside launch" % word)

    args, i = cmd[1:-2], 0  # less the --settings launch adds last
    while i < len(args):
        a = args[i]
        i += 1
        if not a.startswith("-") or a == "-":
            command(a)
            break
        kind = "none" if "=" in a else arity.get(a, "maybe")
        if kind == "one":
            i += 1
        elif kind == "many":
            while i < len(args) and not args[i].startswith("-"):
                i += 1
        elif kind == "maybe" and i < len(args) and not args[i].startswith("-"):
            command(args[i])  # a value, or the command
            i += 1
try:
    os.execvp(run, cmd)
except OSError as e:
    sys.stderr.write("phiward launch: the tool could not start (%s)\n" % e.strerror); os._exit(127)
"""

# the relay, in the Linux helper, where the session reaches the proxy through it. macOS has no
# helper: the profile lets the tool reach the proxy's one port directly
RELAY = r"""
relay = os.environ.pop("PHIWARD_PROXY_RELAY", "")
if relay:
    import socket, threading
    rport, _, rfd = relay.partition(":")
    try:
        ctl = socket.socket(fileno=int(rfd))
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.bind(("127.0.0.1", int(rport)))
        ls.listen(128)
    except (OSError, ValueError) as e:
        sys.stderr.write("phiward launch: the session's network relay cannot start (%s); nothing runs\n" % e)
        os._exit(126)
    parent = os.getpid()
    if os.fork() == 0:
        try:
            ctypes.CDLL(None).prctl(1, 9, 0, 0, 0)  # PR_SET_PDEATHSIG: SIGKILL when the tool ends
            if os.getppid() != parent:
                os._exit(0)
            nul = os.open("/dev/null", os.O_RDWR)
            os.dup2(nul, 0)
            os.dup2(nul, 1)
            keep = sorted((ls.fileno(), ctl.fileno()))
            os.closerange(3, keep[0])
            os.closerange(keep[0] + 1, keep[1])
            os.closerange(keep[1] + 1, 65536)
            asking = threading.Lock()

            def pump(a, b):
                try:
                    while True:
                        d = a.recv(65536)
                        if not d:
                            break
                        b.sendall(d)
                except OSError:
                    pass
                try:
                    b.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            def serve(c):
                # one end of a new pair to the proxy, or the connection is closed: never a
                # direct dial, and no socket with a path
                try:
                    with asking:
                        ctl.sendall(b"c")
                        msg, fds, _f, _a = socket.recv_fds(ctl, 1, 4)
                except OSError:
                    msg, fds = b"", []
                for f in fds[1:]:
                    os.close(f)
                if msg != b"y" or not fds:
                    if fds:
                        os.close(fds[0])
                    c.close()
                    return
                u = socket.socket(fileno=fds[0])
                t = threading.Thread(target=pump, args=(u, c), daemon=True)
                t.start()
                pump(c, u)
                t.join()
                c.close()
                u.close()
            while True:
                c, _ = ls.accept()
                threading.Thread(target=serve, args=(c,), daemon=True).start()
        finally:
            os._exit(0)
    ls.close()
    ctl.close()
"""
HELPER_LINUX = HELPER.replace(
    "# RELAY (Linux: the relay to the proxy's socket, RELAY below)\n", RELAY, 1)


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


def _account_home() -> str:
    """The account's home folder (the password database, never `HOME`), with the links above
    it resolved; "" when it cannot be found."""
    import pwd
    try:
        return os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError):
        return ""


RUN_NAME = re.compile(r"[0-9]{8}-[0-9]{6}-[0-9a-f]{8}")  # build's run folder names


def _own_run_folder(env: Dict[str, str], home: str) -> str:
    """`PHIWARD_RUN` when it is exactly `<home>/.phiward/tools/<adapter>/runs/<id>` and each
    part below the home is a real folder of this account (no link on the way); else ""."""
    run = env.get("PHIWARD_RUN") or ""
    parts = [".phiward", "tools"]
    rest = run[len(home):].split("/") if home and run.startswith(home + "/") else []
    if len(rest) != 6 or rest[1:3] != parts or rest[3] not in ADAPTERS or rest[4] != "runs" \
            or not RUN_NAME.fullmatch(rest[5]):
        return ""
    p = home
    for name in rest[1:]:
        p = os.path.join(p, name)
        try:
            st = os.lstat(p)
        except OSError:
            return ""
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
            return ""
    return run


def _can_make_a_file_in(folder: str) -> bool:
    """A new file can be made in `folder` (O_EXCL, no link followed), then removed."""
    try:
        dfd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        st, now = os.lstat(folder), os.fstat(dfd)
        if (st.st_dev, st.st_ino) != (now.st_dev, now.st_ino):
            return False
        name = f".phiward-probe-{secrets.token_hex(8)}"
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=dfd)
        os.close(fd)
        os.unlink(name, dir_fd=dfd)
        return True
    except OSError:
        return False
    finally:
        os.close(dfd)


def already_confined(env: Dict[str, str]) -> bool:
    """macOS: True only when both facts hold: the canary at the account's home folder (never
    `HOME`), which only the session's profile denies, is denied with EPERM (ordinary
    permissions give EACCES and do not count); and a new file can be made in this session's own
    run folder (`PHIWARD_RUN`, of one exact shape under the account's home). Linux: True only
    when the fingerprint syscall fails with exactly FINGERPRINT_ERRNO; no filter (ENOSYS),
    another filter (EPERM or any other errno), or a filter set later inside the session that
    answers it too, all build the full profile."""
    if sys.platform.startswith("linux"):
        return confine._machine() in confine._AUDIT_ARCH and \
            _fingerprint_errno() == FINGERPRINT_ERRNO
    if sys.platform != "darwin":
        return False
    # Only a phiward session can write a run folder: Claude Code's sandbox denies every write to
    # ~/.phiward, and the gateway cannot write there. So a sandbox that only tightens (one that
    # also denies the canary) fails the second fact, and a process in no sandbox fails the first.
    # The run folder's shape is checked first, so nothing is opened for a launch outside one
    home = _account_home()
    run = _own_run_folder(env, home)
    if not run:
        return False
    # a canary replaced by a link into a folder macOS guards (privacy folders give EPERM too)
    # does not count
    canary = os.path.join(home, ".phiward", CANARY)
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
    return _can_make_a_file_in(run)


START_WINDOW = 5.0  # seconds: a non-zero exit sooner may be sandbox-exec's own refusal


class ToolNotFound(LaunchError):
    pass


def _find_tool(word: str, env: Dict[str, str]) -> str:
    """The program `word` names, as execvp would find it with the session's PATH, by its full
    path; ToolNotFound when there is none."""
    if "/" in word:
        found = os.path.abspath(word)
        if os.path.isfile(found) and os.access(found, os.X_OK):
            return found
        raise ToolNotFound(f"the tool could not start (no such program: {word})")
    found = shutil.which(word, path=env.get("PATH") or os.defpath) or ""
    if found:
        return os.path.abspath(found)
    raise ToolNotFound(f"the tool could not start ({word}: no such program on the session's "
                       "PATH)")


CLAUDE_PACKAGE = "@anthropic-ai/claude-code"  # the npm package of Claude Code
_PACKAGE_JSON_CAP = 64 * 1024


def _read_regular(path: str, cap: int, whole: bool = True) -> Optional[bytes]:
    """Up to `cap` bytes of the regular file `path`, or None: not a regular file, not
    readable, or (with `whole`) longer than `cap`. Opened without blocking (a FIFO would hang
    a plain open) and judged by fstat, so what is read is what was judged."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = os.read(fd, cap + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    return data[:cap] if len(data) <= cap or not whole else None


def _npm_version(script: str, places: Sequence[str]) -> Optional[Tuple[int, int, int]]:
    """The version in the package.json beside `script` (npm's `<package>/cli.js`), when that
    file is Claude Code's package (by its name) and outside the session's write `places`; else
    None. Read, never run."""
    pkg = os.path.realpath(os.path.join(os.path.dirname(script), "package.json"))
    if any(pathid.inside(pkg, os.path.realpath(p)) for p in places):
        return None
    data = _read_regular(pkg, _PACKAGE_JSON_CAP)
    try:
        doc = json.loads(data) if data is not None else None
    except ValueError:
        return None
    if not isinstance(doc, dict) or doc.get("name") != CLAUDE_PACKAGE or \
            not isinstance(doc.get("version"), str):
        return None
    m = re.match(r"(\d+)\.(\d+)\.(\d+)(?![\d.])", doc["version"])
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _native_version(real: str, env: Optional[Dict[str, str]]) -> Optional[Tuple[int, int, int]]:
    """What the native binary `real` says it is (`--version`, from /), or None."""
    try:
        out = subprocess.run([real, "--version"], stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=20, env=env,
                             cwd="/").stdout
    except (OSError, subprocess.SubprocessError, ValueError):
        out = ""
    m = re.match(r"\s*(\d+)\.(\d+)\.(\d+) \(Claude Code\)", out)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def claude_version_problem(tool: str, places: Sequence[str],
                           env: Optional[Dict[str, str]] = None,
                           ask: Optional[Callable[[str, Optional[Dict[str, str]]],
                                                  Optional[Tuple[int, int, int]]]] = None) -> str:
    """Why `tool` cannot run under `--tool claude`, or "": it is not a Claude Code of
    VERSION_HOOK_ARGS or newer. The launched hooks are in exec form (`args`) with `onFailure`,
    and an older one would run their Python alone. Only a native binary outside the session's
    write `places` is started to ask (`--version`, from /), as that runs outside the profile.
    A script (an npm build) is never started: its interpreter is found on PATH, and a shim
    reads the project's config, so either could be the session's. Its version is read from
    its npm package's package.json. No Claude Code version (another program, a wrapper, a
    shim) is a refusal too. `ask` gives a native binary's version in place of starting it
    (doctor, which starts nothing here)."""
    need = claude_settings.version_text(claude_settings.VERSION_HOOK_ARGS)
    unknown = f"`{tool}` gives no Claude Code version: {CLAUDE_STEP}"
    real = os.path.realpath(tool)
    for p in places:
        if pathid.inside(real, os.path.realpath(p)):
            return (f"Claude Code ({real}) is in a folder the session can write; install it "
                    "outside the project and the session's folders")
    head = _read_regular(real, 256, whole=False)  # read, never started
    if head is None:
        return unknown
    head = head.split(b"\n")[0]
    if sys.platform != "darwin" and (real.endswith((".js", ".mjs", ".cjs")) or (
            head.startswith(b"#!") and b"node" in head)):
        # Linux needs the native build (its seccomp filter): the refusal the start gives there,
        # before a JavaScript program would be started to ask its version
        return (f"{real} is a JavaScript program, not Claude Code's native build; update Claude "
                "Code to the native build: `claude install`, or `npm install -g "
                "@anthropic-ai/claude-code@latest`")
    if head.startswith(b"#!"):
        version = _npm_version(real, places)
        if version is None:
            return unknown
    else:
        version = (ask or _native_version)(real, env)
        if version is None:
            return unknown
    if version < claude_settings.VERSION_HOOK_ARGS:
        return (f"Claude Code {claude_settings.version_text(version)} is older than {need}, "
                "which launch needs (an older one would not run phiward's hooks); update "
                "Claude Code")
    return ""


def _make_folders(project: str, names: Sequence[str]) -> List[str]:
    """The folders `names` are made before the tool starts (after every check), so the session
    cannot make one a link, and on Linux a bind covers each. The ones made are returned."""
    made = []
    for n in names:
        p = os.path.join(project, n)
        try:
            os.mkdir(p, 0o755)
            made.append(n)
        except FileExistsError:
            pass  # there already, or another launch in this project made it just now
        st = os.lstat(p)
        if not stat.S_ISDIR(st.st_mode):
            raise OSError(errno.ENOTDIR, f"the project's {n} is not a folder (a link?)", p)
    return made


def _proxy_env(url: str) -> Dict[str, str]:
    """The tool's proxy variables: each names the session's proxy, and nothing bypasses it."""
    out = dict.fromkeys(PROXY_VARS, url)
    out.update(dict.fromkeys(NO_PROXY_VARS, ""))
    return out


RESUME_FLAGS = ("--resume", "-r", "--continue", "-c")


def _asks_resume(args: Sequence[str]) -> bool:
    """Whether Claude Code's arguments, before any `--`, ask for an earlier session."""
    for a in args:
        if a == "--":
            return False
        if a in RESUME_FLAGS or a.startswith(("--resume=", "--continue=")):
            return True
    return False


def _shown_url(url: str) -> str:
    """`scheme://host[:port]` of a URL, without a login or a path: for a message."""
    from urllib.parse import urlsplit  # parsing only
    try:
        u = urlsplit(url.strip())
    except ValueError:
        return "not a URL"
    host = u.netloc.rpartition("@")[2]
    return netproxy._one_line(f"{u.scheme}://{host}" if u.scheme else host or u.path)


def base_url_refusal(url: str, allow: Sequence[str]) -> str:
    """Why a session could not reach the model at ANTHROPIC_BASE_URL `url` (the proxy's own
    rules), with the step, or ""."""
    why = netproxy.base_url_problem(url, allow)
    if not why:
        return ""
    step = ("list its range in [launch] private_networks (user config), or run Claude Code in "
            "Mode A") if why.endswith(netproxy.PRIVATE_WHY) else "run Claude Code in Mode A"
    return (f"ANTHROPIC_BASE_URL ({_shown_url(url)}) {why}; a launch session reaches only HTTPS "
            f"on public addresses and listed private ranges: {step}")


def _start_proxy(cfg: config.Config, env: Dict[str, str], pair: bool = False) -> "netproxy.Proxy":
    try:
        return netproxy.start(env, cfg.launch_private_networks, pair)
    except netproxy.ProxyError as exc:
        raise LaunchError(f"the session's network proxy cannot start: {exc}") from None


def build(argv: Sequence[str], cwd: str, env: Dict[str, str], adapter: Adapter,
          memory: bool = False, store: Optional[carryover.Store] = None,
          server: bool = False
          ) -> Tuple[List[str], Dict[str, str], List[int], str, Callable[[], None],
                     "netproxy.Proxy"]:
    """The tool's command, its environment, the descriptors it is given, the project, the last
    step before it starts, and the session's proxy (serving; the caller closes it)."""
    cfg = config.load(cwd, env=env)
    if cfg.problem:
        raise LaunchError("the phiward config cannot be used (run phiward doctor)")
    if not cfg.has_protected_paths:
        raise LaunchError(NO_PATHS)
    from phiward import phicheck
    masking = None if server else phicheck.check(cfg, cwd)
    if masking and masking.failed:
        raise LaunchError(f"the masking check failed: {masking.failed[0]}; run phiward doctor")
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
        raise LaunchError(PROJECT_STEP.format(why))
    entry = _path_entry_inside(project, env)
    if entry:  # this is the project folder: the step is to take the entry off PATH
        raise LaunchError(_path_step(entry, env))
    # a settings path that is already a link would carry the session's writes to a file a later
    # plain run reads: refused
    for rel in LINK_REFUSED:
        if os.path.islink(os.path.join(project, rel)):
            raise LaunchError(LINK_STEP.format(rel))
    if not server:  # a wrapped MCP server's folder is not the agent's project
        from phiward import projectscan
        scanned = projectscan.scan(cfg, project, projectscan.deadline())
        if scanned.error:
            raise LaunchError("the project scan could not run; run phiward doctor")
        if scanned.hits:
            raise LaunchError(f"the project scan found {projectscan.found_text(scanned)}: move the "
                              "data under a protected root, pseudonymize it (phiward "
                              "pseudonymize), or allow the files ([sanitize] scan_allow); phiward "
                              "doctor --show-paths lists them")
        if not scanned.complete:
            sys.stderr.write(f"phiward launch: NOTE: the project scan stopped at its "
                             f"{projectscan.BUDGET:g} s limit after {scanned.files} files; run "
                             "phiward doctor for the full scan\n")
        elif projectscan.skipped_text(scanned, projectscan.PARTIAL):
            sys.stderr.write("phiward launch: NOTE: the project scan did not read all of the "
                             f"project ({projectscan.skipped_text(scanned, projectscan.PARTIAL)});"
                             " phiward doctor gives the counts\n")
    if project in cfg.no_phi_folders:  # Mode A's opt-out; launch stays all or nothing
        sys.stderr.write("phiward launch: NOTE: the operator lists this folder in [no_phi] "
                         "folders; launch confines it all the same (plain claude here is "
                         "relaxed).\n")
    claude = adapter.name == "claude" and not server
    if claude and env.get("ANTHROPIC_BASE_URL"):
        # the proxy's own rules, once: a model the session cannot reach is said at the start
        why = base_url_refusal(env["ANTHROPIC_BASE_URL"], cfg.launch_private_networks)
        if why:
            raise LaunchError(why)
    # this project's transcripts, for --resume and -c: one folder, by a name of its own
    transcripts = hashlib.sha256(os.fsencode(project)).hexdigest()[:16] if claude else ""
    folder = tool_folder(adapter, env)
    _fixed_folders(folder)
    # this session's own folder: its config folder, built from the trusted copy, and its
    # temp folder; discarded after it, so nothing a session leaves there is read again
    run = os.path.join(folder, carryover.RUNS, time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(4))
    store = store if store is not None else carryover.Store(adapter.name, _real_home(env))
    try:
        for line in store.start(folder, run, memory, adapter.turn_own_sandbox_off,
                                transcripts if cfg.launch_keep_transcripts else ""):
            sys.stderr.write(line + "\n")
    except (carryover.CarryoverError, OSError, RecursionError) as exc:
        raise LaunchError(f"carry-over: {exc}")
    if adapter.name == "claude" and not any(env.get(k) for k in (
            "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")):
        sys.stderr.write(f"phiward launch: {LOGIN_NOTE}\n")
    if claude and not cfg.launch_keep_transcripts and _asks_resume(argv[1:]):
        sys.stderr.write("phiward launch: NOTE: keep_transcripts is off, so this session starts "
                         "with no history and --resume and --continue find nothing from earlier "
                         "sessions ([launch] keep_transcripts, user config)\n")
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
    if transcripts:  # set last: an operator's own value (it passes CLAUDE_) never wins
        child_env["CLAUDE_CODE_PROJECT_DIR_NAME"] = transcripts
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
    if adapter.name == "claude":
        # the Claude Code floor, on every platform: the hooks written into the session's
        # settings need it (claude_version_problem)
        why = claude_version_problem(_find_tool(argv[0], child_env), places, child_env)
        if why:
            raise LaunchError(why)
    backend = confine.backend()
    helper = [sys.executable, "-I", "-S", "-c", HELPER_LINUX]  # bubblewrap only
    if backend == "seatbelt":
        # no helper: `sandbox-exec -f FILE TOOL ARGS...`, the tool by its full path, found on the
        # session's PATH now (sandbox-exec would look it up itself, with no message of ours).
        # Inside another sandbox sandbox-exec refuses to apply the profile, and nothing runs
        tool = _find_tool(argv[0], child_env)
        # the session's own run folder: a launch inside the session checks it (already_confined)
        child_env["PHIWARD_RUN"] = run
        _make_folders(project, [".claude"])
        proxy = _start_proxy(cfg, env)
        try:
            child_env.update(_proxy_env(proxy.url()))
            child_env.pop("PHIWARD_PROXY_RELAY", None)  # no relay on macOS
            confine.prune_profiles()
            path = confine.write_profile(seatbelt_tool_profile(cfg, places, project, env, folder,
                                                               canary, server,
                                                               proxy_port=proxy.port))
        except BaseException:
            proxy.close()
            raise
        return [confine.SANDBOX_EXEC, "-f", path, tool] + list(argv[1:]), child_env, \
            [], project, lambda: None, proxy
    if backend == "bwrap":
        if not os.path.isfile(config.user_config_path(env)):
            raise LaunchError("no user config exists, and on Linux the tool could create one; "
                              "run phiward setup first")
        bwrap = shutil.which("bwrap", path="/usr/bin:/bin") or "bwrap"
        why = confine.net_namespace_problem(bwrap, probe=False)
        if why:
            raise LaunchError(f"the session needs a network of its own, and {why} (phiward "
                              "doctor says so too)")
        # a write place bound at /tmp or above it would cover the session's own /tmp (which the
        # temp variables below name) with the host's shared one
        for p in places:
            if os.path.isdir(p) and _inside("/tmp", os.path.realpath(p)):
                raise LaunchError(f"a write place ({p}) is /tmp or holds it, and on Linux the "
                                  "session's own /tmp would be the shared one; start the tool in "
                                  "a folder below /tmp, or elsewhere")
        # the temp folders by the name the view gives the run's tmp, /tmp: a unix socket's path
        # holds at most 107 bytes, and Claude Code's sandbox bridges (`claude-http-<hex>.sock`)
        # and tmux's sockets do not fit under the run folder's full path
        for k in ("TMPDIR", "TMUX_TMPDIR", "CLAUDE_CODE_TMPDIR"):
            if k in child_env:
                child_env[k] = "/tmp"
        made = _make_folders(project, MADE_ON_LINUX)
        if made:
            sys.stderr.write("phiward launch: made empty, read-only folders in the project: "
                             f"{', '.join(made)}\n")
        made = _placeholders(project)
        if made:
            sys.stderr.write("phiward launch: made read-only placeholders in the project: "
                             f"{', '.join(made)}\n")
        # unix sockets: Landlock where the kernel can tell the session's own from those
        # outside (ABI 9); below it, Claude Code's own sandbox blocks them for Bash, and a tool
        # without one cannot make any
        if landlock_abi() >= UNIX_ABI:
            unix = "landlock"
        elif adapter.name == "claude" and not server:
            unix = "inner"
            why = inner_sandbox_reason(project, child_env)
            if why:
                raise LaunchError(why)
            # whatever runs (claude, a versioned binary, a wrapper), the flag goes last; after a
            # `--` it would be read as an argument, so the start is refused
            if "--" in argv[1:]:
                raise LaunchError(DASH_DASH)
            argv = _without_launch_settings(argv)
            argv = list(argv) + ["--settings", json.dumps(INNER_SETTINGS)]
        else:
            unix = "deny"
        # the session reaches the proxy through the relay on its own 127.0.0.1, which asks for
        # each connection on its end of the proxy's socket pair (no socket with a path)
        proxy = _start_proxy(cfg, env, pair=True)
        opened: List[int] = []  # every descriptor made here: closed with the proxy on a refusal
        try:
            relay = netproxy.random_port()
            child_env.update(_proxy_env(proxy.url(relay)))
            args, fds, checks = bwrap_tool_args(cfg, places, project, env, folder, run, server)
            opened += fds
            end = proxy.take_session_end()
            opened.append(end)
            child_env["PHIWARD_PROXY_RELAY"] = f"{relay}:{end}"
            r, w = os.pipe()
            opened.append(r)
            try:
                os.write(w, tool_seccomp_program(deny_unix=unix == "deny"))
            finally:
                os.close(w)
            os.set_inheritable(r, True)
            # the helper's checks, written by `ready` right before bwrap starts (an unlinked
            # file: a pipe holds too little for a large view)
            with tempfile.TemporaryFile() as fh:
                chk = os.dup(fh.fileno())
            opened.append(chk)
            os.set_inheritable(chk, True)
            held = [str(fd) for fd in fds]
            cmd = _bwrap_command(bwrap, r, args, project, helper + [str(chk), unix], held,
                                 argv)
        except BaseException:  # any refusal (also confine's): nothing is left open
            for fd in opened:
                os.close(fd)
            proxy.close()
            raise
        return cmd, child_env, fds + [r, chk, end], project, \
            lambda: _write_checks(chk, checks), proxy
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
            # wrapped MCP server's profile (the whole `.git` folders read-only too)
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
        cmd, child_env, fds, project, ready, proxy = build(rest, os.getcwd(), env, adapter,
                                                           memory, store, server)
    except (LaunchError, confine.ConfineError, OSError, RecursionError) as exc:
        run.say(f"phiward launch: {exc}; nothing runs")
        if store.run:  # only a session this launcher built: closed, it never ran
            try:
                store.end(folder)
            except (carryover.CarryoverError, OSError):
                pass
        return 127 if isinstance(exc, ToolNotFound) else 126
    try:
        _raise_open_files()
        return _run_tool(cmd, child_env, fds, project, ready, store, folder, run)
    finally:
        refused = proxy.refusal_line()  # the operator's own terminal, at exit (and the report)
        if refused:
            run.say(refused)
        confine.release_profile(cmd)  # macOS: the profile's file, once the tool has ended
        proxy.close()  # after the tool, the carry-over and the report


OPEN_FILES_CAP = 10240  # OPEN_MAX on macOS


def _raise_open_files() -> None:
    """The launcher's soft limit of open files, up to its hard limit (at most OPEN_FILES_CAP):
    the proxy holds two descriptors for each of its 64 tunnels, and carry-over and the report
    still need their own while a session (or a process it left behind) holds them."""
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = OPEN_FILES_CAP if hard == resource.RLIM_INFINITY else min(hard, OPEN_FILES_CAP)
    if soft != resource.RLIM_INFINITY and soft < want:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
        except (OSError, ValueError):
            pass  # the limit stays: the proxy refuses what it cannot hold


def _run_tool(cmd: List[str], child_env: Dict[str, str], fds: List[int], project: str,
              ready: Callable[[], None], store: carryover.Store, folder: str, run: _Run) -> int:
    # wait for the tool; then carry-over: the session's instruction changes to
    # quarantine and its folder discarded, the project's changes reported, and on Linux git
    # control files outside the project compared too
    import signal
    git_before = _git_snapshot(project) if sys.platform.startswith("linux") else {}
    proj_before = carryover.project_state(project)
    try:
        ready()  # last, so the host has the least time to change what was checked
    except Exception as exc:  # any failure (a name fsencode cannot encode): nothing runs
        for fd in fds:
            os.close(fd)
        run.say(f"phiward launch: the session's checks cannot be written ({exc}); nothing runs")
        try:
            store.end(folder)
        except (carryover.CarryoverError, OSError):
            pass
        return 126
    started = time.monotonic()
    proc = subprocess.Popen(cmd, env=child_env, pass_fds=fds)
    run.ran = True
    for fd in fds:
        os.close(fd)
    old = signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ctrl-C goes to the tool, not to us
    try:
        code = proc.wait()
        quick = time.monotonic() - started < START_WINDOW
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
    for line in _git_lines(run.git) + WALK_NOTES:
        run.say(line)
    # sandbox-exec fails at the start; a session that ends with an error later gets no hint
    if code and quick and cmd[:2] == [confine.SANDBOX_EXEC, "-f"]:
        run.say(f"phiward launch: the tool exited with {code}; if sandbox-exec printed an error "
                "above, run `phiward doctor`")
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
