"""The MCP servers Claude Code may start here, read from its config files: the user's
`.claude.json` (in `$CLAUDE_CONFIG_DIR` when that is set, else the home folder; top level, and
this project's entry for local scope) and the project's `.mcp.json`. A server is **wrapped**
when its command runs it under `phiward launch [OPTIONS] -- ...` and nothing in its entry
changes what runs (`env` PATH, HOME, PHIWARD_*, ...; a `cwd`): then it runs in phiward's kernel
profile, and its tools are confined. A remote server (`type` http, sse or ws, and no
`command`) runs nothing here. Every other local server runs with the operator's rights.

The hook finds a tool's server by the hook input's `mcp_server` (`classify`: the scope Claude
Code names, the exact name; plugins from their installed files; `sdk` and the sources phiward
does not read are bare). Without it (Claude Code older than 2.1.274, Copilot), by name in the
operator's own config only (`server_of(..., trust_project=False)`).

When a name is defined more than once (scopes, files, a duplicate key), it is wrapped only when
every definition is. The hook trusts these files, so the agent must not write them: they are on
the hidden list or guard files for the file tools, and Claude Code's sandbox keeps Bash from
them."""

import functools
import json
import os
import re
import shlex
import shutil
import stat
import sys
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Tuple

from phiward import claude_settings, pathid


@dataclass(frozen=True)
class Server:
    name: str
    wrapped: bool  # runs under `phiward launch --` (or is remote)
    remote: bool = False
    # where Claude Code says its definition came from (hook input `mcp_server.source`); "" when
    # found by name (an older Claude Code, Copilot)
    source: str = ""
    # its entries as phiward read them (filled in, as JSON text); none: not found
    specs: Tuple[str, ...] = field(default=(), compare=False)
    # reached by a URL on this machine (an IDE's server): not remote, and cannot be wrapped
    here: bool = False
    # no command phiward can wrap (none, empty, not text), and not remote
    unwrappable: bool = False
    # defined only where phiward does not trust it (the project's `.mcp.json`, without a source)
    untrusted: bool = False
    # for a plugin's server: (registry key, install folder) of each entry in `specs`
    copies: Tuple[Tuple[str, str], ...] = field(default=(), compare=False)


# env keys that change which program runs, or what `phiward launch` reads
_ENV_CHANGES = ("PATH", "HOME", "CLAUDE_CONFIG_DIR", "TMPDIR",
                # what tells a plugin's launcher from a configured one's (`plugin_hash`)
                "CLAUDE_PLUGIN_ROOT", "CLAUDE_PLUGIN_DATA")
_ENV_PREFIXES = ("PHIWARD_", "XDG_", "PYTHON", "LD_", "DYLD_")


def user_file(home: str, env: Optional[Dict[str, str]] = None) -> str:
    """The `.claude.json` Claude Code reads: in `$CLAUDE_CONFIG_DIR` when that is set."""
    env = os.environ if env is None else env
    conf = env.get("CLAUDE_CONFIG_DIR")
    return os.path.join(conf, ".claude.json") if conf else os.path.join(home, ".claude.json")


def _command(spec: dict) -> List[str]:
    """The command line of a server entry. `command` is split on spaces only when there are no
    `args` and it is not, as given, an existing file (`/Applications/My App/srv` stays whole)."""
    first = spec.get("command", "")
    args = spec.get("args", []) or []
    if not isinstance(first, str) or not isinstance(args, list) or \
            not all(isinstance(a, (str, int, float)) and not isinstance(a, bool) for a in args):
        return []  # malformed: not a command phiward can read (it counts as bare)
    args = [str(a) for a in args]
    if "\0" in first or any("\0" in a for a in args):
        return []
    if " " in first and not args and not os.path.exists(first):
        try:
            return shlex.split(first)
        except ValueError:
            return [first]
    return [first] + args


def _is_remote(spec: dict) -> bool:
    """Runs nothing here: no `command`, an http, sse or ws `type` (or only a `url`), and a `url`
    whose host is another machine. A server at this machine's own address (`127.0.0.1`,
    `localhost`, its host name) is a local program, such as an IDE's, and counts as local."""
    if spec.get("command"):
        return False
    t = spec.get("type")
    if not (t in ("http", "sse", "ws") or (t is None and bool(spec.get("url")))):
        return False
    return _elsewhere(spec.get("url"))


HOSTS_FILE = "/etc/hosts"

# a URL phiward reads strictly: printable ASCII only (checked before), no `\\`, no user part,
# a host of letters, digits, dots and dashes or a bracketed IPv6 address, an optional port
_STRICT_URL = re.compile(r"(?i)(?:https?|wss?)://(?P<host>[a-z0-9.-]+|\[[0-9a-f:.]+\])"
                         r"(?::[0-9]{1,5})?(?:[/?#][\x21-\x7e]*)?")


def _elsewhere(url: Any) -> bool:
    """Whether `url` surely names another machine. Claude Code reads it with Node's WHATWG URL
    parser, which turns `\\` into `/`, decodes `%31` in the host, maps full-width characters
    and reads `0177.1` as octal; so a URL counts only when it is plain (`_STRICT_URL`) and its
    host is not this machine (`_host_elsewhere`). Anything else counts as this machine."""
    if not isinstance(url, str) or not url.isascii() or "\\" in url:
        return False
    m = _STRICT_URL.fullmatch(url)
    return bool(m) and _host_elsewhere(m.group("host"))


def _host_elsewhere(host: str) -> bool:
    """Whether a host, as a URL parser gives it (lower case, IPv6 in brackets or not), names
    another machine: not loopback, unspecified or link-local (IPv4 in any WHATWG spelling,
    IPv6 also as `::ffff:a.b.c.d` or `::a.b.c.d`), not `localhost` or `*.localhost`, not this
    machine's host name (or with `.local`), not a name /etc/hosts maps to such an address."""
    import ipaddress
    host = host.casefold()
    if host.startswith("[") or ":" in host:
        try:
            ip6 = ipaddress.IPv6Address(host.strip("[]"))
        except ValueError:
            return False
        return not _here_ip(ip6)
    if host.endswith("."):
        host = host[:-1]
    labels = host.split(".")
    if not host or "" in labels or not re.fullmatch(r"[a-z0-9.-]+", host):
        return False
    last = labels[-1]
    if re.fullmatch(r"[0-9]+|0x[0-9a-f]*", last):  # WHATWG: "ends in a number": an IPv4 host
        ip4 = _whatwg_ipv4(labels)
        return ip4 is not None and not _here_ip(ip4)
    if host == "localhost" or host.endswith(".localhost"):
        return False
    import socket
    me = socket.gethostname().rstrip(".").casefold()
    short = me.split(".")[0]
    if host in {me, short, me + ".local", short + ".local"} or host in _loopback_names():
        return False
    return True


def _whatwg_ipv4(labels: List[str]) -> Any:
    """The IPv4 address of a host's labels by the WHATWG rules (decimal, `0` octal, `0x` hex
    parts; the last one fills the rest), or None where Node refuses the URL."""
    import ipaddress
    if len(labels) > 4:
        return None
    nums = []
    for part in labels:
        base = 10
        if part[:2] in ("0x", "0X"):
            base, part = 16, part[2:]
        elif len(part) > 1 and part.startswith("0"):
            base, part = 8, part[1:]
        if part == "":
            nums.append(0)
            continue
        if not re.fullmatch({10: r"[0-9]+", 8: r"[0-7]+", 16: r"[0-9a-fA-F]+"}[base], part):
            return None  # Node refuses the URL (`-1`, `08`, `0x1g`)
        part = part.lstrip("0") or "0"  # Node allows any number of leading zeros
        if len(part) > 11:
            return None  # 2**32 or more: Node refuses the URL (and int() may refuse it too)
        nums.append(int(part, base))
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = nums[-1]
    for i, n in enumerate(nums[:-1]):
        value += n * 256 ** (3 - i)
    return ipaddress.IPv4Address(value)


def _here_ip(ip: Any) -> bool:
    import ipaddress
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif int(ip) >> 32 == 0 and int(ip) > 1:  # `::a.b.c.d` (IPv4-compatible)
            ip = ipaddress.IPv4Address(int(ip))
    return ip.is_loopback or ip.is_unspecified or ip.is_link_local


@functools.lru_cache(maxsize=1)
def _loopback_names() -> frozenset:
    """The names /etc/hosts maps to a loopback, unspecified or link-local address."""
    import ipaddress
    out = set()
    try:
        with open(HOSTS_FILE, encoding="utf-8", errors="replace") as fh:
            text = fh.read(1024 * 1024)
    except OSError:
        return frozenset()
    for line in text.splitlines():
        words = line.split("#", 1)[0].split()
        if len(words) < 2:
            continue
        try:
            ip = ipaddress.ip_address(words[0].split("%")[0])
        except ValueError:
            continue
        if _here_ip(ip):
            out.update(w.rstrip(".").casefold() for w in words[1:])
    return frozenset(out)


def _has_command(spec: dict) -> bool:
    c = spec.get("command") if isinstance(spec, dict) else None
    return isinstance(c, str) and bool(c.strip())


def _listens_here(spec: dict) -> bool:
    """An entry with no command that Claude Code reaches by a URL on this machine (an IDE's
    server, say): phiward cannot wrap it, and it is not remote."""
    if not isinstance(spec, dict) or spec.get("command"):
        return False
    t, url = spec.get("type"), spec.get("url")
    return (t in ("http", "sse", "ws") or (t is None and bool(url))) and isinstance(url, str) \
        and bool(url) and not _elsewhere(url)


def _changes_what_runs(spec: dict) -> bool:
    """An entry whose `env` sets what chooses the program or what it loads (also every variable
    the hooks clear: install.CLEARED_PREFIXES and CLEARED_NAMES), or that has a `cwd`."""
    return bool(_changed_by(spec))


def _changed_by(spec: dict) -> List[str]:
    """What in an entry changes what runs (`_changes_what_runs`), as the operator would remove it:
    `cwd`, `env` PATH, ..."""
    from phiward import install
    names = set(_ENV_CHANGES) | set(install.CLEARED_NAMES)
    prefixes = _ENV_PREFIXES + install.CLEARED_PREFIXES
    out = []
    if "cwd" in spec:
        out.append("`cwd`")
    env = spec.get("env")
    if env is not None and not isinstance(env, dict):
        out.append("an `env` that is not an object")  # malformed: not known what it sets
    elif isinstance(env, dict):
        out += [f"`env` {shown(k)}" for k in env
                if isinstance(k, str) and (k in names or k.startswith(prefixes))]
    return out


def entry_wrapped(spec: Any, project: str, home: str) -> bool:
    """The one answer to "is this configured entry wrapped", for `mcp list`, `doctor`, the hook
    and `wrap`: `placed_state` is `wrapped` (the launcher file, its own entry id, no copy)."""
    return placed_state(spec, project, home) == "wrapped"


def placed_state(spec: Any, project: str, home: str) -> str:
    """`entry_state` of an entry as it sits in the config files: `copied` when it is wrapped but
    its entry id is in another string of them too (a copy of the entry), so its launcher could
    be the copy's; `wrap` gives it an id of its own."""
    st = entry_state(spec)
    if st == "wrapped":
        eid = entry_id(_command(spec))
        if eid and id_count(eid, project, home) > 1:
            return "copied"
    return st


def entry_state(spec: Any) -> str:
    """What one entry is, and so what `phiward mcp wrap` would do with it. The one answer that
    `mcp list`, `doctor`, the hook's advice and `wrap` all use:
    - `wrapped`: runs under `phiward launch --entry ID --` (its own id: `entry_id`);
    - `remote`: runs nothing here;
    - `bare`: a command `wrap` can wrap;
    - `runner`: starts phiward through another program (`uvx`, `env`, `uv run`, `pipx run`, Python
      with `-m phiward`): the operator edits it (`RUNNER_STEP`); `wrap` never rewrites it;
    - `changed`: wrapped, but its `cwd` or an `env` key changes what runs (the operator removes
      that; wrapping again would not help);
    - `here`: no command, reached by a URL on this machine (it runs outside Claude Code);
    - `no-command`: no command phiward can read.
    `here` and `no-command` cannot be wrapped."""
    if not isinstance(spec, dict):
        return "no-command"
    if _is_remote(spec):
        return "remote"
    if not _has_command(spec):
        return "here" if _listens_here(spec) else "no-command"
    cmd = _command(spec)
    if not cmd or not cmd[0]:
        return "no-command"
    if is_wrapped(cmd, spec):
        # a configured entry without its own id (an older wrap) is not wrapped: `wrap` adds one
        return "wrapped" if entry_id(cmd) else "bare"
    if is_wrapped(cmd):
        return "changed"
    if _launch_shaped(cmd) and os.path.basename(cmd[0]) not in LAUNCHER_NAMES:
        return "runner"
    return "bare"


@dataclass(frozen=True)
class Entry:
    name: str
    path: str  # the config file
    scope: str  # user, local (this project's entry in the user file) or project
    spec: Any = field(compare=False)
    state: str = ""


def entries(project: str, home: str) -> List[Entry]:
    """Every server entry of the config files phiward reads, one per definition, in file order
    (a file that cannot be read strictly has none here: `problems` names it)."""
    out: List[Entry] = []
    mcp_json = os.path.join(project, ".mcp.json")
    for path in _files(project, home):
        data, _why = _load(path)
        if not isinstance(data, dict):
            continue
        if _same_place(path, mcp_json):
            groups = [("project", data.get("mcpServers"))]
        else:
            groups = [("user", data.get("mcpServers"))]
            projects = data.get("projects") if isinstance(data.get("projects"), dict) else {}
            groups += [("local", e.get("mcpServers")) for k, e in projects.items()
                       if isinstance(k, str) and isinstance(e, dict) and _same_place(k, project)]
        for scope, group in groups:
            if isinstance(group, dict):
                out += [Entry(str(n), path, scope, spec, placed_state(spec, project, home))
                        for n, spec in group.items()]
    return out


def _changed_step(spec: dict) -> str:
    """What to do about a `changed` entry, by what it sets."""
    keys = _changed_by(spec)
    if keys == ["`cwd`"]:
        return "remove `cwd` and give the server absolute paths"
    if keys == ["`env` PATH"]:
        return "name the command by its full path and remove PATH from `env`"
    return "remove that from the entry"


def where(path: str, scope: str, home: str) -> str:
    """A config file as the operator knows it: `~/.claude.json`, `.mcp.json`."""
    if scope == "project":
        return ".mcp.json"
    h = os.path.join(home, "")
    shown_path = "~/" + path[len(h):] if path.startswith(h) else path
    return shown_path + (", this project" if scope == "local" else "")


def name_states(project: str, home: str) -> Dict[str, set]:
    """name -> the states of its entries (`entry_state`)."""
    out: Dict[str, set] = {}
    for e in entries(project, home):
        out.setdefault(e.name, set()).add(e.state)
    return out


def cannot_wrap_why(states: set) -> str:
    """Why a name whose entries `wrap` cannot change stays not wrapped, or "" when `wrap` can
    change one of them."""
    if "bare" in states:
        return ""
    if "here" in states:
        return "listens on this machine at its URL and runs outside Claude Code"
    if "no-command" in states:
        return "has no command phiward can read"
    if "runner" in states:
        return ("starts phiward through another program (env, uv, uvx, pipx or python -m): "
                + RUNNER_STEP + ", then run `phiward mcp wrap`")
    if "changed" in states:
        return "its entry sets a `cwd` or an `env` key that changes what runs (remove it)"
    return ""


LAUNCHER_NAMES = ("phiward", "agent-guards")


def _safe_path(path: str, project: str = "", inputs=None) -> str:
    """`path` with only the folders the agent cannot write (`service._safe_path_entries`, and
    none inside Claude Code's project, `$CLAUDE_PROJECT_DIR`, also when this runs elsewhere): a
    project's `.venv/bin` or `node_modules/.bin` could hold another `phiward`."""
    from phiward import service
    project = project or os.environ.get("CLAUDE_PROJECT_DIR", "")
    top = os.path.realpath(project) if project else ""
    keep = [e for e in service.path_entries(path, inputs or service.path_inputs())
            if not top or not (os.path.realpath(e) + "/").startswith(top.rstrip("/") + "/")]
    return ":".join(keep)


@functools.lru_cache(maxsize=8)
def _launchers_on(path: str, project: str, inputs: tuple) -> frozenset:
    safe = _safe_path(path, project, inputs)
    return frozenset(os.path.realpath(p) for p in (shutil.which(n, path=safe)
                                                    for n in LAUNCHER_NAMES) if p)


def _launcher_exes(path: str) -> frozenset:
    """Where the installed `phiward` and its alias lead, found only on the folders of `path` the
    agent cannot write (looked up once per PATH, project and `service.path_inputs()`: a hook
    call may read many entries; the key is what the PATH filter reads, so a changed setting is
    seen at once)."""
    from phiward import service
    return _launchers_on(path, os.environ.get("CLAUDE_PROJECT_DIR", ""), service.path_inputs())


_launcher_exes.cache_clear = _launchers_on.cache_clear  # type: ignore[attr-defined]


def _recorded_launchers() -> Optional[frozenset]:
    """The launcher files phiward's install record lists (`selfcheck.launcher_scripts`), or
    None for a source checkout or an editable install, which keep the PATH rule
    (`_launcher_exes`). A record that cannot be read gives no launcher at all."""
    from phiward import selfcheck
    try:
        return selfcheck.launcher_scripts()
    except Exception:  # noqa: BLE001 - fail closed: nothing counts as the launcher
        return frozenset()


def _file_id(path: str) -> str:
    """A path with its folders resolved but not its last part: the file an entry names, as the
    record lists it (a link on PATH to it is another file, which another program may replace)."""
    return os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path))


def _is_launcher(path: str) -> bool:
    """Whether an entry's command, an absolute path, is the installed launcher: the file
    phiward's install record lists; without a record, the `phiward` found on the PATH folders
    the agent cannot write."""
    rec = _recorded_launchers()
    if rec is not None:
        return _file_id(path) in rec
    return os.path.realpath(path) in _launcher_exes(os.environ.get("PATH", ""))


def installed_launcher() -> Optional[str]:
    """The installed `phiward` as `wrap` writes it into an entry: the file the install record
    lists; without a record, found on PATH folders the agent cannot write; None when there is
    none."""
    rec = _recorded_launchers()
    if rec is not None:
        return next((p for p in sorted(rec) if os.path.basename(p) == "phiward"), None)
    return shutil.which("phiward", path=_safe_path(os.environ.get("PATH", "")))


# programs that start the words after them as a command (uvx, env, uv run, pipx run, ...): an
# entry that starts phiward's launcher through one is named and rewritten, never trusted
_RUNNERS = frozenset({"uvx", "env", "uv", "pipx", "nice", "nohup", "time", "exec", "command",
                      "stdbuf", "timeout", "ionice", "chrt", "taskset"})
# Python options that take the next word as their value
_PY_VALUE_OPTS = frozenset({"-W", "-X", "-Q", "--check-hash-based-pycs"})


def _launch_tail(cmd: List[str]) -> Optional[List[str]]:
    """The words from `launch` on, for any spelling that starts phiward's launcher: the launcher
    (or the alias) by any path; one started through a runner (`uvx [--from X] phiward launch`,
    `env K=V phiward launch`, `uv run phiward launch`); or a Python whose words before `-m
    phiward` are all its own options. Well formed or not; None for any other command. For naming
    and rewriting an entry, never for trusting one (`_launch_rest`)."""
    if not cmd or not cmd[0]:
        return None
    first = os.path.basename(cmd[0])
    rest: Optional[List[str]] = None
    if first in LAUNCHER_NAMES:
        rest = cmd[1:]
    elif first.startswith("python") and "-m" in cmd[1:]:
        i = cmd.index("-m", 1)
        before, ok, k = cmd[1:i], True, 0
        while k < len(before):
            if not before[k].startswith("-"):
                ok = False
                break
            k += 2 if before[k] in _PY_VALUE_OPTS else 1
        if ok and cmd[i + 1:i + 2] == ["phiward"]:
            rest = cmd[i + 2:]
    elif first in _RUNNERS:
        at = next((k for k in range(1, len(cmd) - 1)
                   if os.path.basename(cmd[k]) in LAUNCHER_NAMES and cmd[k + 1] == "launch"),
                  None)
        if at is not None:
            rest = cmd[at + 1:]
    return rest if rest is not None and rest[:1] == ["launch"] else None


def _well_formed(rest: Optional[List[str]]) -> bool:
    """`launch [OPTIONS] -- PROGRAM ...`: a `--` and a program after it."""
    return rest is not None and "--" in rest and len(rest) > rest.index("--") + 1


def _launch_rest(cmd: List[str]) -> Optional[List[str]]:
    """What follows the launcher in `phiward launch [OPTIONS] -- PROGRAM ...`, from `launch` on,
    when the command is the launcher file itself (or the alias): never a Python with `-m
    phiward`, which imports the folder it starts in (the project) before phiward. None for any
    other command, or a `launch` without `--` and a program."""
    if not cmd or os.path.basename(cmd[0]) not in LAUNCHER_NAMES:
        return None
    rest = _launch_tail(cmd)
    return rest if _well_formed(rest) else None


def _launch_options(cmd: List[str]) -> List[str]:
    """The options between `launch` and `--` of a well-formed launcher entry ([] otherwise)."""
    rest = _launch_tail(cmd)
    return rest[1:rest.index("--")] if _well_formed(rest) and rest is not None else []


def _exact_options(cmd: List[str]) -> bool:
    """A wrapped entry takes exactly `--entry ID` before `--`: no `--tool`, `--memory` or
    `--report` (an entry the agent or a repository wrote must not carry them into what the
    operator's `wrap` makes trusted; `--report` writes before the launcher confines)."""
    opts = _launch_options(cmd)
    return len(opts) == 2 and opts[0] == "--entry" and bool(ENTRY_ID.fullmatch(opts[1]))


# what a `runner` entry needs (`entry_state`): the words in front of phiward mean something
# different for each runner, so `wrap` does not guess them
RUNNER_STEP = "edit the entry so its command is the server program itself"


def _launch_shaped(cmd: List[str]) -> bool:
    """Any spelling that starts phiward's launcher (`_launch_tail`), well formed or not."""
    return _launch_tail(cmd) is not None


ENTRY_ID = re.compile(r"[0-9a-f]{16}")


def entry_id(cmd: List[str]) -> Optional[str]:
    """The id `wrap` gives an entry (`phiward launch --entry ID -- ...`), or None."""
    rest = _launch_rest(cmd)
    if rest is None:
        return None
    opts = rest[1:rest.index("--")]
    for i, o in enumerate(opts[:-1]):
        if o == "--entry" and ENTRY_ID.fullmatch(opts[i + 1]):
            return opts[i + 1]
    return None


def new_entry_id() -> str:
    import secrets
    return secrets.token_hex(8)


def _relaunch_args(cmd: List[str]) -> Tuple[List[str], List[str]]:
    """A launcher entry by the launcher's name, in the one form a wrapped entry has: (`launch
    --entry NEW -- PROGRAM ...`, the options it dropped, any old id aside)."""
    rest = _launch_tail(cmd) or []
    cut = rest.index("--")
    opts, prog = rest[1:cut], rest[cut + 1:]
    dropped: List[str] = []
    i = 0
    while i < len(opts):
        if opts[i] == "--entry":
            i += 2
            continue
        dropped.append(opts[i])
        i += 1
    return ["launch", "--entry", new_entry_id(), "--"] + prog, dropped


def launcher_problem(spec: Any) -> str:
    """For an entry that starts `phiward launch` but is not wrapped: why, as `list` says it
    ("" for any other entry)."""
    cmd = _command(spec) if isinstance(spec, dict) else []
    if not _launch_shaped(cmd):
        return ""
    if not _well_formed(_launch_tail(cmd)):
        return "its `phiward launch` has no `--` and a program after it"
    first = os.path.basename(cmd[0])
    if first not in LAUNCHER_NAMES:
        return (f"it starts phiward through `{shown(first)}`, not as the server program itself: "
                f"{RUNNER_STEP}")
    if not os.path.isabs(cmd[0]):
        return "it names `phiward` without its path"
    if not _is_launcher(cmd[0]):
        return "its `phiward` is not the installed launcher"
    if entry_id(cmd) is None:
        return "it was wrapped without an entry id (an older phiward)"
    if not _exact_options(cmd):
        return ("it has options before `--` that wrapped entries do not take ("
                + " ".join(shown(o) for o in _launch_options(cmd)) + ")")
    return ""


def is_wrapped(cmd: List[str], spec: Optional[dict] = None) -> bool:
    """`phiward launch [OPTIONS] -- PROGRAM ...` (or the alias) with the installed launcher file
    by its full path (`_is_launcher`): only that exact shape counts, not a shell around it, not
    `phiward` by name (Claude Code looks a name up on its PATH, where a folder the agent can
    write may come first), not a Python with `-m phiward` (it imports the project folder first),
    and only when the entry (`spec`) does not change what runs."""
    if not cmd or not cmd[0] or (spec is not None and _changes_what_runs(spec)):
        return False
    if not os.path.isabs(cmd[0]) or _launch_rest(cmd) is None:
        return False
    return _is_launcher(cmd[0]) and (entry_id(cmd) is None or _exact_options(cmd))


def _load(path: str) -> Tuple[Optional[dict], str]:
    """A config file as a dict (`claude_settings.read_json`), or (None, why). A key given twice
    makes it unreadable here: which of two server entries Claude Code starts is then not worth
    trusting, so its servers count as bare."""
    data, why, twice = claude_settings.read_json(path)
    if twice:
        return None, "a key is given twice (" + ", ".join(twice[:3]) + ")"
    return data, why


def _same_place(a: str, b: str) -> bool:
    try:
        x, y = os.path.realpath(os.path.normpath(a)), os.path.realpath(os.path.normpath(b))
    except (TypeError, ValueError):  # a NUL in a path: not a place
        return False
    if sys.platform == "darwin":
        x, y = x.casefold(), y.casefold()
    return x == y


def problems(project: str, home: str) -> List[str]:
    """The config files that cannot be read strictly (their servers then count as bare)."""
    out = []
    for path in _files(project, home):
        _d, why = _load(path)
        if why:
            out.append(f"{path}: {why}")
    return out


def _files(project: str, home: str) -> List[str]:
    # the one user file Claude Code reads (`$CLAUDE_CONFIG_DIR/.claude.json` in place of
    # `~/.claude.json` when that is set), and the project's
    files = [user_file(home), os.path.join(project, ".mcp.json")]
    return list(dict.fromkeys(files))


def servers(project: str, home: str, trust_project: bool = True) -> Dict[str, Server]:
    """Every MCP server of the user's and this project's config. A name defined more than once
    is wrapped only when every definition is. A file that cannot be read strictly makes every
    server it may name bare: its names are not known, so a marker records the failure.
    `trust_project` False: a server of the project's `.mcp.json` counts as bare (a repository
    wrote it, and the agent's Bash may rewrite it), and so does every name it defines."""
    found: Dict[str, Server] = {}
    mcp_json = os.path.join(project, ".mcp.json")
    for path in _files(project, home):
        own = trust_project or not _same_place(path, mcp_json)
        data, why = _load(path)
        if not isinstance(data, dict):
            if why:
                found["\0unreadable"] = Server("\0unreadable", False)
                # the names it may hold: read leniently, only to mark them bare
                try:
                    with open(path, encoding="utf-8") as fh:
                        loose = json.loads(fh.read())
                except (OSError, ValueError):
                    loose = None
                for name in _names(loose, project):
                    found[name] = Server(name, False)
            continue
        groups = [data.get("mcpServers")]
        projects = data.get("projects") if isinstance(data.get("projects"), dict) else {}
        for key, entry in projects.items():
            if isinstance(key, str) and isinstance(entry, dict) and _same_place(key, project):
                groups.append(entry.get("mcpServers"))  # this project's only (local scope)
        for group in groups:
            if not isinstance(group, dict):
                continue
            for name, spec in group.items():
                if not isinstance(spec, dict):
                    continue
                remote = own and _is_remote(spec)
                s = Server(str(name), own and (remote or entry_wrapped(spec, project, home)), remote,
                           here=_listens_here(spec),
                           unwrappable=not _is_remote(spec) and not _has_command(spec),
                           untrusted=not own)
                old = found.get(s.name)
                if old is not None:
                    # `here`: an entry on this machine keeps the name bare whatever `wrap` does;
                    # `unwrappable`: no entry has a command `wrap` could wrap;
                    # `untrusted`: any entry of the project's `.mcp.json` (without a source) keeps
                    # the name bare, whatever the other entries are
                    s = Server(s.name, old.wrapped and s.wrapped, old.remote and s.remote,
                               here=old.here or s.here,
                               unwrappable=old.unwrappable and s.unwrappable,
                               untrusted=old.untrusted or s.untrusted)
                found[s.name] = s
    return found


def _names(data: Any, project: str) -> List[str]:
    out: List[str] = []
    if not isinstance(data, dict):
        return out
    groups = [data.get("mcpServers")]
    projects = data.get("projects") if isinstance(data.get("projects"), dict) else {}
    groups += [e.get("mcpServers") for k, e in projects.items()
               if isinstance(k, str) and isinstance(e, dict) and _same_place(k, project)]
    for g in groups:
        if isinstance(g, dict):
            out += [str(n) for n in g]
    return out


def _tool_prefix(name: str) -> str:
    """The `mcp__<server>__` prefix Claude Code gives a server's tools (other characters as
    `_`)."""
    return "mcp__" + re.sub(r"[^A-Za-z0-9_-]", "_", name) + "__"


def server_of(tool: str, project: str, home: str,
              trust_project: bool = True) -> Optional[Server]:
    """The configured server whose tool `tool` is, by its name only, or None (not an MCP tool, a
    plugin's or managed server, or unknown). Only for a hook input without `mcp_server` (an
    older Claude Code, Copilot): then the hook passes `trust_project` False, since a server of
    the app's own may have any name, `.mcp.json` too. The rest of the name after the server's
    prefix must hold no `__` (else it may be another server's tool, whose name begins the same
    way). When several names give the same prefix, the result is wrapped only if all are."""
    if not tool.startswith("mcp__"):
        return None
    every = servers(project, home, trust_project)
    hits = [s for s in every.values()
            if not s.name.startswith("\0") and tool.startswith(_tool_prefix(s.name))
            and "__" not in tool[len(_tool_prefix(s.name)):]]
    if not hits:
        return None
    unreadable = "\0unreadable" in every  # a config file whose servers are not all known
    if len(hits) == 1 and not unreadable:
        return hits[0]
    wrapped = all(s.wrapped for s in hits) and not unreadable
    # the entries of every name the tool may belong to: each needs its own launcher
    specs = tuple(x for s in hits for x in _by_name_specs(s.name, project, home)) if wrapped \
        else ()
    return Server(hits[0].name, wrapped and bool(specs),
                  all(s.remote for s in hits) and not unreadable, specs=specs)


# --- by the source Claude Code reports (hook input `mcp_server`, Claude Code 2.1.274 and newer) -----
#
# Claude Code names the server and where its definition came from, and uses only the entry of the
# highest scope (local, project, user, then plugins and connectors). phiward looks the entry up in
# exactly that scope, by its exact name. Docs: "Base trust decisions on `source` rather than on
# `name` or the `mcp__<server>__` tool-name prefix"; a configured server never reports `sdk`; an
# unknown source is a configured one phiward cannot read (bare).

MIN_SOURCE_VERSION = (2, 1, 274)
CONFIG_SOURCES = ("user", "local", "project")
_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand(value: Any, env: Dict[str, str]) -> Any:
    """`${VAR}` and `${VAR:-default}` filled in, in every string of an entry, as Claude Code does
    before it starts the server; an unset variable without a default stays as written."""
    if isinstance(value, str):
        def one(m: "re.Match[str]") -> str:
            if m.group(1) in env:
                return env[m.group(1)]
            return m.group(2) if m.group(2) is not None else m.group(0)
        return _PLACEHOLDER.sub(one, value)
    if isinstance(value, list):
        return [_expand(v, env) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v, env) for k, v in value.items()}
    return value


def shown(name: Any) -> str:
    """A server name as a refusal may show it: printable, without backticks, short (the docs:
    for any source other than `sdk`, `name` is untrusted text)."""
    text = re.sub(r"[^\x20-\x7e]", "?", str(name)).replace("`", "'")
    return text[:80] + ("..." if len(text) > 80 else "")


def _user_files(home: str) -> List[str]:
    return [user_file(home)]  # the one Claude Code reads


def _scope_specs(source: str, name: str, project: str, home: str
                 ) -> Optional[List[Tuple[dict, Dict[str, str]]]]:
    """The entries of `name` in the scope `source` (each with the placeholders it may use), or
    None when a file of that scope cannot be read strictly (then nothing of it is known)."""
    if source == "project":
        places = [(os.path.join(project, ".mcp.json"), ("mcpServers",))]
    elif source == "user":
        places = [(f, ("mcpServers",)) for f in _user_files(home)]
    else:
        places = [(f, ("projects", None, "mcpServers")) for f in _user_files(home)]
    out: List[Tuple[dict, Dict[str, str]]] = []
    for path, keys in places:
        data, why = _load(path)
        if why:
            return None
        for group in _groups(data, keys, project) if data is not None else []:
            if name in group:
                if not isinstance(group[name], dict):
                    return None
                out.append((group[name], {}))
    return out


def plugins_file(home: str, env: Optional[Dict[str, str]] = None) -> str:
    return os.path.join(claude_settings.user_dir(home, env), "plugins", "installed_plugins.json")


def _fill_env(project: str, env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """What Claude Code fills an entry's `${VAR}` from: the environment, without the hook's own
    plugin variables (the hook may run as a plugin's), with this project."""
    base = os.environ if env is None else env
    out = {k: v for k, v in base.items() if not k.startswith("CLAUDE_PLUGIN_")}
    out["CLAUDE_PROJECT_DIR"] = project
    return out


def _plugin_env(home: str, key: str, root: str) -> Dict[str, str]:
    """The plugin variables Claude Code gives a copy of plugin `key` installed at `root`: its
    folder and its data folder (`~/.claude/plugins/data/<id>`, every character of the id other
    than a letter, digit, `_` or `-` made `-`)."""
    data = os.path.join(os.path.dirname(plugins_file(home)), "data",
                        re.sub(r"[^A-Za-z0-9_-]", "-", key))
    return {"CLAUDE_PLUGIN_ROOT": root, "CLAUDE_PLUGIN_DATA": data}


def _plugin_group(root: str) -> Optional[Dict[str, Any]]:
    """The `mcpServers` a plugin installed at `root` declares (its `.mcp.json`, and `mcpServers`
    in its `plugin.json`: an object, or a file relative to the plugin), or None when one cannot
    be read."""
    group: Dict[str, Any] = {}
    data, why = _load(os.path.join(root, ".mcp.json"))
    if why:
        return None
    if data:
        servers = data.get("mcpServers", data)
        if not isinstance(servers, dict):
            return None
        group.update(servers)
    meta, why = _load(os.path.join(root, ".claude-plugin", "plugin.json"))
    if why:
        return None
    inline = (meta or {}).get("mcpServers")
    if isinstance(inline, str):
        path = os.path.normpath(os.path.join(root, inline))
        if not path.startswith(os.path.normpath(root) + os.sep):
            return None
        more, why = _load(path)
        if why or more is None:
            return None
        inline = more.get("mcpServers", more)
    if isinstance(inline, dict):
        for k, v in inline.items():
            if k in group and group[k] != v:
                return None  # two different entries for one name: not known which runs
            group[k] = v
    elif inline is not None:
        return None
    return group


_PLUGIN_RANK = {"local": 0, "project": 1}  # the more specific install wins; user and others: 2


def _plugin_roots(home: str, env: Dict[str, str], project: str, plugin: str
                  ) -> Optional[Dict[str, List[str]]]:
    """registry key (`plugin@market`) -> the install folders of the copies of `plugin` that apply
    to `project`: a copy made for another project (`projectPath`) does not; of the rest, only
    the most specific scope (local, then project, then the others). None when the registry, or
    an entry of this plugin, cannot be read. Other plugins' entries are not looked at."""
    reg, why = _load(plugins_file(home, env))
    if why or not isinstance(reg, dict) or not isinstance(reg.get("plugins"), dict):
        return None
    out: Dict[str, List[str]] = {}
    for key, installs in reg["plugins"].items():
        if not isinstance(key, str) or key.split("@", 1)[0] != plugin:
            continue
        ranked: List[Tuple[int, str]] = []
        for inst in installs if isinstance(installs, list) else [installs]:
            root = inst.get("installPath") if isinstance(inst, dict) else None
            if not isinstance(root, str) or not os.path.isabs(root) or "\0" in root:
                return None
            where = inst.get("projectPath")
            if where is not None and not isinstance(where, str):
                return None
            if where and not _same_place(where, project):
                continue
            scope = inst.get("scope")
            ranked.append((_PLUGIN_RANK.get(scope, 2) if isinstance(scope, str) else 2, root))
        if ranked:
            best = min(r for r, _ in ranked)
            out[key] = list(dict.fromkeys(root for r, root in ranked if r == best))
    return out


def _plugin_specs(name: str, home: str, env: Dict[str, str], project: str = ""
                  ) -> Optional[List[Tuple[dict, Dict[str, str]]]]:
    """The entries of a plugin's server (`plugin:<plugin>:<server>`) in every installed copy of
    that plugin that applies to `project`, each with `${CLAUDE_PLUGIN_ROOT}`; None when unknown
    or not readable."""
    parts = name.split(":")
    if len(parts) != 3 or parts[0] != "plugin" or not parts[1] or not parts[2]:
        return None
    plugin, server = parts[1], parts[2]
    keys = _plugin_roots(home, env, project or env.get("CLAUDE_PROJECT_DIR") or os.getcwd(),
                         plugin)
    if keys is None:
        return None
    out: List[Tuple[dict, Dict[str, str]]] = []
    for key, roots in keys.items():
        for root in roots:
            group = _plugin_group(root)
            if group is None:
                return None
            if server in group:
                if not isinstance(group[server], dict):
                    return None
                out.append((group[server], dict(_plugin_env(home, key, root), **{"\0key": key})))
    return out


def _segment(name: str, source: str) -> str:
    """The server part of its tools' names: `plugin_<plugin>_<server>` for a plugin's."""
    if source == "plugin":
        parts = name.split(":")
        if len(parts) == 3 and parts[0] == "plugin":
            return f"plugin_{parts[1]}_{parts[2]}"
    return name


def classify(mcp_server: Any, tool: str, project: str, home: str,
             env: Optional[Dict[str, str]] = None) -> Server:
    """The server of `tool` as the hook input's `mcp_server` names it, read from exactly that
    source. Bare unless it is found there and every entry for it is wrapped (or remote):
    `claudeai` connectors are remote; `sdk` and every source phiward does not read are bare.
    (The agent cannot rewrite these files during a session: the file tools refuse them, and
    Claude Code's sandbox denies `.mcp.json` and `~/.claude.json` to Bash.)"""
    env = _fill_env(project, env)
    if not isinstance(mcp_server, dict) or not isinstance(mcp_server.get("name"), str):
        return Server("?", False, False, "?")
    name = mcp_server["name"]
    source = mcp_server.get("source") if isinstance(mcp_server.get("source"), str) else "?"
    bare = Server(name, False, False, source)
    prefix = _tool_prefix(_segment(name, source))
    if not tool.startswith(prefix) or "__" in tool[len(prefix):] or not tool[len(prefix):]:
        return bare  # the tool is not this server's
    if source == "claudeai":
        return Server(name, True, True, source)
    if source in CONFIG_SOURCES:
        found = _scope_specs(source, name, project, home)
    elif source == "plugin":
        found = _plugin_specs(name, home, env, project)
    else:
        return bare
    if not found:
        return bare
    env["CLAUDE_PROJECT_DIR"] = project
    specs = [_expand(spec, dict(env, **extra)) for spec, extra in found]
    copies = tuple((extra.get("\0key", ""), extra.get("CLAUDE_PLUGIN_ROOT", ""))
                   for _spec, extra in found) if source == "plugin" else ()
    if not all(isinstance(s, dict) for s in specs):
        return bare
    try:
        texts = tuple(json.dumps(s, sort_keys=True) for s in specs)
        remote = all(_is_remote(s) for s in specs)
        # a configured entry by the one answer (its own id, not copied); a plugin's by its shape
        wrapped = remote or all(entry_wrapped(s, project, home) if source in CONFIG_SOURCES
                                else is_wrapped(_command(s), s) for s in specs)
        here = any(_listens_here(s) for s in specs)
    except (TypeError, ValueError, OSError):
        return bare  # an entry phiward cannot read
    return Server(name, wrapped, remote, source, texts, here=here, copies=copies,
                  unwrappable=not remote and not any(_has_command(x) for x in specs))


# --- the launcher's record: which wrapped servers really run ------------------------------------
#
# Claude Code starts its servers when a session starts (and again on `/mcp` reconnect): a server
# wrapped in the config after that still runs bare. So the config alone is not enough. Each
# `phiward launch` writes a record of its own process (pid, start time, parent, a hash of what it
# was told to run) in a folder the agent cannot write (a guard file; the confined child cannot
# reach it either), and removes it when it ends. The hook trusts a wrapped entry only when a live
# launcher of that command is a child of the hook's own Claude Code process: the nearest of the
# hook's ancestors that has launcher children. A launcher the agent starts from Bash has the
# sandboxed shell as its parent, never an ancestor of the hook, and could not write the record.

LAUNCHED_MAX = 512


def backups_root(home: str) -> str:
    """Where `wrap` keeps its backups: phiward's own folder, a guard file (config.guard_files)."""
    return os.path.join(home, ".phiward", "backups")


def backup_dir(path: str, home: str) -> str:
    """The backups of one config file: `original` (before phiward first changed it, never
    overwritten) and `last` (before the latest change), in a folder named by the file and a hash
    of where it really is."""
    import hashlib
    real = os.path.realpath(path)
    tag = hashlib.sha256(real.encode("utf-8", "surrogatepass")).hexdigest()[:12]
    return os.path.join(backups_root(home), f"{os.path.basename(path).lstrip('.')}-{tag}")


def _backup_folder(path: str, home: str) -> Tuple[str, str]:
    """The backup folder of `path`, made private (0700) and checked: (folder, "") or ("", why).
    Never through a link, and only folders of the operator's."""
    root = backups_root(home)
    folder = backup_dir(path, home)
    for d in (os.path.dirname(root), root, folder):
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            return "", f"{d} cannot be made ({exc.strerror})"
        try:
            st = os.lstat(d)
        except OSError as exc:
            return "", f"{d} cannot be read ({exc.strerror})"
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
            return "", f"{d} is a link or not your own folder"
    try:
        os.chmod(root, 0o700)
        os.chmod(folder, 0o700)
    except OSError as exc:
        return "", f"{folder} cannot be made private ({exc.strerror})"
    return folder, ""


def launched_dir(env: Optional[Dict[str, str]] = None) -> str:
    env = os.environ if env is None else env
    return os.path.join(pathid.home(env), ".phiward", "launched")


def _private_folder(folder: str) -> bool:
    """`folder` and the one above it (`~/.phiward`) are real folders of the operator's, not
    links, and `folder` is private: the records are trusted only there."""
    try:
        for path in (os.path.dirname(folder), folder):
            st = os.lstat(path)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
                return False
        return not os.lstat(folder).st_mode & 0o077
    except OSError:
        return False


def plugin_hash(root: Optional[str]) -> str:
    """What the record keeps of the launcher's `CLAUDE_PLUGIN_ROOT` (Claude Code exports it to a
    plugin's stdio server, never to a configured one's): "" without one."""
    import hashlib
    if not root:
        return ""
    try:
        root = os.path.realpath(root)  # `/var` and `/private/var`, a trailing `/`
    except (TypeError, ValueError):
        return "?"
    return hashlib.sha256(root.encode("utf-8", "surrogatepass")).hexdigest()


def _launcher_owner(env: Dict[str, str]) -> str:
    """The record's `plugin` for a launcher with environment `env`: "" only when it has no
    plugin variable at all (a configured server's); a plugin's folder hash; "?" (trusted for
    nothing) when a plugin variable is there but the folder is not."""
    if not any(k.startswith("CLAUDE_PLUGIN_") for k in env):
        return ""
    return plugin_hash(env.get("CLAUDE_PLUGIN_ROOT")) or "?"


def launch_hash(argv: List[str]) -> str:
    """What a launcher was told to run (its arguments after `launch`), as one hash."""
    import hashlib
    return hashlib.sha256(json.dumps([str(a) for a in argv]).encode()).hexdigest()


def _spec_hash(spec: dict) -> Optional[str]:
    """The launch hash of a wrapped entry (filled in), or None when it is not wrapped."""
    cmd = _command(spec)
    if not is_wrapped(cmd, spec):
        return None
    return launch_hash((_launch_rest(cmd) or [])[1:])


def view_hash(env: Dict[str, str], cwd: str) -> str:
    """A hash of what a launch profile is built from, derived as `launch` derives it: the hidden
    list, the protected roots and patterns. The launcher records it; the hook trusts the record
    only when its own is the same, so an entry's `env` (`KRB5CCNAME`, `KRB5_CONFIG`) or a change
    since the start cannot leave a wrapped server with a narrower profile. "" when the config
    cannot be used."""
    import hashlib
    from phiward import config, hidden
    try:
        cfg = config.load(cwd, env=env)
        if cfg.problem:
            return ""
        data = {"hidden": sorted(hidden.credentials(env, cfg)), "roots": sorted(cfg.all_roots),
                "patterns": sorted(cfg.patterns)}
    except (OSError, ValueError):
        return ""
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def record_launch(argv: List[str]) -> Optional[str]:
    """Called by `phiward launch` before it starts the tool: this process's record, or None when
    it cannot be written (then the server is just not trusted as wrapped). Never raises."""
    from phiward import procinfo, safeio
    try:
        me = os.getpid()
        got = procinfo.info(me)
        if got is None:
            return None
        folder = launched_dir()
        os.makedirs(folder, mode=0o700, exist_ok=True)
        st = os.lstat(folder)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
            return None
        os.chmod(folder, 0o700)
        if not _private_folder(folder):
            return None
        _prune(folder)
        path = os.path.join(folder, f"{me}.json")
        safeio.write_new(path, json.dumps({"pid": me, "ppid": got[0], "start": got[1],
                                           "argv": launch_hash(argv),
                                           "plugin": _launcher_owner(dict(os.environ)),
                                           "view": view_hash(dict(os.environ), os.getcwd())}),
                         mode=0o600)
        return path
    except (OSError, ValueError):
        return None


def end_launch(path: Optional[str]) -> None:
    if path:
        try:
            os.unlink(path)
        except OSError:
            pass


def _records(folder: str) -> List[dict]:
    """The records of live launchers: plain private files of the operator's, whose process still
    runs with the same parent and start time."""
    from phiward import procinfo, safeio
    out: List[dict] = []
    try:
        if not _private_folder(folder):
            return out
        # records only count toward the cap (a writer's hidden temp name sorts first)
        names = sorted(n for n in os.listdir(folder)
                       if n.endswith(".json") and not n.startswith("."))[:LAUNCHED_MAX]
    except OSError:
        return out
    for name in names:
        if not name.endswith(".json"):
            continue
        path = os.path.join(folder, name)
        try:
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
                continue
            rec = json.loads(safeio.read_text(path, limit=4096))
        except (OSError, ValueError):
            continue
        if not isinstance(rec, dict) or name != f"{rec.get('pid')}.json":
            continue
        pid, ppid, start = rec.get("pid"), rec.get("ppid"), rec.get("start")
        if not all(isinstance(x, int) and not isinstance(x, bool) for x in (pid, ppid, start)):
            continue
        if procinfo.info(pid) != (ppid, start) or not isinstance(rec.get("argv"), str):
            continue
        if not isinstance(rec.get("plugin"), str) or not isinstance(rec.get("view"), str):
            continue  # a record without them (an older or development build's): trusted for nothing
        out.append(rec)
    return out


def _prune(folder: str) -> None:
    """Remove the records of launchers that are gone."""
    from phiward import procinfo
    try:
        names = os.listdir(folder)
    except OSError:
        return
    import time
    for name in names[:4 * LAUNCHED_MAX]:
        path = os.path.join(folder, name)
        if not re.fullmatch(r"[0-9]+\.json", name):
            # another launcher's record being written (safeio's temporary name): only when old
            try:
                alive = time.time() - os.lstat(path).st_mtime < 60
            except OSError:
                continue
        else:
            try:
                with open(path, encoding="utf-8") as fh:
                    rec = json.loads(fh.read(4096))
                alive = procinfo.info(rec["pid"]) == (rec["ppid"], rec["start"])
            except (OSError, ValueError, KeyError, TypeError):
                alive = False
        if not alive:
            try:
                os.unlink(path)
            except OSError:
                pass


def _hash_of(spec: Any, env: Dict[str, str]) -> Optional[str]:
    """The launch hash of an entry filled in with `env`; None when not wrapped or malformed."""
    if not isinstance(spec, dict):
        return None
    try:
        return _spec_hash(_expand(spec, env))
    except (TypeError, ValueError, OSError):
        return None


def _segments(text: str) -> List[List[str]]:
    """The simple commands of a shell text (`sh -c "..."`), as words, split at `;`, `&&`, `|`."""
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        words = list(lex)
    except ValueError:
        words = text.split()
    out: List[List[str]] = [[]]
    for w in words:
        if w and all(c in "();<>|&" for c in w):
            out.append([])
        else:
            out[-1].append(w)
    return [seg for seg in out if seg]


def _launch_tails(words: List[str], depth: int = 0) -> List[List[str]]:
    """What follows each `launch` word, in the words and in any shell text among them (`nice
    phiward launch -- srv`, `env K=V phiward launch ...`, `sh -c "exec phiward launch -- srv"`)."""
    out = [words[i + 1:] for i in range(1, len(words)) if words[i] == "launch"]
    if depth < 3:
        for w in words:
            if any(c in w for c in " \t\n;&|"):
                for seg in _segments(w):
                    out += _launch_tails(seg, depth + 1)
    return out


def _twin_hashes(spec: Any, env: Dict[str, str]) -> set:
    """The launch hashes of an entry that may start a launcher, filled in with `env`, whatever
    else the entry sets and however it starts it (directly, through `nice` or `env`, or in a
    shell's text): for counting the entries that share a command. An entry that changes what
    runs (a `cwd`, an `env` key) or starts the launcher through another program is bare itself,
    yet its launcher has the same command and could vouch for another entry. Counting more than
    run only asks for more launchers (never trusts more)."""
    if not isinstance(spec, dict):
        return set()
    try:
        cmd = _command(_expand(spec, env))
    except (TypeError, ValueError, OSError):
        return set()
    return {launch_hash(t) for t in _launch_tails(cmd)}


def _strings(data: Any) -> List[str]:
    """Every string of a JSON value (decoded: an escape cannot hide one), keys too."""
    out: List[str] = []
    stack = [data]
    while stack:
        d = stack.pop()
        if isinstance(d, str):
            out.append(d)
        elif isinstance(d, dict):
            stack += list(d.keys()) + list(d.values())
        elif isinstance(d, list):
            stack += d
    return out


_STRINGS_CACHE: Dict[str, Tuple[tuple, List[str]]] = {}


def _server_strings(path: str) -> List[str]:
    """The strings of every `mcpServers` object of a config file (the top-level one and every
    project's), decoded; cached by the file's identity, size and change time, so one hook call
    reads a large `.claude.json` once."""
    try:
        st = os.stat(path)
    except OSError:
        return []
    key = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    hit = _STRINGS_CACHE.get(path)
    if hit and hit[0] == key:
        return hit[1]
    data, _why = _load(path)
    groups: List[Any] = []
    if isinstance(data, dict):
        groups.append(data.get("mcpServers"))
        projects = data.get("projects")
        if isinstance(projects, dict):
            groups += [e.get("mcpServers") for e in projects.values() if isinstance(e, dict)]
    out = _strings([g for g in groups if isinstance(g, dict)])
    _STRINGS_CACHE[path] = (key, out)
    return out


def id_count(eid: str, project: str, home: str) -> int:
    """How often an entry id occurs in the server entries of the config files Claude Code reads
    (every scope, every project's part of the user file): 1 for an entry no other copies. Only
    `mcpServers` objects count: an id in a prompt history the file also holds is no copy."""
    seen, n = set(), 0
    for path in _files(project, home):
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        n += sum(x.count(eid) for x in _server_strings(path))
    return n


def vouched(server: Server, project: str, home: str) -> bool:
    """Whether live launchers, children of this hook's Claude Code process, run the command of
    `server`'s wrapped entry. A configured server needs, for each of its entries, a launcher
    without a plugin folder started with that entry's own id (`entry_id`), an id no other
    string of the config files holds. A plugin's server needs, for each registry key, a launcher of one of its copies,
    with that copy's folder, one for each server of the copy with that command."""
    from phiward import procinfo
    specs: List[dict] = []
    for text in server.specs:
        try:
            specs.append(json.loads(text))
        except ValueError:
            return False
    if not specs:
        return False
    hashes = [_hash_of(s, {}) for s in specs]
    if None in hashes:
        return False
    live = _records(launched_dir())
    parents = {r["ppid"] for r in live}
    claude = next((a for a in procinfo.ancestors(depth=4) if a in parents), None)
    if claude is None:
        return False
    # the same profile as this hook would build: from the same hidden list, roots and patterns
    own = view_hash(dict(os.environ), project)
    mine = [(r["argv"], r["plugin"]) for r in live
            if r["ppid"] == claude and own and r["view"] == own]
    if not server.copies:
        # each entry has its own id, so its own launch hash: a launcher vouches for the one
        # entry whose id it was started with, and an id found twice (a copy of the entry, any
        # wrapper around it) is trusted for nothing
        for spec in specs:
            eid = entry_id(_command(spec))
            if eid is None or id_count(eid, project, home) != 1:
                return False
        return all(mine.count((h, "")) >= 1 for h in set(hashes))
    if len(server.copies) != len(hashes):
        return False
    by_key: Dict[str, List[Tuple[str, str]]] = {}
    for h, (key, root) in zip(hashes, server.copies):
        if not root:
            return False
        by_key.setdefault(key, []).append((h, root))
    for key, options in by_key.items():
        # filled in exactly as Claude Code fills it: the folder as the registry has it, the data
        # folder without a trailing `/` (another spelling may name another file)
        if not any(mine.count((h, plugin_hash(root))) >= _in_copy(root, h, dict(
                _fill_env(project), **_plugin_env(home, key, root))) for h, root in options):
            return False
    return True


def _in_copy(root: str, h: str, env: Dict[str, str]) -> float:
    """How many servers of the plugin copy at `root` run the command of launch hash `h`, filled
    in with `env` (at least 1); infinite when the copy cannot be read."""
    group = _plugin_group(root)
    if group is None:
        return float("inf")
    n = sum(1 for spec in group.values() if h in _twin_hashes(spec, env))
    return max(1, n)


def _by_name_specs(name: str, project: str, home: str) -> Tuple[str, ...]:
    """The entries of `name` in the operator's own scopes (user, local), filled in: for a hook
    input without `mcp_server`."""
    env = _fill_env(project)
    out: List[str] = []
    for scope in ("user", "local"):
        for spec, _extra in _scope_specs(scope, name, project, home) or []:
            out.append(json.dumps(_expand(spec, env), sort_keys=True))
    return tuple(out)


def trusted(server: Optional[Server], project: str, home: str) -> Optional[Server]:
    """`server` as the hook may trust it: a remote server as it is; a wrapped one only when a
    live launcher of its command runs for this Claude Code (`vouched`)."""
    if server is None or not server.wrapped or server.remote:
        return server
    if not server.specs:
        server = replace(server, specs=_by_name_specs(server.name, project, home))
    return server if vouched(server, project, home) else replace(server, wrapped=False)


# --- `phiward mcp wrap|unwrap|list`: the operator's command ----------------------------------------

USAGE = ("Run your local MCP servers in phiward's kernel profile (wrap), or as they were (unwrap);\n"
         "list says which are wrapped and the command for each that is not.\n"
         "usage: phiward mcp wrap NAME...|--all [--yes|-y]\n"
         "       phiward mcp unwrap NAME... [--yes|-y]   (only in your own terminal, even with "
         "--yes)\n"
         "       phiward mcp list\n")
_FLAGS = {"wrap": ("--yes", "-y", "--all"), "unwrap": ("--yes", "-y"), "list": ()}


def _places(project: str, home: str) -> List[tuple]:
    """(file, key path) of each `mcpServers` object phiward may change: the user's and this
    project's (local scope) in ~/.claude.json, and the project's .mcp.json."""
    user = user_file(home)
    return [(user, ("mcpServers",)), (user, ("projects", None, "mcpServers")),
            (os.path.join(project, ".mcp.json"), ("mcpServers",))]


def _groups(data: Any, keys: tuple, project: str) -> List[dict]:
    """The `mcpServers` objects at `keys`; None there stands for every project key that names
    this project (in any spelling)."""
    level = [data]
    for k in keys:
        nxt = []
        for d in level:
            if not isinstance(d, dict):
                continue
            if k is None:
                nxt += [v for key, v in d.items() if isinstance(key, str) and _same_place(key, project)]
            else:
                nxt.append(d.get(k))
        level = nxt
    return [g for g in level if isinstance(g, dict)]


def _wrapped_spec(spec: dict, exe: str) -> dict:
    new = dict(spec)
    new["command"] = exe
    new["args"] = ["launch", "--entry", new_entry_id(), "--"] + _command(spec)
    return new


def _unwrapped_spec(spec: dict) -> Optional[dict]:
    cmd = _command(spec)
    if not _well_formed(_launch_tail(cmd)) or os.path.basename(cmd[0]) not in LAUNCHER_NAMES:
        # any `phiward launch -- PROGRAM` by the launcher's name (another path too); a runner's
        # words would be lost (`entry_state` `runner`: the operator edits it)
        return None
    inner = cmd[cmd.index("--") + 1:]
    new = dict(spec)
    new["command"], new["args"] = inner[0], inner[1:]
    return new


def _say(cmd: List[str]) -> str:
    """A command line as the operator reads it: each word quoted, control characters shown as
    escapes (an entry from a repository's `.mcp.json` must not steer the terminal)."""
    return " ".join(shlex.quote(re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", str(w))) for w in cmd)


def entry_text(e: Entry, home: str, others: List[Entry] = ()) -> str:
    """What one entry is, and what to do about it, in a line of `mcp list` (`others`: the other
    entries of the same name)."""
    name = shown(e.name)
    if e.state == "wrapped":
        return "wrapped"
    if e.state == "copied":
        return (f"not wrapped: its entry id is also in another entry (a copy), so a launcher "
                f"cannot tell them apart; `phiward mcp wrap {name}` gives it an id of its own")
    if e.state == "runner":
        return "not wrapped: " + launcher_problem(e.spec) + f", then run `phiward mcp wrap {name}`"
    why = launcher_problem(e.spec) if e.state == "bare" else ""
    if why and not _well_formed(_launch_tail(_command(e.spec))):
        return f"not wrapped: {why}; fix the entry, or remove it and add the server again"
    if why:
        return (f"not wrapped: {why}; `phiward mcp wrap {name}` writes the installed launcher's "
                "full path")
    if e.state == "remote":
        if isinstance(e.spec, dict) and e.spec.get("headersHelper"):
            return ("remote, but its `headersHelper` runs a command here with your rights each "
                    "time Claude Code connects: keep that command a file no session can write")
        return "remote (runs nothing here)"
    gateway = "; its command tools may make only gateway calls"
    if e.state == "here":
        url = e.spec.get("url") if isinstance(e.spec, dict) else ""
        return (f"not wrapped: listens on this machine ({shown(url)}) and runs outside Claude "
                "Code, so it cannot be wrapped" + gateway)
    if e.state == "no-command":
        return "not wrapped: no command phiward can read, so it cannot be wrapped" + gateway
    if e.state == "changed":
        return ("not wrapped: wrapped, but its entry sets " + ", ".join(_changed_by(e.spec)) +
                ", which changes what runs; " + _changed_step(e.spec))
    text = f"not wrapped (runs with your rights): `phiward mcp wrap {name}`"
    stuck = [o for o in others if o.state in ("here", "no-command")]
    if stuck:
        text += (f"; the name stays not wrapped while its entry in "
                 f"{where(stuck[0].path, stuck[0].scope, home)} cannot be wrapped")
    return text


def _list(project: str, home: str) -> int:
    found = entries(project, home)
    for why in problems(project, home):
        print(f"{why}: its servers count as not wrapped until it can be read")
    if not found:
        if not problems(project, home):
            print(f"no MCP servers in {where(user_file(home), 'user', home)} or ./.mcp.json")
        return 0
    by_name: Dict[str, List[Entry]] = {}
    for e in found:
        by_name.setdefault(e.name, []).append(e)
    for name in sorted(by_name):
        group = by_name[name]
        for e in group:
            others = [o for o in group if o is not e]
            print(f"{shown(name)} ({where(e.path, e.scope, home)}): {entry_text(e, home, others)}")
    return 0


def main(argv: List[str]) -> int:
    import json
    from phiward import safeio
    if "-h" in argv or "--help" in argv:
        sys.stdout.write(USAGE)
        return 0
    if not argv or argv[0] not in ("wrap", "unwrap", "list"):
        sys.stderr.write(USAGE)
        return 2
    what, rest = argv[0], argv[1:]
    odd = [a for a in rest if a.startswith("-") and a not in _FLAGS[what]]
    if odd:
        sys.stderr.write(f"mcp {what}: unknown option {odd[0]}\n" + USAGE)
        return 2
    yes = "--yes" in rest or "-y" in rest
    names = [a for a in rest if not a.startswith("-")]
    every = "--all" in rest
    home = pathid.home()
    project = os.getcwd()
    if what == "list":
        return _list(project, home)
    try:
        tty = sys.stdin.isatty()
    except (AttributeError, ValueError):
        tty = False
    if what == "unwrap" and not tty:
        sys.stderr.write("mcp unwrap: run it in your own terminal (unwrapping gives the server "
                         "your full rights). Nothing was changed.\n")
        return 2
    if not names and not every:
        sys.stderr.write(USAGE)
        return 2
    exe = installed_launcher()
    if what == "wrap" and not exe:
        if _recorded_launchers() is not None:
            sys.stderr.write("mcp wrap: phiward's install record lists no `phiward` launcher; "
                             "reinstall it (uv tool install, pipx). Nothing was changed.\n")
        elif shutil.which("phiward"):
            sys.stderr.write("mcp wrap: phiward is found only in a PATH folder that the agent "
                             "or another account can write (a project's `.venv/bin`, a "
                             "group-writable folder), so it cannot be the launcher; install it "
                             "with uv tool or pipx, or make its folder writable by you alone "
                             "(`phiward doctor` names the folders phiward does not search). "
                             "Nothing was changed.\n")
        else:
            sys.stderr.write("mcp wrap: phiward is not on PATH; install it (uv tool, pipx) so "
                             "Claude Code can start `phiward launch`. Nothing was changed.\n")
        return 2
    known = servers(project, home)
    for n in names:
        if n not in known:
            sys.stderr.write(f"mcp {what}: no MCP server named {n} in ~/.claude.json or "
                             ".mcp.json. Nothing was changed.\n")
            return 2
    changes: Dict[str, tuple] = {}  # file -> (before text, data, [lines])
    env_keys: List[str] = []
    # a file that is a link or not a plain file is read where it leads, and never written: only
    # one that holds an entry to change stops the command (below)
    odd = set()
    twice: Dict[str, List[str]] = {}  # a file with a key given twice is never rewritten
    for path, keys in _places(project, home):
        if os.path.islink(path) or (os.path.lexists(path) and not os.path.isfile(path)):
            odd.add(path)
        if path in changes:
            text, data, lines = changes[path]
        else:
            try:
                text = safeio.read_text(path, limit=64 * 1024 * 1024, follow=path in odd)
                twice[path] = claude_settings.read_json(path)[2]
                data = json.loads(text)
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                sys.stderr.write(f"mcp {what}: {path} cannot be read ({type(exc).__name__}). "
                                 "Nothing was changed.\n")
                return 3
            lines = []
        found_groups = _groups(data, keys, project)
        if not found_groups:
            changes.setdefault(path, (text, data, lines))
            continue
        scope = ("project" if keys == ("mcpServers",) and path.endswith(".mcp.json") else
                 "local" if keys[0] == "projects" else "user")
        for group in found_groups:
            for name, spec in list(group.items()):
                if not isinstance(spec, dict) or not (every or name in names):
                    continue
                st = placed_state(spec, project, home)
                at = f"{shown(name)} ({where(path, scope, home)})"
                if st == "remote":
                    print(f"{at}: remote (runs nothing here); left as it is")
                    continue
                if st == "runner":
                    print(f"{at}: {entry_text(Entry(name, path, scope, spec, st), home)}; left "
                          "as it is")
                    continue
                if st in ("here", "no-command"):
                    if what != "wrap":
                        print(f"{at}: not wrapped; left as it is")
                    else:
                        print(f"{at}: {entry_text(Entry(name, path, scope, spec, st), home)}; "
                              "left as it is")
                    continue
                cmd = _command(spec)
                if what == "wrap" and st == "bare" and launcher_problem(spec) and \
                        not _well_formed(_launch_tail(cmd)):
                    print(f"{at}: not wrapped: {launcher_problem(spec)}; left as it is (fix the "
                          "entry)")
                    continue
                if what == "wrap" and (st == "copied" or st == "bare" and launcher_problem(spec)):
                    # its launcher by name, or one that is not the installed phiward: the
                    # installed one's full path, not a second wrap
                    new = dict(spec)
                    new["command"], (new["args"], dropped) = exe, _relaunch_args(cmd)
                    group[name] = new
                    lines.append(f"  {shown(name)} ({os.path.basename(path)}): {_say(cmd)}\n"
                                 f"    -> {_say(_command(new))}")
                    if dropped:
                        lines.append(f"    dropped: {_say(dropped)} (wrapped entries do not take "
                                     "options)")
                    continue
                if what == "wrap" and st == "wrapped":
                    print(f"{at}: wrapped already")
                    continue
                if what == "wrap" and st == "changed":
                    print(f"{at}: runs under `phiward launch`, but its entry sets "
                          + ", ".join(_changed_by(spec)) + ", which changes what runs: phiward "
                          "counts it as not wrapped until you remove that from the entry")
                    continue
                # the installed launcher's full path in every file: by name, a folder on PATH
                # the agent can write (a project's `.venv/bin`) could supply another one
                new = _wrapped_spec(spec, exe or "") if what == "wrap" else _unwrapped_spec(spec)
                if new is None:
                    print(f"{at}: not wrapped; left as it is")
                    continue
                if what == "wrap" and _changes_what_runs(new):
                    print(f"{at}: its entry sets " + ", ".join(_changed_by(new)) + ", which "
                          "changes what runs: phiward counts it as not wrapped until you remove "
                          "that from the entry")
                group[name] = new
                lines.append(f"  {shown(name)} ({os.path.basename(path)}): {_say(_command(spec))}\n"
                             f"    -> {_say(_command(new))}")
                if what == "wrap" and isinstance(spec.get("env"), dict):
                    env_keys += [k for k in spec["env"] if k not in env_keys]
        changes[path] = (text, data, lines)
    todo = {p: c for p, c in changes.items() if c[2]}
    for p in todo:
        if twice.get(p):
            sys.stderr.write(f"mcp {what}: {p} gives a key twice ({', '.join(twice[p][:3])}); "
                             "Claude Code reads the last one, and a rewrite would drop the "
                             "other: remove one yourself, then run `phiward mcp "
                             f"{what}` again. Nothing was changed.\n")
            return 3
        if p in odd:
            # never written through a link (it could point anywhere): the operator edits the
            # file it leads to
            sys.stderr.write(f"mcp {what}: {p} is a link or not a plain file (it leads to "
                             f"{os.path.realpath(p)}); edit the entry there yourself, or make "
                             f"{p} a plain file and run `phiward mcp {what}` again. Nothing was "
                             "changed.\n")
            return 3
    if not todo:
        print(f"mcp {what}: nothing to change.")
        return 0
    print("Close Claude Code first: it writes ~/.claude.json too, and a running session keeps "
          "each server as it started it.")
    for p, (_t, _d, lines) in todo.items():
        print(f"{p}:")
        for ln in lines:
            print(ln)
    if what == "wrap":
        print("Wrapped servers run in phiward's kernel profile: they cannot read protected "
              "data or your keys, and write only the project. Start Claude Code again once this "
              "is written: it starts each server as the file then says.")
        if env_keys:
            print("Their `env` keys reach a wrapped server only when `[launch] pass_env` in your "
                  "user config lists them: " + ", ".join(env_keys))
    if not yes:
        if not tty:
            print(f"mcp {what}: not written. Run it in your own terminal, or add --yes.")
            return 1
        if input("Write these changes? [y/N] ").strip().lower() not in ("y", "yes"):
            print(f"mcp {what}: not written.")
            return 1
    folders: Dict[str, str] = {}
    for p in todo:
        # the backups live only in phiward's own guarded folder, never beside the file (one
        # there could be the agent's): checked before anything is written
        folder, why = _backup_folder(p, home)
        if not folder:
            sys.stderr.write(f"mcp {what}: the backups folder: {why}. Nothing was changed.\n")
            return 3
        folders[p] = folder
    for p, (before, data, _lines) in todo.items():
        try:
            if safeio.read_text(p, limit=64 * 1024 * 1024) != before:
                sys.stderr.write(f"mcp {what}: {p} changed while this ran (Claude Code writes it "
                                 "too); run it again, best with Claude Code closed.\n")
                return 3
            mode = stat.S_IMODE(os.stat(p).st_mode)
            folder = folders[p]
            original = os.path.join(folder, "original")
            if not os.path.lexists(original):
                # the file before phiward first changed it: never overwritten
                safeio.write_new(original, before, mode=0o600)
            safeio.write_new(os.path.join(folder, "last"), before, mode=0o600)
            safeio.write_new(p, json.dumps(data, indent=2) + "\n", mode=mode)
        except OSError as exc:
            sys.stderr.write(f"mcp {what}: {p} cannot be written ({exc})\n")
            return 3
        base = os.path.basename(p)
        shown_folder = "~/" + os.path.relpath(folders[p], home)
        print(f"mcp {what}: wrote {p} (backups in {shown_folder}: `last`, before this change; "
              "`original`, before phiward first changed it)")
        if _same_place(p, os.path.join(project, ".mcp.json")):
            print(f"  {base} is shared with the repository and now names this machine's "
                  f"phiward ({exe}): a contributor whose phiward is elsewhere runs `phiward mcp "
                  "wrap` again.")
    return 0
