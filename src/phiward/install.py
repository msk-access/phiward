"""`phiward install claude [--user|--project] [--write [--yes]]`: wire Claude Code.

It builds two things from the phiward config:
- the PreToolUse hooks (shell, file tools, MCP tools), each with `onFailure: "block"`;
- the sandbox block: `enabled: true`, `allowUnsandboxedCommands: false`;
  `filesystem.denyRead` with every protected root (and the derived ones); `filesystem.denyWrite`
  with the same roots and the phiward config and code; `filesystem.allowWrite` with the
  broker's spool folder (gateway calls are clients that write a request there).

Without `--write` it prints them. With `--write` it merges them into the settings file, shows the
diff, and writes only after the operator says yes (on a terminal), or with `--yes` (the agent tool
asks the operator before it runs that command). It keeps a backup. It adds entries and turns on
what the guard needs; the only thing it removes is its own old gateway entries in
`excludedCommands` (older versions wrote them), because any entry there now means the shell is not confined.
"""

import difflib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from phiward import config, pathid
# what iteration 2 wrote; removed on merge (a gateway call now runs in the sandbox). One list,
# which the refusal's step reads too.
from phiward.claude_settings import OLD_EXCLUDES, install_removes  # noqa: F401

# every tool: a tool Claude Code adds later, an MCP resource reader, a web fetch, reaches the hook
# too (the adapter routes any tool name; the tools that only carry text are not text-checked)
MATCHERS = ["*"]
# what Claude Code reads as "every tool" (its docs): an older install's four groups are not
ALL_TOOLS = ("*", "", ".*")


def _rule_path(p: str, home: str) -> str:
    """A permission rule path: `~/x` under the home folder, `//x` for any other absolute path."""
    p = os.path.normpath(p)
    if p.startswith(home.rstrip("/") + "/"):
        return "~/" + p[len(home.rstrip("/")) + 1:]
    return "/" + p


def _sandbox_paths(xs: List[str], home: str) -> List[str]:
    """`_sandbox_path` of each, and for a link also the link's own path: a deny of the target
    alone leaves the link replaceable where its folder is writable (`~/.local/bin/phiward`)."""
    out: List[str] = []
    for x in xs:
        for v in ([_home_short(os.path.normpath(x), home)] if os.path.islink(x) else []) + [
                _sandbox_path(x, home)]:
            if v not in out:
                out.append(v)
    return out


def _sandbox_path(p: str, home: str) -> str:
    # the file system's own spelling: the kernel compares that one, not the config's letter case
    p = pathid.canon(p) if os.path.exists(p) else os.path.normpath(p)
    return _home_short(p, home)


def _home_short(p: str, home: str) -> str:
    """`~/...` for a path under the home folder: a settings file then holds no user name."""
    return "~/" + p[len(home.rstrip("/")) + 1:] if p.startswith(home.rstrip("/") + "/") else p


def pattern_sandbox(patterns: List[str], home: str) -> "tuple":
    """(denyRead, denyWrite) entries for the protected patterns (`claude_settings.pattern_entries`,
    `~/...` under the home folder). On macOS both; elsewhere only denyRead, an extra layer: the
    sandbox cannot deny writes to a wildcard path there."""
    from phiward import claude_settings
    entries = []
    for p in patterns:
        for e in (_home_short(x, home) for x in claude_settings.pattern_entries(p)):
            if e not in entries:
                entries.append(e)
    return entries, (entries if sys.platform == "darwin" else [])


def permission_rules(places: List[str], home: str = "") -> List[str]:
    """Claude Code permission deny rules for `places` (absolute paths): `Read` (which also stops
    Edit, Write, Grep and Glob) and `Edit` (NotebookEdit), for the path and below it. A second
    check inside Claude Code, beside the hook. Paths under `home` are written
    `~/...`, so a settings file holds no user name."""
    home = home or pathid.home()
    out: List[str] = []
    for p in places:
        r = _rule_path(p, home)
        for rule in (f"Read({r})", f"Read({r}/**)", f"Edit({r})", f"Edit({r}/**)"):
            if rule not in out:
                out.append(rule)
    return out


def edit_rules(places: List[str], home: str = "") -> List[str]:
    """Claude Code permission deny rules that stop its file tools from writing `places` (the
    files that control the guards): a second check inside Claude Code, beside the hook."""
    home = home or pathid.home()
    out: List[str] = []
    for p in places:
        r = _rule_path(p, home)
        for rule in (f"Edit({r})", f"Edit({r}/**)"):
            if rule not in out:
                out.append(rule)
    return out


# a project's committed hook: a clear refusal when phiward is not installed for this contributor,
# instead of a hook that cannot start (onFailure: block would then stop every tool call silently)
# `phiward` by name starts through its launcher's Python: a project's `env` must not choose the
# code it loads (the user wiring runs that Python with -I instead)
# every PYTHON*, LD_* and DYLD_* variable unset, whatever its name (PYTHONPYCACHEPREFIX too),
# __PYVENV_LAUNCHER__ (macOS framework, conda and Homebrew Pythons read it even with -I), and the
# others that make a library load code or read a file it names: OPENSSL_* (providers), MALLOC_*
# and macOS's Malloc*, and glibc's GCONV_PATH, LOCPATH, NLSPATH, GLIBC_TUNABLES, HOSTALIASES,
# LOCALDOMAIN, RES_OPTIONS, RESOLV_HOST_CONF, NIS_PATH, TZDIR and GETCONF_DIR, and a TZ that names a
# file (`/...`, `:/...`, or a path through `..`; a zone name stays). A deny list, not an
# allow list: the hook reads XDG_*, CLAUDE_CONFIG_DIR, KRB5* and the variables an SSH config names,
# listed by awk (by absolute path, so a project's PATH or an exported shell function cannot
# replace it); if awk cannot run, the hook stops with exit 2 (a refusal), never runs uncleaned
CLEAN_TOOLS = ("/usr/bin/awk",)
CLEARED_PREFIXES = ("PYTHON", "LD_", "DYLD_", "OPENSSL_", "MALLOC_", "Malloc")
CLEARED_NAMES = ("__PYVENV_LAUNCHER__", "GCONV_PATH", "LOCPATH", "NLSPATH", "GLIBC_TUNABLES",
                 "HOSTALIASES", "LOCALDOMAIN", "RES_OPTIONS", "RESOLV_HOST_CONF", "NIS_PATH",
                 "TZDIR", "GETCONF_DIR")
CLEAN_ENV = ('V=$(/usr/bin/awk "BEGIN{for(k in ENVIRON)if(k~/^(' + "|".join(CLEARED_PREFIXES) + ')'
             '[A-Za-z0-9_]*\\$/||k~/^(' + "|".join(CLEARED_NAMES) + ')\\$/||'
             '(k==\\"TZ\\"&&(ENVIRON[k]~/^:?\\//||ENVIRON[k]~/\\.\\./)))printf \\"%s \\",k}") '
             '|| { echo "phiward: /usr/bin/awk could not list the '
             'Python and loader variables to clear; every tool call is refused" >&2; exit 2; }; '
             'IFS=" "; unset $V; ')


def cleared(name: str, value: str = "") -> bool:
    """Whether the hooks' CLEAN_ENV unsets the variable `name` (with `value`)."""
    tz = value[1:] if value.startswith(":") else value
    return (name in CLEARED_NAMES or (name == "TZ" and (tz.startswith("/") or ".." in value)) or
            (name.startswith(CLEARED_PREFIXES) and
             all(c.isalnum() or c == "_" for c in name) and name.isascii()))


PROJECT_HOOK = ("/bin/sh -c 'command -v phiward >/dev/null 2>&1 || { echo \"phiward is not installed or "
                "not on PATH: install it (step 1 of its quickstart), then start Claude Code again; "
                "every tool call is refused until then\" >&2; exit 2; }; " + CLEAN_ENV
                + "exec phiward hook claude'")
# the same hook as an earlier release wrote it (another message only): still phiward's own
OLD_PROJECT_HOOKS = (PROJECT_HOOK.replace(
    "install it (step 1 of its quickstart), then start Claude Code again; every tool call is "
    "refused until then", "this project needs it (see its README); every tool call is refused "
    "until it is"),)
PROJECT_NOTE = ("/bin/sh -c 'command -v phiward >/dev/null 2>&1 || { echo \"phiward is not installed: "
                "its guards refuse every tool call until it is; ask the operator\"; exit 0; }; "
                + CLEAN_ENV + "exec phiward session-note claude'")


def _project_split(cfg: config.Config, project_dir: str) -> "tuple":
    """(roots of the repo config inside the project, as ./relative; every other root)."""
    rel, other = [], []
    user = set(cfg.user_roots)
    base = os.path.realpath(project_dir)
    for r in cfg.all_roots:
        rr = os.path.realpath(r)
        if r not in user and (rr == base or rr.startswith(base + "/")):
            rel.append("./" + os.path.relpath(rr, base))
        else:
            other.append(r)
    return rel, other


def wiring(cfg: config.Config, project: bool = False, project_dir: str = "",
           version: Optional[Tuple[int, int, int]] = None,
           block_reads: bool = False) -> Dict[str, Any]:
    """The hook and sandbox settings. `project=True` (the file a project commits): only what is
    the same for every contributor: the hooks (a bare `phiward`, with a clear refusal when it is
    missing), the session note, the sandbox switches, the hidden list as `~/...`, the repo
    config's roots inside the project as `./...`, the default spool. Everything personal (the
    user's roots, phiward's own files, this machine's ticket paths) goes to the local file
    (`local_wiring`: else the committed file named protected folders and the
    conda prefix)."""
    from phiward import hidden
    home = pathid.home()
    sp = (lambda xs: _sandbox_paths(list(xs), home))  # ~/... under the home folder
    secret = [h for h in hidden.paths(None, cfg, session=True) if h not in cfg.all_roots]
    if project:
        hook_cmd, note_cmd = PROJECT_HOOK, PROJECT_NOTE
        secret = [h for h in secret if h.startswith(home.rstrip("/") + "/")]
        rel, _other = _project_split(cfg, project_dir or os.getcwd())
        roots_sb, roots_rules = rel, [f"Read({r})" for r in rel] + [f"Read({r}/**)" for r in rel] \
            + [f"Edit({r})" for r in rel] + [f"Edit({r}/**)" for r in rel]
        guard: List[str] = []
        spool = config.spool_dir()
        allow = sp([spool]) if os.path.normpath(spool) == config.default_spool(home) else []
        ticket_globs: List[str] = []
    else:
        # phiward's own Python, isolated (-I): PYTHONPATH, PYTHONHOME and the user site folder,
        # which a project's settings could set, cannot choose the code the hook runs
        hook_cmd = isolated_command(sys.executable, "hook")
        note_cmd = isolated_command(sys.executable, "session-note")
        roots_sb = sp(cfg.all_roots)
        roots_rules = permission_rules(list(cfg.all_roots), home)
        guard = [g for g in config.guard_files() + config.command_paths(cfg) + config.listed_in_home(cfg) if g not in cfg.all_roots]
        allow = sp([config.spool_dir()])
        # Kerberos caches made later with other names (sssd: krb5cc_<uid>_XXXX)
        ticket_globs = list(hidden.KRB5_NAME_PATTERNS)  # the same list the hook refuses
    from phiward import claude_settings
    # the protected patterns, when this Claude Code reads wildcard entries as the hook does
    wild = bool(not project and version and version >= claude_settings.VERSION_PATTERNS)
    pat_read, pat_write = pattern_sandbox(list(cfg.patterns), home) if wild else ([], [])
    # git's control files at any depth below the home folder (a submodule's config, a
    # worktree's commondir, hooks): Claude Code runs git outside its sandbox, so the shell must
    # not write what git then runs. macOS only: elsewhere the sandbox has no wildcard denyWrite
    git_write = list(claude_settings.GIT_CONTROL_GLOBS) if (
        wild and sys.platform == "darwin") else []
    entry: Dict[str, Any] = {"type": "command", "command": hook_cmd}
    note: Dict[str, Any] = {"type": "command", "command": note_cmd}
    entry.update({"timeout": 10, "onFailure": "block"})
    # the start-of-session note: every session knows the rules before its first refusal
    note["timeout"] = 10
    out = {
        "hooks": {"PreToolUse": [{"matcher": m, "hooks": [dict(entry)]} for m in MATCHERS],
                  "SessionStart": [{"hooks": [note]}]},
        "permissions": {"deny": _once(roots_rules + permission_rules(secret, home)
                                      + edit_rules(guard, home))},
        "sandbox": {
            "enabled": True,
            # without it, Claude Code runs commands unsandboxed when the sandbox cannot start
            # (on Linux: no bubblewrap, a nested container), and the hook would trust a sandbox
            # that is not there
            "failIfUnavailable": True,
            "allowUnsandboxedCommands": False,
            "filesystem": {
                # the hidden list too: a Bash command may not read a key or ticket
                "denyRead": _once(roots_sb + pat_read + sp(secret) + ticket_globs),
                # the project's own Claude Code settings: a Bash command must not rewrite them
                # (`printf ... > .claude/settings.local.json`)
                # and all of phiward's own folder (config.sandbox_denied)
                "denyWrite": _once(roots_sb + pat_write + git_write + sp(guard) + sp(secret)
                                   + sp(config.sandbox_denied())
                                   + ([f"./{f}" for f in claude_settings.PROJECT_FILES]
                                      if project else [])),
                "allowWrite": allow,
            },
        },
    }
    if block_reads and not project:
        # defence in depth around the project: the file tools read nothing outside the working
        # folders, and a call that would wait on a prompt is refused (each from its version on)
        out["permissions"].update(_read_blocking(version))
    if not project:
        # the shell pinned to bash (the hook reads commands as bash)
        out["env"] = {"CLAUDE_CODE_SHELL": claude_settings.BASH}
    if cfg.network_limit and not project:
        # Claude Code honours strictAllowlist only from the user (or managed) settings, and
        # then ignores a repository's allowedDomains and WebFetch allow rules
        out["sandbox"]["network"] = {"strictAllowlist": True,
                                     "allowedDomains": list(cfg.allowed_domains)}
    return out


# the file `claude --settings` reads (config.launch_settings_path): `allowUnsandboxedCommands:
# false` from `--settings` makes the sandbox admin-required (no admin rights needed), so a
# repository's settings cannot turn it off, exclude commands or add writable paths. Source:
# code.claude.com/docs/en/sandboxing, "Repository settings under an admin-required sandbox".
# The hook cannot see this file: it still checks the user and project settings itself
LAUNCH_SETTINGS: Dict[str, Any] = {"sandbox": {
    "enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False}}


def _write_launch_settings() -> int:
    """Write the `--settings` file (replacing a different one, never through a link) and say
    how to start Claude Code with it."""
    from phiward import safeio
    path = config.launch_settings_path()
    folder = os.path.dirname(path)
    text = json.dumps(LAUNCH_SETTINGS, indent=2) + "\n"
    try:
        if os.path.islink(folder):
            # a dotfiles setup: allowed when it leads to a folder of the operator's that no one
            # else can write (config.guard_files guards both names)
            st = os.stat(folder)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
                raise OSError(f"{folder} is a link to a place that is not a folder only you "
                              "can write")
        elif os.path.lexists(folder) and not os.path.isdir(folder):
            raise OSError(f"{folder} is not a plain folder")
        if os.path.islink(path) or (os.path.lexists(path) and not os.path.isfile(path)):
            raise OSError(f"{path} is a link or not a plain file")
        try:
            same = safeio.read_text(path) == text
        except FileNotFoundError:
            same = False
        if not same:
            os.makedirs(folder, mode=0o700, exist_ok=True)
            safeio.write_new(path, text, mode=0o644)
            print(f"install: wrote {path}")
    except (OSError, safeio.UnsafeFile) as exc:
        print(f"install refused: the file for `claude --settings` cannot be written: {exc}",
              file=sys.stderr)
        return 3
    print(f"Start Claude Code with `claude --settings {path}` so that a repository's settings "
          "cannot turn its sandbox off or loosen it. For example, add this line to your shell "
          f"startup file yourself:\n  alias claude='claude --settings {path}'")
    return 0


def _once(items: List[str]) -> List[str]:
    """`items` without repeats, in order (a path can be both a guard file and hidden)."""
    return list(dict.fromkeys(items))


def _entry_key(h: Any) -> "tuple":
    """A hook entry's command line and whether it is in exec form (written by an older phiward
    with the shell prefix): the same line in the two forms is two entries."""
    return (_entry_text(h), "args" in h) if isinstance(h, dict) else ("", False)


def _entry_text(h: Dict[str, Any]) -> str:
    """A hook entry as one command line, in shell form or exec form (`/bin/sh` and `-c X`)."""
    args = h.get("args")
    if isinstance(args, list) and h.get("command") == "/bin/sh" and len(args) == 2 \
            and args[0] == "-c" and isinstance(args[1], str):
        return "/bin/sh -c " + shlex.quote(args[1])
    return str(h.get("command", ""))


def isolated_command(python: str, what: str) -> str:
    """The user wiring's command for `phiward <what> claude`: phiward's own Python, isolated
    (-I: no PYTHON* variable, no user site folder), started by /bin/sh after CLEAN_ENV has
    unset every PYTHON*, LD_* and DYLD_* variable (-I does not cover the loader's)."""
    inner = f"{CLEAN_ENV}exec {shlex.quote(python)} -I -m phiward {what} claude"
    return "/bin/sh -c " + shlex.quote(inner)


def isolated_python(command: str, what: str = "hook") -> str:
    """The Python of an `isolated_command`, or "" when `command` is not exactly one."""
    try:
        words = shlex.split(command)
    except ValueError:
        return ""
    if len(words) != 3 or words[:2] != ["/bin/sh", "-c"] or not words[2].startswith(
            CLEAN_ENV + "exec "):
        return ""
    try:
        rest = shlex.split(words[2][len(CLEAN_ENV) + len("exec "):])
    except ValueError:
        return ""
    if len(rest) == 6 and rest[0].startswith("/") and rest[1:] == ["-I", "-m", "phiward",
                                                                  what, "claude"]:
        return rest[0]
    return ""


# a user-wiring entry phiward wrote, in any of its forms (the launcher by path, an earlier
# `<python> -I -m phiward`, the isolated command): `merge` replaces those it is not writing,
# so the hook does not run twice
_LAUNCHER_FORMS = re.compile(r"^(?:(?:\S*/)?(?:phiward|agent-guards)|(?:'[^']*'|\S+) -I -m phiward) "
                             r"(?:hook|session-note) claude$")


def _is_phiward_user_entry(command: str) -> bool:
    return bool(_LAUNCHER_FORMS.match(command)) or any(
        isolated_python(command, w) for w in ("hook", "session-note"))


def _drop_old_commands(groups: List[Any], keep: Set["tuple"]) -> None:
    for g in groups:
        if isinstance(g, dict) and isinstance(g.get("hooks"), list):
            g["hooks"] = [h for h in g["hooks"] if not (
                isinstance(h, dict) and _is_phiward_user_entry(_entry_text(h))
                and _entry_key(h) not in keep)]
    groups[:] = [g for g in groups if not (isinstance(g, dict) and g.get("hooks") == [])]


def _isolated_import_problem() -> str:
    """Why the hook as written (this Python, -I) would not start, or "": an install in the user
    site folder is not seen with -I, and then every tool call would be refused without a word."""
    try:
        r = subprocess.run([sys.executable, "-I", "-c", "import phiward"], cwd="/",
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"{sys.executable} cannot import phiward with -I ({type(exc).__name__})"
    if r.returncode != 0:
        return (f"{sys.executable} cannot import phiward with -I (an install in the user site "
                "folder is not seen there, and the hook would refuse every tool call). Install "
                "phiward with `uv tool install` or `pipx`, then run this again.")
    return ""


def fix_own_modes() -> None:
    """phiward's own Python, writable by the operator alone (`selfcheck.fix_modes`): with a
    shared group and umask 002 the installer left it group-writable, and the self-check (before
    `launch` and every wrapped MCP server) and doctor's full check would refuse it. What it
    cannot change (the home folder, a folder outside it) gets the one step."""
    from phiward import selfcheck
    try:
        if selfcheck.launcher_scripts() is None:
            return  # a source checkout or an editable install: not phiward's own copy to change
        places = selfcheck.python_places()
        changed = selfcheck.fix_modes(places)
        left = selfcheck.check_python(places)
    except OSError:
        return
    if changed:
        home = selfcheck._home()
        shown = [selfcheck._shown(c, home) for c in changed]
        more = f" and {len(shown) - 10} more" if len(shown) > 10 else ""
        print("install: made phiward's own Python writable by you alone (a group others share "
              f"could write it), in: {', '.join(shown[:10])}{more}")
    if left:
        print(f"install: phiward's own Python still fails its check ({left[0]}): "
              + selfcheck.fix_text(left, selfcheck._running_package()))


def merge(current: Dict[str, Any], want: Dict[str, Any]) -> Dict[str, Any]:
    out = json.loads(json.dumps(current))
    hooks = out.setdefault("hooks", {}).setdefault("PreToolUse", [])
    wanted = {_entry_key(h) for k in ("PreToolUse", "SessionStart")
              for g in want["hooks"].get(k, []) for h in g["hooks"]}
    if any(_is_phiward_user_entry(c) for c, _x in wanted):  # the user wiring: replace older forms
        _drop_old_commands(hooks, wanted)
        if isinstance(out["hooks"].get("SessionStart"), list):
            _drop_old_commands(out["hooks"]["SessionStart"], wanted)
    # phiward's own entries under other matchers (an older install's four groups): dropped, so
    # one tool call never runs the hook twice
    mine = {_entry_key(h) for g in want["hooks"]["PreToolUse"] for h in g["hooks"]}
    matchers = {g["matcher"] for g in want["hooks"]["PreToolUse"]}
    for g in hooks:
        if isinstance(g, dict) and g.get("matcher") not in matchers and \
                isinstance(g.get("hooks"), list):
            g["hooks"] = [h for h in g["hooks"] if not (isinstance(h, dict)
                                                         and _entry_key(h) in mine)]
    for g in hooks if any(k[0] == PROJECT_HOOK for k in mine) else []:
        # a project hook as an earlier release wrote it (another message only): replaced, only
        # when this wiring writes the project hook (init's `--no-hooks` keeps it)
        if isinstance(g, dict) and isinstance(g.get("hooks"), list):
            g["hooks"] = [h for h in g["hooks"] if not (isinstance(h, dict)
                                                         and h.get("command") in OLD_PROJECT_HOOKS)]
    hooks[:] = [g for g in hooks if not (isinstance(g, dict) and g.get("hooks") == [])]
    have = {(g.get("matcher"), _entry_key(h)) for g in hooks if isinstance(g, dict)
            for h in g.get("hooks", []) if isinstance(h, dict)}
    for g in want["hooks"]["PreToolUse"]:
        if (g["matcher"], _entry_key(g["hooks"][0])) not in have:
            hooks.append(g)
    starts = want["hooks"].get("SessionStart", [])
    if starts:
        have_start = out["hooks"].setdefault("SessionStart", [])
        cmds = {_entry_key(h) for g in have_start if isinstance(g, dict)
                for h in g.get("hooks", []) if isinstance(h, dict)}
        for g in starts:
            if _entry_key(g["hooks"][0]) not in cmds:
                have_start.append(g)
    sb = out.setdefault("sandbox", {})
    sb["enabled"] = True
    if "failIfUnavailable" in want["sandbox"]:
        sb["failIfUnavailable"] = True
    sb["allowUnsandboxedCommands"] = False
    if isinstance(sb.get("excludedCommands"), list):
        sb["excludedCommands"] = [c for c in sb["excludedCommands"] if not install_removes(c)]
        if not sb["excludedCommands"]:
            del sb["excludedCommands"]
    fs = sb.setdefault("filesystem", {})
    for key, values in want["sandbox"]["filesystem"].items():
        have = fs.setdefault(key, [])
        for v in values:
            if v not in have:
                have.append(v)
    if "network" in want["sandbox"]:
        net = sb.setdefault("network", {})
        net["strictAllowlist"] = True
        domains = net.setdefault("allowedDomains", [])
        for d in want["sandbox"]["network"]["allowedDomains"]:
            if d not in domains:
                domains.append(d)
    if want.get("env"):
        env = out.get("env") if isinstance(out.get("env"), dict) else {}
        env.update(want["env"])
        # the shell prefix of an older phiward goes (it would wrap the hooks); a prefix the
        # operator set is theirs and stays
        if env.get("CLAUDE_CODE_SHELL_PREFIX") == config.shell_prefix_path():
            del env["CLAUDE_CODE_SHELL_PREFIX"]
        out["env"] = env
    perms = out.setdefault("permissions", {})
    for key, value in want.get("permissions", {}).items():
        if key != "deny" and value is True:
            perms[key] = True
    deny = perms.setdefault("deny", [])
    for rule in want.get("permissions", {}).get("deny", []):
        if rule not in deny:
            deny.append(rule)
    return out


def local_wiring(cfg: config.Config, project_dir: str = "") -> Dict[str, Any]:
    """What `--project` writes into `.claude/settings.local.json` (personal, not committed):
    everything the committed file leaves out: the user's own protected roots (and repo roots
    outside the project), phiward's own files (config, code, launcher), the hidden list entries
    of this machine outside the home folder, the ticket name globs, a spool that is not the
    default."""
    from phiward import hidden
    home = pathid.home()
    sp = (lambda xs: _sandbox_paths(list(xs), home))
    _rel, roots = _project_split(cfg, project_dir or os.getcwd())
    machine = [h for h in hidden.paths(None, cfg, session=True)
               if h not in cfg.all_roots and not h.startswith(home.rstrip("/") + "/")]
    guard = [g for g in config.guard_files() + config.command_paths(cfg) + config.listed_in_home(cfg) if g not in cfg.all_roots]
    globs = ["/tmp/krb5cc*", "/private/tmp/krb5cc*", "/var/tmp/krb5cc*"]
    spool = config.spool_dir()
    allow = [] if os.path.normpath(spool) == config.default_spool(home) else sp([spool])
    return {
        "hooks": {"PreToolUse": []},
        "permissions": {"deny": permission_rules(roots + machine, home)},
        "sandbox": {"filesystem": {"denyRead": sp(roots) + sp(machine) + globs,
                                   "denyWrite": sp(roots) + sp(guard) + sp(machine),
                                   "allowWrite": allow}},
    }


# variables that choose what the guards read: from an agent tool (no terminal) they are refused,
# since the agent would choose them. The Kerberos variables are not here: a session usually has
# them, and the default ticket places are hidden whatever they say (docs/setup.md, the
# agent-run first setup)
OVERRIDES = ("PHIWARD_CONFIG", "PHIWARD_SPOOL", "XDG_CONFIG_HOME", "XDG_CACHE_HOME")


def agent_override_problem() -> str:
    """Without a terminal (an agent tool runs it), the settings must come from the default
    places: a spool or config the agent names would end up in the sandbox's write places, or
    as the config the guards read. "" when there is nothing to refuse."""
    over = [k for k in OVERRIDES if os.environ.get(k)]
    try:
        tty = sys.stdin.isatty()
    except (AttributeError, ValueError):
        tty = False
    if over and not tty:
        return (f"{', '.join(over)} is set and this is not a terminal; run it in your own "
                "terminal, or without those variables")
    return ""


def _claude_folder_problem(project: str) -> str:
    """The project's `.claude` folder and its settings files must be real, inside the project."""
    base = os.path.realpath(project)
    d = os.path.join(project, ".claude")
    if os.path.islink(d) or (os.path.exists(d) and not os.path.realpath(d).startswith(base + "/")):
        return "the project's .claude folder is a link or leads outside the project"
    for n in ("settings.json", "settings.local.json"):
        if os.path.islink(os.path.join(d, n)):
            return f".claude/{n} is a link"
    return ""


def plugin_state(project: str, home: str) -> "tuple":
    """(effective, level, project_off, project_path): whether the phiward plugin is on, as Claude
    Code reads `enabledPlugins` (the highest level that names it wins), the level that decides,
    whether a project level turns it off, and whether a project level sets `env.PATH` (the
    plugin's hooks run `phiward` by name)."""
    from phiward import claude_settings
    effective, level, off, path = None, "", False, False
    for lvl, _p, data in claude_settings.levels(project, home):
        if not isinstance(data, dict):
            continue
        if lvl.startswith("project") and isinstance(data.get("env"), dict) and "PATH" in data["env"]:
            path = True
        plugins = data.get("enabledPlugins")
        if not isinstance(plugins, dict):
            continue
        for k, v in plugins.items():
            if isinstance(k, str) and k == "phiward@phiward":
                if lvl.startswith("project") and v is False:
                    off = True
                if effective is None:
                    effective, level = v is True, lvl
    return bool(effective), level, off, path


def _env_notes(current: Dict[str, Any], after: Dict[str, Any]) -> List[str]:
    """What the merge changes in the settings' `env` that the operator set."""
    before = current.get("env") if isinstance(current.get("env"), dict) else {}
    return [f"env.{k} was {before[k]!r}; it becomes {after['env'][k]!r} (the hook reads "
            "commands as bash)" for k in ("CLAUDE_CODE_SHELL",)
            if k in before and before[k] != after.get("env", {}).get(k)]


def _write(target: str, want: Dict[str, Any], notes: List[str], argv: List[str]) -> int:
    """Merge `want` into `target` after a yes. Read and written never through a link (a project's
    `.claude` folder is one the agent can write): the target is read only as a regular file, and
    the backup and the target are written through fresh names (`safeio.write_new`)."""
    from phiward import safeio
    try:
        before_text = safeio.read_text(target)
        current = json.loads(before_text) if before_text.strip() else {}
        if not isinstance(current, dict):
            raise ValueError("not an object")
    except FileNotFoundError:
        before_text, current = "", {}
    except safeio.UnsafeFile as exc:
        print(f"install refused: {target}: {exc}; make it a plain file, then run install again",
              file=sys.stderr)
        return 3
    except (OSError, ValueError) as exc:
        print(f"install refused: {target} cannot be read as JSON ({type(exc).__name__})",
              file=sys.stderr)
        return 3
    after = merge(current, want)
    after_text = json.dumps(after, indent=2) + "\n"
    if after_text == before_text or after == current:
        print(f"{target} already has the phiward wiring.")
        return 0
    notes = notes + _env_notes(current, after)
    diff = difflib.unified_diff(before_text.splitlines(True), after_text.splitlines(True),
                                fromfile=f"{target} (now)", tofile=f"{target} (new)")
    sys.stdout.writelines(diff)
    for n in notes:
        print(f"Note: {n}")
    if "--yes" not in argv:
        if not sys.stdin.isatty():
            print("install: not written. Run it on a terminal to answer, or add --yes.")
            return 1
        answer = input(f"Write these changes to {target}? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("install: not written.")
            return 1
    os.makedirs(os.path.dirname(target), exist_ok=True)
    try:
        if before_text:
            safeio.write_new(target + ".phiward.bak", before_text, mode=0o600)
        safeio.write_new(target, after_text, mode=0o644)
    except OSError as exc:
        print(f"install refused: {target} cannot be written ({exc})", file=sys.stderr)
        return 3
    print(f"install: wrote {target}" + (" (backup: .phiward.bak)" if before_text else ""))
    return 0


def _patterns_note(project: bool, version: Optional[Tuple[int, int, int]]) -> str:
    """What the wiring does with the protected patterns, and why."""
    from phiward import claude_settings
    need = claude_settings.version_text(claude_settings.VERSION_PATTERNS)
    if project:
        return ("Protected patterns go to the sandbox only from `install claude --user`; until "
                "then the hook's text check for shell commands is best effort for them.")
    if not version or version < claude_settings.VERSION_PATTERNS:
        return (f"Protected patterns are not added to the sandbox: that needs Claude Code {need} "
                "or newer (`claude --version` gave none or older). Until then the hook's text "
                "check for shell commands is best effort for them.")
    if sys.platform != "darwin":
        return ("Protected patterns are added to denyRead only: on this system the sandbox cannot "
                "deny writes to a wildcard path, and a match made while a command runs is "
                "readable in it, so the shell does not count as confined and the hook refuses "
                "shell commands; protect plain folders (roots) instead, or use `phiward run`.")
    return "Protected patterns are added to denyRead and denyWrite (with /** for what is inside)."


def _read_blocking(version: Optional[Tuple[int, int, int]]) -> Dict[str, bool]:
    """The read-blocking permission settings this Claude Code knows."""
    from phiward import claude_settings
    out: Dict[str, bool] = {}
    if version and version >= claude_settings.VERSION_BLOCK_READS:
        out["blockReadsOutsideWorkingDirectories"] = True
    if version and version >= claude_settings.VERSION_DENY_PROMPTS:
        out["denyInsteadOfPrompting"] = True
    return out


USAGE = ("usage: phiward install claude [--user|--project] [--no-hooks] "
         "[--block-outside-reads] [--write [--yes]]\n"
         "       phiward install claude --json")
HELP = USAGE + """

Options:
  --user       the user settings, ~/.claude/settings.json (the default)
  --project    the project settings: .claude/settings.json for what every contributor
               shares, and .claude/settings.local.json for this machine's own entries
  --no-hooks   write only the sandbox and permission settings, not the hooks (the hooks
               then come from your user wiring or the plugin)
  --block-outside-reads
               with --user: set permissions.blockReadsOutsideWorkingDirectories (Claude Code
               2.1.257 or newer: Read, Grep and Glob refuse paths outside the working folders)
               and permissions.denyInsteadOfPrompting (2.1.319 or newer: a call that would
               wait on a prompt is refused). Defence in depth around the project
  --write      merge the wiring into the settings file, show the difference, and write it
               after a yes on a terminal. A backup is kept as .phiward.bak.
  --yes        with --write: write without the question
  --json       print the user wiring as one JSON object and change nothing: for an Agent SDK
               app (its `settings` option) or `claude -p --settings FILE`, so the session is
               guarded even when it loads no settings file (docs/unattended.md)
  -h, --help   show this help

Build the Claude Code wiring from the phiward config: the hooks that run before each tool
call, and the sandbox and permission settings that keep protected data out of the shell.
Without --write it prints the wiring and changes nothing; printing (and --json) runs only in
your own terminal, because the wiring names every protected path. It adds entries and turns on what
the guard needs. It removes only old entries that phiward itself wrote. Without a terminal, --write refuses when PHIWARD_CONFIG, PHIWARD_SPOOL,
XDG_CONFIG_HOME or XDG_CACHE_HOME is set.
"""


def main(argv: List[str]) -> int:
    if "-h" in argv or "--help" in argv:  # also after `claude`: help prints no wiring
        print(HELP, end="")
        return 0
    if argv[:1] != ["claude"]:
        print(f"install: phiward wires Claude Code only (`claude`), not {argv[0]!r}: "
              "`(cd ~ && phiward install claude --user --write)`" if argv else
              "install: name the tool: `(cd ~ && phiward install claude --user --write)`",
              file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2
    cwd = os.getcwd()
    why = agent_override_problem() if "--write" in argv else ""  # printing changes nothing
    if why:
        print(f"install refused: {why}", file=sys.stderr)
        return 2
    spool = os.path.normpath(config.spool_dir())
    for d in config.sandbox_denied():
        if spool == d or spool.startswith(d.rstrip("/") + "/"):
            print(f"install refused: PHIWARD_SPOOL ({spool}) is inside {d}, which the sandbox "
                  "denies in full, so the agent could not write its requests; choose a spool "
                  "outside it (the default is ~/.phiward-spool)", file=sys.stderr)
            return 2
    # the user wiring is for every session: from the user config only, never from the repo
    # config of the folder it happens to run in (its roots would land in the user settings)
    cfg = config.load(cwd if "--project" in argv else "/")
    if cfg.problem:
        print(f"install refused: the phiward config cannot be used: {cfg.problem}",
              file=sys.stderr)
        return 3
    if "--write" not in argv and not sys.stdin.isatty():
        # the wiring names every protected root: printed, it is for the operator's own eyes
        print("install refused: printing the wiring shows your protected paths, so it runs "
              "only in your own terminal (or use --write, which writes it without printing it "
              "here)", file=sys.stderr)
        return 2
    if not cfg.has_protected_paths:
        print("Note: no protected paths are configured; the guards will do nothing yet.",
              file=sys.stderr)
    home = pathid.home()
    project = "--project" in argv
    from phiward import claude_settings
    # the user settings where Claude Code reads them (CLAUDE_CONFIG_DIR too), as doctor does
    target = (os.path.join(cwd, ".claude", "settings.json") if project else
              os.path.join(claude_settings.user_dir(home), "settings.json"))
    version = claude_settings.claude_version()
    block_reads = "--block-outside-reads" in argv
    if block_reads and (project or not _read_blocking(version)):
        print("install refused: --block-outside-reads is for the user wiring, with Claude Code "
              f"{claude_settings.version_text(claude_settings.VERSION_BLOCK_READS)} or newer "
              "(`claude --version` gave none or older)", file=sys.stderr)
        return 2
    want = wiring(cfg, project, cwd, version, block_reads)
    if block_reads and "denyInsteadOfPrompting" not in want["permissions"]:
        print("Note: permissions.denyInsteadOfPrompting needs Claude Code "
              f"{claude_settings.version_text(claude_settings.VERSION_DENY_PROMPTS)}; run this again "
              "after you update it.", file=sys.stderr)
    notes = [
        "Claude Code 2.1.295 or newer is needed for onFailure.",
        "Strong form: put the same settings in managed settings. A repository can set "
        "\"disableAllHooks\": true, or add sandbox.excludedCommands, unless managed settings "
        "set allowUnsandboxedCommands to false.",
    ]
    notes.append("sandbox.excludedCommands must be empty, and sandbox.network.allowAllUnixSockets "
                 "off and allowUnixSockets empty, for the shell to count as confined.")
    notes.append("Start the broker outside the agent (`phiward broker` in a terminal, or once "
                 "`(cd ~ && phiward broker --service --write)` for every login): it runs the "
                 "gateway commands, with the grants of your user config.")
    if "network" in want["sandbox"]:
        n = len(cfg.allowed_domains)
        notes.append(f"[network] limit: shell commands reach only {n} listed host(s) "
                     "(sandbox.network.strictAllowlist), plus hosts of WebFetch(domain:...) allow "
                     "rules in your user settings. WebFetch and MCP servers are not limited by it.")
    elif cfg.network_limit and project:
        notes.append("[network] limit is written only by `install claude --user`: Claude Code "
                     "ignores it in a project's settings.")
    if cfg.patterns:
        notes.append(_patterns_note(project, version))
    if "--no-hooks" in argv:
        # only when the operator says so: a project file can turn a plugin off, so the user
        # wiring keeps its own full-path hooks unless told otherwise
        want["hooks"] = {"PreToolUse": []}
        notes.append("--no-hooks: only the sandbox and permission settings are written here; "
                     "the hooks must come from your user wiring or the plugin.")
    if project:
        why = _claude_folder_problem(cwd)
        if why:
            print(f"install refused: {why}", file=sys.stderr)
            return 2
    missing = [t for t in CLEAN_TOOLS if not os.access(t, os.X_OK)]
    if missing and ("--json" in argv or "--write" in argv):
        print("install refused: the hooks clear the Python and loader variables with "
              + " and ".join(missing) + ", which this system does not have", file=sys.stderr)
        return 2
    if "--json" in argv:
        if project or "--write" in argv or "--no-hooks" in argv:
            print("install refused: --json prints the user wiring only (no --project, --write "
                  "or --no-hooks)", file=sys.stderr)
            return 2
        print(json.dumps(want, indent=2))
        return 0
    if "--write" in argv and not project and os.environ.get("PHIWARD_DEV") != "1":
        why = _isolated_import_problem()
        if why:
            print(f"install refused: {why}", file=sys.stderr)
            return 2
    targets = [(target, want)]
    if project:
        # this machine's entries go to the personal file, which is not committed
        targets.append((os.path.join(cwd, ".claude", "settings.local.json"), local_wiring(cfg, cwd)))
    if "--write" not in argv:
        for t, w in targets:
            print(f"// Merge this into {t}")
            for n in notes:
                print(f"// {n}")
            print(json.dumps(w, indent=2))
        return 0
    code = 0
    for t, w in targets:
        code = code or _write(t, w, notes, argv)
    if code == 0 and not project:
        code = _write_launch_settings()
    if code == 0 and not project:
        fix_own_modes()
        # the folders the sandbox now protects: made now, so bubblewrap covers them from the
        # first session on (it protects only paths that exist)
        config.make_state_dirs(pathid.home())
    return code
