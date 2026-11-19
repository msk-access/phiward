"""Layered configuration: the user's file, then the repository's, combined tighten-only.

- User config (never committed): `$PHIWARD_CONFIG`, else
  `$XDG_CONFIG_HOME/phiward/config.toml`, else `~/.config/phiward/config.toml`.
- Repo config (committed): the first `.phiward.toml` found from the working folder upward.

One source of authority: the agent can write a repo file, and it
chooses the working folder of a gateway request. So a repo file may only add protection: it can
add protected roots and patterns (never writable by the gateway), built-in packs and protected
branches, make `unresolved` stricter, and lower `inventory_limit`. Everything that widens or
changes the gateway (copy remotes, sanitize rules, names files, pack files, the grants
`[broker] write_to` and `net`) comes from the user's file only. A repo file that sets such a key
is not an error; the key is ignored, and `ignored` lists it (doctor shows it).

Grants: nothing asks the operator at run time. `[broker] write_to`
lists the only folders a `--write-to` may name; each must be a real folder (an entry reached
through a link is skipped, so whoever can change the link cannot choose the place);
`[broker] net = true` lets `--net` through. A `write_to` folder that is `/`, the home folder or
above it, a dot-folder in it, above or inside a protected path, or holds or is inside an
phiward folder is a problem; one that does not exist yet is skipped (doctor counts it).

No config, no effect. A file that is present but cannot be read, does not parse, or has an unknown
key or a bad value makes `problem` non-empty; the guards then refuse what they guard (fail closed).
"""

import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from phiward import _toml, pathid

REPO_FILE = ".phiward.toml"
# the names before the rename (v0.2.0b1): the program is kept as an alias for the beta; the old
# config files are refused, never read and never ignored without a word (a repo config may add
# protected roots, so ignoring it would drop protection)
from phiward.names import MODULES, PROGRAMS  # noqa: E402,F401
LEGACY_REPO_FILE = ".agent-guards.toml"
LEGACY_STATE = ".agent-guards"
UNRESOLVED = ("allow", "ask", "deny")  # weakest first

# section -> key -> kind ("list" of strings, or "choice" from UNRESOLVED)
SCHEMA: Dict[str, Dict[str, str]] = {
    "protected_paths": {"roots": "list", "patterns": "list", "unresolved": "choice",
                        "snapshot_names": "list"},
    "sanitize": {"packs": "list", "names_from": "list", "patterns": "list",
                 "inventory_limit": "int", "table": "bool", "subjects": "str"},
    "copy": {"remotes": "list", "ssh_config": "str", "push_limit_gib": "int"},
    "git": {"protected_branches": "list"},
    "broker": {"write_to": "list", "net": "bool", "max_output_lines": "int", "commands": "list"},
    "launch": {"pass_env": "list"},
    # commands on HPC through the broker; every key is the operator's own (USER_ONLY)
    "remote": {"hosts": "list", "commands": "list", "roots": "list",
               "use_shared_connection": "bool"},
    # the network of shell commands in Claude Code sessions (Mode A): Claude Code's own
    # sandbox.network.strictAllowlist and allowedDomains in the user settings (USER_ONLY)
    "network": {"limit": "bool", "allowed_domains": "list"},
    # a shell that no kernel confines: best_effort keeps the hook's text check instead of
    # refusing every such call (USER_ONLY). `strict` and `commands` (strict mode, removed) still
    # load, and do nothing: unconfined calls are refused by default now
    "shell": {"best_effort": "bool", "strict": "bool", "commands": "list"},
}
# built-in program lists for `[broker] commands` (`"@genomics"`): programs that read data and
# print results, chosen so that none runs code it is given. Each still prints what it reads:
# print summaries.
COMMAND_PRESETS = {
    # not in them: `sort` (--compress-program runs a program), `bcftools` (+plugin loads a
    # library from a path), interpreters, shells, `awk`, `find`, `xargs`, `make`, `git`, pagers
    # also not `fastqc` (its wrapper can be told which program to start) or `multiqc` (it reads
    # settings from the working folder)
    "genomics": ("samtools", "bedtools", "tabix", "bgzip", "mosdepth", "seqkit", "wc", "uniq", "cut", "du", "md5sum", "sha256sum", "shasum", "ls",
                 "stat", "file", "head", "tail", "zcat", "gzip", "gunzip"),
    "counts": ("wc", "du", "ls", "stat", "uniq", "cut", "md5sum", "sha256sum", "shasum"),
}


# programs that run other code they are given (a script, an alias in a project's .git/config,
# -exec, a compress program): in `[broker] commands` they let agent code run again
LAUNCHERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "python", "python3", "perl", "ruby",
    "node", "Rscript", "R", "julia", "java", "awk", "gawk", "mawk", "sed", "gsed", "git", "find",
    "xargs", "parallel", "make", "env", "nice", "nohup", "timeout", "time", "sort", "tar", "rsync",
    "less", "more", "vim", "vi", "emacs", "ssh", "snakemake", "nextflow", "cromwell", "conda",
    "mamba", "pip", "uv", "npx", "docker", "apptainer", "singularity", "srun", "sbatch",
    # data tools that can be told to start a program or load a library (not in the presets)
    "fastqc", "multiqc", "bcftools",
    # more interpreters and multi-call programs
    "pypy", "php", "lua", "tclsh", "wish", "osascript", "busybox", "toybox", "pwsh", "deno",
    "bun"})


def runs_other_code(name: str) -> bool:
    """Whether a program, by its file name, runs other code it is given: LAUNCHERS, also with a
    version after the name (`python3.9`, `perl5.34`, `node18`, `pypy3`)."""
    import re as _re
    base = os.path.basename(name)
    return base in LAUNCHERS or _re.sub(r"[0-9][0-9.]*$", "", base) in LAUNCHERS


# keys of iteration 4 that are gone: a file that still sets one is a problem that says why
REMOVED = {("broker", "confirm"), ("broker", "prompt")}
# keys a repo file may not set; they are ignored there
USER_ONLY = {("copy", "remotes"), ("copy", "ssh_config"), ("sanitize", "patterns"),
             ("copy", "push_limit_gib"), ("remote", "use_shared_connection"),
             ("remote", "hosts"), ("remote", "commands"), ("remote", "roots"),
             ("sanitize", "names_from"), ("sanitize", "table"), ("sanitize", "subjects"),
             ("broker", "write_to"), ("broker", "net"), ("launch", "pass_env"),
             ("network", "limit"), ("network", "allowed_domains"), ("shell", "best_effort"),
             ("shell", "commands")}
# an allowed_domains entry: a host name, `*.` and a host name, an IPv4 or bracketed IPv6
# address; an optional :port. Never `*` alone (that allows every host)
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
DOMAIN = re.compile(r"(?:(?:\*\.)?" + _LABEL + r"(?:\." + _LABEL + r")*|\[[0-9A-Fa-f:.]+\])"
                    r"(?::(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}"
                    r"|655[0-2][0-9]|6553[0-5]))?")


_SUFFIX_SECOND = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "nic",
                  "me", "ltd", "plc", "sch", "nhs", "police"}
# names under which anyone can get a host of their own: `*.` over one of them, or over a name
# below one (`*.s3.amazonaws.com`), is every user's site (a short list, not the whole public
# suffix list)
SHARED_HOSTING = {"github.io", "gitlab.io", "githubusercontent.com", "amazonaws.com",
                  "cloudfront.net", "azurewebsites.net", "windows.net", "googleapis.com", "on.aws",
                  "amazonaws.com.cn", "trycloudflare.com",
                  "googleusercontent.com", "r2.dev", "appspot.com", "web.app", "firebaseapp.com",
                  "herokuapp.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
                  "ngrok.io", "ngrok-free.app", "ngrok.app", "onrender.com", "fly.dev",
                  "blogspot.com", "glitch.me", "repl.co", "uk.com", "eu.org"}


def domain_problem(d: str) -> str:
    """Why `d` cannot be an allowed host, or "". A wildcard needs a name of its own below a
    public suffix: `*.example.org`, never `*.org` or `*.co.uk`."""
    if not DOMAIN.fullmatch(d):
        return ("is not a host name (for example github.com, *.example.org or github.com:443; "
                "no http://, no path, not *)")
    if d.startswith("*."):
        labels = d[2:].split(":")[0].lower().split(".")
        name = ".".join(labels)
        if len(labels) < 2 or any(name == s or name.endswith("." + s) for s in SHARED_HOSTING) or (
                len(labels) == 2 and len(labels[1]) == 2 and labels[0] in _SUFFIX_SECOND):
            return ("is a wildcard over a whole public or shared hosting suffix; name a "
                    "domain below it")
    return ""


@dataclass
class Config:
    roots: List[str] = field(default_factory=list)  # absolute, normalized, ~ expanded
    patterns: List[str] = field(default_factory=list)  # absolute glob patterns
    # The roots and patterns of the user's own file. Only these are writable by the gateway: the
    # agent can edit a repo file, so a repo root must not become a place the gateway writes to.
    user_roots: List[str] = field(default_factory=list)
    user_patterns: List[str] = field(default_factory=list)
    write_to: List[str] = field(default_factory=list)  # resolved folders a grant may name
    write_to_missing: int = 0  # write_to entries that name no folder yet
    write_to_linked: int = 0  # write_to entries reached through a link (skipped)
    write_to_claude: int = 0  # write_to entries that hold a .claude folder (skipped)
    net: bool = False
    launch_pass_env: List[str] = field(default_factory=list)  # more variables for `launch`
    max_output_lines: int = 2000  # gateway output lines shown; a repo file may only lower it
    # the programs gateway commands may run ([broker] commands): one list per config file that
    # sets one; a program must be in every list. Empty: no list, any program
    command_lists: List[List[str]] = field(default_factory=list)
    # the user config's own list (None when it sets none): what a listed program runs as comes
    # from it only, never from a repo list, which the agent can write
    user_commands: Optional[List[str]] = None
    ignored: List[str] = field(default_factory=list)  # "section.key" a repo file may not set
    unresolved: str = "deny"
    snapshot_names: List[str] = field(default_factory=list)  # site snapshot folder names
    packs: List[str] = field(default_factory=list)
    # the packs of the user's own file: only these tell doctor that subject identifiers are
    # masked (a repo file, which the agent can write, may add packs too)
    user_packs: List[str] = field(default_factory=list)
    # "none": the operator's record that the protected data holds no subject or sample IDs
    # beyond the names under the roots ([sanitize] subjects, user config only)
    sanitize_subjects: str = ""
    names_from: List[str] = field(default_factory=list)
    sanitize_patterns: List[str] = field(default_factory=list)  # "REGEX => <PLACEHOLDER>"
    # table mode lets bare numbers through (an MRN would pass): the operator's choice only
    sanitize_table: bool = False
    remotes: List[str] = field(default_factory=list)
    remote_hosts: List[str] = field(default_factory=list)  # hosts `run --remote` may use
    remote_commands: List[str] = field(default_factory=list)  # programs it may run there
    remote_roots: List[str] = field(default_factory=list)  # protected paths there, masked
    ssh_config: str = ""  # the ssh config file a remote copy uses (else none: -F /dev/null)
    # HPC requests join the operator's shared SSH connection (no key, no ticket,
    # no network but its socket); false: ssh logs in itself and must read the credentials
    use_shared_connection: bool = True
    # [network]: limit the network of shell commands in Claude Code sessions to allowed_domains
    network_limit: bool = False
    # [shell] best_effort (USER_ONLY): a shell call that no kernel confines gets the text check
    # instead of a refusal
    shell_best_effort: bool = False
    allowed_domains: List[str] = field(default_factory=list)
    push_limit_gib: int = 5  # a larger push is the operator's to do
    protected_branches: List[str] = field(default_factory=list)
    inventory_limit: int = 200_000  # most entries the sanitizer lists under the roots
    # Protected without being configured: the cache folder (it holds the list of protected
    # names) and the .git folder of a work tree that holds a root (it holds copies).
    derived_roots: List[str] = field(default_factory=list)
    found_derived: List[str] = field(default_factory=list)  # derived roots found now, before pins
    cache_dir: str = ""
    files: List[str] = field(default_factory=list)  # the files that were read
    problem: str = ""  # non-empty: fail closed
    # the full text of a repo-config problem; `problem` itself quotes nothing from a repo file
    # (the agent sees it, and the file may be a link into a root)
    problem_detail: str = ""

    @property
    def has_protected_paths(self) -> bool:
        return bool(self.roots or self.patterns)

    @property
    def all_roots(self) -> List[str]:
        """The configured roots and the derived ones (empty when nothing is configured)."""
        if not self.has_protected_paths:
            return []
        return self.roots + [r for r in self.derived_roots if r not in self.roots]

    @property
    def active(self) -> bool:
        return bool(self.problem) or self.has_protected_paths


def xdg_config_home(home: str, env: Optional[Mapping[str, str]] = None) -> str:
    """XDG_CONFIG_HOME, or `HOME/.config`: as the XDG spec says, a relative value is ignored."""
    env = os.environ if env is None else env
    v = env.get("XDG_CONFIG_HOME") or ""
    return v if v.startswith("/") else os.path.join(home, ".config")


def user_config_path(env: Optional[Dict[str, str]] = None) -> str:
    env = os.environ if env is None else env
    named = env.get("PHIWARD_CONFIG", "")
    if named:
        if named == "~" or named.startswith("~/"):
            # a `~` the shell left as it is (`env PHIWARD_CONFIG=~/...`)
            named = os.path.join(pathid.home(env), named[2:])
        return named
    # this process's home (os.environ), not `env`'s, on purpose: the user config is the one the
    # operator's process reads, whatever HOME an env built for a launched tool holds
    base = xdg_config_home(os.path.expanduser("~"), env)
    return os.path.join(base, "phiward", "config.toml")


def launch_settings_path(env: Optional[Dict[str, str]] = None) -> str:
    """The file for `claude --settings`, which `install claude --user --write` writes: with it,
    Claude Code's sandbox is admin-required, so a repository's settings cannot loosen it."""
    env = os.environ if env is None else env
    base = xdg_config_home(pathid.home(env), env)
    return os.path.join(base, "phiward", "claude-settings.json")


def legacy_user_config_path(env: Optional[Dict[str, str]] = None) -> str:
    env = os.environ if env is None else env
    base = xdg_config_home(os.path.expanduser("~"), env)  # as user_config_path
    return os.path.join(base, "agent-guards", "config.toml")


def cache_dir(env: Optional[Dict[str, str]] = None) -> str:
    env = os.environ if env is None else env
    base = env.get("XDG_CACHE_HOME") or os.path.join(
        pathid.home(env), ".cache")
    return os.path.join(base, "phiward")


def spool_dir(env: Optional[Dict[str, str]] = None) -> str:
    """The folder where agent-side clients leave requests for the broker."""
    env = os.environ if env is None else env
    named = env.get("PHIWARD_SPOOL", "")
    if named:
        return os.path.abspath(named)
    return default_spool(pathid.home(env))


def default_spool(home: str) -> str:
    """The spool when `$PHIWARD_SPOOL` is not set: outside `~/.phiward`, which the sandbox denies
    in full (`sandbox_denied`); the spool is the one folder the agent must write."""
    return os.path.join(home, ".phiward-spool")


def sandbox_denied(env: Optional[Dict[str, str]] = None) -> List[str]:
    """Folders Claude Code's sandbox denies in full (not guard files: `phiward launch`'s own
    profile writes in them): `~/.phiward`, phiward's own state (the launch records, wrap's
    backups, the broker's status). Denied as a whole, nothing in a session can write, rename or
    replace them, wherever the session was opened (`denyWrite` holds inside writable folders,
    `--add-dir` and `allowWrite` ones too)."""
    env = os.environ if env is None else env
    return [os.path.join(pathid.home(env), ".phiward")]


def status_path(env: Optional[Dict[str, str]] = None) -> str:
    """The broker's status file: next to the default spool, never inside a spool (the agent can
    write a spool)."""
    env = os.environ if env is None else env
    return os.path.join(pathid.home(env), ".phiward", "broker.json")


def command_paths(cfg: "Config") -> List[str]:
    """The files and folders that `[broker] commands` names by path: the operator's own
    scripts. They are guard places: the agent may not write them, or it could change the code
    that the gateway is allowed to run."""
    out: List[str] = []
    for lst in cfg.command_lists:
        for e in lst:
            if "/" in e and not e.startswith("@"):
                p = os.path.realpath(os.path.expanduser(e))
                if p not in out and p != "/":
                    out.append(p)
    return out


def listed_in_home(cfg: "Config") -> List[str]:
    """The programs `[broker] commands` allows that the operator owns (conda, ~/.local/bin,
    Homebrew): protected from agent writes, like the operator's own scripts."""
    if not cfg.command_lists:
        return []
    from phiward import broker
    out = []
    for p in broker.listed_programs(cfg, broker.program_path()):
        try:
            if os.stat(p).st_uid == os.getuid():
                out.append(p)
        except OSError:
            continue
    return out


def shell_prefix_path(env: Optional[Dict[str, str]] = None) -> str:
    """Where an older phiward (`install claude --user --shell-prefix`, removed) wrote the
    launcher that Claude Code's CLAUDE_CODE_SHELL_PREFIX named: kept guarded while it exists,
    and a reinstall removes the setting that names it."""
    env = os.environ if env is None else env
    return os.path.join(pathid.home(env), ".phiward", "bin",
                        "shell-prefix")


def make_state_dirs(home: str) -> None:
    """phiward's own folders that the sandbox must protect from the first session on (bubblewrap
    covers only paths that exist): `~/.phiward/launched` and `~/.phiward/backups`, private."""
    base = os.path.join(home, ".phiward")
    for d in (base, os.path.join(base, "launched"), os.path.join(base, "backups")):
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            pass
        if d != base and os.path.isdir(d) and not os.path.islink(d):
            os.chmod(d, 0o700)


def guard_files(env: Optional[Dict[str, str]] = None) -> List[str]:
    """Files and folders that the agent must not change, or the guard turns itself off: the user
    config (its folder too, when it is the default place), the phiward code and the
    broker's status file."""
    env = os.environ if env is None else env
    out = []
    user = user_config_path(env)
    out.append(user)
    if os.path.realpath(user) != os.path.normpath(user):
        out.append(os.path.realpath(user))  # a linked config: its target is the config too
    if not env.get("PHIWARD_CONFIG"):
        out.append(os.path.dirname(user))
    out.append(os.path.dirname(os.path.abspath(__file__)))
    out.append(status_path(env))
    # what runs phiward: its interpreter's prefix (the venv or tool folder), the launcher,
    # and the user site folder, which Python reads at start
    import sys
    import shutil
    launchers = [shutil.which(n, path=env.get("PATH")) or "" for n in PROGRAMS]
    launcher = launchers[0]
    for p in (sys.prefix, os.path.dirname(os.path.realpath(sys.argv[0] or "")) if
              os.path.basename(sys.argv[0] or "") in PROGRAMS else "",
              _user_site(env), os.path.realpath(launcher) if launcher else ""):
        if p and os.path.normpath(p) != "/" and os.path.realpath(p) not in out:
            out.append(os.path.realpath(p))
    # the launcher as the hook and the operator call it: a link on PATH (uv tool, pipx) is
    # guarded itself, so it cannot be pointed at other code
    for la in launchers:
        if la and os.path.abspath(la) not in out:
            out.append(os.path.abspath(la))
        if la and os.path.realpath(la) not in out:
            out.append(os.path.realpath(la))
    # the launchers phiward's install record lists: the file a wrapped MCP server's entry names
    # (mcp_config.installed_launcher), wherever PATH leads
    from phiward import selfcheck
    try:
        recorded = selfcheck.launcher_scripts() or ()
    except Exception:  # noqa: BLE001 - the record is read again where it is used
        recorded = ()
    for la in sorted(recorded):
        if la not in out:
            out.append(la)
    from phiward import service
    # the interpreter's own standard library: on uv, pyenv or Homebrew Pythons it is the user's,
    # and the launcher imports from it before any check
    base = os.path.realpath(sys.base_prefix)
    if base != "/" and base not in out and base != os.path.realpath(sys.prefix):
        out.append(base)
    sf = service.service_file(pathid.home(env))
    out.append(sf)
    if sf.endswith(".service"):
        out.append(sf + ".d")  # systemd drop-ins can override ExecStart
    ssh = _user_ssh_config(env)
    if ssh:
        out.append(ssh)
    prefix = shell_prefix_path(env)  # the shell prefix's launcher, once written
    if os.path.lexists(prefix):
        out.append(prefix)
    # the folder of the `claude --settings` file, at both places it can be (the hook may see
    # another XDG_CONFIG_HOME than install did): the agent must not loosen the file, nor put a
    # file where its folder goes
    home = pathid.home(env)
    for base in (xdg_config_home(home, env), os.path.join(home, ".config")):
        if base:
            folder = os.path.join(base, "phiward")
            for f in (folder, os.path.realpath(folder)):  # a linked folder: both names
                if f not in out:
                    out.append(f)
    # the records of the running `phiward launch` processes (mcp_config.launched_dir): the hook
    # trusts a wrapped MCP server by them
    out.append(os.path.join(home, ".phiward", "launched"))
    # the backups `phiward mcp wrap` keeps (mcp_config.backups_root): shown as the operator's
    # original config, so only phiward writes them
    out.append(os.path.join(home, ".phiward", "backups"))
    # the pinned derived roots (phiward pin): the agent must not unpin them
    out.append(os.path.join(os.path.dirname(user), "pinned.toml"))
    return out


def _user_site(env: Dict[str, str]) -> str:
    """The user site-packages folder for this Python and this environment's HOME (Python's own
    value is fixed when it starts, so it can differ between two processes)."""
    import site
    import sys
    if not site.ENABLE_USER_SITE:
        return ""
    home = pathid.home(env)
    ver = f"{sys.version_info[0]}.{sys.version_info[1]}"
    framework = getattr(sys, "_framework", "")
    base = env.get("PYTHONUSERBASE") or (
        os.path.join(home, "Library", framework, ver) if sys.platform == "darwin" and framework
        else os.path.join(home, ".local"))
    if sys.platform == "darwin" and framework:
        return os.path.join(base, "lib", "python", "site-packages")
    return os.path.join(base, "lib", f"python{ver}", "site-packages")


def _user_ssh_config(env: Dict[str, str]) -> str:
    """`[copy] ssh_config` of the user file, read without the rest of the loader."""
    path = user_config_path(env)
    try:
        raw, _ = _toml.load_file(path)
        v = raw.get("copy", {}).get("ssh_config", "")
    except Exception:  # noqa: BLE001 - a bad file is reported by load()
        return ""
    if not isinstance(v, str) or not v:
        return ""
    home = pathid.home(env)
    p = os.path.normpath(_expand_root(v, home))
    return p if p.startswith("/") else ""


def git_dirs(dot_git: str) -> List[str]:
    """The folders that hold the copies of a work tree's files: its `.git` folder, or for a `.git`
    file (a linked worktree or a submodule) the file, the folder it names, and the main
    repository's `.git`. The `.git` file is a derived root, so the agent cannot
    change where it points."""
    if not os.path.isfile(dot_git):
        return [dot_git]
    out = [dot_git]
    from phiward import safeio
    try:
        text = safeio.read_text(dot_git, limit=4096)
    except (OSError, UnicodeDecodeError, ValueError):
        return out
    line = text.strip().splitlines()[0] if text.strip() else ""
    if not line.startswith("gitdir:"):
        return out
    target = os.path.normpath(os.path.join(os.path.dirname(dot_git), line[len("gitdir:"):].strip()))
    out.append(target)
    common = os.path.join(target, "commondir")
    try:
        c = safeio.read_text(common, limit=4096).strip()
        out.append(os.path.normpath(os.path.join(target, c)))
    except (OSError, UnicodeDecodeError, ValueError):
        # a submodule (.git/modules/X) or an old worktree: the main .git is above "modules"
        # or "worktrees"
        parts = target.split("/")
        for marker in ("modules", "worktrees"):
            if marker in parts:
                i = len(parts) - 1 - parts[::-1].index(marker)
                out.append("/".join(parts[:i]) or "/")
                break
    return out


# never a derived git folder (a planted name must not block the system); /var is not here:
# temp and user data live under it (/var/folders, /var/tmp, /var/lib)
_SYSTEM_FOLDERS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/etc", "/System",
                   "/Library", "/Applications", "/private/etc", "/dev", "/proc", "/sys", "/boot",
                   "/nix", "/snap")


def _looks_like_git_dir(d: str) -> bool:
    """A folder git itself would use: a repository (HEAD and objects/), or a worktree or
    submodule entry (HEAD and commondir or gitdir)."""
    if not os.path.isfile(os.path.join(d, "HEAD")):
        return False
    return any(os.path.lexists(os.path.join(d, x)) for x in ("objects", "commondir", "gitdir"))


def _sane_git_dir(d: str, home: str) -> bool:
    """A git folder named by an agent-writable `.git` file is used only when it is a real folder
    that is not `/`, the home folder or above it: a planted name cannot turn
    the guard into a refusal of everything."""
    if "\0" in d or not d.startswith("/") or not os.path.isdir(d):
        return False
    real = os.path.realpath(d)
    if real == "/" or inside(os.path.realpath(home), real):
        return False
    if any(inside(real, s) or inside(real, os.path.realpath(s)) for s in _SYSTEM_FOLDERS):
        return False
    return _looks_like_git_dir(real)


def enclosing_git_dirs(path: str) -> List[str]:
    """Every `.git` (folder or file) from `path` up to `/`, nearest first: a `.git` planted
    closer to a root cannot hide the real one above it."""
    out: List[str] = []
    here = os.path.realpath(path)
    while True:
        candidate = os.path.join(here, ".git")
        if os.path.lexists(candidate):
            out.append(candidate)
        parent = os.path.dirname(here)
        if parent == here:
            return out
        here = parent


def find_repo_config(cwd: str) -> Optional[str]:
    here = os.path.abspath(cwd or ".")
    while True:
        for name in (REPO_FILE, LEGACY_REPO_FILE):
            candidate = os.path.join(here, name)
            if os.path.lexists(candidate):  # a link or a FIFO is found, then refused by load()
                return candidate
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent


def _expand_root(value: str, home: str) -> str:
    if value == "~" or value.startswith("~/"):
        value = home + value[1:]
    value = value.replace("${HOME}", home).replace("$HOME", home)
    return value


def _check(data: Dict[str, Any], where: str) -> Tuple[Dict[str, Dict[str, Any]], str]:
    if not isinstance(data, dict):
        return {}, f"{where}: not a table"
    for section, body in data.items():
        if section not in SCHEMA:
            return {}, f"{where}: unknown section [{section}]"
        if not isinstance(body, dict):
            return {}, f"{where}: [{section}] is not a table"
        for key, value in body.items():
            if (section, key) in REMOVED:
                return {}, (f"{where}: '{section}.{key}' was removed: nothing asks at run time "
                            "now; grants come from [broker] write_to and net in the user config "
                            "(see docs/configuration.md)")
            kind = SCHEMA[section].get(key)
            if kind is None:
                return {}, f"{where}: unknown key '{key}' in [{section}]"
            if kind == "list":
                if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
                    return {}, f"{where}: '{section}.{key}' must be a list of non-empty strings"
            elif kind == "int" and (type(value) is not int or value < 1):
                return {}, f"{where}: '{section}.{key}' must be a whole number of 1 or more"
            elif kind == "choice" and value not in UNRESOLVED:
                return {}, f"{where}: '{section}.{key}' must be one of {', '.join(UNRESOLVED)}"
            elif kind == "str" and (not isinstance(value, str) or not value):
                return {}, f"{where}: '{section}.{key}' must be a non-empty string"
            elif kind == "bool" and type(value) is not bool:
                return {}, f"{where}: '{section}.{key}' must be true or false"
            if (section, key) == ("sanitize", "subjects") and value != "none":
                return {}, (f"{where}: 'sanitize.subjects' can only be \"none\" (your record "
                            "that the protected data holds no subject or sample identifiers "
                            "beyond the names under the roots)")
            if section == "protected_paths" and key in ("roots", "patterns"):
                for v in value:
                    if ".." in v.split("/"):
                        return {}, f"{where}: protected path '{v}' must have no '..'"
    return data, ""


def _check_paths(cfg: Config) -> str:
    for lst in cfg.command_lists:
        for e in lst:
            if "/" in e and not e.startswith("@") and not os.path.expanduser(e).startswith("/"):
                return (f"[broker] commands entry '{e}' must be absolute (or start with ~/): "
                        "a relative one would be read against the broker's own folder")
    for p in cfg.roots + cfg.patterns:
        if not p.startswith("/"):
            return f"protected path '{p}' must be absolute (or start with ~/)"
        parts = p.split("/")
        if ".." in parts or os.path.normpath(p) == "/":
            return f"protected path '{p}' must be below / and have no '..'"
        if "$" in p:
            return f"protected path '{p}' may use only $HOME as a variable"
    for p in cfg.roots:
        if any(ch in p for ch in "*?["):
            return f"root '{p}' has a wildcard; put it under 'patterns'"
    for d in cfg.allowed_domains:
        why = domain_problem(d)
        if why:
            return f"[network] allowed_domains entry '{d}' {why}"
    if cfg.ssh_config and not cfg.ssh_config.startswith("/"):
        return "[copy] ssh_config must be absolute (or start with ~/)"  # else the agent's folder
    from phiward import pathmatch
    for p in cfg.patterns:
        why = pathmatch.problem(p)
        if why:
            return f"pattern '{p}' cannot be used: {why}"
    return ""


def inside(path: str, folder: str) -> bool:
    return pathid.inside(path, folder)


def _folded(path: str) -> List[str]:
    return list({pathid.fold(v) for v in pathid.spellings(path)})


def _deny_inside(a: str, b: str) -> bool:
    """Whether `a` is `b` or inside it, in any spelling the file system treats as equal (a deny
    decision folds broadly: case and Unicode form on macOS)."""
    return any(inside(x, y) for x in _folded(a) for y in _folded(b))


def grant_problem(full: str, cfg: "Config", env: Optional[Dict[str, str]] = None) -> str:
    """Why the resolved folder `full` may not be a write place, or ""."""
    env = os.environ if env is None else env
    if os.path.normpath(full) == "/":
        return "it is /"
    later = runs_later_problem(full, env)
    if later:
        return later
    # a grant may sit inside a protected root (what is written there stays protected), never
    # above one, and never in a derived protected folder (a `.git`) or a pattern match
    for r in cfg.roots:
        if _deny_inside(r, full):
            return "it holds a protected path; grant a folder inside it instead"
    for r in cfg.derived_roots + [_pattern_prefix(p) for p in cfg.patterns]:
        if _deny_inside(full, r) or _deny_inside(r, full):
            return "it is above or inside a derived protected folder or a pattern match"
    # the files that decide what is masked: a gateway command must not rewrite them
    for f in list(cfg.names_from) + [p for p in cfg.packs if "/" in p]:
        if _deny_inside(os.path.realpath(os.path.expanduser(f)), full):
            return "it holds a names or pack file of the config"
    for g in guard_files(env) + [spool_dir(env)]:
        if _deny_inside(full, g) or _deny_inside(g, full):
            return "it holds, or is inside, a phiward file or folder"
    return ""


def runs_later_problem(full: str, env: Optional[Dict[str, str]] = None) -> str:
    """Why the folder `full` is a place where your own tools load code or settings later, so
    the gateway may not write there, or "". A protected root here stays protected; gateway
    commands just cannot write in it."""
    env = os.environ if env is None else env
    home = pathid.home(env)
    if _deny_inside(home, full):
        return "it is the home folder or above it (startup and settings files live there)"
    if _deny_inside(full, home):
        rel = os.path.relpath(pathid.canon(full), pathid.canon(home))
        top = rel.split("/")[0]
        if top.startswith("."):
            return "it is in a dot-folder of the home folder (startup and settings files live there)"
        if pathid.fold(top) == pathid.fold("Library"):
            return "it is in ~/Library (settings and login items live there)"
    for entry in (env.get("PATH") or "").split(":"):
        if not entry.startswith("/"):
            continue
        if _deny_inside(full, entry) or _deny_inside(entry, full):
            return "it is a PATH folder, or holds or is inside one (programs you run live there)"
    return ""


def _pattern_prefix(pattern: str) -> str:
    cut = min([i for i in (pattern.find("*"), pattern.find("?"), pattern.find("[")) if i >= 0]
              or [len(pattern)])
    return os.path.dirname(pattern[:cut]) if cut < len(pattern) else pattern


def _resolve_write_to(cfg: "Config", env: Dict[str, str]) -> str:
    named, cfg.write_to = cfg.write_to, []
    for w in named:
        if not w.startswith("/"):
            return f"[broker] write_to '{w}' must be absolute (or start with ~/)"
        full = os.path.realpath(w)
        if not os.path.isdir(full):
            cfg.write_to_missing += 1
            continue
        written = os.path.normpath(w)
        # an allow decision: exact on a case-sensitive volume, folded only where the volume
        # folds
        same = (full == written) if pathid.case_sensitive(full) else \
            pathid.fold(full) == pathid.fold(written)
        if not same:
            # a link on the way: whoever can change the link would choose the place
            cfg.write_to_linked += 1
            continue
        why = grant_problem(full, cfg, env)
        if not why and os.path.isdir(os.path.join(full, ".claude")):
            # skipped, not a problem: anyone who can make the folder could otherwise stop every
            # guarded action; doctor counts it
            cfg.write_to_claude += 1
            continue
        if why:
            return f"[broker] write_to '{w}' may not be granted: {why}"
        full = pathid.canon(full)  # stored in the file system's own spelling (step 3)
        if full not in cfg.write_to:
            cfg.write_to.append(full)
    return ""


def stricter(a: str, b: str) -> str:
    return a if UNRESOLVED.index(a) >= UNRESOLVED.index(b) else b


def _merge(cfg: Config, data: Dict[str, Dict[str, Any]], home: str, repo: bool) -> None:
    if repo:
        data = {sec: dict(keys) for sec, keys in data.items()}
        for sec, key in sorted(USER_ONLY):
            if key in data.get(sec, {}):
                del data[sec][key]
                if f"{sec}.{key}" not in cfg.ignored:
                    cfg.ignored.append(f"{sec}.{key}")
        packs = data.get("sanitize", {}).get("packs", [])
        if any("/" in p for p in packs):  # a pack file is code the agent could write
            data["sanitize"]["packs"] = [p for p in packs if "/" not in p]
            if "sanitize.packs (files)" not in cfg.ignored:
                cfg.ignored.append("sanitize.packs (files)")
    pp = data.get("protected_paths", {})
    for key, target, mine in (("roots", cfg.roots, cfg.user_roots),
                              ("patterns", cfg.patterns, cfg.user_patterns)):
        for r in pp.get(key, []):
            r = os.path.normpath(_expand_root(r, home))
            if r not in target:
                target.append(r)
            if not repo and r not in mine:
                mine.append(r)
    for v in pp.get("snapshot_names", []):  # adds protection: allowed in a repo file too
        if "/" not in v and v not in cfg.snapshot_names:
            cfg.snapshot_names.append(v)
    if "unresolved" in pp:
        cfg.unresolved = stricter(cfg.unresolved, pp["unresolved"]) if repo else pp["unresolved"]
    san = data.get("sanitize", {})
    if repo and san.get("packs") and not cfg.packs:
        # a repo file adds packs to the user's (or to the default), never replaces them: an
        # empty list means the default, and a repo list would otherwise turn it off
        from phiward.sanitize import DEFAULT_PACKS
        cfg.packs.extend(DEFAULT_PACKS)
    for key, target in (("packs", cfg.packs), ("names_from", cfg.names_from),
                        ("patterns", cfg.sanitize_patterns)):
        for v in san.get(key, []):
            if key == "names_from":
                v = _expand_root(v, home)
            if v not in target:
                target.append(v)
            if key == "packs" and not repo and v not in cfg.user_packs:
                cfg.user_packs.append(v)
    if "subjects" in san:  # USER_ONLY: a repo file's value is ignored (listed in cfg.ignored)
        cfg.sanitize_subjects = san["subjects"]
    if "table" in san:  # USER_ONLY: a repo file's value is ignored (listed in cfg.ignored)
        cfg.sanitize_table = bool(san["table"])
    if "inventory_limit" in san:
        # tighten only: a repo file can lower the limit, never raise it
        lim = san["inventory_limit"]
        cfg.inventory_limit = min(cfg.inventory_limit, lim) if repo else lim
    rm = data.get("remote", {})
    if "use_shared_connection" in rm:  # USER_ONLY
        cfg.use_shared_connection = bool(rm["use_shared_connection"])
    if "push_limit_gib" in data.get("copy", {}):  # USER_ONLY
        cfg.push_limit_gib = max(0, int(data["copy"]["push_limit_gib"]))
    for key, target in (("hosts", cfg.remote_hosts), ("commands", cfg.remote_commands),
                        ("roots", cfg.remote_roots)):
        for v in rm.get(key, []):
            v = os.path.normpath(v) if key == "roots" else v
            if v not in target:
                target.append(v)
    br = data.get("broker", {})
    for v in br.get("write_to", []):  # only from the user file (USER_ONLY); checked in load()
        v = os.path.normpath(_expand_root(v, home))
        if v not in cfg.write_to:
            cfg.write_to.append(v)
    if "net" in br:
        cfg.net = br["net"]
    if "max_output_lines" in br:
        m = br["max_output_lines"]
        cfg.max_output_lines = min(cfg.max_output_lines, m) if repo else m
    if "commands" in br:
        # a repo list can only narrow: a program must be in every list that is set
        cfg.command_lists.append([str(v) for v in br["commands"]])
        if not repo:
            cfg.user_commands = cfg.command_lists[-1]
    for v in data.get("launch", {}).get("pass_env", []):
        if v not in cfg.launch_pass_env:
            cfg.launch_pass_env.append(v)
    if "best_effort" in data.get("shell", {}):  # USER_ONLY
        cfg.shell_best_effort = bool(data["shell"]["best_effort"])
    nw = data.get("network", {})
    if "limit" in nw:  # USER_ONLY
        cfg.network_limit = bool(nw["limit"])
    for v in nw.get("allowed_domains", []):  # USER_ONLY
        if v not in cfg.allowed_domains:
            cfg.allowed_domains.append(v)
    if "ssh_config" in data.get("copy", {}):
        cfg.ssh_config = os.path.normpath(_expand_root(data["copy"]["ssh_config"], home))

    for v in data.get("copy", {}).get("remotes", []):
        if v not in cfg.remotes:
            cfg.remotes.append(v)
    for v in data.get("git", {}).get("protected_branches", []):
        if v not in cfg.protected_branches:
            cfg.protected_branches.append(v)


def load(cwd: str, env: Optional[Dict[str, str]] = None) -> Config:
    """The combined config for a tool call whose working folder is `cwd`."""
    env = os.environ if env is None else env
    home = pathid.home(env)
    cfg = Config()
    places = []
    user = user_config_path(env)
    if env.get("PHIWARD_CONFIG") and not os.path.isabs(user):
        cfg.problem = f"$PHIWARD_CONFIG must be an absolute path: {user}"
        return cfg
    if env.get("PHIWARD_CONFIG") and not os.path.isfile(user):
        cfg.problem = f"$PHIWARD_CONFIG names no file: {user}"
        return cfg
    if not env.get("PHIWARD_CONFIG") and not os.path.lexists(user) and \
            os.path.lexists(legacy_user_config_path(env)):
        cfg.problem = ("the user config is still at ~/.config/agent-guards/config.toml (the name "
                       "before phiward); move that folder to ~/.config/phiward")
        return cfg
    if os.path.isfile(user):
        places.append(user)
    repo = find_repo_config(cwd)
    if repo and os.path.basename(repo) == LEGACY_REPO_FILE:
        cfg.problem = (f"a repo config has the name before phiward ({LEGACY_REPO_FILE}); rename "
                       f"it to {REPO_FILE}")
        return cfg
    if repo and repo not in places:
        places.append(repo)
    for place in places:
        is_repo = place != user
        detail = ""
        try:
            if is_repo:
                from phiward import paths
                pset = paths.ProtectedSet(cfg.roots, cfg.patterns)
                if pset.relation(place) == paths.INSIDE or \
                        pset.relation(os.path.dirname(place)) == paths.INSIDE:
                    raise OSError("it is inside a protected path")
            raw, _ = _toml.load_file(place, follow=not is_repo)
        except (OSError, UnicodeDecodeError) as exc:
            detail = f"{place} cannot be read ({type(exc).__name__}: {exc})"
        except _toml.TomlError as exc:
            detail = f"{place} does not parse: {exc}"
        else:
            data, detail = _check(raw, place)
        if detail:
            if is_repo:
                cfg.problem = (f"{place}: the repo config cannot be used (it is not a plain "
                               "file, it is in a protected place, or it has an error); the "
                               "operator sees why with `phiward doctor --show-paths`")
                cfg.problem_detail = detail
            else:
                cfg.problem = detail
            return cfg
        # The user's value (default deny) is the floor; a repo file can only make it stricter.
        _merge(cfg, data, home, repo=place != user)
        cfg.files.append(place)
    cfg.problem = _check_paths(cfg)
    cfg.cache_dir = cache_dir(env)
    if cfg.has_protected_paths and not cfg.problem:
        cfg.derived_roots.append(cfg.cache_dir)
        spool = os.path.realpath(spool_dir(env))

        def sane(d: str) -> bool:
            if "\0" in d or not _sane_git_dir(d, home):  # the NUL check before any path call
                return False
            real = os.path.realpath(d)
            return (not inside(spool, real) and
                    not inside(real, spool) and not any(inside(r2, d) for r2 in cfg.roots))

        for r in cfg.roots:
            for g in enclosing_git_dirs(r):
                found = git_dirs(g)
                # the .git itself when it is a folder or file in place; a .git that is a link,
                # and folders read out of a .git file, only when they look like git folders and
                # are not system, home, spool or root folders. No
                # dependence on the caller's working folder (finding 11).
                first = [found[0]] if not os.path.islink(found[0]) or sane(found[0]) else []
                keep = first + [d for d in found[1:] if sane(d)]
                for d in keep:
                    if d not in cfg.derived_roots:
                        cfg.derived_roots.append(d)
        # old copies (snapshot folders) and other mounts of the same data
        from phiward import fsinfo
        prefixes = [_pattern_prefix(p) for p in cfg.patterns]
        linux = sys.platform.startswith("linux")
        if linux:
            # an overlay whose folders cannot be read may show protected data: its own mount
            # point is protected, nothing else stops
            for d in fsinfo.unknown_overlays():
                if d not in cfg.derived_roots:
                    cfg.derived_roots.append(d)
        # repeat until nothing new is found: an alias of an alias, a snapshot above an alias
        todo = cfg.roots + prefixes + list(cfg.derived_roots)
        done: List[str] = []
        while todo and len(done) < 1000:
            r = todo.pop(0)
            if r in done:
                continue
            done.append(r)
            extra = fsinfo.snapshot_dirs(r, cfg.snapshot_names)
            if linux:
                extra += [a for a in fsinfo.alias_paths(r) if os.path.lexists(a)]
            for d in extra:
                if d not in cfg.roots and d not in cfg.derived_roots:
                    cfg.derived_roots.append(d)
                    todo.append(d)
        cfg.found_derived = list(cfg.derived_roots)
        # pinned by the operator (phiward pin): never removed by what is found now
        from phiward import pin
        for d in pin.read_pins(env):
            if d not in cfg.roots and d not in cfg.derived_roots and os.path.lexists(d):
                cfg.derived_roots.append(d)
    if not cfg.problem:
        cfg.problem = _resolve_write_to(cfg, env)
    return cfg
