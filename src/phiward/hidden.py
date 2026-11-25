"""The one list of what no agent may read besides the protected data: credentials,
ticket caches and keytabs, SSH keys the ssh configs name, histories, the Trash, other tools'
logins, local IPC sockets. `launch` hides it from the whole tool, the gateway from every command,
`phiward install claude` writes it into Claude Code's sandbox and permission rules, and the hook
refuses it to the file tools. Standard library only: the hook imports it on every call."""

import os
import platform
import re
import sys
from typing import Dict, Iterator, List, Optional, Tuple

from phiward import config, pathid


def _inside(p: str, folder: str) -> bool:
    return pathid.inside(p, folder)

CREDENTIALS = (".ssh", ".aws", ".kube", ".config/gh", ".netrc", ".gnupg", ".docker/config.json",
               ".config/gcloud", ".azure", ".git-credentials", ".config/git/credentials",
               ".claude/.credentials.json", ".phiward/carryover", ".agent-guards", ".pgpass", ".npmrc", ".pypirc", ".irods",
               ".config/rclone", ".cargo/credentials", ".cargo/credentials.toml",
               ".m2/settings.xml", ".gradle/gradle.properties", ".claude", ".claude.json",
               ".vault-token", ".terraform.d", ".config/op", ".s3cfg", ".boto", ".config/hub",
               ".config/glab-cli", ".databrickscfg", ".snowsql",
               # other agent tools' logins and the Claude app
               ".codex", ".gemini", ".config/Claude", "Library/Application Support/Claude",
               # browser profiles: cookies and saved logins
               "Library/Application Support/Google/Chrome", "Library/Application Support/Firefox",
               "Library/Application Support/Microsoft Edge", "Library/Application Support/BraveSoftware",
               "Library/Safari", "Library/Cookies", ".mozilla", ".config/google-chrome",
               ".config/chromium", ".config/BraveSoftware", ".config/microsoft-edge",
               # what the operator typed and read: a history holds paths, names and tokens
               ".zsh_history", ".zsh_sessions", ".bash_history", ".bash_sessions", ".sh_history",
               ".python_history", ".Rhistory", ".julia/logs", ".ipython", ".lesshst", ".viminfo",
               ".psql_history", ".mysql_history", ".sqlite_history", ".node_repl_history",
               ".local/share/fish", ".local/state/nvim", ".Trash", ".local/share/Trash",
               # macOS QuickLook thumbnails of the operator's files
               "Library/Caches/com.apple.QuickLook.thumbnailcache",
               # Linux thumbnails and recent-file lists; R and pip settings that hold tokens
               ".cache/thumbnails", ".thumbnails", ".local/share/recently-used.xbel",
               ".Renviron", ".config/pip", ".pip", ".local/share/jupyter/runtime",
               # more tokens and histories
               ".cache/huggingface/token", ".huggingface", ".config/github-copilot",
               ".terraformrc", ".histfile", ".subversion/auth", ".config/sops", ".globus",
               "Library/Keychains",
               # research data services and container registries
               ".ncbi", ".basespace", ".synapseConfig", ".dnanexus_config", ".nextflow/secrets",
               ".apptainer", ".singularity", ".config/containers/auth.json",
               ".local/share/uv/credentials", ".kaggle",
               # copies of Claude Code's login file that `phiward mcp wrap` keeps
               ".phiward/backups",
               # more agent tools, database and service logins, and a shell history store
               ".copilot", ".cursor", ".my.cnf", ".mylogin.cnf", ".local/share/atuin",
               ".config/ngrok", ".gem/credentials", ".composer/auth.json",
               ".config/pypoetry/auth.toml", ".oci", ".pulumi", ".tsh", ".yarnrc.yml", ".jupyter",
               # more browsers and apps that keep logins and cookies
               "Library/Application Support/Chromium", "Library/Application Support/Arc",
               "Library/Application Support/Slack", "Library/Application Support/Code",
               ".config/Code", ".config/Slack")

# what a Claude Code session itself needs from its own folder (memory, plans, skills, saved tool
# output): in a session that is not launched (Mode A) only its login files are hidden, not the
# whole folder
OWN_CONFIG = (".claude", ".claude.json")

def credentials(env: Dict[str, str], cfg: Optional[config.Config] = None,
                write_to: bool = True, own_config: bool = True) -> List[str]:
    """What no session may read, besides the protected paths: credentials, histories, the
    Trash, Kerberos caches and keytabs, SSH keys named outside ~/.ssh, and the gateway's
    write_to folders (what the gateway writes there is unmasked).
    `own_config=False` (Mode A): of Claude Code's own folder, only its login files."""
    home = pathid.home(env)
    names = [c for c in CREDENTIALS if own_config or c not in OWN_CONFIG]
    out = [os.path.join(home, c) for c in names]
    if not own_config:
        conf = env.get("CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude")
        out += [os.path.join(conf, ".credentials.json"), os.path.join(conf, ".claude.json"),
                os.path.join(home, ".claude.json"),
                # the copies Claude Code keeps of its login file
                os.path.join(conf, "backups"), os.path.join(home, ".claude.json.backup"),
                os.path.join(conf, ".claude.json.backup")]
    # the broker's log holds the real exit status of gateway commands
    from phiward import service
    out.append(service.log_folder(home))
    out += _kerberos_caches(env)
    out += _ssh_identity_files(env, cfg)
    if cfg is not None and write_to:
        out += [w for w in cfg.write_to if w not in out]
    return out


_SSH_LINE = re.compile(r"^\s*(IdentityFile|CertificateFile|Include)\s*(?:=\s*|\s+)(.*?)\s*$", re.I | re.M)


def _token_paths(v: str, home: str) -> List[str]:
    """What to hide for a configured path that may hold `%` or `${...}` tokens: the path whole
    when it has none; else the files that match it with each token as `*`, and the folder
    before the first token unless that is the home folder or above it (for example `~/%h`)."""
    cut = min([i for i in (v.find("%"), v.find("${")) if i >= 0] or [-1])
    if cut < 0:
        return [v]
    import glob
    pat = re.sub(r"%[A-Za-z%]|\$\{[^}]*\}", "*", v)
    out = glob.glob(pat)[:256]
    head = os.path.dirname(v[:cut]) if "/" in v[:cut] else ""
    if head.startswith("/") and not _inside(os.path.normpath(home), os.path.normpath(head)):
        out.append(head)
    return out


def _ssh_words(rest: str) -> List[str]:
    try:
        import shlex
        return shlex.split(rest, comments=True)
    except ValueError:
        return rest.split()


def _ssh_identity_files(env: Dict[str, str], cfg: Optional[config.Config]) -> List[str]:
    """Keys and certificates that the operator's SSH configs name outside ~/.ssh: the
    user's config, the system's, and the [copy] one, with their Include files."""
    home = pathid.home(env)
    todo = [(os.path.join(home, ".ssh", "config"), os.path.join(home, ".ssh")),
            ("/etc/ssh/ssh_config", "/etc/ssh")]
    if cfg is not None and cfg.ssh_config:
        todo.append((os.path.expanduser(cfg.ssh_config), os.path.join(home, ".ssh")))
    out: List[str] = []
    seen: set = set()

    def expand(v: str) -> str:
        v = v.replace("%d", home).replace("${HOME}", home)
        v = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", lambda m: env.get(m.group(1), m.group(0)), v)
        return os.path.join(home, v[2:]) if v.startswith("~/") else v

    depth = 0
    while todo and depth < 64:
        depth += 1
        f, base = todo.pop(0)
        if f in seen:
            continue
        seen.add(f)
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                text = fh.read(1 << 20)
        except OSError:
            continue
        for key, rest in _SSH_LINE.findall(text):
            for v in _ssh_words(rest):
                v = expand(v)
                if key.lower() == "include":
                    import glob
                    pat = v if v.startswith("/") else os.path.join(base, v)
                    todo += [(g, base) for g in sorted(glob.glob(pat))[:64]]
                    continue
                out += [os.path.normpath(x) for x in _token_paths(v, home) if x.startswith("/")]
    return out


def _kerberos_caches(env: Dict[str, str]) -> List[str]:
    """Kerberos ticket caches the operator's tools use: a session that could read one could log
    in to HPC with the operator's ticket over the open network and read protected data there
    unmasked (operator's HPC setup). The cache KRB5CCNAME names (FILE: or DIR:), read
    from the operator's environment before it is cleared, and the default file caches."""
    out: List[str] = []
    cc = env.get("KRB5CCNAME", "")
    kind, _, rest = cc.partition(":")
    path = rest if kind in ("FILE", "DIR") else (cc if cc.startswith("/") else "")
    if path.startswith("/"):
        out.append(os.path.normpath(path))
    uid = os.getuid()
    out += [f"/tmp/krb5cc_{uid}", f"/var/tmp/krb5cc_{uid}", f"/var/kerberos/krb5/user/{uid}"]
    # keytabs the environment names, and the caches and keytabs krb5.conf names
    for k in ("KRB5_KTNAME", "KRB5_CLIENT_KTNAME"):
        v = env.get(k, "")
        v = v.split(":", 1)[1] if v.split(":", 1)[0] in ("FILE", "WRFILE") else v
        if v.startswith("/"):
            out.append(os.path.normpath(v))
    subst = {"%{uid}": str(uid), "%{euid}": str(os.geteuid()), "%{USERID}": str(uid),
             "%{EUID}": str(os.geteuid()), "%{TEMP}": "/tmp",
             "%{username}": env.get("USER", ""), "%{LOCALSTATEDIR}": "/var",
             "%{LIBDIR}": "/usr/lib"}
    for text in _krb5_confs(env):
        for v in _KRB5_NAMES.findall(text):
            for k, w in subst.items():
                if w:
                    v = v.replace(k, w)
            kind, _, rest = v.partition(":")
            v = rest if kind in ("FILE", "DIR", "WRFILE") else v
            home = pathid.home(env)
            out += [os.path.normpath(x) for x in _token_paths(v, home) if x.startswith("/")]
    return out


_KRB5_INCLUDE = re.compile(r"^\s*(include|includedir)\s+(\S+)", re.M)
_KRB5_NAMES = re.compile(r"^\s*default_(?:ccache|keytab|client_keytab)_name\s*=\s*(\S+)", re.M)


# any file named like a Kerberos cache in the shared temp folders (macOS: /tmp is readable)
KRB5_CACHE_NAMES = r"krb5cc[^/]*"
# the same on Linux, as patterns of the session's view (/tmp is the session's own there)
KRB5_CACHE_PATTERNS = ("/var/tmp/krb5cc*", "/dev/shm/krb5cc*")


# the sockets of the IPC list, by name (the same list on every node that shares the home folder)
IPC_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock",
               # Kerberos tickets kept by KCM (sssd-kcm, Heimdal): a socket, not a file
               "/run/.heim_org.h5l.kcm-socket", "/var/run/.heim_org.h5l.kcm-socket")
IPC_PATHS = (f"/run/user/{os.getuid()}", "/run/munge", "/run/dbus") + IPC_SOCKETS


def _platform():
    return sys.platform, platform.machine()


def sockets_blocked(plat: Optional[str] = None, machine: Optional[str] = None) -> bool:
    """Whether Claude Code's sandbox has a filter for new Unix sockets here: on Linux x86_64 and
    aarch64 its seccomp filter refuses socket(AF_UNIX) (sandbox-runtime's README, "Unix Socket
    Restrictions"); elsewhere it has none, or (macOS) denies by path."""
    if plat is None or machine is None:
        plat, machine = _platform()
    return plat.startswith("linux") and machine in ("x86_64", "aarch64")


def _bwrap_version() -> Optional[Tuple[int, int]]:
    """The version of the bubblewrap Claude Code's sandbox finds (on the PATH folders the agent
    cannot write, as doctor looks), or None when there is none or it cannot be read."""
    import shutil
    import subprocess
    from phiward import service
    safe = ":".join(service._safe_path_entries(os.environ.get("PATH", "")))
    found = shutil.which("bwrap", path=safe)
    if not found:
        return None
    try:
        r = subprocess.run([found, "--version"], capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"(\d+)\.(\d+)", r.stdout or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def sockets_left_out() -> bool:
    """Whether the sockets of the IPC list stay out of Claude Code's sandbox lists here: only
    where bubblewrap is older than 0.5, which cannot apply a denyRead or denyWrite on a socket
    (it makes a file there and fails, so every Bash call fails: an HPC node with bubblewrap 0.4
    and the KCM socket), and only where the sandbox has its seccomp filter for new sockets. On
    such a node the sockets rest on that filter alone (doctor says so). Anywhere else, or when
    the version cannot be read, they stay in the lists."""
    if not sockets_blocked():
        return False
    v = _bwrap_version()
    return v is not None and v < (0, 5)


def for_sandbox(hidden_paths: List[str]) -> List[str]:
    """The hidden paths Claude Code's sandbox mounts over (denyRead, denyWrite): all of them,
    except the sockets of the IPC list where `sockets_left_out`. The file tools' permission
    rules keep every path."""
    if not sockets_left_out():
        return list(hidden_paths)
    return [p for p in hidden_paths if p not in IPC_SOCKETS]

# Kerberos caches by name, as path patterns (pathmatch: `*` within one part): new caches are
# made with new names, so the hook and the gateway match the name, not a list taken at a start
KRB5_NAME_PATTERNS = ("/tmp/krb5cc*", "/private/tmp/krb5cc*", "/var/tmp/krb5cc*",
                      "/private/var/tmp/krb5cc*", "/dev/shm/krb5cc*")


def paths(env: Optional[Dict[str, str]] = None, cfg: Optional[config.Config] = None,
          session: bool = False) -> List[str]:
    """The hidden list as absolute paths: credentials (from the operator's environment, never a
    request's), SSH keys and certificates the ssh configs name, local IPC sockets. Not the
    write_to folders (the gateway writes there). `session=True` is the list for a Claude Code
    session that is not launched (Mode A): its own folder stays usable, its login files not."""
    env = dict(os.environ) if env is None else env
    # write_to folders hold unmasked gateway output: hidden from a session, never from the
    # gateway itself, which writes there
    out = credentials(env, cfg, write_to=session, own_config=not session)
    out += [p for p in IPC_PATHS if p not in out]
    # the folders of `launch` sessions (their config folders hold a login and transcripts): a
    # launch session hides the others from itself; the gateway and a Mode A session must not
    # read them either. Not in CREDENTIALS, which `launch` uses for its own view.
    home = pathid.home(env)
    tools = os.path.join(home, ".phiward", "tools")
    if tools not in out:
        out.append(tools)
    # the gateway's and launch's profile files (confine.write_profile): no session or gateway
    # command reads them, and no file tool writes them (the sandbox already denies writes to
    # ~/.phiward)
    profiles = os.path.join(home, ".phiward", "profiles")
    if profiles not in out:
        out.append(profiles)
    return out


def non_file_tickets(env: Optional[Dict[str, str]] = None) -> str:
    """The Kerberos cache type when it is not a file (KEYRING, KCM, API, MEMORY), else "": a
    file list cannot hide those."""
    import sys
    env = dict(os.environ) if env is None else env
    cc = env.get("KRB5CCNAME", "")
    if not cc:
        # unset is the usual case: the configured default (krb5.conf), else the system's
        cc = _default_ccache(env) or ("API:" if sys.platform == "darwin" else "FILE:")
    kind = cc.partition(":")[0] if ":" in cc else "FILE"
    return kind if kind in ("KEYRING", "KCM", "API", "MEMORY") else ""


def _default_ccache(env: Dict[str, str]) -> str:
    """`default_ccache_name` from the krb5.conf files (with include and includedir), or ""."""
    for text in _krb5_confs(env):
        m = re.search(r"^\s*default_ccache_name\s*=\s*(\S+)", text, re.M)
        if m:
            return m.group(1)
    return ""


def _krb5_confs(env: Dict[str, str]) -> Iterator[str]:
    """The text of each krb5.conf file (KRB5_CONFIG, else /etc/krb5.conf), then of the files it
    includes (include, includedir), each once, at most 64."""
    confs = [c for c in env.get("KRB5_CONFIG", "").split(":") if c] or ["/etc/krb5.conf"]
    seen: set = set()
    while confs and len(seen) < 64:
        c = confs.pop(0)
        if c in seen:
            continue
        seen.add(c)
        try:
            with open(c, encoding="utf-8", errors="replace") as fh:
                text = fh.read(1 << 20)
        except OSError:
            continue
        yield text
        for kind, inc in _KRB5_INCLUDE.findall(text):
            if kind == "includedir":
                try:
                    confs += [os.path.join(inc, n) for n in sorted(os.listdir(inc))
                              if re.fullmatch(r"[A-Za-z0-9_-]+|.+\.conf", n)]
                except OSError:
                    pass
            else:
                confs.append(inc)
