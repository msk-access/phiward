"""HPC requests with the login kept outside.

Every request to an HPC host (`copy` to or from a remote, `run --remote`) runs ssh through the
operator's shared connection: the operator starts it (`kinit`, then `ssh -fN HOST`), and it holds
the login. phiward's ssh joins it through its control socket, which needs no key and no ticket.
So the profile of the request reads no credential and has no network except that one socket:
a key or ticket can never reach a request, and a program on the other end that attacks the
local ssh or rsync can reach nothing but the HPC host, where the data already is.

`[remote] use_shared_connection = false` (user config) keeps the older way: ssh logs in itself,
so it must read the key or ticket, and the request has the network.

Pushes (`copy LOCAL... HOST:/path`) do not use rsync: the broker opens each checked source part
by part without following a link, walks it by descriptors, and writes a tar stream into
`ssh HOST tar -x`. Nothing the agent can change is opened by name after the check, and the
remote side cannot ask for anything (the stream goes one way).
"""

import os
import shlex
import stat
import subprocess
import tarfile
from dataclasses import dataclass
from typing import BinaryIO, Callable, List, Optional, Sequence, Tuple

from phiward import config

SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
               "-o", "PermitLocalCommand=no", "-o", "ClearAllForwardings=yes",
               "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ForwardX11Trusted=no",
               "-o", "RequestTTY=no", "-T"]

START_IT = "start your shared connection first: kinit, then ssh -fN {host} (docs/hpc.md)"


def _ssh() -> Optional[str]:
    from phiward.copying import system_program
    return system_program("ssh")


def _ssh_file(cfg: config.Config) -> str:
    return cfg.ssh_config or "/dev/null"


def shared_socket(cfg: config.Config, host: str, timeout: float = 10) -> Tuple[str, str]:
    """(the control socket of the operator's shared connection to `host`, "") or ("", why not).
    The socket is the one the operator's ssh config names (`ssh -G`, no network), and the
    connection must answer (`ssh -O check`); both run in the broker, outside every profile."""
    ssh = _ssh()
    if ssh is None:
        return "", "there is no system ssh"
    env = {"PATH": "/usr/bin:/bin", "HOME": os.path.expanduser("~")}
    try:
        r = subprocess.run([ssh, "-G", "-F", _ssh_file(cfg), "--", host], capture_output=True,
                           text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return "", "ssh could not read its config"
    sock = ""
    for line in r.stdout.splitlines():
        k, _, v = line.partition(" ")
        if k.lower() == "controlpath":
            sock = v.strip()
    if not cfg.ssh_config:
        return "", ("no [copy] ssh_config is set in the user config. The operator does the "
                    "one-time HPC setup (docs/hpc.md), then `kinit` and `ssh -fN " + host + "`")
    if not sock or sock == "none" or not sock.startswith("/"):
        return "", ("[copy] ssh_config names no ControlPath for this host; add one and "
                    + START_IT.format(host=host))
    why = socket_problem(sock)
    if why == "missing":
        return "", START_IT.format(host=host)
    if why:
        return "", why
    sock = os.path.realpath(sock)
    try:
        r = subprocess.run([ssh, "-F", _ssh_file(cfg), "-S", sock, "-O", "check", "--", host],
                           capture_output=True, timeout=timeout, env=env,
                           stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return "", START_IT.format(host=host)
    if r.returncode != 0:
        return "", START_IT.format(host=host)
    return sock, ""


def socket_problem(sock: str) -> str:
    """Why the control socket at `sock` may not be trusted, "missing", or "" (a socket
    the agent made first, where the operator's ssh would find it, would receive a
    push's stream). It must be a socket (not a link to one), owned by the operator, under
    ~/.ssh or /run/user/<uid> (folders no session can read or write), with every folder from
    there down owned by the operator and writable by no one else."""
    try:
        st = os.lstat(sock)
    except OSError:
        return "missing"
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.getuid():
        return ("the shared connection's socket is not a socket of yours; remove it and start "
                "the connection again")
    real = os.path.realpath(sock)
    bases = [os.path.realpath(os.path.join(os.path.expanduser("~"), ".ssh")),
             f"/run/user/{os.getuid()}"]
    base = next((b for b in bases if real.startswith(b + "/")), "")
    if not base:
        return ("the shared connection's ControlPath must be under ~/.ssh (a folder no session "
                "can read or write); see docs/hpc.md")
    d = os.path.dirname(real)
    while True:
        try:
            ds = os.lstat(d)
        except OSError:
            return "missing"
        if ds.st_uid != os.getuid() or ds.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return ("a folder above the shared connection's socket is not yours alone (owner or "
                    "mode)")
        if d == base:
            return ""
        d = os.path.dirname(d)


def ssh_command(cfg: config.Config, sock: str = "") -> Optional[List[str]]:
    """The ssh argv without the host: the operator's chosen config only, no proxy or local
    command, no forwarding, no terminal, never a prompt; with `sock`, through that socket and
    never a new login."""
    ssh = _ssh()
    if ssh is None:
        return None
    cmd = [ssh, "-F", _ssh_file(cfg)] + SSH_OPTIONS
    if sock:
        cmd += ["-o", "ControlMaster=no", "-S", sock]
    return cmd


@dataclass
class Route:
    """How a request reaches a host: the ssh argv (without the host), the socket (empty without
    the shared connection) and the profile settings that go with it."""
    ssh: List[str]
    socket: str
    net: bool
    deny_read: List[str]
    allow_read: List[str]


def route(cfg: config.Config, host: str) -> Tuple[Optional[Route], str]:
    """(the route to `host`, "") or (None, why not)."""
    if not cfg.use_shared_connection:
        ssh = ssh_command(cfg)
        if ssh is None:
            return None, "there is no system ssh"
        # the older way: ssh logs in itself, so it reads the credentials and has the network
        return Route(ssh, "", True, [], []), ""
    sock, why = shared_socket(cfg, host)
    if why:
        return None, why
    from phiward import confine
    # on Linux the socket is bound at a fixed name in a fresh /tmp inside the request
    ssh = ssh_command(cfg, confine.LINUX_SOCKET if confine.backend() == "bwrap" else sock)
    if ssh is None:
        return None, "there is no system ssh"
    from phiward import run
    allow = [cfg.ssh_config] if cfg.ssh_config else []
    return Route(ssh, sock, False, run.gateway_hidden(cfg), allow), ""


# -- pushes ------------------------------------------------------------------------------------

class PushError(Exception):
    pass


@dataclass
class Counts:
    files: int = 0
    folders: int = 0
    skipped: int = 0
    size: int = 0


_NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC

# files a shell, ssh or a tool on the cluster reads at login or when you enter a folder: a push
# never plants them, at any depth (final review: a push to a broad prefix could plant
# ~/.bashrc or ~/.ssh/authorized_keys)
RUNS_AT_LOGIN = frozenset({
    ".ssh", ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc",
    ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".login", ".logout", ".cshrc", ".tcshrc",
    ".kshrc", ".mkshrc", ".inputrc", ".forward", ".rhosts", ".shosts", ".k5login", ".k5users",
    ".pam_environment", ".envrc", ".gnupg", ".netrc", ".config", ".local", ".condarc",
    ".Rprofile", ".Renviron", ".modulerc", ".lmod.d", ".bash_aliases", ".gitconfig", ".ipython",
    ".jupyter", ".vimrc", ".tmux.conf", ".emacs", ".emacs.d", ".conda", ".nextflow", ".julia",
    ".npmrc", ".pypirc", ".Xresources", ".xinitrc", ".xprofile",
    # a repository's config and hooks: git runs what they name when someone runs git there
    ".git"})


def open_by_parts(path: str, forbid: Optional[set] = None) -> int:
    """A read descriptor of the file or folder at the absolute `path`, reached part by part
    without following a link anywhere (OSError otherwise). With `forbid`, a folder on the way
    that lies on one of those devices raises PushError."""
    parts = [p for p in path.split("/") if p]
    if not parts:
        raise PushError("the root folder cannot be pushed")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW)
    try:
        for p in parts[:-1]:
            nxt = os.open(p, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            if forbid and os.fstat(fd).st_dev in forbid:
                raise PushError("a source is in /dev, /proc or /sys")
        last = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | _NOFOLLOW, dir_fd=fd)
        if forbid and os.fstat(last).st_dev in forbid:
            os.close(last)
            raise PushError("a source is in /dev, /proc or /sys")
        return last
    finally:
        os.close(fd)


def _walk(fd: int, name: str, counts: Counts, limit: int,
          visit: Optional[Callable[[str, int, os.stat_result], None]], depth: int = 0) -> None:
    """Each folder and plain file under `fd`, by descriptors only: a link, a special file or a
    file with a second name is skipped and counted, never followed."""
    if depth > 256:
        raise PushError("the folder tree is too deep")
    if name and (os.path.basename(name) in RUNS_AT_LOGIN
                 or ("/" not in name and name.startswith("."))):
        # a login file at any depth; and every dot-name at the top of the destination, which
        # may be a home folder on the cluster (`.gitconfig`, `.vimrc`)
        counts.skipped += 1
        return
    st = os.fstat(fd)
    if stat.S_ISDIR(st.st_mode):
        counts.folders += 1 if name else 0
        if visit and name:
            visit(name, fd, st)
        for n in sorted(os.listdir(fd)):
            if n in RUNS_AT_LOGIN or (not name and n.startswith(".")):
                counts.skipped += 1
                continue
            try:
                c = os.open(n, os.O_RDONLY | os.O_NONBLOCK | _NOFOLLOW, dir_fd=fd)
            except OSError:  # a link (ELOOP), or gone
                counts.skipped += 1
                continue
            try:
                _walk(c, f"{name}/{n}" if name else n, counts, limit, visit, depth + 1)
            finally:
                os.close(c)
        return
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        counts.skipped += 1
        return
    counts.files += 1
    counts.size += st.st_size
    if counts.size > limit:
        raise PushError("the push is larger than [copy] push_limit_gib; ask the operator to copy "
                        "it")
    if visit:
        visit(name, fd, st)


@dataclass
class Source:
    """A push source, resolved once when it is checked: `path` has no link on it then, and it
    is opened part by part without following one ever after (a link put on it later makes the
    open fail). `top` is the name it lands under ("" for a folder's contents, as rsync's
    `src/`)."""
    path: str
    top: str


def contents_only(spec: str) -> bool:
    """rsync's rule: `src/` and `src/.` (and `.`) mean the folder's contents."""
    return spec.endswith("/") or spec.rstrip("/").split("/")[-1] == "."


def resolve(sources: Sequence[str], cwd: str) -> List[Source]:
    out = []
    for src in sources:
        full = os.path.realpath(os.path.join(cwd, os.path.expanduser(src)))
        top = "" if contents_only(src) and os.path.isdir(full) else os.path.basename(full)
        out.append(Source(full, top))
    return out


# file systems whose "files" are not files: /dev/fd/N would stream a file the broker has open
NOT_FILES = ("/dev", "/proc", "/sys")


def _special_devices() -> set:
    out = set()
    for p in NOT_FILES:
        try:
            out.add(os.stat(p).st_dev)
        except OSError:
            pass
    return out


def _open_source(src: "Source") -> int:
    """The source opened without a link on its path, refused when it lies on /dev, /proc or
    /sys: judged by the file system it is on, not by its spelling (the macOS root folder
    ignores case: `/DEV/fd/3`)."""
    # the folders on the way are judged: opening /dev/fd/N gives the file behind it, which is
    # on its own file system, while /dev (in any spelling) is on devfs
    return open_by_parts(src.path, _special_devices())


def survey(sources: Sequence[Source], limit: int) -> Counts:
    """Count what a push would send (and check the limit) without sending anything."""
    counts = Counts()
    for src in sources:
        fd = _open_source(src)
        try:
            _walk(fd, src.top, counts, limit, None)
        finally:
            os.close(fd)
    return counts


def feeder(sources: Sequence[Source], limit: int, counts: Counts) -> Callable[[BinaryIO], None]:
    """A function that writes the tar stream of the sources into ssh's input. It never resolves
    a path again: only the checked ones, opened without following a link."""
    def feed(stream: BinaryIO) -> None:
        with tarfile.open(fileobj=stream, mode="w|", format=tarfile.PAX_FORMAT) as tar:
            def visit(name: str, fd: int, st: os.stat_result) -> None:
                ti = tarfile.TarInfo(name)
                ti.mtime = int(st.st_mtime)
                # folders 0755, files 0644: a pushed file never arrives as a program the operator
                # might run later (a replaced job script)
                ti.mode = 0o755 if stat.S_ISDIR(st.st_mode) else 0o644
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                if stat.S_ISDIR(st.st_mode):
                    ti.type = tarfile.DIRTYPE
                    tar.addfile(ti)
                    return
                ti.size = st.st_size
                with os.fdopen(os.dup(fd), "rb") as fh:
                    os.lseek(fh.fileno(), 0, os.SEEK_SET)
                    tar.addfile(ti, fh)
            for src in sources:
                fd = _open_source(src)
                try:
                    _walk(fd, src.top, counts, limit, visit)
                finally:
                    os.close(fd)
    return feed


# the receiving side of a push, in sh (the login shell may be csh or fish): make the folder,
# then refuse when it is, by its real path, the home folder or above it (a push there could plant
# your login files; a name cannot tell where a cluster keeps home folders), then unpack. Only
# characters that sh, csh and fish all leave alone inside single quotes.
_RECEIVE = ('mkdir -p -- "$1" && d=$(cd -- "$1" && pwd -P) && h=$(cd && pwd -P) && '
            'case "$d" in /) exit 3;; esac && case "$h/" in "$d"/*) '
            'echo "phiward: the destination is your home folder or above it" >&2; exit 3;; esac '
            # keep existing files: --skip-old-files where tar has it (GNU tar 1.28 and later),
            # else -k (bsdtar skips; an older GNU tar keeps them and reports each)
            '&& k=-k && { tar --skip-old-files --version >/dev/null 2>&1 && k=--skip-old-files '
            '|| :; } && exec tar -x "$k" -f - -C "$d"')


def receive_script(path: str) -> str:
    """The remote command of a push: make the folder, check it is not the home folder or above
    it, unpack the stream into it. The path holds only safe characters (copying._SAFE_PATH);
    quoting keeps it one word in sh, csh and fish."""
    return f"sh -c {shlex.quote(_RECEIVE)} sh {shlex.quote(path)}"


# -- pulls -------------------------------------------------------------------------------------

def send_script(path: str) -> str:
    """The remote command of a pull: a tar stream of `path` (its contents for `path/`)."""
    if contents_only(path):
        return f"tar -c -f - -C {shlex.quote(os.path.normpath(path))} ."
    p = os.path.normpath(path)
    return (f"tar -c -f - -C {shlex.quote(os.path.dirname(p) or '/')} -- "
            f"{shlex.quote(os.path.basename(p))}")


# "$2" and "$3" are the system mkdir and tar (never found through the request's PATH)
# The receiving side of a pull, in the gateway profile: a careful extractor in place of tar, the
# same on every system (bsdtar -k could still change an existing folder's mode). Standard
# library only; it reads the stream from stdin and writes under argv[1]. What exists is kept;
# links, special files, `..`, `.claude` are skipped; nothing is followed through a link.
EXTRACT_PY = r"""
import os, stat, sys, tarfile
dest = os.path.realpath(sys.argv[1])
os.makedirs(dest, mode=0o755, exist_ok=True)
NF = os.O_NOFOLLOW | os.O_CLOEXEC
def folder(parts):
    fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | NF)
    try:
        for p in parts:
            try:
                os.mkdir(p, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            nfd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | NF, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except OSError:
        os.close(fd)
        return None
kept = skipped = 0
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as t:
    for m in t:
        parts = [p for p in m.name.split("/") if p not in ("", ".")]
        if not parts or ".." in parts or any(p.casefold() == ".claude" for p in parts):
            skipped += 1
            continue
        if m.isdir():
            fd = folder(parts)
            if fd is None:
                kept += 1
            else:
                os.close(fd)
            continue
        if not m.isreg():
            skipped += 1
            continue
        fd = folder(parts[:-1])
        if fd is None:
            kept += 1
            continue
        try:
            try:
                out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | NF, 0o644,
                              dir_fd=fd)
            except OSError:
                kept += 1
                continue
            src = t.extractfile(m)
            with os.fdopen(out, "wb") as fh:
                while True:
                    b = src.read(1 << 20)
                    if not b:
                        break
                    fh.write(b)
        finally:
            os.close(fd)
sys.stdout.write(f"kept {kept} existing, skipped {skipped}\n")
"""

