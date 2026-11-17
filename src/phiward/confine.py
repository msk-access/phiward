"""Kernel confinement: the boundary that the command text cannot give.

The gateway's profile, built for two backends (macOS Seatbelt via `sandbox-exec`, Linux
bubblewrap); `launch` (Mode B) builds its own from the same parts. The agent's shell is confined
by Claude Code's sandbox, not here.
- GATEWAY: the protected roots can be read; writes go only to the user's protected roots, a
  scratch folder and the folders the operator granted; no network unless granted; no channel to
  other processes (macOS: no mach-lookup, IPC, notifications or signals out; Linux: new IPC, PID
  and network namespaces, a seccomp filter, Landlock). Only the broker starts it.

On Linux the gateway needs Landlock ABI 2 or later as its second write layer; without it the
gateway refuses to run. No backend (Windows, or bubblewrap missing or blocked) raises
ConfineError. Callers fail closed.
"""

import os
import platform
import shutil
import struct
import subprocess
import sys
from typing import Dict, List, Optional, Sequence, Tuple

from phiward import pathmatch

SANDBOX_EXEC = "/usr/bin/sandbox-exec"


class ConfineError(Exception):
    pass


def backend() -> Optional[str]:
    if sys.platform == "darwin" and os.path.exists(SANDBOX_EXEC):
        return "seatbelt"
    if sys.platform.startswith("linux") and shutil.which("bwrap"):
        return "bwrap"
    return None


def _spellings(paths_: Sequence[str]) -> List[str]:
    """Each path as written, with its symlinks resolved, and in canonical spelling (pathid: a
    root written through the /System/Volumes/Data firmlink is denied on its normal path too),
    without duplicates."""
    from phiward import pathid
    out: List[str] = []
    for p in paths_:
        for v in pathid.spellings(p):
            if v not in out:
                out.append(v)
    return out


def _ancestors(paths_: Sequence[str]) -> List[str]:
    """Every folder above each path (both spellings), shallowest first, without "/"."""
    out: List[str] = []
    for p in _spellings(paths_):
        d = os.path.dirname(p)
        while d and d != "/":
            if d not in out:
                out.append(d)
            d = os.path.dirname(d)
    return sorted(out, key=lambda x: x.count("/"))


def _pattern_matches(patterns: Sequence[str]) -> List[str]:
    out: List[str] = []
    for p in patterns:
        out.extend(pathmatch.matches(p))  # dot-names too, never through a link
    return out


def gateway_places(writable: Sequence[str], patterns: Sequence[str]) -> List[str]:
    """The folders the gateway may write, never through a link:
    each `writable` folder exactly as given, which must still be a real folder (else
    ConfineError: the caller resolved it, and a link put on its path since then is refused),
    and each match of a pattern that is a real folder (a match that is a link is skipped)."""
    out: List[str] = []
    for w in writable:
        n = os.path.normpath(w)
        if not os.path.isdir(n) or os.path.realpath(n) != n:
            raise ConfineError("a write place is no longer a real folder (a link is on its "
                               "path); nothing runs")
        if n not in out:
            out.append(n)
    for m in _pattern_matches(patterns):
        n = os.path.normpath(m)
        if os.path.isdir(n) and os.path.realpath(n) == n and n not in out:
            out.append(n)
    return out


def _pattern_spellings(patterns: Sequence[str]) -> List[str]:
    """Each pattern as written and with its literal leading part resolved (/tmp ->
    /private/tmp on macOS): Seatbelt matches the resolved path."""
    from phiward.paths import _realpath_prefix
    out: List[str] = []
    for p in patterns:
        for v in (os.path.normpath(p), _realpath_prefix(p)):
            if v not in out:
                out.append(v)
    return out


def _pattern_prefix(pattern: str) -> str:
    """The folder part of a glob pattern before its first wildcard."""
    head = pattern.split("*", 1)[0].split("?", 1)[0].split("[", 1)[0]
    return head if head.endswith("/") else os.path.dirname(head)


# -- Seatbelt -----------------------------------------------------------------------------------

def _sb_str(p: str) -> str:
    return '"' + p.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sb_regex_for_pattern(pattern: str) -> str:
    """A Seatbelt regex for a glob pattern (the shared meaning: pathmatch), matching the
    pattern and everything below it."""
    return '#"' + pathmatch.regex(pattern).replace('"', '\\"') + '(/.*)?$"'


def _sb_paths(roots: Sequence[str], patterns: Sequence[str]) -> List[str]:
    rules = [f"(subpath {_sb_str(r)})" for r in _spellings(roots)]
    rules += [f"(regex {_sb_regex_for_pattern(p)})" for p in _spellings(patterns)]
    return rules


_DEVICES = ("/dev/null", "/dev/zero", "/dev/dtracehelper", "/dev/stdout", "/dev/stderr")
# DNS, only with the network grant (Codex keeps a list of the same kind)
_NET_SERVICES = ("com.apple.dnssd.service", "com.apple.SystemConfiguration.configd",
                 "com.apple.SystemConfiguration.DNSConfiguration")
# user and group lookups (getpwuid): ssh refuses to start without the operator's user name
# ("No user exists for uid", found in a first run on HPC)
_USER_SERVICES = ("com.apple.system.opendirectoryd.libinfo",
                  "com.apple.system.DirectoryService.libinfo_v1",
                  "com.apple.system.opendirectoryd.membership")


def seatbelt_gateway_profile(writable: Sequence[str], patterns: Sequence[str], net: bool,
                             deny_read: Sequence[str] = (), socket: str = "",
                             allow_read: Sequence[str] = ()) -> str:
    """`socket`: no network at all except a connection to that one unix socket (the operator's
    shared SSH connection); `net` is then ignored."""
    # the places as resolved; a pattern rule matches the resolved path of each write, so a link
    # under a pattern does not carry a write elsewhere
    allow = [f"(subpath {_sb_str(w)})" for w in gateway_places(writable, [])]
    allow += [f"(regex {_sb_regex_for_pattern(p)})" for p in _pattern_spellings(patterns)]
    allow += [f"(literal {_sb_str(d)})" for d in _DEVICES]
    profile = "(version 1)(allow default)"
    profile += "(deny file-write* (require-not (require-any " + " ".join(allow) + ")))"
    # no write to any Claude Code settings, even inside a write place: a write place may hold a
    # project, and its settings can turn the guards off
    profile += '(deny file-write* (regex #"/\\.claude(/.*)?$"))'
    if deny_read:
        profile += "(deny file-read* file-write* " + " ".join(
            f"(subpath {_sb_str(p)})" for p in _spellings(list(deny_read))) + ")"
    # Kerberos ticket caches in the temp folders, by name: made at any time, never listed
    profile += '(deny file-read* file-write* (regex #"^/private/(var/)?tmp/krb5cc[^/]*"))'
    if allow_read:  # single files the request needs back (the operator's ssh config)
        profile += "(allow file-read* " + " ".join(
            f"(literal {_sb_str(p)})" for p in _spellings(list(allow_read))) + ")"
    # Seatbelt matches the resolved path (/tmp is /private/tmp): every spelling of the socket
    profile += "(deny mach-lookup)(deny ipc-posix*)(deny ipc-sysv*)"
    profile += "(deny darwin-notification-post)(deny distributed-notification-post)"
    profile += "(deny signal (require-not (target same-sandbox)))"
    profile += "(deny process-info* (require-not (target same-sandbox)))"
    if socket:
        # connecting needs only network-outbound: no file right on the socket, so a request
        # cannot remove or replace the operator's socket
        profile += "(allow mach-lookup " + " ".join(
            f"(global-name {_sb_str(m)})" for m in _USER_SERVICES) + ")"
        profile += "(deny network*)"
        profile += "(allow network-outbound " + " ".join(
            f"(remote unix-socket (path-literal {_sb_str(p)}))" for p in _spellings([socket])) + ")"
    elif net:
        profile += "(allow mach-lookup " + " ".join(
            f"(global-name {_sb_str(s)})" for s in _NET_SERVICES) + ")"
        # the network, but no unix socket: an SSH agent's or a shared connection's would log
        # in to HPC as the operator; name lookups go through mDNSResponder
        profile += "(deny network-outbound (remote unix-socket))"
        profile += ('(allow network-outbound (remote unix-socket '
                    '(subpath "/private/var/run/mDNSResponder")))')
    else:
        profile += "(deny network*)"  # also unix socket connects
    return profile


# -- bubblewrap, seccomp and Landlock -----------------------------------------------------------

_BWRAP_BASE = ["--dev", "/dev", "--proc", "/proc", "--unshare-pid", "--die-with-parent"]


def open_place(path: str) -> int:
    """An O_PATH descriptor of the folder `path`, reached part by part without following a
    link, so the folder checked is the folder bound (check by path, then bind
    by path, let a swap in between move the bind)."""
    flags = os.O_PATH | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC  # type: ignore[attr-defined]
    fd = os.open("/", flags)
    try:
        for part in [p for p in path.split("/") if p]:
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except OSError:
        os.close(fd)
        raise ConfineError("a write place is no longer a real folder (a link is on its path); "
                           "nothing runs")
    return fd


def bwrap_gateway_args(writable: Sequence[str], patterns: Sequence[str], net: bool,
                       fds: Optional[Dict[str, int]] = None,
                       deny_read: Sequence[str] = (), socket: str = "",
                       allow_read: Sequence[str] = ()) -> List[str]:
    """`fds` maps each place to a descriptor from open_place; each place is bound from its
    descriptor (/proc/self/fd/N), never by its path."""
    args = ["--ro-bind", "/", "/"] + _BWRAP_BASE + [
        "--unshare-ipc", "--new-session"]
    if socket:
        # fresh, empty folders where sockets usually live (an SSH agent's, X11's, other shared
        # connections'): masking by name misses a socket that was renamed after it was bound,
        # as OpenSSH's own master does; the places are bound back below
        home = os.environ.get("HOME", "")
        for d in ("/tmp", "/var/tmp") + ((home,) if home.startswith("/") and home != "/" else ()):
            if os.path.isdir(d):
                args += ["--tmpfs", d]
    # no empty /tmp: it would hide a request folder (or a root) under /tmp, and bubblewrap would
    # then run the command in $HOME without a word. The host /tmp stays
    # read-only, like all of /; the command's TMPDIR is its private scratch folder.
    for w in gateway_places(writable, patterns):
        src = f"/proc/self/fd/{fds[w]}" if fds and w in fds else w
        args += ["--bind", src, w]
    # Claude Code settings inside a write place stay read-only; a new one can
    # still be made in a write place that has none (docs/threat-model.md)
    for w in gateway_places(writable, patterns):
        c = os.path.join(w, ".claude")
        if os.path.isdir(c) and not os.path.islink(c):
            args += ["--ro-bind", c, c]
    # what the command may not read (credentials, traces): masked last, over every bind
    for p in _spellings(list(deny_read)):
        if os.path.isdir(p) and not os.path.islink(p):
            args += ["--tmpfs", p]
        elif os.path.lexists(p) and not os.path.islink(p):
            args += ["--ro-bind", "/dev/null", p]
    hidden = [os.path.realpath(h) for h in deny_read]
    for p in allow_read:
        # the file itself, also when the name is a link (dotfile managers): bound from its
        # resolved target, unless that target is hidden
        real = os.path.realpath(p)
        if os.path.isfile(real) and not any(real == h or real.startswith(h + "/") for h in hidden):
            args += ["--ro-bind", real, p]
    if socket:
        # every other socket that has a path (an SSH agent's, X11's, another shared
        # connection's) is masked: a read-only bind does not stop a connect;
        # then the one socket, bound back over the masks; and no network besides it
        for s in _path_sockets():
            if s != socket and os.path.lexists(s) and not any(
                    s == d or s.startswith(d + "/") for d in ("/tmp", "/var/tmp")):
                args += ["--ro-bind", "/dev/null", s]
        args += ["--bind", socket, LINUX_SOCKET, "--unshare-net"]
    elif not net:
        args.append("--unshare-net")
    return args


# where the shared connection's socket appears inside a Linux request: a fixed
# name in a fresh /tmp, so no other socket in /tmp, /var/tmp or the home folder is reachable
LINUX_SOCKET = "/tmp/phiward-cm"

# system name-service sockets stay reachable (user and group lookups: sssd, nscd)
_NSS_SOCKETS = ("/var/lib/sss/pipes", "/var/run/nscd", "/run/nscd", "/run/systemd/userdb")


def _path_sockets() -> List[str]:
    """Unix sockets that have a path (from /proc/net/unix; the path is the rest of the line after
    seven fields, so it may hold spaces), name-service sockets aside."""
    out: List[str] = []
    try:
        with open("/proc/net/unix", encoding="utf-8", errors="replace") as fh:
            next(fh, None)
            for line in fh:
                parts = line.rstrip("\n").split(None, 7)
                if len(parts) == 8 and parts[7].startswith("/"):
                    p = parts[7]
                    if not any(p == n or p.startswith(n + "/") for n in _NSS_SOCKETS) and \
                            p not in out:
                        out.append(p)
    except OSError:
        pass
    return out


# Syscalls the gateway may not make (seccomp). Numbers per architecture.
_AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
_DENY = {  # name: (x86_64, aarch64)
    "ptrace": (101, 117), "process_vm_readv": (310, 270), "process_vm_writev": (311, 271),
    "unshare": (272, 97), "setns": (308, 268), "mount": (165, 40), "umount2": (166, 39),
    "pivot_root": (155, 41), "io_uring_setup": (425, 425), "io_uring_enter": (426, 426),
    "io_uring_register": (427, 427), "open_tree": (428, 428), "move_mount": (429, 429),
    "fsopen": (430, 430), "fsconfig": (431, 431), "fsmount": (432, 432), "fspick": (433, 433),
    "mount_setattr": (442, 442), "bpf": (321, 280), "perf_event_open": (298, 241),
    "userfaultfd": (323, 282), "keyctl": (250, 219), "add_key": (248, 217),
    "request_key": (249, 218),
}
_SOCKET = (41, 198)
_CLONE3 = (435, 435)
_AF_UNIX = 1
_EPERM, _ENOSYS = 1, 38


def _machine() -> str:
    m = platform.machine().lower()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(m, m)


def seccomp_program(machine: Optional[str] = None, unix: bool = False) -> bytes:
    """A classic BPF program for bwrap's --seccomp: deny the syscalls in _DENY (EPERM), make
    clone3 fail with ENOSYS (the C library then uses clone), and deny socket(AF_UNIX) unless
    `unix` (the shared-connection ssh, which runs with no network and one socket bound in)."""
    machine = machine or _machine()
    if machine not in _AUDIT_ARCH:
        raise ConfineError(f"no seccomp filter for the {machine} architecture")
    col = 0 if machine == "x86_64" else 1
    allow, kill = 0x7FFF0000, 0x80000000
    eperm, enosys = 0x00050000 | _EPERM, 0x00050000 | _ENOSYS
    ld, jeq, jge, ret = 0x20, 0x15, 0x35, 0x06
    prog: List[Tuple[int, int, int, int]] = [(ld, 0, 0, 4), (jeq, 1, 0, _AUDIT_ARCH[machine]),
                                             (ret, 0, 0, kill), (ld, 0, 0, 0)]
    if machine == "x86_64":
        prog += [(jge, 0, 1, 0x40000000), (ret, 0, 0, eperm)]  # the x32 ABI
    for nums in _DENY.values():
        prog += [(jeq, 0, 1, nums[col]), (ret, 0, 0, eperm)]
    prog += [(jeq, 0, 1, _CLONE3[col]), (ret, 0, 0, enosys)]
    if not unix:
        prog += [(jeq, 0, 3, _SOCKET[col]), (ld, 0, 0, 16), (jeq, 0, 1, _AF_UNIX),
                 (ret, 0, 0, eperm)]
    prog += [(ret, 0, 0, allow)]
    return b"".join(struct.pack("<HBBI", *ins) for ins in prog)


# Runs inside bubblewrap before the command: Landlock allows writes only below the given paths.
# argv: N PATH... CMD [ARG]...   Exit 126 when Landlock (ABI 2 or later) is not available.
LANDLOCK_HELPER = r"""
import ctypes, os, struct, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
def fail(msg):
    sys.stderr.write("phiward gateway: " + msg + "; nothing runs\n"); os._exit(126)
abi = libc.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1))
if abi < 2:
    fail("Landlock ABI 2 or later is needed (the kernel has %s)" % ("none" if abi < 0 else abi))
fs = 0
for bit in (1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13):  # write, remove, make, refer
    fs |= 1 << bit
if abi >= 3: fs |= 1 << 14  # truncate
if abi >= 5: fs |= 1 << 15  # ioctl on devices
attr = struct.pack("<Q", fs)
if abi >= 4: attr += struct.pack("<Q", 0)
if abi >= 6: attr += struct.pack("<Q", 3)  # scope: abstract unix sockets, signals
buf = ctypes.create_string_buffer(attr, len(attr))
rs = libc.syscall(444, buf, ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
if rs < 0: fail("Landlock cannot make a ruleset")
n = int(sys.argv[1]); entries = sys.argv[2:2 + n]
k = int(sys.argv[2 + n]); close = sys.argv[3 + n:3 + n + k]; cmd = sys.argv[3 + n + k:]
for c in close:  # the broker's descriptors of the places: the command does not get them
    try:
        os.close(int(c))
    except OSError:
        pass
filebits = (1 << 1) | (fs & ((1 << 14) | (1 << 15)))
for e in entries:
    p, dev, ino = e.rsplit("|", 2)
    try:
        fd = os.open(p, os.O_PATH | os.O_CLOEXEC | (os.O_NOFOLLOW if dev != "-" else 0))
    except OSError:
        continue
    st = os.fstat(fd)
    if dev != "-" and (st.st_dev, st.st_ino) != (int(dev), int(ino)):
        fail("a write place changed before the command started")  # the bound folder only
    bits = fs if os.path.isdir(p) else filebits
    rule = ctypes.create_string_buffer(struct.pack("<Qi", bits, fd), 12)
    if libc.syscall(445, ctypes.c_int(rs), ctypes.c_int(1), rule, ctypes.c_uint32(0)) < 0:
        fail("Landlock cannot add a rule")
    os.close(fd)
if libc.prctl(38, 1, 0, 0, 0) != 0: fail("no_new_privs cannot be set")
if libc.syscall(446, ctypes.c_int(rs), ctypes.c_uint32(0)) < 0: fail("Landlock cannot be enforced")
os.close(rs)
try:
    os.execvp(cmd[0], cmd)
except OSError:
    sys.stderr.write("phiward gateway: the command could not start\n"); os._exit(127)
"""

_GATEWAY_DEVICES = ("/dev/null", "/dev/zero")  # no /dev/tty: the gateway has no terminal


# -- entry points -------------------------------------------------------------------------------

_NO_BACKEND = ("no confinement backend on this system (needs macOS sandbox-exec or Linux "
               "bubblewrap)")


def gateway_command(argv: Sequence[str], writable: Sequence[str], patterns: Sequence[str],
                    net: bool = False, deny_read: Sequence[str] = (),
                    socket: str = "", allow_read: Sequence[str] = ()) -> Tuple[List[str], List[int]]:
    """`argv` wrapped so that it writes only to `writable` (and pattern matches), with no
    network unless `net`, and the file descriptors that must stay open for it (Linux: the
    seccomp program). The caller closes the descriptors after the process starts."""
    b = backend()
    if b == "seatbelt":
        return [SANDBOX_EXEC, "-p", seatbelt_gateway_profile(writable, patterns, net, deny_read,
                                                            socket, allow_read)] + \
            list(argv), []
    if b == "bwrap":
        prog = seccomp_program(unix=bool(socket))
        r, w = os.pipe()
        os.write(w, prog)  # small: it fits in the pipe buffer
        os.close(w)
        fds: Dict[str, int] = {}
        try:
            for p in gateway_places(writable, patterns):
                fds[p] = open_place(p)
        except ConfineError:
            for fd in list(fds.values()) + [r]:
                os.close(fd)
            raise
        entries = []
        for p, fd in fds.items():
            os.set_inheritable(fd, True)
            st = os.fstat(fd)
            entries.append(f"{p}|{st.st_dev}|{st.st_ino}")
        entries += [f"{d}|-|-" for d in _GATEWAY_DEVICES]
        held = [str(fd) for fd in fds.values()]
        helper = [sys.executable, "-I", "-S", "-c", LANDLOCK_HELPER, str(len(entries))] + \
            entries + [str(len(held))] + held
        return [shutil.which("bwrap") or "bwrap", "--seccomp", str(r)] + \
            bwrap_gateway_args(writable, patterns, net, fds, deny_read, socket, allow_read) + \
            ["--"] + helper + \
            list(argv), \
            [r] + list(fds.values())
    raise ConfineError(_NO_BACKEND)


def self_test() -> Optional[str]:
    """Why the gateway's confinement does not work here, or None. It runs `true` in the
    gateway profile."""
    try:
        cmd, fds = gateway_command(["true"], [], [], False)
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=30, pass_fds=fds)
        finally:
            for fd in fds:
                os.close(fd)
        if r.returncode != 0:
            why = r.stderr.decode("utf-8", "replace").strip().splitlines()
            return f"the gateway profile cannot start a process here (exit {r.returncode}" + \
                (f": {why[-1]}" if why else "; on Ubuntu 24.04, unprivileged user namespaces "
                 "may be blocked by AppArmor") + ")"
    except ConfineError as exc:
        return str(exc)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"the confinement backend failed ({type(exc).__name__})"
    return None
