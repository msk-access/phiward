"""`phiward copy SRC... DST`: copy protected data without printing it.

The destination must be inside a protected root of the user's own config, or under a configured
remote (`[copy] remotes = ["host:/abs/prefix"]`) and, for a push, under `[remote] roots`. Like
`run`, the command the agent types is a
client of the broker; the broker calls `execute`. The copy runs with rsync (or
`cp -R` when rsync is missing and every path is local) in the gateway profile of
`phiward run`: it can write only at its destination (a folder inside a protected path of the
user's config, reached with no link), and it gets the network only when a remote is involved. Every line
it prints goes through the sanitizer, which also masks every entry name under the roots. The
wrapper's own messages never name a path.
"""

import os
import re
import subprocess
import sys
from typing import Callable, Dict, List, Optional, Sequence, TextIO, Tuple

from phiward import config, paths, pathid, safeio
from phiward.sanitize import Sanitizer, SanitizerError

USAGE = "usage: phiward copy [--dry-run] SRC... DST\n"
HELP = USAGE + """
Options:
  --dry-run    check the request and copy nothing (only as the first word)
  -h, --help   show this help

Copy protected data without printing it. DST must be inside a protected root of your user
config, or under a configured remote (`[copy] remotes = ["host:/abs/prefix"]`). A source or
destination on a remote is written HOST:/PATH; a push goes only under `[remote] roots` (where
remote output is masked). A local path is made absolute once, and every
check and the copy itself use that path; one with a `..` part, or one that starts with `~` (a
quoted `~`, which the shell did not expand), is refused: give the full path.

The command is only a client. The broker runs the copy outside the agent's sandbox, so a
broker must be running (`phiward broker`). The copy writes only at its destination, which
must be inside a protected path of your config and reached with no link. It gets the network
only when a remote is involved. Every line it prints is masked,
and its own messages never name a path.
"""
_REMOTE = re.compile(r"([A-Za-z0-9_.@-]+):(/.*)", re.S)
# openrsync passes a remote path to the remote shell as it is, so a remote path may hold only
# characters no shell treats as special
_SAFE_PATH = re.compile(r"/[A-Za-z0-9._+/-]*")


_HOME_WORD = re.compile(r"(home\d*|homes|users)", re.I)


def remote_prefix_problem(path: str) -> str:
    """Why a copy remote's folder is too broad, or "": a push there could reach files your
    login on the cluster runs (your home folder's startup files, `~/.ssh`)."""
    parts = [p for p in os.path.normpath(path).split("/") if p]
    if len(parts) < 2:
        return "it is / or a folder just below it; name your work folder on the cluster"
    if any(p.startswith(".") for p in parts):
        return "it is in a dot-folder (`.ssh`, `.config`): files there run or configure later"
    if _HOME_WORD.fullmatch(parts[-2]) or _HOME_WORD.fullmatch(parts[-1]):
        return "it looks like a home folder; name a work folder inside it"
    return ""


def _remote_ok(spec: str, remotes: Sequence[str]) -> bool:
    m = _REMOTE.fullmatch(spec)
    if not m or not _SAFE_PATH.fullmatch(m.group(2)) or ".." in m.group(2).split("/"):
        return False
    host, path = m.group(1), os.path.normpath(m.group(2))
    if any(p.startswith(".") for p in path.split("/") if p):
        return False  # never into a dot-folder (`.ssh`, `.git/hooks`): files there run later
    for r in remotes:
        rm = _REMOTE.fullmatch(r)
        if not rm:
            continue
        prefix = os.path.normpath(rm.group(2))
        if remote_prefix_problem(prefix):
            continue  # too broad: never a place a copy may go
        if rm.group(1) == host and (path == prefix or path.startswith(prefix.rstrip("/") + "/")):
            return True
    return False


def dest_place(dst: str, cwd: str, cfg: config.Config) -> "Tuple[str, str]":
    """(the one place a local copy or a pull may write: the nearest existing folder of its
    destination; why it may not, or ""). The place must be inside one of the user's roots by
    its real path, with no link on the way (a link the agent made inside a root would lead the
    copy out of it), and not where your tools load code later or that holds a names, pack or
    phiward file."""
    d = os.path.normpath(os.path.join(cwd, os.path.expanduser(dst)))
    if any(pathid.fold(c) == ".claude" or c.lower() == ".claude" for c in d.split("/")):
        return d, "the destination is in a .claude folder (Claude Code loads settings from there)"
    while not os.path.isdir(d) or os.path.islink(d):
        if os.path.islink(d):
            return d, "the destination is reached through a link; name the real folder"
        up = os.path.dirname(d)
        if up == d:
            break
        d = up
    real = os.path.realpath(d)
    canon = pathid.canon(real)  # the file system's own spelling (/System/Volumes/Data undone)
    same = any(((x == d) if pathid.case_sensitive(real) else pathid.fold(x) == pathid.fold(d))
               for x in (real, "/System/Volumes/Data" + canon if canon.startswith("/") else ""))
    if not same:
        return real, "the destination is reached through a link; name the real folder"
    real = canon
    # inside a protected root (not a pattern match: in Mode A the agent's own sandbox cannot
    # cover a pattern match it makes, so it could read back what lands there)
    if not any(config._deny_inside(real, r) or _within(real, r) for r in cfg.user_roots):
        return real, "the destination is not inside a protected root of the user config"
    why = config.runs_later_problem(real)
    if why:
        return real, f"the destination is where your own tools load code later: {why}"
    # by name (folded where the system folds) and by identity (device and inode), so a volume
    # that ignores letter case on Linux cannot hide a match
    for r in cfg.derived_roots:
        if _related(real, r):
            return real, "the destination is in or above a derived protected folder (a .git)"
    for f in list(cfg.names_from) + [p for p in cfg.packs if "/" in p]:
        f = os.path.realpath(os.path.expanduser(f))
        if config._deny_inside(f, real) or _holds(real, f):
            return real, "the destination holds a names or pack file of the config"
    for g in config.guard_files() + [config.spool_dir()]:
        if _related(real, g):
            return real, "the destination holds, or is inside, a phiward file or folder"
    return real, ""


def holds_claude(srcs: Sequence[str], cwd: str, limit: int = 200000) -> str:
    """Why a copy source cannot be copied as it is, or "": it is or holds a `.claude` folder in
    any letter case (rsync's exclude matches one spelling only), or it cannot be checked (a
    folder that cannot be read, or one with more entries than `limit`)."""
    seen = 0
    for src in srcs:
        stack = [os.path.join(cwd, os.path.expanduser(src))]
        while stack:
            a = stack.pop()
            seen += 1
            if seen > limit:
                return (f"a source holds more than {limit} entries, so it cannot be checked for "
                        ".claude folders; copy smaller parts")
            if os.path.basename(a.rstrip("/")).casefold() == ".claude":
                return ("a source is or holds a .claude folder (Claude Code loads settings from "
                        "it); copy without it")
            if os.path.isdir(a) and not os.path.islink(a):
                try:
                    stack += [os.path.join(a, n) for n in os.listdir(a)]
                except OSError:
                    return ("a source folder cannot be read, so it cannot be checked for "
                            ".claude folders")
    return ""


def _holds_links(srcs: Sequence[str], cwd: str, limit: int = 200000) -> bool:
    seen = 0
    for src in srcs:
        stack = [os.path.join(cwd, os.path.expanduser(src))]
        while stack and seen < limit:
            a = stack.pop()
            seen += 1
            if os.path.isdir(a) and not os.path.islink(a):
                try:
                    for n in os.listdir(a):
                        p = os.path.join(a, n)
                        if os.path.islink(p):
                            return True
                        stack.append(p)
                except OSError:
                    pass
    return False


def type_clash(srcs: Sequence[str], dst: str, cwd: str, limit: int = 200000) -> bool:
    """Whether a local copy would meet something at the destination of another type (a folder
    where a file exists, a file where a folder or a link exists). rsync on macOS would replace
    it; phiward refuses the whole copy instead."""
    base = os.path.join(cwd, os.path.expanduser(dst))
    many = len(srcs) > 1 or dst.endswith("/")
    seen = 0
    for src in srcs:
        s = os.path.join(cwd, os.path.expanduser(src))
        top = base if not (many or os.path.isdir(base)) else (
            base if src.endswith("/") else os.path.join(base, os.path.basename(s.rstrip("/"))))
        stack = [(s, top)]
        while stack:
            a, b = stack.pop()
            seen += 1
            if seen > limit:
                return True  # too large to check: refused, not guessed
            if not os.path.lexists(b):
                continue
            if os.path.islink(b) or os.path.isdir(a) != os.path.isdir(b):
                return True
            if os.path.isdir(a) and not os.path.islink(a):
                try:
                    stack += [(os.path.join(a, n), os.path.join(b, n)) for n in os.listdir(a)]
                except OSError:
                    return True
    return False


def _within(a: str, b: str) -> bool:
    """Whether `a` is `b` or inside it, by identity: a folder on `a`'s way up is `b`."""
    target = pathid.identity(b)
    if target is None:
        return False
    d = os.path.realpath(a)
    while True:
        if pathid.identity(d) == target:
            return True
        up = os.path.dirname(d)
        if up == d:
            return False
        d = up


def _holds(place: str, path: str) -> bool:
    """Whether the folder `place` holds `path` (or is it), by identity."""
    return _within(path, place)


def _related(a: str, b: str) -> bool:
    """Whether `a` is inside `b` or holds it, by name or by identity."""
    return (config._deny_inside(a, b) or config._deny_inside(b, a)
            or _within(a, b) or _within(b, a))


def _local_inside(path: str, cwd: str, pset: paths.ProtectedSet) -> bool:
    full = os.path.normpath(os.path.join(cwd, os.path.expanduser(path)))
    return pset.relation(full) == paths.INSIDE


def _is_remote(arg: str) -> bool:
    """An argument rsync reads as remote (a `:` before the first `/`) is remote. A local name
    with a `:` is written `./name` (an exception for a name that exists
    in the request's folder made rsync and this check disagree)."""
    return ":" in arg.split("/", 1)[0]


NOT_IN_ROOT = ("the destination is not inside a protected path of the user config; results leave "
               "a root only as `phiward run` output (counts and summaries)")


def plan(args: Sequence[str], cwd: str, cfg: config.Config) -> Optional[str]:
    """Why the copy is refused, or None when it may run."""
    if len(args) < 2:
        return "a copy needs at least one source and a destination"
    if any(a.startswith("-") for a in args):
        return "options are not accepted (the wrapper picks them)"
    dst = args[-1]
    # only the user's own roots: a root that a repo config adds is in the agent's reach
    pset = paths.ProtectedSet(cfg.user_roots, cfg.user_patterns)
    if _is_remote(dst):
        if not _remote_ok(dst, cfg.remotes):
            return "the destination is not under a configured remote ([copy] remotes)"
    elif not _local_inside(dst, cwd, pset):
        return NOT_IN_ROOT
    from phiward import run
    hidden = paths.ProtectedSet(run.gateway_hidden(cfg), [])
    for src in args[:-1]:
        if _is_remote(src) and not _remote_ok(src, cfg.remotes):
            return "a remote source is not under a configured remote ([copy] remotes)"
        if not _is_remote(src):
            full = os.path.realpath(os.path.join(cwd, os.path.expanduser(src)))
            if hidden.relation(full) in (paths.INSIDE, paths.ABOVE):
                # rsync and ssh read credentials for a remote copy, so the profile cannot hide
                # them: a source that is or holds one is refused here
                return "a source is or holds a credential or a trace that no copy may read"
    if _is_remote(dst):
        # what a push puts on the cluster is masked in remote output only under [remote] roots
        m = _REMOTE.fullmatch(dst)
        where = os.path.normpath(m.group(2)) if m else ""
        if not any(where == r or where.startswith(r.rstrip("/") + "/") for r in cfg.remote_roots):
            return ("the destination is not under [remote] roots of the user config (what lands "
                    "there would not be masked)")
    return None


# Programs a copy runs come from system folders only, never from a PATH folder the agent may
# write (~/.local/bin, Homebrew), and ssh reads only the operator's chosen config.
SYSTEM_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")


def system_program(name: str) -> Optional[str]:
    for d in SYSTEM_DIRS:
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def rsync_command(args: Sequence[str], dry_run: bool) -> Optional[List[str]]:
    """The rsync argv of a local copy, or None when there is no system rsync. Remote copies do
    not use rsync (only the system ssh touches the shared connection)."""
    rsync = system_program("rsync")
    if rsync is None:
        return None
    # a `.claude` folder is never copied: Claude Code loads settings and hooks from it
    # existing files are kept, never replaced (an agent could replace a script the operator runs)
    # files, folders and times only: no modes (an existing folder's mode stays), no links
    return [rsync, "-rt", "--ignore-existing", "--exclude=.claude/"] + \
        (["--dry-run"] if dry_run else []) + ["--"] + list(args)


def _never() -> bool:
    return False


def local_args(args: Sequence[str], cwd: str) -> "Tuple[List[str], str]":
    """Each local path once, as every check and every program of the copy then use it: absolute
    and normalized, with rsync's "the folder's contents" marker (`src/`, `src/.`, `.`) kept as
    written. A path with a `..` part or one that starts with `~` is refused (a reason): the
    checks and the programs could read it differently. Remote paths and options stay as given
    (`plan` checks them)."""
    out = []
    for a in args:
        if _is_remote(a) or a.startswith("-"):
            out.append(a)
            continue
        if not a:
            return [], "an empty path is not a path; give the full path"
        if a.startswith("~") or ".." in a.split("/"):
            return [], "a local path holds `..` or starts with `~`; give the full path"
        full = os.path.normpath(os.path.join(cwd, a))
        mark = "/." if (a == "." or a.endswith("/.")) else ("/" if a.endswith("/") else "")
        out.append(full.rstrip("/") + mark if full != "/" else "/")
    return out, ""


def execute(argv: Sequence[str], cwd: str, env: Dict[str, str], out: TextIO,
            cancelled: Callable[[], bool] = _never) -> int:
    """Run a copy request (in the broker), with `cwd` as the working folder."""
    dry_run = False
    args = list(argv)
    if args[:1] == ["--dry-run"]:
        dry_run, args = True, args[1:]
    if args[:1] in (["-h"], ["--help"]):
        out.write(USAGE)
        return 0
    cfg = config.load(cwd)
    if cfg.problem:
        out.write("copy refused: the phiward config cannot be used (run phiward doctor)\n")
        return 3
    args, why = local_args(args, cwd)
    if why:
        out.write(f"copy refused: {why}\n")
        return 2
    why = plan(args, cwd, cfg)
    if why:
        out.write(f"copy refused: {why}\n")
        return 2
    srcs, dst = args[:-1], args[-1]
    remote_srcs = [s for s in srcs if _is_remote(s)]
    if _is_remote(dst) and remote_srcs:
        out.write("copy refused: a copy between two remotes is not supported\n")
        return 2
    try:
        san = Sanitizer.from_config(cfg, entries=True)
    except SanitizerError:
        out.write("copy refused: the sanitizer cannot start (run phiward doctor)\n")
        return 3
    from phiward import confine, run
    try:
        if _is_remote(dst):
            return _push(srcs, dst, cwd, cfg, san, dry_run, env, out, cancelled)
        if remote_srcs:
            hosts = {_REMOTE.fullmatch(s).group(1) for s in remote_srcs}  # type: ignore[union-attr]
            if len(hosts) != 1 or len(remote_srcs) != len(srcs):
                out.write("copy refused: a pull takes sources from one remote only\n")
                return 2
            return _pull(hosts.pop(), remote_srcs, dst, cwd, cfg, san, dry_run, env, out,
                         cancelled)
        cmd = rsync_command(args, dry_run)
        if cmd is None:
            if any(os.path.isdir(os.path.join(cwd, os.path.expanduser(a))) for a in srcs):
                # only rsync leaves `.claude` folders out
                out.write("copy refused: rsync is not installed; a folder is copied only with "
                          "rsync (install it, or copy single files)\n")
                return 2
            cp = system_program("cp") or "/bin/cp"
            cmd = [system_program("true") or "/usr/bin/true"] if dry_run else \
                [cp, "-R", "-n", "--"] + list(args)
        mkdir: List[str] = []
        if not dry_run:
            # make the destination folder first (Linux rsync has no --mkpath): its own step, in
            # the same profile and write place as the copy, which runs only when it succeeded
            folder = dst if (dst.endswith("/") or len(srcs) > 1) else (os.path.dirname(dst) or ".")
            mkdir = ["/bin/mkdir", "-p", "--", folder]
        # a local copy writes only at its destination (inside a protected root), with no
        # network, and reads no credential
        place, why = dest_place(dst, cwd, cfg)
        if why:
            out.write(f"copy refused: {why}\n")
            return 2
        why = holds_claude(srcs, cwd)
        if why:
            out.write(f"copy refused: {why}\n")
            return 2
        if any(os.path.islink(os.path.join(cwd, os.path.expanduser(a.rstrip("/")))) for a in srcs) \
                or _holds_links(srcs, cwd):
            out.write("copy: links in the sources are not copied (only files and folders)\n")
        if type_clash(srcs, dst, cwd):
            out.write("copy refused: something at the destination has another type than what "
                      "would be copied there (a folder over a file, or a link); nothing was "
                      "copied\n")
            return 2
        steps = ([(mkdir, "copy (make the folder)")] if mkdir else []) + \
            [(cmd, "copy (dry run, nothing copied)" if dry_run else "copy")]
        for step, label in steps:
            code = run.run_confined(step, cfg, san, [place], False, out, label=label, env=env,
                                    cwd=cwd, cancelled=cancelled,
                                    deny_read=run.gateway_hidden(cfg))
            if code != 0:
                return code
        return 0
    except confine.ConfineError as exc:
        out.write(f"copy refused: {exc}\n")
        return 3
    except Exception as exc:  # noqa: BLE001 - never print a traceback (it can name paths)
        out.write(f"copy failed ({type(exc).__name__})\n")
        return 3


def _push(srcs: Sequence[str], dst: str, cwd: str, cfg: config.Config, san: Sanitizer,
          dry_run: bool, env: Dict[str, str], out: TextIO,
          cancelled: Callable[[], bool]) -> int:
    """A push: the broker reads the checked sources itself (no link followed) and streams them
    into `tar -x` on the remote."""
    from phiward import run, remote as rmt
    m = _REMOTE.fullmatch(dst)
    assert m is not None  # plan() checked it
    host, path = m.group(1), os.path.normpath(m.group(2))
    limit = cfg.push_limit_gib << 30
    # resolved once, here, and checked here: plan()'s check came earlier, and a link put on a
    # path since then must not change what is sent
    sources = rmt.resolve(srcs, cwd)
    hidden = paths.ProtectedSet(run.gateway_hidden(cfg), [])
    if any(hidden.relation(s.path) in (paths.INSIDE, paths.ABOVE) for s in sources):
        out.write("copy refused: a source is or holds a credential or a trace that no copy may "
                  "read\n")
        return 2
    if any(s.path == "/" or any(s.path == n or s.path.startswith(n + "/") for n in rmt.NOT_FILES)
           for s in sources):
        out.write("copy refused: a source is in /dev, /proc or /sys (or is /)\n")
        return 2
    try:
        counts = rmt.survey(sources, limit)
    except rmt.PushError as exc:
        out.write(f"copy refused: {exc}\n")
        return 2
    except OSError:
        out.write("copy refused: a source is not a plain file or folder reached without a link\n")
        return 2
    if dry_run:
        out.write(f"copy (dry run): would send files={counts.files} folders={counts.folders} "
                  f"skipped={counts.skipped} (links, special files and files with a second "
                  "name are not sent)\n")
        return 0
    rt, why = rmt.route(cfg, host)
    if rt is None:
        out.write(f"copy refused: {why}\n")
        return 2
    run.add_remote_roots(san, cfg)
    sent = rmt.Counts()
    cmd = rt.ssh + [host, "--", rmt.receive_script(path)]
    code = run.run_confined(cmd, cfg, san, [], rt.net, out, label="copy", env=env, cwd=cwd,
                            cancelled=cancelled, deny_read=rt.deny_read, socket=rt.socket,
                            allow_read=rt.allow_read,
                            stdin_feed=rmt.feeder(sources, limit, sent))
    if code == 0:
        out.write(f"copy sent: files={sent.files} folders={sent.folders} "
                  f"skipped={sent.skipped}\n")
    else:
        out.write("copy failed: nothing is known to have arrived (see the line above)\n")
    return code


def _pull(host: str, remote_srcs: Sequence[str], dst: str, cwd: str, cfg: config.Config,
          san: Sanitizer, dry_run: bool, env: Dict[str, str], out: TextIO,
          cancelled: Callable[[], bool]) -> int:
    """A pull: `ssh HOST tar -c` (through the shared connection, no credential, no network but
    its socket) streams into phiward's extractor (`tar_extract.py`), which runs in the gateway profile: it writes only
    at its destination inside a protected path, reads no credential, and has no network at
    all. Only the system
    ssh touches the socket."""
    import shutil
    import tempfile
    from phiward import confine, run, remote as rmt
    dest = os.path.normpath(os.path.join(cwd, os.path.expanduser(dst)))
    place, why = dest_place(dst, cwd, cfg)
    if why:
        out.write(f"copy refused: {why}\n")
        return 2
    if dry_run:
        out.write(f"copy (dry run): would pull {len(remote_srcs)} source(s) from the remote\n")
        return 0
    mkdir, tar = system_program("mkdir"), system_program("tar")
    if mkdir is None or tar is None:
        out.write("copy refused: a pull needs mkdir and tar in a system folder\n")
        return 2
    rt, why = rmt.route(cfg, host)
    if rt is None:
        out.write(f"copy refused: {why}\n")
        return 2
    run.add_remote_roots(san, cfg)
    os.makedirs(cfg.cache_dir, mode=0o700, exist_ok=True)
    code = 0
    for spec in remote_srcs:
        m = _REMOTE.fullmatch(spec)
        assert m is not None
        scratch = tempfile.mkdtemp(prefix="pull-", dir=cfg.cache_dir)
        argv: List[str] = []
        try:
            argv, fds = confine.gateway_command(
                rt.ssh + [host, "--", rmt.send_script(m.group(2))], [os.path.realpath(scratch)],
                [], rt.net, deny_read=rt.deny_read, socket=rt.socket, allow_read=rt.allow_read)
            errs: List[str] = []
            try:
                ssh = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=dict(env, TMPDIR=scratch),
                                       cwd="/", start_new_session=True, close_fds=True,
                                       pass_fds=fds)
            finally:
                for fd in fds:
                    os.close(fd)

            def read_errors(ssh: subprocess.Popen = ssh, errs: List[str] = errs) -> None:
                assert ssh.stderr is not None
                for raw in iter(lambda: ssh.stderr.readline(65536), b""):
                    if len(errs) < 50:
                        errs.append(raw.decode("utf-8", "replace").rstrip("\r\n"))

            import threading
            t = threading.Thread(target=read_errors, daemon=True)
            t.start()

            # the stream, from ssh's output into the extractor
            def relay(stdin, ssh: subprocess.Popen = ssh) -> None:
                assert ssh.stdout is not None
                shutil.copyfileobj(ssh.stdout, stdin, 1 << 20)

            extract = [sys.executable, "-I", rmt.EXTRACTOR, dest]
            try:
                c = run.run_confined(extract, cfg, san, [place], False, out, label="copy",
                                     env=dict(env, PATH="/usr/bin:/bin"), cwd=cwd,
                                     cancelled=cancelled, deny_read=run.gateway_hidden(cfg),
                                     stdin_feed=relay, quiet=True)
            finally:
                # the extraction ended (done, refused a write, cancelled): ssh must not wait on
                # a pipe nobody reads. It is our own child, in its own
                # session: its process group is ours to end
                try:
                    ssh.stdout.close()  # type: ignore[union-attr]
                except OSError:
                    pass
                try:
                    r = ssh.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    import signal
                    try:
                        os.killpg(ssh.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    r = ssh.wait()
            t.join(timeout=10)
            if errs:
                # the remote tar names members relative to the pulled folder; no count either
                out.write("copy: message lines from the remote withheld (they can name files)\n")
            raw = code or c or r
            run._log(f"pull: exit {raw}")
            code = 0 if raw == 0 else 1  # the agent sees success or failure only
        finally:
            confine.release_profile(argv)
            safeio.remove_tree(scratch)
    return code


def main(argv: List[str], out: Optional[TextIO] = None) -> int:
    """The client: the request goes to the broker, which runs it outside the agent's sandbox."""
    out = sys.stdout if out is None else out  # the stdout of the call, not of the import
    if argv[:1] in (["-h"], ["--help"]):
        out.write(HELP)
        return 0
    from phiward import broker
    return broker.client("copy", list(argv), out)
