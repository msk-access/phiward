"""`phiward broker`: the only process that starts gateway commands.

The broker runs in the operator's terminal, outside every sandbox. `phiward run ...` and
`phiward copy ...` are clients only: they run inside the agent's sandbox, leave a request
in the spool folder, and print the output that the broker writes back. No shell outside the
sandbox ever reads a gateway command; the broker gets argv.

The spool (`$PHIWARD_SPOOL`, else `~/.phiward-spool`) is writable by the agent, so the
broker treats everything in it as untrusted data:
- it opens the folder once (no symlink, owned by the user, mode 0700) and works through that
  descriptor; if the path stops naming that folder, it stops;
- it reads a request only as a regular file with one link, owned by the user, opened without
  following a link and without blocking, and of bounded size;
- it creates each file it writes with O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600, so a planted link
  or file makes it skip the request, never write through it;
- it runs argv with no shell, in the gateway profile, in a new session with no terminal. The
  command's environment is not the request's: the broker builds it from a short allow list of
  its own variables (PATH, HOME, USER, LOGNAME, LANG, LC_*, TZ, TERM), so variables such as
  `BASH_ENV`, `RSYNC_RSH` or `LD_PRELOAD` cannot change what an approved command runs.

The broker also writes a status file, `~/.phiward/broker.json` (outside the spool; the
agent may not write it): the user config, cache folder, roots and patterns that it uses. It
writes it again when they change, and removes it when it stops. `doctor` reports a difference
from the agent's own view (the spool too). A reader uses it only while the heartbeat is fresh.

Files: the client writes `req-<id>.json` (through a temporary name and a rename); the broker
claims it by renaming it to `job-<id>.json`, writes the sanitized output to `out-<id>.log`, then
`done-<id>.json` ({"exit": N}). The client writes `cancel-<id>` to stop a command. The broker
touches `broker.alive` every second; a client that sees no fresh heartbeat says so and exits 3.
At most `QUEUE_PER_JOB` requests per worker wait; past that a request is refused ("busy"). A
request cancelled while it waits never starts.

Nothing asks the operator at run time: any prompt on the operator's
screen or terminal is in reach of the agent's code. Grants come from the user config
(`[broker] write_to`, `[broker] net`, `[copy] remotes`), which the operator writes ahead of time,
for example with `phiward setup`.

usage:
  phiward broker [--max-jobs N]
  phiward broker --service [--write]
"""

import errno
import json
import os
import queue
import re
import secrets
import signal
import stat
import sys
import threading
import time
from typing import Any, Dict, List, Optional, TextIO

from phiward import config, safeio

USAGE = ("usage: phiward broker [--max-jobs N]\n"
         "       phiward broker --service [--write]\n")
HELP = USAGE + """
Options:
  --max-jobs N   run at most N gateway commands at the same time (default 4)
  --service      print the login service for the broker, and the command that loads it
  --write        with --service: write the service file, then print the commands that load
                 it and remove it
  -h, --help     show this help

The broker runs the gateway commands (`phiward run`, `phiward copy`) outside the agent's
sandbox, with the grants of your user config. The `phiward run` and `phiward copy` that the
agent types are only clients: they leave a request in the spool and print the masked output
that the broker writes back. Without a running broker they fail.

Start the broker yourself, outside every agent tool. Either keep it running in a terminal of
its own (`phiward broker`), or install it once as a login service.

The login service:
- On macOS it is a LaunchAgent (~/Library/LaunchAgents/org.phiward.broker.plist). On Linux it
  is a systemd user unit (~/.config/systemd/user/phiward-broker.service).
- It starts at login, and starts again if it stops. Its log is in ~/Library/Logs/phiward (macOS)
  or ~/.local/state/phiward (Linux), which no agent session can read. `phiward doctor` shows
  whether the broker runs.
- `--service` without `--write` prints the file and the command that loads it. It writes
  nothing.
- `--service --write` writes the file. In your own terminal it then loads the service, or
  restarts it when it runs already (launchctl or systemctl --user); without a terminal it only
  prints those commands.
- The service gets the PATH of the terminal you install it from (only folders that no one
  else can write). Install it from a terminal where your tools are found, and again after
  your PATH changes.
- Without a terminal, it refuses when PHIWARD_CONFIG, PHIWARD_SPOOL, XDG_CONFIG_HOME or
  XDG_CACHE_HOME is set.

Nothing asks you at run time. The grants come from the user config (`[broker] write_to`,
`[broker] net`, `[copy] remotes`), which you write ahead of time, for example with
`phiward setup`.
"""
HEARTBEAT = 1.0  # seconds between touches of broker.alive
STALE = 10.0  # a heartbeat older than this means no broker
MAX_REQUEST = 256 * 1024  # bytes
MAX_ARGS = 4096
QUEUE_PER_JOB = 8  # waiting requests per worker; past this, "busy"
STATUS_SECONDS = 2.0  # how often the broker checks whether its status changed
GC_SECONDS = 3600  # leftover files older than this are removed
_ID = r"[0-9a-f]{16,64}"
_REQ = re.compile(rf"req-({_ID})\.json")
_LEFTOVER = re.compile(rf"(?:job|out|done|cancel|\.tmp)-{_ID}(?:\.json|\.log)?")
_ENV_KEEP = re.compile(r"(?:PATH|HOME|USER|LOGNAME|LANG|LC_[A-Z]+|TZ|TERM)")

class SpoolError(Exception):
    pass


# ---- shared ------------------------------------------------------------------------------------

def _wait_seconds(env: Dict[str, str]) -> float:
    try:
        return max(0.5, float(env.get("PHIWARD_BROKER_WAIT", "10")))
    except ValueError:
        return 10.0


def _alive(spool: str) -> bool:
    try:
        st = os.lstat(os.path.join(spool, "broker.alive"))
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and time.time() - st.st_mtime < STALE


# ---- the client (inside the agent's sandbox) ---------------------------------------------------

NO_BROKER = ("{name} refused: no phiward broker is running. The operator starts one with "
             "`phiward broker` in a terminal outside the agent (or its login service: "
             "`(cd ~ && phiward broker --service --write)`).\n")
OTHER_SPOOL = ("{name} refused: the broker runs with the spool {other}, and this shell uses "
               "{spool} (an older phiward used {other}). Ask the operator to restart the broker "
               "(`phiward broker`, or its login service).\n")


def _no_broker(name: str, spool: str) -> str:
    """Why a request was not taken: no broker, or one that runs on another spool (an older
    phiward's, before the spool moved out of ~/.phiward)."""
    other = other_spool(spool)
    if other:
        return OTHER_SPOOL.format(name=name, other=other, spool=spool)
    return NO_BROKER.format(name=name)


def client(name: str, args: List[str], out: TextIO = sys.stdout,
           env: Optional[Dict[str, str]] = None) -> int:
    """Send `phiward <name> <args>` to the broker and print what it writes back."""
    env = dict(os.environ if env is None else env)
    spool = config.spool_dir(env)
    if not _alive(spool):
        out.write(_no_broker(name, spool))
        return 3
    rid = secrets.token_hex(16)
    # no environment: the broker builds the command's environment itself
    body = {"v": 1, "cmd": name, "args": args, "cwd": os.getcwd(), "env": {}}
    tmp = os.path.join(spool, f".tmp-{rid}")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(body, fh)
        os.rename(tmp, os.path.join(spool, f"req-{rid}.json"))
    except OSError:
        out.write(f"{name} refused: the request could not be written to the broker's spool "
                  "folder (is it writable from the agent's sandbox?)\n")
        return 3
    req, outp = os.path.join(spool, f"req-{rid}.json"), os.path.join(spool, f"out-{rid}.log")
    done = os.path.join(spool, f"done-{rid}.json")
    try:
        return _follow(name, spool, req, outp, done, out, _wait_seconds(env))
    except KeyboardInterrupt:
        _touch(os.path.join(spool, f"cancel-{rid}"))
        out.write(f"{name} stopped: cancelled\n")
        return 130
    finally:
        for p in (req, outp, done):
            try:
                os.unlink(p)
            except OSError:
                pass


def _touch(path: str) -> None:
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600))
    except OSError:
        pass


class _NotPlain(Exception):
    pass


def _printable(raw: bytes) -> str:
    """A reply line as the client prints it: control characters (terminal escapes) dropped. The
    spool is the agent's, so a forged reply must not steer the operator's terminal."""
    text = raw.decode("utf-8", "replace")
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", text)


def _open_plain(path: str):
    """The broker's output or result file, opened without following a link, and only a plain
    file of this user with one name. The spool is in the agent's reach: a link planted there
    would make a client that runs outside the sandbox (the MCP server) read any file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid():
        os.close(fd)
        raise _NotPlain(path)
    return os.fdopen(fd, "rb")


def _follow(name: str, spool: str, req: str, outp: str, done: str, out: TextIO,
            wait: float) -> int:
    try:
        return _follow_plain(name, spool, req, outp, done, out, wait)
    except (_NotPlain, OSError):
        out.write(f"{name} refused: the broker's reply in the spool is not a plain file of "
                  "yours (something put a link or another file there); nothing is shown\n")
        return 3


def _follow_plain(name: str, spool: str, req: str, outp: str, done: str,
                  out: TextIO, wait: float) -> int:
    t0 = time.time()
    pos = 0
    pending = b""
    fh = None
    while True:
        finished = os.path.lexists(done)
        if fh is None and os.path.lexists(outp):
            fh = _open_plain(outp)
        if fh is not None:
            fh.seek(pos)
            chunk = fh.read()
            pos += len(chunk)
            pending += chunk
            *lines, pending = pending.split(b"\n")
            for line in lines:
                out.write(_printable(line) + "\n")
            out.flush()
        if finished:
            if pending:
                out.write(_printable(pending) + "\n")
            try:
                with _open_plain(done) as d:
                    code = json.loads(d.read(4096).decode("utf-8")).get("exit")
                return code if isinstance(code, int) else 3
            except (ValueError, AttributeError, UnicodeDecodeError):
                return 3
        if os.path.exists(req) and time.time() - t0 > wait:
            try:
                os.unlink(req)  # not claimed: take it back, so it never runs later
            except OSError:
                pass
            else:
                out.write(_no_broker(name, spool))
                return 3
        if not _alive(spool):
            out.write(f"{name} stopped: the broker stopped before the command finished\n")
            return 3
        time.sleep(0.05)


# ---- the broker (outside every sandbox) --------------------------------------------------------

class Spool:
    """The spool folder, opened once and used only through its descriptor."""

    def __init__(self, path: str):
        self.path = path
        parent = os.path.dirname(path)
        try:
            os.makedirs(parent, mode=0o700, exist_ok=True)
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise SpoolError(f"the spool folder cannot be made ({type(exc).__name__})")
        try:
            self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            raise SpoolError(f"the spool folder cannot be opened as a plain folder "
                             f"({type(exc).__name__})")
        st = os.fstat(self.fd)
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            os.close(self.fd)
            raise SpoolError("the spool folder must belong to you and have mode 0700")
        self.ident = (st.st_dev, st.st_ino)

    def still_here(self) -> bool:
        try:
            st = os.lstat(self.path)
        except OSError:
            return False
        return stat.S_ISDIR(st.st_mode) and (st.st_dev, st.st_ino) == self.ident

    def names(self) -> List[str]:
        return os.listdir(self.fd)

    def create(self, name: str) -> int:
        """A new file for writing; never an existing file or a link (raises OSError)."""
        return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                       dir_fd=self.fd)

    def write_new(self, name: str, data: bytes) -> None:
        """`name` with `data`, through a new temporary file and a rename."""
        tmp = f".tmp-{secrets.token_hex(16)}"
        fd = self.create(tmp)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.rename(tmp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)

    def unlink(self, name: str) -> None:
        try:
            os.unlink(name, dir_fd=self.fd)
        except OSError:
            pass

    def exists(self, name: str) -> bool:
        try:
            os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            return True
        except OSError:
            return False

    def read_request(self, name: str) -> Dict[str, Any]:
        """The request in `name`, checked; raises SpoolError."""
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except OSError:
            raise SpoolError("not a plain file")
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid():
                raise SpoolError("not a plain file with one link")
            if st.st_size > MAX_REQUEST:
                raise SpoolError("too large")
            data = os.read(fd, MAX_REQUEST + 1)
        finally:
            os.close(fd)
        if len(data) > MAX_REQUEST:
            raise SpoolError("too large")
        try:
            body = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise SpoolError("not JSON")
        return check_request(body)

    def heartbeat(self) -> None:
        try:
            # O_NONBLOCK: a FIFO planted under this name fails at once (ENXIO) instead of
            # blocking the main loop
            fd = os.open("broker.alive", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=self.fd)
        except OSError:
            self.unlink("broker.alive")  # not a plain file: remove it; the next beat makes one
            return
        try:
            if stat.S_ISREG(os.fstat(fd).st_mode):
                os.utime(fd)
        finally:
            os.close(fd)

    def collect_garbage(self) -> None:
        now = time.time()
        for name in self.names():
            if not _LEFTOVER.fullmatch(name) and not _REQ.fullmatch(name):
                continue
            try:
                st = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            except OSError:
                continue
            if now - st.st_mtime > GC_SECONDS:
                self.unlink(name)


def _plain_words(v: Any, limit: int) -> bool:
    return isinstance(v, list) and len(v) <= limit and all(
        isinstance(w, str) and "\0" not in w for w in v)


def check_request(body: Any) -> Dict[str, Any]:
    if not isinstance(body, dict) or body.get("v") != 1:
        raise SpoolError("unknown request version")
    if body.get("cmd") not in ("run", "copy"):
        raise SpoolError("unknown command")
    if not _plain_words(body.get("args"), MAX_ARGS):
        raise SpoolError("bad arguments")
    cwd = body.get("cwd")
    if not isinstance(cwd, str) or not os.path.isabs(cwd) or "\0" in cwd or \
            not os.path.isdir(cwd):
        raise SpoolError("bad working folder")
    env = body.get("env")
    if not isinstance(env, dict) or not all(
            isinstance(k, str) and isinstance(v, str) and "\0" not in k + v and "=" not in k and k
            for k, v in env.items()):
        raise SpoolError("bad environment")
    return body


def command_env(env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """The command's environment: the allow-listed variables of the broker's own environment.
    The request's environment is never used."""
    env = os.environ if env is None else env
    out = {k: v for k, v in env.items() if _ENV_KEEP.fullmatch(k)}
    if "PATH" in out:
        # the same PATH filter as the login service: a relative entry, a folder others can
        # write or one inside a project would let the agent choose the program that runs
        from phiward import service
        out["PATH"] = ":".join(service._safe_path_entries(out["PATH"])) or "/usr/bin:/bin"
    return out


# the most files a listed folder may hold (with its subfolders): a larger one is never approved
FOLDER_LIMIT = 2000


def program_path() -> str:
    """The PATH on which listed programs are found: the running broker's own (from its status
    file), so `pin` and `doctor` in the operator's terminal see what the broker sees; else this
    process's command PATH."""
    st = read_status()
    p = st.get("path") if isinstance(st, dict) else None
    return p if isinstance(p, str) and p else command_env().get("PATH", "")


def _folder_files(folder: str) -> List[str]:
    """Every file in a listed folder and its subfolders (a script's helpers live there), or a
    marker when it holds more than FOLDER_LIMIT, which is never approved."""
    out: List[str] = []
    for top, dirs, files in os.walk(folder, followlinks=False):
        dirs.sort()
        for n in sorted(files):
            out.append(os.path.join(top, n))
            if len(out) > FOLDER_LIMIT:
                return [f"too-many:{folder}"]
    return out


def listed_programs(cfg: "config.Config", path: str) -> List[str]:
    """The files `[broker] commands` allows, as the broker would find them now: a bare name on
    `path`, a path entry itself, every program in a folder entry."""
    import shutil
    out: List[str] = []
    for lst in cfg.command_lists:
        for entry in lst:
            if entry.startswith("@"):
                names = list(config.COMMAND_PRESETS.get(entry[1:], ()))
            else:
                names = [entry]
            for e in names:
                if "/" in e:
                    p = os.path.realpath(os.path.expanduser(e))
                    if os.path.isdir(p):
                        out += _folder_files(p)
                    elif p != os.path.normpath(os.path.expanduser(e)):
                        # a path entry with a link on it lists nothing (run.py): say so
                        out.append(f"linked:{e}")
                    else:
                        out.append(p)
                else:
                    found = shutil.which(e, path=path)
                    out.append(os.path.realpath(found) if found else f"missing:{e}")
    return out


def config_print() -> str:
    """A fingerprint of what decides what the gateway may do and what it masks: the user config,
    the pins, and the names and pack files the config names. Content and resolved place only
    (an editor's same-content save, or `phiward setup` writing the same text, changes nothing).
    The broker takes it at start and refuses requests when it changes, so a change that the
    agent manages to make has no effect until the operator restarts the broker."""
    import hashlib
    from phiward import pin
    h = hashlib.sha256()
    files = [config.user_config_path(), pin.pins_path()]
    cfg = None
    try:
        cfg = config.load("/")
        files += list(cfg.names_from) + [p for p in cfg.packs if "/" in p]
    except Exception:  # noqa: BLE001 - a config that cannot be loaded is fingerprinted as text
        pass
    for path in files:
        real = os.path.realpath(os.path.expanduser(path))
        h.update(real.encode("utf-8", "surrogateescape") + b"\0")
        try:
            with open(real, "rb") as fh:
                h.update(hashlib.sha256(fh.read(1 << 24)).digest())
        except OSError as exc:
            h.update(f"missing:{exc.errno}".encode())
    # the programs `[broker] commands` allows, as found on the command PATH, by identity: a
    # program replaced or rewritten (its inode or change time, which no one can set back), or a
    # new one of a listed name earlier on PATH, stops the broker until the operator restarts it
    try:
        progs = listed_programs(cfg, command_env().get("PATH", "")) if cfg else []
    except Exception:  # noqa: BLE001
        progs = ["unreadable"]
    for prog in progs:
        h.update(prog.encode("utf-8", "surrogateescape") + b"\0")
        try:
            st = os.stat(prog)
            h.update(f"{st.st_dev}:{st.st_ino}:{st.st_size}:{st.st_ctime_ns}".encode())
        except OSError as exc:
            h.update(f"missing:{exc.errno}".encode())
    return h.hexdigest()


def restart_hint() -> str:
    if sys.platform == "darwin":
        return ("`launchctl kickstart -k gui/$(id -u)/org.phiward.broker` for the login service, "
                "or stop `phiward broker` and start it again")
    return ("`systemctl --user restart phiward-broker.service` for the login service, or stop "
            "`phiward broker` and start it again")


class Broker:
    def __init__(self, spool: Spool, log: TextIO, max_jobs: int = 4):
        self.spool, self.log = spool, log
        self.config_print = config_print()
        # listed programs must match what the operator approved (`phiward pin`): a program
        # replaced while the broker was stopped is not accepted by a restart
        try:
            from phiward import pin
            # on this broker's own PATH (another broker's status file names its own)
            self.unapproved = pin.unapproved(config.load("/"),
                                             path=command_env().get("PATH", ""))
        except Exception:  # noqa: BLE001 - when in doubt, nothing runs
            self.unapproved = ["unreadable"]
        # claimed jobs wait here for one of `max_jobs` workers; the main loop never blocks, so
        # the heartbeat goes on while every worker is busy
        self.jobs: queue.Queue[Any] = queue.Queue()
        self.max_jobs = max_jobs
        self.stop = threading.Event()

    def say(self, msg: str) -> None:
        self.log.write(f"[broker {time.strftime('%H:%M:%S')}] {msg}\n")
        self.log.flush()

    def serve(self) -> int:
        last_gc = last_beat = last_status = 0.0
        from phiward import run as run_mod
        # the scratch folders' place, made now: Claude Code's sandbox (Linux) puts a read-only
        # file at a denied path that does not exist while a command runs, and the cache folder
        # is denied, so a first `phiward run` from a session would find a file there
        try:
            os.makedirs(config.cache_dir(), mode=0o700, exist_ok=True)
        except OSError:
            self.say("the cache folder cannot be made; gateway commands fail until it can")
        if run_mod.sweep_scratch(config.cache_dir()):
            self.say("removed scratch folders an earlier broker left")
        from phiward import confine
        if confine.prune_profiles():
            self.say("removed profile files an earlier broker left")
        status = write_status()
        for _ in range(self.max_jobs):
            threading.Thread(target=self.worker, daemon=True).start()
        if self.unapproved:
            self.say(f"ready, but {len(self.unapproved)} listed program(s) are not approved: "
                     "every request is refused until `phiward pin` and a restart")
        else:
            self.say("ready; requests are read from the spool folder")
        while not self.stop.is_set():
            if not self.spool.still_here():
                self.say("the spool folder was moved or replaced; stopping")
                return 3
            if time.time() - last_beat >= HEARTBEAT:
                self.spool.heartbeat()
                last_beat = time.time()
            if time.time() - last_status >= STATUS_SECONDS:
                status = write_status(status)
                last_status = time.time()
            if time.time() - last_gc > 60:
                self.spool.collect_garbage()
                last_gc = time.time()
            for name in self.spool.names():
                m = _REQ.fullmatch(name)
                if m:
                    self.claim(m.group(1), name)
            self.stop.wait(0.05)
        return 0

    def claim(self, rid: str, name: str) -> None:
        """Take a request and queue it. Nothing here reads the request's content or touches its
        folder, so the main loop (and the heartbeat) never waits on it; every
        refusal from here on ends with a done file, so the client never waits forever."""
        job = f"job-{rid}.json"
        if self.spool.exists(job):
            self.spool.unlink(name)
            return
        try:
            os.rename(name, job, src_dir_fd=self.spool.fd, dst_dir_fd=self.spool.fd)
        except OSError:
            return
        try:
            outfd = self.spool.create(f"out-{rid}.log")
        except OSError:
            self.say(f"request {rid[:8]} refused: its output file already exists")
            self.finish(rid, 3)
            return
        if self.jobs.qsize() >= self.max_jobs * QUEUE_PER_JOB:
            self.say(f"request {rid[:8]} refused: busy")
            with os.fdopen(outfd, "w", encoding="utf-8") as out:
                out.write("refused: the broker is busy (too many requests wait); try again "
                          "later\n")
            self.finish(rid, 3)
            return
        self.jobs.put((rid, outfd))

    def worker(self) -> None:
        while True:
            self.run_job(*self.jobs.get())

    def finish(self, rid: str, code: int) -> None:
        try:
            self.spool.write_new(f"done-{rid}.json", json.dumps({"exit": code}).encode())
        except OSError:
            self.say(f"request {rid[:8]}: the done file could not be written")
        self.spool.unlink(f"job-{rid}.json")

    def run_job(self, rid: str, outfd: int) -> None:
        code = 3
        try:
            with os.fdopen(outfd, "w", encoding="utf-8", errors="replace") as out:
                try:
                    body = self.spool.read_request(f"job-{rid}.json")
                    # the request holds the client's words (globs expanded by a shell that is
                    # not sandboxed): not left in the spool, which the agent can read
                    self.spool.unlink(f"job-{rid}.json")
                except SpoolError as exc:
                    self.say(f"request {rid[:8]} refused: {exc}")
                    out.write(f"refused: the broker cannot use this request ({exc})\n")
                    return
                if self.spool.exists(f"cancel-{rid}"):  # cancelled while it waited
                    out.write(f"{body['cmd']} stopped: cancelled before it started\n")
                    code = 130
                else:
                    code = self.execute(rid, body, out)
        except Exception as exc:  # noqa: BLE001 - one bad job never stops the broker
            self.say(f"request {rid[:8]} failed ({type(exc).__name__})")
        finally:
            self.finish(rid, code)

    def execute(self, rid: str, body: Dict[str, Any], out: TextIO) -> int:
        cancelled = lambda: self.spool.exists(f"cancel-{rid}")  # noqa: E731
        if self.unapproved:
            self.say(f"request {rid[:8]} refused: {len(self.unapproved)} listed program(s) "
                     "not approved")
            out.write(f"refused: {len(self.unapproved)} program(s) of [broker] commands differ "
                      "from what the operator approved, or were never approved. The operator "
                      "runs `phiward doctor`, which names them, checks them, runs `phiward pin` "
                      f"in their own terminal, and restarts the broker: {restart_hint()}.\n")
            return 3
        if config_print() != self.config_print:
            self.say(f"request {rid[:8]} refused: the config changed since the broker started")
            out.write("refused: the phiward config changed since the broker started. The "
                      "operator reads the change and restarts the broker: "
                      f"{restart_hint()}.\n")
            return 3
        env = command_env()
        self.say(f"request {rid[:8]}: {body['cmd']} ({len(body['args'])} words)")
        from phiward import run
        run.log.fn = lambda msg: self.say(f"request {rid[:8]}: {msg}")
        try:
            if body["cmd"] == "run":
                code = run.execute(body["args"], body["cwd"], env, out, cancelled)
            else:
                from phiward import copying
                code = copying.execute(body["args"], body["cwd"], env, out, cancelled)
        finally:
            run.log.fn = None
        self.say(f"request {rid[:8]}: reported exit {code}")
        return code


def _status() -> Dict[str, Any]:
    cfg = config.load("/")
    import socket as _socket
    from phiward import procinfo
    me = procinfo.info(os.getpid())
    return {"v": 1, "pid": os.getpid(), "start": me[1] if me else None,
            "host": _socket.gethostname(), "config": config.user_config_path(), "cache": config.cache_dir(),
            "spool": config.spool_dir(),
            "roots": cfg.user_roots, "patterns": cfg.user_patterns,
            "path": command_env().get("PATH", "")}


def write_status(last: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Write the status file when it differs from `last`; return what is in force."""
    status = _status()
    if status == last:
        return status
    path = config.status_path()
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        safeio.write_new(path, json.dumps(status))
    except OSError:
        pass
    return status


def remove_status() -> None:
    try:
        os.unlink(config.status_path())
    except OSError:
        pass


def running(spool: Optional[str] = None) -> str:
    """Whether a broker serves `spool`, for doctor and pin (not the client, whose sandbox may not
    see the broker's process): "here" when the guarded status file names a live process of this
    machine with the start time it wrote, "on HOST" when it names another machine (a shared home
    folder on a cluster: there only the heartbeat can tell), "" otherwise. The heartbeat alone
    is in the spool, which the agent writes, so it is not enough."""
    if not _alive(spool or config.spool_dir()):
        return ""
    st = _read_status_file()
    import socket as _socket
    from phiward import procinfo
    pid, start, host = st.get("pid"), st.get("start"), st.get("host")
    if isinstance(host, str) and host and host != _socket.gethostname():
        return f"on {host}"
    if not isinstance(pid, int) or isinstance(pid, bool):
        return ""
    got = procinfo.info(pid)
    return "here" if got is not None and got[1] == start else ""


def read_status(spool: Optional[str] = None) -> Dict[str, Any]:
    """What the running broker wrote about itself, or {} when no broker runs (`running`). A
    reader may only use it to add protection."""
    if not running(spool):
        return {}
    return _read_status_file()


def other_spool(spool: str) -> Optional[str]:
    """The spool of a broker that runs with another spool than `spool`, or None. Only to say
    where the broker is (`doctor`, a refused request): nothing else is taken from the file."""
    other = _read_status_file().get("spool")
    if other and os.path.abspath(other) != os.path.abspath(spool) and _alive(other):
        return other
    return None


def _read_status_file() -> Dict[str, Any]:
    try:
        fd = os.open(config.status_path(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return {}
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return {}
        private = st.st_uid == os.getuid() and not st.st_mode & 0o077
        data = json.loads(os.read(fd, MAX_REQUEST).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {}
    finally:
        os.close(fd)
    if not isinstance(data, dict):
        return {}
    out: Dict[str, Any] = {}
    for key in ("config", "cache", "spool"):
        if isinstance(data.get(key), str) and os.path.isabs(data[key]):
            out[key] = data[key]
    if isinstance(data.get("path"), str) and private:
        # where the broker finds programs (program_path): only folders no one else can write,
        # and only from the broker's own private file
        from phiward import service
        out["path"] = ":".join(service._safe_path_entries(data["path"]))
    for key in ("roots", "patterns"):
        v = data.get(key)
        out[key] = [x for x in v if isinstance(x, str) and os.path.isabs(x)] if isinstance(v, list) else []
    if private:  # who wrote it (`running`): only from the broker's own private file
        for key, kind in (("pid", int), ("start", int), ("host", str)):
            v = data.get(key)
            if isinstance(v, kind) and not isinstance(v, bool):
                out[key] = v
    return out


def main(argv: List[str]) -> int:
    max_jobs = 4
    if argv[:1] in (["-h"], ["--help"]):
        sys.stdout.write(HELP)
        return 0
    if argv[:1] == ["--service"]:
        from phiward import service
        return service.main(argv[1:])
    if argv[:1] == ["--max-jobs"] and len(argv) == 2 and argv[1].isdigit() and int(argv[1]) > 0:
        max_jobs = int(argv[1])
    elif argv:
        sys.stderr.write(USAGE)
        return 2
    problem = config.load("/").problem
    if problem:
        sys.stderr.write(f"phiward broker: the user config cannot be used: {problem}\n")
        return 3
    try:
        spool = Spool(config.spool_dir())
    except SpoolError as exc:
        sys.stderr.write(f"phiward broker: {exc}\n")
        return 3
    import fcntl
    try:
        lock = os.open("broker.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=spool.fd)
        if not stat.S_ISREG(os.fstat(lock).st_mode):
            raise OSError(errno.EINVAL, "not a plain file")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        busy = exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN)
        sys.stderr.write("phiward broker: " + ("another broker is running\n" if busy else
                         "the lock file cannot be used\n"))
        return 3
    # the login service appends to its log file: keep it from filling the disk
    from phiward import service
    logf = os.path.join(service.log_folder(), "broker.log")
    try:
        if os.path.getsize(logf) > 50 * 1024 * 1024 and not os.path.islink(logf):
            os.truncate(logf, 0)
    except OSError:
        pass
    broker = Broker(spool, sys.stderr, max_jobs)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: broker.stop.set())
    try:
        return broker.serve()
    except KeyboardInterrupt:
        return 0
    finally:
        from phiward import run as run_mod
        run_mod.end_all()  # running requests end with the broker, their scratch removed
        spool.unlink("broker.alive")
        remove_status()
