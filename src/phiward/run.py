"""`phiward run [GRANTS] -- CMD [ARG]...`: the one way to read protected data.

The command the agent types is a client only (broker.py): it sends argv to the broker and
prints what comes back. The broker calls `execute`, which runs CMD in the GATEWAY profile (see
confine.py): it may read the protected roots; it may write only in a private scratch folder
(its TMPDIR) and in the folders granted with `--write-to` (protected roots are read only); it
has no network unless `--net` is given. Its stdin is empty. Everything it
prints, stdout and stderr, goes through the sanitizer, which also masks the name of every entry
under the roots.

Grants (`--write-to DIR`, `--net`) widen what CMD can do. Nothing asks anyone at run time:
the operator writes the grants into the user config ahead of time.
A `--write-to DIR` is resolved once (links followed) and must be one of the `[broker] write_to`
folders or inside one; `--net` needs `[broker] net = true`. The resolved folder is what the
profile gets, and the gateway refuses to start if it is no longer a real folder. The program is
resolved once too: on the operator's PATH, or as a path in the request's folder.

`--remote HOST` runs CMD on an HPC host instead, through the operator's own ssh
setup (`[copy] ssh_config`, the operator's Kerberos ticket and connection): the agent never holds
them. Only hosts in `[remote] hosts` and programs in `[remote] commands` of the user config are
allowed; the program is one bare name, and every word reaches the remote shell quoted. Nothing
confines CMD on the remote side: the list of commands is what limits its effects there. Its
output is masked like local output, plus the paths under `[remote] roots`.
"""

import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import BinaryIO, Callable, Dict, Iterator, List, Optional, Sequence, TextIO, Tuple

from phiward import config, confine, paths, safeio
from phiward.sanitize import (IDCOL, NO_HEADER_NOTE, WITHHELD, _PLACEHOLDER, Columns,
                              Sanitizer, SanitizerError, fmt_n, placeholder_note)

MAX_LINE = 64 * 1024  # bytes; a longer output line is withheld, not held in memory
USAGE = ("usage: phiward run [--write-to DIR]... [--net] [--names-from FILE]... [--table] "
         "-- CMD [ARG]...\n"
         "       phiward run --remote HOST [--names-from FILE]... [--table] -- CMD [ARG]...\n")
HELP = USAGE + """
Options:
  --write-to DIR     let CMD write in DIR. DIR must be one of the `[broker] write_to` folders
                     of the user config, or inside one.
  --net              let CMD use the network (needs `[broker] net = true`)
  --names-from FILE  also mask the names listed in FILE
  --table            read CSV/TSV output by column: cells under an identifier header are
                     masked whole, numbers in other columns are kept; other lines are masked
                     as text. One table per output: the header is the first non-empty line,
                     and it must name an identifier column (else the whole output is text, so
                     a table without one keeps no numbers). The first line that is not a row
                     of it (an empty line, another field count, a quote, no number cell,
                     another header) ends column mode for the rest. A first line that only
                     looks like a header (prose with commas, data printed without its header
                     as by `tail -n +2`) is read as one when it holds an identifier word.
                     Needs `[sanitize] table = true` in the user config.
  --remote HOST      run CMD on an HPC host, through your own ssh setup. HOST must be in
                     `[remote] hosts`, and CMD in `[remote] commands`.
  --                 ends the options; CMD and its arguments follow (required)
  -h, --help         show this help

Run CMD with read access to the protected data, and print its output masked: protected
paths, entry names and identifiers become placeholders. This is the one way to work with
protected data.

The command is only a client. The broker runs CMD outside the agent's sandbox, so a broker
must be running (`phiward broker`). CMD has no shell and an empty stdin. It may write only in a
private temporary folder and in the folders granted with --write-to (protected roots are read
only; a granted folder may sit inside one). It has no network unless --net is granted. Nothing asks anyone at run time: the grants come from the
user config. With `[broker] commands` set, CMD starts in that private folder, not in yours:
give paths in full. Nothing confines CMD on a remote host; the list of programs limits it
there.

Print counts and summaries, not records: masking hides names and identifiers, not other
content. The last lines count the placeholders in the lines shown, and say when no identifier
placeholder was shown in 20 lines or more.
"""


@dataclass
class RunArgs:
    cmd: List[str] = field(default_factory=list)
    write_to: List[str] = field(default_factory=list)
    net: bool = False
    names_from: List[str] = field(default_factory=list)
    table: bool = False
    remote: str = ""

    @property
    def has_grants(self) -> bool:
        return bool(self.write_to or self.net)


def parse(argv: Sequence[str]) -> Optional[RunArgs]:
    """The parsed arguments, or None when they are not exactly the documented form."""
    a = RunArgs()
    i = 0
    while i < len(argv):
        w = argv[i]
        if w == "--":
            a.cmd = list(argv[i + 1:])
            return a if a.cmd else None
        if w == "--net":
            a.net = True
        elif w == "--table":
            a.table = True
        elif w == "--remote" and i + 1 < len(argv) and not a.remote:
            a.remote = argv[i + 1]
            i += 1
        elif w in ("--write-to", "--names-from") and i + 1 < len(argv):
            (a.write_to if w == "--write-to" else a.names_from).append(argv[i + 1])
            i += 1
        else:
            return None
        i += 1
    return None  # no "--": refused, so the hook and the gateway read the same grants


def _never() -> bool:
    return False


# the broker sets `log.fn` for the request its worker thread runs: what the agent must not see
# (a command's real exit status) goes there, to the operator's broker log
log = threading.local()


def _log(msg: str) -> None:
    fn = getattr(log, "fn", None)
    if fn is not None:
        try:
            fn(msg)
        except Exception:  # noqa: BLE001 - a log line never fails a request
            pass


# the requests running now (process group, scratch folder): a broker that stops ends them and
# removes their scratch, which may hold copies of protected data
_RUNNING: Dict[int, str] = {}
_RUNNING_LOCK = threading.Lock()
SCRATCH_PREFIXES = ("run-", "pull-")
# after its command ends, a request reads what is already in the pipe for at most this long: a
# process the command left behind may hold the pipe open, but the request ends with its command
DRAIN_SECONDS = 1.0


def end_all() -> None:
    """The broker stops: end every running request's process group and remove its scratch."""
    with _RUNNING_LOCK:
        running = list(_RUNNING.items())
    for pgid, scratch in running:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass
        safeio.remove_tree(scratch)


def sweep_scratch(cache: str) -> int:
    """At the broker's start: remove scratch folders that an earlier broker left (it was killed,
    or the machine stopped). Folders only, never through a link. How many were removed."""
    n = 0
    try:
        entries = list(os.scandir(cache))
    except OSError:
        return 0
    for e in entries:
        if e.name.startswith(SCRATCH_PREFIXES) and e.is_dir(follow_symlinks=False):
            safeio.remove_tree(e.path)
            n += 1
    return n


def _raw_lines(proc: "subprocess.Popen[bytes]", stop: Callable[[], bool]
               ) -> "Iterator[Tuple[bytes, bool]]":
    """The command's output as (line, too_long): read without blocking, ended when the command
    ends (after DRAIN_SECONDS of what is left), at the end of the pipe, or when `stop()` says so
    (a cancel). A line longer than MAX_LINE is given once as (b"", True) and the rest of it
    dropped."""
    import select
    assert proc.stdout is not None
    fd = proc.stdout.fileno()
    os.set_blocking(fd, False)
    buf, skipping, ended = b"", False, 0.0
    while True:
        if stop():
            return
        if not ended and proc.poll() is not None:
            ended = time.monotonic()
        r, _w, _x = select.select([fd], [], [], 0.05 if ended else 0.2)
        data, eof = b"", False
        if r:
            try:
                data = os.read(fd, 65536)
                eof = data == b""
            except BlockingIOError:
                pass
        if ended and (not r or time.monotonic() - ended > DRAIN_SECONDS):
            eof = True
        buf += data
        while True:
            i = buf.find(b"\n")
            if i == -1:
                if len(buf) > MAX_LINE:
                    if not skipping:
                        yield b"", True
                    skipping, buf = True, b""
                break
            line, buf = buf[:i + 1], buf[i + 1:]
            if skipping:
                skipping = False  # the end of a line too long to hold
                continue
            if len(line) > MAX_LINE + 1:
                yield b"", True
                continue
            yield line, False
        if eof:
            if buf and not skipping:
                yield buf, False
            return


def run_confined(cmd: Sequence[str], cfg: config.Config, san: Sanitizer, write_to: Sequence[str],
                 net: bool, out: TextIO, table: bool = False, label: str = "run",
                 env: Optional[Dict[str, str]] = None, cwd: Optional[str] = None,
                 cancelled: Callable[[], bool] = _never, deny_read: Sequence[str] = (),
                 socket: str = "", allow_read: Sequence[str] = (),
                 stdin_feed: Optional[Callable[[BinaryIO], None]] = None,
                 quiet: bool = False,
                 in_scratch: bool = False,
                 report_placeholders: bool = False) -> int:
    """Run `cmd` in the gateway profile and write its masked output to `out`. `stdin_feed`, when
    given, writes the command's input from the broker (a push's tar stream) in a thread."""
    os.makedirs(cfg.cache_dir, mode=0o700, exist_ok=True)
    scratch = tempfile.mkdtemp(prefix="run-", dir=cfg.cache_dir)
    try:
        # the gateway writes only its scratch folder and the places granted for this request
        # (`write_to`, or a copy's destination): never a protected root or pattern match as
        # such, where it could plant what your own tools run later, or rewrite a names file
        writable = [os.path.realpath(scratch)] + list(write_to)
        argv, fds = confine.gateway_command(list(cmd), writable, [], net,
                                            deny_read=deny_read, socket=socket,
                                            allow_read=allow_read)
        env = dict(os.environ if env is None else env, TMPDIR=scratch)
        if in_scratch:
            # a listed program starts in a folder the agent cannot write: no `.Rprofile` or
            # `./helper` of the agent's runs with it
            cwd = scratch
        if socket:
            cwd = "/"  # a request through the shared connection needs no working folder
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin_feed else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, env=env, cwd=cwd,
                                    start_new_session=True, close_fds=True, pass_fds=fds)
        except OSError:
            out.write(f"{label} failed: the command could not start\n")
            return 127
        finally:
            for fd in fds:
                os.close(fd)
        with _RUNNING_LOCK:
            _RUNNING[proc.pid] = scratch
        done = threading.Event()
        feed_failed: List[str] = []
        if stdin_feed is not None:
            def feed() -> None:
                assert proc.stdin is not None
                try:
                    stdin_feed(proc.stdin)  # type: ignore[misc]
                except Exception as exc:  # noqa: BLE001 - reported as a fixed line, no names
                    feed_failed.append(str(exc) if type(exc).__name__ == "PushError"
                                       else type(exc).__name__)
                finally:
                    try:
                        proc.stdin.close()
                    except OSError:
                        pass
            feeder_thread = threading.Thread(target=feed, daemon=True)
            feeder_thread.start()

        def watch() -> None:
            while not done.wait(0.5):
                if cancelled():
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    return

        threading.Thread(target=watch, daemon=True).start()
        assert proc.stdout is not None
        lines = changed = 0
        last, repeats, shown, withheld = None, 0, 0, 0
        # `--table`: the output read by column, with state for this call only
        cols = Columns(san, cfg.sanitize_id_columns) if table else None
        # the placeholders in the lines the agent is shown, counted where a line is written
        known = san.placeholders() | ({IDCOL} if cols else set())
        counts: Dict[str, int] = {}
        content = held = 0
        cap = max(1, cfg.max_output_lines)
        try:
            for raw, too_long in _raw_lines(proc, cancelled):
                if too_long:
                    # a line too long to hold: the rest of it is dropped, a fixed notice shown
                    if cols:
                        cols.reset()  # its cells are unknown: text until an empty line
                    lines += 1
                    changed += 1
                    if shown >= cap:  # the notice counts as a line too
                        withheld += 1
                        continue
                    out.write("[line withheld by the gateway: longer than "
                              f"{MAX_LINE // 1024} KiB]\n")
                    shown += 1
                    last = None
                    out.flush()
                    continue
                text = raw.decode("utf-8", "replace").rstrip("\r\n")
                clean = cols.line(text) if cols else san.clean(text)
                lines += 1
                changed += clean != text
                if quiet:
                    # a pull's tar names each member relative to the pulled folder: no mask
                    # knows those names; only counted
                    continue
                # context, not secrecy: identical lines in a row are shown once
                # with a count, and output past the cap is counted, not shown
                if shown >= cap:  # past the cap only counted: no line, no marker
                    withheld += 1
                    continue
                if clean == last:
                    repeats += 1
                    continue
                if repeats:
                    out.write(f"[{repeats} more identical line(s)]\n")
                    shown += 1
                    repeats = 0
                    if shown >= cap:
                        withheld += 1
                        continue
                last = clean
                out.write(clean + "\n")
                shown += 1
                content += 1
                if clean == WITHHELD:
                    held += 1
                else:
                    for tok in _PLACEHOLDER.findall(clean):
                        if tok in known:
                            counts[tok] = counts.get(tok, 0) + 1
                out.flush()
            # no counts in these notes: a count is a number the command chooses
            if repeats and shown < cap:
                out.write("[the line above repeats]\n")
            elif repeats:
                withheld += repeats
            if withheld:
                out.write(f"[more lines withheld: the output is longer than {cap} lines; write "
                          "results to a file in a granted folder and print a summary]\n")
            code = proc.wait()
        finally:
            done.set()
            try:
                os.killpg(proc.pid, signal.SIGKILL)  # nothing it started outlives it
            except OSError:
                pass
            with _RUNNING_LOCK:
                _RUNNING.pop(proc.pid, None)
        if stdin_feed is not None:
            feeder_thread.join(timeout=30)
            if feed_failed:
                out.write(f"{label}: the stream stopped: {feed_failed[0]}\n")
                code = code or 1
        if quiet and lines:
            out.write(f"{label}: message lines from the program withheld (they can name "
                      "files)\n")
        # the agent sees success or failure only: an exit status (0-255) and counts are numbers
        # a command chooses, so code written to leak could encode data in them. The real
        # status goes to the operator's broker log. Cancelled stays 130 (phiward's own).
        # the placeholder note is counted from the lines written above: the agent could count
        # them itself, so it adds nothing; it tells a run that masked nothing from clean data
        kinds = ", ".join(f"{fmt_n(n)} {p}" for p, n in
                          sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
        _log(f"{label}: exit {code}, {lines} line(s), {changed} masked; "
             + (f"placeholders shown: {kinds}" if kinds else "no placeholder shown"))
        if cols and lines and not cols.headers:
            out.write(NO_HEADER_NOTE + "\n")
        if report_placeholders:
            text = placeholder_note(counts, held, content, san.identifier_placeholders()
                                    | ({IDCOL} if cols else set()))
            if text:
                out.write(text + "\n")
        seen = 0 if code == 0 else (130 if cancelled() else 1)
        out.write(f"{label} done: exit={seen}" + ("" if seen != 1 else
                  " (the command failed; its exit status is in the operator's broker log)")
                  + "\n")
        return seen
    finally:
        safeio.remove_tree(scratch)


def resolve_grant(d: str, cwd: str, cfg: config.Config) -> Optional[str]:
    """The folder a `--write-to` grant names, resolved once, or None when the user config does
    not grant it (it must be a `[broker] write_to` folder or inside one)."""
    from phiward import pathid
    full = os.path.realpath(os.path.join(cwd, os.path.expanduser(d)))
    if not os.path.isdir(full):
        return None
    full = pathid.canon(full)  # an allow decision: matched exactly, in canonical spelling
    if not any(config.inside(full, w) for w in cfg.write_to):
        return None
    if config.grant_problem(full, cfg):  # inside a write_to folder, but e.g. a root moved in
        return None
    return full


def resolve_program(word: str, cwd: str, env: Dict[str, str]) -> Optional[str]:
    """The program a command's first word names: a path in the request's folder, or a name on
    the operator's PATH (never the agent's)."""
    if "/" in word:
        p = os.path.realpath(os.path.join(cwd, word))
        return p if os.path.isfile(p) and os.access(p, os.X_OK) else None
    found = shutil.which(word, path=env.get("PATH", os.defpath))
    return os.path.realpath(found) if found else None


NOT_LISTED = ("run refused: this program is not in [broker] commands of the config (the "
              "operator lists the programs gateway commands may run: `(cd ~ && phiward setup)`, "
              "or edit the user config, then restart the broker). A program listed by its name "
              "is called by that name alone, not by a path\n")


def _entry_run_path(entry: str, word: str, program: str, cwd: str,
                    path_env: str) -> str:
    """The path to run when `entry` (one name of a list, presets expanded) lists the program
    the request names, or "": a bare name runs what it finds on the broker's PATH, called by
    that name alone; a path entry runs as itself (any other name of its file is that file, and a
    multi-call program acts as the entry's name); a folder entry runs the word's name in that
    folder, when the word's real folder is that folder."""
    if "/" not in entry:
        if "/" in word or word != entry:
            return ""
        found = shutil.which(entry, path=path_env)
        return os.path.abspath(found) if found else ""
    e = os.path.expanduser(entry)
    if not e.startswith("/"):
        return ""  # a relative entry names nothing (the config check refuses it)
    real = os.path.realpath(e)
    if entry.endswith("/") or os.path.isdir(real):
        given = os.path.join(cwd, word) if "/" in word else (shutil.which(word, path=path_env)
                                                             or "")
        if not given or os.path.realpath(os.path.dirname(given)) != real:
            return ""
        run = os.path.join(real, os.path.basename(given))
        return run if os.path.realpath(run) == program else ""
    # a path entry is a real file: no link and no `..` anywhere on it, so what was checked and
    # approved is what starts (a link could be changed between the check and the start); a
    # link is listed by its name, or through its folder
    if real != os.path.normpath(e) or real != program:
        return ""
    return real


def listed_run_path(word: str, program: str, cfg: config.Config, cwd: str,
                    path_env: str) -> str:
    """The path to run under `[broker] commands`, or "" when the program is not listed. With no
    list, the program itself. A program must be in every list that is set (a repo list narrows);
    the path that runs comes from the user config's list when it sets one, never from a repo's."""
    if not cfg.command_lists:
        return program
    chosen = ""
    for lst in cfg.command_lists:
        hit = ""
        for entry in lst:
            names = config.COMMAND_PRESETS.get(entry[1:], ()) if entry.startswith("@") else (entry,)
            for e in names:
                hit = _entry_run_path(e, word, program, cwd, path_env)
                if hit:
                    break
            if hit:
                break
        if not hit:
            return ""
        if lst is cfg.user_commands:
            chosen = hit
    # with no user list any program may run anyway: the program itself, never a repo list's path
    return chosen or program


def program_listed(word: str, program: str, cfg: config.Config, cwd: str = "",
                   path_env: Optional[str] = None) -> bool:
    """Whether the program may run under `[broker] commands` (`listed_run_path`)."""
    return bool(listed_run_path(word, program, cfg, cwd or os.getcwd(),
                                os.environ.get("PATH", os.defpath) if path_env is None
                                else path_env))


def execute(argv: Sequence[str], cwd: str, env: Dict[str, str], out: TextIO,
            cancelled: Callable[[], bool] = _never) -> int:
    """Run a request (in the broker). `env` is the command's environment; the config in force
    is the broker's own user config plus the repo config of `cwd` (tighten only)."""
    if list(argv[:1]) in (["-h"], ["--help"]):
        out.write(USAGE)
        return 0
    a = parse(argv)
    if a is None:
        if "--" not in argv:
            out.write("run refused: put `--` before the command, for example "
                      "`phiward run -- wc -l FILE`\n")
        out.write(USAGE)
        return 2
    cfg = config.load(cwd)
    if cfg.problem:
        out.write("run refused: the phiward config cannot be used (run phiward doctor)\n")
        return 3
    if a.remote:  # needs only [remote]
        return _execute_remote(a, cwd, env, out, cfg, cancelled)
    if not cfg.has_protected_paths:
        out.write("run refused: no protected paths are configured: the operator has not set "
                  "phiward up yet (`(cd ~ && phiward setup)`, in their own terminal)\n")
        return 2
    if a.net and not cfg.net:
        out.write("run refused: --net is not granted. The operator sets [broker] net = true in "
                  "the user config (`(cd ~ && phiward setup)`, choice 3 \"every setting\", question 5) and restarts "
                  "the broker.\n")
        return 2
    write_to = []
    if (not a.write_to and len(cfg.write_to) == 1 and not cfg.write_to_missing
            and any(config._deny_inside(cfg.write_to[0], r) for r in cfg.user_roots)):
        # one write place, inside a protected root: the default, so the agent needs no
        # --write-to for it (what lands there stays protected)
        write_to.append(cfg.write_to[0])
    for d in a.write_to:
        full = resolve_grant(d, cwd, cfg)
        if full is None:
            out.write("run refused: --write-to names a folder that is not granted. It must be an "
                      "existing folder in, or inside, [broker] write_to of the user config; the "
                      "operator adds one with `(cd ~ && phiward setup)` (its results folder, or in choice 3 "
                      "\"every setting\", question 3) and restarts the broker.\n")
            return 2
        write_to.append(full)
    program = resolve_program(a.cmd[0], cwd, env)
    if program is None and cfg.command_lists and "/" in a.cmd[0]:
        # the same answer as for an unlisted program: a path the agent names must not tell
        # whether a file exists there (in a protected folder too)
        out.write(NOT_LISTED)
        return 2
    if program is None:
        out.write("run refused: the program is not on the broker's PATH (or not an executable "
                  "file). The broker keeps the PATH of the terminal that started it: the "
                  "operator starts it again (or runs `(cd ~ && phiward broker --service --write)` again) "
                  "from a terminal where the program works, for example after `conda "
                  "activate`; or give the program's full path. A folder "
                  "the agent's sandbox may write (a temp folder, or one in allowWrite) is never "
                  "searched: the operator installs the program elsewhere.\n")
        return 127
    path_env = env.get("PATH", os.defpath)
    if cfg.command_lists:
        # what runs is the listed entry itself (a bare name: what it finds on the broker's
        # PATH; a path entry: that path; a folder entry: the name in that folder), taken from
        # the user config's list: never a link of the agent's, never a repo list's path
        run_as = listed_run_path(a.cmd[0], program, cfg, cwd, path_env)
        if not run_as:
            out.write(NOT_LISTED)
            return 2
    else:
        run_as = program if "/" in a.cmd[0] else os.path.abspath(
            shutil.which(a.cmd[0], path=path_env) or program)
    cmd = [run_as] + a.cmd[1:]
    why, lines = _sanitizer_options(a, cwd, cfg)
    if why:
        out.write(f"run refused: {why}\n")
        return 2
    try:
        san = Sanitizer.from_config(cfg, entries=True, names_lines=lines)
    except SanitizerError:
        out.write("run refused: the sanitizer cannot start (run phiward doctor)\n")
        return 3
    watch = _Watch(out)
    try:
        listed = bool(cfg.command_lists)
        code = run_confined(cmd, cfg, san, write_to, a.net, watch, a.table, env=env, cwd=cwd,
                            cancelled=cancelled, deny_read=gateway_hidden(cfg),
                            in_scratch=listed, report_placeholders=True)
        if listed and any(w and not w.startswith(("/", "-")) for w in a.cmd[1:]):
            # said whatever exists there (no file name is looked up for the agent)
            out.write("run: with [broker] commands set, a command starts in a private folder "
                      "that is removed afterwards, not in yours: give paths in full, and write "
                      "results with --write-to.\n")
        if code != 0 and watch.write_refused:
            out.write("run: the command was refused a path. Gateway commands cannot read the "
                      "hidden list (credentials), and write only in a granted folder, named with "
                      "--write-to DIR (protected roots are read only). The operator adds a "
                      "folder with `(cd ~ && phiward setup)` (its results folder, or in choice 3 \"every "
                      "setting\", question 3) and restarts the broker; `phiward doctor` counts "
                      "the granted folders.\n")
        if code != 0 and watch.no_network and not a.net:
            out.write("run: the command had no network (by design). `--net` needs "
                      "[broker] net = true in the user config.\n")
        return code
    except confine.ConfineError as exc:
        out.write(f"run refused: {exc}\n")
        return 3
    except Exception as exc:  # noqa: BLE001 - never print a traceback (it can name paths)
        out.write(f"run failed ({type(exc).__name__})\n")
        return 3


class _Watch:
    """Passes output on unchanged, and notes the words of a refused write or a missing network,
    so `run` can say what to do next."""
    _WRITE = ("Operation not permitted", "Read-only file system", "Permission denied")
    _NET = ("Could not resolve host", "Network is unreachable", "Name or service not known",
            "nodename nor servname", "Temporary failure in name resolution")

    def __init__(self, out):
        self.out, self.write_refused, self.no_network = out, False, False

    def write(self, text: str) -> int:
        if any(w in text for w in self._WRITE):
            self.write_refused = True
        if any(w in text for w in self._NET):
            self.no_network = True
        return self.out.write(text)

    def __getattr__(self, name):
        return getattr(self.out, name)


_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
# a csh or tcsh login shell expands `!` even inside single quotes, and a newline ends a quoted
# word there: no quoting makes these plain text on every login shell
# `!` (csh and tcsh expand it inside quotes), `\\` (fish reads it as an escape inside single
# quotes) and control characters cannot be quoted for every login shell: refused
_UNQUOTABLE = re.compile(r"[!\\\x00-\x1f\x7f]")


TABLE_OFF = ("--table is off: it lets numbers through (`phiward run --table` in columns not "
             "named as identifiers; a record number could pass); the operator turns it on with "
             "[sanitize] table = true in the user config")


NAMES_OUTSIDE = ("a --names-from file must be a plain file inside a protected path of the user "
                 "config, reached without a link (the broker reads it outside the sandbox)")


def _read_by_parts(path: str) -> str:
    """The text of the regular file at the resolved `path`, opened part by part without
    following a link, and with one name only (a hard link could carry another file in)."""
    flags = os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | flags)
    try:
        parts = [p for p in path.split("/") if p]
        for p in parts[:-1]:
            nxt = os.open(p, os.O_RDONLY | os.O_DIRECTORY | flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        f = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | flags, dir_fd=fd)
    finally:
        os.close(fd)
    try:
        st = os.fstat(f)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > (64 << 20):
            raise OSError("not a plain file")
        chunks, total = [], 0
        while True:
            b = os.read(f, 1 << 20)
            if not b:
                break
            total += len(b)
            if total > (64 << 20):  # it grew while it was read
                raise OSError("too large")
            chunks.append(b)
    finally:
        os.close(f)
    return b"".join(chunks).decode("utf-8")


def _sanitizer_options(a: "RunArgs", cwd: str, cfg: config.Config) -> Tuple[str, List[str]]:
    """(why the agent's --table or --names-from cannot be used or "", the names files' lines)
    (what is checked is what is read)."""
    if a.table and not cfg.sanitize_table:
        return TABLE_OFF, []
    pset = paths.ProtectedSet(cfg.user_roots, cfg.user_patterns)
    lines: List[str] = []
    for n in a.names_from:
        full = os.path.realpath(os.path.join(cwd, os.path.expanduser(n)))
        # the broker reads it outside every profile: a file elsewhere (a key, a token) would
        # turn masking into a test of its contents
        if pset.relation(full) != paths.INSIDE:
            return NAMES_OUTSIDE, []
        try:
            text = _read_by_parts(full)
        except (OSError, UnicodeDecodeError):
            return NAMES_OUTSIDE, []
        from phiward.sanitize import STOP_WORDS, name_tokens
        if not name_tokens(text.splitlines(), set(STOP_WORDS)):
            return "a --names-from file yields no name to mask", []
        lines += text.splitlines()
    return "", lines


KRB5_MAX = 2000


def gateway_hidden(cfg: config.Config) -> List[str]:
    """What a local gateway command may not read: the credentials and traces `launch` hides,
    from the broker's own environment (never the request's), the write_to folders aside (a
    grant writes there). Without this, `run -- cat ~/.ssh/id_x` printed the key."""
    from phiward import hidden
    import glob
    out = hidden.paths(dict(os.environ), cfg)
    if sys.platform == "darwin":
        return out  # the profile hides every ticket cache by its name (confine)
    # Linux: every cache name there now, with no cap; past a bound the request is refused (a
    # cache pushed past a cap would be readable)
    found: List[str] = []
    for d in ("/tmp", "/var/tmp", "/dev/shm"):
        found += glob.glob(os.path.join(d, "krb5cc*"))
        if len(found) > KRB5_MAX:
            raise confine.ConfineError(
                f"the temp folders hold more than {KRB5_MAX} Kerberos cache names, too many to "
                "hide one by one; the operator removes the extra ones")
    return out + found


def add_remote_roots(san: Sanitizer, cfg: config.Config) -> None:
    """The remote protected paths, masked before every other step (longest first, so a root
    inside another one does not leave a tail); for `run --remote` and for copies to and from a
    remote."""
    from phiward.sanitize import normalize
    if san.first_rules:
        return
    for root in sorted(cfg.remote_roots, key=len, reverse=True):
        san.first_rules.append((remote_root_regex(normalize(root)), "<PROTECTED>"))


def remote_root_regex(root: str) -> "re.Pattern[str]":
    """A remote protected path in any spelling the remote shell treats as the same (`//`,
    `/./`), with the rest of the path up to a tab or the end of the line: a file name may hold
    spaces."""
    sep = r"/(?:/|\./)*"
    parts = [re.escape(p) for p in root.split("/") if p and p != "."]
    if not parts:
        return re.compile(r"(?!)")
    return re.compile(sep + sep.join(parts) + r"(?:/[^\t\n]*|(?=[\s'\":;,)]|$))")


def _remote_argv(rt, host: str, cmd: Sequence[str]) -> List[str]:
    """The ssh argv for a remote run on the route `rt` (remote.route: the operator's ssh config
    only, no proxy or local command, no forwarding, no terminal, never a prompt); every word
    quoted for the remote shell."""
    return rt.ssh + [host, "--", " ".join(shlex.quote(w) for w in cmd)]


def _execute_remote(a: RunArgs, cwd: str, env: Dict[str, str], out: TextIO, cfg: config.Config,
                    cancelled: Callable[[], bool]) -> int:
    if a.has_grants:
        out.write("run refused: --remote takes no --write-to or --net\n")
        return 2
    if not _HOST.fullmatch(a.remote) or a.remote not in cfg.remote_hosts:
        out.write("run refused: the host is not in [remote] hosts of the user config\n")
        return 2
    prog = a.cmd[0]
    if "/" in prog or prog not in cfg.remote_commands:
        out.write("run refused: the program is not in [remote] commands of the user config (the "
                  "remote side is not confined: the operator lists what may run there)\n")
        return 2
    if any(".." in w.replace("\\", "/").split("/") for w in a.cmd):
        out.write("run refused: a word holds a `..` part; a remote path given that way is not "
                  "masked. Give remote paths without `..`\n")
        return 2
    if any(_UNQUOTABLE.search(w) for w in a.cmd):
        out.write("run refused: a word holds a character the remote shell may expand even when "
                  "quoted (`!`, `\\`, a newline or another control character)\n")
        return 2
    why, lines = _sanitizer_options(a, cwd, cfg)
    if why:
        out.write(f"run refused: {why}\n")
        return 2
    from phiward import remote as rmt
    rt, why = rmt.route(cfg, a.remote)
    if rt is None:
        out.write(f"run refused: {why}\n")
        return 2
    ssh = _remote_argv(rt, a.remote, a.cmd)
    try:
        san = Sanitizer.from_config(cfg, entries=True, names_lines=lines)
    except SanitizerError:
        out.write("run refused: the sanitizer cannot start (run phiward doctor)\n")
        return 3
    # the remote protected paths, masked first (longest first, so a root inside another one
    # does not leave a tail)
    add_remote_roots(san, cfg)
    try:
        # through the shared connection: no credential, no network but its socket
        return run_confined(ssh, cfg, san, [], rt.net, out, a.table, label="remote run",
                            env=env, cwd=cwd, cancelled=cancelled, deny_read=rt.deny_read,
                            socket=rt.socket, allow_read=rt.allow_read,
                            report_placeholders=True)
    except confine.ConfineError as exc:
        out.write(f"run refused: {exc}\n")
        return 3
    except Exception as exc:  # noqa: BLE001 - never print a traceback
        out.write(f"run failed ({type(exc).__name__})\n")
        return 3


def main(argv: List[str], out: TextIO = sys.stdout) -> int:
    """The client: the request goes to the broker, which runs it outside the agent's sandbox."""
    if argv[:1] in (["-h"], ["--help"]):
        out.write(HELP)
        return 0
    if parse(argv) is None:
        if "--" not in argv:
            out.write("run refused: put `--` before the command, for example "
                      "`phiward run -- wc -l FILE`\n")
        out.write(USAGE)
        return 2
    from phiward import broker
    return broker.client("run", list(argv), out)
