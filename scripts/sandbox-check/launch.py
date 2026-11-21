"""Start the real `claude -p` for the sandbox check with a clean environment: only the variables
it needs, the credential from the caller's environment or the first line of stdin (never argv or
a file; a line ANTHROPIC_API_KEY=VALUE names an API key), Claude Code's own credential scrub for its commands, no auto-update. A watchdog stops it.
The session writes into a pipe; launch.py writes RUN_DIR/stream.jsonl itself once the session
is stopped. However it ends (normally, the watchdog, SIGINT, SIGTERM or SIGHUP), it stops the
session's process group, and records only whether the token was there: RUN_DIR/token-seen (in the
session's output: what the model and the provider saw) and RUN_DIR/token-in-env (in the
commands' environment, as probes.sh saved it in env.txt, which is then removed). Exit: claude's
code, 124 for the watchdog, 128 + the signal for a signal.
A process the session starts in a session of its own (setsid) is not in that group and can
outlive the check; check.sh removes the whole run folder afterwards, so nothing it writes is kept.

Nothing of the check's home is kept except what `--keep` writes: the judge's report and, per
mode, the stream and the facts, each read into memory, the token's value replaced with <TOKEN>,
checked again, and only then written as new files outside the home. If the token is still
found, or anything fails, it writes nothing, prints "redaction failed: nothing kept" and exits 3.
Usage: python3 launch.py HOME RUN_DIR SECONDS -- CLAUDE ARGS...
       python3 launch.py --keep OUT|- REPORT RUN_DIR...   (prints the redacted report; OUT "-"
       keeps no file)"""
import signal
import sys

if __name__ == "__main__":
    # first of all: a signal before the session exists ends launch.py (128 + the signal), and
    # --keep then removes what it wrote (the exit passes through its cleanup)
    def _early(signum, _frame):
        raise SystemExit(128 + signum)
    for _sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(_sig, _early)

import os  # noqa: E402
import subprocess  # noqa: E402
import threading  # noqa: E402

SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class Stopped(Exception):
    pass


class KeepError(Exception):
    pass


VARS = ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY")


def _token():
    """(the variable, the token): from the environment, else the first line of stdin, which
    may name its variable (ANTHROPIC_API_KEY=VALUE; check.sh passes an API key so)."""
    for var in VARS:
        if os.environ.get(var):
            return var, os.environ[var]
    line = sys.stdin.readline().strip()
    for var in VARS:
        if line.startswith(var + "="):
            return var, line[len(var) + 1:]
    return "CLAUDE_CODE_OAUTH_TOKEN", line


def _redacted(data, token):
    needle = token.encode()
    out = data.replace(needle, b"<TOKEN>")
    if not needle or needle in out:
        raise KeepError("the token is still there after the redaction")
    return out


def keep(token, report, run_dirs, out):
    """The redacted report as text; with OUT, also report.txt, stream-MODE.jsonl and
    facts-MODE.txt there, written only when every one of them is redacted (KeepError else)."""
    def read(path):
        with open(path, "rb") as fh:
            return fh.read()
    files = {"report.txt": _redacted(read(report), token)}
    for d in run_dirs:
        mode = os.path.basename(os.path.normpath(d)).replace("run-", "", 1)
        for src, dst in (("stream.jsonl", f"stream-{mode}.jsonl"), ("facts.txt", f"facts-{mode}.txt")):
            path = os.path.join(d, src)
            if os.path.exists(path):
                files[dst] = _redacted(read(path), token)
    if out:
        made = []  # every path this call created, partial or final
        try:
            for name, data in files.items():  # all the parts first
                tmp = os.path.join(out, "." + name + ".part")
                with open(tmp, "xb") as fh:  # "x": never a file this call did not make
                    made.append(tmp)
                    fh.write(data)
            for name in files:  # then the renames, only when every part is written
                final = os.path.join(out, name)
                os.rename(os.path.join(out, "." + name + ".part"), final)
                made.append(final)
        except BaseException:  # a KeyboardInterrupt too: nothing is left
            for path in made:
                try:
                    os.remove(path)
                except OSError:
                    pass
            raise
    return files["report.txt"].decode("utf-8", "replace")


def _stop(p):
    """Stop the session's whole process group: SIGINT, then SIGKILL."""
    for sig, wait in ((signal.SIGINT, 10), (signal.SIGKILL, 10)):
        try:
            os.killpg(p.pid, sig)
        except OSError:
            pass
        try:
            p.wait(timeout=wait)
            break
        except subprocess.TimeoutExpired:
            continue
    try:  # the group may outlive its leader
        os.killpg(p.pid, signal.SIGKILL)
    except OSError:
        pass


def _contains(path, token):
    try:
        with open(path, "rb") as fh:
            return token.encode() in fh.read()
    except OSError:
        return None


def _keep_main(argv):
    try:
        out, report, runs = argv[2], argv[3], argv[4:]
        _name, token = _token()
        if not token:
            raise KeepError("no token")
        text = keep(token, report, runs, None if out == "-" else out)
    except Exception:  # fail closed: whatever went wrong, nothing is kept or shown
        print("redaction failed: nothing kept", file=sys.stderr)
        return 3
    sys.stdout.write(text)
    return 0


def main(argv):
    if argv[1:2] == ["--keep"]:
        return _keep_main(argv)
    home, run_dir, seconds = argv[1:4]
    cmd = argv[argv.index("--") + 1:]
    name, token = _token()
    if not token:
        sys.exit("no token: paste the one `claude setup-token` "
                 "prints")
    env = {"HOME": home, "PATH": os.environ["PATH"], "USER": os.environ.get("USER", ""),
           "LOGNAME": os.environ.get("LOGNAME", ""), "LANG": os.environ.get("LANG", "en_US.UTF-8"),
           "TERM": "dumb", "SHELL": "/bin/bash", "TMPDIR": os.path.join(home, "tmp"),
           "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1", "DISABLE_AUTOUPDATER": "1",
           "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", name: token}

    def stopped(signum, _frame):
        for sig in SIGNALS:  # no second signal may cut the stop short
            signal.signal(sig, signal.SIG_IGN)
        raise Stopped(signum)
    for sig in SIGNALS:
        signal.signal(sig, stopped)
    # the session writes into a pipe; launch.py writes the stream file itself, after the session
    # is stopped, so the session never holds the file
    stream_out = os.path.join(run_dir, "stream.jsonl")
    chunks = []
    code, p, reader = 130, None, None
    try:
        # a signal between the start and the assignment of p waits until p is known, so the
        # session is always stopped; the child starts with the signals unblocked
        signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        try:
            p = subprocess.Popen(
                cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, start_new_session=True,
                preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_UNBLOCK, SIGNALS))
            reader = threading.Thread(target=lambda: chunks.extend(iter(
                lambda: p.stdout.read1(65536), b"")), daemon=True)
            reader.start()
        finally:
            signal.pthread_sigmask(signal.SIG_UNBLOCK, SIGNALS)
        try:
            code = p.wait(timeout=float(seconds))
        except subprocess.TimeoutExpired:
            print(f"claude was stopped after {seconds} seconds", file=sys.stderr)
            code = 124
    except Stopped as exc:
        print("claude was stopped (signal %d)" % exc.args[0], file=sys.stderr)
        code = 128 + exc.args[0]
    finally:
        for sig in SIGNALS:  # no second signal may cut the cleanup short
            signal.signal(sig, signal.SIG_IGN)
        if p is not None:
            _stop(p)
        if reader is not None:
            reader.join(timeout=5)  # a process left in a session of its own may hold the pipe
        with open(stream_out, "wb") as fh:
            fh.write(b"".join(chunks))
        in_stream = _contains(stream_out, token)
        env_dump = os.path.join(home, "proj", "env.txt")
        in_env = {True: "yes", False: "no", None: "missing"}[_contains(env_dump, token)]
        try:
            os.remove(env_dump)  # no file holds what the commands' environment held
        except OSError:
            pass
        for fname, value in (("token-in-env", in_env),
                             ("token-seen", "yes" if in_stream else "no")):
            with open(os.path.join(run_dir, fname), "w") as fh:
                fh.write(value + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
