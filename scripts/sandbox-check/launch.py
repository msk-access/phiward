"""Start the real `claude -p` for the sandbox check with a clean environment: only the variables
it needs, the credential from the caller's environment or the first line of stdin (never argv or
a file), Claude Code's own credential scrub for its commands, no auto-update. A watchdog stops it.
However it ends (normally, the watchdog, Ctrl-C or SIGTERM), it stops the whole session, then
replaces the token's value with <TOKEN> in the stream and in every file of the check's home it
scans, and records only whether it was there: RUN_DIR/token-seen (in the session's output: what
the model and the provider saw) and RUN_DIR/token-in-env (in the commands' environment, as
probes.sh saved it in env.txt, which is then removed). A copy in another file of the home is
only reported (and redacted).
Usage: python3 launch.py HOME RUN_DIR SECONDS -- CLAUDE ARGS...
       python3 launch.py --redact HOME   (the token from the environment or stdin: redact every
       file of HOME once more, after the last one is written)"""
import os
import signal
import subprocess
import sys


class Stopped(Exception):
    pass


def redact(path, token):
    """Replace the token's value with <TOKEN> in the file; True if it was there."""
    needle = token.encode()
    with open(path, "rb") as fh:
        data = fh.read()
    if needle not in data:
        return False
    with open(path, "wb") as fh:
        fh.write(data.replace(needle, b"<TOKEN>"))
    return True


def redact_tree(home, token):
    """Redact every file under HOME (not the copied Python or the caches); the paths, relative
    to HOME, that held the token."""
    seen = []
    for root, dirs, files in os.walk(home):
        dirs[:] = [d for d in dirs
                   if d not in ("py", ".cache") and not os.path.islink(os.path.join(root, d))]
        for f in files:
            path = os.path.join(root, f)
            try:
                if os.path.islink(path) or os.path.getsize(path) > 50_000_000:
                    continue
                if redact(path, token):
                    seen.append(os.path.relpath(path, home))
            except OSError:
                continue
    return seen


def _scan_and_remove(path, token):
    """yes or no (the token in the file, which is then removed), or None if there is none."""
    try:
        found = redact(path, token)
        os.remove(path)  # a kept folder never holds what an environment held
    except OSError:
        return None
    return "yes" if found else "no"


def _token():
    for var in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"):
        if os.environ.get(var):
            return var, os.environ[var]
    return "CLAUDE_CODE_OAUTH_TOKEN", sys.stdin.readline().strip()


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


def main(argv):
    if argv[1:2] == ["--redact"]:
        _name, token = _token()
        if not token:
            sys.exit("no token to redact")
        for path in redact_tree(argv[2], token):
            print(f"note: the token was in a file of the check's home (now <TOKEN>): ~/{path}",
                  file=sys.stderr)
        return 0
    home, run_dir, seconds = argv[1:4]
    cmd = argv[argv.index("--") + 1:]
    name, token = _token()
    if not token:
        sys.exit("no token: set CLAUDE_CODE_OAUTH_TOKEN or paste the one `claude setup-token` "
                 "prints")
    env = {"HOME": home, "PATH": os.environ["PATH"], "USER": os.environ.get("USER", ""),
           "LOGNAME": os.environ.get("LOGNAME", ""), "LANG": os.environ.get("LANG", "en_US.UTF-8"),
           "TERM": "dumb", "SHELL": "/bin/bash", "TMPDIR": os.path.join(home, "tmp"),
           "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1", "DISABLE_AUTOUPDATER": "1",
           "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", name: token}

    def stopped(signum, _frame):
        raise Stopped(signum)
    signal.signal(signal.SIGINT, stopped)
    signal.signal(signal.SIGTERM, stopped)
    stream_out = os.path.join(run_dir, "stream.jsonl")
    code, p = 130, None
    try:
        with open(stream_out, "wb") as out:
            p = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=out,
                                 stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = p.wait(timeout=float(seconds))
            except subprocess.TimeoutExpired:
                print(f"claude was stopped after {seconds} seconds", file=sys.stderr)
                code = 124
    except Stopped as exc:
        print("claude was stopped (signal %d)" % exc.args[0], file=sys.stderr)
        code = 130
    finally:
        # no second signal may cut the cleanup short
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if p is not None:
            _stop(p)
        try:
            in_stream = redact(stream_out, token)
        except OSError:
            in_stream = False
        in_env = _scan_and_remove(os.path.join(home, "proj", "env.txt"), token) or "missing"
        seen = redact_tree(home, token)
        for fname, value in (("token-in-env", in_env),
                             ("token-seen", "yes" if in_stream else "no")):
            with open(os.path.join(run_dir, fname), "w") as fh:
                fh.write(value + "\n")
        for path in seen:
            print(f"note: the token was in a file of the check's home (now <TOKEN>): ~/{path}",
                  file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
