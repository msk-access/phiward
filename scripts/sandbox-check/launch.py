"""Start the real `claude -p` for the sandbox check with a clean environment: only the variables
it needs, the credential from the caller's environment or the first line of stdin (never argv or
a file), Claude Code's own credential scrub for its commands, no auto-update. A watchdog stops it.
Afterwards, before the judge reads anything, it replaces the token's value with <TOKEN> in the
stream and in every file of the check's home it scans, and records only whether it was there:
RUN_DIR/token-seen (in the session's output: what the model and the provider saw),
RUN_DIR/token-in-env (in the commands' environment, as probes.sh saved it in env.txt) and
RUN_DIR/parent-environ (in the environment of a parent process, as probes.sh read it from /proc
into environ.txt: yes, no, or n/a without /proc). env.txt and environ.txt are then removed. A
copy in another file of the home is only reported (and redacted).
Usage: python3 launch.py HOME RUN_DIR SECONDS -- CLAUDE ARGS..."""
import os
import signal
import subprocess
import sys


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


def _scan_and_remove(path, token):
    """yes or no (the token in the file, which is then removed), or None if there is none."""
    try:
        found = redact(path, token)
        os.remove(path)  # a kept folder never holds what an environment held
    except OSError:
        return None
    return "yes" if found else "no"


def main(argv):
    home, run_dir, seconds = argv[1:4]
    cmd = argv[argv.index("--") + 1:]
    name, token = None, None
    for var in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"):
        if os.environ.get(var):
            name, token = var, os.environ[var]
            break
    if token is None:
        token = sys.stdin.readline().strip()
        name = "CLAUDE_CODE_OAUTH_TOKEN"
    if not token:
        sys.exit("no token: set CLAUDE_CODE_OAUTH_TOKEN or paste the one `claude setup-token` "
                 "prints")
    env = {"HOME": home, "PATH": os.environ["PATH"], "USER": os.environ.get("USER", ""),
           "LOGNAME": os.environ.get("LOGNAME", ""), "LANG": os.environ.get("LANG", "en_US.UTF-8"),
           "TERM": "dumb", "SHELL": "/bin/bash", "TMPDIR": os.path.join(home, "tmp"),
           "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1", "DISABLE_AUTOUPDATER": "1",
           "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", name: token}
    stream_out = os.path.join(run_dir, "stream.jsonl")
    with open(stream_out, "wb") as out:
        p = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=out,
                             stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = p.wait(timeout=float(seconds))
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGINT)
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
            print(f"claude was stopped after {seconds} seconds", file=sys.stderr)
            code = 124
    in_stream = redact(stream_out, token)
    proj = os.path.join(home, "proj")
    in_env = _scan_and_remove(os.path.join(proj, "env.txt"), token) or "missing"
    parent = _scan_and_remove(os.path.join(proj, "environ.txt"), token)
    if parent is None:
        parent = "n/a" if not os.path.isdir("/proc/self") else "missing"
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
    for fname, value in (("token-in-env", in_env), ("token-seen", "yes" if in_stream else "no"),
                         ("parent-environ", parent)):
        with open(os.path.join(run_dir, fname), "w") as fh:
            fh.write(value + "\n")
    for path in seen:
        print(f"note: the token was in a file of the check's home (now <TOKEN>): ~/{path}",
              file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
