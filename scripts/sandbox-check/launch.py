"""Start the real `claude -p` for the sandbox check with a clean environment: only the variables
it needs, the credential from the caller's environment or the first line of stdin (never argv or
a file), Claude Code's own credential scrub for its commands, no auto-update. A watchdog stops it.
Afterwards, writes HOME/token-in-env (whether the token is in the commands' environment, as
probes.sh saved it; that file is then removed) and HOME/token-seen (whether it is in the
session's output: what the model and the provider saw); a copy in another file of the check's
home is only reported.
Usage: python3 launch.py HOME STREAM_OUT SECONDS -- CLAUDE ARGS..."""
import os
import signal
import subprocess
import sys

home, stream_out, seconds = sys.argv[1:4]
cmd = sys.argv[sys.argv.index("--") + 1:]
name, token = None, None
for var in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"):
    if os.environ.get(var):
        name, token = var, os.environ[var]
        break
if token is None:
    token = sys.stdin.readline().strip()
    name = "CLAUDE_CODE_OAUTH_TOKEN"
if not token:
    sys.exit("no token: set CLAUDE_CODE_OAUTH_TOKEN or paste the one `claude setup-token` prints")
env = {"HOME": home, "PATH": os.environ["PATH"], "USER": os.environ.get("USER", ""),
       "LOGNAME": os.environ.get("LOGNAME", ""), "LANG": os.environ.get("LANG", "en_US.UTF-8"),
       "TERM": "dumb", "SHELL": "/bin/bash", "TMPDIR": os.path.join(home, "tmp"),
       "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1", "DISABLE_AUTOUPDATER": "1",
       "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", name: token}
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
needle = token.encode()
seen = []
for root, dirs, files in os.walk(home):
    dirs[:] = [d for d in dirs
               if d not in ("py", ".cache") and not os.path.islink(os.path.join(root, d))]
    for f in files:
        path = os.path.join(root, f)
        try:
            if os.path.islink(path) or os.path.getsize(path) > 50_000_000:
                continue
            with open(path, "rb") as fh:
                if needle in fh.read():
                    seen.append(os.path.relpath(path, home))
        except OSError:
            continue
with open(stream_out, "rb") as fh:
    in_stream = needle in fh.read()
env_dump = os.path.join(home, "proj", "env.txt")
try:
    with open(env_dump, "rb") as fh:
        in_env = "yes" if needle in fh.read() else "no"
    os.remove(env_dump)  # a kept folder never holds what the commands' environment held
except OSError:
    in_env = "missing"
with open(os.path.join(home, "token-in-env"), "w") as fh:
    fh.write(in_env + "\n")
with open(os.path.join(home, "token-seen"), "w") as fh:
    fh.write("yes\n" if in_stream else "no\n")
for path in seen:
    print(f"note: the token is in a file of the check's home (removed with it): ~/{path}",
          file=sys.stderr)
sys.exit(code)
