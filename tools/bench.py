"""Speed of phiward's parts on a made-up tree (developer tool, not shipped).

    BENCH_N=100000 python3 tools/bench.py

Times: Python start, the hook (allowed and denied), launch, exec, a gateway round trip through a
real broker, the sanitizer build and its per-line cost. Everything runs in a temp folder with a
fake HOME; nothing touches the operator's files.
"""
import json, os, subprocess, sys, tempfile, time, statistics
SRC = os.path.abspath("src")
t = os.path.realpath(tempfile.mkdtemp(dir=os.environ.get("BENCH_DIR")))
for d in ("home", "phi", "repo"):
    os.makedirs(os.path.join(t, d), exist_ok=True)
N = int(os.environ.get("BENCH_N", "2000"))
for i in range(N):
    sub = os.path.join(t, "phi", f"d{i // 100}")
    os.makedirs(sub, exist_ok=True)
    open(os.path.join(sub, f"FAKE-PT-{i:05d}.bam"), "w").write("SECRET\n")
cfg = os.path.join(t, "home", "c.toml")
open(cfg, "w").write(f'[protected_paths]\nroots = ["{t}/phi"]\n')
env = dict(os.environ, HOME=t + "/home", PHIWARD_CONFIG=cfg, PHIWARD_SPOOL=t + "/spool",
           PYTHONPATH=SRC, PHIWARD_DIALOG="/nonexistent")
def timeit(argv, n=10, stdin=None, cwd=t + "/repo"):
    xs = []
    for _ in range(n):
        a = time.perf_counter()
        r = subprocess.run(argv, input=stdin, capture_output=True, text=True, env=env, cwd=cwd)
        xs.append((time.perf_counter() - a) * 1000)
    return statistics.median(xs), r
PY = sys.executable
print("python start (-c pass):          %.0f ms" % timeit([PY, "-c", "pass"])[0])
print("python -I -S start:              %.0f ms" % timeit([PY, "-I", "-S", "-c", "pass"])[0])
pay = lambda tool, inp: json.dumps({"hook_event_name": "PreToolUse", "cwd": t + "/repo",
      "permission_mode": "default", "tool_name": tool, "tool_input": inp})
ms, r = timeit([PY, "-m", "phiward", "hook", "claude"], stdin=pay("Bash", {"command": "ls -la src && git status"}))
print("hook, Bash allowed:              %.0f ms" % ms)
ms, r = timeit([PY, "-m", "phiward", "hook", "claude"], stdin=pay("Read", {"file_path": t + "/repo/README.md"}))
print("hook, Read allowed:              %.0f ms" % ms)
ms, r = timeit([PY, "-m", "phiward", "hook", "claude"], stdin=pay("Read", {"file_path": t + "/phi/d0/FAKE-PT-00001.bam"}))
print("hook, Read denied:               %.0f ms   reason %d chars" % (ms, len(r.stderr)))
fast = dict(env, PHIWARD_HOOK_ROOTS=json.dumps([t + "/phi"]))
xs = []
for _ in range(10):
    a = time.perf_counter()
    subprocess.run([PY, "-I", "-S", "-c", f"import sys; sys.path.insert(0, {SRC!r}); from phiward.cli import main; sys.exit(main())",
                    "hook", "claude", "--launched"], input=pay("Bash", {"command": "ls -la src"}), capture_output=True,
                   text=True, env=fast, cwd=t + "/repo")
    xs.append((time.perf_counter() - a) * 1000)
print("hook under launch (fast path):   %.0f ms" % statistics.median(xs))
open(os.path.join(t, "deny.txt"), "w").write(r.stderr)
if sys.platform == "darwin":
    ms, _ = timeit([PY, "-m", "phiward", "launch", "--", "/usr/bin/true"], n=5)
    print("launch -- true:                  %.0f ms   (true alone ~2 ms)" % ms)
b = subprocess.Popen([PY, "-m", "phiward", "broker"], env=env, cwd=t + "/home",
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2.5)
first, _ = timeit([PY, "-m", "phiward", "run", "--", "true"], n=1)
print(f"run -- true, first (N={N}):     %.0f ms" % first)
time.sleep(2.5)  # past the two-second freshness window of the folder cache
ms, r = timeit([PY, "-m", "phiward", "run", "--", "true"], n=5)
print(f"run -- true, warm (N={N}):      %.0f ms" % ms)
ms, r = timeit([PY, "-m", "phiward", "run", "--", "ls", "-R", t + "/phi"], n=3)
print(f"run -- ls -R root ({N} lines):  %.0f ms   output %d chars" % (ms, len(r.stdout)))
b.terminate(); b.wait()
sys.path.insert(0, SRC)
os.environ.update(env)
from phiward import config, sanitize
c = config.load(t + "/repo")
a = time.perf_counter(); s = sanitize.Sanitizer.from_config(c, entries=True); bt = (time.perf_counter() - a) * 1000
lines = [f"{t}/phi/d{i//100}/FAKE-PT-{i:05d}.bam  chr1:12345 ACGT" for i in range(5000)]
a = time.perf_counter(); [s.clean(l) for l in lines]; ct = (time.perf_counter() - a) * 1000
print(f"sanitizer build (N={N}):         %.0f ms" % bt)
print("sanitizer clean, 5000 lines:     %.0f ms  (%.1f us/line)" % (ct, ct * 1000 / 5000))
