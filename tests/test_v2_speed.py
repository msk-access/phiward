"""Speed and context. A fast hook under `launch`; the broker keeps the sanitizer
between calls; repeated masked lines are collapsed and gateway output is capped; refusals are
one short line. Memory files: test_v2_carryover.py."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from helpers import needs_confine

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable


def ag(args, cwd, env=None, stdin=None, timeout=120):
    e = dict(os.environ, PYTHONPATH=SRC)
    e.update(env or {})
    t = time.perf_counter()
    r = subprocess.run([PY, "-m", "phiward", *args], cwd=str(cwd), capture_output=True,
                       text=True, env=e, input=stdin, timeout=timeout)
    return r.returncode, r.stdout, r.stderr, (time.perf_counter() - t) * 1000


def payload(tree, tool, inp):
    return json.dumps({"hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
                       "permission_mode": "default", "tool_name": tool, "tool_input": inp})


# --- S1: the hook under launch is a fast first layer ---------------------------------------------

def test_s1_under_launch_the_hook_is_fast_and_still_helpful(tree):
    env = {"PHIWARD_LAUNCH_DEPTH": "1",
           "PHIWARD_HOOK_ROOTS": json.dumps([str(tree / "phi")])}
    times = []
    for _ in range(5):
        code, out, err, ms = ag(["hook", "claude", "--launched"], tree / "repo", env,
                                payload(tree, "Bash", {"command": "ls -la src"}))
        times.append(ms)
        assert code == 0
    code, out, err, _ = ag(["hook", "claude", "--launched"], tree / "repo", env,
                           payload(tree, "Read", {"file_path": str(tree / "phi" / "x")}))
    assert code == 2 and "phiward run" in err
    full = []
    for _ in range(5):
        full.append(ag(["hook", "claude"], tree / "repo", None,
                       payload(tree, "Bash", {"command": "ls -la src"}))[3])
    assert sorted(times)[2] < sorted(full)[2] * 0.7, (times, full)


# --- S4: one short refusal ------------------------------------------------------------------------

def test_s4_a_refusal_is_one_short_line(tree):
    code, out, err, _ = ag(["hook", "claude"], tree / "repo", None,
                           payload(tree, "Read", {"file_path": str(tree / "phi" / "FAKE-PT-0001.bam")}))
    assert code == 2
    assert len(err) < 260 and "phiward run" in err and err.count("\n") <= 1, err


# --- S3: collapsed and capped gateway output -----------------------------------------------------

@needs_confine
def test_s3_repeated_masked_lines_are_collapsed(tree, broker):
    for i in range(300):
        (tree / "phi" / f"FAKE-PT-{i:05d}.bam").write_text("x\n")
    code, out, err, _ = ag(["run", "--", "ls", str(tree / "phi")], tree / "repo")
    lines = out.splitlines()
    assert any("identical" in l for l in lines), out[:400]
    assert len(lines) < 30, len(lines)


@needs_confine
def test_s3_output_is_capped(tree, broker):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + "[broker]\nmax_output_lines = 50\n")
    broker()  # a changed config takes effect when the operator restarts the broker
    code, out, err, _ = ag(["run", "--", PY, "-c", "for i in range(500): print('line', i)"],
                           tree / "repo")
    assert "withheld" in out and len(out.splitlines()) < 60, out[-300:]


# --- S2: the broker keeps the sanitizer between calls --------------------------------------------

def test_s2_the_names_are_compiled_once_per_set():
    """The broker keeps the compiled names between calls (compiling is most of the cost for a
    large root). Checked on the cache itself: a wall-clock ratio failed on a busy CI runner
    (640 ms, then 428 ms, where it asked for under 60%)."""
    from phiward import inventory
    names = [f"FAKE-PT-{i:05d}" for i in range(20000)]
    first = inventory.matcher(names)
    assert inventory.matcher(list(reversed(names))) is first  # the same set, in any order
    grown = inventory.matcher(names + ["FAKE-NEW-ZZZZ"])
    assert grown is not first and grown.search("x FAKE-NEW-ZZZZ y")


@needs_confine
def test_s2_a_new_entry_is_still_masked_at_once(tree, broker):
    ag(["run", "--", "true"], tree / "repo")  # warm the cache
    (tree / "phi" / "sub" / "FAKE-NEW-ZZZZ.bam").write_text("x\n")
    _, out, _, _ = ag(["run", "--", "ls", str(tree / "phi" / "sub")], tree / "repo")
    assert "FAKE-NEW-ZZZZ" not in out, out


# --- S5: memory files: see test_v2_carryover.py (carry-over replaced the S5 report) ---------------
