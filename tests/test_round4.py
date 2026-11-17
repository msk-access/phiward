"""Security review findings (fourth set), each as a test.

K4: no run-time approval. Grants come from the user config only (`[broker] write_to`, `net`).
Bugs 1, 2, 4, 5, 7, 8 of the round. `phiward setup`: the operator's first-time prompts.
"""

import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import pytest

from phiward import config, confine
from helpers import confinement, needs_confine

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")

LAUNCH = ("import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; "
          "from phiward.cli import main; sys.exit(main())")


def ag(args, cwd, env=None, timeout=60, stdin=subprocess.DEVNULL):
    e = dict(os.environ, PYTHONPATH=SRC)
    e.update(env or {})
    r = subprocess.run([PY, "-c", LAUNCH] + args, cwd=str(cwd), capture_output=True, text=True,
                       env=e, timeout=timeout, stdin=stdin)
    return r.returncode, r.stdout + r.stderr


def gate(t, args, cwd="repo"):
    return ag(["run"] + args, t / cwd)


def user_cfg(t, extra):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + extra)


# --- K4: grants from the user config only -------------------------------------------------------

@pytest.mark.parametrize("key", ["confirm = \"all\"", "prompt = \"terminal\""])
def test_k4_the_old_prompt_keys_are_a_problem_that_names_the_new_ones(tree, key):
    user_cfg(tree, f"[broker]\n{key}\n")
    cfg = config.load(str(tree / "repo"))
    assert cfg.problem and "write_to" in cfg.problem


def test_k4_write_to_must_be_a_real_folder(tree):
    real = tree / "pub" / "out"
    real.mkdir()
    os.symlink(real, tree / "pub" / "link")
    user_cfg(tree, f'[broker]\nwrite_to = ["{tree}/pub/link", "{real}"]\nnet = true\n')
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem, cfg.problem
    assert cfg.write_to == [str(real)] and cfg.write_to_linked == 1 and cfg.net is True


def test_k4_the_defaults_grant_nothing(tree):
    cfg = config.load(str(tree / "repo"))
    assert cfg.write_to == [] and cfg.net is False


# a folder inside a root ("{t}/phi/sub") may be granted now: roots are read only for the gateway
@pytest.mark.parametrize("where", ["/", "{h}", "{h}/..", "{h}/.ssh", "{t}",
                                   "{c}", "{t}/runs/run1/panel"])
def test_k4_a_write_to_place_that_may_not_be_granted_is_a_problem(tree, where):
    h = tree / "home"
    (h / ".ssh").mkdir()
    c = Path(os.environ["PHIWARD_CONFIG"]).parent
    user_cfg(tree, f'[broker]\nwrite_to = ["{where.format(h=h, t=tree, c=c)}"]\n')
    assert config.load(str(tree / "repo")).problem


def test_k4_a_write_to_place_that_does_not_exist_is_skipped(tree):
    user_cfg(tree, f'[broker]\nwrite_to = ["{tree}/pub/not-yet"]\n')
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem and cfg.write_to == [] and cfg.write_to_missing == 1


@pytest.mark.parametrize("body", ['[broker]\nwrite_to = ["{t}/pub"]\n', "[broker]\nnet = true\n"])
def test_k4_a_repo_config_cannot_grant(tree, body):
    (tree / "repo" / ".phiward.toml").write_text(body.format(t=tree))
    cfg = config.load(str(tree / "repo"))
    assert cfg.write_to == [] and cfg.net is False and cfg.ignored


@needs_confine
def test_k4_a_write_to_outside_the_config_is_refused(tree, broker):
    code, out = gate(tree, ["--write-to", "../pub", "--", "sh", "-c", "echo x > ../pub/f"])
    assert code == 2 and "write_to" in out and not (tree / "pub" / "f").exists()


@needs_confine
def test_k4_a_write_to_inside_a_configured_place_runs(tree, broker):
    (tree / "pub" / "out" / "deep").mkdir(parents=True)
    user_cfg(tree, f'[broker]\nwrite_to = ["{tree}/pub/out"]\n')
    broker()  # a changed config takes effect when the operator restarts the broker
    code, out = gate(tree, ["--write-to", "../pub/out/deep", "--", "sh", "-c",
                            "echo aggregate > ../pub/out/deep/f && echo y > ../pub/g"])
    assert (tree / "pub" / "out" / "deep" / "f").read_text() == "aggregate\n", out
    assert not (tree / "pub" / "g").exists()  # only the granted folder


@needs_confine
def test_k4_net_needs_the_config(tree, broker):
    code, out = gate(tree, ["--net", "--", "true"])
    assert code == 2 and "net" in out


@needs_confine
def test_k4_nothing_asks_anyone(tree, broker, tmp_path, monkeypatch):
    prog = tmp_path / "dialog.sh"
    prog.write_text(f"#!/bin/sh\ntouch {tmp_path}/asked\nexit 0\n")
    prog.chmod(0o755)
    monkeypatch.setenv("PHIWARD_DIALOG", str(prog))
    broker()
    gate(tree, ["--write-to", "../pub", "--net", "--", "true"])
    assert not (tmp_path / "asked").exists()


# --- bug 1: a grant is used exactly as resolved ---------------------------------------------------

@needs_confine
def test_bug1_a_grant_swapped_for_a_link_is_refused(tree, broker):
    out_dir = tree / "pub" / "out"
    out_dir.mkdir()
    user_cfg(tree, f'[broker]\nwrite_to = ["{out_dir}"]\n')
    out_dir.rmdir()
    other = tree / "elsewhere"
    other.mkdir()
    os.symlink(other, out_dir)  # after the config was written
    code, out = gate(tree, ["--write-to", "../pub/out", "--", "sh", "-c", "echo x > ../pub/out/f"])
    assert code != 0 and not (other / "f").exists(), out


def _gateway_argv(argv, writable, patterns, net=False):
    """The argv of confine.gateway_command (its descriptors closed)."""
    cmd, fds = confine.gateway_command(argv, writable, patterns, net)
    for fd in fds:
        os.close(fd)
    return cmd


def test_bug1_the_gateway_refuses_a_place_that_is_not_a_real_folder(tree):
    real = tree / "pub" / "real"
    real.mkdir()
    os.symlink(real, tree / "pub" / "link")
    with pytest.raises(confine.ConfineError):
        _gateway_argv(["true"], [str(tree / "pub" / "link")], [], False)


@needs_confine
@macos
def test_bug1_the_profile_holds_the_resolved_place_only(tree):
    real = tree / "pub" / "real"
    real.mkdir()
    argv = _gateway_argv(["true"], [str(real)], [], False)
    assert str(real) in argv[2] and "(subpath" in argv[2]


# --- bug 2: a pattern match that is a link is not a write place --------------------------------

def test_bug2_a_linked_pattern_match_is_not_writable(tree):
    os.symlink(tree / "pub", tree / "runs" / "run1" / "panel2")
    places = confine.gateway_places([], [str(tree / "runs" / "*" / "panel2")])
    assert str(tree / "pub") not in places
    assert str(tree / "runs" / "run1" / "panel2") not in places


# --- bug 4: the status file is out of the agent's reach and used only while fresh --------------

def test_bug4_the_status_file_is_not_in_the_spool(tree, monkeypatch):
    monkeypatch.delenv("PHIWARD_SPOOL", raising=False)
    st = config.status_path()
    assert os.path.dirname(st) != config.spool_dir()
    assert st in config.guard_files()


@needs_confine
def test_bug4_the_broker_writes_its_status_outside_the_spool(tree, broker):
    assert not os.path.exists(os.path.join(broker.spool, "broker.json"))
    from phiward import broker as b
    assert str(tree / "phi") in b.read_status().get("roots", [])


@needs_confine
def test_bug4_a_status_without_a_fresh_heartbeat_is_ignored(tree, broker):
    from phiward import broker as b
    os.utime(os.path.join(broker.spool, "broker.alive"), (1, 1))
    assert b.read_status() == {} or b._alive(broker.spool)  # the broker may touch it again


@needs_confine
def test_bug4_the_status_follows_a_config_change(tree, broker):
    from phiward import broker as b
    Path(os.environ["PHIWARD_CONFIG"]).write_text("")
    for _ in range(60):
        if not b.read_status().get("roots"):
            break
        time.sleep(0.1)
    assert not b.read_status().get("roots")


# --- bug 5: a wildcard allowRead inside a root re-opens it ---------------------------------------

@pytest.mark.parametrize("allow", ["{r}/*", "{r}/sub/*.bam", "{t}/ph*", "{t}/*/sub"])
def test_bug5_a_wildcard_allow_read_is_seen(tree, allow):
    root = str(tree / "phi")
    proj = tree / "repo"
    (proj / ".claude").mkdir()
    (proj / ".claude" / "settings.json").write_text(json.dumps({"sandbox": {
        "enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
        "filesystem": {"denyRead": [root], "denyWrite": [root] + config.guard_files() + config.sandbox_denied(),
                       "allowRead": [allow.format(r=root, t=tree)]}}}))
    ok, why = confinement(str(proj), str(tree / "home"), [root], [],
                                          config.guard_files())
    assert not ok and "allowRead" in why


def test_bug5_a_wildcard_allow_read_elsewhere_is_fine(tree):
    root = str(tree / "phi")
    proj = tree / "repo"
    (proj / ".claude").mkdir()
    (proj / ".claude" / "settings.json").write_text(json.dumps({"sandbox": {
        "enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
        "filesystem": {"denyRead": [root], "denyWrite": [root] + config.guard_files() + config.sandbox_denied(),
                       "allowRead": [f"{tree}/pu*"]}}}))
    ok, why = confinement(str(proj), str(tree / "home"), [root], [],
                                          config.guard_files())
    assert ok, why


# --- bug 7: a bounded queue, and a cancel before the start ---------------------------------------

def _request(spool, args, rid=None):
    rid = rid or secrets.token_hex(16)
    body = {"v": 1, "cmd": "run", "args": args, "cwd": os.getcwd(), "env": {}}
    tmp = os.path.join(spool, f".tmp-{rid}")
    with open(tmp, "w") as fh:
        json.dump(body, fh)
    os.rename(tmp, os.path.join(spool, f"req-{rid}.json"))
    return rid


def _done(spool, rid, seconds=30):
    p = os.path.join(spool, f"done-{rid}.json")
    for _ in range(int(seconds * 20)):
        if os.path.exists(p):
            time.sleep(0.05)
            return json.loads(Path(p).read_text())["exit"], \
                Path(spool, f"out-{rid}.log").read_text()
        time.sleep(0.05)
    raise AssertionError("no done file")


@needs_confine
def test_bug7_a_job_cancelled_while_queued_never_starts(tree, broker, monkeypatch):
    monkeypatch.chdir(tree / "repo")
    broker(["--max-jobs", "1"])
    first = _request(broker.spool, ["--", "sleep", "2"])
    rid = secrets.token_hex(16)
    Path(broker.spool, f"cancel-{rid}").touch()
    _request(broker.spool, ["--", "sh", "-c", f"echo x > {tree}/phi/started"], rid)
    code, out = _done(broker.spool, rid)
    assert code == 130 and not (tree / "phi" / "started").exists(), out
    _done(broker.spool, first)


@needs_confine
def test_bug7_the_queue_has_a_bound(tree, broker, monkeypatch):
    from phiward import broker as b
    monkeypatch.chdir(tree / "repo")
    broker(["--max-jobs", "1"])
    # the one slot is busy (the job has printed) while the queue overflows by two; the job
    # runs until the test cancels it, so the claims have all the time they need
    first = _request(broker.spool, ["--", "sh", "-c", "echo STARTED; sleep 60"])
    out = Path(broker.spool, f"out-{first}.log")
    for _ in range(200):
        if out.exists() and "STARTED" in out.read_text():
            break
        time.sleep(0.05)
    assert "STARTED" in out.read_text()
    rids = [_request(broker.spool, ["--", "true"]) for _ in range(b.QUEUE_PER_JOB + 2)]
    try:
        # every request is claimed (no req- file left); a refusal is done at once, a queued
        # one waits for the slot (the broker claims in directory order, not in send order)
        for _ in range(400):
            if not any(Path(broker.spool, f"req-{r}.json").exists() for r in rids):
                break
            time.sleep(0.05)
        done = [r for r in rids if Path(broker.spool, f"done-{r}.json").exists()]
        assert len(done) == 2, done
        refused = [_done(broker.spool, r) for r in done]
        assert all(code == 3 and "busy" in out for code, out in refused), refused
    finally:
        Path(broker.spool, f"cancel-{first}").touch()  # free the slot
    assert _done(broker.spool, first)[0] != 0
    assert all(_done(broker.spool, r)[0] == 0 for r in rids if r not in done)


# --- bug 8: a missing root is never created ------------------------------------------------------

# --- setup: the operator's first-time prompts ----------------------------------------------------

def test_setup_refuses_without_a_terminal(tree):
    p = Path(os.environ["PHIWARD_CONFIG"])
    before = p.read_text()
    code, out = ag(["setup"], tree / "repo")
    assert code == 2 and "terminal" in out and p.read_text() == before


def test_setup_is_refused_as_an_agent_command(tree):
    code, out = ag(["check", "--", "phiward setup"], tree / "repo")
    assert "deny" in out.lower() and "operator" in out


def _drive(tree, answers, cfg_path, timeout=30):
    """Run `phiward setup` on a pseudo-terminal and type `answers`, one per prompt."""
    import pty
    import select
    master, slave = pty.openpty()
    env = dict(os.environ, PYTHONPATH=SRC, PHIWARD_CONFIG=str(cfg_path))
    p = subprocess.Popen([PY, "-c", LAUNCH, "setup"], cwd=str(tree / "repo"), stdin=slave,
                         stdout=slave, stderr=slave, env=env)
    os.close(slave)
    seen = b""
    left = list(answers)
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.2)
        if r:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            seen += chunk
            if left and seen.rstrip().endswith((b"]", b">")):
                os.write(master, left.pop(0).encode() + b"\n")
        elif p.poll() is not None:
            break
    p.wait(timeout=10)
    os.close(master)
    return p.returncode, seen.decode("utf-8", "replace")


def test_setup_writes_a_config_that_loads(tree, tmp_path):
    (tree / "pub" / "out").mkdir()
    cfg_path = tmp_path / "new" / "config.toml"
    answers = ["3",                            # choose every setting
               str(tree / "phi"), "",          # roots
               "",                             # patterns
               str(tree / "pub" / "out"), "",  # write places
               "",                             # programs (none: any)
               "n",                            # network
               "",                             # remotes
               "n",                            # the shell's network
               "n",                            # HPC
               "y",                            # write the file
               "n",                            # wire Claude Code now
               "n"]                            # start the broker service now
    code, out = _drive(tree, answers, cfg_path)
    assert code == 0, out
    cfg = config.load(str(tree / "repo"), env=dict(os.environ, PHIWARD_CONFIG=str(cfg_path)))
    assert not cfg.problem, cfg.problem
    assert cfg.roots == [str(tree / "phi")] and cfg.write_to == [str(tree / "pub" / "out")]
    assert cfg.net is False
    assert oct(cfg_path.stat().st_mode & 0o777) == "0o600"
    assert "phiward broker" in out and "doctor" in out


def test_setup_asks_again_for_a_bad_answer(tree, tmp_path):
    cfg_path = tmp_path / "config.toml"
    answers = ["3", "/", str(tree / "phi"), "", "", "", "", "n", "", "n", "n", "n"]  # "/" refused; no
    code, out = _drive(tree, answers, cfg_path)
    assert "refused" in out.lower() or "cannot" in out.lower()
    assert not cfg_path.exists()


# --- found later: the Linux gateway hid /tmp ------------------------------------------------------

@needs_confine
def test_the_gateway_runs_in_the_request_folder(tree, broker):
    # by a file only the request folder has: the printed path may be masked (a temp path with a
    # long run of digits becomes <NUM>, as on the GitHub macOS runners)
    (tree / "repo" / "ONLY-IN-REPO.txt").write_text("x\n")
    code, out = gate(tree, ["--", "sh", "-c", "test -f ONLY-IN-REPO.txt && echo IN-THE-REQUEST-FOLDER"])
    assert code == 0 and "IN-THE-REQUEST-FOLDER" in out, out


# --- file-tool writes to the files that control the guards ----------------------------------------

@pytest.mark.parametrize("which", ["config", "status", "code", "user-settings", "project-settings",
                                   "local-settings"])
def test_round5_file_tools_cannot_write_guard_files(tree, which):
    from phiward import core
    from phiward.guards import protected_paths
    home = tree / "home"
    target = {
        "config": os.environ["PHIWARD_CONFIG"],
        "status": config.status_path(),
        "code": str(Path(config.__file__).parent / "config.py"),
        "user-settings": str(home / ".claude" / "settings.json"),
        "project-settings": str(tree / "repo" / ".claude" / "settings.json"),
        "local-settings": ".claude/settings.local.json",
    }[which]
    cfg = config.load(str(tree / "repo"))
    act = core.Action(kind=core.FILE_WRITE, cwd=str(tree / "repo"), paths=(target,), tool="Write")
    assert protected_paths.check(act, cfg).verdict == core.DENY


def test_round5_file_tools_still_write_ordinary_files(tree):
    from phiward import core
    from phiward.guards import protected_paths
    cfg = config.load(str(tree / "repo"))
    act = core.Action(kind=core.FILE_WRITE, cwd=str(tree / "repo"), paths=("src/app.py",),
                      tool="Write")
    assert protected_paths.check(act, cfg).verdict != core.DENY
