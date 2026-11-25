"""Security review findings (third set), each as a test.

K1: the user config is the only source of what widens or changes the gateway.
K2: the command's environment is fixed by the broker; a grant is resolved once and granted as shown.
K3: the agent cannot draw on the operator's terminal (the prompts themselves are gone:
tests/test_round4.py).
B2-B10: the code bugs of the round.
"""

import json
import os
import subprocess
import sys
import time
import unicodedata
import uuid
from pathlib import Path

import pytest

from phiward import config, copying
from phiward.sanitize import Sanitizer
from helpers import confinement, needs_confine

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")

LAUNCH = ("import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; "
          "from phiward.cli import main; sys.exit(main())")


def ag(args, cwd, env=None, timeout=60):
    e = dict(os.environ, PYTHONPATH=SRC)
    e.update(env or {})
    r = subprocess.run([PY, "-c", LAUNCH] + args, cwd=str(cwd), capture_output=True, text=True,
                       env=e, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def gate(t, args, cwd="repo", env=None):
    return ag(["run"] + args, t / cwd, env)


def user_cfg(t, extra):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + extra)


# --- K1: one source of authority --------------------------------------------------------------

def test_k1_a_repo_config_cannot_add_copy_remotes(tree):
    (tree / "repo" / ".phiward.toml").write_text('[copy]\nremotes = ["evil:/"]\n')
    cfg = config.load(str(tree / "repo"))
    assert cfg.remotes == []
    why = copying.plan([str(tree / "phi" / "FAKE-PT-0001.bam"), "evil:/x"], str(tree / "repo"), cfg)
    assert why is not None


@pytest.mark.parametrize("body", [
    '[sanitize]\npatterns = ["zzzz => <MRN99887>"]\n',
    '[sanitize]\nnames_from = ["/etc/hosts"]\n',
    '[sanitize]\npacks = ["/tmp/agent-made-pack.toml"]\n',
    '[sanitize]\ninventory_limit = 5\n',  # lowering stays allowed; it is checked below
])
def test_k1_a_repo_config_cannot_change_the_sanitizer(tree, body):
    (tree / "repo" / ".phiward.toml").write_text(body)
    cfg = config.load(str(tree / "repo"))
    assert cfg.problem == ""
    assert cfg.sanitize_patterns == [] and cfg.names_from == []
    assert all("/" not in p for p in cfg.packs)
    if "inventory_limit" in body:
        assert cfg.inventory_limit == 5


def test_k1_a_built_in_pack_from_a_repo_is_kept(tree):
    (tree / "repo" / ".phiward.toml").write_text('[sanitize]\npacks = ["msk"]\n')
    assert "msk" in config.load(str(tree / "repo")).packs


def test_k1_rule_placeholders_never_exempt_an_entry_name(tree):
    (tree / "phi" / "MRN99887.txt").write_text("x\n")
    user_cfg(tree, '[sanitize]\npatterns = ["zzzz => <MRN99887>"]\n')  # even from the user file
    san = Sanitizer.from_config(config.load(str(tree / "repo")), entries=True)
    assert san.clean("see MRN99887 here") == "see <ENTRY> here"


def test_k1_doctor_lists_what_a_repo_config_may_not_set(tree):
    (tree / "repo" / ".phiward.toml").write_text('[copy]\nremotes = ["evil:/"]\n')
    code, out = ag(["doctor"], tree / "repo")
    assert "ignored" in out and "copy.remotes" in out


# --- K2: a fixed environment, grants resolved once ---------------------------------------------

@needs_confine
def test_k2_the_request_environment_does_not_reach_the_command(tree, broker):
    code, out = gate(tree, ["--", "env"], env={"BASH_ENV": "/x/y", "RSYNC_RSH": "evil",
                                               "GIT_SSH_COMMAND": "evil", "PYTHONSTARTUP": "/x"})
    assert code == 0, out
    for k in ("BASH_ENV", "RSYNC_RSH", "GIT_SSH_COMMAND", "PYTHONSTARTUP"):
        assert k not in out


@needs_confine
def test_k2_the_program_comes_from_the_operators_path(tree, broker):
    fake = tree / "repo" / "bin"
    fake.mkdir()
    (fake / "ls").write_text("#!/bin/sh\necho FAKE-LS-RAN\n")
    (fake / "ls").chmod(0o755)
    code, out = gate(tree, ["--", "ls", "."], env={"PATH": f"{fake}:{os.environ['PATH']}"})
    assert "FAKE-LS-RAN" not in out


@needs_confine
def test_k2_a_grant_is_granted_resolved(tree, broker):
    real = tree / "pub" / "real"
    real.mkdir()
    user_cfg(tree, f'[broker]\nwrite_to = ["{real}"]\n')
    broker()  # a changed config takes effect when the operator restarts the broker
    os.symlink(real, tree / "repo" / "out")
    code, out = gate(tree, ["--write-to", "out", "--", "sh", "-c", "echo x > out/f"])
    assert code == 0, out
    assert (real / "f").exists()


@needs_confine
@pytest.mark.parametrize("where", ["home", "home/.ssh", "config"])
def test_k2_a_grant_to_a_home_or_guard_folder_is_refused(tree, broker, where):
    target = tree / "home" if where == "home" else (
        tree / "home" / ".ssh" if where == "home/.ssh" else Path(os.environ["PHIWARD_CONFIG"]).parent)
    target.mkdir(exist_ok=True)
    code, out = gate(tree, ["--write-to", str(target), "--", "true"])
    assert code == 2 and "refused" in out


# --- K3: the operator's terminal ---------------------------------------------------------------

# --- B2 to B10 ---------------------------------------------------------------------------------

@pytest.mark.parametrize("name,shown", [
    (unicodedata.normalize("NFD", "JoséFake99.txt"), "JoséFake99"),  # macOS spelling
    ("ＡＢＣＤＥＦ.txt", "ABCDEF"),                  # full-width letters
])
def test_b2_entry_names_are_normalized_like_lines(tree, name, shown):
    (tree / "phi" / name).write_text("x\n")
    san = Sanitizer.from_config(config.load(str(tree / "repo")), entries=True)
    assert shown.lower() not in san.clean(f"see {shown} here").lower()


def _settings(t, fs, level="user"):
    path = (t / "home" / ".claude" / "settings.json") if level == "user" else \
        (t / "repo" / ".claude" / "settings.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"sandbox": {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
                                            "filesystem": fs}}))


def _confined(t):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(f'[protected_paths]\nroots = ["{t}/phi"]\n')
    cfg = config.load(str(t / "repo"))
    return confinement(str(t / "repo"), str(t / "home"), cfg.all_roots,
                                       cfg.patterns, config.guard_files())


def _full(t):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(f'[protected_paths]\nroots = ["{t}/phi"]\n')
    cfg = config.load(str(t / "repo"))
    return list(cfg.all_roots), list(cfg.all_roots) + config.guard_files() + config.sandbox_denied()


@pytest.mark.parametrize("allow", ["{t}/phi/sub", "{t}/phi", "{t}"])
def test_b3_an_allow_read_inside_the_denied_area_breaks_confinement(tree, allow):
    deny, deny_w = _full(tree)
    _settings(tree, {"denyRead": [str(tree)] + deny, "denyWrite": deny_w,
                     "allowRead": [allow.format(t=tree)]})
    ok, why = _confined(tree)
    if allow == "{t}":  # wider than the exact deny of the root: the deny holds
        assert ok, why
    else:
        assert not ok and "allowRead" in why


def test_b4_a_relative_user_entry_is_relative_to_the_user_folder(tree):
    deny, deny_w = _full(tree)
    rel = os.path.relpath(str(tree / "phi"), str(tree / "repo"))  # relative to the repo, not ~/.claude
    _settings(tree, {"denyRead": [rel] + [d for d in deny if d != str(tree / "phi")],
                     "denyWrite": deny_w})
    ok, why = _confined(tree)
    assert not ok and "denyRead" in why


@needs_confine
def test_b8_the_heartbeat_continues_while_every_slot_is_busy(tree, broker):
    p = broker(args=["--max-jobs", "1"])
    rids = []
    for _ in range(2):
        rid = uuid.uuid4().hex
        rids.append(rid)
        tmp = os.path.join(broker.spool, f".tmp-{rid}")
        with open(tmp, "w") as fh:
            json.dump({"v": 1, "cmd": "run", "cwd": str(tree / "repo"), "env": {},
                       "args": ["--", "sh", "-c", "echo STARTED; sleep 15"]}, fh)
        os.rename(tmp, os.path.join(broker.spool, f"req-{rid}.json"))
    try:
        # one job runs (it has printed) and the other waits for the one slot (claimed, not done)
        def started():
            out = [os.path.join(broker.spool, f"out-{r}.log") for r in rids]
            return [n for n in range(2) if os.path.exists(out[n]) and "STARTED" in open(out[n]).read()]

        def claimed(n):
            return os.path.exists(os.path.join(broker.spool, f"job-{rids[n]}.json"))
        # the broker may list the spool between the two renames: then the first job can start
        # before the next pass claims the second, so wait for both
        for _ in range(200):
            s = started()
            if len(s) == 1 and claimed(1 - s[0]):
                break
            time.sleep(0.05)
        assert len(started()) == 1, started()
        waiting = rids[1 - started()[0]]
        assert os.path.exists(os.path.join(broker.spool, f"job-{waiting}.json"))
        # the heartbeat goes on: broker.alive is touched again, twice (HEARTBEAT is 1 s)
        alive = os.path.join(broker.spool, "broker.alive")
        seen = {os.stat(alive).st_mtime}
        for _ in range(200):
            seen.add(os.stat(alive).st_mtime)
            if len(seen) >= 3:
                break
            time.sleep(0.05)
        assert len(seen) >= 3 and p.poll() is None, seen
        assert not any(os.path.exists(os.path.join(broker.spool, f"done-{r}.json")) for r in rids)
        age = time.time() - os.stat(alive).st_mtime
        assert age < 5
    finally:
        for r in rids:  # no `sleep 15` outlives the test
            open(os.path.join(broker.spool, f"cancel-{r}"), "w").close()


@needs_confine
def test_b9_a_huge_line_is_withheld_not_buffered(tree, broker):
    code, out = gate(tree, ["--", PY, "-c",
                            "import sys; sys.stdout.write('A' * 3000000); print(); print('after')"])
    assert "withheld" in out and "after" in out and len(out) < 100000


def test_b10_remote_names_are_read_as_rsync_reads_them(tree):
    # a name that exists in the request folder used to count as local,
    # while rsync still read it as remote; a local name with a ":" is written "./name"
    (tree / "repo" / "host:" / "x").mkdir(parents=True)
    assert copying._is_remote("host:/x") is True
    assert copying._is_remote("./host:/x") is False


def test_b11_doctor_reports_a_different_broker_view(tree, broker, tmp_path):
    empty = tmp_path / "empty.toml"
    empty.write_text("")
    code, out = ag(["doctor"], tree / "repo", env={"PHIWARD_CONFIG": str(empty)})
    assert "the broker uses the user config" in out
