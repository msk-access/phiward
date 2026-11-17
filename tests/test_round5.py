"""Security review findings (fifth set), each as a test.

K5: one path, one meaning: the same matcher everywhere; files the trusted side reads are opened
safely and never quoted to the agent; Linux write places are bound by descriptor.
K6: what the trusted side reads or runs is out of the agent's reach.
Bugs: a done file for every refusal; request checks off the main loop; Seatbelt pattern spellings.
"""

import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import pytest

from phiward import config, confine, core, pathmatch
from phiward.guards import protected_paths
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
                       env=e, timeout=timeout, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


def user_cfg(t, extra):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + extra)


def set_patterns(t, pats):
    p = Path(os.environ["PHIWARD_CONFIG"])
    s = p.read_text()
    old = s.split("patterns = ", 1)[1].split("\n", 1)[0]
    p.write_text(s.replace(old, json.dumps(pats)))


# --- K5: one matcher --------------------------------------------------------------------------

def test_k5_the_matcher_handles_dot_names(tree):
    (tree / "data" / "FAKE-PT-7").mkdir(parents=True)
    (tree / "data" / ".FAKE-PT-8").mkdir()
    got = sorted(os.path.basename(m) for m in pathmatch.matches(f"{tree}/data/*"))
    assert ".FAKE-PT-8" in got and "FAKE-PT-7" in got  # glob would skip the dot-name


@pytest.mark.parametrize("pat,path,hit", [
    ("/a/*x", "/a/7x", True), ("/a/*x", "/a/x7", False), ("/a/*/p", "/a/.h/p", True),
    ("/a/b*", "/a/b", True), ("/a/*", "/a/b/c", False),
])
def test_k5_the_regex_and_the_matcher_agree(pat, path, hit):
    import re
    rx = re.compile(pathmatch.regex(pat) + "$")
    assert bool(rx.match(path)) is hit
    assert pathmatch.match_path(pat, path) is hit


@needs_confine
def test_k5_names_under_a_dot_named_match_are_masked(tree, broker):
    d = tree / "runs" / ".FAKE-PT-0007" / "panel"
    d.mkdir(parents=True)
    (d / "FAKE-SAMPLE-AAAA.txt").write_text("x\n")
    code, out = ag(["run", "--", "ls", str(d)], tree / "repo")
    assert "FAKE-SAMPLE-AAAA" not in out, out


@macos
def test_k5_an_allow_read_in_another_case_re_opens_the_root(tree):
    root = str(tree / "phi")
    proj = tree / "repo"
    (proj / ".claude").mkdir()
    (proj / ".claude" / "settings.json").write_text(json.dumps({"sandbox": {
        "enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
        "filesystem": {"denyRead": [root], "denyWrite": [root] + config.guard_files(),
                       "allowRead": [root.upper() + "/sub"]}}}))
    ok, why = confinement(str(proj), str(tree / "home"), [root], [],
                                          config.guard_files())
    assert not ok and "allowRead" in why


# --- K5: files the trusted side reads -----------------------------------------------------------

def test_k5_a_repo_config_that_is_a_link_is_refused_and_not_quoted(tree):
    (tree / "phi" / "x.toml").write_text("[FAKE-PT-0001-tumor]\n")
    os.symlink(tree / "phi" / "x.toml", tree / "repo" / ".phiward.toml")
    cfg = config.load(str(tree / "repo"))
    assert cfg.problem and "FAKE-PT" not in cfg.problem


def test_k5_repo_config_errors_do_not_quote_the_file(tree):
    (tree / "repo" / ".phiward.toml").write_text("[FAKE-PT-0001-tumor]\n")
    cfg = config.load(str(tree / "repo"))
    assert cfg.problem and "FAKE-PT" not in cfg.problem
    act = core.Action(kind=core.SHELL, cwd=str(tree / "repo"), command="ls")
    assert "FAKE-PT" not in protected_paths.check(act, cfg).reason


def test_k5_a_repo_config_that_is_a_fifo_does_not_block(tree):
    os.mkfifo(tree / "repo" / ".phiward.toml")
    t = time.time()
    cfg = config.load(str(tree / "repo"))
    assert time.time() - t < 5 and cfg.problem


def test_k5_a_names_file_that_is_a_fifo_does_not_block(tree):
    fifo = tree / "repo" / "names.fifo"
    os.mkfifo(fifo)
    cfg = config.load(str(tree / "repo"))
    t = time.time()
    with pytest.raises(Exception):
        Sanitizer.from_config(cfg, [str(fifo)], entries=False)
    assert time.time() - t < 5


def test_k5_a_names_file_inside_a_root_is_readable_but_a_link_out_is_not(tree):
    cfg = config.load(str(tree / "repo"))
    (tree / "phi" / "names.txt").write_text("1\t/x/FAKE-NAME-ZZZZ.bam\n")
    san = Sanitizer.from_config(cfg, [str(tree / "phi" / "names.txt")], entries=False)
    assert "FAKE-NAME-ZZZZ" not in san.clean("a FAKE-NAME-ZZZZ b")
    os.symlink(tree / "phi" / "names.txt", tree / "repo" / "n.txt")
    with pytest.raises(Exception):
        Sanitizer.from_config(cfg, [str(tree / "repo" / "n.txt")], entries=False)


# --- K5: Linux places bound by descriptor -------------------------------------------------------

@linux
def test_k5_linux_places_are_bound_by_descriptor(tree):
    out = tree / "pub" / "out"
    out.mkdir()
    argv, fds = confine.gateway_command(["true"], [str(out)], [], False)
    try:
        assert any(a.startswith("/proc/self/fd/") for a in argv), argv
    finally:
        for fd in fds:
            os.close(fd)


# --- K6: the trusted side's inputs --------------------------------------------------------------

def test_k6_guard_files_hold_the_interpreter_and_launcher():
    g = config.guard_files()
    assert os.path.realpath(sys.prefix) in g


def test_k6_a_remote_copy_uses_a_fixed_ssh(tree):
    # remote copies use the system ssh only (no rsync), with fixed options
    from phiward import remote
    cfg = config.load(str(tree / "repo"))
    cmd = remote.ssh_command(cfg)
    assert cmd[0].startswith("/") and "-F" in cmd and "ProxyCommand=none" in cmd
    assert "ForwardAgent=no" in cmd


def test_k6_the_ssh_config_is_user_only_and_a_guard_file(tree):
    sshc = tree / "home" / "ag-ssh-config"
    sshc.write_text("Host cluster\n  HostName 127.0.0.1\n")
    user_cfg(tree, f'[copy]\nssh_config = "{sshc}"\n')
    cfg = config.load(str(tree / "repo"))
    assert cfg.ssh_config == str(sshc)
    assert str(sshc) in config.guard_files()
    (tree / "repo" / ".phiward.toml").write_text('[copy]\nssh_config = "/tmp/x"\n')
    assert config.load(str(tree / "repo")).ssh_config == str(sshc)


@needs_confine
@macos
def test_k6_the_gateway_cannot_write_claude_settings(tree, broker):
    proj = tree / "pub" / "proj"
    proj.mkdir(parents=True)
    user_cfg(tree, f'[broker]\nwrite_to = ["{tree}/pub"]\n')
    ag(["run", "--write-to", str(proj), "--", "sh", "-c",
        f"mkdir -p {proj}/.claude && echo x > {proj}/.claude/settings.json"], tree / "repo")
    assert not (proj / ".claude" / "settings.json").exists()


def test_k6_a_write_to_that_holds_a_claude_folder_is_skipped(tree):
    (tree / "pub" / "proj" / ".claude").mkdir(parents=True)
    user_cfg(tree, f'[broker]\nwrite_to = ["{tree}/pub/proj"]\n')
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem and cfg.write_to == [] and cfg.write_to_claude == 1


# --- sixth set ------------------------------------------------------------------------------------

def test_round6_a_relative_ssh_config_is_a_problem(tree):
    user_cfg(tree, '[copy]\nssh_config = "ssh.conf"\n')
    assert config.load(str(tree / "repo")).problem


def test_round6_the_launcher_link_on_path_is_a_guard_file(tree, monkeypatch):
    bindir = tree / "home" / ".local" / "bin"
    bindir.mkdir(parents=True)
    real = tree / "tool" / "bin"
    real.mkdir(parents=True)
    (real / "phiward").write_text("#!/bin/sh\n")
    (real / "phiward").chmod(0o755)
    os.symlink(real / "phiward", bindir / "phiward")
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    g = config.guard_files()
    assert str(bindir / "phiward") in g and str(real / "phiward") in g


def test_round6_pack_files_are_not_read_through_a_link(tree):
    from phiward.sanitize import SanitizerError, load_pack
    src = Path(__file__).resolve().parents[1] / "src" / "phiward" / "packs" / "genomics.toml"
    link = tree / "repo" / "pack.toml"
    os.symlink(src, link)
    with pytest.raises(SanitizerError):
        load_pack(str(link))


# --- bugs ----------------------------------------------------------------------------------------

def _raw_request(spool, body):
    rid = secrets.token_hex(16)
    tmp = os.path.join(spool, f".tmp-{rid}")
    with open(tmp, "w") as fh:
        json.dump(body, fh)
    os.rename(tmp, os.path.join(spool, f"req-{rid}.json"))
    return rid


@needs_confine
@pytest.mark.parametrize("body", [
    {"v": 1, "cmd": "run", "args": ["--", "true"], "cwd": "/no/such/folder", "env": {}},
    {"v": 9, "cmd": "run", "args": [], "cwd": "/", "env": {}},
])
def test_bug_every_refusal_writes_a_done_file(tree, broker, body):
    rid = _raw_request(broker.spool, body)
    done = os.path.join(broker.spool, f"done-{rid}.json")
    for _ in range(100):
        if os.path.exists(done):
            break
        time.sleep(0.05)
    assert os.path.exists(done) and json.loads(Path(done).read_text())["exit"] == 3


@macos
def test_bug_the_seatbelt_gateway_pattern_rule_has_both_spellings(tmp_path):
    prof = confine.seatbelt_gateway_profile([], ["/tmp/agt-x/*/panel"], False)
    assert "/private/tmp/agt-x" in prof
