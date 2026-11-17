"""Round 18f: the review rev18f of d271fb9: how a requested program is matched against `[broker] commands`
and which file is started. Every test asserts the INTENDED invariant, so a failing test marks a
place where the invariant does not hold. Made-up trees only (the suite's `tree` fixture).

Written by the review in a Linux container; part of the suite since round 18f.
"""
import io
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from helpers import needs_confine


def _cfg(tree, commands, extra=""):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/phi"]\n[broker]\ncommands = {commands}\n{extra}')


def _script(p, text, interp="/bin/sh"):
    p.write_text(f"#!{interp}\n{text}\n")
    p.chmod(0o755)
    return p


def _fake_confined(seen, before=None):
    """Stands for run_confined: records the argv, then starts it (as the kernel would)."""
    def run_confined(cmd, *a, **k):
        seen.append(list(cmd))
        if before:
            before()
        r = subprocess.run(cmd, capture_output=True, text=True)
        seen.append(r.stdout)
        return r.returncode
    return run_confined


def _run(tree, monkeypatch, word, cwd=None, before=None, args=("x",)):
    from phiward import run
    seen = []
    monkeypatch.setattr(run, "run_confined", _fake_confined(seen, before))
    out = io.StringIO()
    code = run.execute(["--", word, *args], str(cwd or tree / "repo"), dict(os.environ), out)
    return code, seen, out.getvalue()


def _approved_paths():
    from phiward import pin
    return {r.split("  ", 1)[1] for r in pin.read_approved()}


# =================================================================================================
# Invariant 1: the file that is started is one the user config lists
# =================================================================================================

def test_inv1_a_bare_name_runs_only_by_that_name(tree, monkeypatch):
    d = tree / "opbin"
    d.mkdir()
    _script(d / "wc", "echo REAL-WC")
    monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
    _cfg(tree, '["wc"]')
    code, seen, _ = _run(tree, monkeypatch, "wc")
    assert code == 0 and seen[0][0] == str(d / "wc") and "REAL-WC" in seen[1]
    # the same file by its path, by a relative path, by a link of the agent's: never
    os.symlink(str(d / "wc"), str(tree / "repo" / "wc"))
    _script(tree / "repo" / "src" / "wc", "echo AGENT")
    for word in (str(d / "wc"), "./wc", "src/wc", "src/../wc", f"{tree}/repo/../opbin/wc"):
        code, seen, _ = _run(tree, monkeypatch, word)
        assert code == 2 and not seen, word


def test_inv1_a_path_entry_starts_exactly_the_file_it_names(tree, monkeypatch):
    """FAILS at d271fb9. An entry with `..` after a link: the kernel (and realpath, which the
    match and the approval use) reads `link/../tool` as the file beside the link's TARGET;
    `os.path.normpath` (run.py, the path that is started) reads it as the file beside the LINK.
    The file that starts is then neither the one matched nor the one approved."""
    from phiward import pin, config
    op = tree / "op"
    (op / "real" / "sub").mkdir(parents=True)
    os.symlink(str(op / "real" / "sub"), str(op / "current"))      # op/current -> op/real/sub
    _script(op / "real" / "tool", "echo LISTED-AND-APPROVED")       # = op/current/../tool
    _script(op / "tool", "echo NEVER-LISTED")                       # = normpath of the entry
    entry = f"{op}/current/../tool"
    assert os.path.realpath(entry) == str(op / "real" / "tool")
    _cfg(tree, f'["{entry}"]')
    # round 18f: a path entry with a link (or `..` after one) on it lists nothing: what would
    # be checked and what would start could differ; `pin` says so, and the broker refuses
    assert any("a link" in line for line in pin.describe(config.load("/")))
    assert pin.unapproved(config.load("/"))
    code, seen, _ = _run(tree, monkeypatch, str(op / "real" / "tool"))
    assert code == 2 and not seen, seen


def test_inv1_a_folder_entry_runs_only_names_of_that_folder(tree, monkeypatch):
    d = tree / "pipelines" / "bin"
    (d / "helpers").mkdir(parents=True)
    _script(d / "count", "echo REAL-COUNT")
    _script(d / "helpers" / "inner", "echo INNER")
    _cfg(tree, f'["{d}/"]')
    repo = tree / "repo"
    os.symlink(str(d), str(repo / "dirlink"))                  # a folder link of the agent's
    os.symlink(str(d / "count"), str(repo / "filelink"))       # a file link of the agent's
    _script(repo / "evil", "echo AGENT")
    os.symlink(str(repo), str(repo / "src" / "up"))
    for word in (str(d / "count"), "dirlink/count", f"{d}/helpers/../count",
                 f"{tree}/pipelines/./bin/count"):
        code, seen, _ = _run(tree, monkeypatch, word)
        assert code == 0 and seen[0][0] == str(d / "count") and "REAL-COUNT" in seen[1], word
    for word in ("./filelink", "./evil", "src/up/evil", f"{d}/../../repo/evil",
                 f"{d}/helpers/inner", f"{d}/count/", f"{d}/.."):
        code, seen, _ = _run(tree, monkeypatch, word)
        assert code in (2, 127) and not seen, word

    def swap():  # the agent's folder link changes between the check and the start
        os.unlink(str(repo / "dirlink"))
        os.symlink(str(repo), str(repo / "dirlink"))
        _script(repo / "count", "echo AGENT")
    code, seen, _ = _run(tree, monkeypatch, "dirlink/count", before=swap)
    assert seen[0][0] == str(d / "count") and "REAL-COUNT" in seen[1]


def test_inv1_a_link_to_a_folder_inside_a_listed_folder_is_not_a_way_out(tree, monkeypatch):
    d = tree / "pipelines" / "bin"
    d.mkdir(parents=True)
    other = tree / "otherbin"
    other.mkdir()
    _script(other / "sh", "echo OTHER")
    os.symlink(str(other), str(d / "sub"))
    _cfg(tree, f'["{d}/"]')
    code, seen, _ = _run(tree, monkeypatch, f"{d}/sub/sh")
    assert code == 2 and not seen


def test_inv1_each_listed_link_to_a_multi_call_program_acts_as_its_own_name(tree, monkeypatch):
    """FAILS at d271fb9. Two path entries that are links to one multi-call program: the first
    entry of the list answers for both, so `…/cat` runs as `ls`. (The docs: a path entry
    "acts as the listed name".)"""
    b = tree / "bin"
    b.mkdir()
    u = tree / "usrbin"
    u.mkdir()
    _script(b / "busybox", 'echo "APPLET=$(basename "$0")"')
    os.symlink(str(b / "busybox"), str(u / "ls"))
    os.symlink(str(b / "busybox"), str(u / "cat"))
    # round 18f: links are listed by name (found on the broker's PATH), each acts as its name
    monkeypatch.setenv("PATH", f"{u}:{os.environ['PATH']}")
    _cfg(tree, '["ls", "cat"]')
    code, seen, _ = _run(tree, monkeypatch, "ls")
    assert "APPLET=ls" in seen[1]
    code, seen, _ = _run(tree, monkeypatch, "cat")
    assert "APPLET=cat" in seen[1], seen
    code, seen, _ = _run(tree, monkeypatch, str(u / "cat"))
    assert code == 2 and not seen, seen


def test_inv1_tilde_entries(tree, monkeypatch):
    d = tree / "home" / "pipelines" / "bin"
    d.mkdir(parents=True)
    _script(d / "count", "echo REAL-COUNT")
    _script(tree / "home" / "one", "echo ONE")
    _cfg(tree, '["~/pipelines/bin/", "~/one"]')
    code, seen, _ = _run(tree, monkeypatch, str(d / "count"))
    assert code == 0 and seen[0][0] == str(d / "count")
    code, seen, _ = _run(tree, monkeypatch, str(tree / "home" / "one"))
    assert code == 0 and seen[0][0] == str(tree / "home" / "one")


# =================================================================================================
# Invariant 2: a project's list only narrows; it never decides which file starts
# =================================================================================================

def test_inv2_a_repo_list_cannot_add_a_program(tree, monkeypatch):
    d = tree / "opbin"
    d.mkdir()
    _script(d / "wc", "echo REAL-WC")
    monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
    _cfg(tree, '["wc"]')
    repo = tree / "repo"
    _script(repo / "evil", "echo AGENT")
    (repo / ".phiward.toml").write_text(
        f'[broker]\ncommands = ["wc", "{repo}/evil", "{repo}/", "@genomics", "sh"]\n')
    for word in ("./evil", str(repo / "evil"), "sh", "head"):
        code, seen, _ = _run(tree, monkeypatch, word)
        assert code == 2 and not seen, word
    code, seen, _ = _run(tree, monkeypatch, "wc")
    assert code == 0 and seen[0][0] == str(d / "wc")


def test_inv2_a_repo_list_narrows(tree, monkeypatch):
    d = tree / "opbin"
    d.mkdir()
    _script(d / "wc", "echo REAL-WC")
    _script(d / "du", "echo REAL-DU")
    monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
    _cfg(tree, '["wc", "du"]')
    (tree / "repo" / ".phiward.toml").write_text('[broker]\ncommands = ["wc"]\n')
    assert _run(tree, monkeypatch, "wc")[0] == 0
    assert _run(tree, monkeypatch, "du")[0] == 2


def test_inv2_the_started_path_is_the_user_entrys_with_both_lists(tree, monkeypatch):
    d = tree / "pipelines" / "bin"
    d.mkdir(parents=True)
    _script(d / "count", "echo REAL-COUNT")
    _cfg(tree, f'["{d}/"]')
    repo = tree / "repo"
    _script(repo / "evil", "echo AGENT")
    os.symlink(str(d), str(repo / "d"))
    os.symlink(str(d / "count"), str(repo / "x"))
    # the repo list comes in any order relative to the user list: it is still not the chooser
    (repo / ".phiward.toml").write_text(f'[broker]\ncommands = ["{repo}/x", "{repo}/d/"]\n')

    def swap():
        os.unlink(str(repo / "x"))
        os.symlink(str(repo / "evil"), str(repo / "x"))
        os.unlink(str(repo / "d"))
        os.symlink(str(repo), str(repo / "d"))
        _script(repo / "count", "echo AGENT")
    code, seen, _ = _run(tree, monkeypatch, "d/count", before=swap)
    assert code == 0 and seen[0][0] == str(d / "count") and "REAL-COUNT" in seen[1], seen


def test_inv2_with_no_user_list_a_repo_list_does_not_choose_the_path(tree, monkeypatch):
    """FAILS at d271fb9 (by the letter; no gain for the agent, since without a user list any
    program runs). With no list in the user config, the path that starts is the repo entry's:
    here a link of the agent's, changed after the check."""
    Path(os.environ["PHIWARD_CONFIG"]).write_text(f'[protected_paths]\nroots = ["{tree}/phi"]\n')
    d = tree / "opbin"
    d.mkdir()
    _script(d / "count", "echo REAL-COUNT")
    repo = tree / "repo"
    _script(repo / "evil", "echo AGENT")
    os.symlink(str(d / "count"), str(repo / "x"))
    (repo / ".phiward.toml").write_text(f'[broker]\ncommands = ["{repo}/x"]\n')

    def swap():
        os.unlink(str(repo / "x"))
        os.symlink(str(repo / "evil"), str(repo / "x"))
    code, seen, _ = _run(tree, monkeypatch, str(d / "count"), before=swap)
    # the repo entry is a link, so it lists nothing: refused, and never the agent's file
    assert not any("AGENT" in str(x) for x in seen), seen


# =================================================================================================
# Invariant 3: the file that starts is the file whose content the operator approved
# =================================================================================================

def _stub_broker():
    """A Broker as `Broker.__init__` makes it, without a spool."""
    from phiward import broker, config, pin

    class _Spool:
        def exists(self, name):
            return False
    b = object.__new__(broker.Broker)
    b.spool, b.log = _Spool(), io.StringIO()
    b.config_print = broker.config_print()
    b.unapproved = pin.unapproved(config.load("/"))
    return b


def test_inv3_a_changed_program_is_refused(tree, monkeypatch):
    from phiward import config, pin
    d = tree / "opbin"
    d.mkdir()
    _script(d / "count", "echo REAL-COUNT")
    hb = tree / "hbbin"
    hb.mkdir()
    cellar = tree / "Cellar"
    cellar.mkdir()
    _script(cellar / "samtools", "echo SAM-1")
    os.symlink("../Cellar/samtools", str(hb / "samtools"))
    _cfg(tree, f'["{d}/count", "{hb}/"]')
    pin.write_pins(config.load("/"))
    assert pin.unapproved(config.load("/")) == []
    b = _stub_broker()
    out = io.StringIO()
    seen = []
    from phiward import run
    monkeypatch.setattr(run, "run_confined", _fake_confined(seen))
    body = {"cmd": "run", "args": ["--", str(hb / "samtools"), "x"], "cwd": str(tree / "repo")}
    assert b.execute("r" * 16, body, out) == 0 and "SAM-1" in seen[1]
    # while the broker runs: the target of the folder's link is rewritten
    time.sleep(0.02)
    _script(cellar / "samtools", "echo SAM-2")
    out = io.StringIO()
    assert b.execute("r" * 16, body, out) == 3 and "changed" in out.getvalue()
    # while the broker is stopped: the restart does not accept it
    assert pin.unapproved(config.load("/")) == [str(hb / "samtools")]
    # a new file in a listed folder is not approved either
    pin.write_pins(config.load("/"))
    _script(hb / "extra", "echo EXTRA")
    assert pin.unapproved(config.load("/")) == [str(hb / "extra")]


def test_inv3_a_listed_link_changed_between_the_check_and_the_start(tree, monkeypatch):
    """FAILS at d271fb9. A path entry that is a link (documented: "when it is a link to a
    multi-call program…") in a folder the agent can write. Only the link's target is a guard
    place (config.command_paths: the real path), not the link. The broker checks approval at
    its start and identity at the top of each request; the link is read again later
    (`_entry_run_path`), and once more by the kernel. A link changed after the request's check
    starts a file that was never approved."""
    from phiward import config, pin, run
    op = tree / "opbin"
    op.mkdir()
    _script(op / "tool", "echo APPROVED")
    shared = tree / "repo" / "tools"
    shared.mkdir()
    os.symlink(str(op / "tool"), str(shared / "tool"))
    _script(tree / "repo" / "evil", "echo AGENT-CODE")
    _cfg(tree, f'["{shared}/tool"]')
    cfg = config.load("/")
    pin.write_pins(cfg)
    # round 18f: a path entry that is a link is never approved; the broker refuses every request
    b = _stub_broker()
    assert b.unapproved
    real_load = config.load

    def load(cwd, *a, **k):
        if cwd != "/":  # run.execute's load: after Broker.execute's two checks passed
            os.unlink(str(shared / "tool"))
            os.symlink(str(tree / "repo" / "evil"), str(shared / "tool"))
        return real_load(cwd, *a, **k)
    monkeypatch.setattr(config, "load", load)
    seen = []
    monkeypatch.setattr(run, "run_confined", _fake_confined(seen))
    out = io.StringIO()
    body = {"cmd": "run", "args": ["--", str(tree / "repo" / "evil")], "cwd": str(tree / "repo")}
    code = b.execute("r" * 16, body, out)
    started = seen[1] if seen else ""
    assert "AGENT-CODE" not in started, (code, seen)


# round 18f: a listed script's `#!` interpreter is not part of what is approved; this is stated
# in docs/configuration.md (list an interpreter you own and keep it where the agent cannot write)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every file")
def test_inv3_a_program_the_broker_cannot_read_is_not_approved_by_default(tree, monkeypatch):
    """FAILS at d271fb9. pin.program_record writes `missing  PATH` both for "not installed" and
    for "cannot be read" (an execute-only program, mode 0111). That record equals itself, so
    such a program counts as approved whatever its content, and a replaced one is accepted at
    the next start."""
    from phiward import config, pin
    op = tree / "opbin"
    op.mkdir()
    shutil.copy(shutil.which("true"), str(op / "tool"))
    os.chmod(str(op / "tool"), 0o111)
    _cfg(tree, f'["{op}/tool"]')
    pin.write_pins(config.load("/"))
    # replaced while the broker is stopped
    os.unlink(str(op / "tool"))
    shutil.copy(shutil.which("false"), str(op / "tool"))
    os.chmod(str(op / "tool"), 0o111)
    assert pin.unapproved(config.load("/")) != []


def test_inv3_the_broker_checks_approval_on_the_path_it_runs_with(tree, monkeypatch, home):
    """FAILS at d271fb9. `Broker.__init__` -> pin.unapproved -> broker.program_path() takes the
    PATH from the status file when that names a live broker, not this process's own command
    PATH. The status file is one per home folder, the spool is not: a broker started with
    another spool (whose heartbeat file the agent can write) while a first one runs checks
    approval on the first broker's PATH and then runs programs from its own."""
    from phiward import broker, config, pin, procinfo
    a = tree / "envA" / "bin"
    b = tree / "envB" / "bin"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    _script(a / "samtools", "echo APPROVED-A")
    _script(b / "samtools", "echo NEVER-APPROVED-B")
    _cfg(tree, '["samtools"]')
    # the operator approved with env A
    monkeypatch.setenv("PATH", f"{a}:/usr/bin:/bin")
    assert broker.command_env()["PATH"].split(":")[0] == str(a)   # the test's folders are kept
    pin.write_pins(config.load("/"))
    assert _approved_paths() == {str(a / "samtools")}
    # a live broker (stood in for by this process) wrote the status file with env A's PATH
    import socket
    me = procinfo.info(os.getpid())
    os.makedirs(os.path.dirname(config.status_path()), mode=0o700, exist_ok=True)
    Path(config.status_path()).write_text(json.dumps(
        {"v": 1, "pid": os.getpid(), "start": me[1], "host": socket.gethostname(),
         "path": f"{a}:/usr/bin:/bin"}))
    os.chmod(config.status_path(), 0o600)
    # a second broker starts with env B and its own spool; its heartbeat file is there
    spool = tree / "spoolB"
    spool.mkdir()
    (spool / "broker.alive").write_text("")
    monkeypatch.setenv("PHIWARD_SPOOL", str(spool))
    monkeypatch.setenv("PATH", f"{b}:/usr/bin:/bin")
    will_run = broker.listed_programs(config.load("/"), broker.command_env()["PATH"])
    assert will_run == [str(b / "samtools")]
    # what Broker.__init__ computes: on its own command PATH (round 18f)
    unapproved = pin.unapproved(config.load("/"), path=broker.command_env()["PATH"])
    assert unapproved == [str(b / "samtools")], unapproved


# =================================================================================================
# Invariant 4: ordinary documented use works (end to end, with the real confinement)
# =================================================================================================

@needs_confine
def test_inv4_documented_use_end_to_end(tree, monkeypatch, home):
    from phiward import config, pin
    # a Homebrew-like prefix and a conda-like env on PATH, and a scripts folder off PATH
    cellar = tree / "brew" / "Cellar" / "samtools" / "1.0" / "bin"
    cellar.mkdir(parents=True)
    hb = tree / "brew" / "bin"
    hb.mkdir()
    _script(cellar / "samtools", 'echo "BREW-SAMTOOLS $(basename "$0")"')
    os.symlink("../Cellar/samtools/1.0/bin/samtools", str(hb / "samtools"))
    _script(cellar / "extra", "echo BREW-EXTRA")
    os.symlink("../Cellar/samtools/1.0/bin/extra", str(hb / "extra"))
    conda = tree / "home" / "miniconda3" / "envs" / "x" / "bin"
    conda.mkdir(parents=True)
    _script(conda / "bedtools", "echo CONDA-BEDTOOLS")
    pl = tree / "home" / "pipelines" / "bin"
    pl.mkdir(parents=True)
    _script(pl / "count.sh", 'echo "COUNT $(wc -l < "$1")"')
    monkeypatch.setenv("PATH", f"{hb}:{conda}:/usr/bin:/bin")
    _cfg(tree, f'["@genomics", "~/pipelines/bin/", "{hb}/"]')
    cfg = config.load("/")
    pin.write_pins(cfg)
    assert pin.unapproved(config.load("/")) == [], pin.describe(config.load("/"))
    b = _stub_broker()
    data = str(tree / "phi" / "FAKE-PT-0001.bam")

    def go(*words):
        out = io.StringIO()
        body = {"cmd": "run", "args": ["--", *words], "cwd": str(tree / "repo")}
        return b.execute("r" * 16, body, out), out.getvalue()
    code, text = go("wc", "-l", data)                       # a preset name
    assert code == 0 and "1 " in text, text
    code, text = go("head", "-c", "6", data)                # @genomics
    assert code == 0 and "SECRET" in text, text
    code, text = go("samtools", "view")                     # Homebrew, by name (preset)
    assert code == 0 and "BREW-SAMTOOLS samtools" in text, text
    code, text = go("bedtools")                             # conda, by name (preset)
    assert code == 0 and "CONDA-BEDTOOLS" in text, text
    code, text = go(str(hb / "extra"))                      # a folder of links, by path
    assert code == 0 and "BREW-EXTRA" in text, text
    code, text = go("extra")                                # ... and by name
    assert code == 0 and "BREW-EXTRA" in text, text
    code, text = go(str(pl / "count.sh"), data)             # a script by its full path
    assert code == 0 and "COUNT 1" in " ".join(text.split()), text
    code, text = go("sh", "-c", "echo no")                  # not listed
    assert code == 2 and "not in [broker] commands" in text, text
    code, text = go("/bin/wc", "-l", data)                  # a listed name by a path
    assert code == 2, text


# =================================================================================================
# Beside the four: one answer for a path that is not listed; the other two commands
# =================================================================================================

def test_extra_a_refused_path_does_not_say_whether_the_file_exists(tree, monkeypatch):
    """FAILS at d271fb9. With a list set, a path word is looked up before it is matched:
    exit 127 for no (executable) file there, exit 2 for an existing one that is not listed. The
    broker reads protected folders, so the agent learns which names exist in them."""
    d = tree / "opbin"
    d.mkdir()
    _script(d / "wc", "echo REAL-WC")
    monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
    _cfg(tree, '["wc"]')
    _script(tree / "phi" / "FAKE-PT-0009.sh", "true")
    there = _run(tree, monkeypatch, str(tree / "phi" / "FAKE-PT-0009.sh"))
    absent = _run(tree, monkeypatch, str(tree / "phi" / "FAKE-PT-0010.sh"))
    assert (there[0], there[2]) == (absent[0], absent[2]), (there, absent)


def test_extra_remote_has_its_own_user_only_list(tree, monkeypatch):
    from phiward import config, run
    _cfg(tree, '["wc"]', extra='[remote]\nhosts = ["hpc"]\ncommands = ["squeue"]\n')
    (tree / "repo" / ".phiward.toml").write_text(
        '[remote]\ncommands = ["bash"]\nhosts = ["evil"]\n[broker]\ncommands = ["wc"]\n')
    cfg = config.load(str(tree / "repo"))
    assert cfg.remote_commands == ["squeue"] and cfg.remote_hosts == ["hpc"]
    assert "remote.commands" in cfg.ignored
    for word in ("wc", "bash", "/usr/bin/squeue", "./squeue"):
        out = io.StringIO()
        code = run.execute(["--remote", "hpc", "--", word], str(tree / "repo"),
                           dict(os.environ), out)
        assert code == 2 and "[remote] commands" in out.getvalue(), (word, out.getvalue())


def test_extra_copy_starts_only_system_programs(tree, monkeypatch):
    from phiward import copying
    d = tree / "opbin"
    d.mkdir()
    _script(d / "rsync", "echo AGENT")
    _script(d / "ssh", "echo AGENT")
    monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
    for name in ("rsync", "ssh", "cp"):
        p = copying.system_program(name)
        assert p is None or os.path.dirname(p) in copying.SYSTEM_DIRS
