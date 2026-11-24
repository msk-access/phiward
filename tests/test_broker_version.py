"""The broker's version in its status file (pre-release P7): after an upgrade, a broker that
still runs keeps the old code. Doctor and `doctor --headless` say so when the running broker's
version differs from doctor's own, or is missing (an older broker writes none). This process
stands in for the running broker: it writes the status file and the spool's heartbeat."""

import json
import os
import socket

import pytest

from phiward import __version__, broker, config, doctor, procinfo

RESTART = "(cd ~ && phiward broker --service --write)"


def _stand_in_broker(version):
    """A live broker (this process) that wrote the status file, with `version` or none."""
    me = procinfo.info(os.getpid())
    st = {"v": 1, "pid": os.getpid(), "start": me[1], "host": socket.gethostname(),
          "config": config.user_config_path(), "cache": config.cache_dir(),
          "spool": config.spool_dir(), "roots": config.load("/").user_roots,
          "patterns": config.load("/").user_patterns}
    if version is not None:
        st["version"] = version
    os.makedirs(os.path.dirname(config.status_path()), mode=0o700, exist_ok=True)
    with open(config.status_path(), "w", encoding="utf-8") as fh:
        json.dump(st, fh)
    os.chmod(config.status_path(), 0o600)
    os.makedirs(config.spool_dir(), mode=0o700, exist_ok=True)
    with open(os.path.join(config.spool_dir(), "broker.alive"), "w"):
        pass
    assert broker.running(config.spool_dir()) == "here"


def _doctor(tree, monkeypatch, capsys):
    monkeypatch.chdir(tree / "repo")
    doctor.main([])
    return capsys.readouterr().out


def _version_lines(out):
    return [ln for ln in out.splitlines() if "broker" in ln and "version" in ln]


def test_the_status_file_holds_the_version(tree):
    assert broker._status()["version"] == __version__


def test_the_reader_keeps_the_version(tree):
    _stand_in_broker("0.0.1")
    assert broker.read_status(config.spool_dir()).get("version") == "0.0.1"


@pytest.mark.parametrize("version", ["0.0.1", None])
def test_doctor_warns_on_another_or_a_missing_version(tree, monkeypatch, capsys, version):
    _stand_in_broker(version)
    lines = _version_lines(_doctor(tree, monkeypatch, capsys))
    assert len(lines) == 1 and lines[0].startswith("WARNING: "), lines
    assert RESTART in lines[0] and "stop and start `phiward broker`" in lines[0], lines
    assert __version__ in lines[0], lines
    if version:
        assert version in lines[0], lines


def test_doctor_is_silent_on_the_same_version(tree, monkeypatch, capsys):
    _stand_in_broker(__version__)
    out = _doctor(tree, monkeypatch, capsys)
    assert "broker: running" in out, out
    assert _version_lines(out) == [], out


@pytest.mark.parametrize("version", ["0.0.1", None])
def test_headless_names_another_or_a_missing_version(tree, version):
    _stand_in_broker(version)
    probs = [p for p in doctor.headless_problems(str(tree / "repo"), str(tree / "home"))
             if "version" in p]
    assert len(probs) == 1 and RESTART in probs[0], probs


def test_a_status_that_cannot_be_read_while_the_broker_runs_counts_as_missing(
        tree, monkeypatch, capsys):
    # `running` says yes, the read just after it fails (the file replaced or gone between them)
    _stand_in_broker(__version__)
    monkeypatch.setattr(broker, "read_status", lambda spool=None: {})
    probs = [p for p in doctor.headless_problems(str(tree / "repo"), str(tree / "home"))
             if "version" in p]
    assert len(probs) == 1 and RESTART in probs[0], probs
    lines = _version_lines(_doctor(tree, monkeypatch, capsys))
    assert len(lines) == 1 and lines[0].startswith("WARNING: "), lines


def test_no_version_line_when_no_broker_runs(tree, monkeypatch, capsys):
    assert not broker.running(config.spool_dir())
    out = _doctor(tree, monkeypatch, capsys)
    assert _version_lines(out) == [], out
    probs = doctor.headless_problems(str(tree / "repo"), str(tree / "home"))
    assert not [p for p in probs if "version" in p], probs


def test_headless_is_silent_on_the_same_version(tree):
    _stand_in_broker(__version__)
    probs = doctor.headless_problems(str(tree / "repo"), str(tree / "home"))
    assert not [p for p in probs if "version" in p], probs
