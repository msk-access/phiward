"""phiward's own bubblewrap is the system one only (PLAN-0.2.0-SAFE-WAYS 3.1).

The gateway, its self-test and launch run `/usr/bin/bwrap` or `/bin/bwrap`, never one a PATH
entry or a bare name picks: a conda env or a project's `.venv/bin` first on the broker's PATH
must not choose what confines the gateway. Made-up stubs only.
"""

import os
import stat
import sys

import pytest

from phiward import confine


def _stub(folder, marker):
    folder.mkdir(parents=True, exist_ok=True)
    b = folder / "bwrap"
    b.write_text(f"#!/bin/sh\necho ran > '{marker}'\nexit 0\n")
    b.chmod(b.stat().st_mode | stat.S_IXUSR)
    return str(b)


@pytest.fixture()
def linux(tmp_path, monkeypatch):
    """A made-up Linux: the system folders hold no bwrap, a stub one is first on PATH."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(confine, "_machine", lambda: "x86_64")
    system = tmp_path / "system-bin"
    system.mkdir()
    monkeypatch.setattr(confine, "SYSTEM_BIN", str(system), raising=False)
    marker = tmp_path / "path-bwrap-ran"
    path_stub = _stub(tmp_path / "venv" / "bin", marker)
    monkeypatch.setenv("PATH", os.path.dirname(path_stub) + os.pathsep + "/usr/bin:/bin")
    return system, marker


def test_a_bwrap_on_path_is_no_backend(linux):
    _system, marker = linux
    assert confine.backend() is None
    with pytest.raises(confine.ConfineError) as exc:
        confine.gateway_command(["true"], [], [], False)
    assert "--remote" in str(exc.value), exc.value
    why = confine.self_test()
    assert why and "--remote" in why and "PATH" in why, why
    assert not marker.exists()


def test_the_gateway_runs_the_system_bwrap(linux):
    system, marker = linux
    real = _stub(system, marker.parent / "system-bwrap-ran")
    assert confine.backend() == "bwrap"
    cmd, fds = confine.gateway_command(["true"], [], [], False)
    for fd in fds:
        os.close(fd)
    assert cmd[0] == real, cmd[:2]
