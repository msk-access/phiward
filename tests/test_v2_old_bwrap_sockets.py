"""A socket in the hidden list, on bubblewrap before 0.5 (an HPC compute node, 2026-11-25).

Claude Code's sandbox (sandbox-runtime) cannot apply a denyRead or denyWrite that names a socket
on bubblewrap before 0.5: it makes a file at the place and fails ("bwrap: Can't create file at
/run/.heim_org.h5l.kcm-socket: No such device or address"), so every Bash call failed on a
RHEL 8 node (bubblewrap 0.4.0) where the Kerberos KCM socket exists. There, and only where the
sandbox has its seccomp filter for new Unix sockets (Linux x86_64 and aarch64), the sockets of
the IPC list stay out of the sandbox's lists; doctor says so. Everywhere else nothing changes,
and the file tools' permission rules keep every path. Made-up paths only."""

import json
import os

import pytest

from phiward import claude_settings, config, doctor, hidden, install
from phiward.adapters import decide
from phiward.core import SHELL, Action


def _node(monkeypatch, plat, machine, bwrap):
    monkeypatch.setattr(hidden, "_platform", lambda: (plat, machine))
    monkeypatch.setattr(hidden, "_bwrap_version", lambda: bwrap)


def _sandbox_entries(w):
    fs = w["sandbox"]["filesystem"]
    return fs["denyRead"] + fs["denyWrite"]


def _fake_socket(tree, monkeypatch):
    """A made-up path in the IPC socket list, present on this machine (as the KCM socket is on
    the node), so the hook's and doctor's lists, which keep only paths that exist, hold it."""
    sock = tree / "run" / "fake-kcm-socket"
    sock.parent.mkdir(exist_ok=True)
    sock.write_text("")
    monkeypatch.setattr(hidden, "IPC_SOCKETS", hidden.IPC_SOCKETS + (str(sock),))
    monkeypatch.setattr(hidden, "IPC_PATHS", hidden.IPC_PATHS + (str(sock),))
    return str(sock)


def _install(tree, cfg):
    settings = os.path.join(claude_settings.user_dir(str(tree / "home")), "settings.json")
    os.makedirs(os.path.dirname(settings), exist_ok=True)
    with open(settings, "w") as fh:
        json.dump(install.wiring(cfg), fh)


@pytest.mark.parametrize("plat, machine, bwrap, kept", [
    ("linux", "x86_64", (0, 4), False), ("linux", "aarch64", (0, 4), False),
    ("linux", "x86_64", (0, 12), True),    # bubblewrap hides the socket: keep it
    ("linux", "x86_64", None, True),       # the version is unknown: keep it
    ("linux", "ppc64le", (0, 4), True),    # no seccomp filter for sockets there
    ("darwin", "arm64", (0, 4), True)])
def test_the_sockets_leave_the_sandbox_lists_only_on_old_bubblewrap_with_the_filter(
        tree, monkeypatch, plat, machine, bwrap, kept):
    _node(monkeypatch, plat, machine, bwrap)
    w = install.wiring(config.load(str(tree / "repo")))
    listed = [e for e in _sandbox_entries(w) if "kcm-socket" in e or "docker.sock" in e]
    assert bool(listed) == kept, listed
    # Claude Code merges the Read and Edit deny rules into its sandbox too ("Paths and domains
    # from both sandbox settings and permission rules are merged into the final sandbox
    # configuration", code.claude.com/docs/en/sandboxing), so the whole file must leave them out
    # (the HPC rerun of 2026-11-25 failed on the rules); phiward's hook still refuses a file tool
    # that names them
    text = json.dumps(w)
    assert ("kcm-socket" in text or "docker.sock" in text) == kept, text
    # the folders of the IPC list stay: bubblewrap mounts over a folder
    assert any(e.endswith("/run/munge") for e in _sandbox_entries(w)), _sandbox_entries(w)


def test_the_filter_is_known_only_on_linux_x86_64_and_aarch64():
    assert hidden.sockets_blocked("linux", "x86_64") and hidden.sockets_blocked("linux", "aarch64")
    assert not hidden.sockets_blocked("linux", "ppc64le")
    assert not hidden.sockets_blocked("darwin", "arm64")


def test_the_hook_judges_the_sandbox_by_the_list_install_wrote(tree, monkeypatch):
    _node(monkeypatch, "linux", "x86_64", (0, 4))
    sock = _fake_socket(tree, monkeypatch)
    seen = {}

    def reason(*a, **k):
        seen["hidden"] = list(k.get("hidden") or [])
        return None
    monkeypatch.setattr(claude_settings, "named_project_holds", lambda cwd: True)
    monkeypatch.setattr(claude_settings, "shell_reason", reason)
    decide(Action(SHELL, str(tree / "repo"), command="ls", tool="Bash"), claude_sandbox=True)
    assert "hidden" in seen and sock not in seen["hidden"], seen
    # on a node whose bubblewrap hides sockets, the hook expects it in the sandbox's lists
    _node(monkeypatch, "linux", "x86_64", (0, 12))
    decide(Action(SHELL, str(tree / "repo"), command="ls", tool="Bash"), claude_sandbox=True)
    assert sock in seen["hidden"], seen


def test_doctor_counts_a_fresh_install_and_says_what_the_sockets_rest_on(tree, monkeypatch):
    _node(monkeypatch, "linux", "x86_64", (0, 4))
    sock = _fake_socket(tree, monkeypatch)
    cfg = config.load(str(tree / "repo"))
    _install(tree, cfg)
    out = "\n".join(doctor.mode_report(str(tree / "repo"), str(tree / "home"), cfg))
    line = next(ln for ln in out.splitlines() if "hidden list in the sandbox" in ln)
    assert "WARNING" not in line, out
    assert "only Claude Code's seccomp filter keeps a shell command from them" in out, out
    # the same settings on a node whose bubblewrap hides sockets: not enough there (fail closed)
    _node(monkeypatch, "linux", "x86_64", (0, 12))
    out = "\n".join(doctor.mode_report(str(tree / "repo"), str(tree / "home"), cfg))
    line = next(ln for ln in out.splitlines() if "hidden list in the sandbox" in ln)
    assert "WARNING" in line and "seccomp" not in out, (sock, out)


@pytest.mark.parametrize("stdout, want", [("bubblewrap 0.4.0\n", (0, 4)),
                                          ("bubblewrap 0.11.1\n", (0, 11)), ("", None),
                                          ("no version here\n", None)])
def test_the_bubblewrap_version_is_read_or_none(monkeypatch, tmp_path, stdout, want):
    import subprocess
    import shutil
    from phiward import service
    monkeypatch.setattr(service, "_safe_path_entries", lambda p: [str(tmp_path)])
    monkeypatch.setattr(shutil, "which", lambda name, path=None: str(tmp_path / "bwrap"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a[0], 0, stdout=stdout, stderr=""))
    assert hidden._bwrap_version() == want


def test_a_bubblewrap_that_hangs_or_is_missing_keeps_the_sockets(monkeypatch, tmp_path):
    import subprocess
    import shutil

    def hang(*a, **k):
        raise subprocess.TimeoutExpired(a[0], k.get("timeout", 0))
    monkeypatch.setattr(shutil, "which", lambda name, path=None: str(tmp_path / "bwrap"))
    monkeypatch.setattr(subprocess, "run", hang)
    assert hidden._bwrap_version() is None
    monkeypatch.setattr(shutil, "which", lambda name, path=None: None)
    assert hidden._bwrap_version() is None
    monkeypatch.setattr(hidden, "_platform", lambda: ("linux", "x86_64"))
    assert hidden.sockets_left_out() is False


def test_the_hook_still_refuses_a_file_tool_on_a_left_out_socket(tree, monkeypatch):
    from phiward.core import DENY, FILE_READ
    _node(monkeypatch, "linux", "x86_64", (0, 4))
    d = decide(Action(FILE_READ, str(tree / "repo"), paths=["/run/.heim_org.h5l.kcm-socket"],
                      tool="Read"))
    assert d.verdict == DENY, d.reason


def test_the_local_file_leaves_the_sockets_out_too(tree, monkeypatch):
    _node(monkeypatch, "linux", "x86_64", (0, 4))
    w = install.local_wiring(config.load(str(tree / "repo")), str(tree / "repo"))
    text = json.dumps(w)
    assert "kcm-socket" not in text and "docker.sock" not in text, text
