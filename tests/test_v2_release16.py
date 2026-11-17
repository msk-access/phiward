"""Round 16: the code cleanup's few behaviour points. Made-up trees only."""

import os

import pytest

from phiward import safeio


def test_write_new_leaves_no_temp_file_when_the_move_fails(tmp_path, monkeypatch):
    target = tmp_path / "f.json"
    target.write_text("old")

    def boom(a, b):
        raise OSError("no")
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        safeio.write_new(str(target), "new")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["f.json"]
    assert target.read_text() == "old"


def test_write_new_leaves_no_temp_file_when_the_write_fails(tmp_path):
    target = tmp_path / "f.json"
    with pytest.raises(UnicodeEncodeError):
        safeio.write_new(str(target), "\udcff")
    assert list(tmp_path.iterdir()) == []


def test_the_launcher_cache_sees_a_changed_temp_folder(tree, monkeypatch):
    # the cache key is what the PATH filter reads (service.path_inputs), the temp folders too
    from phiward import claude_settings, mcp_config
    bin_dir = tree / "pub" / "bin16"
    bin_dir.mkdir(parents=True)
    exe = bin_dir / "phiward"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    mcp_config._launcher_exes.cache_clear()
    monkeypatch.setattr(claude_settings, "_temp_roots", lambda: [])
    first = mcp_config._launcher_exes(str(bin_dir))
    monkeypatch.setattr(claude_settings, "_temp_roots", lambda: [str(bin_dir)])
    second = mcp_config._launcher_exes(str(bin_dir))
    mcp_config._launcher_exes.cache_clear()
    assert os.path.realpath(exe) in first and second == frozenset(), (first, second)


def test_a_temp_file_does_not_take_a_launch_record_slot(tree, launchers, monkeypatch):
    # write_new's hidden temp names sort first: the cap counts records only
    from phiward import mcp_config
    p = launchers.start("h" * 64)
    folder = mcp_config.launched_dir()
    tmp = os.path.join(folder, f".{p.pid}.json.0123456789abcdef.tmp")
    with open(tmp, "w") as fh:
        fh.write("{}")
    os.chmod(tmp, 0o600)
    monkeypatch.setattr(mcp_config, "LAUNCHED_MAX", 1)
    assert [r["pid"] for r in mcp_config._records(folder)] == [p.pid]


def test_the_remote_argv_on_the_shared_connection_quotes_every_word(tree, monkeypatch):
    # the default route (the operator's shared connection), as production builds it
    from phiward import config, copying, remote, run
    monkeypatch.setattr(copying, "system_program", lambda name: "/usr/bin/ssh")
    monkeypatch.setattr(remote, "shared_socket", lambda cfg, host: (str(tree / "pub" / "s"), ""))
    cfg = config.load(str(tree / "repo"))
    assert cfg.use_shared_connection
    rt, why = remote.route(cfg, "hpc-test")
    assert rt is not None and not rt.net, why
    cmd = run._remote_argv(rt, "hpc-test", ["wc", "-l", "a; touch x", "$(id)"])
    assert cmd[-3:] == ["hpc-test", "--", "wc -l 'a; touch x' '$(id)'"], cmd
    assert "BatchMode=yes" in cmd and "ProxyCommand=none" in cmd and "-T" in cmd, cmd
