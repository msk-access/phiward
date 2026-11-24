"""Every typical refusal names its next step in one line, and `phiward doctor` warns about each
one it can see before the start (PLAN-USABILITY-FIXES c1 and c2). Only messages, doctor lines and
the session note change here: nothing that was refused is allowed, nothing allowed is refused.
Made-up trees and names only (FAKE-PT-0001)."""

import os

import pytest

from phiward import config, copying, doctor, netproxy, paths, session_note, wholetool


def _refusal(argv, cwd, env, adapter="generic"):
    with pytest.raises(wholetool.LaunchError) as exc:
        wholetool.build(argv, str(cwd), env, wholetool.ADAPTERS[adapter])
    return str(exc.value)


# --- c1: launch's own refusals ------------------------------------------------------------------

def test_no_protected_paths_names_setup(tree):
    empty = tree / "home" / "empty.toml"
    empty.write_text("[shell]\nbest_effort = true\n")
    env = dict(os.environ, PHIWARD_CONFIG=str(empty))
    msg = _refusal(["/bin/echo", "x"], tree / "repo", env)
    assert "nothing to confine" in msg and "phiward setup" in msg, msg


def test_a_wrapper_gives_one_step_with_the_version_it_needs(tree):
    shim = tree / "shim" / "claude"
    shim.parent.mkdir()
    shim.write_text("#!/bin/sh\nexec /nonexistent/claude \"$@\"\n")
    shim.chmod(0o755)
    msg = wholetool.claude_version_problem(str(shim), [str(tree / "repo")])
    assert "native binary" in msg and "cli.js" in msg and "must print" not in msg, msg
    assert "\n" not in msg and "wrapper" in msg and "--tool generic" in msg, msg


def test_a_dash_dash_refusal_says_drop_it():
    assert "drop the `--`" in wholetool.DASH_DASH, wholetool.DASH_DASH
    assert "prompt last" in wholetool.DASH_DASH, wholetool.DASH_DASH


def test_a_plain_http_request_names_https():
    assert "https://" in netproxy.ONLY_CONNECT, netproxy.ONLY_CONNECT


# --- c2: the gateway's copy ---------------------------------------------------------------------

def test_a_copy_out_of_a_root_names_phiward_run(tree):
    cfg = config.load(str(tree / "repo"))
    msg = copying.plan([str(tree / "phi" / "FAKE-PT-0001.bam"), str(tree / "pub" / "x.bam")],
                       str(tree / "repo"), cfg)
    assert msg and "not inside a protected path" in msg and "phiward run" in msg, msg


# --- c1: doctor's launch section ----------------------------------------------------------------

def _launch(tree, project=None, platform="darwin", version=(2, 1, 300), installed=True,
            show=False, cfg=None, **env):
    base = {k: v for k, v in os.environ.items()
            if k not in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                         "ANTHROPIC_BASE_URL", "VIRTUAL_ENV")}
    base["PATH"] = "/usr/bin:/bin"
    base.update(env)
    project = str(project or tree / "repo")
    return doctor.launch_report(project, str(tree / "home"), cfg or config.load(project),
                                env=base, platform=platform, version=version,
                                installed=installed, show=show)


@pytest.fixture()
def native(tree, monkeypatch):
    """A made-up native `claude` (no `#!` line) on a PATH folder of its own; starting it fails
    the test: doctor never starts it."""
    folder = tree / "native"
    folder.mkdir()
    (folder / "claude").write_bytes(b"\xcf\xfa\xed\xfe fake native build\n")
    (folder / "claude").chmod(0o755)

    def never(real, env):
        raise AssertionError(f"doctor started {real}")
    monkeypatch.setattr(wholetool, "_native_version", never)
    return f"{folder}:/usr/bin:/bin"


def _text(lines):
    return "\n".join(lines)


def test_doctor_warns_when_the_folder_cannot_be_launchs_project(tree):
    out = _text(_launch(tree, project=tree / "home"))
    assert "WARNING" in out and "the home folder or above it" in out, out
    assert "start the tool in a project folder" in out, out


def test_doctor_warns_about_a_path_entry_inside_the_project(tree):
    venv = tree / "repo" / ".venv"
    (venv / "bin").mkdir(parents=True)
    out = _text(_launch(tree, PATH=f"{venv}/bin:/usr/bin:/bin", VIRTUAL_ENV=str(venv)))
    assert "WARNING" in out and ".venv/bin" in out and "deactivate" in out, out
    assert str(tree) not in out, out  # the entry relative to the project
    shown = _text(_launch(tree, show=True, PATH=f"{venv}/bin:/usr/bin:/bin",
                          VIRTUAL_ENV=str(venv)))
    assert f"{venv}/bin" in shown, shown


def test_doctor_warns_that_launch_needs_protected_paths(tree):
    empty = tree / "home" / "empty.toml"
    empty.write_text("[shell]\nbest_effort = true\n")
    cfg = config.load(str(tree / "repo"), env=dict(os.environ, PHIWARD_CONFIG=str(empty)))
    out = _text(_launch(tree, cfg=cfg))
    assert "WARNING" in out and wholetool.NO_PATHS in out, out


def test_doctor_judges_a_native_binary_by_the_version_it_read(tree, native):
    assert "WARNING" not in _text(_launch(tree, PATH=native))
    old = _text(_launch(tree, PATH=native, version=(2, 1, 1)))
    assert "WARNING" in old and "older than 2.1.295" in old, old


def test_doctor_notes_an_unknown_version_and_starts_nothing(tree, native):
    out = _text(_launch(tree, PATH=native, version=None))
    assert "NOTE" in out and "only launch can tell" in out and "WARNING" not in out, out


def test_the_launch_section_reuses_the_version_doctor_read(tree, native, monkeypatch, capsys):
    from phiward import claude_settings
    monkeypatch.setattr(claude_settings, "claude_version", lambda: (2, 1, 300))
    # as on Linux, or with no protected patterns: doctor's other reading gives None
    monkeypatch.setattr(doctor, "_pattern_version", lambda cfg: None)
    got = {}
    real = doctor.launch_report
    monkeypatch.setattr(doctor, "launch_report",
                        lambda *a, **k: got.update(k) or real(*a, **k))
    monkeypatch.chdir(tree / "repo")
    doctor.main([])
    assert got.get("version") == (2, 1, 300) and "installed" in got, got
    assert got.get("show") is False, got  # paths in full only with --show-paths

    def again():
        raise AssertionError("launch_report read the version itself")
    monkeypatch.setattr(claude_settings, "claude_version", again)
    _launch(tree, PATH=native, version=None)


def test_doctor_warns_about_a_linked_settings_folder(tree):
    (tree / "dotfiles").mkdir()
    os.symlink(tree / "dotfiles", tree / "repo" / ".vscode")
    out = _text(_launch(tree))
    assert "WARNING" in out and ".vscode in the project is a link" in out, out


def test_doctor_warns_about_a_wrapper_named_claude(tree):
    shim = tree / "shim"
    shim.mkdir()
    (shim / "claude").write_text("#!/bin/sh\nexec /nonexistent/claude \"$@\"\n")
    (shim / "claude").chmod(0o755)
    out = _text(_launch(tree, PATH=f"{shim}:/usr/bin:/bin"))
    assert "WARNING" in out and "gives no Claude Code version" in out, out
    assert "native binary" in out, out


def test_doctor_warns_about_a_base_url_the_proxy_refuses(tree):
    out = _text(_launch(tree, ANTHROPIC_BASE_URL="http://127.0.0.1:4000"))
    assert "WARNING" in out and "ANTHROPIC_BASE_URL" in out and "Mode A" in out, out


def test_doctor_notes_the_login_without_a_token(tree):
    assert "setup-token" in _text(_launch(tree))
    assert "setup-token" not in _text(_launch(tree, CLAUDE_CODE_OAUTH_TOKEN="fake-token"))


def test_doctor_notes_the_read_only_files_of_a_launch_session(tree):
    out = _text(_launch(tree))
    assert "NOTE" in out and ".Rprofile" in out and ".vscode" in out, out
    assert "carryover add" in out and "renv::init()" in out, out


def test_doctor_notes_a_source_checkout(tree, monkeypatch):
    from phiward import selfcheck

    def again(*a, **k):
        raise AssertionError("a second self-check")
    monkeypatch.setattr(selfcheck, "check_isolated", again)
    out = _text(_launch(tree, installed=False, PHIWARD_DEV="0"))
    assert "PHIWARD_DEV=1" in out, out
    assert "PHIWARD_DEV=1" not in _text(_launch(tree, installed=False, PHIWARD_DEV="1"))
    assert "PHIWARD_DEV=1" not in _text(_launch(tree, installed=True, PHIWARD_DEV="0"))


def test_doctor_names_linuxs_inner_mode_and_its_refusals(tree, monkeypatch):
    monkeypatch.setattr(wholetool, "landlock_abi", lambda: 6)
    monkeypatch.setattr(wholetool, "inner_sandbox_reason", lambda project, env, machine=None: None)
    out = _text(_launch(tree, platform="linux"))
    assert "inner" in out and "--settings" in out and "`--`" in out and "claude mcp" in out, out
    monkeypatch.setattr(wholetool, "landlock_abi", lambda: 9)
    out = _text(_launch(tree, platform="linux"))
    assert "Landlock" in out and "claude mcp" not in out, out


def test_doctor_warns_when_inner_mode_would_refuse_the_settings(tree, monkeypatch):
    monkeypatch.setattr(wholetool, "landlock_abi", lambda: 6)
    monkeypatch.setattr(wholetool, "inner_sandbox_reason",
                        lambda project, env, machine=None: "Claude Code's settings open its "
                        "sandbox (sandbox.excludedCommands is not empty)")
    out = _text(_launch(tree, platform="linux"))
    assert "WARNING" in out and "excludedCommands" in out, out


def test_doctor_on_macos_says_nothing_of_linuxs_modes(tree):
    out = _text(_launch(tree))
    assert "Landlock" not in out and "inner" not in out, out


def test_doctor_main_prints_the_launch_section(tree, monkeypatch, capsys):
    monkeypatch.chdir(tree / "repo")
    doctor.main([])
    assert "launch (Mode B)" in capsys.readouterr().out


# --- c2: Mode A ---------------------------------------------------------------------------------

def test_the_session_note_names_the_way_around_each_typical_limit(tree, monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_DISABLE_FILE_MENTIONS", "1")
    text = session_note.note(config.load(str(tree / "repo")))
    assert "git push" in text and "operator's own terminal" in text, text
    assert "@file" in text and "Read" in text, text
    assert "--no-cache-dir" in text and "PIP_CACHE_DIR" in text and "UV_CACHE_DIR" in text, text


def test_the_session_note_says_nothing_of_mentions_when_they_are_on(tree, monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_DISABLE_FILE_MENTIONS", raising=False)
    assert "@file" not in session_note.note(config.load(str(tree / "repo")))


def test_doctor_notes_the_read_only_package_caches():
    out = _text(doctor.package_cache_lines())
    assert "NOTE" in out and "~/.cache/pip" in out and "~/.cache/uv" in out and "~/.npm" in out
    assert "--no-cache-dir" in out, out


def test_doctor_says_grep_and_glob_need_a_subfolder_above_a_root():
    line = doctor.relation_line(paths.ABOVE)
    assert "WARNING" in line and "Grep and Glob" in line and "subfolder" in line, line
    assert "Grep and Glob" not in doctor.relation_line(paths.INSIDE)


def test_doctor_warns_about_a_listed_program_not_on_the_brokers_path(tree):
    (tree / "home" / "phiward.toml").write_text(
        (tree / "home" / "phiward.toml").read_text()
        + '[broker]\ncommands = ["sh", "fake-tool-not-here"]\n')
    cfg = config.load(str(tree / "repo"))
    out = _text(doctor.broker_path_lines(cfg, {"path": "/usr/bin:/bin"}))
    assert "WARNING" in out and "fake-tool-not-here" in out and "conda activate" in out, out
    assert "`sh`" not in out, out
    assert doctor.broker_path_lines(cfg, {}) == []


# --- P6: refusals that named no step, and quiet failures ----------------------------------------

def test_no_confinement_backend_names_bubblewrap_and_setup(tree, monkeypatch):
    from phiward import confine
    monkeypatch.setattr(confine, "backend", lambda: None)
    msg = _refusal(["/bin/echo", "x"], tree / "repo", dict(os.environ))
    assert "no confinement backend" in msg, msg
    assert "install bubblewrap" in msg and "setup.md" in msg, msg
    with pytest.raises(confine.ConfineError) as exc:
        confine.gateway_command(["/bin/echo", "x"], [str(tree / "phi")], [])
    assert "install bubblewrap" in str(exc.value) and "setup.md" in str(exc.value), exc.value


@pytest.mark.parametrize("value", ["https://proxy.example:3128", "socks5://proxy.example:1080"])
def test_an_upstream_proxy_that_is_not_http_names_the_way_out(value):
    with pytest.raises(netproxy.ProxyError) as exc:
        netproxy.upstream_from({"HTTPS_PROXY": value})
    msg = str(exc.value)
    assert "unset it" in msg and "http:// proxy" in msg, msg


def test_landlock_below_abi_2_names_the_kernel_it_needs():
    from phiward import confine
    line = next(t for t in confine.LANDLOCK_HELPER.splitlines() if "Landlock ABI 2" in t)
    assert "Linux 5.19 or newer" in line and "Landlock turned on" in line, line


def test_a_pull_without_system_mkdir_or_tar_names_the_step(tree, monkeypatch):
    import io
    (tree / "home" / "phiward.toml").write_text(
        (tree / "home" / "phiward.toml").read_text()
        + '[copy]\nremotes = ["hpc-test:/work/me"]\n'
        + '[remote]\nhosts = ["hpc-test"]\ncommands = ["wc"]\n')
    real = copying.system_program
    monkeypatch.setattr(copying, "system_program",
                        lambda n: None if n == "tar" else real(n))
    out = io.StringIO()
    code = copying.execute(["hpc-test:/work/me/x", str(tree / "phi") + "/"], str(tree / "repo"),
                           dict(os.environ), out)
    msg = out.getvalue()
    assert code == 2 and "mkdir and tar" in msg, msg
    assert "/usr/bin" in msg and "package manager" in msg, msg


def test_the_session_note_says_when_the_project_scan_could_not_run(tree, monkeypatch):
    from phiward import projectscan
    cfg = config.load(str(tree / "repo"))
    monkeypatch.setattr(projectscan, "scan", lambda *a, **k: projectscan.Result(
        [], {}, 0, False, "the project scan could not run"))
    text = session_note.note(cfg, str(tree / "repo"))
    assert "project scan could not run" in text and "phiward doctor" in text, text

    def boom(*a, **k):
        raise OSError("fake")
    monkeypatch.setattr(projectscan, "scan", boom)
    text = session_note.note(cfg, str(tree / "repo"))
    assert "project scan could not run" in text and "phiward doctor" in text, text
    # a scan that ran and found nothing says nothing
    monkeypatch.setattr(projectscan, "scan", lambda *a, **k: projectscan.Result(
        [], {}, 1, True, ""))
    assert "project scan" not in session_note.note(cfg, str(tree / "repo"))


def _extract(dest, members):
    """Run the pull's extractor on a made-up tar stream of `members` (name, bytes)."""
    import io
    import subprocess
    import sys
    import tarfile
    from phiward import remote
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return subprocess.run([sys.executable, "-I", remote.EXTRACTOR, str(dest)],
                          input=buf.getvalue(), capture_output=True)


def test_the_extractor_counts_an_existing_file_as_kept(tree):
    dest = tree / "phi" / "pulled"
    dest.mkdir()
    (dest / "a.txt").write_text("old\n")
    r = _extract(dest, [("a.txt", b"new\n"), ("b.txt", b"b\n")])
    assert r.returncode == 0, r
    assert b"kept 1 existing" in r.stdout, r.stdout
    assert (dest / "a.txt").read_text() == "old\n" and (dest / "b.txt").read_text() == "b\n"


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes a read-only folder")
def test_the_extractor_fails_on_a_file_it_cannot_write(tree):
    dest = tree / "phi" / "pulled"
    (dest / "ro").mkdir(parents=True)
    (dest / "ro").chmod(0o555)
    try:
        r = _extract(dest, [("ro/a.txt", b"a\n"), ("b.txt", b"b\n")])
    finally:
        (dest / "ro").chmod(0o755)
    assert r.returncode != 0, r
    assert b"kept 0 existing" in r.stdout and b"failed 1" in r.stdout, r.stdout
    assert (dest / "b.txt").read_text() == "b\n"  # the rest is still written
