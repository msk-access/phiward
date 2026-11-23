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
    assert "`claude --version`" in msg and "2.1.295" in msg, msg
    assert "\n" not in msg and "wrapper" in msg, msg


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

def _launch(tree, project=None, platform="darwin", **env):
    base = {k: v for k, v in os.environ.items()
            if k not in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                         "ANTHROPIC_BASE_URL", "VIRTUAL_ENV")}
    base["PATH"] = "/usr/bin:/bin"
    base.update(env)
    project = str(project or tree / "repo")
    return doctor.launch_report(project, str(tree / "home"), config.load(project), env=base,
                                platform=platform)


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
    assert "`claude --version`" in out, out


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
    monkeypatch.setattr(selfcheck, "check_isolated", lambda timeout=60: (False, []))
    out = _text(_launch(tree, PHIWARD_DEV="0"))
    assert "PHIWARD_DEV=1" in out, out
    assert "PHIWARD_DEV=1" not in _text(_launch(tree, PHIWARD_DEV="1"))


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
