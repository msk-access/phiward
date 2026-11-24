"""`[launch] write_to`: folders in the user config (USER_ONLY) that a `phiward launch` session
may write besides the project.

- The key: absolute (or `~/`), no `..`; a repo file's value is ignored. Existence, links and
  overlaps are checked when launch starts, not by `config.load`.
- The start check: a missing entry is skipped with a NOTE; a file, a link (a dangling one too),
  a link above it, and an overlap with a protected path, a derived folder, a place where files
  run later, a PATH folder, the spool, a guard file or a `[broker] write_to` folder refuse with
  the entry and the step. One inside the project is dropped; one inside another listed entry is
  dropped; one that holds the project is allowed.
- Each listed folder gets the project's rules: what runs later and git control files read-only
  (macOS by path, Linux by read-only binds of what exists at the start: no placeholders), the
  project scan (instruction files first, one shared budget), and the end report.
- An abnormal end: SIGHUP and SIGTERM still give the report; after SIGKILL the next start names
  the folders of the unfinished session (`runs/<name>.write_to`).
- `--tool claude` gets `--add-dir D` for each listed folder; the broker's PATH filter and
  `pseudonymize` treat the folders as agent-writable.

Made-up trees only (`FAKE-PT-0001`; tests/conftest.py)."""

import json
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from helpers import fake_native_claude, needs_confine, tool_py
from phiward import (carryover, claude_settings, config, confine, doctor, projectscan,
                     pseudonymize, service, wholetool)

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
LINUX = sys.platform.startswith("linux")
linux = pytest.mark.skipif(not LINUX, reason="bwrap's arguments: Linux")
macos = pytest.mark.skipif(sys.platform != "darwin", reason="the Seatbelt profile: macOS")
STEP = "fix or remove it in [launch] write_to of the user config"
PATTERN = r"FAKE-PT-\d{4} => <SUBJECT>"
READ_ONLY = ("EPERM", "EROFS", "EACCES")


def user(text):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + text)


def listed(*paths):
    user("[launch]\nwrite_to = [" + ", ".join(f"'{p}'" for p in paths) + "]\n")


def folder(tree, name="sib"):
    d = tree / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def scan_cfg():
    user("[sanitize]\npacks = ['genomics', 'msk', 'dates']\n" f"patterns = ['{PATTERN}']\n")


def build(tree, argv=None, adapter="generic", env=None, server=False, store=None, info=None,
          cwd=None):
    env = dict(os.environ) if env is None else env
    return wholetool.build(argv or ["/bin/echo", "x"], str(cwd or tree / "repo"), env,
                           wholetool.ADAPTERS[adapter], store=store, server=server, info=info)


def close(built):
    cmd, _env, fds, _project, _ready, proxy = built
    for fd in fds:
        os.close(fd)
    proxy.close()
    text = ""
    if cmd[:2] == [confine.SANDBOX_EXEC, "-f"]:
        text = Path(cmd[2]).read_text()
    confine.release_profile(cmd)
    return cmd, text


def session_text(built):
    """What the session is given, as text: the profile on macOS, bwrap's command on Linux."""
    cmd, text = close(built)
    return text + "\n" + " ".join(cmd)


def tool_folder(env=None):
    return wholetool.tool_folder(wholetool.ADAPTERS["generic"], env or dict(os.environ))


# --- 1. the key ------------------------------------------------------------------------------------

def test_a_relative_entry_is_a_config_problem(tree):
    listed("sib")
    assert "[launch] write_to" in config.load(str(tree / "repo")).problem


def test_an_entry_with_dot_dot_is_a_config_problem(tree):
    listed(f"{tree}/repo/../sib")
    assert "[launch] write_to" in config.load(str(tree / "repo")).problem


def test_a_repo_file_cannot_set_it(tree):
    (tree / "repo" / ".phiward.toml").write_text(f"[launch]\nwrite_to = ['{tree}/sib']\n")
    cfg = config.load(str(tree / "repo"))
    assert cfg.problem == "" and "launch.write_to" in cfg.ignored, cfg.ignored
    assert cfg.launch_write_to == []


def test_tilde_is_expanded_against_the_home_folder_and_entries_are_kept_once(tree):
    listed("~/x", "~/x", f"{tree}/sib")
    cfg = config.load(str(tree / "repo"))
    assert cfg.problem == ""
    assert cfg.launch_write_to == [str(tree / "home" / "x"), str(tree / "sib")]


def test_a_missing_or_linked_entry_is_no_problem_for_the_hook(tree):
    os.symlink(tree / "pub", tree / "lnk")
    listed(tree / "gone", tree / "lnk")
    assert config.load(str(tree / "repo")).problem == ""


# --- 2. the start check: each refusal names the entry and the step, and nothing runs ---------------

def _file(tree, mp):
    (tree / "afile").write_text("x\n")
    return tree / "afile", None


def _link(tree, mp):
    folder(tree)
    os.symlink(tree / "sib", tree / "links" / "to_sib")
    return tree / "links" / "to_sib", None


def _link_above(tree, mp):
    folder(tree, "real/sub")
    os.symlink(tree / "real", tree / "lk")
    return tree / "lk" / "sub", None


def _dangling(tree, mp):
    os.symlink(tree / "gone", tree / "dangling")
    return tree / "dangling", None


def _in_root(tree, mp):
    return tree / "phi" / "sub", None


def _above_root(tree, mp):
    return tree, None


def _above_pattern(tree, mp):
    return tree / "runs", None


def _derived(tree, mp):
    folder(tree, "xdg/phiward")
    return tree / "xdg", dict(os.environ, XDG_CACHE_HOME=str(tree / "xdg"))


def _home(tree, mp):
    return tree / "home", None


def _home_config(tree, mp):
    return folder(tree, "home/.config"), None


def _home_phiward(tree, mp):
    return folder(tree, "home/.phiward"), None


def _path_folder(tree, mp):
    d = folder(tree, "pbin")
    return d, dict(os.environ, PATH=f"{d}:{os.environ.get('PATH', '')}")


def _spool(tree, mp):
    d = folder(tree, "spool")
    return d, dict(os.environ, PHIWARD_SPOOL=str(d))


def _broker(tree, mp):
    d = folder(tree, "bout")
    user(f"[broker]\nwrite_to = ['{d}']\n")
    return d, None


def _above_broker(tree, mp):
    d = folder(tree, "outer/bout")
    user(f"[broker]\nwrite_to = ['{d}']\n")
    return tree / "outer", None


def _holds_config(tree, mp):
    d = folder(tree, "cfgd")
    new = d / "config.toml"
    new.write_text(Path(os.environ["PHIWARD_CONFIG"]).read_text())
    mp.setenv("PHIWARD_CONFIG", str(new))
    return d, None


REFUSALS = {"a file": _file, "a link": _link, "a link above it": _link_above,
            "a dangling link": _dangling, "inside a root": _in_root, "above a root": _above_root,
            "above a pattern": _above_pattern, "a derived folder": _derived, "HOME": _home,
            "HOME/.config": _home_config, "HOME/.phiward": _home_phiward,
            "a PATH folder": _path_folder, "the spool": _spool,
            "a [broker] write_to folder": _broker, "above a [broker] write_to folder": _above_broker,
            "a folder that holds the user config": _holds_config}


@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_a_listed_folder_that_may_not_be_written_stops_the_start(tree, monkeypatch, case):
    entry, env = REFUSALS[case](tree, monkeypatch)
    listed(entry)
    env = env or dict(os.environ)
    with pytest.raises(wholetool.LaunchError) as exc:
        build(tree, env=env)
    msg = str(exc.value)
    assert f"[launch] write_to {entry}" in msg and STEP in msg, msg
    assert not os.path.exists(tool_folder(env)), "a run folder was made"
    if "broker" in case:
        assert "[broker] write_to" in msg.split(STEP)[0].split(str(entry), 1)[1], msg


def test_launch_write_problem_answers_for_one_folder(tree):
    cfg = config.load(str(tree / "repo"))
    env = dict(os.environ)
    assert wholetool.launch_write_problem(str(folder(tree)), cfg, env) == ""
    assert wholetool.launch_write_problem(str(tree / "phi" / "sub"), cfg, env)
    os.symlink(tree / "sib", tree / "lnk")
    assert "link" in wholetool.launch_write_problem(str(tree / "lnk"), cfg, env)


@needs_confine
def test_a_missing_entry_is_skipped_with_a_note(tree, capsys):
    listed(tree / "gone")
    info = {}
    text = session_text(build(tree, info=info))
    err = capsys.readouterr().err
    note = (f"phiward launch: NOTE: [launch] write_to {tree / 'gone'} does not exist, so the "
            "session does not write there")
    assert note in err, err
    assert info["write_to"] == [] and note in info["notes"], info
    assert str(tree / "gone") not in text


@needs_confine
def test_a_folder_inside_the_project_is_dropped_and_named(tree, capsys):
    inner = folder(tree, "repo/sub")
    listed(inner)
    info = {}
    close(build(tree, info=info))
    err = capsys.readouterr().err
    assert f"{inner} (already in the project)" in err, err
    assert info["write_to"] == []


@needs_confine
def test_a_folder_that_holds_the_project_is_allowed(tree):
    project = folder(tree, "work/repo")
    listed(tree / "work")
    info = {}
    close(build(tree, cwd=project, info=info))
    assert info["write_to"] == [str(tree / "work")]


def test_a_folder_inside_another_listed_one_is_dropped(tree):
    s = folder(tree)
    folder(tree, "sib/inner")
    listed(s, s / "inner", s)
    cfg = config.load(str(tree / "repo"))
    got, missing, dropped = wholetool.extra_write_places(cfg, dict(os.environ), str(tree / "repo"))
    assert got == [str(s)] and missing == [] and dropped == [], (got, missing, dropped)


def test_write_places_keeps_the_order_and_each_place_once(tree):
    env = dict(os.environ)
    a, b = str(folder(tree, "a")), str(folder(tree, "b"))
    run = str(folder(tree, "run"))
    project = str(tree / "repo")
    got = wholetool.write_places(project, env, run, extra=[a, b, a])
    assert got[:4] == [project, a, b, run], got
    assert got.count(a) == 1


# --- 3. macOS: the Seatbelt profile (its text; it is made on every platform) ------------------------

def _profile(tree, extra=(), server=False):
    project = str(tree / "repo")
    env = dict(os.environ)
    places = wholetool.write_places(project, env, extra=list(extra))
    return wholetool.seatbelt_tool_profile(config.load(project), places, project, env,
                                           str(tree / "toolfolder"), str(tree / "canary"),
                                           server=server, listed=list(extra))


def test_the_profile_writes_a_listed_folder_and_keeps_its_later_files_read_only(tree):
    s = folder(tree)
    (s / ".git" / "hooks").mkdir(parents=True)
    (s / "inner" / ".git").mkdir(parents=True)
    prof = _profile(tree, [str(s)])
    assert f'(subpath "{s}")' in prof
    rx = wholetool._rx(str(s))
    assert f'(regex #"^{rx}/(.*/)?(' in prof, prof
    assert f'(regex #"^{wholetool._rx(str(s / ".git"))}/(config|' in prof, prof
    assert f'(regex #"^{wholetool._rx(str(s / "inner" / ".git"))}/(config|' in prof, prof


@needs_confine
def test_a_wrapped_server_gets_no_listed_folder(tree):
    s = folder(tree)
    listed(s)
    info = {}
    cmd, text = close(build(tree, server=True, info=info))
    if LINUX:  # the read-only view may name the folder; it is never bound writable
        assert _at(cmd, "--bind", s) == -1, cmd
    else:
        assert str(s) not in text
    assert info.get("write_to", []) == []


def _launch(tree, code, extra=(), cwd=None):
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([PY, "-m", "phiward", "launch", *extra, "--", PY, "-c", code],
                       cwd=str(cwd or tree / "repo"), capture_output=True, text=True, env=env,
                       timeout=120, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


def _tries(paths):
    return ("import errno, os\nfor p in %r:\n    try:\n        d = os.path.dirname(p)\n"
            "        os.makedirs(d, exist_ok=True)\n        open(p, 'w').write('x')\n"
            "        print('DONE', p)\n    except OSError as e:\n"
            "        print('REFUSED', errno.errorcode.get(e.errno, e.errno), p)\n" % (list(paths),))


def _refused(out, path):
    return any(f"REFUSED {code} {path}" in out for code in READ_ONLY)


@needs_confine
@pytest.mark.parametrize("where", ["sib", "sib/nested"])
def test_a_session_writes_a_listed_folder_but_not_what_runs_later_there(tree, where):
    s = folder(tree)
    top = folder(tree, where)
    (top / ".vscode").mkdir()
    (top / ".mcp.json").write_text("{}\n")
    (top / ".git" / "hooks").mkdir(parents=True)
    (top / "sub" / ".claude").mkdir(parents=True)
    listed(s)
    ok = top / "x.txt"
    targets = [top / ".vscode" / "x", top / ".mcp.json", top / ".git" / "hooks" / "x",
               top / "sub" / ".claude" / "x"]
    _code, out = _launch(tree, _tries([str(ok)] + [str(t) for t in targets]))
    assert f"DONE {ok}" in out, out
    for t in targets:
        assert _refused(out, t), (t, out)


@needs_confine
@macos
def test_on_macos_what_runs_later_cannot_be_made_in_a_listed_folder(tree):
    s = folder(tree)
    listed(s)
    targets = [s / ".vscode" / "x", s / ".mcp.json", s / "sub" / ".claude" / "x"]
    _code, out = _launch(tree, _tries([str(t) for t in targets]))
    for t in targets:
        assert f"REFUSED EPERM {t}" in out, (t, out)


# --- 4. Linux: the bwrap arguments ----------------------------------------------------------------

def _args(tree, extra=(), project=None):
    project = str(project or tree / "repo")
    run = tree / "run"
    (run / "tmp").mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    places = wholetool.write_places(project, env, str(run), extra=[str(e) for e in extra])
    return wholetool.bwrap_tool_args(config.load(project), places, project, env,
                                     str(tree / "toolfolder"), str(run),
                                     listed=[str(e) for e in extra])


def _at(args, op, dest):
    """The index of `op <src> dest` in args, or -1."""
    for i in range(len(args) - 2):
        if args[i] == op and args[i + 2] == str(dest):
            return i
    return -1


def _closed(out):
    for fd in out[1]:
        os.close(fd)
    return out


@linux
def test_a_listed_folder_is_bound_after_the_view_and_before_its_read_only_files(tree):
    s = folder(tree)
    (s / ".vscode").mkdir()
    (s / ".git").mkdir()
    (s / ".git" / "config").write_text("[core]\n")
    args, _fds, _checks = _closed(_args(tree, [s]))
    at = _at(args, "--bind", s)
    assert at > args.index("--die-with-parent"), args
    assert args[at + 1].startswith("/proc/self/fd/")
    for ro in (s / ".vscode", s / ".git" / "config"):
        assert _at(args, "--ro-bind", ro) > at, (ro, args)


@linux
def test_a_listed_folder_that_holds_the_project_is_bound_first(tree):
    project = folder(tree, "work/repo")
    work = tree / "work"
    args, _fds, checks = _closed(_args(tree, [work], project=project))
    assert -1 < _at(args, "--bind", work) < _at(args, "--bind", project), args
    dests = {d for d, view, _x in checks if not view}
    assert {str(work), str(project)} <= dests, dests


@linux
def test_a_listed_folder_beside_a_root_is_bound_after_the_split_folder(tree):
    s = folder(tree)
    args, _fds, _checks = _closed(_args(tree, [s]))
    tmpfs =[i for i in range(len(args) - 1) if args[i] == "--tmpfs" and args[i + 1] == str(tree)]
    assert tmpfs and tmpfs[0] < _at(args, "--bind", s), args
    assert not any(args[i] == "--remount-ro" and args[i + 1] == str(s)
                   for i in range(len(args) - 1)), args


@linux
def test_an_existing_mcp_json_in_a_listed_folder_is_read_only(tree):
    s = folder(tree)
    (s / ".mcp.json").write_text("{}\n")
    args, _fds, _checks = _closed(_args(tree, [s]))
    assert _at(args, "--ro-bind", s / ".mcp.json") > _at(args, "--bind", s) > -1, args


@linux
def test_git_control_files_of_repos_in_a_listed_folder_are_read_only_on_linux(tree):
    s = folder(tree)
    (s / ".git" / "hooks").mkdir(parents=True)
    (s / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n")
    (s / "inner" / ".git").mkdir(parents=True)
    (s / "inner" / ".git" / "config").write_text("[core]\n")
    args, _fds, _checks = _closed(_args(tree, [s]))
    assert _at(args, "--ro-bind", s / ".git" / "hooks") > -1, args
    assert _at(args, "--ro-bind", s / "inner" / ".git" / "config") > -1, args


@linux
@needs_confine
def test_launch_makes_nothing_in_a_listed_folder(tree, capsys):
    s = folder(tree)
    listed(s)
    close(build(tree))
    err = capsys.readouterr().err
    for n in (".claude", ".vscode", ".idea", ".mcp.json"):
        assert not os.path.lexists(s / n), n
    line = [ln for ln in err.splitlines() if "made empty, read-only folders" in ln]
    assert line and str(s) not in line[0], err


@linux
@needs_confine
def test_what_a_session_makes_in_a_listed_folder_is_named_at_exit(tree):
    s = folder(tree)
    listed(s)
    report = folder(tree, "out") / "report.json"
    code = ("import os\nopen(%r, 'w').write('{}')\nos.makedirs(%r)\nopen(%r, 'w').write('x')\n"
            "try:\n    open(%r, 'w').write('x')\n    print('WROTE')\nexcept OSError:\n"
            "    print('REFUSED')\n"
            % (str(s / ".mcp.json"), str(s / "sub" / ".vscode"),
               str(s / "sub" / ".vscode" / "f.json"), str(tree / "repo" / ".mcp.json")))
    _rc, out = _launch(tree, code, ("--report", str(report)))
    assert "REFUSED" in out and "WROTE" not in out, out
    tail = out.split(f"in {s}", 1)
    assert len(tail) == 2 and ".mcp.json" in tail[1] and "sub/.vscode/f.json" in tail[1], out
    data = json.loads(report.read_text())
    notes = "\n".join(data["notes"])
    assert f"in {s}" in notes and ".mcp.json" in notes, notes


# --- 5. a listed folder replaced after the check (Linux) ------------------------------------------

@linux
def test_a_listed_folder_swapped_for_a_link_is_not_written(tree, monkeypatch):
    s = folder(tree)
    real = wholetool._open_no_follow

    def swapping(path):
        if path == str(s) and not os.path.islink(path):
            os.rename(s, tree / "sib-away")
            os.symlink(tree / "pub", s)
        return real(path)
    monkeypatch.setattr(wholetool, "_open_no_follow", swapping)
    try:
        args, _fds, _checks = _closed(_args(tree, [s]))
    except wholetool.LaunchError:
        return  # the start stops
    assert _at(args, "--bind", s) == -1 and _at(args, "--bind", tree / "pub") == -1, args


# --- 7. the project scan --------------------------------------------------------------------------

def _scan_refusal(tree):
    with pytest.raises(wholetool.LaunchError) as exc:
        build(tree)
    return str(exc.value)


def test_a_finding_in_a_listed_folder_stops_the_start_and_names_it(tree):
    scan_cfg()
    s = folder(tree)
    (s / "notes.txt").write_text("FAKE-PT-0001\n")
    listed(s)
    msg = _scan_refusal(tree)
    assert msg.startswith("the project scan found <SUBJECT> in 1 file") and str(s) in msg, msg
    assert "FAKE-PT-0001" not in msg
    assert not os.path.exists(tool_folder())


def test_a_listed_skill_is_scanned_before_the_tool_starts(tree):
    scan_cfg()
    s = folder(tree)
    (s / ".claude" / "skills" / "x").mkdir(parents=True)
    (s / ".claude" / "skills" / "x" / "SKILL.md").write_text("# a\nFAKE-PT-0001\n")
    listed(s)
    msg = _scan_refusal(tree)
    assert "the project scan found" in msg and str(s) in msg, msg


class _Clock:
    """A clock that moves 1 ms each time it is read (test_projectscan's)."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        self.now += 0.001
        return self.now


def _bulk(top, n=3000):
    for i in range(n):
        d = top / "pkg" / f"d{i // 100}"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"m{i}.py").write_text("x = 1\n")


def test_the_instruction_files_of_every_folder_are_read_before_the_bulk(tree, monkeypatch):
    scan_cfg()
    _bulk(tree / "repo")
    s = folder(tree)
    (s / ".claude" / "rules").mkdir(parents=True)
    (s / ".claude" / "rules" / "r.md").write_text("# a\nFAKE-PT-0001\n")
    listed(s)
    monkeypatch.setattr(projectscan, "time", _Clock())
    monkeypatch.setattr(projectscan, "BUDGET", 0.05)
    msg = _scan_refusal(tree)
    assert "the project scan found" in msg and str(s) in msg, msg


def test_instruction_files_not_read_in_time_stop_the_start(tree, monkeypatch):
    scan_cfg()
    s = folder(tree)
    for i in range(300):
        (s / ".claude" / "skills" / f"s{i}").mkdir(parents=True)
        (s / ".claude" / "skills" / f"s{i}" / "SKILL.md").write_text("made-up\n")
    listed(s)
    monkeypatch.setattr(projectscan, "time", _Clock())
    monkeypatch.setattr(projectscan, "BUDGET", 0.05)
    msg = _scan_refusal(tree)
    assert msg.startswith(f"the project scan could not read the instruction files of {s} in "), msg
    assert "run phiward doctor, or make them smaller" in msg, msg


@needs_confine
def test_the_projects_own_instruction_files_over_the_budget_keep_the_note(tree, monkeypatch,
                                                                          capsys):
    # with no listed folder the project keeps its old rule: a NOTE, and the tool starts
    scan_cfg()
    repo = tree / "repo"
    for i in range(300):
        (repo / ".claude" / "skills" / f"s{i}").mkdir(parents=True)
        (repo / ".claude" / "skills" / f"s{i}" / "SKILL.md").write_text("made-up\n")
    monkeypatch.setattr(projectscan, "time", _Clock())
    monkeypatch.setattr(projectscan, "BUDGET", 0.05)
    close(build(tree))
    assert "the project scan stopped at its" in capsys.readouterr().err


@needs_confine
def test_the_bulk_not_read_in_time_gives_the_note_and_starts(tree, monkeypatch, capsys):
    scan_cfg()
    _bulk(tree / "repo")
    s = folder(tree)
    listed(s)
    monkeypatch.setattr(projectscan, "time", _Clock())
    monkeypatch.setattr(projectscan, "BUDGET", 0.05)
    close(build(tree))
    err = capsys.readouterr().err
    line = [ln for ln in err.splitlines() if "the project scan stopped at its" in ln]
    assert line and str(s) in line[0], err


def test_a_whole_scan_reads_both_parts_as_before(tree):
    scan_cfg()
    repo = tree / "repo"
    (repo / "CLAUDE.md").write_text("FAKE-PT-0001\n")
    (repo / "notes.txt").write_text("FAKE-PT-0002\n")
    cfg = config.load(str(repo))
    whole = projectscan.scan(cfg, str(repo))
    assert whole == projectscan.scan(cfg, str(repo), part=None)
    first = projectscan.scan(cfg, str(repo), part="first")
    rest = projectscan.scan(cfg, str(repo), part="rest")
    assert sorted(first.hits + rest.hits) == sorted(whole.hits), (first, rest, whole)
    assert [h[0] for h in first.hits] == ["CLAUDE.md"], first


# --- 8. visible: the start line, the report, doctor -----------------------------------------------

@needs_confine
def test_the_start_names_the_listed_folders(tree, capsys):
    s = folder(tree)
    listed(s)
    info = {}
    close(build(tree, info=info))
    assert f"phiward launch: the session also writes: {s}" in capsys.readouterr().err
    assert info["write_to"] == [str(s)]


def test_the_end_report_names_the_folder_in_its_header(tree):
    s = str(folder(tree))
    changes = carryover.Changes({0: [], 1: [], 2: [(".mcp.json", "new")], 3: []}, False)
    lines = carryover.project_report(changes, where=s)
    assert f"in {s}" in lines[0] and "in the project" not in lines[0], lines
    assert carryover.project_report(changes)[0].startswith(
        "phiward launch: the session changed 1 file(s) in the project;")


def test_the_truncation_warning_of_a_listed_folder_names_the_folder(tree):
    s = str(folder(tree))
    changes = carryover.Changes({0: [], 1: [], 2: [], 3: []}, True)
    warning = [ln for ln in carryover.project_report(changes, where=s) if "WARNING" in ln]
    assert warning and f"Read {s} before" in warning[0], warning
    assert "the project" not in warning[0], warning
    own = [ln for ln in carryover.project_report(changes) if "WARNING" in ln]
    assert "Read the project before you run anything outside launch." in own[0], own


@needs_confine
def test_the_report_json_holds_the_listed_folders(tree):
    s = folder(tree)
    listed(s)
    report = folder(tree, "out") / "report.json"
    _rc, out = _launch(tree, "print('RAN')", ("--report", str(report)))
    assert json.loads(report.read_text())["write_to"] == [str(s)], out


def test_a_report_file_cannot_be_in_a_listed_folder(tree, monkeypatch):
    s = folder(tree)
    listed(s)
    monkeypatch.chdir(tree / "repo")
    _full, why = wholetool._report_place(str(s / "r.json"), dict(os.environ))
    assert why, "a report inside a listed folder was allowed"


def test_doctor_names_a_linked_and_a_missing_entry(tree):
    folder(tree)
    os.symlink(tree / "sib", tree / "lnk")
    listed(tree / "lnk", tree / "gone")
    cfg = config.load(str(tree / "repo"))
    lines = doctor.launch_report(str(tree / "repo"), str(tree / "home"), cfg, dict(os.environ))
    text = "\n".join(lines)
    assert f"WARNING: launch would refuse to start here: [launch] write_to {tree / 'lnk'}" in text
    assert "launch writes also: 0 folder(s) ([launch] write_to) (skipped: 1 that do not exist)" \
        in text, text
    assert f"NOTE: [launch] write_to {tree / 'gone'} does not exist" in text, text


def test_doctor_lists_the_folders_with_show_paths(tree):
    s = folder(tree)
    listed(s)
    cfg = config.load(str(tree / "repo"))
    args = (str(tree / "repo"), str(tree / "home"), cfg, dict(os.environ))
    shown = "\n".join(doctor.launch_report(*args, show=True))
    hidden = "\n".join(doctor.launch_report(*args))
    assert "launch writes also: 1 folder(s) ([launch] write_to)" in hidden, hidden
    assert str(s) in shown and str(s) not in hidden, (shown, hidden)


def test_headless_lists_a_launch_refusal(tree):
    os.symlink(tree / "pub", tree / "lnk")
    listed(tree / "lnk")
    problems = doctor.headless_problems(str(tree / "repo"), str(tree / "home"))
    assert any(f"[launch] write_to {tree / 'lnk'}" in p for p in problems), problems


# --- 8a. an abnormal end --------------------------------------------------------------------------

LAUNCHER = r"""
import json, os, signal, sys
from phiward import carryover, wholetool
project, sib, report, pidfile, home, base, ignore = sys.argv[1:8]
if ignore:  # as under nohup: the launcher inherits SIGHUP ignored
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
child = ("import os, time\nopen(%r, 'w').write('{}')\n"
         "open(%r, 'w').write(str(os.getpid()))\ntime.sleep(60)\n" % (
             os.path.join(sib, '.mcp.json'), pidfile))
run = wholetool._Run()
run.write_to = [sib]
run.record = (base, os.path.join(base, "runs", "20260101-000000-0000cccc"))
store = carryover.Store("generic", home)
code = wholetool._run_tool([sys.executable, "-c", child], dict(os.environ), [], project,
                           lambda: None, store, os.path.join(home, "toolfolder"), run,
                           listed=[sib])
sys.exit(wholetool._end(report, run, code))
"""


def _signalled(tree, sig, ignore=False, then_kill_tool=False):
    """The stand-in launcher, its tool started, sent `sig`: (its exit, stderr, the record)."""
    s = folder(tree)
    base, runs = _runs(tree)
    rec = runs / "20260101-000000-0000cccc.write_to"
    rec.write_text(f"{s}\n")
    report = tree / "out.json"
    pidfile = tree / "child.pid"
    p = subprocess.Popen([PY, "-c", LAUNCHER, str(tree / "repo"), str(s), str(report),
                          str(pidfile), str(tree / "home"), str(base), "1" if ignore else ""],
                         env=dict(os.environ, PYTHONPATH=SRC),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         stdin=subprocess.DEVNULL)
    child = 0
    try:
        for _ in range(600):
            if pidfile.exists() and pidfile.read_text():
                child = int(pidfile.read_text())
                break
            time.sleep(0.05)
        assert child, "the stand-in tool did not start"
        time.sleep(0.2)
        p.send_signal(sig)
        if then_kill_tool:
            time.sleep(1)
            assert p.poll() is None, "the launcher ended on an ignored signal"
            os.kill(child, signal.SIGKILL)
            child = 0
        _out, err = p.communicate(timeout=60)
    finally:
        if p.poll() is None:
            p.kill()
        if child:
            try:
                os.kill(child, signal.SIGKILL)
            except OSError:
                pass
    return p.returncode, err, rec


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGHUP])
def test_sigterm_and_sighup_still_give_the_exit_report(tree, sig):
    code, err, rec = _signalled(tree, sig)
    s = tree / "sib"
    assert code == 128 + sig, (code, err)
    assert f"in {s}" in err and ".mcp.json" in err.split(f"in {s}", 1)[1], err
    data = json.loads((tree / "out.json").read_text())
    assert data["exit"] == 128 + sig
    assert any(".mcp.json" in n for n in data["notes"]), data
    # on macOS the tool may outlive the launcher: the next start names the folders
    assert rec.exists(), "the record went with a signal end"


def test_an_inherited_ignored_sighup_stays_ignored(tree):
    code, err, rec = _signalled(tree, signal.SIGHUP, ignore=True, then_kill_tool=True)
    # the tool's own end (sys.exit(-9) is status 247), not the signal's
    assert code == -signal.SIGKILL & 0xFF, (code, err)
    assert not rec.exists(), "a normal end keeps the record"


def test_an_orphaned_record_gives_the_note(tree):
    # its run folder already went to the trash (the launcher died during the end walks)
    base, runs = _runs(tree)
    rec = runs / "20260101-000000-0000dddd.write_to"
    rec.write_text(f"{tree / 'sib'}\n")
    msgs = carryover._clean_runs(str(base), str(runs / "now"), lambda n: [])
    text = "\n".join(msgs)
    assert "an earlier session (20260101-000000-0000dddd) did not finish" in text, text
    assert str(tree / "sib") in text and not os.path.lexists(rec), text


def _run_name(store):
    return os.path.basename(store.run)


@needs_confine
def test_build_writes_the_record_of_the_write_set_outside_it(tree):
    s = folder(tree)
    listed(s)
    store = carryover.Store("generic", str(tree / "home"))
    close(build(tree, store=store))
    try:
        rec = Path(tool_folder()) / "runs" / (_run_name(store) + ".write_to")
        assert rec.read_text().splitlines() == [str(s)]
        assert stat.S_IMODE(rec.lstat().st_mode) == 0o600
        places = wholetool.write_places(str(tree / "repo"), dict(os.environ), store.run,
                                        extra=[str(s)])
        assert not any(os.path.realpath(str(rec)).startswith(p.rstrip("/") + "/")
                       for p in places), places
    finally:
        store.end(tool_folder())


@needs_confine
def test_no_record_for_an_empty_list(tree):
    store = carryover.Store("generic", str(tree / "home"))
    close(build(tree, store=store))
    try:
        assert not os.path.lexists(Path(tool_folder()) / "runs" /
                                   (_run_name(store) + ".write_to"))
    finally:
        store.end(tool_folder())


KILLED = r"""
import os, sys, time
from phiward import wholetool
built = wholetool.build(["/bin/echo", "x"], sys.argv[1], dict(os.environ),
                        wholetool.ADAPTERS["generic"])
print("BUILT", flush=True)
time.sleep(60)
"""


@needs_confine
def test_after_sigkill_the_next_start_names_the_folders(tree):
    s = folder(tree)
    listed(s)
    p = subprocess.Popen([PY, "-c", KILLED, str(tree / "repo")],
                         env=dict(os.environ, PYTHONPATH=SRC), stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL)
    try:
        line = p.stdout.readline()
        assert line.startswith("BUILT"), (line, p.stderr.read() if p.poll() is not None else "")
    finally:
        os.kill(p.pid, signal.SIGKILL)
        p.wait(timeout=30)
    runs = Path(tool_folder()) / "runs"
    recs = [n for n in os.listdir(runs) if n.endswith(".write_to")]
    assert len(recs) == 1, recs
    store = carryover.Store("generic", str(tree / "home"))
    msgs = store.start(tool_folder(), str(runs / "20260101-000000-0000beef"))
    try:
        text = "\n".join(msgs)
        assert "phiward launch: NOTE: an earlier session" in text and str(s) in text, text
        assert not os.path.lexists(runs / recs[0])
    finally:
        store.end(tool_folder())


def _runs(tree):
    base = Path(tool_folder())
    (base / "runs").mkdir(parents=True, exist_ok=True)
    (base / "trash").mkdir(parents=True, exist_ok=True)
    return base, base / "runs"


def test_a_live_sessions_record_is_left_alone(tree):
    import fcntl
    base, runs = _runs(tree)
    (runs / "20260101-000000-0000aaaa").mkdir()
    rec = runs / "20260101-000000-0000aaaa.write_to"
    rec.write_text(f"{tree / 'sib'}\n")
    fd = os.open(runs / "20260101-000000-0000aaaa", os.O_RDONLY)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        msgs = carryover._clean_runs(str(base), str(runs / "now"), lambda n: [])
    finally:
        os.close(fd)
    assert rec.exists() and not any("earlier session" in m for m in msgs), msgs


@pytest.mark.parametrize("bad", ["link", "large"])
def test_a_garbled_or_linked_record_gives_the_unknown_note(tree, bad):
    base, runs = _runs(tree)
    (runs / "20260101-000000-0000bbbb").mkdir()
    rec = runs / "20260101-000000-0000bbbb.write_to"
    target = tree / "pub" / "target.txt"
    target.write_text(f"{tree / 'sib'}\n")
    if bad == "link":
        os.symlink(target, rec)
    else:
        rec.write_text("x" * (64 * 1024 + 1))
    msgs = carryover._clean_runs(str(base), str(runs / "now"), lambda n: [])
    text = "\n".join(msgs)
    assert "an earlier session (20260101-000000-0000bbbb) did not finish" in text, text
    assert "its write folders are unknown" in text and str(tree / "sib") not in text, text
    assert not os.path.lexists(rec)
    assert target.read_text() == f"{tree / 'sib'}\n"


def test_claude_code_inside_a_listed_folder_is_refused(tree):
    s = folder(tree)
    listed(s)
    claude = fake_native_claude(s / "cc" / "claude", python=True)
    with pytest.raises(wholetool.LaunchError, match="a folder the session can write"):
        build(tree, argv=[str(claude)], adapter="claude")


# --- 9. the broker and pseudonymize ---------------------------------------------------------------

def test_the_brokers_path_filter_drops_an_entry_in_a_listed_folder(tree):
    s = folder(tree)
    folder(tree, "sib/bin")
    keep = folder(tree, "tbin")
    listed(s)
    path = f"{s / 'bin'}:{keep}"
    got = service.path_entries(path, service.path_inputs())
    assert str(keep) in got and str(s / "bin") not in got, got


def test_pseudonymize_refuses_an_input_in_a_listed_folder(tree, monkeypatch):
    s = folder(tree)
    (s / "t.tsv").write_text("id\tx\nA\t1\n")
    other = folder(tree, "mine")
    (other / "t.tsv").write_text("id\tx\nA\t1\n")
    listed(s)
    monkeypatch.chdir(tree / "pub")
    cfg = config.load(str(tree / "pub"))
    home = str(tree / "home")
    assert pseudonymize._input_place(str(other / "t.tsv"), cfg, home)
    with pytest.raises(pseudonymize.Refused):
        pseudonymize._input_place(str(s / "t.tsv"), cfg, home)


def test_an_unreadable_user_config_makes_every_folder_agent_writable(tree):
    Path(os.environ["PHIWARD_CONFIG"]).write_text("[launch\nwrite_to = \n")
    assert "/" in claude_settings.agent_writable_anywhere(str(tree / "home"))


def test_a_user_config_not_written_yet_lists_no_folders(tree, tmp_path):
    # setup names the file before it writes it: nothing is listed, nothing is refused
    env = dict(os.environ, PHIWARD_CONFIG=str(tmp_path / "not-yet.toml"))
    assert config.launch_write_to_entries(env) == []


def test_listed_folders_are_agent_writable_anywhere(tree):
    s = folder(tree)
    listed(s, tree / "gone")
    got = claude_settings.agent_writable_anywhere(str(tree / "home"))
    assert str(s) in got and str(tree / "gone") in got, got


# --- 10. Claude Code: --add-dir -------------------------------------------------------------------

def test_with_add_dirs_puts_each_folder_last_as_two_words():
    assert wholetool._with_add_dirs(["claude", "-p", "hi"], ["/x/sib", "/x/b"]) == [
        "claude", "-p", "hi", "--add-dir", "/x/sib", "--add-dir", "/x/b"]
    assert wholetool._with_add_dirs(["claude"], []) == ["claude"]


def _claude_cmd(tree, args=(), **kw):
    built = build(tree, argv=[tool_py(tree)] + list(args), adapter="claude", **kw)
    cmd, _text = close(built)
    return cmd


@needs_confine
def test_claude_gets_add_dir_for_a_listed_folder_after_its_arguments(tree):
    s = folder(tree)
    listed(s)
    cmd = _claude_cmd(tree, ["-p", "hi"])
    i = len(cmd) - 1 - cmd[::-1].index("--add-dir")
    assert cmd[i:i + 2] == ["--add-dir", str(s)], cmd
    assert cmd.index("hi") < i, cmd
    assert cmd[i + 2:] in ([], ["--settings", json.dumps(wholetool.INNER_SETTINGS)]), cmd


@linux
@needs_confine
def test_in_the_inner_mode_add_dir_comes_before_settings(tree, monkeypatch):
    monkeypatch.setattr(wholetool, "landlock_abi", lambda: 0)
    s = folder(tree)
    listed(s)
    cmd = _claude_cmd(tree, ["-p", "hi"])
    assert cmd[-4:] == ["--add-dir", str(s), "--settings", json.dumps(wholetool.INNER_SETTINGS)]


def test_a_dash_dash_with_a_listed_folder_refuses(tree):
    s = folder(tree)
    listed(s)
    with pytest.raises(wholetool.LaunchError) as exc:
        build(tree, argv=[tool_py(tree), "--", "hi"], adapter="claude")
    assert str(exc.value) == wholetool.DASH_DASH
    assert "--add-dir" in wholetool.DASH_DASH, wholetool.DASH_DASH


@needs_confine
def test_no_add_dir_for_generic_a_server_or_a_missing_entry(tree):
    s = folder(tree)
    listed(s)
    cmd, _t = close(build(tree, argv=[tool_py(tree), "-p", "hi"], adapter="generic"))
    assert "--add-dir" not in cmd
    cmd = _claude_cmd(tree, ["-p", "hi"], server=True)
    assert "--add-dir" not in cmd


@needs_confine
def test_no_add_dir_for_a_missing_entry(tree):
    listed(tree / "gone")
    assert "--add-dir" not in _claude_cmd(tree, ["-p", "hi"])


@needs_confine
def test_the_variable_for_instruction_files_is_passed_on_as_it_is(tree):
    s = folder(tree)
    listed(s)
    env = dict(os.environ, CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD="1")
    built = build(tree, argv=[tool_py(tree)], adapter="claude", env=env)
    child_env = built[1]
    close(built)
    assert child_env.get("CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD") == "1"
