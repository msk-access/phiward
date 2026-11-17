"""The release goal G4, as attacks: an agent that can write only the project, the spool and the
folders Claude Code's sandbox opens must not make an MCP server count as wrapped when it is not,
plant a launcher or a backup, or make phiward write an entry that starts its code. Each test is
an attack from a review round, written as the safe result that must hold. phiward is installed
with a record here (`helpers.installed_site`), as a user installs it. Made-up trees only."""

import io
import json
import os
import sys

import pytest

from phiward import config, install, mcp_config, selfcheck
from phiward.adapters import claude
from helpers import Tty, installed_site, protect

ID = "0123456789abcdef"
PROG = ["npx", "-y", "some-server"]
RUN = {"command": "id"}


def _plant(folder):
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / "phiward"
    p.write_text("#!/bin/sh\necho planted\n")
    p.chmod(0o755)
    return str(p)


@pytest.fixture()
def t(tree, monkeypatch, launchers):
    _record, _pkg, exe = installed_site(tree)
    real = {os.path.realpath(exe), os.path.realpath(os.path.join(os.path.dirname(exe),
                                                                 "agent-guards"))}
    monkeypatch.setattr(selfcheck, "launcher_scripts",
                        lambda record=None, package_dir=None: frozenset(real))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(sys, "stdin", Tty())
    protect(tree, [], best_effort=False)
    mcp_config._launcher_exes.cache_clear()
    yield _T(tree, launchers, exe)
    mcp_config._launcher_exes.cache_clear()


class _T:
    def __init__(self, tree, launchers, exe):
        self.tree, self.L, self.exe = tree, launchers, exe

    def __truediv__(self, other):
        return self.tree / other

    def wrapped(self, eid=ID, command=None):
        return {"command": command or self.exe, "args": ["launch", "--entry", eid, "--"] + PROG}

    def user(self, servers):
        (self.tree / "home" / ".claude.json").write_text(json.dumps({"mcpServers": servers}))

    def start(self, spec):
        self.L.start(mcp_config.launch_hash(spec["args"][1:]))

    def hook(self, name="a"):
        p = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(self.tree / "repo"),
             "permission_mode": "default", "tool_name": f"mcp__{name}__run_command",
             "tool_input": RUN, "mcp_server": {"name": name, "source": "user"}}
        return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), io.StringIO())


# --- the launcher -------------------------------------------------------------------------------

def test_the_control_a_wrapped_entry_with_its_launcher_is_trusted(t):
    t.user({"a": t.wrapped()})
    t.start(t.wrapped())
    assert t.hook() == 0


def test_phiward_by_name_is_never_trusted_even_with_a_launcher_of_its_hash(t, monkeypatch):
    # a planted .venv/bin/phiward could have started it and written its own record
    _plant(t / "repo" / ".venv" / "bin")
    monkeypatch.setenv("PATH", f"{t / 'repo' / '.venv' / 'bin'}:/usr/bin:/bin")
    spec = t.wrapped(command="phiward")
    t.user({"a": spec})
    t.start(spec)
    assert t.hook() == 2


@pytest.mark.parametrize("where", ["repo/.venv/bin", "repo/node_modules/.bin", "scratch/bin",
                                   "tmp/bin"])
def test_a_launcher_planted_on_path_is_never_the_one_wrap_writes(t, monkeypatch, where):
    planted = _plant(t / where)
    monkeypatch.setenv("PATH", f"{os.path.dirname(planted)}:/usr/bin:/bin")
    mcp_config._launcher_exes.cache_clear()
    assert mcp_config.installed_launcher() == t.exe
    t.user({"a": {"command": "npx", "args": PROG[1:]}})
    assert mcp_config.main(["wrap", "a", "--yes"]) == 0
    got = json.loads((t / "home" / ".claude.json").read_text())["mcpServers"]["a"]
    assert got["command"] == t.exe
    # and an entry that names the planted file is not wrapped
    assert mcp_config.entry_state(t.wrapped(command=planted)) != "wrapped"


def test_a_group_writable_install_folder_still_wraps(t):
    # umask 002 with a private group: the record decides, not the folder's mode
    os.chmod(os.path.dirname(t.exe), 0o775)
    t.user({"a": {"command": "npx", "args": PROG[1:]}})
    assert mcp_config.main(["wrap", "a", "--yes"]) == 0
    got = json.loads((t / "home" / ".claude.json").read_text())["mcpServers"]["a"]
    assert mcp_config.entry_state(got) == "wrapped"


def test_claude_code_in_the_home_folder_still_finds_the_launcher(t, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(t / "home"))
    mcp_config._launcher_exes.cache_clear()
    assert mcp_config.installed_launcher() == t.exe


# --- one entry, one launcher --------------------------------------------------------------------

@pytest.mark.parametrize("twin", [
    lambda t: {"command": "sh", "args": ["-c", f'exec "$0" launch --entry {ID} -- "$@"', t.exe]
               + PROG},
    lambda t: {"command": "sh", "args": ["-c", f"X=npx; exec {t.exe} launch --entry {ID} -- $X"]},
    lambda t: {"command": "python3", "args": [
        "-c", f"import os; os.execv({t.exe!r}, ['p', 'launch', '--entry', '{ID}', '--', 'npx'])"]},
    lambda t: {"command": "nice", "args": [t.exe] + t.wrapped()["args"]},
    lambda t: dict(t.wrapped(), cwd="/tmp"),
])
def test_a_twin_in_any_spelling_makes_the_entry_trusted_for_nothing(t, twin):
    t.user({"a": t.wrapped(), "twin": twin(t)})
    t.start(t.wrapped())
    t.start(t.wrapped())
    assert t.hook() == 2


def test_a_twin_with_the_id_escaped_in_another_file_is_still_found(t):
    t.user({"a": t.wrapped()})
    escaped = json.dumps({"mcpServers": {"p": t.wrapped()}}).replace(ID, "\\u0030" + ID[1:])
    (t / "repo" / ".mcp.json").write_text(escaped)
    t.start(t.wrapped())
    assert t.hook() == 2


def test_a_launcher_without_the_entry_id_never_vouches(t):
    # a twin that starts the same program without the id (an older entry, a wrapper): its
    # launcher has another hash
    t.user({"a": t.wrapped(), "old": {"command": t.exe, "args": ["launch", "--"] + PROG}})
    t.L.start(mcp_config.launch_hash(["--"] + PROG))
    assert t.hook() == 2


# --- the backups ---------------------------------------------------------------------------------

def test_a_backup_planted_beside_the_project_file_is_never_shown(t, capsys):
    (t / "repo" / ".mcp.json").write_text(json.dumps({"mcpServers": {"a": {"command": "npx"}}}))
    (t / "repo" / ".mcp.json.phiward.orig").write_text('{"evil": 1}')
    (t / "repo" / ".mcp.json.phiward.bak").write_text('{"evil": 1}')
    assert mcp_config.main(["wrap", "a", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "phiward.orig" not in out and "phiward.bak" not in out
    folder = mcp_config.backup_dir(str(t / "repo" / ".mcp.json"), str(t / "home"))
    assert "evil" not in open(os.path.join(folder, "original")).read()


def test_the_backups_folder_is_denied_to_the_sandboxed_shell(t):
    cfg = config.load(str(t / "repo"))
    backups = str(t / "home" / ".phiward" / "backups")
    deny = install.wiring(cfg)["sandbox"]["filesystem"]["denyWrite"]
    home = os.environ["HOME"]
    full = [os.path.join(home, x[2:]) if x.startswith("~/") else x for x in deny]
    assert backups in full or backups.replace(home, "~", 1) in deny, deny


# --- the launcher is a file, never Python with -m (review of 6997fb6) -------------------------

@pytest.mark.parametrize("pre", [["-m", "phiward"], ["-I", "-m", "phiward"], ["-B", "-m", "phiward"]])
def test_python_dash_m_phiward_is_never_the_launcher(t, pre):
    # without -I, `-m` imports the project folder's `phiward/` first: a planted one would run
    spec = {"command": sys.executable,
            "args": pre + ["launch", "--entry", ID, "--"] + PROG}
    assert mcp_config.entry_state(spec) != "wrapped"
    t.user({"a": spec})
    t.L.start(mcp_config.launch_hash(["--entry", ID, "--"] + PROG))
    assert t.hook() == 2


def test_list_names_the_python_form_and_wrap_leaves_it_with_the_step(t, capsys):
    # round 4: Python with `-m phiward` is a runner like uvx: wrap does not rewrite it
    spec = {"command": sys.executable, "args": ["-m", "phiward", "launch", "--entry", ID, "--"]
            + PROG}
    t.user({"a": spec})
    before = (t / "home" / ".claude.json").read_text()
    assert mcp_config.main(["list"]) == 0
    assert "edit the entry so its command is the server program itself" in \
        capsys.readouterr().out
    mcp_config.main(["wrap", "a", "--yes"])
    assert (t / "home" / ".claude.json").read_text() == before


# --- the real install-record lookup, not a stand-in (review of 6997fb6) ------------------------

@pytest.fixture()
def real(tree, monkeypatch, launchers):
    """phiward installed with a record, found by the real lookup (selfcheck.launcher_scripts):
    only the record and the running package's folder are pointed at the made-up install."""
    record, pkg, exe = installed_site(tree / "real")
    monkeypatch.setattr(selfcheck, "_record_path", lambda: record)
    monkeypatch.setattr(selfcheck, "_running_package", lambda: pkg)
    selfcheck._SCRIPTS_CACHE.clear()
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(sys, "stdin", Tty())
    protect(tree, [], best_effort=False)
    yield _T(tree, launchers, exe)
    selfcheck._SCRIPTS_CACHE.clear()


def test_the_real_lookup_finds_the_recorded_launcher(real):
    assert mcp_config.installed_launcher() == os.path.realpath(real.exe)
    real.user({"a": real.wrapped(command=os.path.realpath(real.exe))})
    real.start(real.wrapped())
    assert real.hook() == 0


def test_an_entry_that_names_the_path_link_is_named_and_wrap_gives_it_the_file(real, capsys):
    # uv tool puts a link in ~/.local/bin; another program could replace a link, the record's
    # file is a guard file
    link = real / "home" / ".local" / "bin"
    link.mkdir(parents=True)
    os.symlink(real.exe, str(link / "phiward"))
    spec = real.wrapped(command=str(link / "phiward"))
    real.user({"a": spec})
    assert mcp_config.entry_state(spec) != "wrapped"
    assert mcp_config.main(["list"]) == 0
    assert "not the installed launcher" in capsys.readouterr().out
    assert mcp_config.main(["wrap", "a", "--yes"]) == 0
    got = json.loads((real / "home" / ".claude.json").read_text())["mcpServers"]["a"]
    assert got["command"] == os.path.realpath(real.exe)


# --- other spellings of the launcher: named and rewritten, never trusted (review of 67f65ee) ----

SPELLINGS = [
    ["uvx", "phiward", "launch"],
    ["uvx", "--from", "phiward==0.2.0b1", "phiward", "launch"],
    ["/usr/bin/env", "phiward", "launch"],
    ["env", "FOO=1", "phiward", "launch"],
    ["uv", "run", "phiward", "launch"],
    ["pipx", "run", "phiward", "launch"],
    ["python3", "-W", "ignore", "-m", "phiward", "launch"],
]


RUNNER_STEP = "edit the entry so its command is the server program itself"


@pytest.mark.parametrize("pre", SPELLINGS)
def test_another_spelling_is_a_runner_and_wrap_and_unwrap_leave_it_with_one_step(t, capsys, pre):
    # round 4: the words of a runner mean different things for each one (`uvx --from X` starts
    # phiward, `env K=V` sets the program's environment, `uv run --directory D` its folder), so
    # wrap never rewrites them: it says what to edit (round 3 rewrote them and dropped the words)
    spec = {"command": pre[0], "args": pre[1:] + ["--entry", ID, "--"] + PROG}
    assert mcp_config.entry_state(spec) == "runner"
    t.user({"a": spec})
    before = (t / "home" / ".claude.json").read_text()
    assert mcp_config.main(["list"]) == 0
    out = capsys.readouterr().out
    assert RUNNER_STEP in out and f"through `{os.path.basename(pre[0])}`" in out, out
    mcp_config.main(["wrap", "a", "--yes"])
    assert RUNNER_STEP in capsys.readouterr().out
    mcp_config.main(["unwrap", "a", "--yes"])
    assert RUNNER_STEP in capsys.readouterr().out
    assert (t / "home" / ".claude.json").read_text() == before


def test_a_runner_entry_gets_the_same_step_from_the_hook_doctor_and_list(t):
    import types
    from phiward import doctor
    spec = {"command": "uvx", "args": ["phiward", "launch", "--entry", ID, "--"] + PROG}
    t.user({"a": spec})
    project, home = str(t / "repo"), str(t / "home")
    states = mcp_config.name_states(project, home)["a"]
    why = mcp_config.cannot_wrap_why(states)
    assert RUNNER_STEP in why, why
    assert doctor.bare_split(project, home) == ([], [("a", why)])
    configured = types.SimpleNamespace(name="a", source="user", wrapped=False, untrusted=False,
                                       here=False, unwrappable=False)
    advice = claude._advice("mcp__a__run_command", configured, True, (states, []))
    assert RUNNER_STEP in advice, advice


def test_options_before_the_dash_dash_are_not_wrapped_and_wrap_drops_them(t, capsys):
    # round 4 (review of the plan): `--report PATH` makes the launcher write before it confines;
    # an entry the agent or a repository wrote must not carry it into what the operator's wrap
    # then trusts
    spec = {"command": t.exe, "args": ["launch", "--report", str(t / "r.json"), "--entry", ID,
                                       "--"] + PROG}
    assert mcp_config.entry_state(spec) == "bare"
    assert not mcp_config.is_wrapped(mcp_config._command(spec), spec)
    t.user({"a": spec})
    assert mcp_config.main(["list"]) == 0
    assert "options before `--`" in capsys.readouterr().out
    assert mcp_config.main(["wrap", "a", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "dropped" in out and "--report" in out, out
    got = json.loads((t / "home" / ".claude.json").read_text())["mcpServers"]["a"]
    assert got["command"] == t.exe and got["args"][:2] == ["launch", "--entry"], got
    assert got["args"][3:] == ["--"] + PROG and mcp_config.entry_state(got) == "wrapped"


@pytest.mark.parametrize("change,step", [
    ({"cwd": "/tmp"}, "remove `cwd` and give the server absolute paths"),
    ({"env": {"PATH": "/x"}}, "name the command by its full path and remove PATH from `env`"),
    ({"env": {"PYTHONPATH": "/x"}}, "remove that from the entry"),
])
def test_a_changed_entry_gets_the_step_for_what_it_sets(t, change, step):
    spec = dict(t.wrapped(), **change)
    assert mcp_config.entry_state(spec) == "changed"
    home = str(t / "home")
    e = mcp_config.Entry("x", home + "/.claude.json", "user", spec, "changed")
    assert step in mcp_config.entry_text(e, home)


def test_a_python_script_before_dash_m_is_not_taken_for_the_launcher(t):
    # `python3 tool.py -m phiward launch ...` runs tool.py: not a spelling of the launcher, so
    # wrap must not drop tool.py
    spec = {"command": "python3", "args": ["tool.py", "-m", "phiward", "launch", "--"] + PROG}
    assert mcp_config.launcher_problem(spec) == ""
