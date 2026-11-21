"""Carry-over, stateless. Each session runs in a config folder built from a
trusted copy that no session can read or write, and thrown away after it. Nothing is shared
between sessions; what a session changes in its instructions goes to quarantine, for the
operator to accept. Every check asks the one question that matters: what does the next session
see?"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import carryover
from helpers import needs_confine, ready_line, tool_py

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
CFG = "os.environ['CLAUDE_CONFIG_DIR']"
UUID = "0b1e8f2a-1234-4abc-9def-0123456789ab"


def base(tree):
    return tree / "home" / ".phiward" / "tools" / "claude"


def store_dir(tree):
    return tree / "home" / ".phiward" / "carryover" / "claude"


def env():
    return dict(os.environ, PYTHONPATH=SRC)


def launch(tree, code, extra=(), tool="claude"):
    r = subprocess.run([PY, "-m", "phiward", "launch", "--tool", tool, *extra, "--", tool_py(tree, tool),
                        "-c", code],
                       cwd=str(tree / "repo"), capture_output=True, text=True, env=env(),
                       timeout=120, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout, r.stderr


def ag(tree, *args):
    stdin = subprocess.DEVNULL
    if args[:1] == ("carryover",) and args[1:2] in (("add",), ("accept",), ("reset",)):
        import pty  # the operator's own terminal: these refuse without one
        master, slave = pty.openpty()
        stdin = slave
    try:
        r = subprocess.run([PY, "-m", "phiward", *args], cwd=str(tree / "repo"), stdin=stdin,
                           capture_output=True, text=True, env=env(), timeout=60)
    finally:
        if stdin is not subprocess.DEVNULL:
            os.close(master)
            os.close(slave)
    return r.returncode, r.stdout, r.stderr


def writes(rel, text="planted"):
    return (f"import os\np = os.path.join({CFG}, {rel!r})\nos.makedirs(os.path.dirname(p), exist_ok=True)\n"
            f"open(p, 'w').write({text!r})\n")


def sees(tree, rel, extra=()):
    """What the next session finds at `rel` in its config folder."""
    _, out, err = launch(tree, f"import os\np = os.path.join({CFG}, {rel!r})\n"
                               "print('SEES', repr(open(p).read()) if os.path.isfile(p) else "
                               "('DIR' if os.path.isdir(p) else None))\n", extra)
    line = [x for x in out.splitlines() if x.startswith("SEES ")]
    assert line, out + err
    return line[0][5:]


# --- instructions: quarantined, never carried over ------------------------------------------------

@needs_confine
@pytest.mark.parametrize("rel", ["CLAUDE.md", "rules/x.md", "skills/s/SKILL.md", "plugins/p/plugin.json",
                                 "agents/a.md", "agent-memory/m.md", "hooks/run.sh"])
def test_c1_instruction_files_go_to_quarantine_and_not_to_the_next_session(tree, rel):
    _, _, err = launch(tree, writes(rel))
    assert "quarantine" in err and "carryover show" in err, err
    assert sees(tree, rel) == "None"
    code, out, _ = ag(tree, "carryover", "show", "--tool", "claude")
    assert code == 0 and rel.split("/")[-1] in out, out


@needs_confine
def test_c1_settings_changes_do_not_reach_the_next_session(tree):
    launch(tree, f"import json, os\np = os.path.join({CFG}, 'settings.json')\nd = json.load(open(p))\n"
                 "d['hooks']['SessionStart'] = [{'hooks': [{'type': 'command', 'command': 'evil'}]}]\n"
                 "json.dump(d, open(p, 'w'))\n")
    s = sees(tree, "settings.json")
    assert "evil" not in s and "phiward" in s, s


# --- nothing else is shared -----------------------------------------------------------------------

@needs_confine
@pytest.mark.parametrize("rel", ["projects/-k/s.jsonl", f"projects/-k/{UUID}/r.txt", "projects/-k/memory/M.md",
                                 "history.jsonl", ".credentials.json", "ide/1.lock", "tasks/t.json",
                                 "plans/p.md", "shell-snapshots/s.sh", "something-new/x.md"])
def test_c2_nothing_else_reaches_the_next_session(tree, rel):
    launch(tree, writes(rel))
    assert sees(tree, rel) == "None"


@needs_confine
@pytest.mark.parametrize("var", ["npm_config_cache", "GOMODCACHE", "GRADLE_USER_HOME", "CARGO_HOME",
                                 "PRE_COMMIT_HOME", "XDG_CACHE_HOME", "UV_CACHE_DIR", "XDG_STATE_HOME"])
def test_c3_caches_are_new_in_each_session(tree, var):
    launch(tree, f"import os\np = os.path.join(os.environ[{var!r}], 'x')\nos.makedirs(os.path.dirname(p), exist_ok=True)\n"
                 "open(p, 'w').write('x')\n")
    _, out, _ = launch(tree, f"import os\nprint('SEES', os.path.exists(os.path.join(os.environ[{var!r}], 'x')))")
    assert "SEES False" in out, out


@needs_confine
def test_c4_claude_json_changes_are_dropped_except_notable_keys_which_are_quarantined(tree):
    launch(tree, f"import json, os\np = os.path.join({CFG}, '.claude.json')\n"
                 "d = {'numStartups': 7, 'mcpServers': {'mine': {'command': 'x'}}}\njson.dump(d, open(p, 'w'))")
    nxt = sees(tree, ".claude.json")
    assert "numStartups" not in nxt and "mine" not in nxt, nxt  # only the onboarding default
    _, out, _ = ag(tree, "carryover", "show", "--tool", "claude")
    assert "mcpServers" in out and "numStartups" not in out, out


@needs_confine
def test_c5_an_accepted_change_reaches_every_later_session(tree):
    launch(tree, writes("CLAUDE.md", "the operator's note"))
    _, out, _ = ag(tree, "carryover", "show", "--tool", "claude")
    code, out, err = ag(tree, "carryover", "accept", out.split()[0], "--tool", "claude")
    assert code == 0, out + err
    assert sees(tree, "CLAUDE.md") == "\"the operator's note\""
    assert sees(tree, "CLAUDE.md") == "\"the operator's note\""


@needs_confine
def test_c5_an_accepted_mcp_server_reaches_later_sessions(tree):
    launch(tree, f"import json, os\njson.dump({{'mcpServers': {{'mine': {{'command': 'x'}}}}}}, "
                 f"open(os.path.join({CFG}, '.claude.json'), 'w'))")
    _, out, _ = ag(tree, "carryover", "show", "--tool", "claude")
    code, out, err = ag(tree, "carryover", "accept", out.split()[0], "--tool", "claude")
    assert code == 0, out + err
    assert "mine" in sees(tree, ".claude.json")


@needs_confine
def test_c6_the_operator_adds_an_instruction_file_of_their_own(tree):
    f = tree / "pub" / "CLAUDE.md"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("my rules\n")
    code, out, err = ag(tree, "carryover", "add", str(f), "--tool", "claude")
    assert code == 0, out + err
    assert sees(tree, "CLAUDE.md") == "'my rules\\n'"


def test_c6_add_refuses_links_and_unknown_names(tree):
    store = carryover.Store("claude", str(tree / "home"))
    (tree / "pub").mkdir(exist_ok=True)
    os.symlink(tree / "pub", tree / "pub-link")
    with pytest.raises(carryover.CarryoverError):
        store.add(str(tree / "pub-link"), "skills")
    (tree / "pub" / "x.txt").write_text("x")
    with pytest.raises(carryover.CarryoverError):
        store.add(str(tree / "pub" / "x.txt"))


@needs_confine
def test_c7_auto_memory_is_off_unless_asked_and_then_lives_in_the_session(tree):
    probe = "import os; print('AUTO', os.environ.get('CLAUDE_CODE_DISABLE_AUTO_MEMORY'))"
    _, out, _ = launch(tree, probe)
    assert "AUTO 1" in out, out
    _, out, _ = launch(tree, probe, extra=("--memory",))
    assert "AUTO None" in out, out
    s = json.loads(eval(sees(tree, "settings.json", extra=("--memory",))))
    assert "/runs/" in s.get("autoMemoryDirectory", ""), s


def test_c8_an_unfinished_session_is_finished_at_the_next_start(tree):
    b = base(tree)
    store = carryover.Store("claude", str(tree / "home"))
    run1 = b / "runs" / "one"
    store.start(str(b), str(run1))
    (run1 / "config" / "CLAUDE.md").write_text("planted\n")
    os.close(store._run_fd)  # the launcher was killed: its lock is gone, no end
    store2 = carryover.Store("claude", str(tree / "home"))
    msgs = store2.start(str(b), str(b / "runs" / "two"))
    assert any("CLAUDE.md" in m for m in msgs), msgs
    assert not (b / "runs" / "two" / "config" / "CLAUDE.md").exists() and not run1.exists()


@needs_confine
def test_c9_two_sessions_run_side_by_side(tree):
    # the first session waits (on its stdin) until the second one has started and ended
    first = subprocess.Popen([PY, "-m", "phiward", "launch", "--tool", "claude", "--",
                              tool_py(tree), "-c",
                              f"import os, sys\nopen(os.path.join({CFG}, 'CLAUDE.md'), 'w').write('one')\n"
                              "print('READY', flush=True)\nsys.stdin.read()\n"
                              "print('FIRST', os.path.exists(os.environ['CLAUDE_CONFIG_DIR']))"],
                             cwd=str(tree / "repo"), env=env(), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ready_line(first)
    code, out, err = launch(tree, "print('SECOND')")
    o1, e1 = first.communicate(timeout=60)
    assert "SECOND" in out, err
    assert "FIRST True" in o1, o1 + e1  # the second start did not remove the first one's folder
    assert "CLAUDE.md" in e1, e1  # and the first one's change still reached quarantine


@needs_confine
def test_c10_the_trusted_copy_cannot_be_read_or_written_in_a_session(tree):
    launch(tree, "print('first')")
    m = store_dir(tree) / "manifest.json"
    assert m.is_file()
    _, out, _ = launch(tree, f"for mode in ('r', 'w'):\n    try:\n        open({str(m)!r}, mode)\n        print('OPENED', mode)\n"
                             "    except OSError as e:\n        print('REFUSED', e.errno)\n")
    assert "OPENED" not in out, out
    if sys.platform == "darwin":  # Linux: the tree is in the session's private /tmp (ENOENT)
        assert out.count("REFUSED 1") == 2, out


@needs_confine
def test_c10_another_session_folder_is_not_writable(tree):
    launch(tree, "print('first')")
    other = base(tree) / "runs" / "zz-other"
    _, out, _ = launch(tree, f"import os\ntry:\n    os.makedirs({str(other)!r})\n"
                             "    print('WROTE')\nexcept OSError as e:\n    print('REFUSED', e.errno)\n")
    assert not other.exists(), out
    if sys.platform == "darwin":
        assert "REFUSED 1" in out, out


# --- the project: reported, ranked ----------------------------------------------------------------

@needs_confine
def test_c11_project_changes_are_reported_instructions_first(tree):
    (tree / "repo" / "a.py").write_text("x = 1\n")
    r = tree / "repo"
    code = (f"import os\nos.makedirs({str(r / 'sub')!r})\nopen({str(r / 'sub' / 'CLAUDE.md')!r}, 'w').write('x')\n"
            f"open({str(r / 'a.py')!r}, 'w').write('x = 2')\nos.makedirs({str(r / '.husky')!r})\n"
            f"open({str(r / '.husky' / 'pre-commit')!r}, 'w').write('x')\n")
    _, _, err = launch(tree, code, tool="generic")
    assert "instructions for models" in err and "sub/CLAUDE.md" in err, err
    assert err.index("sub/CLAUDE.md") < err.index(".husky/pre-commit"), err
    assert "a.py" in err, err


@needs_confine
def test_c12_a_reset_time_is_still_seen(tree):
    f = tree / "repo" / "AGENTS.md"
    f.write_text("aaaa\n")
    st = os.stat(f)
    code = (f"import os\nopen({str(f)!r}, 'w').write('bbbb\\n')\n"
            f"os.utime({str(f)!r}, ns=({st.st_atime_ns}, {st.st_mtime_ns}))\n")
    _, _, err = launch(tree, code, tool="generic")
    assert "AGENTS.md" in err, err


# --- what the real Claude Code writes -------------------------------------------------------------

@needs_confine
def test_spike_the_plugin_catalog_is_not_downloaded_or_quarantined(tree):
    _, out, _ = launch(tree, "import os; print('OFF', os.environ.get('CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL'))")
    assert "OFF 1" in out, out
    code = writes("plugins/marketplaces/official/plugins/x/SKILL.md") + writes("plugins/known_marketplaces.json", "{}")
    _, _, err = launch(tree, code)
    assert "quarantine" not in err, err


@needs_confine
def test_spike_an_installed_plugin_still_goes_to_quarantine(tree):
    code = writes("plugins/marketplaces/official/x.md") + writes("plugins/installed_plugins.json", "{}")
    _, _, err = launch(tree, code)
    assert "installed_plugins.json" in err and "marketplaces" not in err, err


@needs_confine
def test_spike_empty_claude_json_defaults_are_not_reported(tree):
    launch(tree, f"import json, os\njson.dump({{'projects': {{'/p': {{'mcpServers': {{}}, 'allowedTools': [], "
                 f"'hasTrustDialogAccepted': True}}}}}}, open(os.path.join({CFG}, '.claude.json'), 'w'))")
    _, out, _ = ag(tree, "carryover", "show", "--tool", "claude")
    assert "hasTrustDialogAccepted" in out and "allowedTools" not in out and "mcpServers" not in out, out


@needs_confine
def test_spike_accept_one_item_of_an_entry(tree):
    code = (f"import json, os\np = os.path.join({CFG}, 'settings.json')\nd = json.load(open(p))\nd['theme'] = 'auto'\n"
            "json.dump(d, open(p, 'w'))\n" + writes("CLAUDE.md", "not wanted"))
    launch(tree, code)
    _, out, _ = ag(tree, "carryover", "show", "--tool", "claude")
    assert "settings.json: theme (changed)" in out, out
    code, o, e = ag(tree, "carryover", "accept", out.split()[0], "settings.json", "--tool", "claude")
    assert code == 0, o + e
    assert "auto" in sees(tree, "settings.json")
    assert sees(tree, "CLAUDE.md") == "None"


@needs_confine
def test_spike_every_session_starts_with_onboarding_done(tree):
    s = sees(tree, ".claude.json")
    assert "hasCompletedOnboarding" in s and "true" in s, s


@needs_confine
def test_spike_server_policy_and_builtin_plugin_records_are_not_quarantined(tree):
    code = (writes("remote-settings.json", "{}") + writes("policy-limits.json", "{}") +
            writes("plugins/store/cc-plugin-agents-md_builtin-b049.json", "{}"))
    _, _, err = launch(tree, code)
    assert "quarantine" not in err, err
    assert sees(tree, "remote-settings.json") == "None"
