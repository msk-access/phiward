"""The beta fixes."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import inventory
from helpers import needs_confine

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")


def ag(args, cwd, env=None, stdin=None):
    e = dict(os.environ, PYTHONPATH=SRC)
    e.update(env or {})
    r = subprocess.run([PY, "-m", "phiward", *args], cwd=str(cwd), capture_output=True,
                       text=True, env=e, input=stdin, timeout=120)
    return r.returncode, r.stdout, r.stderr


def payload(tree, tool, inp):
    return json.dumps({"hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
                       "permission_mode": "default", "tool_name": tool, "tool_input": inp})


# --- the inventory sees every current name (findings 2, 3) ------------------------------------

def test_b2_a_name_added_in_the_same_tick_is_seen(tree):
    d = tree / "phi" / "sub"
    stop = set()
    inventory.build([str(tree / "phi")], [], 10000, stop)
    st = os.stat(d)
    (d / "FAKE-SAMETICK-AAAA.bam").write_text("")
    os.utime(d, ns=(st.st_atime_ns, st.st_mtime_ns))  # a coarse clock: the time did not move
    names = inventory.build([str(tree / "phi")], [], 10000, stop)
    assert any("fake-sametick-aaaa" in n for n in names)


def test_b3_a_root_written_as_a_link_is_listed_every_time(tree):
    os.symlink(tree / "phi", tree / "linkroot")
    inventory.build([str(tree / "linkroot")], [], 10000, set())
    (tree / "phi" / "FAKE-VIA-LINK-BBBB.bam").write_text("")
    names = inventory.build([str(tree / "linkroot")], [], 10000, set())
    assert any("fake-via-link-bbbb" in n for n in names)


# --- the fast hook (findings 6, 7, 8, 10) -------------------------------------------------------

def _fast(tree):
    return {"PHIWARD_HOOK_ROOTS": json.dumps([str(tree / "phi")])}


def test_b6_the_variable_alone_does_not_choose_the_fast_hook(tree):
    code, _, err = ag(["hook", "claude"], tree / "repo", {"PHIWARD_HOOK_ROOTS": "[]"},
                      payload(tree, "Read", {"file_path": str(tree / "phi" / "FAKE-PT-0001.bam")}))
    assert code == 2, err


def test_b7_the_fast_hook_allows_a_gateway_call(tree):
    code, _, err = ag(["hook", "claude", "--launched"], tree / "repo", _fast(tree),
                      payload(tree, "Bash", {"command": f"phiward run -- wc -l {tree}/phi/FAKE-PT-0001.bam"}))
    assert code == 0, err


def test_b7_the_fast_hook_still_refuses_a_plain_read(tree):
    code, _, err = ag(["hook", "claude", "--launched"], tree / "repo", _fast(tree),
                      payload(tree, "Read", {"file_path": str(tree / "phi" / "FAKE-PT-0001.bam")}))
    assert code == 2 and "phiward run" in err


def test_b8_writing_a_script_that_names_the_data_folder_is_allowed(tree):
    code, _, err = ag(["hook", "claude", "--launched"], tree / "repo", _fast(tree),
                      payload(tree, "Write", {"file_path": str(tree / "repo" / "count.py"),
                                              "content": f"print(len(open('{tree}/phi/x').read()))"}))
    assert code == 0, err


# --- the output cap holds (finding 11) ----------------------------------------------------------

@needs_confine
def test_b11_the_cap_holds_with_alternating_lines(tree, broker):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + "[broker]\nmax_output_lines = 50\n")
    _, out, _ = ag(["run", "--", PY, "-c", "for i in range(10000): print('a' if i % 4 < 2 else 'b')"],
                   tree / "repo")
    assert len(out.splitlines()) <= 53, len(out.splitlines())


# --- memory: a planted link never exposes a root (finding 1; carry-over replaced the binds) -------

@needs_confine
@linux
def test_b1_a_planted_memory_link_does_not_mount_a_root(tree):
    folder = tree / "home" / ".phiward" / "tools" / "claude"
    (folder / "projects").mkdir(parents=True)
    os.symlink(os.path.relpath(tree / "phi", folder / "projects"), folder / "projects" / "evil")
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([PY, "-m", "phiward", "launch", "--tool", "claude", "--memory", "--", PY, "-c",
                        f"import os\nprint(os.listdir({str(tree / 'phi')!r}))"], cwd=str(tree / "repo"),
                       capture_output=True, text=True, env=env, timeout=120)
    assert "FAKE-PT" not in r.stdout, r.stdout + r.stderr


# --- HPC variables, settings.local.json, .claude/.vscode ----------------------------------------

@needs_confine
@pytest.mark.parametrize("var", ["LD_LIBRARY_PATH", "MODULEPATH", "LMOD_CMD", "PKG_CONFIG_PATH"])
def test_b9_module_system_variables_pass(tree, var):
    env = dict(os.environ, PYTHONPATH=SRC, **{var: "/opt/x"})
    r = subprocess.run([PY, "-m", "phiward", "launch", "--", PY, "-c",
                        f"import os; print('HAS', {var!r} in os.environ)"], cwd=str(tree / "repo"),
                       capture_output=True, text=True, env=env, timeout=60)
    assert "HAS True" in r.stdout, r.stdout + r.stderr


@needs_confine
def test_l3_settings_local_json_is_read_only(tree):
    (tree / "repo" / ".claude").mkdir()
    f = tree / "repo" / ".claude" / "settings.local.json"
    f.write_text("{}\n")
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([PY, "-m", "phiward", "launch", "--", PY, "-c",
                        f"open({str(f)!r}, 'w').write('{{\"hooks\": {{}}}}')"], cwd=str(tree / "repo"),
                       capture_output=True, text=True, env=env, timeout=60)
    assert f.read_text() == "{}\n", r.stdout + r.stderr


@needs_confine
@macos
def test_l1_a_missing_claude_folder_cannot_be_made_a_link(tree):
    target = tree / "pub"
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([PY, "-m", "phiward", "launch", "--", PY, "-c",
                        f"import os\ntry:\n    os.symlink({str(target)!r}, {str(tree / 'repo' / '.claude')!r})\n"
                        "    print('LINKED')\nexcept OSError as e:\n    print('REFUSED', e.errno)\n"],
                       cwd=str(tree / "repo"), capture_output=True, text=True, env=env, timeout=60)
    assert "LINKED" not in r.stdout, r.stdout + r.stderr


@needs_confine
def test_beta3_long_line_notices_count_toward_the_cap(tree, broker):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + "[broker]\nmax_output_lines = 20\n")
    _, out, _ = ag(["run", "--", PY, "-c", "import sys\nfor i in range(200): sys.stdout.write('x' * 70000 + '\\n')"],
                   tree / "repo")
    assert len(out.splitlines()) <= 23, len(out.splitlines())


@needs_confine
@pytest.mark.parametrize("rel", [".claude", ".vscode", ".mcp.json"])
def test_beta4_a_settings_path_that_is_a_link_stops_launch(tree, rel):
    os.symlink(tree / "pub", tree / "repo" / rel)
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([PY, "-m", "phiward", "launch", "--", PY, "-c", "print('RAN')"],
                       cwd=str(tree / "repo"), capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode != 0 and "is a link" in r.stderr and "RAN" not in r.stdout, r.stderr


def test_beta_carryover_is_operator_only():
    from phiward import gateway
    assert gateway.is_operator_command("phiward carryover accept 1")
    assert gateway.is_operator_command("x=$(phiward carryover accept 1")
