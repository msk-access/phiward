"""The copy wrapper, the Claude Code adapter (with Copilot's payload form), `check` and `doctor`.

Payloads are made up in the shapes the tools document; no real session is recorded.
"""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import copying as agcopy
from phiward.adapters import claude

SRC = str(Path(__file__).resolve().parents[1] / "src")


def run_cli(args, cwd, stdin="", env=None):
    e = dict(os.environ)
    e["PYTHONPATH"] = SRC
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "phiward"] + args, cwd=str(cwd),
                          input=stdin, capture_output=True, text=True, env=e, timeout=60)


# --- copy ------------------------------------------------------------------------------------

def test_copy_into_a_protected_folder_runs_and_prints_no_names(tree):
    out = io.StringIO()
    # into a folder inside a protected root (a pattern match is not a copy destination)
    (tree / "phi" / "copies").mkdir()
    code = agcopy.execute([str(tree / "phi" / "FAKE-PT-0001.bam"), str(tree / "phi/copies/")],
                          str(tree / "repo"), dict(os.environ), out)
    assert code == 0
    assert (tree / "phi/copies/FAKE-PT-0001.bam").exists()
    assert "FAKE-PT-0001" not in out.getvalue() and str(tree / "phi") not in out.getvalue()


def test_copy_out_of_protected_folders_is_refused(tree):
    out = io.StringIO()
    code = agcopy.execute([str(tree / "phi" / "FAKE-PT-0001.bam"), str(tree / "repo/")],
                          str(tree / "repo"), dict(os.environ), out)
    assert code == 2 and "refused" in out.getvalue()
    assert not (tree / "repo" / "FAKE-PT-0001.bam").exists()


def test_copy_brace_destination_is_refused_at_run_time(tree):
    # hole 5 of the external review again, after the shell expanded the braces: the last word is
    # the destination
    out = io.StringIO()
    args = [str(tree / "phi/FAKE-PT-0001.bam"), str(tree / "runs/run2/panel/"),
            str(tree / "runs/run2/public/")]
    assert agcopy.execute(args, str(tree / "repo"), dict(os.environ), out) == 2
    assert not (tree / "runs/run2/public/FAKE-PT-0001.bam").exists()


def test_copy_errors_are_sanitized(tree):
    out = io.StringIO()
    code = agcopy.execute([str(tree / "phi" / "P-9990001-T01-IM6.bam"), str(tree / "phi/sub/")],
                          str(tree / "repo"), dict(os.environ), out)
    assert code != 0  # the source does not exist; the error line names it
    assert "P-9990001" not in out.getvalue() and str(tree / "phi") not in out.getvalue()


@pytest.mark.parametrize("spec,ok", [
    ("hpc-test:/work/proj/a", True), ("hpc-test:/work/proj", True),
    ("hpc-test:/work/projx/a", False), ("hpc-test:/work/proj/../x", False),
    ("other:/work/proj/a", False),
])
def test_remote_destinations(spec, ok):
    assert agcopy._remote_ok(spec, ["hpc-test:/work/proj"]) is ok


def test_copy_into_a_root_that_only_a_repo_config_adds_is_refused(tree):
    (tree / "repo" / ".phiward.toml").write_text(f'[protected_paths]\nroots = ["{tree}/pub"]\n')
    out = io.StringIO()
    code = agcopy.execute([str(tree / "phi" / "FAKE-PT-0001.bam"), str(tree / "pub/")],
                          str(tree / "repo"), dict(os.environ), out)
    assert code == 2 and not (tree / "pub" / "FAKE-PT-0001.bam").exists()


# --- the Claude Code adapter -----------------------------------------------------------------

def hook(payload):
    fout, ferr = io.StringIO(), io.StringIO()
    code = claude.main(io.StringIO(json.dumps(payload)), fout, ferr)
    return code, fout.getvalue(), ferr.getvalue()


def bash(t, command, **extra):
    p = {"session_id": "fake", "hook_event_name": "PreToolUse", "cwd": str(t / "repo"),
         "permission_mode": "default", "tool_name": "Bash",
         "tool_input": {"command": command, "description": "x"}}
    p.update(extra)
    return p


def test_hook_allow_is_silent(tree):
    assert hook(bash(tree, "git status")) == (0, "", "")


def test_hook_deny_is_exit_2_with_reason(tree):
    code, out, err = hook(bash(tree, f"cat {tree}/phi/FAKE-PT-0001.bam"))
    assert code == 2 and out == "" and "protected" in err
    assert "FAKE-PT-0001" not in err


def test_hook_ask_reply(tree):
    p = tree / "home" / "phiward.toml"
    p.write_text(p.read_text() + 'unresolved = "ask"\n')
    code, out, _ = hook(bash(tree, "cat $PHI_DIR/x"))
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "ask"


@pytest.mark.parametrize("mode", ["bypassPermissions", "dontAsk"])
def test_hook_ask_becomes_deny_when_the_mode_skips_prompts(tree, mode):
    p = tree / "home" / "phiward.toml"
    p.write_text(p.read_text() + 'unresolved = "ask"\n')
    code, out, err = hook(bash(tree, "cat $PHI_DIR/x", permission_mode=mode))
    assert code == 2 and out == "" and "cannot ask" in err


@pytest.mark.parametrize("tool,inp,code", [
    ("Read", {"file_path": "{t}/phi/FAKE-PT-0001.bam"}, 2),
    ("Read", {"file_path": "{t}/repo/README.md"}, 0),
    ("Grep", {"pattern": "x", "path": "{t}"}, 2),
    ("Grep", {"pattern": "x"}, 0),
    ("Glob", {"pattern": "**/*.maf", "path": "{t}/runs"}, 2),
    ("Glob", {"pattern": "{t}/runs/*/panel/*.maf"}, 2),
    ("Edit", {"file_path": "{t}/phi/a.txt", "old_string": "a", "new_string": "b"}, 2),
    ("Write", {"file_path": "{t}/repo/new.txt", "content": "hi"}, 0),
    ("mcp__fs__read_file", {"path": "{t}/phi/FAKE-PT-0001.bam"}, 2),
    ("WebFetch", {"url": "https://example.org", "prompt": "x"}, 0),
])
def test_hook_file_and_other_tools(tree, tool, inp, code):
    inp = {k: v.format(t=tree) if isinstance(v, str) else v for k, v in inp.items()}
    p = {"hook_event_name": "PreToolUse", "cwd": str(tree / "repo"), "tool_name": tool,
         "tool_input": inp}
    assert hook(p)[0] == code


def test_hook_reads_copilot_camel_case(tree):
    p = {"cwd": str(tree / "repo"), "toolName": "bash",
         "toolArgs": json.dumps({"command": f"ls {tree}/phi"})}
    assert hook(p)[0] == 2
    p = {"cwd": str(tree / "repo"), "toolName": "view",
         "toolArgs": {"path": f"{tree}/phi/FAKE-PT-0001.bam"}}
    assert hook(p)[0] == 2


def test_hook_copilot_ask_is_top_level(tree):
    p = tree / "home" / "phiward.toml"
    p.write_text(p.read_text() + 'unresolved = "ask"\n')
    code, out, _ = hook({"cwd": str(tree / "repo"), "toolName": "bash",
                         "toolArgs": {"command": "cat $PHI_DIR/x"}})
    assert code == 0 and json.loads(out)["permissionDecision"] == "ask"


@pytest.mark.parametrize("raw", ["", "not json", "[]", '{"tool_name": "Bash", "tool_input": 3}'])
def test_hook_fails_closed_on_a_bad_payload(raw):
    code = claude.main(io.StringIO(raw), io.StringIO(), io.StringIO())
    assert code == 2


def test_hook_end_to_end(tree):
    r = run_cli(["hook", "claude"], tree / "repo", stdin=json.dumps(bash(tree, f"ls {tree}/phi")),
                env={"HOME": os.environ["HOME"], "PHIWARD_CONFIG": os.environ["PHIWARD_CONFIG"]})
    assert r.returncode == 2 and "protected" in r.stderr


def test_check_command(tree):
    r = run_cli(["check", "--", f"cat {tree}/phi/x"], tree / "repo")
    assert r.returncode == 2 and r.stdout.startswith("deny")
    assert run_cli(["check", "--", "git status"], tree / "repo").returncode == 0


def test_install_prints_and_writes_nothing(tree, capsys, monkeypatch):
    from phiward import install
    monkeypatch.setattr("sys.stdin", type("Tty", (), {"isatty": lambda self: True})())
    monkeypatch.chdir(tree / "repo")
    assert install.main(["claude"]) == 0  # printing needs a terminal: the operator's own
    assert '"onFailure": "block"' in capsys.readouterr().out
    assert not (tree / "home" / ".claude").exists()


def test_doctor_reports_a_project_disable_all_hooks(tree):
    (tree / "repo" / ".claude").mkdir()
    (tree / "repo" / ".claude" / "settings.json").write_text('{"disableAllHooks": true}')
    r = run_cli(["doctor"], tree / "repo")
    assert r.returncode == 0
    assert "disableAllHooks is true at the project level" in r.stdout
    assert str(tree / "phi") not in r.stdout  # paths only with --show-paths


def test_doctor_reports_a_bad_config(tree):
    p = tree / "home" / "phiward.toml"
    p.write_text("[nope]\n")
    r = run_cli(["doctor"], tree / "repo")
    assert r.returncode == 1 and "PROBLEM" in r.stdout
