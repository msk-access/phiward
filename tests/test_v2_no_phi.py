"""The "no PHI here" folders (PLAN-USABILITY-FIXES §5, PR d): `[no_phi] folders`, user config
only, exact absolute folders the operator is sure hold no PHI. In Mode A the hook acts there as
with `[shell] best_effort` (a shell that a sandbox opener leaves unconfined gets the text check,
not the blanket refusal); `phiward launch` runs as usual, with a NOTE. Protected roots, the
prompt scan, the project scan and the asks for files that run later stay on. Made-up trees only
(`tests/conftest.py`, `FAKE-PT-0001`)."""

import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import protect
from phiward import config, session_note, wholetool
from test_v2_excluded_per_call import _hook, _wired

SRC = str(Path(__file__).resolve().parents[1] / "src")
LAUNCH = ("import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; "
          "from phiward.cli import main; sys.exit(main())")
BLANKET = "every command is refused but a whole gateway call"
RELAXED = ("phiward: no-PHI folder (your user config): the shell's sandbox openers are checked "
           "by text here; protected roots are still denied and prompts still scanned.")
CONTEXT = ("The operator marked this folder as holding no PHI. Protected paths are still "
           "refused; use phiward run for them.")
LAUNCH_NOTE = ("phiward launch: NOTE: the operator lists this folder in [no_phi] folders; launch "
               "confines it all the same (plain claude here is relaxed).")


def _add(text):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + text)


def _list(*folders):
    _add("[no_phi]\nfolders = [" + ", ".join(json.dumps(str(f)) for f in folders) + "]\n")


@pytest.fixture()
def opened(tree):
    """No best_effort; Claude Code's sandbox with an opener on every platform, so the shell is
    not confined and, outside a listed folder, every command but a gateway call is refused."""
    protect(tree, [], best_effort=False)
    _wired(tree, enableWeakerNestedSandbox=True)
    return tree


def _refused_blanket(tree, monkeypatch, command="ls", **kw):
    code, text = _hook(tree, monkeypatch, command, **kw)
    assert code == 2 and BLANKET in text, text


# --- the config -------------------------------------------------------------------------------

def test_the_key_loads_from_the_user_config_with_a_tilde(tree):
    (tree / "home" / "site").mkdir()
    _list(tree / "repo", "~/site")
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem, cfg.problem
    assert cfg.no_phi_folders == [str(tree / "repo"), str(tree / "home" / "site")]


def test_a_relative_entry_is_a_config_problem(tree):
    _list("code/site")
    assert config.load(str(tree / "repo")).problem == (
        "[no_phi] folders entry 'code/site' must be absolute (or start with ~/)")


def test_a_repo_file_cannot_set_it(tree):
    (tree / "repo" / ".phiward.toml").write_text(
        f'[no_phi]\nfolders = ["{tree}/repo"]\n')
    cfg = config.load(str(tree / "repo"))
    assert "no_phi.folders" in cfg.ignored and cfg.no_phi_folders == [], cfg


def test_a_missing_entry_is_no_problem(tree):
    _list(tree / "gone")
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem and cfg.no_phi_folders == [str(tree / "gone")]


def test_load_reads_no_file_system_for_the_key(tree, monkeypatch):
    # no protected paths: nothing else in load resolves a path
    Path(os.environ["PHIWARD_CONFIG"]).write_text(f'[no_phi]\nfolders = ["{tree}/repo"]\n')

    def boom(*_a, **_k):
        raise AssertionError("load touched the file system for [no_phi]")
    monkeypatch.setattr(config, "guard_files", boom)
    monkeypatch.setattr(os.path, "realpath", boom)
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem and cfg.no_phi_folders == [str(tree / "repo")]


# --- the hook ---------------------------------------------------------------------------------

def test_a_listed_folder_gets_the_text_check_in_place_of_the_refusal(opened, monkeypatch):
    tree = opened
    _refused_blanket(tree, monkeypatch)
    _list(tree / "repo")
    code, text = _hook(tree, monkeypatch, "ls")
    assert code == 0, text
    code, text = _hook(tree, monkeypatch, f"cat {tree}/phi/FAKE-PT-0001.bam")
    assert code == 2 and "names a protected path" in text, text
    code, text = _hook(tree, monkeypatch, "ls", tool="Monitor")
    assert code == 0, text


@pytest.mark.skipif(sys.platform != "darwin", reason="allowLocalBinding opens it on macOS only")
def test_a_dev_server_folder_on_macos(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    _wired(tree, network={"allowLocalBinding": True})
    code, text = _hook(tree, monkeypatch, "ls")
    assert code == 2 and "[no_phi] folders" in text, text  # the refusal names the way out
    _list(tree / "repo")
    assert _hook(tree, monkeypatch, "ls")[0] == 0
    code, text = _hook(tree, monkeypatch, f"cat {tree}/phi/FAKE-PT-0001.bam")
    assert code == 2 and "names a protected path" in text, text


def test_a_subfolder_of_a_listed_folder_is_not_relaxed(opened, monkeypatch):
    tree = opened
    _list(tree / "repo")
    _refused_blanket(tree, monkeypatch, cwd=tree / "repo" / "src",
                     project=tree / "repo" / "src")


def test_a_call_outside_the_listed_project_is_not_relaxed(opened, monkeypatch):
    tree = opened
    _list(tree / "repo")
    code, text = _hook(tree, monkeypatch, "ls", cwd=tree / "pub")
    assert code == 2, text


def _note(tree, monkeypatch, capsys, project):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"cwd": str(project)})))
    assert session_note.main(["claude"]) == 0
    return json.loads(capsys.readouterr().out)


def test_a_listed_folder_through_a_link_is_not_relaxed(opened, monkeypatch, capsys):
    tree = opened
    os.symlink(tree / "repo", tree / "linked")
    _list(tree / "linked")
    _refused_blanket(tree, monkeypatch, cwd=tree / "linked", project=tree / "linked")
    out = _note(tree, monkeypatch, capsys, tree / "linked")
    assert out["systemMessage"] == ("phiward: [no_phi] folders lists this folder, but it has a "
                                    "link on its path: not relaxed."), out


def test_the_home_folder_is_not_relaxed(opened, monkeypatch, capsys):
    tree = opened
    _list("~")
    code, text = _hook(tree, monkeypatch, "ls", cwd=tree / "home", project=tree / "home")
    assert code == 2, text
    out = _note(tree, monkeypatch, capsys, tree / "home")
    assert out["systemMessage"] == ("phiward: [no_phi] folders lists this folder, but it is the "
                                    "home folder or above it: not relaxed."), out


@pytest.fixture()
def above(tree):
    """A root at T/data/phi (T/data holds no home folder, unlike T itself), listed by T/data."""
    (tree / "data" / "phi").mkdir(parents=True)
    (tree / "data" / "phi" / "FAKE-PT-0001.txt").write_text("SECRET-CONTENT-0001\n")
    protect(tree, [], root="data/phi", best_effort=False)
    _wired(tree, enableWeakerNestedSandbox=True)
    _list(tree / "data")
    return tree / "data"


def test_a_folder_above_a_root_is_not_relaxed(tree, above, monkeypatch, capsys):
    _refused_blanket(tree, monkeypatch, cwd=above, project=above)
    out = _note(tree, monkeypatch, capsys, above)
    assert out["systemMessage"] == ("phiward: [no_phi] folders lists this folder, but it is "
                                    "above a protected path: not relaxed."), out


def test_files_that_run_later_still_ask(opened, monkeypatch):
    from test_v2_release18 import _write
    tree = opened
    _list(tree / "repo")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    assert _write(tree, tree / "repo" / ".vscode" / "tasks.json")[0] == "ask"


# --- the session note --------------------------------------------------------------------------

def test_the_session_note_says_the_folder_is_relaxed(opened, monkeypatch, capsys):
    tree = opened
    _list(tree / "repo")
    out = _note(tree, monkeypatch, capsys, tree / "repo")
    assert out["systemMessage"] == RELAXED, out
    assert CONTEXT in out["hookSpecificOutput"]["additionalContext"], out


def test_no_system_message_outside_a_listed_folder(opened, monkeypatch, capsys):
    out = _note(opened, monkeypatch, capsys, opened / "repo")
    assert "systemMessage" not in out and CONTEXT not in json.dumps(out), out


def test_the_session_note_warns_when_the_scan_finds_data_in_a_listed_folder(opened, monkeypatch,
                                                                            capsys):
    tree = opened
    _list(tree / "repo")
    _add("[sanitize]\npatterns = ['FAKE-PT-\\d{4} => <SUBJECT>']\n")
    (tree / "repo" / "samples.csv").write_text("subject,group\nFAKE-PT-0001,a\n")
    out = _note(tree, monkeypatch, capsys, tree / "repo")
    msg = out["systemMessage"]
    assert msg.startswith("phiward: WARNING: this folder is listed as holding no PHI, but the "
                          "project scan found <SUBJECT>"), msg
    assert msg.endswith("; check it (phiward doctor --show-paths) or take it off [no_phi] "
                        "folders."), msg
    assert "FAKE-PT-0001" not in json.dumps(out)
    # still relaxed: the scan warns in Mode A, it never stops a session
    assert _hook(tree, monkeypatch, "ls")[0] == 0


# --- doctor -----------------------------------------------------------------------------------

def _doctor(cwd, project=None):
    e = {k: v for k, v in os.environ.items() if k != "CLAUDE_PROJECT_DIR"}
    if project:
        e["CLAUDE_PROJECT_DIR"] = str(project)
    e["PYTHONPATH"] = SRC
    r = subprocess.run([sys.executable, "-c", LAUNCH, "doctor"], cwd=str(cwd),
                       capture_output=True, text=True, env=e, timeout=120,
                       stdin=subprocess.DEVNULL)
    return r.stdout + r.stderr


def test_doctor_shows_the_folders_and_this_folder(opened):
    tree = opened
    _list(tree / "repo", tree / "gone")
    out = _doctor(tree / "repo")
    assert (f"no-PHI folders (user config): {tree}/repo, {tree}/gone (this folder: relaxed)"
            in out), out
    assert (f"NOTE: [no_phi] folders entry {tree}/gone does not exist (moved or removed?); it "
            "relaxes nothing") in out, out
    assert "PROBLEM" not in out, out


def test_doctor_in_a_subfolder_says_entries_are_exact(opened):
    tree = opened
    _list(tree / "repo")
    out = _doctor(tree / "repo" / "src")
    assert (f"NOTE: inside the no-PHI folder {tree}/repo, but not {tree}/repo itself: not "
            "relaxed (entries are exact)") in out, out
    assert "(this folder: relaxed)" not in out, out


def test_doctor_warns_when_a_listed_folder_fails_its_check(above):
    out = _doctor(above)
    assert ("WARNING: phiward: [no_phi] folders lists this folder, but it is above a protected "
            "path: not relaxed.") in out, out


# --- launch -----------------------------------------------------------------------------------

def _build(tree):
    return wholetool.build(["/bin/echo", "x"], str(tree / "repo"), dict(os.environ),
                           wholetool.ADAPTERS["generic"])


def _release(cmd):
    from phiward import confine
    confine.release_profile(cmd)


def test_launch_runs_as_usual_with_a_note(tree, capsys):
    _list(tree / "repo")
    cmd, *rest = _build(tree)
    _release(cmd)
    rest[-1].close()
    assert LAUNCH_NOTE in capsys.readouterr().err


def test_launch_prints_no_note_outside_a_listed_folder(tree, capsys):
    cmd, *rest = _build(tree)
    _release(cmd)
    rest[-1].close()
    assert "[no_phi]" not in capsys.readouterr().err


@pytest.mark.skipif(sys.platform != "darwin", reason="the Seatbelt profile is text")
def test_launch_builds_the_same_profile_with_and_without_the_entry(tree, monkeypatch):
    texts = []
    orig = wholetool.seatbelt_tool_profile

    def keep(*a, **k):
        texts.append(re.sub(r"runs/[0-9]{8}-[0-9]{6}-[0-9a-f]{8}", "runs/X",
                            orig(*a, **dict(k, proxy_port=1))))
        return orig(*a, **k)
    monkeypatch.setattr(wholetool, "seatbelt_tool_profile", keep)
    for listed in (False, True):
        if listed:
            _list(tree / "repo")
        cmd, *rest = _build(tree)
        _release(cmd)
        rest[-1].close()
    assert len(texts) == 2 and texts[0] == texts[1]
