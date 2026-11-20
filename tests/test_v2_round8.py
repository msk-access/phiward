"""The eighth review round: masking around patterns whose wildcard is not at the end, the words
after a protected path, the project lookup from a nested repository, and the Linux launch view
next to large folders. Made-up trees only."""

import errno
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from phiward import claude_settings, config, install, wholetool
from phiward.adapters import decide
from phiward.core import ALLOW, DENY, SHELL, Action
from phiward.guards import protected_paths
from phiward.sanitize import Sanitizer
from helpers import gone


def _san(tree, patterns, folders=(), entries=True):
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/phi"]\npatterns = {json.dumps(patterns)}\n')
    for f in folders:
        (tree / f).mkdir(parents=True, exist_ok=True)
    return Sanitizer.from_config(config.load(str(tree / "repo")), entries=entries)


# --- H1: a wildcard that is not at the end of its pattern ---------------------------------------

_MID = ["{t}/runs/*/panel", "{t}/pat/phi_*_raw"]


@pytest.mark.parametrize("entries", [True, False])
@pytest.mark.parametrize("folders,line,words", [
    ([], "{t}/runs/Zed (B)/panel/new_Quux.txt", "Zed Quux"),
    (["runs/Zed (B)/panel"], "{t}/runs/Zed (B)/panel/new_Quux.txt", "Zed Quux"),
    ([], "{t}/pat/phi_Pat (copy)_raw", "Pat copy"),
    (["pat/phi_Pat (copy)_raw"], "{t}/pat/phi_Pat (copy)_raw", "Pat copy"),
    ([], "{t}/pat/phi_O'Brien_raw/a.txt", "Brien"),
    (["pat/phi_O'Brien_raw"], "{t}/pat/phi_O'Brien_raw/Quux.txt", "Brien Quux"),
    ([], "cat '{t}/runs/A&B;Zorro/panel/x.maf'", "Zorro"),
])
def test_a_wildcard_before_more_of_the_pattern_matches_any_name(tree, entries, folders, line, words):
    san = _san(tree, [p.format(t=tree) for p in _MID], folders, entries)
    gone(san.clean(line.format(t=tree)), words)


def test_a_wildcard_at_the_end_still_stops_at_a_quote(tree):
    san = _san(tree, [f"{tree}/wild/phi_*"], ["wild/phi_A"])
    assert san.clean(f"ls '{tree}/wild/phi_A' done").startswith("ls '<PROTECTED>")


# --- M1: the words after a protected path ------------------------------------------------------

@pytest.mark.parametrize("entries", [True, False])
@pytest.mark.parametrize("line,words", [
    ("{t}/phi/New Person 7", "Person 7"),
    ("12K\t{t}/phi/New Person 7", "Person 7"),
    ("{t}/wild/phi_Ann/New Person 7", "Person 7"),
    ("{t}/phi/New  Person/x", "Person"),
    ("{t}/phi/Doe Jane", "Jane"),  # on disk: without the inventory its name is not known
])
def test_words_after_a_protected_path_and_a_space_are_masked(tree, entries, line, words):
    (tree / "phi" / "Doe Jane").mkdir()
    san = _san(tree, [f"{tree}/wild/phi_*"], ["wild/phi_Ann"], entries)
    gone(san.clean(line.format(t=tree)), words)


def test_a_tab_ends_the_mask_and_a_path_after_a_space_stays(tree):
    san = _san(tree, [f"{tree}/wild/phi_*"], ["wild/phi_A"])
    assert san.clean(f"{tree}/phi/New Person\tok") == "<PROTECTED>\tok"
    assert san.clean(f"cat {tree}/phi/FAKE-PT-0001.bam /tmp/out").endswith(" /tmp/out")
    assert san.clean(f"at {tree}/phi, then") == "at <PROTECTED>, then"


# --- M2: what may stay after a folder on disk ---------------------------------------------------

@pytest.mark.parametrize("line,words", [
    ("{t}/wild/phi_Ann: 1 Zorro Quux", "Zorro Quux"),
    ("{t}/wild/phi_Ann 4471", "4471"),
    ("{t}/wild/phi_Ann 12 44 9", "12 44"),
    ("{t}/wild/phi_Ann: 3 reads Zorro", "Zorro"),
])
def test_text_after_a_folder_on_disk_that_could_be_more_of_a_name_is_masked(tree, line, words):
    san = _san(tree, [f"{tree}/wild/phi_*"], ["wild/phi_Ann"])
    gone(san.clean(line.format(t=tree)), words)


def test_a_count_and_a_plain_unit_after_a_folder_on_disk_stay(tree):
    san = _san(tree, [f"{tree}/wild/phi_*"], ["wild/phi_A"])
    assert san.clean(f"{tree}/wild/phi_A: 12 reads, 3 errors") == "<PROTECTED>: 12 reads, 3 errors"
    assert san.clean(f"{tree}/wild/phi_A: 12") == "<PROTECTED>: 12"


# --- H2: the project lookup from a nested repository or a folder with its own .claude -----------

def _decoy_project(tree, monkeypatch):
    decoy = tree / "pub" / "decoy"
    decoy.mkdir(parents=True)
    (tree / "repo" / ".claude").mkdir()
    (tree / "repo" / ".claude" / "settings.json").write_text(
        json.dumps({"env": {"SHELLOPTS": "xtrace"}}))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(decoy))
    return decoy


@pytest.mark.parametrize("inner", [".git", ".claude"])
def test_a_nested_repository_does_not_hide_the_project_settings(tree, monkeypatch, inner):
    _decoy_project(tree, monkeypatch)
    sub = tree / "repo" / "vendor" / "lib"
    (sub / inner).mkdir(parents=True)
    found = claude_settings.project_folders(str(sub), str(tree / "home"))
    assert str(tree / "repo") in found and str(sub) in found, found
    d = protected_paths.check(Action(SHELL, str(sub), command="ls"), config.load(str(tree / "repo")))
    assert d.verdict == DENY and "env.SHELLOPTS" in d.reason, d.reason


def test_the_home_folder_is_never_a_project(tree, monkeypatch):
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    home = tree / "home"
    (home / ".claude").mkdir(exist_ok=True)
    (home / "work").mkdir()
    found = claude_settings.project_folders(str(home / "work"), str(home))
    assert str(home) not in found, found


def test_a_named_project_that_does_not_hold_the_call_does_not_confine_it(tree, monkeypatch):
    monkeypatch.setattr(claude_settings, "confinement_reason", lambda *a, **k: None)
    cmd = "cat $UNKNOWN_VAR"  # allowed only where the kernel guards the shell
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    inside = decide(Action(SHELL, str(tree / "repo"), command=cmd, tool="Bash"),
                    claude_sandbox=True)
    assert inside.verdict == ALLOW, inside.reason  # the kernel guards a confined shell
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "pub"))
    outside = decide(Action(SHELL, str(tree / "repo"), command=cmd, tool="Bash"),
                     claude_sandbox=True)
    assert outside.verdict == DENY, outside.reason


# --- M3, L1, L3: the Linux launch view next to large folders ------------------------------------

def _crowd(folder, n):
    folder.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (folder / f"s{i:05d}").mkdir()


def test_the_folder_of_a_protected_root_is_never_shown_whole(tree):
    data = tree / "data"
    _crowd(data, 3000)
    (data / "Zorro Quux").mkdir()
    with pytest.raises(wholetool.LaunchError, match="protect"):
        wholetool.hidden_view([str(data / "Zorro Quux")], [], ())


def test_a_folder_above_the_root_s_folder_may_be_shown_whole(tree):
    data = tree / "data"
    _crowd(data, 3000)
    (data / "study" / "Zorro Quux").mkdir(parents=True)
    ops, _split, whole = wholetool.hidden_view([str(data / "study" / "Zorro Quux")], [], ())
    assert str(data) in whole and str(tree) not in whole, whole
    assert ("tmpfs", str(data / "study")) in ops  # its own folder is rebuilt: the name is gone
    assert not any(o[-1] == str(data / "study" / "Zorro Quux") for o in ops), ops


def test_many_small_folders_shrink_the_view_quickly(tree):
    runs = tree / "many"
    for i in range(1200):
        (runs / f"r{i:04d}" / "panel").mkdir(parents=True)
        (runs / f"r{i:04d}" / "public").mkdir()
    start = time.monotonic()
    ops, _split, whole = wholetool.hidden_view([], [str(runs) + "/*/panel"], (), limit=5000)
    assert time.monotonic() - start < 20
    assert sum(wholetool._OP_ARGS[o[0]] for o in ops) <= 5000
    assert whole


def test_a_folder_shown_whole_masks_its_hidden_entry_by_the_name_on_disk(tree):
    runs = tree / "runs2"
    (runs / "r1" / "PANEL").mkdir(parents=True)  # the pattern's name in another case
    for i in range(3000):  # the folder that saves the most when shown whole
        (runs / "r1" / f"f{i}").mkdir()
    full, _s, _w = wholetool.hidden_view([], [str(runs) + "/*/panel"], ())
    limit = sum(wholetool._OP_ARGS[o[0]] for o in full) - 1
    ops, _split, whole = wholetool.hidden_view([], [str(runs) + "/*/panel"], (), limit=limit)
    assert str(runs / "r1") in whole, whole
    masked = {os.path.basename(o[1]).casefold() for o in ops if o[0] == "mask"}
    assert "panel" in masked, ops
    if sys.platform != "darwin":  # case-sensitive: the name on disk, not the one written
        assert ("mask", str(runs / "r1" / "PANEL")) in ops, ops


# --- L2, L4: the whole bwrap command line, and binds that cannot be opened ----------------------

linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="bwrap's view: Linux")


@linux_only
def test_launch_refuses_a_command_line_bwrap_cannot_take(tree, monkeypatch):
    monkeypatch.setattr(wholetool, "BWRAP_MAX_ARGS", 50)
    cfg = config.load(str(tree / "repo"))
    run = tree / "run"
    (run / "tmp").mkdir(parents=True)
    with pytest.raises(wholetool.LaunchError, match="bwrap"):
        wholetool.bwrap_tool_args(cfg, [str(tree / "repo")], str(tree / "repo"), dict(os.environ),
                                  str(tree / "toolfolder"), str(run))


@linux_only
def test_a_read_only_bind_that_cannot_be_opened_stops_launch(tree, monkeypatch):
    subprocess.run(["git", "init", "-q"], cwd=str(tree / "repo"), check=True)
    real = wholetool._open_no_follow

    def failing(path):
        if "/.git/" in path:
            raise OSError(errno.EMFILE, "Too many open files")
        return real(path)
    monkeypatch.setattr(wholetool, "_open_no_follow", failing)
    cfg = config.load(str(tree / "repo"))
    run = tree / "run"
    (run / "tmp").mkdir(parents=True)
    with pytest.raises(wholetool.LaunchError, match="open"):
        wholetool.bwrap_tool_args(cfg, [str(tree / "repo")], str(tree / "repo"), dict(os.environ),
                                  str(tree / "toolfolder"), str(run))


# --- L5: the environment clean-up ---------------------------------------------------------------

def test_the_hooks_clear_the_other_glibc_and_macos_malloc_variables(tree):
    fake = tree / "fakepython"
    fake.write_text("#!/bin/sh\n/usr/bin/env\n")
    fake.chmod(0o755)
    cmd = install.isolated_command(str(fake), "hook")
    names = ["LOCALDOMAIN", "RES_OPTIONS", "RESOLV_HOST_CONF", "NIS_PATH", "TZDIR", "GETCONF_DIR",
             "MallocStackLogging", "MallocNanoZone"]
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                         env=dict(dict.fromkeys(names, "x"), PATH="/usr/bin:/bin",
                                  KEEP_ME="yes", TZ="UTC")).stdout
    assert "KEEP_ME=yes" in out and "TZ=UTC" in out, out
    for n in names:
        assert n + "=" not in out, out


def test_doctor_notes_every_loader_variable_a_project_sets(tree):
    (tree / "repo" / ".claude").mkdir()
    (tree / "repo" / ".claude" / "settings.json").write_text(
        json.dumps({"env": {"GCONV_PATH": "/x", "LOCPATH": "/x", "LD_PRELOAD": "/x"}}))
    keys = claude_settings.project_loader_keys(str(tree / "repo"), str(tree / "home"))
    assert set(keys) == {"GCONV_PATH", "LOCPATH", "LD_PRELOAD"}, keys


def test_doctor_says_when_phiward_does_not_start_in_the_cleaned_environment(tree, monkeypatch):
    from phiward import doctor
    bad = tree / "bin"
    bad.mkdir()
    (bad / "phiward").write_text('#!/bin/sh\n[ -n "$PYTHONPATH" ] || exit 1\n')
    (bad / "phiward").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bad}:/usr/bin:/bin")
    monkeypatch.setenv("PYTHONPATH", "/needed")
    problem = doctor.clean_start_problem()
    assert problem and "PYTHONPATH" in problem, problem
    (bad / "phiward").write_text("#!/bin/sh\nexit 0\n")
    assert doctor.clean_start_problem() is None
