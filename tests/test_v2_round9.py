"""The ninth review round: a shell character after a protected path, the folders that decide
confinement, the hook's pattern regex (false refusals, slow lines), the launch view's cost of a
hidden folder that is also split, and the full bwrap command line. Made-up trees only."""

import json
import os
import subprocess
import sys
import time

import pytest

from phiward import claude_settings, config, install, wholetool
from phiward.adapters import decide
from phiward.core import ALLOW, DENY, SHELL, Action
from phiward.guards import protected_paths
from phiward.sanitize import Sanitizer
from helpers import gone, protect


def _san(tree, patterns, folders=(), entries=True):
    cfg = protect(tree, patterns)
    for f in folders:
        (tree / f).mkdir(parents=True, exist_ok=True)
    return Sanitizer.from_config(cfg, entries=entries)


# --- M-a, L-d: a shell character or another separator after a protected path ------------------

@pytest.mark.parametrize("entries", [True, False])
@pytest.mark.parametrize("line,words", [
    ("{t}/phi/O'Brien Pat", "Brien Pat"),
    ("{t}/phi/Ann&Zorro", "Zorro"),
    ("{t}/phi/Zorro(Quux)", "Quux"),
    ("{t}/phi/Ann;Zorro", "Zorro"),
    ("{t}/phi/Ann|Zorro", "Zorro"),
    ("{t}/runs/r1/panel/O'Brien Pat.txt", "Brien Pat"),
    ("{t}/phi/New Zorro", "Zorro"),
    ("{t}/phi/New\x85Zorro", "Zorro"),
])
def test_a_name_after_a_shell_character_or_separator_is_masked(tree, entries, line, words):
    san = _san(tree, [f"{tree}/runs/*/panel"], ["runs/r1/panel"], entries)
    gone(san.clean(line.format(t=tree)), words)


# --- L-g: what may stay after a folder on disk ------------------------------------------------

def test_a_one_letter_unit_is_masked_and_a_path_after_a_folder_on_disk_stays(tree):
    san = _san(tree, [f"{tree}/wild/phi_*"], ["wild/phi_Ann"])
    gone(san.clean(f"{tree}/wild/phi_Ann: 12 B"), "B")
    assert san.clean(f"cp {tree}/wild/phi_Ann /tmp/x").endswith(" /tmp/x")
    assert san.clean(f"{tree}/wild/phi_Ann: 12 KB") == "<PROTECTED>: 12 KB"


# --- M-b, L-e: the folders that decide whether the shell is confined ---------------------------

def test_a_parent_folder_outside_the_named_project_does_not_decide_confinement(tree, monkeypatch):
    parent = tree / "outer"
    proj = parent / "P"
    (proj / "src").mkdir(parents=True)
    (parent / ".claude").mkdir()  # claude was once run there: no settings of this session
    (proj / ".git").mkdir()
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(proj))
    seen = []

    def confinement_reason(p, *a, **k):
        seen.append(p)
        return (None if os.path.realpath(p) != os.path.realpath(parent) else
                claude_settings.Reason("not confined", "x"))
    monkeypatch.setattr(claude_settings, "confinement_reason", confinement_reason)
    d = decide(Action(SHELL, str(proj / "src"), command="cat $UNKNOWN_VAR", tool="Bash"),
               claude_sandbox=True)
    assert d.verdict == ALLOW, (d.reason, seen)


def test_a_nested_folder_inside_the_named_project_still_decides(tree, monkeypatch):
    proj = tree / "repo"
    sub = proj / "vendor" / "lib"
    (sub / ".git").mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(proj))
    monkeypatch.setattr(claude_settings, "confinement_reason",
                        lambda p, *a, **k: claude_settings.Reason("not confined", "x")
                        if os.path.realpath(p) == os.path.realpath(sub) else None)
    d = decide(Action(SHELL, str(sub), command="cat $UNKNOWN_VAR", tool="Bash"),
               claude_sandbox=True)
    assert d.verdict == DENY, d.reason


def test_an_outer_folder_s_redirect_still_refuses_every_call(tree, monkeypatch):
    outer = tree / "outer"
    (outer / "P" / ".git").mkdir(parents=True)
    (outer / ".claude").mkdir()
    (outer / ".claude" / "settings.json").write_text(json.dumps({"env": {"BASH_ENV": "/x"}}))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(outer / "P"))
    d = protected_paths.check(Action(SHELL, str(outer / "P"), command="ls"),
                              config.load(str(tree / "repo")))
    assert d.verdict == DENY and "BASH_ENV" in d.reason, d.reason


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS volumes ignore letter case")
def test_the_named_project_holds_a_folder_written_in_another_case(tree, monkeypatch):
    (tree / "CaseProj" / "sub").mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "caseproj"))
    assert claude_settings.named_project_holds(str(tree / "CaseProj" / "sub"))


# --- L-a, L-b: the hook's pattern regex -------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "ls {t}/pat/phi_a.txt && echo done_raw",
    "ls {t}/pat/phi_a.txt; echo x_raw",
])
def test_separate_commands_are_not_read_as_one_protected_path(tree, cmd):
    (tree / "pat").mkdir()
    (tree / "pat" / "phi_a.txt").write_text("ok\n")
    (tree / "runs" / "notes.txt").write_text("ok\n")
    cfg = protect(tree, [f"{tree}/pat/phi_*_raw", f"{tree}/runs/*/panel"])
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command=cmd.format(t=tree)), cfg)
    assert d.verdict == ALLOW, d.reason


def test_the_hook_s_pattern_regex_does_not_cross_a_command_separator(tree):
    from phiward import paths
    pset = paths.ProtectedSet([], [f"{tree}/runs/*/panel"])
    assert pset.text_search(f"cat {tree}/runs/notes.txt; ls /panel") is None
    assert pset.text_search(f"cat {tree}/runs/notes.txt && ls x/panel") is None
    assert pset.text_search(f"cat '{tree}/runs/Zed (B)/panel/x'")


def test_a_quoted_name_with_shell_characters_is_still_refused(tree):
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    d = protected_paths.check(Action(SHELL, str(tree / "repo"),
                                     command=f"cat '{tree}/runs/A&B;C/panel/x'"), cfg)
    assert d.verdict == DENY, d.reason


@pytest.mark.parametrize("pattern,line", [
    ("{t}/x/*_*_raw", '"_\'' * 20000),
    ("{t}/x/*_*_*_raw", "_" * 3000),
    ("{t}/x/*_*_*_raw", "{t}/x/" + "_" * 3000),
])
def test_a_long_line_is_masked_and_checked_quickly(tree, pattern, line):
    p = pattern.format(t=tree)
    san = _san(tree, [p])
    text = line.format(t=tree)
    start = time.monotonic()
    san.clean(text)
    protected_paths.check(Action(SHELL, str(tree / "repo"), command="echo " + text[:20000]),
                          config.load(str(tree / "repo")))
    assert time.monotonic() - start < 3


def test_a_pattern_with_several_wildcards_in_one_name_still_matches(tree):
    san = _san(tree, [f"{tree}/x/*_*_raw"])
    gone(san.clean(f"{tree}/x/a_Zorro_raw/f.txt"), "Zorro")
    assert san.clean(f"{tree}/x/plain.txt").endswith("/x/plain.txt")


# --- L-c: a hidden folder that is also split ----------------------------------------------------

def test_a_hidden_folder_that_a_pattern_walks_costs_only_its_mask_when_shown_whole(tree):
    big = tree / "big"
    big.mkdir()
    for i in range(2000):  # the folder that must be shown whole
        (big / f"f{i}").write_text("x")
    for i in range(150):
        (big / "phi" / f"r{i}").mkdir(parents=True)
    hide, pats = [str(big / "phi")], [str(big / "phi") + "/*/raw"]
    # the view with no limit: with the default one, a crowded temp folder (many tests run
    # before) already shrinks it, and `full - 3000` would be below what is left
    full, _s, _w = wholetool.hidden_view(hide, pats, (), limit=10 ** 9, named=[])
    limit = sum(wholetool._OP_ARGS[o[0]] for o in full) - 3000
    ops, _split, whole = wholetool.hidden_view(hide, pats, (), limit=limit, named=[])
    assert sum(wholetool._OP_ARGS[o[0]] for o in ops) <= limit
    phi = str(big / "phi")
    # never split, never shown: only masked where big is shown whole (big itself, or a crowded
    # folder above it that leaves big to be rebuilt without it)
    assert not any(o[0] in ("tmpfs", "bind", "symlink") and (o[-1] == phi or o[-1].startswith(phi + "/"))
                   for o in ops)
    assert any(str(big) == w or str(big).startswith(w + "/") for w in whole)
    assert (("mask", phi) in ops) == (str(big) in whole)


# --- M-c: the whole bwrap command line ----------------------------------------------------------

def test_the_bwrap_command_counts_every_word_after_the_separator(monkeypatch):
    monkeypatch.setattr(wholetool, "BWRAP_MAX_ARGS", 40)
    args = ["--tmpfs", "/x"] * 10  # 20 words
    with pytest.raises(wholetool.LaunchError, match="bwrap"):
        wholetool._bwrap_command("bwrap", 3, args, "/p", ["python", "-c", "h"],
                                 [str(n) for n in range(12)], ["tool"])
    cmd = wholetool._bwrap_command("bwrap", 3, args[:10], "/p", ["python"], ["5"], ["tool"])
    assert cmd[-3:] == ["1", "5", "tool"] and "--" in cmd


# --- L-f: the environment clean-up and doctor's notes -------------------------------------------

def test_a_tz_that_names_a_file_is_cleared_and_a_plain_tz_stays(tree):
    fake = tree / "fakepython"
    fake.write_text("#!/bin/sh\n/usr/bin/env\n")
    fake.chmod(0o755)
    cmd = install.isolated_command(str(fake), "hook")
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                         env={"PATH": "/usr/bin:/bin", "TZ": ":/evil/zone"}).stdout
    assert "TZ=" not in out, out
    for tz in ("UTC", "America/New_York", ":America/New_York"):
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                             env={"PATH": "/usr/bin:/bin", "TZ": tz}).stdout
        assert f"TZ={tz}\n" in out, (tz, out)


def test_doctor_notes_malloc_variables_a_project_sets(tree):
    (tree / "repo" / ".claude").mkdir()
    (tree / "repo" / ".claude" / "settings.json").write_text(
        json.dumps({"env": {"MallocLogFile": "/x", "MALLOC_CONF": "x", "KEEP": "1"}}))
    keys = claude_settings.project_loader_keys(str(tree / "repo"), str(tree / "home"))
    assert set(keys) == {"MallocLogFile", "MALLOC_CONF"}, keys
