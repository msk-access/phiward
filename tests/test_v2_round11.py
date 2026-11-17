"""The eleventh review round: a protected path written in free text is found by a root search
and a part-by-part pattern matcher, not one regex with a check after it (a rejected match hid a
root or a shorter, real name); long paths; the text after a protected path. Made-up trees only."""

import time

import pytest

from phiward import paths
from phiward.core import ALLOW, DENY
from phiward.sanitize import Sanitizer
from helpers import check_shell, gone, protect


# --- H1: a pattern match that is not protected must not hide a root -----------------------------

@pytest.mark.parametrize("pattern", ["{t}/p*_*_raw", "{t}/p*/panel", "{t}/ph*"])
def test_a_root_is_found_after_a_pattern_match_that_does_not_count(tree, pattern):
    cfg = protect(tree, [pattern.format(t=tree)])
    cmd = f"python3 -c \"import os; print(os.listdir('{tree}/phi')); x='a_raw'\""
    assert check_shell(tree, cfg, cmd).verdict == DENY
    out = Sanitizer.from_config(cfg).clean(f"listing {tree}/phi then a_raw")
    assert str(tree / "phi") not in out, out


def test_a_second_pattern_is_tried_where_the_first_does_not_count(tree):
    (tree / "d" / "phi_a_raw").mkdir(parents=True)
    cfg = protect(tree, [f"{tree}/d/p*_*_zz", f"{tree}/d/phi_*_raw"])
    cmd = f"python3 -c \"import os; os.listdir('{tree}/d/phi_a_raw'); x='q_zz'\""
    assert check_shell(tree, cfg, cmd).verdict == DENY


# --- H2: a real name before a `;` is matched even when a longer text is not ---------------------

@pytest.mark.parametrize("on_disk", [True, False])
def test_a_name_before_a_command_separator_is_found(tree, on_disk):
    if on_disk:
        (tree / "d" / "phi_a_raw").mkdir(parents=True)
    cfg = protect(tree, [f"{tree}/d/phi_*_raw"])
    for cmd in (f"python3 -c \"import os; os.listdir('{tree}/d/phi_a_raw');x='y_raw'\"",
                f"ls {tree}/d/phi_a_raw;echo y_raw",
                f"ls {tree}/d/phi_a_raw&&echo y_raw"):
        assert check_shell(tree, cfg, cmd).verdict == DENY, cmd


def test_a_folder_with_a_separator_in_its_name_is_found_in_the_middle_of_a_pattern(tree):
    (tree / "runs" / "A;B" / "panel").mkdir(parents=True)
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    assert check_shell(tree, cfg, f"python3 -c \"open('{tree}/runs/A;B/panel/x')\"").verdict == DENY
    gone(Sanitizer.from_config(cfg).clean(f"{tree}/runs/A;B/panel/Zorro.txt"), "Zorro")


def test_a_separator_after_a_folder_that_is_not_on_disk_is_two_commands(tree):
    (tree / "runs" / "r1").mkdir(parents=True)
    (tree / "runs" / "r1" / "notes.txt").write_text("ok\n")
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    assert check_shell(tree, cfg, f"cat {tree}/runs/r1/notes.txt; ls /tmp/panel").verdict == ALLOW


def test_many_candidate_names_past_a_separator_are_refused(tree):
    cfg = protect(tree, [f"{tree}/pat/phi_*_raw"])
    few = f"ls {tree}/pat/phi_a.txt; echo" + " x_raw" * 3
    many = f"ls {tree}/pat/phi_a.txt; echo" + " x_raw" * (paths.DISK_CHECKS + 10)
    assert check_shell(tree, cfg, few).verdict == ALLOW
    assert check_shell(tree, cfg, many).verdict == DENY


# --- M1: long paths -----------------------------------------------------------------------------

def test_passes_through_checks_a_path_of_many_parts_quickly(tree):
    pset = paths.ProtectedSet([str(tree / "phi")], [f"{tree}/runs/*/panel"])
    start = time.monotonic()
    assert not pset.passes_through("/a" * 40000)
    assert not pset.passes_through("/a/.." * 40000 + "/b")
    assert time.monotonic() - start < 2


def test_passes_through_still_finds_a_root_on_the_way(tree):
    pset = paths.ProtectedSet([str(tree / "phi")], [f"{tree}/runs/*/panel"])
    deep = "/x" * 50
    assert pset.passes_through(f"{tree}/phi/a/../../" + deep)
    assert pset.passes_through(f"/a/b/../..{tree}/runs/r1/panel/../../.." + deep)
    assert not pset.passes_through(f"{tree}/runs/r1/../.." + deep)


def test_the_hook_checks_a_long_command_quickly(tree):
    cfg = protect(tree, [f"{tree}/runs/*/panel", f"{tree}/pat/phi_*_raw", f"{tree}/w/*x*"])
    start = time.monotonic()
    check_shell(tree, cfg, "echo " + "/a" * 40000)
    check_shell(tree, cfg, "echo " + (f"{tree}/pat/phi_" + "_raw" * 50 + " ") * 200)
    check_shell(tree, cfg, "echo " + f"{tree}/w/" + "x" * 100000)
    assert time.monotonic() - start < 5


def test_the_sanitizer_masks_long_lines_quickly(tree):
    cfg = protect(tree, [f"{tree}/runs/*/panel", f"{tree}/pat/phi_*_raw", f"{tree}/w/*x*"])
    san = Sanitizer.from_config(cfg)
    start = time.monotonic()
    san.clean((f"{tree}/pat/phi_" + "_raw" * 50 + " ") * 200)
    san.clean(f"{tree}/w/" + "x" * 100000)
    san.clean((f"{tree}/runs/" + "a" * 50) * 300)
    assert time.monotonic() - start < 3


# --- L1, L2: the text after a protected path ----------------------------------------------------

@pytest.mark.parametrize("entries", [True, False])
@pytest.mark.parametrize("line,words", [
    ("'{t}/phi/Ann'+Zorro", "Zorro"),
    ("'{t}/phi/Ann'@Zorro", "Zorro"),
    ("'{t}/phi/Ann'#Zorro", "Zorro"),
    ("{t}/phi/O' Brien", "Brien"),
    ("{t}/phi/Ann) Zorro", "Zorro"),
    ("{t}/phi/Doe, Jane", "Jane"),
    ("'{t}/phi/O' Brien'", "Brien"),
    ("({t}/phi/Ann) Zorro)", "Zorro"),
])
def test_text_after_a_protected_path_that_may_be_more_of_the_name_is_masked(tree, entries, line,
                                                                              words):
    san = Sanitizer.from_config(protect(tree, [f"{tree}/runs/*/panel"]), entries=entries)
    gone(san.clean(line.format(t=tree)), words)


def test_the_masked_line_is_stable(tree):
    san = Sanitizer.from_config(protect(tree, [f"{tree}/runs/*/panel", f"{tree}/w/phi_*"]))
    for line in (f"open('{tree}/phi/x').read()", f"cat '{tree}/w/phi_Ann' done",
                 f"{tree}/runs/A B/panel/x and {tree}/phi/y"):
        out = san.clean(line)
        assert san.clean(out) == out and "[line withheld" not in out, (line, out)
