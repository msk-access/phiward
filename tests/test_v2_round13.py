"""The thirteenth review round: the text after a mask is judged against the rest of the line
(not only to the next protected path), roots are found in fully case-folded text, other
spellings of a path (`//`, `/./`, a backslash-newline), a command separator no longer ends a
name, and the genomics read-name rule on long words. Made-up trees only."""

import sys
import time

import pytest

from phiward.core import DENY
from phiward.sanitize import Sanitizer
from helpers import check_shell, gone, protect


def _san(tree, entries=False):
    return Sanitizer.from_config(protect(tree, [f"{tree}/runs/*/panel"]), entries=entries)


# --- H1, M1: the rest of the line decides, also past the next protected path -------------------

@pytest.mark.parametrize("entries", [True, False])
@pytest.mark.parametrize("line", ["'{t}/phi/O' Brien' '{t}/phi/b'",
                                  "\"{t}/phi/O\" Brien\" \"{t}/phi/b\"",
                                  "'{t}/phi/O' Brien' x '{t}/phi/b'",
                                  "({t}/phi/Ann) Zorro) ({t}/phi/b)"])
def test_a_quote_after_the_next_protected_path_still_counts(tree, entries, line):
    gone(_san(tree, entries).clean(line.format(t=tree)), "Brien Zorro")


# --- M2: a long line with no tab ----------------------------------------------------------------

@pytest.mark.parametrize("unit", ["{t}/phi/a ", "{t}/phi/a; ", "('{t}/phi/a'), "])
def test_a_long_line_of_masks_without_a_tab_is_quick(tree, unit):
    san = _san(tree)
    u = unit.format(t=tree)
    start = time.monotonic()
    san.clean(u * (1_000_000 // len(u)))
    assert time.monotonic() - start < 5


# --- H2: a root whose name has a letter with a longer case fold ---------------------------------

@pytest.mark.skipif(sys.platform != "darwin", reason="letter case is folded on macOS only")
def test_a_root_is_found_in_another_case_with_a_longer_fold(tree):
    (tree / "Straße").mkdir()
    cfg = protect(tree, [f"{tree}/runs/*/panel"], root="Straße")
    cmd = f"python3 -c \"print(open('{tree}/STRASSE/FAKE-PT-9.txt').read())\""
    assert check_shell(tree, cfg, cmd).verdict == DENY
    out = Sanitizer.from_config(cfg).clean(f"see {tree}/STRASSE/Zorro_Pat.txt")
    gone(out, "Zorro_Pat STRASSE")


# --- H3: other spellings of the same path -------------------------------------------------------

@pytest.mark.parametrize("path", ["{t}//phi/x", "{t}/./phi/x", "{t}/.//phi/x",
                                  "{t}/runs//r1/panel/x", "{t}/runs/r1/./panel/x"])
def test_another_spelling_of_a_protected_path_is_refused_and_masked(tree, path):
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    p = path.format(t=tree)
    assert check_shell(tree, cfg, f"python3 -c \"print(open('{p}').read())\"").verdict == DENY
    gone(Sanitizer.from_config(cfg).clean(f"{p}/Zorro_Pat.txt"), "Zorro_Pat")


def test_a_backslash_newline_inside_a_protected_path_is_refused(tree):
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    assert check_shell(tree, cfg, f"python3 -c \"print(open('{tree}/ph\\\ni/x').read())\"").verdict == DENY
    heredoc = f"python3 - <<'EOF'\nprint(open('{tree}/runs/r1/pan\\\nel/x').read())\nEOF"
    assert check_shell(tree, cfg, heredoc).verdict == DENY


# --- the separator rule is withdrawn (P5) -------------------------------------------------------

@pytest.mark.parametrize("line,words", [
    ("{t}/phi/Doe; Jane", "Jane"), ("{t}/phi/Doe && Jane", "Jane"), ("{t}/phi/Doe | Jane", "Jane")])
def test_a_separator_and_a_space_inside_a_name_are_masked(tree, line, words):
    gone(_san(tree).clean(line.format(t=tree)), words)


# --- M3: the read-name rule on long words -------------------------------------------------------

def test_the_read_name_rule_is_linear_and_still_masks(tree):
    san = _san(tree)
    start = time.monotonic()
    san.clean("x" * 40000)
    san.clean("a_" * 20000)
    san.clean("a-" * 20000 + ":")
    assert time.monotonic() - start < 2
    assert san.clean("read A00123:45:HABCDEFXX:1:1101:12345:6789") == "read <READ>"
    gone(san.clean("x --A00123:45:HABCDEFXX:1:1101 y"), "A00123 HABCDEFXX")
    gone(san.clean("@A00123:45:HABCDEFXX:1:1101:12345:6789/1"), "A00123 HABCDEFXX")
