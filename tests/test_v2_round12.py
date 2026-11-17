"""The twelfth review round: the text after many masks on one line, letters whose case fold is
longer than one character, a command separator after a protected path, a JSON-escaped slash and
a root written in NFD. Made-up trees only."""

import sys
import time
import unicodedata

import pytest

from phiward.core import DENY
from phiward.sanitize import Sanitizer
from helpers import check_shell, gone, protect


# --- M1: many masks on one line ----------------------------------------------------------------

@pytest.mark.parametrize("unit", ["('{t}/phi/a'),", "{t}/phi/a ", "'{t}/phi/a' x, "])
def test_a_line_with_many_masks_is_masked_quickly(tree, unit):
    san = Sanitizer.from_config(protect(tree, [f"{tree}/runs/*/panel"]))
    u = unit.format(t=tree)
    line = u * (300000 // len(u))
    start = time.monotonic()
    out = san.clean(line)
    assert time.monotonic() - start < 3
    assert str(tree / "phi") not in out


# --- L1: a letter whose case fold is longer than one character ----------------------------------

@pytest.mark.skipif(sys.platform != "darwin", reason="letter case is folded on macOS only")
@pytest.mark.parametrize("pattern,name", [("{t}/d/i*", "İx_raw"), ("{t}/d/*ss", "Straß")])
def test_a_letter_with_a_longer_case_fold_still_matches(tree, pattern, name):
    (tree / "d" / name).mkdir(parents=True)
    cfg = protect(tree, [pattern.format(t=tree)])
    path = f"{tree}/d/{name}"
    assert check_shell(tree, cfg, f"python3 -c \"print(open('{path}/f').read())\"").verdict == DENY
    gone(Sanitizer.from_config(cfg).clean(f"{path}/Zorro_Pat.txt"), "Zorro_Pat")


def test_a_letter_with_a_longer_case_fold_does_not_break_positions(tree):
    san = Sanitizer.from_config(protect(tree, [f"{tree}/runs/*/panel"]))
    out = san.clean(f"Straße İ {tree}/phi/x then İ ok")
    assert out.startswith("Straße İ <PROTECTED>"), out


# --- L2: a command separator after a protected path ---------------------------------------------

@pytest.mark.parametrize("line,want", [
    # round 13: a separator and a space may be part of a name (P5), so what follows is masked
    ("+ cat {t}/phi/a.txt; echo done", "+ cat <PROTECTED>"),
    ("+ cat {t}/phi/a.txt && echo done", "+ cat <PROTECTED>"),
    ("+ cat {t}/phi/a.txt | wc -l", "+ cat <PROTECTED>"),
])
def test_a_command_separator_after_a_protected_path_keeps_what_follows(tree, line, want):
    san = Sanitizer.from_config(protect(tree, [f"{tree}/runs/*/panel"]))
    assert san.clean(line.format(t=tree)) == want


@pytest.mark.parametrize("line,words", [
    ("{t}/phi/Ann;Zorro", "Zorro"),
    ("{t}/phi/Ann&Zorro", "Zorro"),
    ("{t}/phi/Ann|Zorro", "Zorro"),
    ("{t}/phi/Ann>Zorro", "Zorro"),
    ("{t}/phi/Ann> Zorro", "Zorro"),
])
def test_a_separator_inside_a_name_is_still_masked(tree, line, words):
    san = Sanitizer.from_config(protect(tree, [f"{tree}/runs/*/panel"]))
    gone(san.clean(line.format(t=tree)), words)


# --- L3: a JSON-escaped slash, a root written in NFD ---------------------------------------------

def test_a_json_escaped_slash_is_a_slash(tree):
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    san = Sanitizer.from_config(cfg)
    esc = str(tree).replace("/", "\\/")
    gone(san.clean(f'{{"p": "{tree}/phi\\/Zorro"}}'), "Zorro")
    gone(san.clean(f'{{"p": "{esc}\\/phi\\/Zorro"}}'), "Zorro")
    gone(san.clean(f'{{"p": "{esc}\\/runs\\/r1\\/panel\\/Zorro"}}'), "Zorro")
    assert check_shell(tree, cfg, f"echo '{esc}\\/phi\\/x'").verdict == DENY
    assert check_shell(tree, cfg, f"echo '{esc}\\/runs\\/r1\\/panel'").verdict == DENY


def test_a_root_written_in_nfd_is_found(tree):
    cfg = protect(tree, [f"{tree}/runs/*/panel"], root="café")
    nfd = unicodedata.normalize("NFD", f"{tree}/café")
    assert check_shell(tree, cfg, f"python3 -c \"print(open('{nfd}/x').read())\"").verdict == DENY
