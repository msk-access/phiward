"""Properties of the free-text check and the masking, over seeded random inputs (made-up trees
only). They are the gate for any change to `paths._TextFinder` or the sanitizer's tail rule:
- P5: no part of a name inside a protected path survives masking, whatever follows the path;
- the hook and the sanitizer find every path `pathmatch` says is a match;
- long inputs take time in proportion to their length."""

import random
import re
import time

import pytest

from phiward import paths, pathmatch
from phiward.sanitize import Sanitizer
from helpers import protect

SEED = 20261112
ROUNDS = 3000
# characters a name may hold (no `/`, tab or newline); `Zq` marks the secret part
NAME_CHARS = "abcXY019 _-.,:;&|()[]{}<>'\"`+@#$!?=~^%*"
FOLLOW = ["", " done", "' done", "') ok", "\")", ", 3)", "] ok", ": 12 reads", "; echo x",
          " && y", " | wc -l", "\tcol2", " /tmp/other", "'+x", " 'q'", ")"]
OPEN = ["", "'", "\"", "(", "[", "{", "<", "cat ", "('", "see "]


def _name(rng):
    body = "".join(rng.choice(NAME_CHARS) for _ in range(rng.randint(0, 8)))
    cut = rng.randint(0, len(body))
    name = body[:cut] + "Zq" + body[cut:]
    # a name that ends in a space before a `/` reads as two paths (a known, documented gap)
    return name.replace(" /", "_/")


def _leaks(out):
    return re.search(r"zq", out, re.I) is not None


@pytest.mark.parametrize("entries", [False, True])
def test_p5_no_part_of_a_name_inside_a_protected_path_survives(tree, entries):
    cfg = protect(tree, [f"{tree}/runs/*/panel", f"{tree}/w/phi_*"])
    san = Sanitizer.from_config(cfg, entries=entries)
    rng = random.Random(SEED)
    for _ in range(ROUNDS):
        name = _name(rng)
        place = rng.choice([f"{tree}/phi/{name}", f"{tree}/phi/a/{name}",
                            f"{tree}/runs/r1/panel/{name}", f"{tree}/runs/{name}/panel/x",
                            f"{tree}/w/phi_{name}"])
        line = rng.choice(OPEN) + place + rng.choice(FOLLOW)
        out = san.clean(line)
        assert not _leaks(out), (line, out)
        assert san.clean(out) == out, (line, out)


def test_text_after_a_path_stays_only_where_the_name_has_ended(tree):
    san = Sanitizer.from_config(protect(tree, [f"{tree}/runs/*/panel"]))
    assert san.clean(f"at {tree}/phi, then") == "at <PROTECTED>, then"  # the root itself ended
    assert san.clean(f"cp {tree}/phi/a /tmp/b") == "cp <PROTECTED> /tmp/b"
    assert san.clean(f"{tree}/phi/a\tcol2") == "<PROTECTED>\tcol2"
    assert san.clean(f"cat '{tree}/phi/x' done") == "cat '<PROTECTED>"


def _part(rng):
    stars = rng.randint(0, 2)
    lits = ["".join(rng.choice("abX_.-") for _ in range(rng.randint(0, 3))) for _ in range(stars + 1)]
    part = "*".join(lits)
    return part or "*"


def test_the_matcher_finds_every_path_pathmatch_matches(tree):
    rng = random.Random(SEED + 1)
    for _ in range(ROUNDS):
        pattern = f"{tree}/m/" + "/".join(_part(rng) for _ in range(rng.randint(1, 3)))
        if pathmatch.problem(pattern):  # the config refuses it (`.` as a part)
            continue
        names = []
        for part in pathmatch.parts(pattern)[len(pathmatch.parts(str(tree))) + 1:]:
            fill = "".join(rng.choice("abX_.- 'q(") for _ in range(rng.randint(0, 4)))
            names.append(part.replace("*", fill, 1).replace("*", ""))
        if any(not n for n in names):
            continue
        path = f"{tree}/m/" + "/".join(names)
        if not pathmatch.match_path(pattern, path):
            continue
        pset = paths.ProtectedSet([], [pattern])
        text = f"cat {path} x"
        assert pset.text_search(text), (pattern, path)
        spans = pset.text_spans(text)
        start = text.index(path)
        assert any(s <= start and (e >= start + len(path) or o) for s, e, o in spans), \
            (pattern, path, spans)


@pytest.mark.parametrize("unit", ["{t}/phi/a ", "('{t}/phi/a'), ", "{t}/runs/r/panel/x; ",
                                  "{t}/w/phi_" + "_x" * 20 + " ", "/" * 50, "a_" * 25,
                                  "{t}//phi/./a ", "ßİ "])
def test_long_inputs_take_time_in_proportion(tree, unit):
    cfg = protect(tree, [f"{tree}/runs/*/panel", f"{tree}/w/phi_*_x", f"{tree}/*/q*"])
    san = Sanitizer.from_config(cfg)
    pset = paths.ProtectedSet([f"{tree}/phi"], cfg.patterns)
    u = unit.format(t=tree)
    line = u * (1_000_000 // len(u))
    start = time.monotonic()
    san.clean(line)
    pset.text_search("echo " + line)
    assert time.monotonic() - start < 6, unit
