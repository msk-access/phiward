"""Randomized tests of the three parts that decide refusals and masking: the path
model, the gateway's command parser, and the sanitizer. Standard library only; a fixed seed per
test (set AG_FUZZ_SEED to explore), so a failure can be repeated."""

import os
import random
import re

import pytest

from phiward import gateway, pathmatch, paths
from phiward.sanitize import Sanitizer

SEED = int(os.environ.get("AG_FUZZ_SEED", "20261104"))
ROUNDS = int(os.environ.get("AG_FUZZ_ROUNDS", "400"))


# --- the path model: every spelling that resolves into a root is inside it --------------------

def _spellings(rng, root, base):
    """Random spellings of paths near `root`, written from `base`."""
    rel = os.path.relpath(root, base)
    parts = ["a", "b", ".", "..", "", "x y", "FAKE-PT-1"]
    tail = "/".join(rng.choice(parts) for _ in range(rng.randint(0, 4)))
    lead = rng.choice([root, root + "/", root + "//", rel, "./" + rel, rel + "/.",
                       os.path.join(rel, "a", ".."), "/" + root.lstrip("/"),
                       os.path.dirname(root) + "/./" + os.path.basename(root),
                       os.path.dirname(root) + "/x/../" + os.path.basename(root)])
    return os.path.join(lead, tail) if tail else lead


def test_fuzz_every_spelling_into_a_root_is_inside(tree):
    rng = random.Random(SEED)
    root = str(tree / "phi")
    (tree / "phi" / "a").mkdir(exist_ok=True)
    os.symlink(tree / "phi", tree / "pub" / "via-link") if (tree / "pub").exists() else None
    pset = paths.ProtectedSet([root], [])
    base = str(tree / "repo")
    real_root = os.path.realpath(root)
    for _ in range(ROUNDS):
        p = _spellings(rng, root, base)
        full = p if p.startswith("/") else os.path.join(base, p)
        real = os.path.realpath(full)
        rel = pset.relation(full)
        if real == real_root or real.startswith(real_root + os.sep):
            assert rel == paths.INSIDE, (p, rel)


def test_fuzz_pattern_matching_agrees_with_a_reference(tree):
    rng = random.Random(SEED + 1)
    alphabet = ["a", "b", "ab", "FAKE", "x.y", "-"]
    for _ in range(ROUNDS):
        pat_parts = ["".join(rng.choice(alphabet + ["*"]) for _ in range(rng.randint(1, 3)))
                     for _ in range(rng.randint(1, 3))]
        name_parts = ["".join(rng.choice(alphabet) for _ in range(rng.randint(1, 3)))
                      for _ in range(len(pat_parts))]
        pattern = "/r/" + "/".join(pat_parts)
        path = "/r/" + "/".join(name_parts)
        if pathmatch.problem(pattern):
            continue
        # reference: `*` matches any run within one part, nothing else is special
        want = all(re.fullmatch(".*".join(re.escape(x) for x in pp.split("*")), np, re.S | re.I)
                   is not None for pp, np in zip(pat_parts, name_parts))
        assert pathmatch.match_path(pattern, path) == want, (pattern, path)


# --- the gateway's parser: an unquoted operator anywhere means "not a gateway call" ---------------

_SAFE = ["wc", "-l", "file.txt", "'a b'", '"c d"', "x=1", "--", "./s.sh", "~/f", "{a,b}"]
_OPS = [";", "|", "&", "&&", "||", ">", "<", ">>", "2>&1", "$(id)", "`id`", "\n", "<(ls)", ">(cat)"]


def test_fuzz_the_parser_refuses_every_unquoted_operator():
    rng = random.Random(SEED + 2)
    for _ in range(ROUNDS):
        words = [rng.choice(_SAFE) for _ in range(rng.randint(1, 5))]
        has_op = rng.random() < 0.6
        if has_op:
            op = rng.choice(_OPS)
            # a newline at the very end is allowed on purpose (trailing newlines are stripped)
            words.insert(rng.randint(0, len(words) - (1 if op == "\n" else 0)), op)
        cmd = "phiward run -- " + " ".join(words)
        call = gateway.parse_call(cmd)
        if has_op:
            assert call is None, repr(cmd)
        else:
            assert call is not None and call.name == "run", repr(cmd)


def test_fuzz_the_parser_never_raises():
    rng = random.Random(SEED + 3)
    chars = "phiward run copy -- ;|&<>$()`'\"\\{}*?[]~#\n\t =x"
    for _ in range(ROUNDS * 2):
        s = "".join(rng.choice(chars) for _ in range(rng.randint(0, 40)))
        gateway.parse_call(s)
        gateway.parse_call("phiward run -- " + s)


# --- the sanitizer: no protected name or path survives, and a second pass changes nothing --------

def test_fuzz_the_sanitizer_never_leaves_a_name_and_is_stable(tree):
    rng = random.Random(SEED + 4)
    root = str(tree / "phi")
    names = ["FAKE-PT-0001", "FAKE-PT-0002", "P-9990001-T01-IM6", "SECRETNAME"]
    for n in names:
        (tree / "phi" / f"{n}.txt").write_text("x\n")
    pset = paths.ProtectedSet([root], [])
    san = Sanitizer(pset, entries=[n + ".txt" for n in names] + names)
    noise = ["ok", "count=5", "\x1b[31m", "\x1b[0m", " ", "/", "\t", ":", "ｆａｋｅ", "é", "\u200b"]
    for _ in range(ROUNDS):
        bits = []
        for _ in range(rng.randint(1, 6)):
            r = rng.random()
            if r < 0.3:
                bits.append(rng.choice(names))
            elif r < 0.5:
                bits.append(root + "/" + rng.choice(names) + ".txt")
            else:
                bits.append(rng.choice(noise))
        line = "".join(bits)
        out = san.clean(line)
        assert san.clean(out) == out, (line, out)
        low = out.casefold()
        for n in names:
            assert n.casefold() not in low, (line, out)
        assert root not in out, (line, out)


@pytest.mark.parametrize("seed", range(3))
def test_fuzz_the_sanitizer_never_raises_on_bytes(seed):
    rng = random.Random(SEED + 10 + seed)
    san = Sanitizer()
    for _ in range(ROUNDS):
        raw = bytes(rng.randrange(256) for _ in range(rng.randint(0, 64)))
        san.clean(raw.decode("utf-8", "replace"))


@pytest.mark.parametrize("cmd", ["<<", "x <<", ">", "a >", "phiward run -- wc <<"])
def test_found_by_fuzzing_a_missing_redirect_word_is_a_syntax_error(cmd):
    # the parser read past the end of the string (IndexError) instead of refusing
    assert gateway.parse_call(cmd) is None
