"""Entry names are matched in other spellings: with their separators (`-`, `_`, `.`, a space)
changed or left out, with other dashes (U+2010, U+2013, U+2212...) and with other decimal digits
(Arabic-Indic). One form on both sides: lines and names are folded the same way
(`inventory.normalize`), and a name of 5 or more letters and digits with a letter is also found
with its separators changed or left out. A hit that runs past a rule's match takes that match
with it. Made-up names only (FAKE-PT-0001, Doe_Jane_FAKE, P-9990001-T01-IM6)."""

import random
import re
import time
import unicodedata

import pytest

from helpers import check_shell, needs_confine, protect
from phiward import config, inventory, paths
from phiward.core import DENY
from phiward.sanitize import (STOP_WORDS, WITHHELD, Sanitizer, _MARK, KEEP_PLACEHOLDER,
                              load_pack, parse_rule, unescape)

NAMES = ["Doe_Jane_FAKE", "FAKEPT0005", "T_xyz9", "ab12", "20240115", "SAM_PLE", "EN-TRY"]


def _san(tree, packs=("genomics",)):
    for name in NAMES:
        (tree / "phi" / name).write_text("SECRET-CONTENT-0009\n")
    (tree / "phi" / "P-9990001-T01-IM6.bam").write_text("SECRET-CONTENT-0009\n")
    cfg = tree / "home" / "phiward.toml"
    cfg.write_text(cfg.read_text() + "[sanitize]\npacks = [" +
                   ", ".join(f'"{p}"' for p in packs) + "]\n")
    return Sanitizer.from_config(config.load(str(tree / "repo")), entries=True)


@pytest.fixture()
def san(tree):
    return _san(tree)


@pytest.fixture()
def msk(tree):
    return _san(tree, ("genomics", "msk"))


# --- R1: each spelling of an entry name reads <ENTRY> ---------------------------------------------

@pytest.mark.parametrize("spelling", [
    "FAKE_PT_0001", "FAKE.PT.0001", "FAKEPT0001", "FAKE PT 0001", "fake-pt-0001",
    "FAKE‐PT‐0001", "FAKE‑PT‑0001", "FAKE–PT–0001",
    "FAKE−PT−0001", "FAKE﹣PT﹣0001", "FAKE PT 0001",
    "FAKE　PT　0001", "FAKE-PT-٠٠٠١", "FAKE_PT-0001",
])
def test_each_spelling_of_an_entry_name_reads_entry(san, spelling):
    assert san.clean(f"x {spelling} y") == "x <ENTRY> y"


# --- R2: the reverse: a name written without separators, text with them --------------------------

@pytest.mark.parametrize("spelling", ["FAKE-PT-0005", "FAKE PT 0005", "fake_pt_0005"])
def test_a_name_without_separators_is_found_with_them(san, spelling):
    assert san.clean(f"x {spelling} y") == "x <ENTRY> y"


# --- R3: in context ---------------------------------------------------------------------------------

@pytest.mark.parametrize("line,gone", [
    ("RG:Z:FAKE_PT_0001", ["FAKE", "0001"]),
    ("@RG\tID:FAKEPT0001\tSM:FAKE PT 0001", ["FAKE", "0001"]),
    ('a,"FAKE–PT–0001",b', ["FAKE", "0001"]),
    ("out/FAKE_PT_0001.vcf", ["FAKE", "0001"]),
    ("Doe Jane FAKE done", ["Doe", "Jane"]),
    ("doe.jane.fake done", ["doe", "jane"]),
])
def test_other_spellings_are_masked_in_context(san, line, gone):
    out = san.clean(line)
    assert out != WITHHELD and not any(g.lower() in out.lower() for g in gone), out


# --- R4: a pack rule fires on a dash or digit spelling ---------------------------------------------

@pytest.mark.parametrize("spelling", [
    "P‐9990011‐T01‐IM6", "P–9990011–T01–IM6",
    "P-٩٩٩٠٠١١-T01-IM6",
])
def test_a_pack_rule_fires_on_a_dash_or_digit_spelling(msk, spelling):
    assert msk.clean(f"x {spelling} y") == msk.clean("x P-9990011-T01-IM6 y") == "x <SAMPLEID> y"


# --- R5: controls that stay plain ---------------------------------------------------------------

@pytest.mark.parametrize("line", [
    "x FAKE-PT-0009 y", "x FAKE_PT y", "x PT 0001 y", "on 2024-01-15 ok", "x FAKE/PT/0001 y",
    "x FAKE\tPT0001 y", "x ab 12 y",
])
def test_other_text_stays_plain(san, line):
    assert san.clean(line) == line


def test_a_digits_only_name_is_matched_only_as_written(san):
    assert san.clean("x 20240115 y") == "x <ENTRY> y"
    assert san.clean("x 2024-01-15 y") == "x 2024-01-15 y"


def test_a_short_name_is_matched_only_as_written(san):
    assert san.clean("x ab12 y") == "x <ENTRY> y"


# --- R6: names that would clash with placeholders ----------------------------------------------

def test_a_name_that_clashes_with_a_placeholder_is_masked_as_written(msk):
    line = "x P-9990011-T01-IM6 FAKE_PT_0001 y"
    assert msk.clean(line) == "x <SAMPLEID> <ENTRY> y"
    assert msk.clean("x SAM_PLE y") == "x <ENTRY> y"
    assert msk.clean("x EN-TRY y") == "x <ENTRY> y"
    # only as written: `sample` and `entry` are placeholder words (a stated limit)
    assert msk.clean("x sample entry y") == "x sample entry y"


# --- R7: a root and a pattern's folder holding a dash other than `-` ---------------------------
# (a pattern holds only printable ASCII; its wildcard, or a link in its literal part, can still
# lead to a folder whose name holds U+2010)

DASH = "\u2010"


def _dash_tree(tree):
    import os
    (tree / f"phi{DASH}x").mkdir()
    (tree / f"phi{DASH}x" / "f").write_text("SECRET-CONTENT-0010\n")
    (tree / f"run{DASH}a" / "panel").mkdir(parents=True)
    (tree / f"run{DASH}a" / "panel" / "g").write_text("SECRET-CONTENT-0011\n")
    (tree / f"dash{DASH}top" / "r1" / "panel").mkdir(parents=True)
    (tree / f"dash{DASH}top" / "r1" / "panel" / "h").write_text("SECRET-CONTENT-0012\n")
    os.symlink(tree / f"dash{DASH}top", tree / "dlink")
    return protect(tree, [f"{tree}/run*/panel", f"{tree}/dlink/*/panel"], root=f"phi{DASH}x")


@pytest.mark.parametrize("dash", [DASH, "-"])
def test_a_root_or_pattern_with_another_dash_is_masked_in_both_spellings(tree, dash):
    cfg = _dash_tree(tree)
    s = Sanitizer.from_config(cfg, entries=True)
    for path in (f"{tree}/phi{dash}x/f", f"{tree}/run{dash}a/panel/g",
                 f"{tree}/dash{dash}top/r1/panel/h"):
        out = s.clean(f"cat {path}")
        assert out == "cat <PROTECTED>", out


def test_a_sibling_written_with_a_plain_dash_is_refused_by_the_hook(tree):
    """The folded forms also serve the hook and the git hooks: a path written with `-` next to a
    root written with U+2010 is refused too (a refusal, never an allow)."""
    cfg = _dash_tree(tree)
    pset = paths.ProtectedSet(cfg.roots, cfg.patterns)
    assert pset.text_search(f"cat {tree}/phi-x/f") is not None
    assert pset.text_search(f"cat {tree}/dash-top/r1/panel/h") is not None
    assert check_shell(tree, cfg, f"cat {tree}/phi-x/f").verdict == DENY


# --- R8: a real and a guessed ID read the same, in each spelling ------------------------------------

@pytest.mark.parametrize("form", [
    lambda s: s, lambda s: s.replace("-", DASH),
    lambda s: "".join(chr(0x0660 + int(c)) if c.isdigit() else c for c in s),
])
def test_a_real_and_a_guessed_id_read_the_same_in_each_spelling(msk, form):
    real, guess = form("P-9990001-T01-IM6"), form("P-9990002-T01-IM6")
    for line in (f"x {real} y", f"{real}.bam", f"{real}\t{guess}"):
        other = line.replace(real, guess)
        assert msk.clean(line) == msk.clean(other), (line, msk.clean(line))
    assert "9990001" not in msk.clean(f"x {real} y")


# --- C: a hit that runs past a rule's match takes the match with it ------------------------------

def test_a_hit_past_a_rule_match_masks_the_whole_match(msk):
    assert msk.clean("AB123456-T xyz9") == "<ENTRY>"
    assert msk.clean("AB123456-T_xyz9") == "<ENTRY>"


# --- end to end ---------------------------------------------------------------------------------

@needs_confine
def test_another_spelling_is_masked_through_the_gateway(tree, broker):
    import os
    import subprocess
    import sys
    from pathlib import Path
    src = str(Path(__file__).resolve().parents[1] / "src")
    r = subprocess.run([sys.executable, "-m", "phiward", "run", "--", "echo",
                        "got FAKE_PT_0001 and FAKE PT 0001"], cwd=str(tree / "repo"),
                       capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=src),
                       timeout=120)
    assert "got <ENTRY> and <ENTRY>" in r.stdout, (r.stdout, r.stderr)


# --- R9: never less masked than before ------------------------------------------------------------
# The masking as it was before this change, kept here as the reference: lines in NFKC only (no
# dash or digit folding), every name string in one literal trie, and an entry hit covered only by
# a rule match that holds it whole.

def _plain_normalize(text):
    text = inventory._ESCAPES.sub("", text)
    text = text.replace("\\ ", " ")
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


class _Before(Sanitizer):
    def __init__(self, *a, strings=(), **k):
        super().__init__(*a, **k)
        words = sorted(set(strings))
        self.old = re.compile(inventory._trie_regex(words), re.IGNORECASE) if words else None

    def _entries(self, line, *_rest):
        rx = self.old
        if rx is None:
            return line
        hits = [(m.start(), m.end()) for m in rx.finditer(line)]
        if not hits:
            return line
        spans = []
        for rule, repl in self.path_rules + self.id_rules:
            spans += [(m.start(), m.end(), repl) for m in rule.finditer(line)
                      if m.end() > m.start() and _MARK not in m.group(0)
                      and not (repl == KEEP_PLACEHOLDER and self.keep_files
                               and self._kept(m.group(0)))]
        parts = []
        for a, b in hits:
            cover = next(((s, e, r) for s, e, r in spans if s <= a and b <= e), None)
            parts.append(cover or (a, b, "<ENTRY>"))
        parts.sort()
        merged = []
        for a, b, r in parts:
            if merged and a < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
                if r == "<ENTRY>" or merged[-1][2] != r:
                    merged[-1][2] = "<ENTRY>"
            else:
                merged.append([a, b, r])
        out, pos = [], 0
        for a, b, r in merged:
            out += [line[pos:a], r]
            pos = b
        out.append(line[pos:])
        return "".join(out)

    def clean(self, line, table=False):
        try:
            line = _plain_normalize(line)
            out = self._mask(line, table)
            if self._mask(out, table) != out:
                return WITHHELD
            if "\\" in out or "%" in out:
                plain = _plain_normalize(unescape(out))
                if plain != out and self._mask(plain, table) != plain:
                    return WITHHELD
            return out
        except Exception:  # noqa: BLE001
            return WITHHELD


def _rules(packs, patterns=()):
    loaded = [load_pack(p) for p in packs]
    ids = [r for p in loaded for r in p.identifiers]
    ids += [parse_rule(v, "[sanitize] patterns") for v in patterns]
    ids = [(re.compile(rx.pattern, rx.flags | re.IGNORECASE), r) for rx, r in ids]
    return {"path_rules": [r for p in loaded for r in p.paths], "id_rules": ids,
            "pos_rules": [r for p in loaded for r in p.positions],
            "keep_files": [k for p in loaded for k in p.keep_files]}


def _pair(names, packs, patterns=()):
    stop = {w.casefold() for w in STOP_WORDS}
    strings = sorted({s for n in names for s in inventory._strings_of(n, stop)})
    rules = _rules(packs, patterns)
    return Sanitizer(entries=strings, **rules), _Before(strings=strings, **rules)


_HOLE = re.compile(r"<[A-Z][A-Z0-9_]*>")


def _kept(out):
    return [inventory.normalize(k) for k in _HOLE.split(out) if k]


def _never_less(new, old, line, table):
    n, o = new.clean(line, table), old.clean(line, table)
    if o == WITHHELD:
        assert n == WITHHELD, (line, n)
        return
    if n == WITHHELD:
        return
    # each run of text the new masking keeps lies inside a run the old masking kept
    olds = _kept(o)
    for k in _kept(n):
        assert any(k in x for x in olds), (line, n, o)


R9_NAMES = ["FAKE-PT-0001.bam", "Doe_Jane_FAKE", "FAKEPT0002", "T_xyz9", "AB123456-T_sorted",
            "P-9990001-T01-IM6", "xxabc", "abcdefg", "_lead_fake", "trail_fake_", "Roe Ann.bam",
            "fake.dots.name", "ab12", "20240115", "SAM_PLE", "EN-TRY", "C-ABC123-L001-d"]
R9_PIECES = ["FAKE", "PT", "0001", "0002", "Doe", "Jane", "T", "xyz9", "AB123456", "sorted", "P",
             "9990001", "T01", "IM6", "xx", "abc", "defg", "lead", "trail", "Roe", "Ann", "bam",
             "dots", "name", "ab", "12", "2024", "0115", "SAM", "PLE", "EN", "TRY", "C", "ABC123",
             "L001", "d", "chr1", "12345", "x", "file", "q"]
R9_SEPS = ["-", "_", ".", " ", "", "", "‐", "–", " ", "/", "\t", ":", ","]


@pytest.mark.slow
@pytest.mark.parametrize("packs,patterns", [
    (("genomics",), ()), (("genomics", "msk"), ()),
    (("genomics",), (r"\bQ\d{3,}\b => <QID>", r"(?i)\bfake[_-]?pt\b => <FAKEPT>")),
])
@pytest.mark.parametrize("table", [False, True])
def test_never_less_masked_than_before(packs, patterns, table):
    new, old = _pair(R9_NAMES, packs, patterns)
    rnd = random.Random(20261121)
    for case in ("AB123456-T xyz9", "AB123456-T_xyz9", "xx-abcdefg", "_lead_fake x",
                 "x trail_fake_ y"):
        _never_less(new, old, case, table)
    for _ in range(4000):
        parts = []
        for _ in range(rnd.randint(1, 8)):
            parts += [rnd.choice(R9_PIECES), rnd.choice(R9_SEPS)]
        if rnd.random() < 0.3:
            parts.insert(rnd.randrange(len(parts) + 1), rnd.choice(R9_NAMES))
        _never_less(new, old, "".join(parts), table)


# --- R10: speed ----------------------------------------------------------------------------------

def _made_up_lines(n):
    rnd = random.Random(7)
    out = []
    for i in range(n):
        k = rnd.randrange(200000)
        out.append(rnd.choice([
            f"read{i}\t0\tchr1\t{rnd.randrange(10**8)}\t60\t100M\t*\t0\t0\tACGTACGTAC\tFFFFFFFFFF",
            f"INFO {i}: processed sample_{k:06d} in {rnd.random():.3f}s, 0 errors",
            f"{i},FAKE-SPEED-{k:06d},tumor,{rnd.random():.4f},pass",
            f"[{i}] wrote out/run{k % 50}/summary.txt ({rnd.randrange(10**6)} bytes)",
        ]))
    return out


@pytest.mark.slow
def test_speed_within_the_targets():
    """200,000 made-up names: building the matcher and masking a line each cost at most 1.5x
    what they did before this change (the targets of the change)."""
    stop = {w.casefold() for w in STOP_WORDS}
    strings = sorted({s for i in range(200000)
                      for s in inventory._strings_of(f"FAKE-SPEED-{i:06d}.bam", stop)})
    inventory._MATCHER.clear()
    re.purge()  # `re` keeps compiled patterns: each build compiles its own
    t = time.perf_counter()
    new = Sanitizer(entries=strings)
    t_new = time.perf_counter() - t
    re.purge()
    t = time.perf_counter()
    old = _Before(strings=strings)
    t_old = time.perf_counter() - t
    lines = _made_up_lines(100000)
    size = sum(len(x) + 1 for x in lines)
    t = time.perf_counter()
    for x in lines:
        new.clean(x)
    l_new = time.perf_counter() - t
    t = time.perf_counter()
    for x in lines:
        old.clean(x)
    l_old = time.perf_counter() - t
    print(f"\nR10: build {t_new:.2f}s (before {t_old:.2f}s); {size / 1e6:.1f} MB masked in "
          f"{l_new:.2f}s (before {l_old:.2f}s)")
    assert t_new <= 1.5 * t_old + 0.5, (t_new, t_old)
    assert l_new <= 1.5 * l_old + 0.5, (l_new, l_old)


# --- R11: the cost in other text (measured) -------------------------------------------------------

R11_NAMES = ["FAKE-PT-0001.bam", "Doe_Jane_FAKE", "sample_01", "batch_12", "FAKE-PT-0002.cram",
             "run_2024_01", "tumor-normal", "Roe_Ann"]


def _corpus():
    rnd = random.Random(11)
    lines = ["@HD\tVN:1.6\tSO:coordinate", "@SQ\tSN:chr1\tLN:248956422",
             "@RG\tID:FAKE-PT-0001\tSM:FAKE-PT-0001\tLB:lib1\tPL:ILLUMINA",
             "@PG\tID:bwa\tPN:bwa\tVN:0.7.17\tCL:bwa mem -t 8 ref.fa r1.fq r2.fq",
             "##fileformat=VCFv4.2", "##source=made-up-caller 1.0",
             "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tFAKE_PT_0001",
             "Sample_ID,Sample_Name,I7_Index_ID,index,Sample_Project",
             "sample 01,Doe Jane FAKE,N701,TAAGGCGA,batch 12",
             "| Sample Name | % Dups | % GC | M Seqs |", "| sample_01 | 12.3% | 41% | 22.1 |",
             "The tumor-normal pair was run in batch 12 with sample 01 as the control.",
             "We compared run 2024 01 with earlier runs; Roe Ann reviewed the report."]
    words = ["the", "sample", "batch", "run", "tumor", "normal", "reads", "01", "12", "2024",
             "mapped", "quality", "pass", "Doe", "Jane", "Ann", "Roe", "fake", "pt", "0001"]
    for _ in range(3000):
        lines.append(f"chr{rnd.randint(1, 22)}\t{rnd.randrange(10**7)}\t.\tA\tG\t{rnd.randint(1, 99)}"
                     f"\tPASS\tDP={rnd.randint(5, 200)}\tGT\t0/1")
        lines.append(" ".join(rnd.choice(words) for _ in range(rnd.randint(4, 14))) + ".")
    return lines


@pytest.mark.slow
def test_the_cost_in_other_text_is_measured():
    new, old = _pair(R11_NAMES, ("genomics",))
    lines = _corpus()
    changed = held = generic = 0
    for x in lines:
        n, o = new.clean(x), old.clean(x)
        changed += n != o
        held += n == WITHHELD
        generic += n != o and bool(re.search(r"(?i)sample.01|batch.12", x))
    print(f"\nR11: {len(lines)} lines, {changed} masked more than before, {held} withheld, "
          f"{generic} of them for a generic name (sample 01, batch 12)")
    assert held == 0
