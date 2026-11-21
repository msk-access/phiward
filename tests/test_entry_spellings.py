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


def test_the_dash_and_space_lists_hold_every_one_this_python_knows():
    import sys
    known = {c: unicodedata.category(chr(c)) for c in range(sys.maxunicode + 1)
             if unicodedata.category(chr(c)) in ("Pd", "Zs")}
    assert {c for c, k in known.items() if k == "Pd"} <= set(inventory.DASHES)
    assert {c for c, k in known.items() if k == "Zs"} <= set(inventory._ZS)


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


# --- a rule match, a hit and a number: none cuts another ------------------------------------------

def _one(names, packs, patterns=()):
    return _pair(names, packs, patterns)[0]


@pytest.mark.parametrize("table", [False, True])
def test_a_rule_match_that_starts_inside_a_hit_is_not_taken_in(table):
    s = _one(["Roe Ann.bam"], ("genomics",))
    assert s.clean("MRN77_Roe Ann.bam.1.vcf", table) == "<BAMFILE>"


@pytest.mark.parametrize("line", [
    "C-PLE12345", "C–PLE12345", "Donor–1,234,567", "Donor-1,234,567",
    "1,234,567-AB123456.a:b:c:d:e", "x 1,234,567‐AB123456.a:b:c:d:e y",
])
def test_a_rule_match_never_ends_or_starts_inside_a_number(line):
    out = _one([], ("genomics", "msk")).clean(line)
    assert not re.search(r"[0-9]", out), out


def test_a_hit_never_cuts_a_number():
    s = _one(["ABCDE12", "T_xyz9"], ("genomics",))
    assert s.clean("ABCDE 12345") == "<ENTRY>"
    assert not re.search(r"[0-9]", s.clean("PT‐xyz90002")), s.clean("PT‐xyz90002")


# --- R9: never less masked than before ------------------------------------------------------------
# The masking as it was before this change, kept here as the reference: lines in NFKC only (no fold
# of dashes or digits), every name string in one literal trie, an entry hit covered only by a rule
# match that holds it whole, and each rule applied as a plain substitution. The line as written
# goes to both; the text each keeps is compared after the fold. Where the reference withheld a
# line (its masked line was not a fixed point), its first masked line is the reference.

def _nfkc_only(text):
    """The form lines were read in before this change: NFKC, with no fold of dashes or digits."""
    text = inventory._ESCAPES.sub("", text)
    text = text.replace("\\ ", " ")
    text = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


class _Before(Sanitizer):
    def __init__(self, *a, strings=(), **k):
        super().__init__(*a, **k)
        words = sorted(set(strings))
        self.old = re.compile(inventory._trie_regex(words), re.IGNORECASE) if words else None

    def _apply(self, rules, line):
        for rx, repl in rules:
            if repl == KEEP_PLACEHOLDER and self.keep_files:
                line = rx.sub(lambda m, r=repl: m.group(0) if self._kept(m.group(0)) else r, line)
            else:
                line = rx.sub(lambda _m, r=repl: r, line)
        return line

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

    def first(self, line, table=False):
        """The reference's first masked line (before the check that withholds a line)."""
        return self._mask(_nfkc_only(line), table)

    def clean(self, line, table=False):
        try:
            line = _nfkc_only(line)
            out = self._mask(line, table)
            if self._mask(out, table) != out:
                return WITHHELD
            if "\\" in out or "%" in out:
                plain = _nfkc_only(unescape(out))
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
    return [inventory.normalize(k).casefold() for k in _HOLE.split(out) if k]


def _less(new, old, line, table):
    """None, or why the new masking keeps text the reference masked."""
    n = new.clean(line, table)
    if n == WITHHELD:
        return None
    o = old.clean(line, table)
    if o == WITHHELD:
        o = old.first(line, table)
    olds = _kept(o)
    for k in _kept(n):
        # text with no letter or digit names no one, nor does punctuation at a kept run's edge
        # (a `,` a rule used to take with a number)
        k = re.sub(r"^\W+|\W+$", "", k)
        if k and not any(k in x for x in olds):
            return (line, n, o)
    return None


R9_NAMES = ["FAKE-PT-0001.bam", "Doe_Jane_FAKE", "FAKEPT0002", "T_xyz9", "AB123456-T_sorted",
            "P-9990001-T01-IM6", "xxabc", "abcdefg", "Roe Ann.bam", "fake.dots.name", "ab12",
            "20240115", "SAM_PLE", "EN-TRY", "C-ABC123-L001-d", "PLE12", "Donor_FAKE7",
            "s_C_FAKE01", "chr1_12345_A", "12345678", "XY123456-N", "run2024_01", "_lead_fake",
            "trail_fake_", "ABCDE12"]
R9_PIECES = ["FAKE", "PT", "0001", "0002", "Doe", "Jane", "T", "xyz9", "AB123456", "sorted", "P",
             "9990001", "T01", "IM6", "xx", "abc", "defg", "Roe", "Ann", "bam", "C", "ABC123", "PLE",
             "12345", "PLE12345", "L001", "d", "chr1", "s", "Donor", "FAKE7", "2024", "01", "15",
             "0115", "N", "XY123456", "1,234,567", "a:b:c:d:e", "out", "x.vcf", ".vcf", ".1.vcf",
             "٠١", "١٢٣٤٥", "Q123", "fakept", "SAMPLE", "ENTRY",
             "jan", "3", "12:00", "MRN77", "lead", "trail", "ABCDE"]
R9_SEPS = ["-", "_", ".", " ", "", "", "", "‐", "–", "−", " ", "/", "\t", ":",
           ",", "'"]
R9_PACKS = [(("genomics",), ()), (("genomics", "msk"), ()), (("genomics", "msk", "dates"), ()),
            (("genomics",), (r"\bQ\d{3,}\b => <QID>", r"(?i)\bfake[_-]?pt\b => <FAKEPT>"))]


def _r9_lines(seed, n):
    rnd = random.Random(seed)
    for _ in range(n):
        parts = []
        for _ in range(rnd.randint(1, 8)):
            parts += [rnd.choice(R9_PIECES), rnd.choice(R9_SEPS)]
        if rnd.random() < 0.4:
            name = rnd.choice(R9_NAMES)
            if rnd.random() < 0.5:
                name = name.replace("-", rnd.choice(["‐", "–", "_", " ", ""]))
            parts.insert(rnd.randrange(len(parts) + 1), name)
        yield "".join(parts)


@pytest.mark.slow
@pytest.mark.parametrize("packs,patterns", R9_PACKS)
@pytest.mark.parametrize("table", [False, True])
def test_never_less_masked_than_before(packs, patterns, table):
    new, old = _pair(R9_NAMES, packs, patterns)
    for case in ("AB123456-T xyz9", "AB123456-T_xyz9", "xx-abcdefg", "_lead_fake x",
                 "x trail_fake_ y", "MRN77_Roe Ann.bam.1.vcf", "PT‐xyz90002",
                 "C–PLE12345", "Donor–1,234,567", "ABCDE 12345"):
        assert _less(new, old, case, table) is None, _less(new, old, case, table)
    bad = [f for seed in range(1, 6) for f in (_less(new, old, x, table)
                                                for x in _r9_lines(seed, 1500)) if f]
    assert not bad, (len(bad), bad[:5])


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
            f"{i}\tFAKE–SPEED–{k:06d}\t{rnd.randrange(100)} µg — ok",
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
    lines = _made_up_lines(400000)
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
    assert t_new <= 1.5 * t_old + 0.2, (t_new, t_old)
    assert l_new <= 1.5 * l_old + 0.2, (l_new, l_old)


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
