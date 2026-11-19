"""An entry name under a root that looks like an identifier reads the same in masked output
whether or not the entry exists: the identifier rules (case-insensitive) mask it either way, and
the entry list only adds what the rules alone would leave. A plain name (no rule matches it) is
still masked because it exists, and so is a name with a plain part (`sample_P-...`). Made-up
names only (P-9990001-T01-IM6, Doe Jane)."""

import re

import pytest

from phiward import config
from phiward.sanitize import Sanitizer

REAL = ["P-9990001-T01-IM6.bam", "sample_P-9990006-T01-IM6.bam", "AB123456-T.bam",
        "C-ABC123-L001-d.bam", "Doe Jane", "P-9990003 Doe Jane", "P-9990004.Roe Ann.bam"]


@pytest.fixture()
def san(tree):
    for name in REAL:
        (tree / "phi" / name).write_text("SECRET-CONTENT-0009\n")
    cfg = tree / "home" / "phiward.toml"
    cfg.write_text(cfg.read_text() + '[sanitize]\npacks = ["genomics", "msk"]\n')
    return Sanitizer.from_config(config.load(str(tree / "repo")), entries=True)


@pytest.mark.parametrize("real,guess", [
    ("P-9990001-T01-IM6", "P-9990002-T01-IM6"),
    ("P-9990001-T01-IM6.bam", "P-9990002-T01-IM6.bam"),
    ("p-9990001-t01-im6", "p-9990002-t01-im6"),
    ("P-9990001-T01-IM6_R1", "P-9990002-T01-IM6_R1"),
    ("AB123456-T", "AB123457-T"),
    ("ab123456-t", "ab123457-t"),
    ("C-ABC123-L001-d", "C-ABC124-L001-d"),
])
def test_an_id_shaped_name_reads_the_same_whether_or_not_it_exists(san, real, guess):
    for line in (real, f"x {real} y", f"{real}\t{guess}"):
        other = line.replace(real, guess)
        assert san.clean(line) == san.clean(other), (line, san.clean(line), san.clean(other))
    assert real.lower() not in san.clean(f"x {real} y").lower()


@pytest.mark.parametrize("line,gone", [
    ("Doe Jane", ["Doe", "Jane"]),
    ("file P-9990003 Doe Jane here", ["Doe", "Jane", "9990003"]),
    ("P-9990004.Roe Ann.bam", ["Roe", "Ann", "9990004"]),
    # a plain part makes it a plain name: masked whole, as an entry
    ("sample_P-9990006-T01-IM6", ["sample", "9990006"]),
])
def test_a_name_with_a_personal_part_stays_masked_whole(san, line, gone):
    out = san.clean(line)
    assert not any(re.search(rf"\b{g}\b", out) for g in gone), out


def test_text_after_a_protected_path_stays_masked(san, tree):
    out = san.clean(f"open {tree}/phi/x.bam Doe Jane")
    assert "Doe" not in out and "Jane" not in out, out


def test_an_id_after_an_underscore_is_masked(san):
    assert san.clean("x_P-9990009-T01-IM6 done") == "x_<SAMPLEID> done"
