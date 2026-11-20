"""`phiward run --table` reads CSV/TSV output by column (issue #2): a cell under an identifier
header is masked whole (`<IDCOL>`); a plain number passes only in a parsed cell of another
column; every other line is masked as text. Made-up data only (FAKE-PT-0001, numeric fake MRNs
such as 1234567 and 9990001)."""

import ast
import io
import os
import random
import re
import stat
import sys
from pathlib import Path

import pytest

from phiward import config, copying, inventory, run, sanitize
from phiward.sanitize import WITHHELD, Sanitizer
from helpers import needs_confine

PY = sys.executable
SRC = Path(__file__).resolve().parents[1] / "src"


# --- fixtures (copied from test_sanitize.py, not imported) ----------------------------------------

def names_file(tmp_path):
    p = tmp_path / "runs.tsv"
    p.write_text("\n".join(sanitize.MADE_UP_RUNS) + "\n")
    return str(p)


@pytest.fixture()
def genomics():
    return Sanitizer._build(config.Config(packs=["genomics"]), (), ())


@pytest.fixture()
def msk(tmp_path):
    cfg = config.Config(packs=["genomics", "msk"], names_from=[names_file(tmp_path)])
    return Sanitizer.from_config(cfg)


def read(san, lines, extra=()):
    cols = sanitize.Columns(san, list(extra))
    return [cols.line(l) for l in lines]


def text_mode(san, lines):
    return [san.clean(l) for l in lines]


# --- what a column shows ------------------------------------------------------------------------

def test_numeric_mrn_in_id_column_is_masked(genomics):
    assert read(genomics, ["sample_id\tfragment_count", "1234567\t7654321"]) == \
        ["sample_id\tfragment_count", "<IDCOL>\t7654321"]
    # today's per-line table mode shows the record number
    assert genomics.clean("1234567\t7654321", table=True) == "1234567\t7654321"


@pytest.mark.parametrize("header", ["MRN", "Patient ID", "sample-id", "#SubjectID", "Sample.ID",
                                    "patientid", "Tumor_Sample_Barcode"])
def test_header_match_is_case_and_separator_blind(genomics, header):
    assert read(genomics, [f"{header}\tn", "1234567\t12"])[1] == "<IDCOL>\t12"


def test_number_kept_in_other_columns(genomics):
    got = read(genomics, ["fragment_count\tmean\tsd\tmrn", "7654321\t12.5\t1e-05\t1",
                          "1,234,567\t-0.5\t3%\t2"])
    assert got[1:] == ["7654321\t12.5\t1e-05\t<IDCOL>", "1,234,567\t-0.5\t3%\t<IDCOL>"]


def test_non_number_cell_gets_positions(genomics):
    got = read(genomics, ["locus\tn\tmrn", "chr1:1234567\t3\t1", "near 7654321\t4\t2"])
    assert got[1:] == ["<LOCUS>\t3\t<IDCOL>", "near <NUM>\t4\t<IDCOL>"]


def test_identifier_rules_on_every_cell(msk):
    got = read(msk, ["note\tsample_id\tn", "P-9990001-T01-IM6\tP-9990002-T01-IM6\t1",
                     "ok\tP-9990001 x\t2"])
    assert got[1:] == ["<SAMPLEID>\t<SAMPLEID>\t1", "ok\t<IDCOL>\t2"]


def test_headerless_output_is_text_mode(genomics):
    lines = ["1234567\t7654321", "sample_id\tn", "7654321\t3"]
    assert read(genomics, lines) == text_mode(genomics, lines)
    assert "1234567" not in "".join(read(genomics, lines))


def test_line_before_header_means_text_mode(genomics):
    lines = ["warning: x", "sample_id\tcount", "1234567\t7654321"]
    assert read(genomics, lines) == text_mode(genomics, lines)


def test_an_empty_line_ends_column_mode(genomics):
    # one table per output: after an empty line every line is text, also a second header
    lines = ["sample_id\tn", "1234567\t7654321", "", "n\tmrn", "7654321\t1234567"]
    got = read(genomics, lines)
    assert got[:2] == ["sample_id\tn", "<IDCOL>\t7654321"]
    assert got[2:] == text_mode(genomics, lines[2:])


def test_misfit_row_is_text_mode(genomics):
    # the first misfit ends column mode for the rest of the output
    lines = ["sample_id\tn", "1234567\t7654321\t5", "1234567", "1234567\t7654321"]
    got = read(genomics, lines)
    assert got[1:] == text_mode(genomics, lines[1:])


def test_quoted_row_is_text_mode(genomics):
    lines = ["name,count", '"Doe, J",1234567']
    assert read(genomics, lines)[1] == genomics.clean(lines[1])
    assert "1234567" not in read(genomics, lines)[1]


def test_csv_comma_delimiter(genomics):
    assert read(genomics, ["sample_id,count", "1234567,7654321"])[1] == "<IDCOL>,7654321"


def test_entry_with_delimiter_falls_back(genomics):
    genomics.entries = inventory.matcher(["Doe, Jane"])
    # the rows have the header's field count until the entry name is masked
    got = read(genomics, ["name,note,count", "Doe, Jane,7654321", "x,Doe, Jane"])
    joined = "\n".join(got)
    assert "Doe" not in joined and "Jane" not in joined, got
    assert got[1:] == text_mode(genomics, ["Doe, Jane,7654321", "x,Doe, Jane"])


def test_protected_path_cell_falls_back():
    root = sanitize.SELFTEST_ROOT
    san = Sanitizer.from_config(config.Config(roots=[root]))
    row = f"{root}/Doe, Jane,7654321"
    got = read(san, ["file,note,count", row])
    assert "Doe" not in got[1] and "Jane" not in got[1] and "7654321" not in got[1], got
    assert got[1] == san.clean(row)


def test_header_with_identifier_is_not_a_header(msk):
    lines = ["gene\tP-9990001-T01-IM6", "TP53\t1234567"]
    assert read(msk, lines) == text_mode(msk, lines)


def test_fullwidth_comma_is_split_after_normalize(genomics):
    got = read(genomics, ["sample_id,n", "1234567\uff0c12"])
    assert "1234567" not in got[1] and got[1] == "<IDCOL>,12"


@pytest.mark.parametrize("row", ["\\x31234567\t12", "%31234567\t12", "a\\t1234567\t12"])
def test_escaped_row_is_text_mode(genomics, row):
    assert read(genomics, ["note\tn", row])[1] == genomics.clean(row)


def test_reset_after_too_long_line(genomics):
    cols = sanitize.Columns(genomics, [])
    assert cols.line("sample_id\tn") == "sample_id\tn"
    cols.reset()
    assert cols.line("1234567\t7654321") == genomics.clean("1234567\t7654321")
    assert cols.line("") == ""
    assert cols.line("sample_id\tn") == "sample_id\tn"
    assert cols.line("1234567\t7654321") == genomics.clean("1234567\t7654321")


def test_empty_tsv_row_does_not_reread_the_header(genomics):
    got = read(genomics, ["sample_id\tnote", "1234567\tok", "\t", "FAKE-PT-0001\tok",
                          "7654321\tok"])
    joined = "\n".join(got)
    assert "1234567" not in joined and "7654321" not in joined, got
    assert got[2] == "\t"


@pytest.mark.parametrize("first", ["FAKE-PT-0001\tok", "abc123\tok", "P-9990001-T01-IM6\tok"])
def test_data_first_line_is_not_a_header(msk, first):
    got = read(msk, [first, "7654321\tok"])
    assert "7654321" not in got[1], got
    assert got == text_mode(msk, [first, "7654321\tok"])


@pytest.mark.parametrize("lines", [
    ["gene,depth", "TP53,12", "depth,mrn", "12,9990001"],
    ["score\tn", "1\t2", "sample\tpatient_id", "x\t9990001"],
    ["a\tb\tc", "1\t2\t3", "sample_id,gene,n", "9990001\tx\t9990002"],
])
def test_second_header_without_empty_line_ends_the_table(genomics, lines):
    # `cat a.csv b.csv`: the second header is not a row of the first table
    got = read(genomics, lines)
    assert "9990001" not in got[3], got
    assert got[2:] == text_mode(genomics, lines[2:])


def test_row_without_a_number_ends_column_mode(genomics):
    lines = ["gene,n", "TP53,BRCA1", "x,9990001", "", "mrn,n", "9990002,4"]
    got = read(genomics, lines)
    assert got[1:] == text_mode(genomics, lines[1:])


def test_empty_lines_before_the_header(genomics):
    assert read(genomics, ["", "sample_id,n", "9990002,4"]) == ["", "sample_id,n", "<IDCOL>,4"]


@pytest.mark.parametrize("lines", [
    ["depth,mrn", "12,9990002", '"mrn","depth"', "9990001,12"],  # R's quoted header
    ["gene,depth,n", "TP53,12,3", ",sample,mrn", "0,x,9990001"],  # a pandas index header
    ["gene,depth", "TP53,12", "mrn_v100,depth", "9990001,12"],  # a 3-digit run
    ["gene,depth", "TP53,12", "mrn:id,depth", "9990001,12"],  # a colon
    ["gene,n", "TP53,1", "", "yes,no", "9990001,1"],  # a header after an empty line
])
def test_a_second_table_is_text(genomics, lines):
    # `cat a.csv b.csv`: one table per output; a line that does not fit, a row with no number
    # and an empty line end column mode for the rest of the output
    got = read(genomics, lines)
    assert "9990001" not in got[-1], got
    assert got[2:] == text_mode(genomics, lines[2:])


@pytest.mark.parametrize("lines", [
    ["Results, see below", "9990001,5"],
    ["Cohort summary, generated by tool, v2", "mrn,2023,2024", "9990001,5,7"],
    ["gene,depth", "TP53,9990001"],
])
def test_a_header_must_name_an_id_column(genomics, lines):
    # prose with commas, or a table with no identifier column: the whole output is text
    got = read(genomics, lines)
    assert got == text_mode(genomics, lines)
    assert "9990001" not in "\n".join(got)


@pytest.mark.parametrize("header", ["caseno", "ptno", "patno", "labno", "empi", "fin", "csn",
                                    "participant", "individual_id", "proband", "person",
                                    "collection_date", "date"])
def test_more_id_globs(genomics, header):
    assert read(genomics, [f"{header}\tn", "1234567\t5"])[1] == "<IDCOL>\t5"


def test_words_as_the_first_line_are_a_header(genomics):
    # documented: a first row of words that names an identifier column is read as a header
    assert read(genomics, ["NA,NA", "9990002,4"])[1] == "<NUM>,4"
    assert read(genomics, ["NA,id", "9990002,4"])[1] == "9990002,<IDCOL>"


def test_bom_header(genomics):
    assert read(genomics, ["\ufeffsample_id\tn", "1234567\t5"]) == ["sample_id\tn", "<IDCOL>\t5"]


def test_chrom_pos_cells_are_kept(genomics):
    # documented limit (R6): positions rules that span cells do not match cell by cell
    assert read(genomics, ["chrom\tpos\tmrn", "chr1\t1234567\t1"])[1] == "chr1\t1234567\t<IDCOL>"
    assert genomics.clean("chr1\t1234567") == "<LOCUS>"


@pytest.mark.parametrize("header", ["pt", "pt_no", "subj", "ids", "identifier",
                                    "medical_record_number", "record", "chart_no", "encounter",
                                    "visit", "ssn", "phone", "zip", "id", "case", "dob",
                                    "birth_date", "specimen", "accession", "donor", "MedRecNo",
                                    "PatNum", "Acct", "acct_nbr", "rec_key", "visitno"])
def test_builtin_globs_cover_common_headers(genomics, header):
    assert read(genomics, [f"{header}\tn", "1234567\t5"])[1] == "<IDCOL>\t5"


@pytest.mark.parametrize("header", ["gene", "mean", "count", "fragment_count", "depth", "note",
                                    "chrom", "pos", "locus", "gc", "HospNo", "kit", "tube"])
def test_other_headers_are_not_id_columns(genomics, header):
    # (also documented gaps: `HospNo`, `kit`, `tube`; they belong in id_columns)
    assert read(genomics, [f"{header}\tmrn", "1234567\t5"])[1] == "1234567\t<IDCOL>"


def test_comma_joined_digits_are_not_a_number(genomics):
    got = read(genomics, ["count\tn", "1234567,7654321\t5"])[1]
    assert "1234567" not in got and "7654321" not in got, got
    assert got == "<NUM>,<NUM>\t5"


def test_second_pass_misfit_is_withheld(genomics, monkeypatch):
    cols = sanitize.Columns(genomics, [])
    assert cols.line("sample_id\tn") == "sample_id\tn"
    real = cols._mask
    calls = []

    def eat_on_second(s):
        calls.append(s)
        out = real(s)
        return out.replace("\t", "", 1) if len(calls) == 2 else out

    monkeypatch.setattr(cols, "_mask", eat_on_second)
    assert cols.line("1234567\t7654321") == WITHHELD
    assert len(calls) == 2


def test_exception_in_a_row_is_withheld(genomics, monkeypatch):
    cols = sanitize.Columns(genomics, [])
    cols.line("sample_id\tn")

    def boom(s):
        raise RuntimeError("fault")

    monkeypatch.setattr(cols, "_mask", boom)
    assert cols.line("1234567\t7654321") == WITHHELD


def test_a_placeholder_like_id_cell_that_this_sanitizer_never_writes_is_masked(genomics):
    got = read(genomics, ["sample_id\tn", "<P9990001>\t1", "<NUM>\t2", " \t3"])
    assert got[1:] == ["<IDCOL>\t1", "<NUM>\t2", " \t3"]


def test_idcol_is_a_placeholder_word(tmp_path):
    p = tmp_path / "runs.tsv"
    p.write_text("1\t/x/idcol/FAKE-PT-0001.bam\n")
    san = Sanitizer.from_config(config.Config(), [str(p)])
    assert "idcol" not in {t.lower() for t in san.tokens}
    assert read(san, ["sample_id\tn", "1234567\t5"])[1] == "<IDCOL>\t5"


# --- idempotence and the property test ----------------------------------------------------------

PIECES = [  # from test_sanitize.py
    "P-9990001-T01-IM6", "C-ABC123-L001", "s_C_XYZ789_P1", "AB123456-T", "DonorFake-1", "x.bam",
    "slice.bam", "FAKE-PT-0001.fastq.gz", "A00123:45:HABCDEFXX:1:1101:12345:6789/1", "chr1:1234567",
    "7:100-200", "12,345,678", "98765", "1234", "\t", " ", "/data/fake/x", "/tmp/inputs/patient/a",
    "ZedRun_77", "alpha", "QQSAMP", "<NAME>", "<PROTECTED>", "<LOCUS>", "=", ",", ";", "(", ")",
    "1_1234_A_C", "m54012_190101_000000/12345/ccs", "name", "read", "locus", ".", "-", "_", ":", "/",
]
ID_HEADERS = ["sample_id", "MRN", "Patient ID", "#SubjectID", "Tumor_Sample_Barcode", "pt_no",
              "visit", "accession"]
OTHER_HEADERS = ["fragment_count", "mean", "locus", "note", "gene", "pos", "chrom", "depth"]
WORDS = ["NA", "TP53", "BRCA1", "ok", "yes", "no", "id", "accepted"]
WORD_IDS = {"id", "accepted"}  # identifier column names (`accepted`: acc*, a false positive)
SMALL = ["12", "12.5", "1e-05", "0", "-3", "7.25%", "1,234"]


@pytest.fixture()
def secret_san(tmp_path):
    cfg = config.Config(packs=["genomics", "msk"], names_from=[names_file(tmp_path)],
                        sanitize_patterns=[r"FAKE-PT-\d{4} => <SUBJECT>"])
    san = Sanitizer.from_config(cfg)
    san.entries = inventory.matcher(["Doe, Jane", "Zorro Quux"])
    return san


def _table(rng, counter):
    """Lines and, for each line, (secrets that may be shown, secrets that must not be)."""
    lines, allowed, banned = [], [], []

    def mrn():
        counter[0] += 1
        return str(9000000 + counter[0])  # unique 7-digit made-up record numbers

    def fake():
        counter[0] += 1
        return f"FAKE-PT-{counter[0] % 10000:04d}"

    # the model of what the docs promise, from what the generator knows it wrote (not from the
    # reader's header test): one table per output. Its header is the first non-empty line, when
    # it names an identifier column (a header, or a row of words with `id` or `accepted`);
    # from then on every line is a row that fits (the header's field count, no delimiter,
    # quote or escape inside a cell, and a number cell), or it ends the table for the rest of
    # the output: an empty line, another header, a misfit. After that every line is text:
    # nothing is allowed. Rows always take the width and delimiter of the latest header-like
    # line, whatever the model's state, so a reader that goes back into column mode is caught.
    state, is_id = "start", []
    last = None  # (width, delimiter) of the latest header-like line
    for _ in range(rng.randint(1, 14)):
        kind = rng.choice(["header", "row", "row", "row", "row", "row", "blank", "noise",
                           "quoted", "empty", "wide", "words", "badheader", "prose"])
        ok_line, bad = [], []
        fits = False
        if kind == "blank":
            line = ""
        elif kind == "header":
            d = rng.choice(["\t", ","])
            names = rng.sample(ID_HEADERS + OTHER_HEADERS, rng.randint(2, 5))
            line = d.join(names)
            last = (len(names), d)
            if state == "start" and any(n in ID_HEADERS for n in names):
                state, is_id = "table", [n in ID_HEADERS for n in names]
                fits = True
        elif kind == "words":
            width, d = last if last else (rng.randint(2, 4), rng.choice(["\t", ","]))
            words = [rng.choice(WORDS) for _ in range(width)]
            line = d.join(words)
            last = (width, d)
            if state == "start" and any(w in WORD_IDS for w in words):
                state, is_id = "table", [w in WORD_IDS for w in words]
                fits = True
        elif kind == "badheader":
            d = rng.choice(["\t", ","])
            fields = rng.choice([['"mrn"', '"depth"'], ["", "gene", "mrn"],
                                 ["mrn_v100", "depth"], ["mrn:id", "depth"]])
            line = d.join(fields)
            last = (len(fields), d)
        elif kind == "prose":
            line = rng.choice(["Results, see below", "Cohort summary, generated by tool, v2"])
            last = (line.count(",") + 1, ",")
        elif kind == "noise":
            s = mrn()
            bad.append(s)
            line = rng.choice([f"warning: record {s} skipped", f"{fake()} done {s}",
                               "progress 10%"])
        elif kind == "quoted":
            s = mrn()
            bad.append(s)
            line = f'"Doe, J",{s}'
        elif kind == "empty":
            line = "\t" if rng.random() < 0.5 else "   "
        else:
            width, d = last if last else (rng.randint(2, 4), rng.choice(["\t", ","]))
            if kind == "wide":
                width += rng.choice([-1, 1])
            cells, plain, number = [], [], False
            for _ in range(max(1, width)):
                c = rng.random()
                if c < 0.4:
                    s = mrn()
                    cell, p, number = s, s, True
                elif c < 0.55:
                    cell, p, number = rng.choice(SMALL), None, True
                elif c < 0.65:
                    s = mrn()
                    bad.append(s)
                    cell, p = f"id {s} x", None
                elif c < 0.75:
                    f = fake()
                    bad.append(f)
                    cell, p = f, None
                elif c < 0.8:
                    bad.extend(["Doe", "Jane", "Zorro", "Quux"])
                    cell, p = rng.choice(["Doe, Jane", "Zorro Quux"]), None
                else:  # never a plain number: it starts with a letter
                    cell = "t" + "".join(rng.choice(PIECES) for _ in range(rng.randint(1, 4)))
                    p = None
                cells.append(cell)
                plain.append(p)
            line = d.join(cells)
            fits = (state == "table" and len(cells) == len(is_id) and number and
                    not any(d in c for c in cells) and '"' not in line and "\\" not in line
                    and not re.search(r"%[0-9A-Fa-f]{2}", line))
            for i, p in enumerate(plain):
                if p is None:
                    continue
                if fits and not is_id[i]:
                    ok_line.append(p)
                else:
                    bad.append(p)
        if not fits and not (state == "start" and kind == "blank"):
            state = "none"
        lines.append(line)
        allowed.append(ok_line)
        banned.append(bad)
    return lines, allowed, banned


def _shown(word, text):
    if word.isdigit():
        return re.search(rf"(?<![0-9]){word}(?![0-9])", text) is not None
    return re.search(rf"(?<![A-Za-z0-9]){re.escape(word)}(?![A-Za-z0-9])", text, re.I) is not None


def test_property_never_shows_what_text_mode_masks(secret_san):
    """The oracle does not use text mode: it knows each planted secret and where it put it. A
    secret is shown only as a whole plain-number cell of a non-ID column in a row made
    well-formed under a real header."""
    rng = random.Random(20261119)
    counter = [0]
    kept = 0
    for _ in range(500):
        lines, allowed, banned = _table(rng, counter)
        cols = sanitize.Columns(secret_san, [])
        out = [cols.line(l) for l in lines]
        for i, words in enumerate(banned):
            for w in words:
                assert not _shown(w, out[i]), (w, lines, out)
        kept += sum(_shown(w, out[i]) for i, ws in enumerate(allowed) for w in ws)
    assert kept > 10  # the test makes well-formed rows, and their numbers pass


def test_second_pass_is_idempotent(secret_san):
    rng = random.Random(20261120)
    counter = [0]
    for _ in range(300):
        lines, _a, _b = _table(rng, counter)
        cols = sanitize.Columns(secret_san, [])
        for l in lines:
            state = (cols.state, cols.delim, cols.width, list(cols.is_id))
            rows = cols.rows
            out = cols.line(l)
            if cols.rows == rows:  # not read by column (text mode, a header, a blank line)
                continue
            again = sanitize.Columns(secret_san, [])
            again.state, again.delim, again.width, again.is_id = state
            assert again.line(out) == out, (l, out)


# --- config: [sanitize] id_columns ----------------------------------------------------------------

def load(tmp_path, user, repo=None):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    cfg = tmp_path / "cfg.toml"
    cfg.write_text(user)
    rd = tmp_path / "repo"
    rd.mkdir(exist_ok=True)
    if repo is not None:
        (rd / ".phiward.toml").write_text(repo)
    return config.load(str(rd), env={"HOME": str(home), "PHIWARD_CONFIG": str(cfg),
                                     "PATH": os.environ.get("PATH", "")})


def test_user_id_column_with_space_matches(tmp_path, genomics):
    cfg = load(tmp_path, '[sanitize]\nid_columns = ["Lab Code", "Visit-Code"]\n')
    assert not cfg.problem, cfg.problem
    assert cfg.sanitize_id_columns == ["lab_code", "visit_code"]
    got = read(genomics, ["Lab Code\tvisit.code\tn", "1234567\t7654321\t5"],
               cfg.sanitize_id_columns)
    assert got[1] == "<IDCOL>\t<IDCOL>\t5"


@pytest.mark.parametrize("value", ['["a/b"]', '["a\\"b"]', "[12]", '["' + "x" * 65 + '"]',
                                   '["#"]', '[" "]', '"lab"'])
def test_id_columns_bad_value_is_a_problem(tmp_path, value):
    cfg = load(tmp_path, f"[sanitize]\nid_columns = {value}\n")
    assert cfg.problem


def test_id_columns_is_user_only(tmp_path):
    cfg = load(tmp_path, "", '[sanitize]\nid_columns = ["lab_code"]\n')
    assert not cfg.problem
    assert cfg.sanitize_id_columns == []
    assert "sanitize.id_columns" in cfg.ignored


def test_id_columns_add_to_the_built_in_list(tmp_path, genomics):
    cfg = load(tmp_path, '[sanitize]\nid_columns = ["lab_code"]\n')
    got = read(genomics, ["lab_code\tsample_id\tn", "1234567\t7654321\t5"],
               cfg.sanitize_id_columns)
    assert got[1] == "<IDCOL>\t<IDCOL>\t5"


# --- the gateway ----------------------------------------------------------------------------------

def user_cfg(extra):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + extra)


NO_HEADER = "[--table: no header line was found; the output was masked as text]"


def go(tree, lines, table=True):
    code = "import sys\nsys.stdout.write(" + repr("".join(l + "\n" for l in lines)) + ")"
    out = io.StringIO()
    argv = (["--table"] if table else []) + ["--", PY, "-c", code]
    rc = run.execute(argv, str(tree / "repo"), dict(os.environ), out)
    return rc, out.getvalue()


@needs_confine
def test_run_table_masks_id_column(tree):
    user_cfg("[sanitize]\ntable = true\n")
    rc, text = go(tree, ["sample_id\tfragment_count", "1234567\t7654321"])
    assert rc == 0, text
    assert "<IDCOL>\t7654321" in text.splitlines(), text
    assert "1234567" not in text and NO_HEADER not in text


@needs_confine
def test_run_table_state_is_per_request(tree):
    user_cfg("[sanitize]\ntable = true\n")
    rc, text = go(tree, ["sample_id\tn", "1234567\t7654321"])
    assert rc == 0 and "<IDCOL>\t7654321" in text, text
    rc, text = go(tree, ["1234567\t7654321"])
    assert rc == 0, text
    assert "<NUM>\t<NUM>" in text.splitlines() and NO_HEADER in text, text
    assert "1234567" not in text and "7654321" not in text


@needs_confine
def test_run_table_rows_differing_only_in_id_collapse(tree):
    user_cfg("[sanitize]\ntable = true\n")
    rc, text = go(tree, ["sample_id\tn", "1234567\t5", "7654321\t5", "9990001\t5", "end"])
    assert rc == 0, text
    assert "<IDCOL>\t5\n[2 more identical line(s)]\nend" in text, text


@needs_confine
def test_run_table_counts_idcol_in_the_note(tree):
    user_cfg("[sanitize]\ntable = true\n")
    rc, text = go(tree, ["sample_id\tn"] + [f"{9990001 + i}\t{i}" for i in range(25)])
    assert rc == 0, text
    assert "[placeholders in the lines shown: 25 <IDCOL>]" in text, text
    assert "no identifier placeholder" not in text


@needs_confine
def test_run_without_table_reads_no_columns(tree):
    user_cfg("[sanitize]\ntable = true\n")
    rc, text = go(tree, ["sample_id\tn", "1234567\t5"], table=False)
    assert rc == 0 and "<NUM>\t5" in text and "<IDCOL>" not in text and NO_HEADER not in text


@needs_confine
def test_remote_run_table_reads_columns(tree, monkeypatch):
    user_cfg('[remote]\nhosts = ["hpc-test"]\ncommands = ["wc"]\nroots = ["/data/protected"]\n'
             'use_shared_connection = false\n[sanitize]\ntable = true\n')
    fake = tree / "pub" / "fake-ssh"
    fake.parent.mkdir(exist_ok=True)
    fake.write_text("#!/bin/sh\nprintf 'sample_id\\tn\\n1234567\\t7654321\\n'\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(copying, "system_program", lambda name: str(fake))
    out = io.StringIO()
    code = run.execute(["--remote", "hpc-test", "--table", "--", "wc", "-l", "x"],
                       str(tree / "repo"), dict(os.environ), out)
    text = out.getvalue()
    assert code == 0, text
    assert "<IDCOL>\t7654321" in text.splitlines() and "1234567" not in text, text


def test_copy_never_reads_columns():
    tree = ast.parse((SRC / "phiward" / "copying.py").read_text())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and getattr(n.func, "attr", "") == "run_confined"]
    assert calls
    for c in calls:
        assert len(c.args) <= 6 and not any(k.arg == "table" for k in c.keywords)


def test_run_help_says_what_table_does():
    words = " ".join(run.HELP.split())
    assert "cells under an identifier header are masked whole" in words
    assert "other lines are masked as text" in words
