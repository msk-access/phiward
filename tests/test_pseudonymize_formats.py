"""`phiward pseudonymize`, more kinds of input: the extension chain picks the parser and the
content must agree; plain gzip in and out; `.txt` read as TSV; MAF; the scan of the whole
output (step 1 of the formats plan). VCF, BGZF in and out, the sample-name rule (step 2). JSON,
its key paths and the array rule (step 3). Markdown pipe tables (step 4). Made-up data only (`FAKE-PT-0007`,
`P-9990001-T01-IM6`, MAF barcodes `FAKE-AB-0001-01A`, MRNs from 9990001), in a scratch HOME."""

import csv
import gzip
import io
import json
import os
import shutil
import struct
import subprocess
import zlib

import pytest

from test_pseudonymize import base, key_lines, key_map, mrns, read_table, run, write_table

MAF_IDS = ("P-9990001-T01-IM6", "P-9990001-N01-IM6", "FAKE-AB-0001-01A", "FAKE-AB-0001-10A")


@pytest.fixture()
def ps(tree, monkeypatch):
    """As in test_pseudonymize: the scratch home as the account's home, the backups folder made,
    the working folder in the home, a table of 20 made-up MRNs."""
    from phiward import config, pseudonymize
    home = tree / "home"
    config.make_state_dirs(str(home))
    monkeypatch.setattr(pseudonymize, "_account_home", lambda: str(home))
    monkeypatch.chdir(home)
    write_table(tree / "data" / "labs.tsv", ["mrn", "site", "value"],
                [[m, "lab", str(i)] for i, m in enumerate(mrns(20))])
    return pseudonymize


TABLE = "mrn\tsite\tvalue\n" + "".join(f"{m}\tlab\t{i}\n" for i, m in enumerate(mrns(20)))


def gz(text, name=None, mtime=0):
    """gzip bytes of `text`, with a FNAME header field when `name` is given."""
    buf = io.BytesIO()
    with gzip.GzipFile(filename=name or "", mode="wb", fileobj=buf, mtime=mtime) as f:
        f.write(text.encode() if isinstance(text, str) else text)
    return buf.getvalue()


def put(tree, name, data):
    p = tree / "data" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def none_written(tree, out="out.tsv", name="labs"):
    assert not (tree / "phi" / out).exists()
    assert not (tree / "home" / ".phiward" / "backups" / "keys" / f"{name}.tsv").exists()


def fresh(tree, out="out.tsv", name="labs"):
    for p in (tree / "phi" / out, tree / "home" / ".phiward" / "backups" / "keys" / f"{name}.tsv"):
        if p.exists():
            os.unlink(p)


# --- 1. gzip in, gzip out, no input header field copied (inv. 4) -----------------------------

def test_a_gzip_table_gives_a_gzip_copy_without_the_input_header_fields(tree, ps):
    data = gz(TABLE, name="FAKE-PT-0007.tsv", mtime=1234567)
    assert b"FAKE-PT-0007" in data
    p = put(tree, "labs.tsv.gz", data)
    out = tree / "phi" / "out.tsv.gz"
    code, text = run(tree, base(tree, inp=p, out=out, more=["--keep-order"]),
                     extra=["FAKE-PT-0007"])
    assert code == 0 and "20 row(s)" in text, text
    raw = out.read_bytes()
    assert raw[:3] == b"\x1f\x8b\x08"
    assert raw[3] == 0, "no FNAME, FCOMMENT or FEXTRA"
    assert struct.unpack("<I", raw[4:8])[0] == 0, "mtime 0"
    assert b"FAKE-PT-0007" not in raw
    got = key_map(tree / "home", "labs")
    rows = [ln.split("\t") for ln in gzip.decompress(raw).decode().splitlines()]
    assert rows[0] == ["pseudonym", "site", "value"]
    assert [r[0] for r in rows[1:]] == [got[m] for m in mrns(20)]
    assert os.stat(out).st_mode & 0o777 == 0o600


def test_a_csv_gz_is_taken(tree, ps):
    p = put(tree, "labs.csv.gz", gz(TABLE.replace("\t", ",")))
    assert run(tree, base(tree, inp=p, out=tree / "phi" / "out.csv.gz"))[0] == 0
    rows = list(csv.reader(io.StringIO(gzip.decompress(
        (tree / "phi" / "out.csv.gz").read_bytes()).decode())))
    assert rows[0] == ["pseudonym", "site", "value"] and len(rows) == 21


# --- 2. members, padding, and what is refused (inv. 2, 10) ------------------------------------

def test_two_members_read_as_one_table_and_zero_padding_is_accepted(tree, ps):
    head, rest = TABLE.split("\n", 3)[:3], TABLE.split("\n", 3)[3]
    first = "\n".join(head) + "\n"
    p = put(tree, "labs.tsv.gz", gz(first) + gz(rest) + b"\0" * 512)
    out = tree / "phi" / "out.tsv.gz"
    assert run(tree, base(tree, inp=p, out=out, more=["--keep-order"]))[0] == 0
    rows = gzip.decompress(out.read_bytes()).decode().splitlines()
    assert len(rows) == 21 and [r.split("\t")[2] for r in rows[1:]] == [str(i) for i in range(20)]


def _bad_crc(data):
    b = bytearray(data)
    b[-8] ^= 0xFF
    return bytes(b)


BGZF_EOF = bytes.fromhex("1f8b08040000000000ff0600424302001b0003000000000000000000")


def bgzf(data, size=65280):
    """BGZF blocks of `size` input bytes each, then the EOF block, as bgzip writes them."""
    data = data.encode() if isinstance(data, str) else data
    out = b""
    for i in range(0, len(data), size):
        raw = data[i:i + size]
        c = zlib.compressobj(6, zlib.DEFLATED, -15)
        body = c.compress(raw) + c.flush()
        out += (b"\x1f\x8b\x08\x04" + b"\0" * 4 + b"\0\xff" + struct.pack("<H", 6) + b"BC" +
                struct.pack("<HH", 2, 25 + len(body)) + body +
                struct.pack("<II", zlib.crc32(raw), len(raw)))
    return out + BGZF_EOF


GZ = gz(TABLE)
BROKEN = {
    "trailing": GZ + b"junk",
    "crc": _bad_crc(GZ),
    "truncated": GZ[:-12],
    "gzip_in_gzip": gz(GZ),
}


@pytest.mark.parametrize("case", sorted(BROKEN))
def test_a_broken_gzip_gives_one_fixed_refusal(tree, ps, case):
    p = put(tree, "labs.tsv.gz", BROKEN[case])
    code, text = run(tree, base(tree, inp=p, out=tree / "phi" / "out.tsv.gz"))
    assert code == 2, text
    if case != "gzip_in_gzip":
        assert "cannot be read as a gzip-compressed TSV file" in text, text
    none_written(tree, "out.tsv.gz")


@pytest.mark.parametrize("name,data,out", [
    ("labs.tsv", GZ, "out.tsv"),                      # gzip bytes under a plain name
    ("labs.tsv.gz", TABLE.encode(), "out.tsv.gz"),    # plain text under a .gz name
    ("labs.tsv.gz", GZ, "out.tsv"),                   # OUT of another chain
    ("labs.tsv", TABLE.encode(), "out.tsv.gz"),
    ("labs.tsv.gz", GZ, "out.csv.gz"),
    ("labs.parquet", b"PAR1\0\0PAR1", "out.parquet"),
    ("labs.tsv.gz.gz", gz(GZ), "out.tsv.gz.gz"),
    ("labs.gz", GZ, "out.gz"),
    ("labs.bgz", GZ, "out.bgz"),
    ("labs.tsv.bgz", GZ, "out.tsv.bgz"),
    ("labs.xlsx", TABLE.encode(), "out.xlsx"),
    ("labs.vcf", b"##fileformat=VCFv4.2\n", "out.vcf"),
    ("labs.vcf.gz", gz("##fileformat=VCFv4.2\n"), "out.vcf.gz"),
    ("labs.json", TABLE.encode(), "out.json"),           # a table under a .json name
    ("labs.md", b"##fileformat=VCFv4.2\n", "out.md"),           # a VCF under a .md name
    ("labs.tsv", b"##fileformat=VCFv4.2\nmrn\tsite\n9990001\tlab\n", "out.tsv"),
    ("labs.maf.gz", gz("##fileformat=VCFv4.2\nmrn\tsite\n9990001\tlab\n"), "out.maf.gz"),
])
def test_a_chain_or_content_that_does_not_fit_is_refused(tree, ps, name, data, out):
    p = put(tree, name, data)
    code, text = run(tree, base(tree, inp=p, out=tree / "phi" / out))
    assert code == 2, (name, text)
    none_written(tree, out)


def test_parquet_names_the_way_out(tree, ps):
    p = put(tree, "labs.parquet", b"PAR1\0\0PAR1")
    code, text = run(tree, base(tree, inp=p, out=tree / "phi" / "out.parquet"))
    assert code == 2 and "convert it to TSV" in text, text


def test_the_extension_chain_is_case_blind(tree, ps):
    p = put(tree, "labs.TSV.GZ", GZ)
    assert run(tree, base(tree, inp=p, out=tree / "phi" / "out.tsv.gz"))[0] == 0


# --- 3. a gzip bomb costs at most LIMIT (inv. 3) ----------------------------------------------

def test_a_gzip_that_expands_past_the_limit_is_refused(tree, ps, monkeypatch):
    import tracemalloc
    monkeypatch.setattr(ps, "LIMIT", 8 << 20)
    p = put(tree, "labs.tsv.gz", gz("mrn\tsite\n" + "9990001\tlab\n" * (4 << 20)))
    assert p.stat().st_size < (1 << 20)
    tracemalloc.start()
    try:
        code, text = run(tree, base(tree, inp=p, out=tree / "phi" / "out.tsv.gz"))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert code == 2 and "too large" in text, text
    # what is held: the expanded chunks up to LIMIT and one step more, never the whole 48 MiB
    assert peak < ps.LIMIT + (4 << 20), peak
    none_written(tree, "out.tsv.gz")


# --- 4. what is written is what was scanned (inv. 6) ------------------------------------------

@pytest.mark.parametrize("how", ["short", "other"])
def test_a_compressed_copy_that_does_not_read_back_is_refused(tree, ps, monkeypatch, how):
    real = gzip.compress

    def bad(data, *a, **kw):
        if how == "short":
            return real(data, *a, **kw)[:-1]
        return real(data[:-1], *a, **kw)
    monkeypatch.setattr(ps.gzip, "compress", bad)
    p = put(tree, "labs.tsv.gz", GZ)
    code, text = run(tree, base(tree, inp=p, out=tree / "phi" / "out.tsv.gz"))
    # a cut copy fails the read of the copy; a changed one reads but is not the table
    want = {"short": "the input cannot be read as a gzip-compressed TSV file",
            "other": "the compressed copy does not read back as the table"}[how]
    assert code == 2 and want in text, text
    none_written(tree, "out.tsv.gz")


# --- 5. every exception gives one fixed refusal (inv. 10) -------------------------------------

ERRORS = [RecursionError("deep"), ValueError("FAKE-PT-0007"), EOFError("x"),
          gzip.BadGzipFile("x"), zlib.error("x"), UnicodeDecodeError("utf-8", b"\xff", 0, 1, "x"),
          MemoryError(), csv.Error("x"), OSError("x"), KeyError("FAKE-PT-0007")]


@pytest.mark.parametrize("where", ["_read_table", "_write_table", "_decompress"])
@pytest.mark.parametrize("exc", ERRORS, ids=lambda e: type(e).__name__)
def test_any_exception_in_reading_or_writing_gives_the_one_refusal(tree, ps, monkeypatch,
                                                                     where, exc):
    def boom(*a, **kw):
        raise exc
    monkeypatch.setattr(ps, where, boom)
    p = put(tree, "labs.tsv.gz", GZ)
    code, text = run(tree, base(tree, inp=p, out=tree / "phi" / "out.tsv.gz"),
                     extra=["FAKE-PT-0007", "Traceback", type(exc).__name__])
    assert code == 2, text
    assert text.strip() == ("phiward pseudonymize: the input cannot be read as a "
                            "gzip-compressed TSV file. Nothing was written."), text
    none_written(tree, "out.tsv.gz")


# --- 6. .txt is a TSV with 2 or more columns --------------------------------------------------

def test_a_txt_with_tabs_is_coded_as_a_tsv(tree, ps):
    p = put(tree, "labs.txt", TABLE.encode())
    out = tree / "phi" / "out.txt"
    assert run(tree, base(tree, inp=p, out=out))[0] == 0
    assert read_table(out)[0] == ["pseudonym", "site", "value"]


@pytest.mark.parametrize("data", [b"mrn\n9990001\n9990002\n",
                                  b"mrn notes\n9990001 seen today\n"])
def test_a_one_column_txt_is_free_text_and_refused(tree, ps, data):
    p = put(tree, "labs.txt", data)
    code, text = run(tree, base(tree, inp=p, out=tree / "phi" / "out.txt"))
    assert code == 2 and "free text" in text, text
    none_written(tree, "out.txt")


# --- 7. MAF -----------------------------------------------------------------------------------

MAF_HEAD = ["Hugo_Symbol", "Entrez_Gene_Id", "Chromosome", "Start_Position",
            "Tumor_Sample_Barcode", "Matched_Norm_Sample_Barcode", "Exon_Number", "t_depth"]
MAF_KEEP = ["--keep", "Entrez_Gene_Id,Exon_Number"]
MAF_COLS = "Tumor_Sample_Barcode,Matched_Norm_Sample_Barcode"


def maf_rows():
    return [["TP53", "7157", "17", "7674220", "P-9990001-T01-IM6", "P-9990001-N01-IM6", "5/11",
             "120"],
            ["KRAS", "3845", "12", "25245350", "FAKE-AB-0001-01A", "FAKE-AB-0001-10A", "2/6",
             "88"]]


def write_maf(tree, head=MAF_HEAD, rows=None, pre=("#version 2.4",), post=(), name="x.maf"):
    lines = list(pre) + ["\t".join(head)] + ["\t".join(r) for r in (rows or maf_rows())]
    lines += list(post)
    return put(tree, name, ("\n".join(lines) + "\n").encode())


def maf_run(tree, p, out="out.maf", more=(), cols=MAF_COLS):
    return run(tree, base(tree, key="maf", inp=p, out=tree / "phi" / out, cols=cols,
                          more=MAF_KEEP + ["--keep-order"] + list(more)),
               extra=MAF_IDS + ("/x/", "cmd"))


def test_a_maf_keeps_its_version_line_and_headers_and_codes_both_barcodes(tree, ps):
    p = write_maf(tree, pre=("#version 2.4", "#cmd /x/FAKE-PT-0007 --flag"))
    code, text = maf_run(tree, p)
    assert code == 0 and "2 row(s)" in text, text
    lines = (tree / "phi" / "out.maf").read_text().splitlines()
    assert lines[0] == "#version 2.4"
    assert not any(ln.startswith("#") for ln in lines[1:])
    assert "FAKE-PT-0007" not in "\n".join(lines)
    rows = [ln.split("\t") for ln in lines[1:]]
    assert rows[0] == MAF_HEAD
    got = key_map(tree / "home", "maf")
    assert sorted(got) == sorted(MAF_IDS)
    assert [r[4] for r in rows[1:]] == [got["P-9990001-T01-IM6"], got["FAKE-AB-0001-01A"]]
    assert [r[5] for r in rows[1:]] == [got["P-9990001-N01-IM6"], got["FAKE-AB-0001-10A"]]
    assert [r[3] for r in rows[1:]] == ["7674220", "25245350"]


def test_a_maf_gz_is_coded_and_compressed(tree, ps):
    raw = write_maf(tree).read_bytes()
    p = put(tree, "x.maf.gz", gz(raw))
    assert maf_run(tree, p, out="out.maf.gz")[0] == 0
    text = gzip.decompress((tree / "phi" / "out.maf.gz").read_bytes()).decode()
    assert text.startswith("#version 2.4\nHugo_Symbol\t")


def test_a_maf_with_no_hash_line_is_taken(tree, ps):
    assert maf_run(tree, write_maf(tree, pre=()))[0] == 0
    assert (tree / "phi" / "out.maf").read_text().startswith("Hugo_Symbol\t")


@pytest.mark.parametrize("line", ["#version 2.4 FAKE-PT-0007", "#version: 2.4", "#Version 2.4",
                                  "# version 2.4", "#version 9990001"])
def test_a_maf_hash_line_that_is_not_an_exact_version_is_dropped(tree, ps, line):
    code, text = maf_run(tree, write_maf(tree, pre=(line,)))
    assert code == 0, text
    assert not (tree / "phi" / "out.maf").read_text().startswith("#")


def test_an_unnamed_maf_id_column_is_refused(tree, ps):
    head = MAF_HEAD + ["Tumor_Sample_UUID"]
    rows = [r + ["0b6e5a5e-0000-4000-8000-000000000001"] for r in maf_rows()]
    code, text = maf_run(tree, write_maf(tree, head=head, rows=rows))
    assert code == 2 and "column 9" in text, text
    none_written(tree, "out.maf", "maf")


def test_a_maf_free_text_column_with_an_id_is_refused(tree, ps):
    head = MAF_HEAD + ["BAM_File"]
    rows = [r + ["/x/P-9990001-T01-IM6.bam"] for r in maf_rows()]
    code, text = maf_run(tree, write_maf(tree, head=head, rows=rows))
    assert code == 2 and "column 9" in text, text
    none_written(tree, "out.maf", "maf")


@pytest.mark.parametrize("post", [["#cmd x"], ["#version 2.4"]])
def test_a_hash_line_after_the_maf_header_is_refused(tree, ps, post):
    code, text = maf_run(tree, write_maf(tree, post=post))
    assert code == 2, text
    none_written(tree, "out.maf", "maf")


def test_a_maf_column_renamed_follows_the_tsv_rules(tree, ps):
    code, text = maf_run(tree, write_maf(tree),
                         cols="Tumor_Sample_Barcode=tumor_code,Matched_Norm_Sample_Barcode")
    assert code == 0, text
    head = (tree / "phi" / "out.maf").read_text().splitlines()[1].split("\t")
    assert head[4:6] == ["tumor_code", "Matched_Norm_Sample_Barcode"]


# --- 8. the scan of the whole output (inv. 5) -------------------------------------------------

@pytest.mark.parametrize("ident,cell", [
    ("FAKE-PT-0007", "\\u0046AKE-PT-0007"),
    ("FAKE-PT-0007", "FAKE%2DPT%2D0007"),
    ("A12", "A12"),
])
def test_an_id_in_a_kept_cell_in_any_form_is_refused(tree, ps, ident, cell):
    write_table(tree / "data" / "labs.tsv", ["mrn", "note"], [[ident, cell], ["9990009", "ok"]])
    code, text = run(tree, base(tree), extra=[ident, "note"])
    assert code == 2 and "column 2" in text, (cell, text)
    none_written(tree)


@pytest.mark.parametrize("cell", ["19990001", "199900012", "A123", "xA12", "0.12"])
def test_an_id_only_inside_a_longer_run_or_word_passes(tree, ps, cell):
    write_table(tree / "data" / "labs.tsv", ["mrn", "note"],
                [["9990001", cell], ["A12", "ok"], ["12", "ok"]])
    code, text = run(tree, base(tree))
    assert code == 0, (cell, text)


def test_a_new_header_that_holds_an_id_is_refused(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "patient", "site"],
                [["9990001", "FAKE-PT-0007", "lab"]])
    code, text = run(tree, base(tree, cols="mrn=xFAKE-PT-0007x,patient"), extra=["FAKE-PT-0007"])
    assert code == 2, text
    none_written(tree)


def test_a_kept_header_that_holds_an_id_is_refused(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "note_9990001"], [["9990001", "x"]])
    code, text = run(tree, base(tree), extra=["note_"])
    assert code == 2, text
    none_written(tree)


def test_an_old_code_that_is_an_id_of_this_run_is_refused(tree, ps, monkeypatch):
    """Codes are scanned too: a code of the key that equals an ID in this table would put that
    ID, as a code, in the output."""
    monkeypatch.setattr(ps.secrets, "randbelow", lambda n: n - 1)
    write_table(tree / "data" / "a.tsv", ["mrn", "site"], [["9990001", "lab"]])
    assert run(tree, base(tree, inp=tree / "data" / "a.tsv", out=tree / "phi" / "a.tsv"))[0] == 0
    assert key_map(tree / "home", "labs") == {"9990001": "S9999"}
    write_table(tree / "data" / "b.tsv", ["mrn", "site"], [["9990001", "lab"], ["S9999", "lab"]])
    code, text = run(tree, base(tree, new=False, inp=tree / "data" / "b.tsv"), extra=["S9999"])
    assert code == 2, text
    assert not (tree / "phi" / "out.tsv").exists()


# --- 9. the draw skips a code the scan would flag ---------------------------------------------

def test_the_draw_skips_a_code_that_holds_an_id(tree, ps, monkeypatch):
    monkeypatch.setattr(ps.secrets, "randbelow", lambda n: n - 1)
    write_table(tree / "data" / "labs.tsv", ["mrn", "site"],
                [["X9999", "lab"], ["9990002", "lab"]])
    assert run(tree, base(tree, more=["--prefix", "QX", "--keep-order"]))[0] == 0
    codes = key_map(tree / "home", "labs").values()
    assert "QX9999" not in codes and len(set(codes)) == 2


def test_the_matcher_hits_an_id_in_a_longer_text_but_not_a_longer_run(ps):
    m = ps._Matcher({"X9999", "9999", "S99", "1234567"})
    assert m.hit("QX9999") and m.hit("9999") and m.hit("S99") and m.hit("a/1234567.b")
    assert not m.hit("QX9998") and not m.hit("S991") and not m.hit("11234567")


# --- step 1 keeps the TSV and CSV behaviour ---------------------------------------------------

def test_a_plain_tsv_still_works_and_reports_the_row_count_only(tree, ps):
    code, text = run(tree, base(tree), extra=["mrn", "labs.tsv"])
    assert code == 0 and text.strip().endswith("20 row(s). Read it with `phiward run`."), text


# --- review round 1 ---------------------------------------------------------------------------

def test_a_key_id_that_spans_two_written_fields_is_refused(tree, ps):
    """The scan reads the written lines too: a key ID `Doe, John` split over two CSV fields
    (`Doe`, ` John`) is found in the line as written."""
    write_table(tree / "data" / "names.tsv", ["name", "value"], [["Doe, John", "1"]])
    assert run(tree, base(tree, key="k", inp=tree / "data" / "names.tsv", cols="name",
                          out=tree / "phi" / "names.tsv"), extra=["Doe"])[0] == 0
    p = put(tree, "labs.csv", b'mrn,last,first\n9990001,Doe," John"\n9990002,Roe,Ann\n')
    code, text = run(tree, base(tree, key="k", new=False, inp=p, out=tree / "phi" / "out.csv"),
                     extra=["Doe", "John"])
    assert code == 2, text
    assert not (tree / "phi" / "out.csv").exists()


@pytest.mark.parametrize("ident,cell", [
    ("FAKE-PT-0007", "FAKE％２ＤPT-0007"),      # full-width %2D
    ("FAKE-PT-0007", "FAKE＼u002DPT-0007"),             # full-width backslash, u002D
    ("FAKE-PT-0007", "FAKE%252DPT-0007"),                   # %2D escaped twice
    ("9990002", "٩٩٩٠٠٠٢"),  # Arabic-Indic digits
    ("9990002", "see ٩٩٩٠٠٠٢ again"),
])
def test_an_id_behind_nfkc_escapes_or_other_digits_is_refused(tree, ps, ident, cell):
    write_table(tree / "data" / "labs.tsv", ["mrn", "note"], [[ident, cell], ["9990009", "ok"]])
    code, text = run(tree, base(tree), extra=[ident, "note"])
    assert code == 2 and "column 2" in text, (cell, text)
    none_written(tree)


def _flags(data, bits):
    b = bytearray(data)
    b[3] |= bits
    return bytes(b)


@pytest.mark.parametrize("case", ["bgzf_second", "reserved_first", "reserved_second"])
def test_every_gzip_member_header_is_checked(tree, ps, case):
    first, rest = TABLE.split("\n", 3)[:3], TABLE.split("\n", 3)[3]
    first = "\n".join(first) + "\n"
    data = {"bgzf_second": gz(first) + bgzf(rest),
            "reserved_first": _flags(gz(first), 0x20) + gz(rest),
            "reserved_second": gz(first) + _flags(gz(rest), 0x80)}[case]
    p = put(tree, "labs.tsv.gz", data)
    code, text = run(tree, base(tree, inp=p, out=tree / "phi" / "out.tsv.gz"))
    assert code == 2, text
    none_written(tree, "out.tsv.gz")


# === step 2: VCF, BGZF, the sample rule ======================================================

FIXED = ["#CHROM", "POS", "ID", "REF", "ALT", "QUAL", "FILTER", "INFO", "FORMAT"]
SAMPLES = ["P-9990001-T01-IM6", "P-9990002-T01-IM6", "P-9990003-T01-IM6"]
KEPT_META = ['##INFO=<ID=DP,Number=1,Type=Integer,Description="Total depth">',
             '##FORMAT=<ID=GT,Number=1,Type=String,Description="Genotype">',
             '##FORMAT=<ID=AD,Number=R,Type=Integer,Description="Allelic depths">',
             '##FILTER=<ID=q10,Description="Quality below 10">',
             '##ALT=<ID=DEL,Description="Deletion">']
META = (["##fileformat=VCFv4.2", "##fileDate=20261119", "##source=FAKEcaller",
         "##reference=file:///x/FAKE-PT-0007.fa"] + KEPT_META +
        ['##contig=<ID=chr1,length=248956422,assembly="FAKE build, 1">',
         '##contig=<ID=chr2,length=242193529>',
         '##SAMPLE=<ID=P-9990001-T01-IM6,Description="FAKE-PT-0007 tumor">',
         '##PEDIGREE=<Child=P-9990002-T01-IM6>',
         '##commandline="caller --in /x/FAKE-PT-0007.bam"',
         "##bcftools_viewCommand=view /x/FAKE-PT-0007.vcf",
         "##other=FAKE-PT-0007"])
VCF_IDS = tuple(SAMPLES) + ("FAKE-PT-0007", "/x/", "commandline", "TUMOR", "normal")


def records(n_samples, n=4, chrom="chr1"):
    """Records sorted by position; sample j's AD holds (j + 1) * 10, so its column can be
    followed."""
    return [[chrom, str(10000 + 7 * i), ".", "A", "G", "50", "PASS", f"DP={30 + i}", "GT:AD"] +
            [f"0/1:{(j + 1) * 10},{i}" for j in range(n_samples)] for i in range(n)]


def vcf_text(samples=SAMPLES, recs=None, meta=META, fixed=FIXED):
    recs = records(len(samples)) if recs is None else recs
    lines = list(meta) + ["\t".join(list(fixed) + list(samples))] + ["\t".join(r) for r in recs]
    return "\n".join(lines) + "\n"


def vcf_run(tree, p, out="out.vcf", more=("--keep-order",), key="vcf", new=True, extra=()):
    args = ["--new-key" if new else "--key", key, *more, p, tree / "phi" / out]
    return run(tree, args, extra=VCF_IDS + tuple(extra))


def vcf_lines(path):
    raw = path.read_bytes()
    text = gzip.decompress(raw).decode() if raw[:2] == b"\x1f\x8b" else raw.decode()
    return text.split("\n")[:-1]


# --- 11. a VCF: the samples coded, the ## lines from an allow list, records in order ----------

def test_a_vcf_codes_its_samples_and_keeps_only_the_allowed_meta_lines(tree, ps):
    p = put(tree, "calls.vcf", vcf_text().encode())
    code, text = vcf_run(tree, p)
    assert code == 0 and "4 record(s)" in text, text
    lines = vcf_lines(tree / "phi" / "out.vcf")
    assert lines[0] == "##fileformat=VCFv4.2"
    assert lines[1:7] == KEPT_META + ["##contig=<ID=chr1>"]
    assert lines[7] == "##contig=<ID=chr2>"
    got = key_map(tree / "home", "vcf")
    assert sorted(got) == sorted(SAMPLES)
    assert lines[8].split("\t") == FIXED + [got[s] for s in SAMPLES]
    assert [ln.split("\t") for ln in lines[9:]] == records(3)
    out = "\n".join(lines)
    for s in VCF_IDS[:4] + ("source", "fileDate", "reference", "248956422", "PEDIGREE", "other"):
        assert s not in out, s
    assert os.stat(tree / "phi" / "out.vcf").st_mode & 0o777 == 0o600


def test_a_vcf_gz_in_plain_gzip_gives_plain_gzip(tree, ps):
    p = put(tree, "calls.vcf.gz", gz(vcf_text()))
    assert vcf_run(tree, p, out="out.vcf.gz")[0] == 0
    raw = (tree / "phi" / "out.vcf.gz").read_bytes()
    assert raw[3] == 0  # no FEXTRA: plain gzip for plain gzip
    assert vcf_lines(tree / "phi" / "out.vcf.gz")[0] == "##fileformat=VCFv4.2"


def test_a_known_sample_keeps_its_code_in_the_next_vcf(tree, ps):
    assert vcf_run(tree, put(tree, "a.vcf", vcf_text().encode()), out="a.vcf")[0] == 0
    first = key_map(tree / "home", "vcf")
    samples = [SAMPLES[1], "P-9990004-T01-IM6"]
    p = put(tree, "b.vcf", vcf_text(samples=samples).encode())
    assert vcf_run(tree, p, out="b.vcf", new=False, extra=("P-9990004-T01-IM6",))[0] == 0
    got = key_map(tree / "home", "vcf")
    assert got[SAMPLES[1]] == first[SAMPLES[1]] and len(got) == 4
    assert vcf_lines(tree / "phi" / "b.vcf")[8].split("\t")[9:] == [got[s] for s in samples]


@pytest.mark.parametrize("bad", [
    {"meta": ["##fileformat=VCFv4.2x"] + META[1:]},           # the first line
    {"meta": META[1:]},                                        # no fileformat line
    {"meta": ["##fileformat=VCFv4.2", "#a comment"] + META[1:]},  # a # line that is not ##
    {"meta": META + ["##contig=<length=5>"]},                  # a contig without an ID
    {"meta": META + ['##contig=<ID="chr3>']},                  # a broken quote
    {"meta": META + ["##INFO"]},                               # no `=`
    {"fixed": FIXED[:8]},                                      # no FORMAT
    {"fixed": ["#CHROM", "POS", "ID", "REF", "ALT", "QUAL", "FILTER", "INF", "FORMAT"]},
    {"samples": []},                                           # no sample
    {"samples": [SAMPLES[0], SAMPLES[0]]},                     # a sample twice
    {"samples": [SAMPLES[0], " "]},                            # an empty name
    {"samples": [SAMPLES[0], "P-9990002\u200b-T01"]},          # an invisible character
    {"recs": records(3)[:1] + [records(3)[1][:-1]]},           # a record of another width
    {"recs": records(3)[:1] + [["#x"] + records(3)[1][1:]]},   # a # line after the header
    {"recs": records(3)[:1] + [[""]]},                         # an empty line
])
def test_a_vcf_that_does_not_fit_is_refused(tree, ps, bad):
    p = put(tree, "calls.vcf", vcf_text(**bad).encode())
    code, text = vcf_run(tree, p)
    assert code == 2, (bad, text)
    none_written(tree, "out.vcf", "vcf")


def test_a_vcf_with_crlf_line_ends_is_refused(tree, ps):
    p = put(tree, "calls.vcf", vcf_text().replace("\n", "\r\n").encode())
    assert vcf_run(tree, p)[0] == 2
    none_written(tree, "out.vcf", "vcf")


def test_vcf_content_under_another_name_and_other_content_as_vcf_are_refused(tree, ps):
    p = put(tree, "calls.tsv", vcf_text().encode())
    assert run(tree, base(tree, inp=p))[0] == 2
    p = put(tree, "labs.vcf", TABLE.encode())
    assert vcf_run(tree, p)[0] == 2
    none_written(tree, "out.vcf", "vcf")


# --- 12. the sample columns are shuffled, one permutation for every line ----------------------

def test_the_sample_columns_are_shuffled_the_same_in_every_record(tree, ps, monkeypatch):
    monkeypatch.setattr(ps, "_shuffle", lambda xs: xs.reverse())
    p = put(tree, "calls.vcf", vcf_text().encode())
    assert vcf_run(tree, p, more=())[0] == 0
    lines = vcf_lines(tree / "phi" / "out.vcf")
    got = key_map(tree / "home", "vcf")
    assert lines[8].split("\t")[9:] == [got[s] for s in reversed(SAMPLES)]
    for i, ln in enumerate(lines[9:]):
        assert ln.split("\t") == records(3)[i][:9] + [f"0/1:{k * 10},{i}" for k in (3, 2, 1)]


def test_keep_order_keeps_the_sample_columns(tree, ps, monkeypatch):
    monkeypatch.setattr(ps, "_shuffle", lambda xs: xs.reverse())
    assert vcf_run(tree, put(tree, "calls.vcf", vcf_text().encode()))[0] == 0
    got = key_map(tree / "home", "vcf")
    assert vcf_lines(tree / "phi" / "out.vcf")[8].split("\t")[9:] == [got[s] for s in SAMPLES]


def test_the_real_shuffle_moves_the_sample_columns(tree, ps):
    samples = [f"P-{9990001 + i}-T01-IM6" for i in range(12)]
    p = put(tree, "calls.vcf", vcf_text(samples=samples).encode())
    assert vcf_run(tree, p, more=(), extra=tuple(samples))[0] == 0
    got = key_map(tree / "home", "vcf")
    head = vcf_lines(tree / "phi" / "out.vcf")[8].split("\t")[9:]
    assert sorted(head) == sorted(got.values()) and head != [got[s] for s in samples]


# --- 13. sample names that are words never enter a key (inv. 8) -------------------------------

@pytest.mark.parametrize("name", ["TUMOR", "normal", "S1", "Sample", "sample1", "NA", "none",
                                  "Germline", "blood", "x7"])
def test_a_sample_name_that_is_a_word_is_refused(tree, ps, name):
    samples = [SAMPLES[0], name, SAMPLES[2]]
    p = put(tree, "calls.vcf", vcf_text(samples=samples).encode())
    code, text = vcf_run(tree, p, extra=(name,))
    assert code == 2 and "sample 2" in text and "--keep-samples" in text, text
    none_written(tree, "out.vcf", "vcf")


def test_keep_samples_keeps_a_word_name_out_of_the_key(tree, ps):
    samples = [SAMPLES[0], "TUMOR", "normal"]
    p = put(tree, "calls.vcf", vcf_text(samples=samples).encode())
    code, text = vcf_run(tree, p, more=("--keep-order", "--keep-samples", "2,3"))
    assert code == 0, text
    got = key_map(tree / "home", "vcf")
    assert list(got) == [SAMPLES[0]]
    assert vcf_lines(tree / "phi" / "out.vcf")[8].split("\t")[9:] == \
        [got[SAMPLES[0]], "TUMOR", "normal"]


@pytest.mark.parametrize("value", ["0", "4", "1,1", "a", "", "2,", "-1"])
def test_keep_samples_must_name_samples_by_number(tree, ps, value):
    p = put(tree, "calls.vcf", vcf_text().encode())
    code, text = vcf_run(tree, p, more=("--keep-samples", value))
    assert code == 2, text
    none_written(tree, "out.vcf", "vcf")


def test_keep_samples_goes_with_a_vcf_only(tree, ps):
    code, text = run(tree, base(tree, more=["--keep-samples", "1"]))
    assert code == 2 and "VCF" in text, text
    none_written(tree)


# --- 14. an ID left in a record or a kept ## line; the column options -------------------------

def _with(rec_i, col, value):
    recs = records(3)
    recs[rec_i][col] = value
    return recs


@pytest.mark.parametrize("recs,meta", [
    (_with(1, 7, "DP=31;TUMOR=P-9990001-T01-IM6"), META),          # an INFO value
    (_with(2, 2, "P-9990002-T01-IM6"), META),                       # the ID column
    (_with(0, 6, "q10;P-9990003-T01-IM6"), META),                   # FILTER
    (_with(3, 10, "0/1:P-9990001-T01-IM6"), META),                  # a sample value
    (None, META + ['##INFO=<ID=XS,Number=0,Type=Flag,Description="in P-9990002-T01-IM6">']),
    (None, META + ['##contig=<ID=P-9990001-T01-IM6>']),
])
def test_a_sample_name_left_in_a_record_or_a_kept_line_is_refused(tree, ps, recs, meta):
    p = put(tree, "calls.vcf", vcf_text(recs=recs, meta=meta).encode())
    code, text = vcf_run(tree, p)
    assert code == 2, text
    none_written(tree, "out.vcf", "vcf")


@pytest.mark.parametrize("meta", [
    META + ['##INFO=<ID=XS,Number=0,Type=Flag,Description="seen in ab12c only">'],
    META + ['##contig=<ID=AB12C>'],
])
def test_a_kept_meta_line_that_names_a_sample_is_refused_by_the_scan(tree, ps, meta):
    """A sample name the sanitizer leaves alone (`AB12C`) in a kept line: the scan finds it."""
    samples = [SAMPLES[0], "AB12C"]
    p = put(tree, "calls.vcf", vcf_text(samples=samples, recs=records(2), meta=meta).encode())
    code, text = vcf_run(tree, p, extra=("AB12C", "ab12c"))
    assert code == 2 and "holds an ID of a sample" in text, text
    none_written(tree, "out.vcf", "vcf")


def test_an_id_with_a_colon_split_across_format_values_is_refused(tree, ps):
    samples = [SAMPLES[0], "FK:9990005"]
    recs = records(2)
    recs[1][8], recs[1][10] = "GT:AD:XX", "0/1:FK:9990005"
    p = put(tree, "calls.vcf", vcf_text(samples=samples, recs=recs).encode())
    code, text = vcf_run(tree, p, extra=("FK:9990005",))
    assert code == 2, text
    none_written(tree, "out.vcf", "vcf")


def test_a_key_id_in_a_vcf_record_is_refused(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "site"], [["9990009", "lab"]])
    assert run(tree, base(tree, key="vcf"))[0] == 0
    p = put(tree, "calls.vcf", vcf_text(recs=_with(1, 7, "DP=31;M=9990009")).encode())
    code, text = vcf_run(tree, p, new=False, extra=("9990009",))
    assert code == 2, text
    assert not (tree / "phi" / "out.vcf").exists()


def test_a_position_that_holds_a_key_id_inside_a_longer_run_passes(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "site"], [["9990009", "lab"]])
    assert run(tree, base(tree, key="vcf"))[0] == 0
    p = put(tree, "calls.vcf", vcf_text(recs=_with(1, 1, "19990009")).encode())
    code, text = vcf_run(tree, p, new=False, extra=("9990009",))
    assert code == 0, text


@pytest.mark.parametrize("opt", [["--columns", "FORMAT"], ["--drop", "INFO"],
                                 ["--keep", "ID"]])
def test_the_column_options_are_refused_with_a_vcf(tree, ps, opt):
    p = put(tree, "calls.vcf", vcf_text().encode())
    code, text = vcf_run(tree, p, more=opt)
    assert code == 2 and "VCF" in text, text
    none_written(tree, "out.vcf", "vcf")


def test_a_kept_meta_line_the_sanitizer_masks_is_refused(tree, ps):
    meta = META + ['##INFO=<ID=XM,Number=1,Type=String,Description="see /x/FAKE-PT-0001.bam">']
    p = put(tree, "calls.vcf", vcf_text(meta=meta).encode())
    code, text = vcf_run(tree, p, extra=("FAKE-PT-0001",))
    assert code == 2 and "##" in text, text
    none_written(tree, "out.vcf", "vcf")


# --- 15. BGZF in gives BGZF out (inv. 6) ------------------------------------------------------

def bgzf_blocks(raw):
    """The blocks of a BGZF file, each checked against the SAM spec (section 4.1): the header
    with FEXTRA, XLEN 6, the subfield BC with SLEN 2, BSIZE (the block size - 1) that chains to
    the next block, at most 64 KiB a block, ISIZE and CRC32 of its data; the last block is the
    28-byte EOF block."""
    pos, blocks = 0, []
    while pos < len(raw):
        assert raw[pos:pos + 4] == b"\x1f\x8b\x08\x04", pos
        mtime, _, _, xlen = struct.unpack("<IBBH", raw[pos + 4:pos + 12])
        assert mtime == 0 and xlen == 6
        si1, si2, slen, bsize = struct.unpack("<BBHH", raw[pos + 12:pos + 18])
        assert (si1, si2, slen) == (66, 67, 2)
        block = raw[pos:pos + bsize + 1]
        assert len(block) == bsize + 1 <= 65536
        data = zlib.decompress(block[18:-8], -15)
        crc, isize = struct.unpack("<II", block[-8:])
        assert crc == zlib.crc32(data) and isize == len(data) <= 65536
        blocks.append((block, data))
        pos += bsize + 1
    assert pos == len(raw) and blocks[-1][0] == BGZF_EOF
    return blocks


def big_vcf():
    recs = records(3, n=4000)
    return vcf_text(recs=recs)


def test_a_bgzf_vcf_gives_a_bgzf_vcf(tree, ps):
    text = big_vcf()
    assert len(text) > 3 * 65280
    p = put(tree, "calls.vcf.gz", bgzf(text, size=40000))
    code, msg = vcf_run(tree, p, out="out.vcf.gz")
    assert code == 0 and "4000 record(s)" in msg, msg
    raw = (tree / "phi" / "out.vcf.gz").read_bytes()
    blocks = bgzf_blocks(raw)
    assert len(blocks) >= 3 and all(len(d) == 65280 for _, d in blocks[:-2])
    out = gzip.decompress(raw).decode()
    assert b"".join(d for _, d in blocks).decode() == out
    assert out.startswith("##fileformat=VCFv4.2\n") and out.count("\n") == 4000 + 9


def test_a_bgzf_tsv_gives_a_bgzf_tsv(tree, ps):
    """Was: BGZF was refused (step 1, `test_a_chain_or_content_that_does_not_fit_is_refused`);
    BGZF in now gives BGZF out for every kind."""
    p = put(tree, "labs.tsv.gz", bgzf(TABLE))
    assert run(tree, base(tree, inp=p, out=tree / "phi" / "out.tsv.gz"))[0] == 0
    raw = (tree / "phi" / "out.tsv.gz").read_bytes()
    assert len(bgzf_blocks(raw)) == 2
    assert gzip.decompress(raw).decode().startswith("pseudonym\tsite\tvalue\n")


def _extra(data, sub):
    """A one-member gzip whose FEXTRA field is `sub`."""
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    body = c.compress(data) + c.flush()
    return (b"\x1f\x8b\x08\x04" + b"\0" * 4 + b"\0\xff" + struct.pack("<H", len(sub)) + sub +
            body + struct.pack("<II", zlib.crc32(data), len(data)))


def _bsize(data, delta):
    b = bytearray(bgzf(data))
    b[16:18] = struct.pack("<H", struct.unpack("<H", b[16:18])[0] + delta)
    return bytes(b)


@pytest.mark.parametrize("case", ["bgzf_then_gzip", "gzip_then_bgzf", "other_extra",
                                  "bsize_short", "bsize_long", "bc_slen"])
def test_a_bgzf_that_does_not_fit_is_refused(tree, ps, case):
    text = vcf_text()
    half = text.index("#CHROM")
    data = {"bgzf_then_gzip": bgzf(text[:half])[:-28] + gz(text[half:]),
            "gzip_then_bgzf": gz(text[:half]) + bgzf(text[half:]),
            "other_extra": _extra(text.encode(), b"XY\x02\x00ab"),
            "bsize_short": _bsize(text, -1),
            "bsize_long": _bsize(text, 1),
            "bc_slen": _extra(text.encode(), b"BC\x04\x00abcd")}[case]
    p = put(tree, "calls.vcf.gz", data)
    code, text = vcf_run(tree, p, out="out.vcf.gz")
    assert code == 2, (case, text)
    none_written(tree, "out.vcf.gz", "vcf")


def test_a_bgzf_copy_that_does_not_read_back_is_refused(tree, ps, monkeypatch):
    real = ps._bgzf

    def bad(data):
        return real(data[:-1])
    monkeypatch.setattr(ps, "_bgzf", bad)
    p = put(tree, "calls.vcf.gz", bgzf(vcf_text()))
    code, text = vcf_run(tree, p, out="out.vcf.gz")
    assert code == 2 and "the compressed copy does not read back as the table" in text, text
    none_written(tree, "out.vcf.gz", "vcf")


@pytest.mark.skipif(not shutil.which("tabix"), reason="tabix is not on PATH (htslib)")
def test_tabix_indexes_the_bgzf_copy(tree, ps):
    text = vcf_text(recs=records(3, n=3000) + records(3, n=3000, chrom="chr2"))
    p = put(tree, "calls.vcf.gz", bgzf(text))
    assert vcf_run(tree, p, out="out.vcf.gz")[0] == 0
    out = tree / "phi" / "out.vcf.gz"
    r = subprocess.run(["tabix", "-p", "vcf", str(out)], capture_output=True, text=True,
                       timeout=60, check=False)
    assert r.returncode == 0, r.stderr
    r = subprocess.run(["tabix", str(out), "chr2:10000-10010"], capture_output=True, text=True,
                       timeout=60, check=False)
    assert r.returncode == 0 and len(r.stdout.splitlines()) == 2, (r.stdout, r.stderr)


# --- step 2, review round 1 -------------------------------------------------------------------

def _cut_last_block(raw):
    """The BGZF file without its EOF block and its last data block."""
    blocks = bgzf_blocks(raw)
    return raw[:len(raw) - len(blocks[-1][0]) - len(blocks[-2][0])]


@pytest.mark.parametrize("cut", ["no_eof", "last_block_and_eof", "eof_short"])
def test_a_truncated_bgzf_is_refused(tree, ps, cut):
    """A BGZF input must end with the EOF block: one cut at a block boundary reads as a shorter
    file."""
    raw = bgzf(big_vcf(), size=40000)
    data = {"no_eof": raw[:-28], "last_block_and_eof": _cut_last_block(raw),
            "eof_short": raw[:-1]}[cut]
    p = put(tree, "calls.vcf.gz", data)
    code, text = vcf_run(tree, p, out="out.vcf.gz")
    assert code == 2 and "cannot be read as a gzip-compressed VCF file" in text, (cut, text)
    none_written(tree, "out.vcf.gz", "vcf")


@pytest.mark.parametrize("name", ["\uff53\uff41\uff4d\uff50\uff4c\uff451",  # full-width sample, 1
                                  "\uff33\uff21\uff2d\uff30\uff2c\uff25\uff11"])
def test_the_stop_list_is_checked_on_the_normalized_name(tree, ps, name):
    samples = [SAMPLES[0], name]
    p = put(tree, "calls.vcf", vcf_text(samples=samples, recs=records(2)).encode())
    code, text = vcf_run(tree, p, extra=(name,))
    assert code == 2 and "sample 2" in text, text
    none_written(tree, "out.vcf", "vcf")


TWINS = [("P-9990001-T01-IM6", "p-9990001-t01-im6"),
         ("P-9990001-T01-IM6", "Ｐ-9990001-T01-IM6"),  # a full-width P
         ("FAKE-PT-0007", "fake-pt-0007")]


@pytest.mark.parametrize("a,b", TWINS)
def test_two_ids_that_differ_only_in_case_or_form_are_refused_in_one_table(tree, ps, a, b):
    write_table(tree / "data" / "labs.tsv", ["mrn", "site"], [[a, "lab"], [b, "lab"]])
    code, text = run(tree, base(tree), extra=(a, b))
    assert code == 2 and "differ only" in text, text
    none_written(tree)


@pytest.mark.parametrize("a,b", TWINS)
def test_an_id_that_differs_from_a_key_id_only_in_case_or_form_is_refused(tree, ps, a, b):
    write_table(tree / "data" / "a.tsv", ["mrn", "site"], [[a, "lab"]])
    assert run(tree, base(tree, inp=tree / "data" / "a.tsv", out=tree / "phi" / "a.tsv"),
               extra=(a,))[0] == 0
    before = key_lines(tree / "home", "labs")
    write_table(tree / "data" / "b.tsv", ["mrn", "site"], [[b, "lab"]])
    code, text = run(tree, base(tree, new=False, inp=tree / "data" / "b.tsv"), extra=(a, b))
    assert code == 2 and "differ only" in text, text
    assert key_lines(tree / "home", "labs") == before
    assert not (tree / "phi" / "out.tsv").exists()


def test_two_vcf_samples_that_differ_only_in_case_are_refused(tree, ps):
    samples = [SAMPLES[0], SAMPLES[0].lower()]
    p = put(tree, "calls.vcf", vcf_text(samples=samples, recs=records(2)).encode())
    code, text = vcf_run(tree, p, extra=(samples[1],))
    assert code == 2 and "differ only" in text, text
    none_written(tree, "out.vcf", "vcf")


def test_the_vcf_draw_avoids_a_value_inside_a_field(tree, ps, monkeypatch):
    """`X=S9999` in INFO: the code S9999 would stand beside an unrelated value."""
    monkeypatch.setattr(ps.secrets, "randbelow", lambda n: n - 1)
    p = put(tree, "calls.vcf", vcf_text(recs=_with(1, 7, "DP=31;X=S9999")).encode())
    assert vcf_run(tree, p)[0] == 0
    assert "S9999" not in key_map(tree / "home", "vcf").values()


# === step 3: JSON =============================================================================

JSON_COLS = "samples[].id,samples[].mrn"
JSON_IDS = ("FAKE-PT-0001", "FAKE-PT-0002", "FAKE-PT-0003", "FAKE-PT-0004", "9990002",
            "samples", "[]", ".id", ".mrn", "patient_id", "Traceback", "Error")
FIXED_JSON = "phiward pseudonymize: the input cannot be read as a JSON file. Nothing was written."


def jdoc(n=4, **more):
    """A study of `n` made-up samples: an ID string, an MRN integer (the third one null), a
    value that follows its sample."""
    doc = {"study": "lab",
           "samples": [{"id": f"FAKE-PT-{i:04d}", "mrn": None if i == 3 else 9990000 + i,
                        "assay": "panel", "value": i} for i in range(1, n + 1)]}
    doc.update(more)
    return doc


def jput(tree, doc, name="doc.json"):
    data = doc if isinstance(doc, bytes) else (doc if isinstance(doc, str) else
                                               json.dumps(doc)).encode()
    return put(tree, name, data)


def jrun(tree, p, cols=JSON_COLS, out="out.json", more=(), new=True,
         extra=()):
    args = ["--new-key" if new else "--key", "js", "--columns", cols, *more, p, tree / "phi" / out]
    code, text = run(tree, args, extra=JSON_IDS + tuple(extra))
    assert "not covered" not in text, text  # a refusal of the JSON rules, not of the kind
    return code, text


def jread(path):
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw)


# --- 16. the IDs at the key paths coded, null kept, the array of objects shuffled -------------

def test_json_codes_the_values_at_the_paths_keeps_null_and_shuffles_the_objects(tree, ps,
                                                                                  monkeypatch):
    monkeypatch.setattr(ps, "_shuffle", lambda xs: xs.reverse())
    p = jput(tree, jdoc())
    code, text = jrun(tree, p)
    assert code == 0, text
    assert text.strip() == ("phiward pseudonymize: wrote the coded JSON file. Read it with "
                            "`phiward run`."), text
    got = key_map(tree / "home", "js")
    assert sorted(got) == sorted([f"FAKE-PT-{i:04d}" for i in (1, 2, 3, 4)] +
                                 ["9990001", "9990002", "9990004"])
    want = {"study": "lab", "samples": [
        {"id": got[f"FAKE-PT-{i:04d}"], "mrn": None if i == 3 else got[str(9990000 + i)],
         "assay": "panel", "value": i} for i in (4, 3, 2, 1)]}
    out = tree / "phi" / "out.json"
    assert out.read_text() == json.dumps(want, ensure_ascii=False, indent=2) + "\n"
    assert os.stat(out).st_mode & 0o777 == 0o600


def test_json_keep_order_keeps_the_array(tree, ps, monkeypatch):
    monkeypatch.setattr(ps, "_shuffle", lambda xs: xs.reverse())
    assert jrun(tree, jput(tree, jdoc()), more=("--keep-order",))[0] == 0
    assert [s["value"] for s in jread(tree / "phi" / "out.json")["samples"]] == [1, 2, 3, 4]


def test_json_the_real_shuffle_moves_the_objects_and_keeps_each_whole(tree, ps):
    assert jrun(tree, jput(tree, jdoc(30)))[0] == 0
    got = key_map(tree / "home", "js")
    samples = jread(tree / "phi" / "out.json")["samples"]
    assert [s["value"] for s in samples] != list(range(1, 31))
    for s in samples:
        assert s["id"] == got[f"FAKE-PT-{s['value']:04d}"]


def test_json_an_integer_id_gets_the_code_of_the_same_id_in_a_table(tree, ps):
    write_table(tree / "data" / "a.tsv", ["mrn", "site"], [["9990001", "lab"]])
    args = ["--new-key", "js", "--columns", "mrn", tree / "data" / "a.tsv", tree / "phi" / "a.tsv"]
    assert run(tree, args)[0] == 0
    first = key_map(tree / "home", "js")["9990001"]
    p = jput(tree, {"patient": {"mrn": 9990001}})
    assert jrun(tree, p, cols="patient.mrn", new=False)[0] == 0
    assert jread(tree / "phi" / "out.json") == {"patient": {"mrn": first}}


def test_json_a_top_level_array_is_named_with_brackets(tree, ps, monkeypatch):
    monkeypatch.setattr(ps, "_shuffle", lambda xs: xs.reverse())
    p = jput(tree, [{"mrn": 9990001, "v": 1}, {"mrn": 9990002, "v": 2}])
    assert jrun(tree, p, cols="[].mrn", more=())[0] == 0
    got = key_map(tree / "home", "js")
    assert jread(tree / "phi" / "out.json") == [{"mrn": got["9990002"], "v": 2},
                                                 {"mrn": got["9990001"], "v": 1}]


def test_json_drop_removes_a_key_and_keep_keeps_one(tree, ps):
    p = jput(tree, jdoc(patient_id="FAKE-PT-0009", visit_no="v1"))
    code, text = jrun(tree, p, more=("--keep", "visit_no", "--drop", "patient_id"),
                      extra=("FAKE-PT-0009",))
    assert code == 0, text
    doc = jread(tree / "phi" / "out.json")
    assert "patient_id" not in doc and doc["visit_no"] == "v1"
    assert "FAKE-PT-0009" not in (tree / "phi" / "out.json").read_text()


def test_json_a_key_is_named_by_its_number_in_the_input(tree, ps):
    """Counted in IN, dropped keys too (OUT is never written on a refusal)."""
    doc = {"study": "lab", "extra": {"a": 1, "b": 2}}
    doc.update(jdoc(), patient_id="x")
    code, text = jrun(tree, jput(tree, doc), more=("--drop", "extra"),
                      extra=("extra",))
    assert code == 2 and "key 22 (in the order of the file) looks like" in text, text


def test_json_gz_and_bgzf_give_the_same_compression(tree, ps):
    p = jput(tree, gz(json.dumps(jdoc())), name="doc.json.gz")
    assert jrun(tree, p, out="out.json.gz")[0] == 0
    raw = (tree / "phi" / "out.json.gz").read_bytes()
    assert raw[3] == 0 and len(jread(tree / "phi" / "out.json.gz")["samples"]) == 4
    fresh(tree, "out.json.gz", "js")
    p = jput(tree, bgzf(json.dumps(jdoc())), name="doc2.json.gz")
    assert jrun(tree, p, out="out2.json.gz")[0] == 0
    raw = (tree / "phi" / "out2.json.gz").read_bytes()
    assert raw[3] == 4 and raw.endswith(BGZF_EOF)


def test_json_keeps_text_that_is_not_ascii_as_it_is(tree, ps):
    assert jrun(tree, jput(tree, jdoc(study="Zürich")))[0] == 0
    assert '"study": "Zürich"' in (tree / "phi" / "out.json").read_text(encoding="utf-8")


# --- 17. a path that ends in [] codes scalars whose order may follow the IDs ------------------

def test_json_a_path_on_an_array_of_strings_needs_keep_order(tree, ps):
    p = jput(tree, {"ids": ["FAKE-PT-0001", "FAKE-PT-0002"]})
    code, text = jrun(tree, p, cols="ids[]", more=(), extra=("ids",))
    assert code == 2 and "--keep-order" in text, text
    none_written(tree, "out.json", "js")
    assert jrun(tree, p, cols="ids[]", more=("--keep-order",))[0] == 0
    got = key_map(tree / "home", "js")
    assert jread(tree / "phi" / "out.json") == {"ids": [got["FAKE-PT-0001"], got["FAKE-PT-0002"]]}


# --- 18. what is refused ----------------------------------------------------------------------

def _deep(n):
    return "[" * n + "]" * n


def _text_with(extra):
    """The study as JSON text, with `extra` (raw JSON text) as its last member."""
    return json.dumps(jdoc())[:-1] + ", " + extra + "}"


FIXED_CASES = {
    "duplicate_key": _text_with('"study": "lab2"'),
    "nan": _text_with('"x": NaN'),
    "infinity": _text_with('"x": Infinity'),
    "minus_infinity": _text_with('"x": -Infinity'),
    "float_overflow": _text_with('"x": 1e400'),
    "deep_past_the_limit": _text_with('"x": ' + _deep(150)),
    "deep_past_the_recursion_limit": _text_with('"x": ' + _deep(100000)),
    "huge_integer": _text_with('"x": ' + "7" * 5000),
    "not_json": "mrn\tsite\n9990001\tlab\n",
    "two_documents": json.dumps(jdoc()) + "\n" + json.dumps(jdoc()),
    "lone_surrogate": _text_with('"x": "\\ud800"'),
}


@pytest.mark.parametrize("case", sorted(FIXED_CASES))
def test_json_that_cannot_be_read_gives_the_one_fixed_refusal(tree, ps, case):
    p = jput(tree, FIXED_CASES[case])
    code, text = jrun(tree, p, extra=("RecursionError", "ValueError", "lab2"))
    assert code == 2 and text.strip() == FIXED_JSON, text
    none_written(tree, "out.json", "js")


def _set_mrn(value):
    doc = jdoc()
    doc["samples"][1]["mrn"] = value
    return doc


REFUSED = {
    "key_is_an_id": jdoc(notes={"FAKE-PT-0002": "seen"}),
    "key_is_a_key_id_inside": jdoc(notes={"x-FAKE-PT-0001-y": "seen"}),
    "key_the_sanitizer_masks": jdoc(notes={"P-9990001-T01-IM6": 1}),
    "key_is_a_coded_mrn": jdoc(notes={"9990002": "seen"}),
    "key_holds_a_coded_mrn": jdoc(notes={"x/9990002.bam": "seen"}),
    "unnamed_patient_id": jdoc(patient_id="x"),
    "unnamed_id_deep_inside": jdoc(meta={"runs": [{"specimen": "x"}]}),
    "bool_at_a_coded_path": _set_mrn(True),
    "float_at_a_coded_path": _set_mrn(9990002.0),
    "object_at_a_coded_path": _set_mrn({"v": "9990002"}),
    "array_at_a_coded_path": _set_mrn(["9990002"]),
    "id_in_a_kept_value": jdoc(note="FAKE-PT-0002"),
    "id_inside_a_kept_value": jdoc(note="see FAKE-PT-0002 again"),
    "mrn_as_a_kept_number": jdoc(count=9990002),
    "mrn_inside_a_kept_string": jdoc(note="x/9990002.bam"),
    "id_in_a_kept_array": jdoc(more=["a", ["FAKE-PT-0001"]]),
    "invisible_character_in_a_key": jdoc(notes={"a​b": 1}),
    "invisible_character_in_a_value": jdoc(note="a​b"),
    "tab_in_a_coded_value": jdoc(samples=[{"id": "FAKE-PT-0001\tx", "mrn": None}]),
}


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_json_refuses(tree, ps, case):
    p = jput(tree, REFUSED[case])
    code, text = jrun(tree, p, extra=("P-9990001-T01-IM6", "notes", "meta", "runs", "specimen"))
    assert code == 2, text
    none_written(tree, "out.json", "js")


def test_json_a_key_that_is_a_coded_id_is_refused_by_the_scan(tree, ps):
    """A short ID the sanitizer leaves alone, as a whole word of a key."""
    p = jput(tree, {"samples": [{"id": "AB12"}], "notes": {"seen AB12": 1}})
    code, text = jrun(tree, p, cols="samples[].id", extra=("AB12",))
    assert code == 2 and "key 4 (in the order of the file) holds an ID" in text, text
    none_written(tree, "out.json", "js")


def test_json_the_scan_covers_every_key_and_scalar(ps):
    m = ps._Matcher({"FAKE-PT-0001", "9990001"})
    for doc in ({"a": {"FAKE-PT-0001": 1}}, {"a": [{"b": "x FAKE-PT-0001"}]}, {"a\u200bb": 1},
                [1, [9990001]], {"a": "x\u200by"}, {"a": 9990001.5}):
        with pytest.raises(ps.Refused):
            ps._scan_json(doc, m)
    ps._scan_json({"a": [{"b": 19990001, "c": "FAKE-PT-0002", "d": None, "e": True}]}, m)


def test_json_an_id_escaped_in_the_input_is_refused(tree, ps):
    """19: an ID under a kept key written with JSON escapes in IN is the ID once read."""
    p = jput(tree, json.dumps(jdoc())[:-1] + ', "note": "\\u0046AKE\\u002dPT-0002"}')
    assert jrun(tree, p)[0] == 2
    none_written(tree, "out.json", "js")


def test_json_an_old_code_of_the_key_as_a_kept_value_is_refused(tree, ps):
    assert jrun(tree, jput(tree, jdoc()))[0] == 0
    old = key_map(tree / "home", "js")["FAKE-PT-0002"]
    os.unlink(tree / "phi" / "out.json")
    p = jput(tree, jdoc(1, note="was FAKE-PT-0002"), name="b.json")
    code, text = jrun(tree, p, new=False, extra=(old,))
    assert code == 2, text
    assert not (tree / "phi" / "out.json").exists()


@pytest.mark.parametrize("cols,more", [
    ("samples[].id,patient.mrn", ()),                        # matches nothing
    ("samples.id", ()),                                      # a key where there is an array
    ("study[].id", ()),                                      # [] where there is a string
    ("samples[].id=zzname", ()),                             # no new name in JSON
    ("samples[].id,samples[].id", ()),                       # twice
    ("samples[].id", ("--keep", "samples[].id")),            # in two options
    ("samples[].id", ("--drop", "zzgone")),                  # matches nothing
    ("samples[].id", ("--keep", "samples")),                 # a container, not a value
    ("samples[].id", ("--drop", "samples[]")),               # --drop names a key
    ("samples[.id", ()),
    ("a..b", ()),
])
def test_json_paths_that_do_not_fit_are_refused(tree, ps, cols, more):
    code, text = jrun(tree, jput(tree, jdoc()), cols=cols, more=more,
                      extra=("zzgone", "patient", "zzname", "study"))
    assert code == 2, text
    none_written(tree, "out.json", "js")


def test_json_the_draw_avoids_a_kept_value(tree, ps, monkeypatch):
    monkeypatch.setattr(ps.secrets, "randbelow", lambda n: n - 1)
    assert jrun(tree, jput(tree, jdoc(1, note="S9999")))[0] == 0
    assert "S9999" not in key_map(tree / "home", "js").values()


@pytest.mark.parametrize("how", ["changed", "kind"])
def test_json_a_copy_that_does_not_read_back_is_refused(tree, ps, monkeypatch, how):
    """The read-back compares the kinds too: `true == 1` in Python."""
    real = ps._write_json

    def bad(doc):
        return real(doc).replace('"value": 1', '"value": 7' if how == "changed" else
                                 '"value": true')
    monkeypatch.setattr(ps, "_write_json", bad)
    code, text = jrun(tree, jput(tree, jdoc()))
    assert code == 2, text
    none_written(tree, "out.json", "js")


@pytest.mark.parametrize("where", ["_read_json", "_write_json"])
@pytest.mark.parametrize("exc", ERRORS, ids=lambda e: type(e).__name__)
def test_json_any_exception_in_reading_or_writing_gives_the_one_refusal(tree, ps, monkeypatch,
                                                                          where, exc):
    def boom(*a, **kw):
        raise exc
    monkeypatch.setattr(ps, where, boom)
    code, text = jrun(tree, jput(tree, jdoc()), extra=("FAKE-PT-0007", type(exc).__name__))
    assert code == 2 and text.strip() == FIXED_JSON, text
    none_written(tree, "out.json", "js")


# --- review round 1 of step 3 -----------------------------------------------------------------

SURROGATE = '{"a": [{"id": "\\ud800"}, {"id": "FAKE-PT-0001"}, {"id": "FAKE-PT-0002"}]}'


@pytest.mark.parametrize("new", [True, False])
def test_json_a_lone_surrogate_in_a_coded_value_is_the_fixed_refusal(tree, ps, new):
    keys = tree / "home" / ".phiward" / "backups" / "keys"
    if not new:
        assert jrun(tree, jput(tree, {"a": [{"id": "FAKE-PT-0003"}, {"id": "FAKE-PT-0004"}]},
                               name="first.json"), cols="a[].id", out="first.json")[0] == 0
    before = (keys / "js.tsv").read_bytes() if not new else None
    code, text = jrun(tree, jput(tree, SURROGATE), cols="a[].id", new=new,
                      extra=("\ud800", "\udc00", "UnicodeEncodeError"))
    assert code == 2 and text.strip() == FIXED_JSON, text
    assert not (tree / "phi" / "out.json").exists()
    if new:
        assert not (keys / "js.tsv").exists()
        p = jput(tree, {"a": [{"id": "FAKE-PT-0001"}, {"id": "FAKE-PT-0002"}]}, name="ok.json")
        assert jrun(tree, p, cols="a[].id")[0] == 0  # the name can be used again
    else:
        assert (keys / "js.tsv").read_bytes() == before


@pytest.mark.parametrize("value", ['"\\udc00"', '{"\\ud83d": 1}', '["x\\ud800y"]'])
def test_json_a_lone_surrogate_anywhere_is_the_fixed_refusal(tree, ps, value):
    code, text = jrun(tree, jput(tree, _text_with('"note": ' + value)))
    assert code == 2 and text.strip() == FIXED_JSON, text
    none_written(tree, "out.json", "js")


def test_any_unexpected_error_of_the_run_is_one_fixed_refusal(tree, ps, monkeypatch):
    def boom(*a, **kw):
        raise UnicodeEncodeError("utf-8", "FAKE-PT-0001\ud800", 12, 13, "surrogates")
    monkeypatch.setattr(ps, "_append_key", boom)
    code, text = jrun(tree, jput(tree, jdoc()), extra=("UnicodeEncodeError", "surrogates"))
    assert code == 1, text
    assert text.strip() == ("phiward pseudonymize: the run stopped on an unexpected error. "
                            "No output was kept, and no new key; an existing key may keep codes "
                            "appended to it."), text
    none_written(tree, "out.json", "js")


def test_a_new_key_file_is_removed_when_its_write_fails(tree, ps, monkeypatch):
    real = ps._write_all
    calls = []

    def fail_first(fd, data):
        calls.append(1)
        if len(calls) == 1:
            os.write(fd, data[:5])
            raise OSError("disk full")
        return real(fd, data)
    monkeypatch.setattr(ps, "_write_all", fail_first)
    code, text = jrun(tree, jput(tree, jdoc()))
    assert code == 2, text
    none_written(tree, "out.json", "js")
    monkeypatch.setattr(ps, "_write_all", real)
    assert jrun(tree, jput(tree, jdoc()))[0] == 0


def test_a_new_key_is_removed_when_the_output_cannot_be_written(tree, ps, monkeypatch):
    def fail(*a, **kw):
        raise OSError("disk full")
    monkeypatch.setattr(ps, "_write_out", fail)
    code, text = jrun(tree, jput(tree, jdoc()))
    assert code == 2 and "new key was removed" in text, text
    none_written(tree, "out.json", "js")


def _paired(n=6, **more):
    doc = {"a": [{"id": f"FAKE-PT-{i:04d}"} for i in range(1, n + 1)],
           "purity": [i / 10 for i in range(1, n + 1)]}
    doc.update(more)
    return doc


def test_json_a_shuffled_array_beside_an_array_of_its_length_is_refused(tree, ps):
    code, text = jrun(tree, jput(tree, _paired()), cols="a[].id", extra=("purity",))
    assert code == 2 and "pairing" in text and "--keep-order" in text, text
    none_written(tree, "out.json", "js")
    assert jrun(tree, jput(tree, _paired()), cols="a[].id", more=("--keep-order",))[0] == 0
    assert jread(tree / "phi" / "out.json")["purity"] == [i / 10 for i in range(1, 7)]


def test_json_a_sibling_array_of_another_length_does_not_stop_the_shuffle(tree, ps):
    doc = _paired()
    doc["purity"] = doc["purity"][:5]
    assert jrun(tree, jput(tree, doc), cols="a[].id")[0] == 0


def test_json_two_coded_arrays_of_one_length_side_by_side_are_refused(tree, ps):
    doc = _paired()
    doc["b"] = [{"id": f"FAKE-PT-{i:04d}"} for i in range(11, 17)]
    del doc["purity"]
    code, text = jrun(tree, jput(tree, doc), cols="a[].id,b[].id")
    assert code == 2 and "pairing" in text, text


def test_json_a_container_key_needs_no_name(tree, ps):
    """`samples` holds objects: only its scalar paths (`samples[].id`) are named."""
    assert jrun(tree, jput(tree, jdoc()))[0] == 0


def test_json_an_unnamed_array_of_strings_under_an_id_key_is_refused(tree, ps):
    doc = {"x": [{"id": "FAKE-PT-0001"}, {"id": "FAKE-PT-0002"}], "samples": ["FAKE-PT-0009"]}
    code, text = jrun(tree, jput(tree, doc), cols="x[].id", extra=("FAKE-PT-0009",))
    assert code == 2 and "looks like an identifier" in text, text
    none_written(tree, "out.json", "js")
    assert jrun(tree, jput(tree, doc), cols="x[].id", more=("--keep", "samples[]"),
                extra=("FAKE-PT-0009",))[0] == 0


def test_json_drop_takes_a_container_whole(tree, ps):
    p = jput(tree, jdoc(meta={"runs": [{"specimen": "x"}]}))
    assert jrun(tree, p, more=("--drop", "meta"), extra=("meta", "specimen"))[0] == 0
    assert "meta" not in jread(tree / "phi" / "out.json")


@pytest.mark.parametrize("ident,note", [("9990001", "9.990001e6"), ("9990001", 9990001.0),
                                        ("1234", 1234.0), ("1234", "1234.0"),
                                        ("1234", "1.234E3")])
def test_json_a_number_matches_an_id_by_its_integer_form(tree, ps, ident, note):
    doc = {"a": [{"id": ident}, {"id": "FAKE-PT-0001"}], "note": note}
    code, text = jrun(tree, jput(tree, doc), cols="a[].id", extra=(ident,))
    assert code == 2, text
    none_written(tree, "out.json", "js")


def test_json_a_number_that_is_not_whole_or_another_number_passes(ps):
    m = ps._Matcher({"1234", "FAKE-PT-0001"})
    ps._scan_json({"a": [1234.5, "12.34", 12340.0, "1.2345e3", "x1234.0"]}, m)


def test_json_paths_take_spaces_after_commas(tree, ps):
    assert jrun(tree, jput(tree, jdoc(visit_no="v1")), cols="samples[].id, samples[].mrn",
                more=("--keep", "study, visit_no"))[0] == 0


# === step 4: Markdown pipe tables =============================================================

MD_IDS = ("FAKE-PT-0001", "FAKE-PT-0002", "9990001", "9990002", "patient_id", "Traceback",
          "Error", "| mrn")
FIXED_MD = ("phiward pseudonymize: the input cannot be read as a Markdown file. Nothing was "
            "written.")
LABS_MD = ("| mrn | site | value |\n"
           "|:----|:----:|------:|\n"
           "| FAKE-PT-0001 | lab | 1 |\n"
           "| 9990002 | lab | 2 |\n"
           "| FAKE-PT-0003 | clinic | 3 |\n")
ASSAY_MD = ("| assay | count |\n"
            "| --- | --- |\n"
            "| panel | 10 |\n"
            "| exome | 20 |\n")


def md_text(*tables):
    return "\n".join(tables)


def mput(tree, text, name="notes.md"):
    return put(tree, name, text.encode() if isinstance(text, str) else text)


def mrun(tree, p, cols="mrn", out="out.md", more=(), new=True, extra=()):
    args = ["--new-key" if new else "--key", "md", "--columns", cols, *more, p,
            tree / "phi" / out]
    code, text = run(tree, args, extra=MD_IDS + tuple(extra))
    assert "not covered yet" not in text, text  # a refusal of the Markdown rules, not of the kind
    return code, text


def md_cells(text):
    """The tables of a Markdown text: each a list of rows of stripped cells."""
    tables, cur = [], []
    for line in text.split("\n"):
        if not line.strip():
            if cur:
                tables.append(cur)
            cur = []
            continue
        cur.append([c.strip() for c in line.strip()[1:-1].split("|")])
    if cur:
        tables.append(cur)
    return tables


# --- 20. pipe tables: the named column coded, its rows shuffled, the rest kept ----------------

def test_markdown_codes_the_named_column_and_shuffles_its_table_only(tree, ps, monkeypatch):
    monkeypatch.setattr(ps, "_shuffle", lambda xs: xs.reverse())
    p = mput(tree, md_text(LABS_MD, ASSAY_MD))
    code, text = mrun(tree, p)
    assert code == 0, text
    assert text.strip() == ("phiward pseudonymize: wrote the coded Markdown tables, 5 row(s). "
                            "Read it with `phiward run`."), text
    got = key_map(tree / "home", "md")
    assert sorted(got) == ["9990002", "FAKE-PT-0001", "FAKE-PT-0003"]
    out = (tree / "phi" / "out.md").read_text()
    assert out == ("| pseudonym | site | value |\n"
                   "| :---- | :----: | ------: |\n"
                   f"| {got['FAKE-PT-0003']} | clinic | 3 |\n"
                   f"| {got['9990002']} | lab | 2 |\n"
                   f"| {got['FAKE-PT-0001']} | lab | 1 |\n"
                   "\n"
                   "| assay | count |\n"
                   "| --- | --- |\n"
                   "| panel | 10 |\n"
                   "| exome | 20 |\n"), out
    assert os.stat(tree / "phi" / "out.md").st_mode & 0o777 == 0o600


def test_markdown_keep_order_and_a_new_header(tree, ps, monkeypatch):
    monkeypatch.setattr(ps, "_shuffle", lambda xs: xs.reverse())
    p = mput(tree, LABS_MD)
    assert mrun(tree, p, cols="mrn=code", more=("--keep-order",))[0] == 0
    got = key_map(tree / "home", "md")
    t = md_cells((tree / "phi" / "out.md").read_text())
    assert t == [[["code", "site", "value"], [":----", ":----:", "------:"],
                  [got["FAKE-PT-0001"], "lab", "1"], [got["9990002"], "lab", "2"],
                  [got["FAKE-PT-0003"], "clinic", "3"]]]


def test_markdown_the_real_shuffle_keeps_each_row_whole(tree, ps):
    rows = "".join(f"| FAKE-PT-{i:04d} | v{i} |\n" for i in range(1, 41))
    p = mput(tree, "| mrn | value |\n| --- | --- |\n" + rows)
    assert mrun(tree, p, extra=("FAKE-PT-0040",))[0] == 0
    back = {v: k for k, v in key_map(tree / "home", "md").items()}
    body = md_cells((tree / "phi" / "out.md").read_text())[0][2:]
    assert sorted(back[c] + " " + v for c, v in body) == sorted(
        f"FAKE-PT-{i:04d} v{i}" for i in range(1, 41))
    assert [back[c] for c, _ in body] != [f"FAKE-PT-{i:04d}" for i in range(1, 41)]


def test_markdown_gz_is_coded_and_compressed(tree, ps):
    p = put(tree, "notes.md.gz", gz(md_text(LABS_MD, ASSAY_MD)))
    assert mrun(tree, p, out="out.md.gz")[0] == 0
    out = gzip.decompress((tree / "phi" / "out.md.gz").read_bytes()).decode()
    assert md_cells(out)[0][0] == ["pseudonym", "site", "value"]


def test_markdown_a_column_named_in_two_tables_codes_both_with_one_code_per_id(tree, ps):
    second = "| mrn | note |\n| --- | --- |\n| FAKE-PT-0001 | again |\n| FAKE-PT-0002 | x |\n"
    p = mput(tree, md_text(LABS_MD, second))
    assert mrun(tree, p, more=("--keep-order",))[0] == 0
    got = key_map(tree / "home", "md")
    t = md_cells((tree / "phi" / "out.md").read_text())
    assert t[0][2][0] == t[1][2][0] == got["FAKE-PT-0001"]
    assert t[1][3][0] == got["FAKE-PT-0002"]


def test_markdown_a_known_id_keeps_its_code_from_a_table(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "site"], [["FAKE-PT-0001", "lab"]])
    assert run(tree, base(tree, key="md"))[0] == 0
    code = key_map(tree / "home", "md")["FAKE-PT-0001"]
    assert mrun(tree, mput(tree, LABS_MD), new=False)[0] == 0
    assert code in (tree / "phi" / "out.md").read_text()


# --- what is not a table is free text: refused (decision C) -----------------------------------

@pytest.mark.parametrize("extra_line", [
    "Seen today: FAKE-PT-0001.",              # prose
    "# Labs",                                  # a heading
    "- FAKE-PT-0001",                          # a list
    "```",                                     # a code fence
    "    | mrn | site | value |",              # indented: a code block
    "---",                                     # a rule, or front matter
    "<!-- FAKE-PT-0001 -->",                   # an HTML comment
    "mrn | site | value",                      # a row without its outer pipes
    "| FAKE-PT-0004 | lab | 4",                # a row that does not end with a pipe
])
def test_markdown_any_line_outside_a_table_is_refused(tree, ps, extra_line):
    for text in (extra_line + "\n\n" + LABS_MD, LABS_MD + "\n" + extra_line + "\n",
                 LABS_MD + extra_line + "\n"):
        fresh(tree, "out.md", "md")
        code, text = mrun(tree, mput(tree, text))
        assert code == 2 and "free text" in text, text
        none_written(tree, "out.md", "md")


@pytest.mark.parametrize("bad", [
    "| mrn | site |\n| FAKE-PT-0001 | lab |\n",                 # no alignment row
    "| mrn | site |\n| --- |\n| FAKE-PT-0001 | lab |\n",         # an alignment row too short
    "| mrn | site |\n| --- | x |\n| FAKE-PT-0001 | lab |\n",     # not an alignment row
    "| mrn | site |\n| --- | --- |\n| FAKE-PT-0001 |\n",         # a row too short
    "| mrn | site |\n| --- | --- |\n| FAKE-PT-0001 | lab | x |\n",  # a row too wide
    "| mrn | site |\r\n| --- | --- |\r\n| FAKE-PT-0001 | lab |\r\n",  # CRLF
    "",                                                           # empty
    "\n\n",                                                       # no table
])
def test_markdown_a_table_that_does_not_fit_is_refused(tree, ps, bad):
    code, text = mrun(tree, mput(tree, bad))
    assert code == 2, text
    none_written(tree, "out.md", "md")


@pytest.mark.parametrize("line", [
    "| FAKE\\-PT\\-0001 | lab | 4 |",         # a backslash escape
    "| FAKE-PT-0004 | a \\| b | 4 |",         # an escaped pipe
    "| FAKE-PT-0004 | `x|y` | 4 |",          # a code span
    "| FAKE-PT-0004 | ``x`` | 4 |",
])
def test_markdown_a_row_with_a_backslash_or_a_backtick_is_refused(tree, ps, line):
    code, text = mrun(tree, mput(tree, LABS_MD + line + "\n"))
    assert code == 2 and "backslash" in text, text
    none_written(tree, "out.md", "md")


def test_markdown_a_header_or_alignment_row_with_a_backslash_is_refused(tree, ps):
    for text in ("| mrn | si\\|te | value |\n" + LABS_MD.split("\n", 1)[1],
                 LABS_MD.replace("|:----|", "|:--\\-|")):
        fresh(tree, "out.md", "md")
        code, out = mrun(tree, mput(tree, text))
        assert code == 2, out
        none_written(tree, "out.md", "md")


# --- the scan reads each cell raw and with Markdown and HTML decoded (inv. 5) -----------------

@pytest.mark.parametrize("cell", [
    "&#70;AKE-PT-0001", "FAKE&#45;PT&#x2D;0001", "FAKE&amp;#45;PT-0001",
    "FAKE&amp;amp;#45;PT-0001", "**FAKE**-PT-0001", "*FAKE*-PT-*0001*", "~~FAKE~~-PT-0001",
    "__FAKE__-PT-0001",
    "FAKE%26%2345%3BPT-0001", "ＦＡＫＥ&#45;PT-0001",
    "see &#57;990002 again", "999**0002**", "x/9990&#48;02.bam",
])
def test_markdown_an_id_behind_an_entity_or_markup_in_a_kept_cell_is_refused(tree, ps, cell):
    code, text = mrun(tree, mput(tree, LABS_MD + f"| FAKE-PT-0004 | {cell} | 4 |\n"),
                      extra=(cell,))
    assert code == 2 and "column 2" in text and "table 1" in text, text
    none_written(tree, "out.md", "md")


@pytest.mark.parametrize("cell", ["&#8203;", "a&#x200B;b", "&amp;#8203;", "​"])
def test_markdown_an_invisible_format_character_also_by_an_entity_is_refused(tree, ps, cell):
    code, text = mrun(tree, mput(tree, LABS_MD + f"| FAKE-PT-0004 | {cell} | 4 |\n"))
    assert code == 2, text
    none_written(tree, "out.md", "md")


def test_markdown_entities_nested_past_the_rounds_are_refused(tree, ps):
    cell = "&amp;amp;amp;amp;amp;amp;#45;"
    code, text = mrun(tree, mput(tree, LABS_MD + f"| FAKE-PT-0004 | {cell} | 4 |\n"))
    assert code == 2, text
    none_written(tree, "out.md", "md")


def test_markdown_markup_and_entities_with_no_id_pass(tree, ps):
    cells = ["**bold**", "https://example.org/a_b", "a &amp; b", "&lt;x&gt;",
             "1999**0001**", "snake_case_name", "100%", "a > b"]
    rows = "".join(f"| FAKE-PT-{i + 4:04d} | {c} | {i} |\n" for i, c in enumerate(cells))
    assert mrun(tree, mput(tree, LABS_MD + rows), more=("--keep-order",))[0] == 0
    body = md_cells((tree / "phi" / "out.md").read_text())[0][5:]
    assert [r[1] for r in body] == cells


def test_markdown_an_id_of_another_table_in_a_kept_cell_is_refused(tree, ps):
    second = "| mrn | note |\n| --- | --- |\n| FAKE-PT-0002 | x |\n"
    first = LABS_MD + "| FAKE-PT-0004 | see FAKE-PT-0002 | 4 |\n"
    code, text = mrun(tree, mput(tree, md_text(first, second)))
    assert code == 2 and "table 1" in text, text
    none_written(tree, "out.md", "md")


def test_markdown_twin_ids_across_tables_are_refused(tree, ps):
    second = "| mrn | note |\n| --- | --- |\n| fake-pt-0001 | x |\n"
    code, text = mrun(tree, mput(tree, md_text(LABS_MD, second)), extra=("fake-pt-0001",))
    assert code == 2 and "letter case" in text, text
    none_written(tree, "out.md", "md")


def test_markdown_the_draw_avoids_a_kept_value_also_decoded(tree, ps, monkeypatch):
    monkeypatch.setattr(ps.secrets, "randbelow", lambda n: n - 1)
    p = mput(tree, LABS_MD + "| FAKE-PT-0004 | S&#57;999 | 4 |\n")
    assert mrun(tree, p)[0] == 0
    assert "S9999" not in key_map(tree / "home", "md").values()


# --- the ID-glob rule per table; headers ------------------------------------------------------

def test_markdown_an_unnamed_id_column_in_any_table_is_refused(tree, ps):
    second = "| patient_id | note |\n| --- | --- |\n| FAKE-PT-0009 | x |\n"
    code, text = mrun(tree, mput(tree, md_text(LABS_MD, second)), extra=("FAKE-PT-0009",))
    assert code == 2 and "table 2" in text and "column 1" in text, text
    none_written(tree, "out.md", "md")
    assert mrun(tree, tree / "data" / "notes.md", more=("--drop", "patient_id"),
                extra=("FAKE-PT-0009",))[0] == 0
    out = (tree / "phi" / "out.md").read_text()
    assert "FAKE-PT-0009" not in out and md_cells(out)[1][0] == ["note"]


def test_markdown_a_name_found_in_no_table_is_refused(tree, ps):
    for cols, more in (("mrn", ("--drop", "zzgone")), ("zzgone", ()), ("mrn", ("--keep", "zz"))):
        fresh(tree, "out.md", "md")
        code, text = mrun(tree, mput(tree, LABS_MD), cols=cols, more=more,
                          extra=("zzgone", "zz"))
        assert code == 2 and "not found" in text, text
        none_written(tree, "out.md", "md")


@pytest.mark.parametrize("header", ["**patient_id**", "_mrn_", "patient&#95;id",
                                    "pat*ient_id*", "~~mrn~~"])
def test_markdown_a_header_with_markup_or_an_entity_is_refused(tree, ps, header):
    text = LABS_MD.replace("| site |", f"| {header} |", 1)
    code, out = mrun(tree, mput(tree, text), extra=(header,))
    assert code == 2 and "column 2" in out, out
    none_written(tree, "out.md", "md")


def test_markdown_a_new_header_that_breaks_the_table_is_refused(tree, ps):
    for new in ("a|b", "a\\b", "a`b"):
        fresh(tree, "out.md", "md")
        code, text = mrun(tree, mput(tree, LABS_MD), cols=f"mrn={new}", extra=(new,))
        assert code == 2, text
        none_written(tree, "out.md", "md")


# --- errors (inv. 10) -------------------------------------------------------------------------

@pytest.mark.parametrize("where", ["_read_md", "_write_md"])
@pytest.mark.parametrize("exc", ERRORS, ids=lambda e: type(e).__name__)
def test_markdown_any_exception_in_reading_or_writing_gives_the_one_refusal(tree, ps,
                                                                              monkeypatch,
                                                                              where, exc):
    def boom(*a, **kw):
        raise exc
    monkeypatch.setattr(ps, where, boom)
    code, text = mrun(tree, mput(tree, LABS_MD), extra=("FAKE-PT-0007", type(exc).__name__))
    assert code == 2 and text.strip() == FIXED_MD, text
    none_written(tree, "out.md", "md")


def test_markdown_a_copy_that_does_not_read_back_is_refused(tree, ps, monkeypatch):
    real = ps._write_md
    monkeypatch.setattr(ps, "_write_md", lambda tables: real(tables).replace("| lab |",
                                                                              "| lbb |"))
    code, text = mrun(tree, mput(tree, LABS_MD))
    assert code == 2 and "read back" in text, text
    none_written(tree, "out.md", "md")


# --- step 4, review round 1 -------------------------------------------------------------------

DASHES = ["‐", "‑", "‒", "–", "—", "―", "−", "⁃",
          "˗", "ー", "﹣", "⸺"]


@pytest.mark.parametrize("dash", DASHES + ["%E2%80%90", "%E2%88%92"])
def test_an_id_with_a_unicode_dash_in_a_kept_tsv_cell_is_refused(tree, ps, dash):
    write_table(tree / "data" / "labs.tsv", ["mrn", "note"],
                [["FAKE-PT-0001", f"FAKE{dash}PT-0001"], ["FAKE-PT-0002", "ok"]])
    code, text = run(tree, base(tree), extra=["note", f"FAKE{dash}PT-0001"])
    assert code == 2 and "column 2" in text, text
    none_written(tree)


def test_a_kept_tsv_header_with_a_unicode_dash_id_is_refused(tree, ps):
    write_table(tree / "data" / "labs.tsv", ["mrn", "FAKE‐PT-0001"],
                [["FAKE-PT-0001", "x"], ["FAKE-PT-0002", "ok"]])
    code, text = run(tree, base(tree), extra=["FAKE‐PT-0001"])
    assert code == 2, text
    none_written(tree)


@pytest.mark.parametrize("dash", ["–", "−", "‐"])
def test_two_ids_that_differ_only_in_a_dash_are_twins(tree, ps, dash):
    write_table(tree / "data" / "labs.tsv", ["mrn", "site"],
                [["FAKE-PT-0001", "a"], [f"FAKE{dash}PT-0001", "b"]])
    code, text = run(tree, base(tree), extra=[f"FAKE{dash}PT-0001"])
    assert code == 2 and "letter case" in text, text
    none_written(tree)


def test_a_vcf_record_with_a_unicode_dash_sample_id_is_refused(tree, ps):
    p = put(tree, "calls.vcf", vcf_text(recs=_with(1, 7, "DP=31;T=P‑9990001-T01-IM6"))
            .encode())
    code, text = vcf_run(tree, p)
    assert code == 2, text
    none_written(tree, "out.vcf", "vcf")


@pytest.mark.parametrize("note", ["FAKE‐PT-0001", "FAKE%E2%80%90PT-0001",
                                  "FAKE\\u2212PT-0001"])
def test_a_json_value_with_a_unicode_dash_id_is_refused(tree, ps, note):
    code, text = jrun(tree, jput(tree, jdoc(note=note)), extra=(note,))
    assert code == 2, text
    none_written(tree, "out.json", "js")


@pytest.mark.parametrize("cell", ["FAKE&hyphen;PT-0001", "FAKE&dash;PT-0001",
                                  "FAKE&minus;PT-0001", "FAKE&#8208;PT-0001",
                                  "FAKE%E2%80%90PT-0001", "FAKE–PT-0001"])
def test_markdown_an_id_with_a_unicode_dash_is_refused(tree, ps, cell):
    code, text = mrun(tree, mput(tree, LABS_MD + f"| FAKE-PT-0004 | {cell} | 4 |\n"),
                      extra=(cell,))
    assert code == 2 and "table 1" in text, text
    none_written(tree, "out.md", "md")


@pytest.mark.parametrize("cell", ["FAKE PT 0001", "seen FAKE  PT/0001 today", "FAKE.PT.0001",
                                  "FAKEPT0001", "f-a-k-e-p-t-0-0-0-1"])
def test_an_id_with_other_separators_in_a_kept_tsv_cell_is_refused(tree, ps, cell):
    write_table(tree / "data" / "labs.tsv", ["mrn", "note"],
                [["FAKE-PT-0001", cell], ["FAKE-PT-0002", "ok"]])
    code, text = run(tree, base(tree), extra=["note", cell])
    assert code == 2 and "column 2" in text, (cell, text)
    none_written(tree)


@pytest.mark.parametrize("cell", ["999 0001", "999-0001", "9.990001", "999,0001"])
def test_digit_ids_are_not_joined_across_separators(tree, ps, cell):
    write_table(tree / "data" / "labs.tsv", ["mrn", "note"],
                [["9990001", cell], ["9990002", "ok"]])
    assert run(tree, base(tree), extra=["note"])[0] == 0, cell


@pytest.mark.parametrize("cell", ["FAKE-**PT**-0001", "FAKE PT 0001", "*FAKE* PT_0001"])
def test_markdown_an_id_split_by_emphasis_or_spaces_is_refused(tree, ps, cell):
    code, text = mrun(tree, mput(tree, LABS_MD + f"| FAKE-PT-0004 | {cell} | 4 |\n"),
                      extra=(cell,))
    assert code == 2 and "table 1" in text, text
    none_written(tree, "out.md", "md")


@pytest.mark.parametrize("cell", [
    'FAKE<a title="x>y">-PT-0001', "FAKE<!-- > -->-PT-0001", "FAKE<?x>?>-PT-0001",
    "FAKE<![CDATA[>]]>-PT-0001", "[FAKE-PT](a(b))-0001", "<b>x</b>", "a < b", "[x]",
    "x]", "<https://example.org>", "[FAKE-PT](x)-0001", "![FAKE-PT](x)-0001",
    "[x](FAKE-PT-0001)", "[x](&#70;AKE-PT-0001)", "FAKE<b></b>-PT-0001",
    "FAKE-PT-<!-- x -->0001", "<a href=\"&#70;AKE-PT-0001\">x</a>", "[999](x)0002",
])
def test_markdown_a_cell_with_a_raw_angle_or_square_bracket_is_refused(tree, ps, cell):
    code, text = mrun(tree, mput(tree, LABS_MD + f"| FAKE-PT-0004 | {cell} | 4 |\n"),
                      extra=(cell,))
    assert code == 2 and "line 6" in text and "<, [ or ]" in text, text
    none_written(tree, "out.md", "md")


def test_markdown_two_tables_without_a_blank_line_are_refused(tree, ps):
    text = ("| mrn | site |\n| --- | --- |\n| FAKE-PT-0001 | lab |\n"
            "| patient_id | site |\n| :-- | --: |\n| FAKE-PT-0009 | x |\n")
    code, out = mrun(tree, mput(tree, text), more=("--keep-order",), extra=("FAKE-PT-0009",))
    assert code == 2 and "line 5" in out and "blank line" in out, out
    none_written(tree, "out.md", "md")


# === hygiene: pins on the rules that are spelled in one helper each =========================
# Each rule had two copies; each pin runs a caller of the helper and checks its exact refusal,
# so a change to the helper shows in both callers.

def test_pin_an_input_reached_through_a_link_or_that_cannot_be_checked(tree, ps):
    os.symlink(tree / "data" / "labs.tsv", tree / "data" / "l.tsv")
    code, text = run(tree, base(tree, inp=tree / "data" / "l.tsv"))
    assert code == 2 and "reached through a link" in text, text
    code, text = run(tree, base(tree, inp=tree / "data" / "labs.tsv" / "x.tsv"))
    assert code == 2 and "the input cannot be checked" in text, text
    none_written(tree)


ID_HEADER = "looks like an identifier"


def test_pin_the_id_header_rule_on_a_table_header(tree, ps):
    """`col_key` drops one `#`: `#pt` is the header `pt`, an ID; `##pt` is `#pt`, not one."""
    write_table(tree / "data" / "labs.tsv", ["mrn", "#pt", "value"], [["9990001", "a", "1"]])
    code, text = run(tree, base(tree))
    assert code == 2 and f"column 2 {ID_HEADER}" in text, text
    none_written(tree)
    write_table(tree / "data" / "labs.tsv", ["mrn", "##pt", "value"], [["9990001", "a", "1"]])
    code, text = run(tree, base(tree))
    assert code == 0, text


def test_pin_the_id_header_rule_on_a_new_header(tree, ps):
    code, text = run(tree, base(tree, cols="mrn=#pt"))
    assert code == 2 and f"new header of column 1 is empty, {ID_HEADER}" in text, text
    none_written(tree)
    code, text = run(tree, base(tree, cols="mrn=##pt"))
    assert code == 0, text


def test_pin_the_id_header_rule_on_a_json_key(tree, ps):
    code, text = jrun(tree, jput(tree, jdoc(**{"#pt": "x"})))
    assert code == 2 and ID_HEADER in text, text
    none_written(tree, "out.json", "js")
    code, text = jrun(tree, jput(tree, jdoc(**{"##pt": "x"})))
    assert code == 0, text


BAD_ID_TEXT = "holds a tab, a line break or an invisible format character"


@pytest.mark.parametrize("cell", ["FAKE\tPT-0001", "FAKE\nPT-0001", "FAKE\rPT-0001",
                                  "FAKE​PT-0001"])
def test_pin_the_bad_id_text_rule_in_a_table(tree, ps, cell):
    p = tree / "data" / "labs.csv"
    with open(p, "w", newline="") as f:
        # every field quoted: Python 3.9's writer leaves a field with a lone \r unquoted
        csv.writer(f, lineterminator="\n", quoting=csv.QUOTE_ALL).writerows(
            [["mrn", "site"], [cell, "lab"]])
    code, text = run(tree, base(tree, inp=p, out=tree / "phi" / "out.csv"), extra=[cell])
    assert code == 2 and f"a cell of column 1 {BAD_ID_TEXT}" in text, text
    none_written(tree, "out.csv")


@pytest.mark.parametrize("value", ["FAKE\tPT-0001", "FAKE\nPT-0001", "FAKE\rPT-0001",
                                   "FAKE​PT-0001"])
def test_pin_the_bad_id_text_rule_in_json(tree, ps, value):
    code, text = jrun(tree, jput(tree, jdoc(samples=[{"id": value, "mrn": None}])))
    assert code == 2 and f"a value at path 1 of --columns {BAD_ID_TEXT}" in text, text
    none_written(tree, "out.json", "js")


def test_pin_the_bad_id_text_rule_in_markdown_keeps_the_table_number(tree, ps):
    text = LABS_MD + "| FAKE​PT-0004 | lab | 4 |\n"
    code, out = mrun(tree, mput(tree, text))
    assert code == 2 and f"table 1: a cell of column 1 {BAD_ID_TEXT}" in out, out
    none_written(tree, "out.md", "md")


@pytest.mark.parametrize("header", ["**site**", "si&#116;e", "si&amp;te"])
def test_pin_the_markdown_header_markup_rule_on_a_header(tree, ps, header):
    code, out = mrun(tree, mput(tree, LABS_MD.replace("| site |", f"| {header} |", 1)),
                     extra=(header,))
    assert code == 2 and "table 1: the header of column 2 holds Markdown" in out, out
    none_written(tree, "out.md", "md")


@pytest.mark.parametrize("new", ["**code**", "co&#100;e", "co&amp;de", "a|b", "a\\b", "a`b"])
def test_pin_the_markdown_header_markup_rule_on_a_new_header(tree, ps, new):
    code, out = mrun(tree, mput(tree, LABS_MD), cols=f"mrn={new}", extra=(new,))
    assert code == 2 and "table 1: a new header holds a pipe" in out, out
    none_written(tree, "out.md", "md")


def test_pin_the_ids_are_drawn_in_order_of_first_appearance(tree, ps, monkeypatch):
    """Row by row, in each row the coded columns in --columns order: the key lines follow."""
    monkeypatch.setattr(ps.secrets, "randbelow", lambda n: n - 1)
    write_table(tree / "data" / "labs.tsv", ["mrn", "patient", "site"],
                [["9990003", "FAKE-PT-0002", "a"], ["", "9990001", "b"],
                 ["9990001", "FAKE-PT-0002", "c"], ["9990004", "", "d"]])
    code, text = run(tree, base(tree, cols="patient,mrn", more=["--keep-order"]))
    assert code == 0, text
    assert [ln.split("\t")[0] for ln in key_lines(tree / "home", "labs")[1:]] == \
        ["FAKE-PT-0002", "9990003", "9990001", "9990004"]


def test_pin_markdown_the_draw_knows_the_ids_of_every_coded_column(tree, ps, monkeypatch):
    """The draw would pick QX9999 first; `X9999` in the second coded column of the second
    table makes it skip that code."""
    monkeypatch.setattr(ps.secrets, "randbelow", lambda n: n - 1)
    second = ("| case | patient_id |\n| --- | --- |\n| FAKE-PT-0005 | X9999 |\n")
    code, out = mrun(tree, mput(tree, md_text(LABS_MD, second)), cols="mrn,case,patient_id",
                     more=("--prefix", "QX", "--keep-order"), extra=("X9999",))
    assert code == 0, out
    codes = key_map(tree / "home", "md").values()
    assert "QX9999" not in codes and len(set(codes)) == 5
