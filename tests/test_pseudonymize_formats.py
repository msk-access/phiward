"""`phiward pseudonymize`, more kinds of input (step 1 of the formats plan): the extension chain
picks the parser and the content must agree; plain gzip in and out; `.txt` read as TSV; MAF;
the scan of the whole output. Made-up data only (`FAKE-PT-0007`, `P-9990001-T01-IM6`, MAF
barcodes `FAKE-AB-0001-01A`, MRNs from 9990001), in a scratch HOME."""

import csv
import gzip
import io
import os
import struct
import zlib

import pytest

from test_pseudonymize import base, key_map, mrns, read_table, run, write_table

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


def _bgzf(text):
    """One BGZF block and the EOF block (an FEXTRA `BC` subfield in each header)."""
    raw = text.encode()
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    body = c.compress(raw) + c.flush()
    block = (b"\x1f\x8b\x08\x04" + b"\0" * 4 + b"\0\xff" + struct.pack("<H", 6) + b"BC" +
             struct.pack("<HH", 2, 25 + len(body)) + body +
             struct.pack("<II", zlib.crc32(raw), len(raw)))
    eof = bytes.fromhex("1f8b08040000000000ff0600424302001b0003000000000000000000")
    return block + eof


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
    ("labs.json", b'{"mrn": "9990001"}\n', "out.json"),
    ("labs.md", b"| mrn |\n|---|\n| 9990001 |\n", "out.md"),
    ("labs.tsv", b"##fileformat=VCFv4.2\nmrn\tsite\n9990001\tlab\n", "out.tsv"),
    ("labs.maf.gz", gz("##fileformat=VCFv4.2\nmrn\tsite\n9990001\tlab\n"), "out.maf.gz"),
    ("labs.tsv.gz", _bgzf(TABLE), "out.tsv.gz"),      # BGZF: a later step
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
    monkeypatch.setattr(ps, "LIMIT", 4 << 20)
    p = put(tree, "labs.tsv.gz", gz("mrn\tsite\n" + "9990001\tlab\n" * (1 << 20)))
    assert p.stat().st_size < (1 << 20)
    total = []
    real = gzip.GzipFile.read

    def counted(self, *a):
        b = real(self, *a)
        total.append(len(b))
        return b
    monkeypatch.setattr(gzip.GzipFile, "read", counted)
    code, text = run(tree, base(tree, inp=p, out=tree / "phi" / "out.tsv.gz"))
    assert code == 2 and "too large" in text, text
    assert sum(total) <= ps.LIMIT + (1 << 20), sum(total)
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
    assert code == 2, text
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
    ("FAKE PT 0007", "seen FAKE PT 0007 today"),
    ("9990001", "PT:9990001"),
    ("FAKE-PT-0007", "ＦＡＫＥ-PT-0007"),
    ("9990002", "see 9990002 again"),
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


def test_the_draw_uses_the_scan(ps):
    m = ps._Matcher({"X9999", "9999", "S99", "1234567"})
    assert m.hit("QX9999") and m.hit("9999") and m.hit("S99") and m.hit("a/1234567.b")
    assert not m.hit("QX9998") and not m.hit("S991") and not m.hit("11234567")


# --- step 1 keeps the TSV and CSV behaviour ---------------------------------------------------

def test_a_plain_tsv_still_works_and_reports_the_row_count_only(tree, ps):
    code, text = run(tree, base(tree), extra=["mrn", "labs.tsv"])
    assert code == 0 and text.strip().endswith("20 row(s). Read it with `phiward run`."), text
