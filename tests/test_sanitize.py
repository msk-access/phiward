"""The sanitizer: every value here is made up. Configs are tmp files named by
PHIWARD_CONFIG, with HOME in a tmp folder; the user's own config is never read."""

import io
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import config, sanitize
from phiward.sanitize import (
    GENOMICS_CASES, GENOMICS_TABLE_CASES, MADE_UP_RUNS, MSK_CASES, MSK_TABLE_CASES,
    PROTECTED_CASES, SELFTEST_ROOT, WITHHELD, Sanitizer, SanitizerError,
)

SRC = str(Path(__file__).resolve().parents[1] / "src")


def make_env(tmp_path, cfg_text=None):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    cfg = tmp_path / "cfg.toml"
    cfg.write_text(cfg_text if cfg_text is not None else "")
    return {"HOME": str(home), "PHIWARD_CONFIG": str(cfg), "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": SRC, "PYTHONDONTWRITEBYTECODE": "1"}


def load_cfg(tmp_path, cfg_text):
    env = make_env(tmp_path, cfg_text)
    return config.load(str(tmp_path), env=env)


def run_cli(tmp_path, args, stdin="", cfg_text="", env=None):
    env = env or make_env(tmp_path, cfg_text)
    return subprocess.run([sys.executable, "-m", "phiward", "sanitize"] + args,
                          input=stdin.encode(), capture_output=True, env=env, cwd=str(tmp_path),
                          timeout=60)


def names_file(tmp_path):
    p = tmp_path / "runs.tsv"
    p.write_text("\n".join(MADE_UP_RUNS) + "\n")
    return str(p)


@pytest.fixture()
def genomics():
    return Sanitizer._build(config.Config(packs=["genomics"]), (), ())


@pytest.fixture()
def msk(tmp_path):
    cfg = load_cfg(tmp_path, f'[sanitize]\npacks = ["genomics", "msk"]\nnames_from = ["{names_file(tmp_path)}"]\n')
    return Sanitizer.from_config(cfg)


# --- the cases ported from the original selftest, split by pack ---------------------------------

@pytest.mark.parametrize("src,want", GENOMICS_CASES)
def test_genomics_text_cases(genomics, src, want):
    got = genomics.clean(src)
    assert got == want
    assert genomics.clean(got) == got


@pytest.mark.parametrize("src,want", GENOMICS_TABLE_CASES)
def test_genomics_table_cases(genomics, src, want):
    assert genomics.clean(src, table=True) == want


@pytest.mark.parametrize("src,want", MSK_CASES)
def test_msk_text_cases(msk, src, want):
    got = msk.clean(src)
    assert got == want
    assert msk.clean(got) == got


@pytest.mark.parametrize("src,want", MSK_TABLE_CASES)
def test_msk_table_cases(msk, src, want):
    assert msk.clean(src, table=True) == want


@pytest.fixture()
def msk_only_packs():
    return Sanitizer._build(config.Config(packs=["genomics", "msk"]), (), ())


# What each msk rule is for (the pack's comments, MSK_CASES, the spelling tests): each stays
# masked, in made-up shapes.
MSK_INTENDED = [
    # <DONOR>: a donor name with a number in it
    ("x DonorFake-7 y", "x <DONOR> y"), ("x DONOR_X1 y", "x <DONOR> y"),
    ("x Donor_FAKE7 y", "x <DONOR> y"), ("x donorfake12 y", "x <DONOR> y"),
    ("x Donor-1234567 y", "x <DONOR> y"), ("x id_DonorFake-3 y", "x id_<DONOR> y"),
    # <CMOID>: C- and six letters or digits, with or without the suffixes; s_C_ forms
    ("x C-ABC123-L001-d y", "x <CMOID> y"), ("x c-abc123-l001-d y", "x <CMOID> y"),
    ("x C-FAKE01 y", "x <CMOID> y"), ("x C-ABCDEF y", "x <CMOID> y"),
    ("x C-ABCDEF-L001 y", "x <CMOID> y"), ("x C-ABC123_P001_d y", "x <CMOID> y"),
    ("x s_C_FAKE01_P001_d y", "x <CMOID> y"), ("x bam_C-FAKE02-N001 y", "x bam_<CMOID> y"),
]


@pytest.mark.parametrize("src,want", MSK_INTENDED)
def test_msk_rules_keep_masking_what_they_are_for(msk_only_packs, src, want):
    assert msk_only_packs.clean(src) == want


# Ordinary words of coding prompts (tests/data/prompt_corpus*.txt) that no msk rule masks
MSK_ORDINARY = [
    "the donor_id column", "rename donors to participants", "the DonorSearch class",
    "donor-derived cells", "a Donor", "how a C-string differs", "add a c-header",
    "move src/clinical/report.py", "under tests/inputs/patient/ here",
]


@pytest.mark.parametrize("src", MSK_ORDINARY)
def test_msk_rules_leave_ordinary_words(msk_only_packs, src):
    assert msk_only_packs.clean(src) == src


def test_default_pack_is_genomics():
    san = Sanitizer.from_config(config.Config())
    assert san.clean("read A00123:45:HABCDEFXX:1:1101:12345:6789") == "read <READ>"
    assert san.clean("sample P-9990001-T01-IM6") == "sample P-<NUM>-T01-IM6"  # no msk pack


@pytest.mark.parametrize("src,want", [
    ("1234567,7654321", "<NUM>,<NUM>"),  # a CSV row of two long numbers
    ("FAKE,9990001,12", "FAKE,<NUM>,12"),
    ("9990001,12", "<NUM>,12"),
    ("12,9990001", "12,<NUM>"),
    ("12345,67", "<NUM>,67"),  # a decimal comma: the whole part is masked
])
def test_a_long_number_next_to_a_comma_is_masked(genomics, src, want):
    # configuration.md: any run of five or more digits becomes <NUM>; a comma is no exception
    assert genomics.clean(src) == want


@pytest.mark.parametrize("src", ["12,345 reads", "1,234 and 999,999", "mean=12345.678", "0.0123456"])
def test_grouped_thousands_and_decimals_are_kept(genomics, src):
    assert genomics.clean(src) == src


def test_msk_pack_has_no_personal_paths():
    text = (Path(SRC) / "phiward" / "packs" / "msk.toml").read_text()
    assert "/users/" not in text.lower() and "/home/" not in text.lower()


# --- protected paths ----------------------------------------------------------------------------

@pytest.mark.parametrize("src,want", PROTECTED_CASES)
def test_protected_cases(src, want):
    san = Sanitizer.from_config(config.Config(roots=[SELFTEST_ROOT]))
    assert san.clean(src) == want


def test_protected_root_and_pattern_through_the_env_config(tmp_path):
    t = tmp_path.resolve()
    (t / "phi").mkdir()
    cfg = load_cfg(t, f'[protected_paths]\nroots = ["{t}/phi"]\npatterns = ["{t}/runs/*/panel"]\n')
    assert not cfg.problem
    san = Sanitizer.from_config(cfg)
    assert san.clean(f"open {t}/phi/FAKE-PT-0001.bam\tnow") == "open <PROTECTED>\tnow"
    assert san.clean(f"open {t}/runs/run1/panel/x.maf\tnow") == "open <PROTECTED>\tnow"
    assert san.clean(f"list {t}/phi") == "list <PROTECTED>"
    other = san.clean(f"open {t}/runs/run1/public/ok.txt now")
    assert "<PROTECTED>" not in other and "ok.txt" in other
    assert san.clean(f"open {t}/phi2/x") != "open <PROTECTED>"


def test_symlinked_root_realpath_is_masked_too(tmp_path):
    t = tmp_path.resolve()
    (t / "real" / "sub").mkdir(parents=True)
    os.symlink(t / "real", t / "link")
    cfg = load_cfg(t, f'[protected_paths]\nroots = ["{t}/link"]\n')
    san = Sanitizer.from_config(cfg)
    assert san.clean(f"a {t}/link/sub/f\there") == "a <PROTECTED>\there"
    assert san.clean(f"a {t}/real/sub/f\there") == "a <PROTECTED>\there"


def test_config_sanitize_patterns(tmp_path):
    cfg = load_cfg(tmp_path, "[sanitize]\npatterns = ['TICKET-\\d+ => <TICKET>']\n")
    san = Sanitizer.from_config(cfg)
    assert san.clean("see TICKET-77 now") == "see <TICKET> now"


def test_pack_by_path_and_pack_order(tmp_path):
    pack = tmp_path / "mine.toml"
    pack.write_text("[pack]\nname = 'mine'\nidentifiers = ['FAKEID\\d+ => <MYID>']\n"
                    "positions = ['QQ\\d+ => <MYPOS>']\n")
    san = Sanitizer.from_config(load_cfg(tmp_path, f'[sanitize]\npacks = ["{pack}"]\n'))
    assert san.clean("FAKEID12 QQ34") == "<MYID> <MYPOS>"
    assert san.clean("FAKEID12 QQ34", table=True) == "<MYID> QQ34"
    assert san.clean("chr1:1234567") == "chr1:1234567"  # genomics is not loaded


# --- names --------------------------------------------------------------------------------------

def test_name_tokens_and_stop_words():
    toks = sanitize.name_tokens(MADE_UP_RUNS)
    assert {"ZedRun_77", "ZedStudy9", "QQSAMP", "ALPHA", "Quux_Case_B"} <= toks
    low = {t.lower() for t in toks}
    assert not low & {"analysis", "star", "aligned", "sortedbycoord", "bam"}
    assert not any(t.isdigit() or len(t) < 4 for t in toks)


def test_placeholder_words_never_become_name_tokens():
    toks = sanitize.name_tokens(["1\t/x/sampleid/NAME/Bamfile/CLINICALPATH/real_Thing9"])
    assert {t.lower() for t in toks} == {"real_thing9", "real", "thing9"}


def test_date_is_a_placeholder_word(tmp_path):
    # the dates pack writes <DATE>: a names file with a path part `date` must not turn it into
    # another placeholder (`<<NAME>>`)
    p = tmp_path / "runs.tsv"
    p.write_text("1\t/x/date/FAKE-PT-0001.bam\n")
    san = Sanitizer.from_config(config.Config(packs=["genomics", "dates"]), [str(p)])
    assert "date" not in {t.lower() for t in san.tokens}
    assert san.clean("seen 2024-03-05 ok") == "seen <DATE> ok"


def test_names_file_without_token_fails_closed(tmp_path):
    p = tmp_path / "empty.tsv"
    p.write_text("1\t/x/bam/sampleid\nno slash here at all\n")
    with pytest.raises(SanitizerError):
        Sanitizer.from_config(config.Config(), [str(p)])


def test_names_file_missing_fails_closed(tmp_path):
    with pytest.raises(SanitizerError):
        Sanitizer.from_config(config.Config(), [str(tmp_path / "nope.tsv")])


def test_extra_names_from(tmp_path):
    san = Sanitizer.from_config(config.Config(), [names_file(tmp_path)])
    assert san.clean("run ZedRun_77 ok") == "run <NAME> ok"


# --- fail closed --------------------------------------------------------------------------------

@pytest.mark.parametrize("rule", [
    "no separator here",
    "(unclosed => <X>",
    "a* => <EMPTYMATCH>",
    "abc => lowercase",
    " => <X>",
])
def test_bad_pattern_fails_closed(tmp_path, rule):
    cfg = config.Config(sanitize_patterns=[rule])
    with pytest.raises(SanitizerError):
        Sanitizer.from_config(cfg)


@pytest.mark.parametrize("text", [
    "",                                            # no [pack]
    "[pack]\nbogus = 1\n",                         # unknown key
    "[pack]\nidentifiers = 'x => <X>'\n",          # not a list
    "[pack]\nidentifiers = ['(( => <X>']\n",       # does not compile
    "[pack\n",                                     # does not parse
    "[[pack]]\n",                                  # unsupported TOML
])
def test_bad_pack_fails_closed(tmp_path, text):
    p = tmp_path / "bad.toml"
    p.write_text(text)
    with pytest.raises(SanitizerError):
        Sanitizer.from_config(config.Config(packs=[str(p)]))


def test_missing_and_odd_pack_names_fail_closed(tmp_path):
    for name in ("nonesuch", "..", "a b", str(tmp_path / "missing.toml")):
        with pytest.raises(SanitizerError):
            Sanitizer.from_config(config.Config(packs=[name]))


def test_config_problem_fails_closed():
    with pytest.raises(SanitizerError):
        Sanitizer.from_config(config.Config(problem="broken"))


def test_second_pass_change_is_withheld():
    san = Sanitizer.from_config(config.Config(sanitize_patterns=["X => <XX>"]))
    assert san.clean("an X here") == WITHHELD


def test_exception_is_withheld(genomics, monkeypatch):
    def boom(line, table):
        raise RuntimeError("fault")
    monkeypatch.setattr(genomics, "_mask", boom)
    assert genomics.clean("anything") == WITHHELD


def test_fmt_n_never_prints_five_digits():
    assert [sanitize.fmt_n(n) for n in (0, 9999, 10000, 123456, 999999, 1000000, 98765432)] == \
        ["0", "9999", "10.0k", "123.5k", "1000.0k", "1.0M", "98.8M"]


# --- streams ------------------------------------------------------------------------------------

def test_filter_stream_counts_cr_and_binary(genomics):
    data = (b"plain line\r\nread A00123:45:HABCDEFXX:1:1101:12345:6789\rprogress 1234567\n"
            b"bad \xff\xfe bytes\nno newline at end")
    out = io.StringIO()
    lines, changed = sanitize.filter_stream(genomics, io.BytesIO(data), out)
    assert out.getvalue().split("\n") == [
        "plain line", "read <READ>", "progress <NUM>", "bad �� bytes", "no newline at end", ""]
    assert (lines, changed) == (5, 2)


def test_filter_stream_table_mode(genomics):
    out = io.StringIO()
    sanitize.filter_stream(genomics, io.BytesIO(b"a\t1234567\tx.bam\n"), out, table=True)
    assert out.getvalue() == "a\t1234567\t<BAMFILE>\n"


# --- idempotence on random made-up lines --------------------------------------------------------

PIECES = [
    "P-9990001-T01-IM6", "C-ABC123-L001", "s_C_XYZ789_P1", "AB123456-T", "DonorFake-1", "x.bam",
    "slice.bam", "FAKE-PT-0001.fastq.gz", "A00123:45:HABCDEFXX:1:1101:12345:6789/1", "chr1:1234567",
    "7:100-200", "12,345,678", "98765", "1234", "\t", " ", "/data/fake/x", "/tmp/inputs/patient/a",
    "ZedRun_77", "alpha", "QQSAMP", "<NAME>", "<PROTECTED>", "<LOCUS>", "=", ",", ";", "(", ")",
    "1_1234_A_C", "m54012_190101_000000/12345/ccs", "name", "read", "locus", ".", "-", "_", ":", "/",
]


@pytest.mark.parametrize("table", [False, True])
def test_idempotence_on_random_lines(msk, table):
    rng = random.Random(20260211)
    for _ in range(600):
        line = "".join(rng.choice(PIECES) for _ in range(rng.randint(1, 9)))
        once = msk.clean(line, table=table)
        assert msk.clean(once, table=table) == once, line


# --- the command --------------------------------------------------------------------------------

def test_selftest_exits_zero(tmp_path):
    r = run_cli(tmp_path, ["--selftest"])
    assert r.returncode == 0, r.stdout
    assert b"0 failed" in r.stdout


def test_selftest_in_process(capsys):
    assert sanitize.main(["--selftest"]) == 0
    assert "0 failed" in capsys.readouterr().out


def test_cli_end_to_end(tmp_path):
    t = tmp_path.resolve()
    (t / "phi").mkdir()
    cfg_text = (f'[protected_paths]\nroots = ["{t}/phi"]\n'
                '[sanitize]\npacks = ["genomics", "msk"]\n')
    stdin = (f"open {t}/phi/FAKE-PT-0001.bam\n"
             "sample P-9990001-T01-IM6 at chr1:1234567\r\n"
             "reads 12,345,678 total\n")
    r = run_cli(t, [], stdin, cfg_text)
    assert r.returncode == 0
    out = r.stdout.decode()
    assert out.splitlines()[0].startswith("sanitizer on: name tokens=0 ")
    assert "open <PROTECTED>" in out
    assert "sample <SAMPLEID> at <LOCUS>" in out
    assert "reads <NUM> total" in out
    assert "FAKE-PT-0001" not in out and "9990001" not in out
    assert out.splitlines()[-1] == "sanitizer done: lines=3 changed=3"


def test_cli_table_and_names_from(tmp_path):
    nf = names_file(tmp_path)
    r = run_cli(tmp_path, ["--table", "--names-from", nf], "12\t3456\tZedRun_77\t1234567\n",
                cfg_text="[sanitize]\ntable = true\n")
    out = r.stdout.decode().splitlines()
    assert r.returncode == 0
    assert out[0].endswith("mode=table")
    assert out[1] == "12\t3456\t<NAME>\t1234567"


def test_cli_check_files(tmp_path):
    f = tmp_path / "in.txt"
    f.write_text("a 1234567\nplain\n")
    r = run_cli(tmp_path, ["--check", str(f)])
    assert r.returncode == 0
    assert r.stdout.decode().strip() == "check file 1: lines=2 changed=1"
    r = run_cli(tmp_path, ["--check-table", str(f)], cfg_text="[sanitize]\ntable = true\n")
    assert r.stdout.decode().strip() == "check file 1: lines=2 changed=0"
    # off by default: the operator's choice
    r = run_cli(tmp_path, ["--check-table", str(f)])
    assert r.returncode == 2 and b"[sanitize] table = true" in r.stderr
    r = run_cli(tmp_path, ["--check", str(tmp_path / "missing")])
    assert r.returncode == 1 and str(tmp_path) not in r.stdout.decode()


@pytest.mark.parametrize("args", [["--bogus"], ["--names-from"], ["--check"], ["stray"],
                                  ["--selftest", "--table"]])
def test_cli_bad_args_exit_two(tmp_path, args):
    r = run_cli(tmp_path, args)
    assert r.returncode == 2
    assert b"usage:" in r.stderr


def _exits_three_without_reading_stdin(tmp_path, args, env):
    """Start the command with a stdin that never closes: if it read stdin it would hang."""
    p = subprocess.Popen([sys.executable, "-m", "phiward", "sanitize"] + args,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env=env, cwd=str(tmp_path))
    try:
        code = p.wait(timeout=30)
        out = p.stdout.read().decode()
    finally:
        p.kill()
        for s in (p.stdin, p.stdout, p.stderr):
            s.close()
    assert code == 3
    assert "sanitizer on" not in out
    assert str(tmp_path) not in out
    return out


def test_exit_three_on_bad_config(tmp_path):
    env = make_env(tmp_path, "[protected_paths]\nbogus = 1\n")
    _exits_three_without_reading_stdin(tmp_path, [], env)


def test_exit_three_on_missing_config_file(tmp_path):
    env = make_env(tmp_path)
    env["PHIWARD_CONFIG"] = str(tmp_path / "missing.toml")
    _exits_three_without_reading_stdin(tmp_path, [], env)


def test_exit_three_on_bad_names_file(tmp_path):
    env = make_env(tmp_path)
    _exits_three_without_reading_stdin(tmp_path, ["--names-from", str(tmp_path / "nope.tsv")], env)
    empty = tmp_path / "empty.tsv"
    empty.write_text("nothing useful\n")
    _exits_three_without_reading_stdin(tmp_path, ["--names-from", str(empty)], env)


def test_exit_three_on_bad_config_names_file(tmp_path):
    env = make_env(tmp_path, f'[sanitize]\nnames_from = ["{tmp_path}/nope.tsv"]\n')
    _exits_three_without_reading_stdin(tmp_path, [], env)


def test_exit_three_on_bad_pack_and_pattern(tmp_path):
    env = make_env(tmp_path, '[sanitize]\npacks = ["nonesuch"]\n')
    _exits_three_without_reading_stdin(tmp_path, [], env)
    env = make_env(tmp_path, "[sanitize]\npatterns = ['(( => <X>']\n")
    _exits_three_without_reading_stdin(tmp_path, [], env)


def test_cli_never_echoes_input_on_failure(tmp_path):
    env = make_env(tmp_path, '[sanitize]\npacks = ["nonesuch"]\n')
    r = run_cli(tmp_path, [], "FAKE-PT-0001 P-9990001-T01-IM6\n", env=env)
    assert r.returncode == 3
    assert b"FAKE-PT-0001" not in r.stdout + r.stderr


@pytest.mark.parametrize("src", [
    "x \x1b[31mFAKE-\x1b[0mPT-0042.bam y",          # a color code inside the name
    "x FAKE​-PT-0042.bam y",                    # a zero-width space
    "x ＦＡＫＥ-PT-0042.bam y",      # full-width letters
    "x \x1b]0;t\x07FAKE-PT-0042 y",                  # a title escape before it
])
def test_entry_names_are_masked_through_escapes_and_lookalikes(src):
    san = Sanitizer(entries={"fake-pt-0042.bam", "fake-pt-0042"})
    out = san.clean(src)
    assert "PT-0042" not in out and "\x1b" not in out and "<ENTRY>" in out


# --- the label of each built-in rule: identifier or detail (the prompt scan) ---------------------
# Every built-in pack is listed with the placeholders it labels detail: a new pack must say.
DETAIL_LABELS = {"genomics": {"<BAMFILE>", "<READ>"}, "msk": set(), "dates": set()}


def test_every_built_in_rule_has_a_label():
    folder = Path(sanitize.__file__).with_name("packs")
    assert {p.stem for p in folder.glob("*.toml")} == set(DETAIL_LABELS)
    for name, want in DETAIL_LABELS.items():
        pack = sanitize.load_pack(name)
        assert pack.detail == want, name
        written = {r for _rx, r in pack.paths + pack.identifiers}
        assert pack.detail <= written, name


def _pack_file(tmp_path, body):
    p = tmp_path / "mine.toml"
    p.write_text("[pack]\n" + body)
    return str(p)


def test_detail_naming_a_placeholder_the_pack_does_not_write_is_refused(tmp_path):
    for body in ("identifiers = ['ZQX\\d+ => <BAR>']\ndetail = [\"<FOO>\"]\n",
                 "identifiers = ['ZQX\\d+ => <BAR>']\ndetail = \"<BAR>\"\n",
                 # a positions placeholder is no paths or identifiers rule's
                 "positions = ['ZQX\\d+ => <BAR>']\ndetail = [\"<BAR>\"]\n"):
        with pytest.raises(SanitizerError) as exc:
            sanitize.load_pack(_pack_file(tmp_path, body))
        assert "'detail'" in str(exc.value) and "unknown key" not in str(exc.value)


def test_a_pack_file_detail_does_not_drop_its_rule(tmp_path):
    f = _pack_file(tmp_path, "identifiers = ['ZQX\\d+ => <BAMFILE>']\ndetail = [\"<BAMFILE>\"]\n")
    assert sanitize.load_pack(f).detail == set()
    cfg = load_cfg(tmp_path, f'[sanitize]\npacks = ["{f}"]\n')
    san = Sanitizer.from_config(cfg, identifiers_only=True)
    assert san.clean("see ZQX123 here") == "see <BAMFILE> here"


def _raises(*_a, **_k):
    raise AssertionError("must not run")


def test_identifiers_only_drops_details_positions_names_and_entries(tmp_path, monkeypatch):
    nf = names_file(tmp_path)
    cfg = load_cfg(tmp_path, f'[sanitize]\npacks = ["genomics", "msk"]\nnames_from = ["{nf}"]\n')
    monkeypatch.setattr(sanitize.inventory, "build", _raises)
    monkeypatch.setattr(sanitize, "_read_names_file", _raises)
    san = Sanitizer.from_config(cfg, identifiers_only=True)
    assert san.entries is None and san.re_names is None and not san.pos_rules
    for line in ("why does Sample7.sorted.bam fail at chr1:1234567",
                 "read A00123:8:H5:1:1101:1000:2000 has 12345678 bases"):
        assert san.clean(line) == sanitize.normalize(line)
    assert san.clean("P-9990001-T01-IM6") == "<SAMPLEID>"
    # output masking is unchanged
    out = Sanitizer.from_config(load_cfg(tmp_path, '[sanitize]\npacks = ["genomics"]\n'))
    assert "<BAMFILE>" in out.clean("Sample7.sorted.bam")
    assert "<LOCUS>" in out.clean("chr1:1234567")


def test_identifiers_only_uses_the_configured_roots_only(tmp_path):
    root = tmp_path / "phi"
    root.mkdir()
    cfg = load_cfg(tmp_path, f'[protected_paths]\nroots = ["{root}"]\n')
    cfg.derived_roots.append(str(tmp_path / "derivedgit"))
    san = Sanitizer.from_config(cfg, identifiers_only=True)
    assert san.clean(f"{root}/FAKE-PT-0001/x") != f"{root}/FAKE-PT-0001/x"
    lock = f"{tmp_path}/derivedgit/index.lock"
    assert san.clean(lock) == lock
