"""`phiward run` ends with one note that counts the placeholders in the lines the agent was shown
(issue #5), so a run whose rules masked nothing can be told from a run over clean data. The note
is computed from the shown lines only: lines past the cap, collapsed repeats and copies are not
counted. Made-up data only (FAKE-PT-0099 and up are never in the test tree)."""

import io
import os
import re
import stat
import sys
from pathlib import Path

import pytest

from phiward import copying, run, sanitize
from helpers import needs_confine

PY = sys.executable
IDNOTE = "no identifier placeholder"


def user_cfg(extra):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + extra)


def subjects():
    user_cfg("[sanitize]\npatterns = ['FAKE-PT-\\d{4} => <SUBJECT>']\n")


def go(tree, lines):
    """Run a made-up program that prints `lines`; the output and its exit code."""
    code = "import sys\nsys.stdout.write(" + repr("".join(l + "\n" for l in lines)) + ")"
    out = io.StringIO()
    rc = run.execute(["--", PY, "-c", code], str(tree / "repo"), dict(os.environ), out)
    return rc, out.getvalue()


def note(text):
    found = [l for l in text.splitlines() if l.startswith(("[placeholders", "[no placeholder"))]
    assert len(found) <= 1, text
    return found[0] if found else ""


def shown(text):
    return [l for l in text.splitlines()
            if not l.startswith(("[", "run done:"))]


# --- the note's text (no confinement needed) --------------------------------------------------------

def test_placeholder_note_text():
    pn = sanitize.placeholder_note
    ids = {"<SUBJECT>"}
    assert pn({}, 0, 19, ids) == ""
    assert pn({"<SUBJECT>": 3, "<BAMFILE>": 1}, 0, 4, ids) == \
        "[placeholders in the lines shown: 3 <SUBJECT>, 1 <BAMFILE>]"
    assert pn({"<NUM>": 25}, 0, 26, ids).startswith(
        "[placeholders in the lines shown: 25 <NUM>; no identifier placeholder in the 26 lines shown")
    assert pn({}, 0, 20, ids).startswith("[no placeholder in the 20 lines shown")
    assert pn({}, 3, 5, ids) == "[placeholders in the lines shown: 3 lines withheld by the sanitizer]"
    assert pn({"<A>": 12345, "<B>": 12345, "<C>": 1}, 0, 9, ids) == \
        "[placeholders in the lines shown: 12.3k <A>, 12.3k <B>, 1 <C>]"
    for t in (pn({}, 0, 20, ids), pn({"<NUM>": 25}, 0, 26, ids)):
        assert "tell the operator" in t and "phiward doctor" in t


def test_placeholder_sets(tree):
    from phiward import config
    subjects()
    user_cfg('[remote]\nhosts = ["hpc-test"]\nroots = ["/data/protected"]\n')
    san = sanitize.Sanitizer.from_config(config.load(str(tree / "repo")))
    run.add_remote_roots(san, config.load(str(tree / "repo")))
    assert {"<SUBJECT>", "<NUM>", "<BAMFILE>", "<PROTECTED>", "<ENTRY>", "<NAME>"} <= san.placeholders()
    ident = san.identifier_placeholders()
    assert {"<SUBJECT>", "<PROTECTED>", "<ENTRY>", "<NAME>"} <= ident
    assert not ({"<NUM>", "<BAMFILE>", "<LOCUS>", "<READ>"} & ident)


# --- through a real run ---------------------------------------------------------------------------

@needs_confine
def test_note_counts_each_kind_in_the_shown_lines(tree):
    subjects()
    rc, out = go(tree, [f"id FAKE-PT-0099 line {i}" for i in range(3)] + ["file Sample7.sorted.bam", "end"])
    assert rc == 0, out
    lines = out.splitlines()
    assert lines[-2] == "[placeholders in the lines shown: 3 <SUBJECT>, 1 <BAMFILE>]", out
    assert lines[-1] == "run done: exit=0"


@needs_confine
def test_note_equals_the_placeholders_in_the_text_above_it(tree):
    import random
    subjects()
    rnd = random.Random(5)
    parts = ["FAKE-PT-0{}".format(100 + i) for i in range(30)] + ["x.bam", "y.bam", "word", "chr1:1234567"]
    lines = [f"{i:02d} " + " ".join(rnd.choice(parts) for _ in range(3)) for i in range(40)] + ["end"]
    rc, out = go(tree, lines)
    want = {}
    for l in shown(out):
        for p in re.findall(r"<[A-Z][A-Z0-9_]*>", l):
            want[p] = want.get(p, 0) + 1
    got = dict((p, int(n)) for n, p in re.findall(r"(\d+) (<[A-Z][A-Z0-9_]*>)", note(out)))
    assert got == want, (got, want, out)


@needs_confine
def test_lines_past_the_cap_are_not_counted(tree, broker):
    subjects()
    user_cfg("[broker]\nmax_output_lines = 25\n")
    rc, out = go(tree, [f"plain {i}" for i in range(25)] + [f"id FAKE-PT-0{101 + i}" for i in range(10)])
    assert "<SUBJECT>" not in note(out), out
    assert note(out).startswith("[no placeholder in the 25 lines shown"), out


@needs_confine
def test_collapsed_repeats_are_not_counted(tree):
    subjects()
    rc, out = go(tree, ["id FAKE-PT-0102"] * 30 + ["end"])
    assert "[29 more identical line(s)]" in out, out
    assert note(out) == "[placeholders in the lines shown: 1 <SUBJECT>]", out


@needs_confine
def test_withheld_lines_are_their_own_kind(tree, monkeypatch):
    real = sanitize.Sanitizer.clean

    def clean(self, line, table=False):
        return sanitize.WITHHELD if "HOLD" in line else real(self, line, table)
    monkeypatch.setattr(sanitize.Sanitizer, "clean", clean)
    lines = []
    for i in range(25):
        lines.append(f"HOLD {i}" if i in (3, 9, 15) else f"plain {i}")
    rc, out = go(tree, lines)
    assert "3 lines withheld by the sanitizer" in note(out), out
    assert IDNOTE in note(out), out


@needs_confine
@pytest.mark.parametrize("n,want", [(19, False), (20, True)])
def test_identifier_note_needs_20_shown_lines(tree, n, want):
    rc, out = go(tree, [f"plain {i}" for i in range(n - 1)] + ["end"])
    assert (IDNOTE in note(out) or note(out).startswith("[no placeholder")) is want, out


@needs_confine
def test_genomics_alone_over_sample_ids_warns(tree):
    rc, out = go(tree, [f"sample P-99900{i:02d}-T01-IM6 line {i}" for i in range(25)] + ["end"])
    assert "P-<NUM>-T01-IM6" in out, out
    assert note(out).startswith("[placeholders in the lines shown: 25 <NUM>; no identifier "
                                "placeholder in the 26 lines shown"), out


@needs_confine
def test_only_config_placeholders_are_counted(tree):
    subjects()
    rc, out = go(tree, [f"{i:02d} <NA> <HTML> <FAKEPLACE>" for i in range(25)])
    assert note(out).startswith("[no placeholder in the 25 lines shown"), out
    rc, out = go(tree, ["literal <SUBJECT>", "end"])
    assert note(out) == "[placeholders in the lines shown: 1 <SUBJECT>]", out


def test_remote_run_reports_counts(tree, monkeypatch):
    user_cfg('[remote]\nhosts = ["hpc-test"]\ncommands = ["wc"]\nroots = ["/data/protected"]\n'
             "use_shared_connection = false\n")
    fake = tree / "pub" / "fake-ssh"
    fake.write_text("#!/bin/sh\necho '42 /data/protected/x.bam'\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(copying, "system_program", lambda name: str(fake))
    out = io.StringIO()
    rc = run.execute(["--remote", "hpc-test", "--", "wc", "-l", "x"], str(tree / "repo"),
                     dict(os.environ), out)
    assert rc == 0, out.getvalue()
    assert note(out.getvalue()) == "[placeholders in the lines shown: 1 <PROTECTED>]", out.getvalue()


@needs_confine
def test_copy_prints_no_note(tree):
    # green before and after: copy masks only tool messages, so it gets no note (decided)
    out = io.StringIO()
    code = copying.execute([str(tree / "phi" / "FAKE-PT-0001.bam"), str(tree / "phi" / "c") + "/"],
                           str(tree / "repo"), dict(os.environ), out)
    assert code == 0 and note(out.getvalue()) == "", out.getvalue()


@needs_confine
def test_broker_log_has_the_counts(tree, monkeypatch):
    subjects()
    logged = []
    monkeypatch.setattr(run.log, "fn", logged.append, raising=False)
    go(tree, [f"id FAKE-PT-0099 line {i}" for i in range(3)] + ["file Sample7.sorted.bam", "end"])
    assert any(l.endswith("placeholders shown: 3 <SUBJECT>, 1 <BAMFILE>") for l in logged), logged
