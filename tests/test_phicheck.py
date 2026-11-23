"""The masking check (`phicheck`): the user's own rules mask their made-up examples, and a made-up
path below each root comes out masked, at doctor, launch and the broker's start.

Every fault is made through the config (a pattern edited, a pack file weakened, a remote root
written so the sanitizer does not match it), so it reaches the broker and launch as it would in
use. Made-up values only.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from phiward import config, inventory, phicheck, promptscan, sanitize, wholetool

SRC = str(Path(__file__).resolve().parents[1] / "src")
LAUNCH = ("import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; "
          "from phiward.cli import main; sys.exit(main())")

PATTERN = r"FAKE-PT-\d{4} => <SUBJECT>"
EDITED = r"FAKE-PT-\d{5} => <SUBJECT>"


def ag(args, cwd, timeout=60):
    e = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([sys.executable, "-c", LAUNCH] + args, cwd=str(cwd), capture_output=True,
                       text=True, env=e, timeout=timeout, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


def user_cfg(extra):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + extra)


def lst(vals):
    return "[" + ", ".join(f"'{v}'" for v in vals) + "]"  # TOML literal strings


def sanitize_cfg(patterns=(), examples=(), packs=()):
    user_cfg("[sanitize]\n" + (f"patterns = {lst(patterns)}\n" if patterns else "")
             + (f"examples = {lst(examples)}\n" if examples else "")
             + (f"packs = {lst(packs)}\n" if packs else ""))


def pack_file(tree, *rules, name="fake-pack.toml"):
    p = tree / "home" / name
    p.write_text("[pack]\nidentifiers = [" + ", ".join(f"'{r}'" for r in rules) + "]\n")
    return str(p)


def check(tree):
    repo = str(tree / "repo")
    return phicheck.check(config.load(repo), repo)


def secrets_of(tree, *more):
    """What the check's words must never hold: the roots, the patterns, the examples."""
    return [str(tree / "phi"), "runs/", "FAKE-PT-", r"\d{4}", r"\d{5}"] + list(more)


def assert_never_shown(text, words):
    for w in words:
        assert w not in text, (w, text)


# --- 1. user patterns and their examples -----------------------------------------------------

def test_a_pattern_with_its_example_passes(tree):
    sanitize_cfg([PATTERN], ["FAKE-PT-0001"])
    r = check(tree)
    assert r.failed == [] and r.notes == []
    assert r.summary == "masking check: ok (1 example, 2 roots; 1 of 1 rules tested)"


def test_an_edited_pattern_fails_and_names_the_entry_only(tree):
    sanitize_cfg([EDITED], ["FAKE-PT-0001"])
    r = check(tree)
    assert r.failed and "[sanitize] examples entry 1" in r.failed[0], r
    assert any("[sanitize] patterns entry 1" in n for n in r.notes), r
    assert_never_shown(" ".join(r.failed + r.notes + [r.summary]), secrets_of(tree))


def test_a_pattern_with_no_example_gets_a_note(tree):
    sanitize_cfg([PATTERN, r"ZQX-\d{3} => <CODE>"], ["FAKE-PT-0001"])
    r = check(tree)
    assert r.failed == []
    assert r.notes == ["[sanitize] patterns entry 2 matches no entry of [sanitize] examples, so "
                       "it is not tested"]
    assert "1 of 2 rules tested" in r.summary


def test_the_key_in_a_repo_file_is_ignored(tree):
    (tree / "repo" / ".phiward.toml").write_text('[sanitize]\nexamples = ["FAKE-PT-0001"]\n')
    cfg = config.load(str(tree / "repo"))
    assert "sanitize.examples" in cfg.ignored and cfg.sanitize_examples == []


def test_examples_load_from_the_user_config(tree):
    sanitize_cfg([PATTERN], ["FAKE-PT-0001", "FAKE-PT-0002"])
    assert config.load(str(tree / "repo")).sanitize_examples == ["FAKE-PT-0001", "FAKE-PT-0002"]


# --- 2. a pack file, and "fully masked" in both modes -------------------------------------------

def test_a_pack_file_that_masks_part_of_its_example_fails_and_names_no_path(tree):
    path = pack_file(tree, r"\d{7} => <NUM>")
    sanitize_cfg(examples=["P-9990001-T01-IM6"], packs=[path])
    r = check(tree)
    assert r.failed and "[sanitize] examples entry 1" in r.failed[0], r
    assert "pack file 1, rule 1" in r.failed[0], r
    assert_never_shown(" ".join(r.failed + r.notes + [r.summary]),
                       secrets_of(tree, path, "fake-pack", "9990001", "T01", "IM6"))


def test_a_pack_file_that_masks_its_example_passes(tree):
    path = pack_file(tree, r"P-\d{7}-T\d{2}-IM\d => <SAMPLEID>")
    sanitize_cfg(examples=["P-9990001-T01-IM6"], packs=[path])
    r = check(tree)
    assert r.failed == [] and "1 of 1 rules tested" in r.summary, r


@pytest.mark.parametrize("out,ok", [
    ("x <SAMPLEID> y", True),
    ("x <LOCUS>/<NUM> y", True),
    (sanitize.WITHHELD, True),
    ("x <PROTECTED>", True),            # a path mask runs to the end of the line
    ("x P-<NUM>-T01-IM6 y", False),
    ("x FAKE-PT-0001 y", False),
    ("x <SUBJECT>7 y", False),
])
def test_fully_masked_means_only_placeholders_are_left(out, ok):
    assert phicheck.fully_masked(out) is ok


def test_table_mode_is_checked_too(tree, monkeypatch):
    # a value that text mode masks and table mode keeps (a number) is not fully masked
    san = sanitize.Sanitizer.from_config(config.load(str(tree / "repo")))
    assert phicheck.fully_masked(san.clean("x chr7:55249071 y"))
    assert not phicheck.fully_masked(san.clean("x 1234567 y", table=True))
    assert not phicheck.value_masked(san, "1234567")


# --- 3. roots -------------------------------------------------------------------------------

def test_the_roots_and_a_pattern_root_pass(tree):
    r = check(tree)
    assert r.failed == [] and r.notes == []
    assert r.summary == "masking check: ok (2 roots; no rules of your own)"


def test_a_remote_root_the_sanitizer_does_not_match_as_written_fails(tree):
    user_cfg('[remote]\nroots = ["~/fakedata"]\n')
    r = check(tree)
    assert r.failed == ["a made-up path below remote root 1 came out unmasked"], r
    assert_never_shown(" ".join(r.failed), ["fakedata"])


# --- 4. doctor -------------------------------------------------------------------------------

def test_doctor_prints_the_ok_line(tree):
    sanitize_cfg([PATTERN], ["FAKE-PT-0001"])
    _code, out = ag(["doctor"], tree / "repo")
    assert "masking check: ok (1 example, 2 roots; 1 of 1 rules tested)" in out, out


def test_doctor_warns_and_headless_lists_the_failure(tree):
    sanitize_cfg([EDITED], ["FAKE-PT-0001"])
    _code, out = ag(["doctor"], tree / "repo")
    assert "WARNING: masking check: [sanitize] examples entry 1 is not fully masked" in out, out
    assert "NOTE: masking check: [sanitize] patterns entry 1 matches no entry" in out, out
    _code, head = ag(["doctor", "--headless"], tree / "repo")
    assert "- masking check: [sanitize] examples entry 1 is not fully masked" in head, head
    assert_never_shown(out + head, ["FAKE-PT-0001", r"\d{5}"])


# --- 5. launch -------------------------------------------------------------------------------

def _build(tree, server=False):
    env = dict(os.environ)
    return wholetool.build(["/bin/echo", "x"], str(tree / "repo"), env,
                           wholetool.ADAPTERS["generic"], server=server)


def _try_build(tree, server=False):
    try:
        cmd, *_rest = _build(tree, server=server)
    except wholetool.LaunchError as exc:
        return str(exc)
    from phiward import confine
    confine.release_profile(cmd)
    return ""


def test_launch_refuses_on_a_failure_before_any_run_folder(tree):
    sanitize_cfg([EDITED], ["FAKE-PT-0001"])
    folder = wholetool.tool_folder(wholetool.ADAPTERS["generic"], dict(os.environ))
    with pytest.raises(wholetool.LaunchError) as exc:
        _build(tree)
    msg = str(exc.value)
    assert msg.startswith("the masking check failed: [sanitize] examples entry 1"), msg
    assert msg.endswith("; run phiward doctor"), msg
    assert not os.path.exists(folder)
    assert_never_shown(msg, secrets_of(tree))


def test_launch_is_not_stopped_by_the_check_on_a_pass(tree):
    sanitize_cfg([PATTERN], ["FAKE-PT-0001"])
    assert "masking check" not in _try_build(tree)


def test_a_wrapped_server_is_not_checked(tree):
    sanitize_cfg([EDITED], ["FAKE-PT-0001"])
    assert "masking check" not in _try_build(tree, server=True)


# --- 6. the broker -----------------------------------------------------------------------------

REFUSED = "refused: the masking check failed when the broker started"


def test_the_broker_refuses_while_the_check_fails_and_runs_once_fixed(tree, broker):
    cfg = Path(os.environ["PHIWARD_CONFIG"])
    good = cfg.read_text()
    sanitize_cfg([EDITED], ["FAKE-PT-0001"])
    broker()
    _code, out = ag(["run", "--", "ls", str(tree / "repo")], tree / "repo")
    assert REFUSED in out and "phiward doctor" in out, out
    assert "README.md" not in out
    assert_never_shown(out, secrets_of(tree))
    cfg.write_text(good)
    sanitize_cfg([PATTERN], ["FAKE-PT-0001"])
    broker()
    _code, out = ag(["run", "--", "ls", str(tree / "repo")], tree / "repo")
    assert REFUSED not in out and "README.md" in out, out


# --- 8. fail closed ----------------------------------------------------------------------------

def test_a_pack_file_that_cannot_be_used_makes_launch_refuse(tree):
    path = tree / "home" / "broken-pack.toml"
    path.write_text('[pack]\nidentifiers = ["(FAKE => <X>"]\n')
    sanitize_cfg(packs=[str(path)])
    r = check(tree)
    assert r.failed == ["the check could not run (the sanitizer cannot be built)"], r
    with pytest.raises(wholetool.LaunchError) as exc:
        _build(tree)
    assert "the masking check failed" in str(exc.value)
    assert_never_shown(str(exc.value), [str(path), "broken-pack"])


def test_a_pack_file_that_cannot_be_used_makes_the_broker_refuse(tree, broker):
    path = tree / "home" / "broken-pack.toml"
    path.write_text('[pack]\nidentifiers = ["(FAKE => <X>"]\n')
    sanitize_cfg(packs=[str(path)])
    broker()
    _code, out = ag(["run", "--", "ls", str(tree / "repo")], tree / "repo")
    assert REFUSED in out, out


def test_an_exception_inside_the_check_is_a_failure(tree, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("FAKE-PT-0001")
    monkeypatch.setattr(promptscan, "verdict_with", boom)
    r = check(tree)
    assert r.failed == ["the check could not run"], r


# --- 9. the prompt scan's split keeps its verdicts ----------------------------------------------

def test_the_split_gives_the_same_verdicts(tree):
    from test_promptscan import CORPUS
    sanitize_cfg([r"ZQX-FAKE\d+ => <CODE>"], packs=["genomics", "msk"])
    repo = str(tree / "repo")
    cfg = config.load(repo)
    san = promptscan.prompt_sanitizer(cfg)
    lines = CORPUS + [f"cat {tree}/phi/FAKE-PT-0001.bam", "check P-9990001-T01-IM6",
                      "the code ZQX-FAKE7 failed", "is s_C_FAKE01_P001_d done?"]
    for t in lines:
        assert promptscan.verdict_with(san, cfg, t, repo) == \
            promptscan.prompt_verdict(t, cfg, repo), t
    assert sum(promptscan.prompt_verdict(t, cfg, repo).blocked for t in lines) == 4


# --- 10. speed, and no walk of the roots ------------------------------------------------------

def test_the_check_is_quick_and_walks_no_root(tree, monkeypatch):
    def no_walk(*_a, **_k):
        raise AssertionError("the masking check walked a root")
    monkeypatch.setattr(inventory, "build", no_walk)
    pats = [rf"ZQ{chr(65 + i)}-\d{{6}} => <CODE>" for i in range(20)]
    exs = [f"ZQ{chr(65 + i)}-{777000 + i}" for i in range(20)]
    roots = ", ".join(f'"{tree}/more{i}"' for i in range(4))
    user_cfg(f"[sanitize]\npatterns = {lst(pats)}\nexamples = {lst(exs)}\n"
             + f"[remote]\nroots = [{roots}]\n")
    cfg = config.load(str(tree / "repo"))
    assert len(cfg.sanitize_patterns) == 20 and len(cfg.sanitize_examples) == 20
    start = time.monotonic()
    r = phicheck.check(cfg, str(tree / "repo"))
    took = time.monotonic() - start
    print(f"masking check: {took * 1000:.0f} ms")
    assert r.failed == [] and "20 of 20 rules tested" in r.summary, r
    assert took < 0.5, took
