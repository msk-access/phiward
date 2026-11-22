"""The prompt scan (promptscan.py): would the sanitizer change the prompt? Every value here is
made up (FAKE-PT-0001, P-9990001-T01-IM6); the user config is a tmp file named by
PHIWARD_CONFIG, with HOME in a tmp folder."""

import os

import pytest

from phiward import config, inventory, promptscan, sanitize

MSK = '[sanitize]\npacks = ["genomics", "msk"]\n'


@pytest.fixture()
def place(tmp_path, monkeypatch):
    """home/ with the root home/data (FAKE-PT-0001.txt in it), and home/repo, the working
    folder, with src/main.py and a link `leak` to the file in the root."""
    t = tmp_path.resolve()
    home = t / "home"
    data = home / "data"
    (data / "FAKE-PT-0001").mkdir(parents=True)
    (data / "FAKE-PT-0001.txt").write_text("SECRET-CONTENT-0001\n")
    repo = home / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "main.py").write_text("print('hi')\n")
    os.symlink(data / "FAKE-PT-0001.txt", repo / "leak")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    def verdict(text, user="", cwd=repo, repo_cfg=None, roots=(data,)):
        cfg_file = t / "user.toml"
        listed = ", ".join(f'"{r}"' for r in roots)
        cfg_file.write_text(f"[protected_paths]\nroots = [{listed}]\n" + user)
        monkeypatch.setenv("PHIWARD_CONFIG", str(cfg_file))
        if repo_cfg is not None:
            (repo / ".phiward.toml").write_text(repo_cfg)
        cfg = config.load(str(cwd))
        return promptscan.prompt_verdict(text, cfg, str(cwd))

    verdict.home, verdict.data, verdict.repo = home, data, repo
    return verdict


ORDINARY = [
    "Add a --verbose flag to the CLI and update the tests",
    "why does pytest fail on test_parse with a KeyError?",
    "see pages 2–3 of the design doc",                      # an en dash (Review 3 H1)
    "why does Sample7.sorted.bam fail at chr1:1234567",     # details, positions (default packs)
    "the run printed 12345678 reads",
    "FAKE-PT-0001",                                         # an entry name alone: not checked
    "rename @src/main.py and fix @pytest.fixture usage; bump @types/node",
    "mail a@b.org about https://x.org/a/b",
    "git status shows src/main.py modified",
]


@pytest.mark.parametrize("text", ORDINARY)
def test_ordinary_prompts_clear(place, text):
    v = place(text)
    assert not v.blocked and v.kinds == () and v.why == ""


def test_pack_ids_and_user_patterns_block(place):
    v = place("check P-9990001-T01-IM6 please", MSK)
    assert v.blocked and v.kinds == ("<SAMPLEID>",)
    assert not place("check P-9990001-T01-IM6 please").blocked  # msk is not a default
    user = "[sanitize]\npatterns = ['ZQX-FAKE\\d+ => <CODE>']\n"
    assert place("see ZQX-FAKE42", user).kinds == ("<CODE>",)
    # a user rule is an identifier whatever its placeholder (Review 3 H2)
    v = place("see ZQX123", "[sanitize]\npatterns = ['ZQX\\d+ => <BAMFILE>']\n")
    assert v.blocked and v.kinds == ("<BAMFILE>",)


def test_dates_block_when_the_dates_pack_is_on(place):
    assert not place("the 2026-11-22 release").blocked
    on = '[sanitize]\npacks = ["genomics", "dates"]\n'
    assert place("the 2026-11-22 release", on).kinds == ("<DATE>",)


def test_a_repo_pattern_does_not_block_and_a_repo_root_does(place):
    pat = "[sanitize]\npatterns = ['ZQX-FAKE\\d+ => <CODE>']\n"
    # [sanitize] patterns are USER_ONLY: a repo file's are ignored
    assert not place("see ZQX-FAKE42", repo_cfg=pat).blocked
    assert place("see ZQX-FAKE42", pat).blocked
    other = place.home / "other"
    other.mkdir()
    v = place(f"open {other}/FAKE-PT-0009/x",
              repo_cfg=f'[protected_paths]\nroots = ["{other}"]\n')
    assert v.blocked and v.kinds == ("<PROTECTED>",)


def test_paths_block_in_every_spelling(place):
    d = place.data
    for text in (f"open {d}/FAKE-PT-0001/x", f"what is in {d}",          # the bare root too
                 "open ~/data/FAKE-PT-0001/x", "open $HOME/data/FAKE-PT-0001/x",
                 "open ${HOME}/data/FAKE-PT-0001/x", "../data/FAKE-PT-0001/x",
                 f'look at @"{d}/x y"', "look at ./leak", "look at (./leak)."):
        v = place(text)
        assert v.blocked and v.kinds == ("<PROTECTED>",), text
    for text in ("open data/FAKE-PT-0001/x", "@data/FAKE-PT-0001.txt", "@data/f.txt#L1-5",
                 "see `data/FAKE-PT-0001/x`:"):
        assert place(text, cwd=place.home).blocked, text


def test_remote_roots_count(place):
    user = '[remote]\nroots = ["/fake/hpc/phi"]\n'
    assert place("cat /fake/hpc/phi/FAKE-PT-0001.bam", user).kinds == ("<PROTECTED>",)


def test_derived_roots_do_not_count(place):
    """A root inside a git work tree makes its .git protected; the scan uses the configured
    roots and patterns only (Review 3 M2, D3)."""
    (place.repo / ".git").mkdir()
    inner = place.repo / "data"
    inner.mkdir()
    v = place("why is .git/index.lock there", roots=(place.data, inner))
    assert not v.blocked
    # the .git is a derived root, which output masking protects
    assert str(place.repo / ".git") in config.load(str(place.repo)).all_roots
    assert place("see data/FAKE-PT-0001/x", roots=(place.data, inner)).blocked


def test_no_names_and_no_inventory(place, monkeypatch, tmp_path):
    names = tmp_path / "names.tsv"
    names.write_text("1\t/x/FAKE-PT-0007/y\n")

    def boom(*_a, **_k):
        raise AssertionError("must not run")

    monkeypatch.setattr(inventory, "build", boom)
    monkeypatch.setattr(sanitize, "_read_names_file", boom)
    v = place("FAKE-PT-0007 and FAKE-PT-0001", f'[sanitize]\nnames_from = ["{names}"]\n')
    assert not v.blocked


def test_fails_closed_with_a_reason(place, monkeypatch, tmp_path):
    missing = tmp_path / "gone.toml"
    v = place("hello", f'[sanitize]\npacks = ["{missing}"]\n')
    assert v.blocked and "gone.toml" in v.why and v.why.endswith("run `phiward doctor`.")
    v = place("hello", "[sanitize\n")
    assert v.blocked and "config" in v.why and v.why.endswith("run `phiward doctor`.")
    v = place("hello", repo_cfg="[sanitize\n")
    assert v.blocked and "repo config" in v.why and v.why.endswith("run `phiward doctor`.")
    v = place("x" * (promptscan.MAX_BYTES + 1))
    assert v.blocked and "too long" in v.why
    monkeypatch.setattr(sanitize.Sanitizer, "clean", lambda *a, **k: 1 / 0)
    v = place("hello")
    assert v.blocked and "could not run" in v.why


def test_withheld_text_blocks(place):
    v = place("see P%2D9990001%2DT01%2DIM6", MSK)
    assert v.blocked and v.kinds


SECRETS = ("FAKE-PT", "9990001", "ZQX", "x y", "2026-11-22", "leak", "fake/hpc")


@pytest.mark.parametrize("text,user", [
    ("check P-9990001-T01-IM6", MSK), ("see ZQX-FAKE42", "[sanitize]\npatterns = ['ZQX-FAKE\\d+ => <CODE>']\n"),
    ("open ~/data/FAKE-PT-0001/x", ""), ('@"{d}/x y"', ""), ("look at ./leak", ""),
    ("the 2026-11-22 release", '[sanitize]\npacks = ["dates"]\n'),
    ("cat /fake/hpc/phi/FAKE-PT-0001.bam", '[remote]\nroots = ["/fake/hpc/phi"]\n'),
    ("see P%2D9990001%2DT01%2DIM6", MSK),
])
def test_kinds_and_why_never_hold_input_text(place, text, user):
    v = place(text.replace("{d}", str(place.data)), user)
    assert v.blocked
    said = v.why + " ".join(v.kinds)
    assert not any(s in said for s in SECRETS) and str(place.data) not in said
