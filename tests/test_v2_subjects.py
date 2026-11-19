"""Subject and sample identifiers (issue #3): `phiward doctor` warns when the user config masks
none (no subject pack, no patterns, no names_from) and does not record `[sanitize] subjects =
"none"`; `--headless` gives a NOTE and stays ready; setup asks. Only the user config decides: a
repo config may add packs (they mask) but never silences the warning. Made-up data only."""

import os
import shutil
from pathlib import Path

import pytest

from phiward import config, doctor, install, sanitize

WARN = "WARNING: your user config enables no pack that masks subject"
SRC = Path(__file__).resolve().parents[1] / "src" / "phiward"


def user_cfg(extra):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + extra)


def repo_cfg(tree, text):
    (tree / "repo" / ".phiward.toml").write_text(text)


def run_doctor(tree, capsys, monkeypatch):
    monkeypatch.chdir(tree / "repo")
    code = doctor.main([])
    return code, capsys.readouterr().out


# --- the config key ---------------------------------------------------------------------------------

def test_subjects_none_loads(tree):
    user_cfg('[sanitize]\nsubjects = "none"\n')
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem, cfg.problem
    assert cfg.sanitize_subjects == "none"


@pytest.mark.parametrize("value", ['"yes"', '"None"', '""', "true", '["none"]'])
def test_subjects_other_values_are_a_problem(tree, value):
    user_cfg(f"[sanitize]\nsubjects = {value}\n")
    cfg = config.load(str(tree / "repo"))
    assert "sanitize.subjects" in cfg.problem, cfg.problem


def test_a_repo_config_cannot_set_subjects(tree):
    repo_cfg(tree, '[sanitize]\nsubjects = "none"\n')
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem, cfg.problem
    assert "sanitize.subjects" in cfg.ignored and cfg.sanitize_subjects == ""


# --- what counts as masking subject identifiers -------------------------------------------------------

def _pack(tree, name, body):
    p = tree / "home" / name
    p.write_text('[pack]\nname = "x"\n' + body)
    return str(p)


@pytest.mark.parametrize("case,want", [
    ("default", False), ("genomics+dates", False), ("msk", True), ("patterns", True),
    ("names_from", True), ("file-ids", True), ("file-positions", False),
    ("copy-genomics", False), ("copy-dates", False),
])
def test_masks_subjects(tree, case, want):
    if case == "genomics+dates":
        user_cfg('[sanitize]\npacks = ["genomics", "dates"]\n')
    elif case == "msk":
        user_cfg('[sanitize]\npacks = ["genomics", "msk"]\n')
    elif case == "patterns":
        user_cfg("[sanitize]\npatterns = ['FAKE-PT-\\d{4} => <SAMPLEID>']\n")
    elif case == "names_from":
        names = tree / "phi" / "names.tsv"
        names.write_text(f"1\t{tree}/phi/FAKE-PT-0001.bam\n")
        user_cfg(f'[sanitize]\nnames_from = ["{names}"]\n')
    elif case == "file-ids":
        p = _pack(tree, "ids.toml", "identifiers = ['FAKE-PT-\\d{4} => <SAMPLEID>']\n")
        user_cfg(f'[sanitize]\npacks = ["genomics", "{p}"]\n')
    elif case == "file-positions":
        p = _pack(tree, "pos.toml", "positions = ['\\d{9} => <NUM>']\n")
        user_cfg(f'[sanitize]\npacks = ["genomics", "{p}"]\n')
    elif case.startswith("copy-"):
        name = case[5:]
        p = tree / "home" / f"my-{name}.toml"
        shutil.copy(SRC / "packs" / f"{name}.toml", p)
        user_cfg(f'[sanitize]\npacks = ["genomics", "{p}"]\n')
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem, cfg.problem
    assert sanitize.masks_subjects(cfg) is want


# --- doctor ---------------------------------------------------------------------------------------

def test_doctor_warns_when_nothing_masks_subjects(tree, capsys, monkeypatch):
    code, out = run_doctor(tree, capsys, monkeypatch)
    line = next((l for l in out.splitlines() if l.startswith(WARN)), "")
    assert line and 'subjects = "none"' in line, out


@pytest.mark.parametrize("extra", [
    '[sanitize]\npacks = ["genomics", "msk"]\n',
    "[sanitize]\npatterns = ['FAKE-PT-\\d{4} => <SAMPLEID>']\n",
    '[sanitize]\nsubjects = "none"\n',
])
def test_doctor_is_quiet_when_the_user_config_masks_or_records_it(tree, capsys, monkeypatch, extra):
    user_cfg(extra)
    code, out = run_doctor(tree, capsys, monkeypatch)
    assert WARN not in out, out


def test_a_repo_pack_does_not_silence_the_warning(tree, capsys, monkeypatch):
    repo_cfg(tree, '[sanitize]\npacks = ["msk"]\n')
    cfg = config.load(str(tree / "repo"))
    assert "msk" in cfg.packs and "msk" not in cfg.user_packs
    san = sanitize.Sanitizer.from_config(cfg)
    assert san.clean("P-0000001-T01-IM6") == "<SAMPLEID>"  # the repo's pack masks
    code, out = run_doctor(tree, capsys, monkeypatch)
    assert WARN in out, out


def test_a_repo_record_does_not_silence_the_warning(tree, capsys, monkeypatch):
    repo_cfg(tree, '[sanitize]\nsubjects = "none"\n')
    code, out = run_doctor(tree, capsys, monkeypatch)
    assert WARN in out and "sanitize.subjects" in out, out


# --- headless ---------------------------------------------------------------------------------------

def _wired(tree, broker):
    from test_v2_unattended import user_settings
    Path(os.environ["PHIWARD_CONFIG"]).write_text(f'[protected_paths]\nroots = ["{tree}/phi"]\n')
    user_settings(tree, install.merge({}, install.wiring(config.load(str(tree / "repo")))))
    broker()


@pytest.mark.parametrize("record", [False, True])
def test_headless_notes_it_and_stays_ready(tree, broker, capsys, monkeypatch, record):
    _wired(tree, broker)
    if record:
        user_cfg('[sanitize]\nsubjects = "none"\n')
        broker()
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.setattr(doctor, "sandbox_needs", lambda *a: [])
    code = doctor.main(["--headless"])
    out = capsys.readouterr().out
    assert code == 0 and out.startswith("headless: ready"), out
    assert ("NOTE: your user config enables no pack" in out) is (not record), out


# --- setup (driven through a terminal, as test_v2_release_review does) --------------------------------

def _setup(tree, tmp_path, subject_answers, profile="1", extra=(), cfg_path=None):
    from test_v2_release_review import _drive_setup
    cfg_path = cfg_path or tmp_path / "cfg" / "config.toml"
    cfg_path.parent.mkdir(exist_ok=True)
    if profile == "2":
        head = ["2", str(tree / "phi"), "", ""]               # roots, results folder
        tail = ["y", "n", "n"]                                 # write, wire, service
    else:
        head = ["1", str(tree / "phi"), "", "", "", "n"]       # roots, results, scripts, network
        tail = ["n", "y", "y", "n", "n"]                       # HPC, write, approve, wire, service
    code, out = _drive_setup(tree, ([] if not extra else ["y"]) + head + subject_answers + tail,
                             cfg_path, extra=extra)
    cfg = config.load(str(tree / "repo"), env=dict(os.environ, PHIWARD_CONFIG=str(cfg_path)))
    return code, out, cfg, cfg_path


def test_setup_records_none(tree, tmp_path):
    code, out, cfg, _ = _setup(tree, tmp_path, ["1"])
    assert code == 0, out[-800:]
    assert cfg.sanitize_subjects == "none" and cfg.packs == []


def test_setup_adds_the_msk_pack_and_keeps_genomics(tree, tmp_path):
    code, out, cfg, _ = _setup(tree, tmp_path, ["2"])
    assert code == 0, out[-800:]
    assert cfg.packs == ["genomics", "msk"] and cfg.sanitize_subjects == ""


def test_setup_takes_checked_patterns(tree, tmp_path):
    code, out, cfg, _ = _setup(tree, tmp_path, ["3", "x => y", "FAKE-PT-\\d{4} => <SAMPLEID>", ""])
    assert code == 0, out[-800:]
    assert "Refused" in out
    assert cfg.sanitize_patterns == ["FAKE-PT-\\d{4} => <SAMPLEID>"]


def test_setup_has_no_default_on_a_first_run(tree, tmp_path):
    code, out, cfg, _ = _setup(tree, tmp_path, ["", "1"])
    assert code == 0 and "there is no default" in out, out[-800:]
    assert cfg.sanitize_subjects == "none"


def test_a_rerun_offers_msk_but_never_none(tree, tmp_path):
    code, out, cfg, p = _setup(tree, tmp_path, ["2"])
    assert code == 0, out[-800:]
    again = ["1", "n", "", "", "n"]  # profile, keep the roots, results, scripts, network
    from test_v2_release_review import _drive_setup
    code, out = _drive_setup(tree, again + [""] + ["n", "y", "n", "n"], p)
    assert code == 0 and "  Choose 1, 2 or 3 [2]" in out, out[-800:]
    code, out = _drive_setup(tree, again + ["1"] + ["n", "y", "n", "n"], p)
    cfg = config.load(str(tree / "repo"), env=dict(os.environ, PHIWARD_CONFIG=str(p)))
    assert code == 0 and cfg.sanitize_subjects == "none", out[-800:]
    code, out = _drive_setup(tree, again + [""] + ["n", "y", "n", "n"], p)
    cfg = config.load(str(tree / "repo"), env=dict(os.environ, PHIWARD_CONFIG=str(p)))
    assert code == 0 and "  Choose 1, 2 or 3 [1]" not in out, out[-800:]
    assert cfg.sanitize_subjects == "" and "msk" in cfg.packs  # Enter took 2, not "none"


def test_a_rerun_of_a_none_record_has_no_default(tree, tmp_path):
    code, out, cfg, p = _setup(tree, tmp_path, ["1"])
    assert code == 0, out[-800:]
    from test_v2_release_review import _drive_setup
    code, out = _drive_setup(tree, ["1", "n", "", "", "n", "", "1", "n", "y", "n", "n"], p)
    assert code == 0 and "there is no default" in out and "  Choose 1, 2 or 3 [1]" not in out, out[-800:]


def test_profile_2_asks_too(tree, tmp_path):
    code, out, cfg, _ = _setup(tree, tmp_path, ["1"], profile="2")
    assert code == 0 and "Subject and sample identifiers" in out, out[-800:]
    assert cfg.sanitize_subjects == "none"


def test_a_team_template_fills_the_default_but_cannot_record_none(tree, tmp_path):
    team = tmp_path / "team.toml"
    team.write_text('[sanitize]\npacks = ["genomics", "msk"]\n')
    code, out, cfg, _ = _setup(tree, tmp_path, [""], extra=("--from", str(team)))
    assert code == 0 and "  Choose 1, 2 or 3 [2]" in out, out[-800:]
    assert cfg.packs == ["genomics", "msk"]
    team.write_text('[sanitize]\nsubjects = "none"\n')
    from test_v2_release_review import _drive_setup
    code, out = _drive_setup(tree, [], tmp_path / "other.toml", extra=("--from", str(team)))
    assert code == 2 and "team template" in out.lower(), out


@pytest.mark.parametrize("answer", ["1", "2"])
def test_a_team_msk_only_list_keeps_genomics(tree, tmp_path, answer):
    team = tmp_path / "team.toml"
    team.write_text('[sanitize]\npacks = ["msk"]\n')
    code, out, cfg, _ = _setup(tree, tmp_path, [answer], extra=("--from", str(team)))
    assert code == 0, out[-800:]
    assert cfg.packs == ["genomics", "msk"]


def test_setup_says_nothing_else_that_ends_like_a_prompt(tree, tmp_path):
    code, out, cfg, _ = _setup(tree, tmp_path, ["9", "1"])
    start = out.index("Subject and sample identifiers")
    block = out[start:out.index("HPC", start)]
    for line in block.splitlines():
        if "  Choose 1, 2 or 3" in line:
            continue
        assert not line.rstrip().endswith(("]", ">")), line
