"""File mentions off: `@path` in a prompt is a Read that phiward's hook sees, not file text put
into the prompt with no tool call. The user settings and the `--settings` file set
`CLAUDE_CODE_DISABLE_FILE_MENTIONS=1`; Claude Code ignores it in a project's settings, so
nothing is written there. `doctor` reports a missing value and a Claude Code that does not know
it. Made-up trees only."""

import json
import sys

import pytest

from phiward import claude_settings, config, doctor, install
from helpers import Tty, user_settings

NAME = "CLAUDE_CODE_DISABLE_FILE_MENTIONS"


def test_the_user_wiring_turns_mentions_off_and_a_project_never_does(tree):
    cfg = config.load(str(tree / "repo"))
    assert install.wiring(cfg)["env"][NAME] == "1"
    assert "env" not in install.wiring(cfg, project=True, project_dir=str(tree / "repo"))


def test_the_launch_settings_turn_mentions_off():
    assert install.LAUNCH_SETTINGS["env"][NAME] == "1"


def test_merge_sets_it_over_an_operators_value_and_says_so(tree, capsys):
    target = tree / "home" / ".claude" / "settings.json"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({"env": {NAME: "0"}}))
    cfg = config.load(str(tree / "repo"))
    assert install.merge(json.loads(target.read_text()), install.wiring(cfg))["env"][NAME] == "1"
    assert install._write(str(target), install.wiring(cfg), [], ["--yes"]) == 0
    notes = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("Note:")]
    assert any(NAME in n and "'0'" in n for n in notes), notes


def test_the_launch_settings_file_written_by_install_has_it(tree, monkeypatch):
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.chdir(tree / "repo")
    assert install.main(["claude", "--user", "--write", "--yes"]) == 0
    with open(config.launch_settings_path()) as fh:
        assert json.load(fh)["env"][NAME] == "1"


def _doctor(tree, monkeypatch, capsys, data, version=None):
    monkeypatch.setenv("HOME", str(tree / "home"))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(claude_settings, "claude_version", lambda: version)
    # wired as install writes it, with `data`'s env entry in place of the wiring's own
    wired = install.wiring(config.load(str(tree / "repo")))
    wired["env"].pop(NAME)
    wired["env"].update(data.get("env", {}))
    user_settings(tree, wired)
    doctor.main([])
    return capsys.readouterr().out


@pytest.mark.parametrize("data", [{}, {"env": {NAME: "0"}}, {"env": {NAME: "true"}}])
def test_doctor_flags_a_missing_or_wrong_value(tree, monkeypatch, capsys, data):
    out = _doctor(tree, monkeypatch, capsys, data)
    assert any(NAME in ln and "WARNING" in ln for ln in out.splitlines()), out


def test_doctor_is_quiet_when_it_is_set_and_the_version_is_new(tree, monkeypatch, capsys):
    out = _doctor(tree, monkeypatch, capsys, {"env": {NAME: "1"}}, version=(2, 1, 299))
    assert NAME not in out, out


def test_a_project_s_value_does_not_count(tree, monkeypatch, capsys):
    (tree / "repo" / ".claude").mkdir(exist_ok=True)
    (tree / "repo" / ".claude" / "settings.json").write_text(json.dumps({"env": {NAME: "1"}}))
    out = _doctor(tree, monkeypatch, capsys, {})
    assert any(NAME in ln and "WARNING" in ln for ln in out.splitlines()), out


@pytest.mark.parametrize("version,word", [((2, 1, 294), "PROBLEM"), ((2, 1, 295), "WARNING"),
                                          ((2, 1, 298), "WARNING")])
def test_doctor_reports_a_claude_code_that_does_not_know_it(tree, monkeypatch, capsys, version, word):
    out = _doctor(tree, monkeypatch, capsys, {"env": {NAME: "1"}}, version=version)
    assert any(word in ln and "2.1.299" in ln for ln in out.splitlines()), out
