"""`phiward launch --tool claude` and the file `install` writes for `claude --settings` (a common
shell alias adds it). Claude Code keeps one `--settings`, the last, and launch passes its own:
the operator's is dropped only when launch's own settings already say the same, so nothing in
it is lost. Anything else stops the start. Made-up trees only."""

import copy
import json

import pytest

from phiward import config, install, wholetool


def _install_file(tree, capsys):
    assert install._write_launch_settings() == 0, capsys.readouterr().err
    return config.launch_settings_path()


def test_launch_passes_what_install_writes():
    assert wholetool.INNER_SETTINGS == install.LAUNCH_SETTINGS


@pytest.mark.parametrize("form", ["two words", "one word"])
def test_the_file_install_writes_is_accepted(tree, capsys, form):
    path = _install_file(tree, capsys)
    given = ["--settings", path] if form == "two words" else [f"--settings={path}"]
    assert wholetool._without_launch_settings(["claude", "-p", "x", *given]) == \
        ["claude", "-p", "x"]


def _changed(how):
    data = copy.deepcopy(install.LAUNCH_SETTINGS)
    if how == "an extra key":
        data["model"] = "opus"
    elif how == "an opener":
        data["sandbox"]["excludedCommands"] = ["docker"]
    elif how == "a switch turned":
        data["sandbox"]["allowUnsandboxedCommands"] = True
    elif how == "an allow":
        data["permissions"] = {"allow": ["Bash(curl:*)"]}
    elif how == "a hook":
        data["hooks"] = {"PreToolUse": [{"hooks": [{"type": "command", "command": "true"}]}]}
    elif how == "mentions on":
        data["env"] = {install.MENTIONS_OFF: "0"}
    return data


@pytest.mark.parametrize("how", ["an extra key", "an opener", "a switch turned", "an allow",
                                 "a hook", "mentions on"])
def test_a_file_that_says_more_or_other_is_refused(tree, capsys, how):
    path = _install_file(tree, capsys)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(_changed(how), fh)
    with pytest.raises(wholetool.LaunchError, match="keeps only one"):
        wholetool._without_launch_settings(["claude", "--settings", path])


@pytest.mark.parametrize("text", ["", "{", "not json", "[]"])
def test_a_file_that_does_not_parse_is_refused(tree, text):
    f = tree / "home" / "settings.json"
    f.write_text(text)
    with pytest.raises(wholetool.LaunchError, match="keeps only one"):
        wholetool._without_launch_settings(["claude", "--settings", str(f)])


def test_a_missing_file_is_refused(tree):
    with pytest.raises(wholetool.LaunchError, match="keeps only one"):
        wholetool._without_launch_settings(["claude", "--settings", str(tree / "nowhere.json")])
