"""Part 4: the shell is pinned to bash, and a project may not change Claude Code's shell or
shell prefix. (Part 3, phiward's shell prefix, is gone: Claude Code's sandbox confines the
shell.) Made-up trees only; the real `claude` never runs."""

import json

import pytest

from phiward import config, install
from phiward.core import DENY, SHELL, Action
from phiward.guards import protected_paths


@pytest.fixture()
def home(tree, monkeypatch):
    monkeypatch.setenv("HOME", str(tree / "home"))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    return tree / "home"


def test_the_user_wiring_always_pins_bash_and_a_project_never_does(tree, home):
    cfg = config.load(str(tree / "repo"))
    assert install.wiring(cfg)["env"] == {"CLAUDE_CODE_SHELL": "/bin/bash",
                                          "CLAUDE_CODE_DISABLE_FILE_MENTIONS": "1"}
    assert "env" not in install.wiring(cfg, project=True, project_dir=str(tree / "repo"))


@pytest.mark.parametrize("name", ["CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_CODE_SHELL"])
def test_a_project_that_sets_the_prefix_or_the_shell_is_refused(tree, home, name):
    (tree / "repo" / ".claude").mkdir(exist_ok=True)
    (tree / "repo" / ".claude" / "settings.json").write_text(json.dumps({"env": {name: "/x"}}))
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command="ls"),
                              config.load(str(tree / "repo")))
    assert d.verdict == DENY and name in d.reason, d.reason
