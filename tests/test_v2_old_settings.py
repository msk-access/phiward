"""Settings left by an older phiward name their own file (round 4). An `allowWrite` inside
`~/.phiward` (the spool lived there before 281490c) makes the shell not confined: the refusal
says which settings file holds it, user or project, so the operator removes that one entry.
`install` refuses a spool inside `~/.phiward`, which the sandbox denies in full. A client whose
broker still runs on the old spool is told so, and to ask the operator to restart the broker.
Made-up trees only."""

import io
import json
import os
import sys

from phiward import broker, config, install
from helpers import Tty, protect
from helpers import confinement


def _confined(tree):
    cfg = config.load(str(tree / "repo"))
    return confinement(str(tree / "repo"), str(tree / "home"), cfg.all_roots,
                                       cfg.patterns, config.guard_files())


def _user_settings(tree, extra_allow=()):
    cfg = config.load(str(tree / "repo"))
    want = install.wiring(cfg)
    want["sandbox"]["filesystem"]["allowWrite"] += list(extra_allow)
    s = tree / "home" / ".claude" / "settings.json"
    s.parent.mkdir(parents=True, exist_ok=True)
    s.write_text(json.dumps(want))
    return s


def test_an_old_allow_write_in_the_user_settings_is_named_with_its_file(tree):
    protect(tree, [], best_effort=False)
    _user_settings(tree, ["~/.phiward/spool"])
    ok, why = _confined(tree)
    assert not ok and "~/.claude/settings.json" in why and "removes that entry" in why, why


def test_an_old_allow_write_in_the_projects_local_settings_is_named_with_its_file(tree):
    protect(tree, [], best_effort=False)
    _user_settings(tree)
    assert _confined(tree)[0]
    local = tree / "repo" / ".claude" / "settings.local.json"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(json.dumps({"sandbox": {"filesystem": {"allowWrite": ["~/.phiward/spool"]}}}))
    ok, why = _confined(tree)
    assert not ok and ".claude/settings.local.json" in why and "removes that entry" in why, why
    assert "~/.claude/settings.json" not in why


def test_install_refuses_a_spool_inside_phiwards_own_folder(tree, monkeypatch, capsys):
    protect(tree, [], best_effort=False)
    monkeypatch.setenv("PHIWARD_SPOOL", str(tree / "home" / ".phiward" / "spool"))
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.chdir(tree / "repo")
    assert install.main(["claude", "--user", "--write"]) == 2
    err = capsys.readouterr().err
    assert "PHIWARD_SPOOL" in err and "~/.phiward-spool" in err, err


def test_a_broker_on_the_old_spool_is_named_and_the_operator_restarts_it(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    monkeypatch.delenv("PHIWARD_SPOOL", raising=False)
    old = tree / "home" / ".phiward" / "spool"
    old.mkdir(parents=True)
    (old / "broker.alive").write_text("")
    status = config.status_path()
    os.makedirs(os.path.dirname(status), exist_ok=True)
    with open(status, "w") as fh:
        json.dump({"spool": str(old)}, fh)
    out = io.StringIO()
    assert broker.client("run", ["--", "true"], out=out) == 3
    text = out.getvalue()
    assert str(old) in text and "Ask the operator to restart the broker" in text, text


def test_no_broker_at_all_keeps_the_old_text(tree, monkeypatch):
    protect(tree, [], best_effort=False)
    monkeypatch.delenv("PHIWARD_SPOOL", raising=False)
    out = io.StringIO()
    assert broker.client("run", ["--", "true"], out=out) == 3
    assert "no phiward broker is running" in out.getvalue()


def test_the_hooks_refusal_names_the_file_and_not_install(tree, monkeypatch):
    # found by the quickstart check: the refusal said "run install", which does not remove an
    # entry an older phiward left; it must say what doctor says
    from phiward.adapters import claude
    protect(tree, [], best_effort=False)
    _user_settings(tree, ["~/.phiward/spool"])
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    payload = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
               "permission_mode": "default", "tool_name": "Bash",
               "tool_input": {"command": "ls"}}
    out, err = io.StringIO(), io.StringIO()
    assert claude.main(io.StringIO(json.dumps(payload)), out, err) == 2
    text = out.getvalue() + err.getvalue()
    assert "~/.claude/settings.json" in text and "removes that entry" in text, text
    assert "install claude --user --write" not in text, text
