"""An activated `.venv` puts a folder of the project on PATH. `launch` still refuses (the
operator's own shell runs `.venv/bin/*` first after the session, and the session could write
there), but its step names the entry and the way out: `deactivate`, or take it off PATH. The
session note's scan (`projectscan.place_problem`) still refuses the same folder."""

import os

import pytest

from phiward import config, projectscan, wholetool


def _env(tree, venv=True):
    proj = tree / "repo"
    (proj / ".venv" / "bin").mkdir(parents=True)
    env = dict(os.environ, PATH=f"{proj}/.venv/bin:/usr/bin:/bin")
    env.pop("VIRTUAL_ENV", None)
    if venv:
        env["VIRTUAL_ENV"] = str(proj / ".venv")
    return env


def _refusal(tree, env):
    with pytest.raises(wholetool.LaunchError) as exc:
        wholetool.build(["/bin/echo", "x"], str(tree / "repo"), env, wholetool.ADAPTERS["generic"])
    return str(exc.value)


def test_an_activated_venv_names_the_entry_and_deactivate(tree):
    msg = _refusal(tree, _env(tree))
    assert ".venv/bin" in msg and "deactivate" in msg, msg
    assert "start the tool in a project folder" not in msg, msg


def test_a_path_entry_without_virtual_env_says_take_it_off(tree):
    msg = _refusal(tree, _env(tree, venv=False))
    assert ".venv/bin" in msg and "take" in msg.lower() and "deactivate" not in msg, msg


def test_the_entry_is_found_by_its_own_function(tree):
    env = _env(tree)
    proj = os.path.realpath(tree / "repo")
    assert wholetool._path_entry_inside(proj, env) == f"{tree / 'repo'}/.venv/bin"
    assert wholetool._path_entry_inside(proj, dict(env, PATH="/usr/bin:/bin")) == ""


def test_the_session_notes_scan_still_refuses_the_folder(tree, monkeypatch):
    env = _env(tree)
    monkeypatch.setenv("PATH", env["PATH"])
    monkeypatch.setenv("VIRTUAL_ENV", env["VIRTUAL_ENV"])
    cfg = config.load(str(tree / "repo"))
    assert projectscan.place_problem(cfg, str(tree / "repo"))
