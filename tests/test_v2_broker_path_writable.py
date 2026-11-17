"""The broker searches no PATH folder the agent's sandbox may write (round 6): a temp folder
outside the home folder, the spool, and the allowWrite and additionalDirectories folders of
the user's and the managed settings (a project's own settings are not known to the broker:
docs/threat-model.md). A relative entry is never resolved against the broker's own folder.
The texts that name dropped folders say why. Made-up trees only."""

import json
import os

from phiward import claude_settings, run, service


def _user_settings(home, data):
    f = home / ".claude" / "settings.json"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(data))


def test_a_temp_folder_outside_home_is_not_searched(tree, monkeypatch):
    home = tree / "home"
    monkeypatch.chdir(home)
    # the tests' own trees live in temp folders, so conftest names none: name one here
    tmp = tree / "faketmp"
    (tmp / "bin").mkdir(parents=True)
    monkeypatch.setattr(claude_settings, "_temp_roots", lambda: [str(tmp), str(tree)])
    b = os.path.realpath(tmp / "bin")
    assert service._safe_path_entries(b) == []
    assert b in service.dropped_path_entries(b)
    # a home folder inside a temp folder (a test's, mac.sh's) keeps its own PATH folders
    local = home / ".local" / "bin"
    local.mkdir(parents=True)
    assert service._safe_path_entries(str(local)) == [str(local)]


def test_an_allow_write_folder_of_the_user_settings_is_not_searched(tree, monkeypatch):
    home = tree / "home"
    monkeypatch.chdir(home)
    tools, local = home / "tools" / "bin", home / ".local" / "bin"
    tools.mkdir(parents=True)
    local.mkdir(parents=True)
    _user_settings(home, {"sandbox": {"filesystem": {"allowWrite": ["~/tools"]}},
                          "permissions": {"additionalDirectories": [str(home / "extra")]}})
    (home / "extra").mkdir()
    path = f"{tools}:{local}:{home / 'extra'}"
    assert service._safe_path_entries(path) == [str(local)]


def test_a_relative_entry_is_not_resolved_against_the_brokers_folder(tree, monkeypatch):
    home = tree / "home"
    monkeypatch.chdir(home)
    _user_settings(home, {"permissions": {"additionalDirectories": ["../somewhere"]}})
    assert all(p.startswith("/") for p in claude_settings.agent_writable_anywhere(str(home)))


def test_the_texts_name_the_new_reason():
    import inspect
    from phiward import doctor
    assert "the agent's sandbox may write" in inspect.getsource(doctor)
    assert "the agent's sandbox may write" in inspect.getsource(run)
