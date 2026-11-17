"""The opt-in network limit for shell commands in Claude Code sessions (Mode A): `[network]
limit` and `allowed_domains` in the user config become Claude Code's own
`sandbox.network.strictAllowlist` and `allowedDomains` in the user settings. Made-up data only."""

import json
import os
import sys
from pathlib import Path

import pytest

from phiward import config, install

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v2_release_review import _drive_setup  # noqa: E402
from helpers import user_settings


def _add(text: str) -> None:
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + "\n" + text)


def test_the_user_config_sets_the_network_limit(tree):
    _add('[network]\nlimit = true\nallowed_domains = ["github.com", "*.pypi.org:443", "[::1]:8080"]\n')
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem, cfg.problem
    assert cfg.network_limit is True
    assert cfg.allowed_domains == ["github.com", "*.pypi.org:443", "[::1]:8080"]


def test_the_network_limit_is_off_by_default(tree):
    cfg = config.load(str(tree / "repo"))
    assert cfg.network_limit is False and cfg.allowed_domains == []


@pytest.mark.parametrize("bad", ["*", "*.*", "http://github.com", "git hub.com", "github.com/x",
                                 "github.com:99999", "-x.org"])
def test_a_domain_that_is_not_a_host_is_a_problem(tree, bad):
    _add(f'[network]\nlimit = true\nallowed_domains = ["{bad}"]\n')
    cfg = config.load(str(tree / "repo"))
    assert "allowed_domains" in cfg.problem


def test_a_repo_file_cannot_set_the_network_limit(tree):
    (tree / "repo" / ".phiward.toml").write_text(
        '[network]\nlimit = false\nallowed_domains = ["evil.example"]\n')
    _add("[network]\nlimit = true\n")
    cfg = config.load(str(tree / "repo"))
    assert cfg.network_limit is True and cfg.allowed_domains == []
    assert "network.allowed_domains" in cfg.ignored and "network.limit" in cfg.ignored


def test_user_wiring_writes_the_strict_allowlist(tree):
    _add('[network]\nlimit = true\nallowed_domains = ["github.com"]\n')
    w = install.wiring(config.load(str(tree / "repo")))
    assert w["sandbox"]["network"] == {"strictAllowlist": True, "allowedDomains": ["github.com"]}


def test_no_network_entry_without_the_limit(tree):
    w = install.wiring(config.load(str(tree / "repo")))
    assert "network" not in w["sandbox"]


def test_project_wiring_never_writes_the_network_limit(tree):
    # Claude Code ignores strictAllowlist in a repository's settings; it belongs to the user file
    _add('[network]\nlimit = true\nallowed_domains = ["github.com"]\n')
    w = install.wiring(config.load(str(tree / "repo")), project=True,
                       project_dir=str(tree / "repo"))
    assert "network" not in w["sandbox"]


def test_merge_turns_the_limit_on_and_keeps_the_users_own_domains(tree):
    _add('[network]\nlimit = true\nallowed_domains = ["github.com"]\n')
    w = install.wiring(config.load(str(tree / "repo")))
    have = {"sandbox": {"network": {"strictAllowlist": False, "allowedDomains": ["mine.example"]}}}
    m = install.merge(have, w)
    assert m["sandbox"]["network"]["strictAllowlist"] is True
    assert m["sandbox"]["network"]["allowedDomains"] == ["mine.example", "github.com"]
    assert install.merge(m, w) == m


def test_merge_without_the_limit_leaves_the_network_alone(tree):
    w = install.wiring(config.load(str(tree / "repo")))
    have = {"sandbox": {"network": {"allowedDomains": ["mine.example"]}}}
    assert install.merge(have, w)["sandbox"]["network"] == {"allowedDomains": ["mine.example"]}


def test_doctor_reports_the_limit(tree, capsys):
    from phiward import doctor
    _add('[network]\nlimit = true\nallowed_domains = ["github.com"]\n')
    user_settings(tree, {"sandbox": {"network": {"strictAllowlist": True,
                                             "allowedDomains": ["github.com"]}}})
    doctor.main([])
    out = capsys.readouterr().out
    assert "network for shell commands: limited to 1 host" in out


def test_doctor_warns_when_the_limit_is_not_wired(tree, capsys):
    from phiward import doctor
    _add("[network]\nlimit = true\n")
    user_settings(tree, {})
    doctor.main([])
    out = capsys.readouterr().out
    assert "WARNING: [network] limit is set" in out


def test_doctor_counts_webfetch_allow_rules_as_open_hosts(tree, capsys):
    from phiward import doctor
    _add("[network]\nlimit = true\n")
    user_settings(tree, {"sandbox": {"network": {"strictAllowlist": True}},
                     "permissions": {"allow": ["WebFetch(domain:example.org)"]}})
    doctor.main([])
    out = capsys.readouterr().out
    assert "limited to 1 host" in out


def test_doctor_notes_an_open_network(tree, capsys):
    from phiward import doctor
    user_settings(tree, {})
    doctor.main([])
    out = capsys.readouterr().out
    assert "network for shell commands: open" in out


def test_setup_profile_for_real_data_asks_for_the_network_limit(tree, tmp_path):
    cfg_path = tmp_path / "config.toml"
    answers = ["1", str(tree / "phi"), "",      # profile, roots
               "",                              # results folder: the suggestion
               "",                              # no scripts folder
               "",                              # limit the shell's network: the default (yes)
               "github.com", "",                # the hosts
               "n",                             # no HPC
               "y", "y", "n", "n"]              # write, approve programs, wire, service
    code, out = _drive_setup(tree, answers, cfg_path)
    assert code == 0, out
    cfg = config.load(str(tree / "repo"), env=dict(os.environ, PHIWARD_CONFIG=str(cfg_path)))
    assert not cfg.problem, cfg.problem
    assert cfg.network_limit is True and cfg.allowed_domains == ["github.com"]


def test_setup_refuses_a_bad_host(tree, tmp_path):
    cfg_path = tmp_path / "config.toml"
    answers = ["1", str(tree / "phi"), "", "", "",
               "y", "http://x", "", "n", "y", "y", "n", "n"]
    code, out = _drive_setup(tree, answers, cfg_path)
    assert code == 0, out
    assert "Refused" in out
    cfg = config.load(str(tree / "repo"), env=dict(os.environ, PHIWARD_CONFIG=str(cfg_path)))
    assert cfg.network_limit is True and cfg.allowed_domains == []


@pytest.mark.parametrize("bad", ["*.com", "*.co.uk", "*.org", "*.ac.jp"])
def test_a_wildcard_over_a_public_suffix_is_a_problem(tree, bad):
    _add(f'[network]\nlimit = true\nallowed_domains = ["{bad}"]\n')
    assert "allowed_domains" in config.load(str(tree / "repo")).problem


def test_a_wildcard_below_a_name_is_fine(tree):
    _add('[network]\nlimit = true\nallowed_domains = ["*.pypi.org", "*.example.co.uk"]\n')
    assert not config.load(str(tree / "repo")).problem


def test_doctor_warns_when_a_project_turns_the_sandbox_off(tree, capsys):
    from phiward import doctor
    _add("[network]\nlimit = true\n")
    user_settings(tree, {"sandbox": {"network": {"strictAllowlist": True}}})
    proj = tree / "repo" / ".claude"
    proj.mkdir()
    (proj / "settings.json").write_text(json.dumps({"sandbox": {"excludedCommands": ["curl *"]}}))
    os.environ["CLAUDE_PROJECT_DIR"] = str(tree / "repo")
    try:
        doctor.main([])
    finally:
        del os.environ["CLAUDE_PROJECT_DIR"]
    out = capsys.readouterr().out
    assert "WARNING: the network limit does not hold" in out


def test_doctor_names_hosts_in_the_settings_that_the_config_no_longer_lists(tree, capsys):
    from phiward import doctor
    _add('[network]\nlimit = true\nallowed_domains = ["github.com"]\n')
    user_settings(tree, {"sandbox": {"network": {"strictAllowlist": True,
                                             "allowedDomains": ["github.com", "files.example.org"]}}})
    doctor.main([])
    out = capsys.readouterr().out
    assert "1 host(s) in Claude Code's user settings are not in [network] allowed_domains" in out


@pytest.mark.parametrize("bad", ["*.github.io", "*.amazonaws.com", "*.cloudfront.net",
                                 "*.pages.dev", "*.vercel.app", "*.ngrok.io", "*.me.uk"])
def test_a_wildcard_over_a_shared_hosting_suffix_is_a_problem(tree, bad):
    _add(f'[network]\nlimit = true\nallowed_domains = ["{bad}"]\n')
    assert "allowed_domains" in config.load(str(tree / "repo")).problem


@pytest.mark.parametrize("bad", ["*.s3.amazonaws.com", "*.execute-api.us-east-1.amazonaws.com",
                                 "*.githubusercontent.com", "*.r2.dev",
                                 "*.storage.googleapis.com", "*.web.core.windows.net"])
def test_a_wildcard_below_a_shared_hosting_name_is_a_problem(tree, bad):
    _add(f'[network]\nlimit = true\nallowed_domains = ["{bad}"]\n')
    assert "allowed_domains" in config.load(str(tree / "repo")).problem
