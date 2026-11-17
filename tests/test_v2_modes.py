"""Mode A (a Claude Code session wired by the hook) gets the same hidden list as
launch and the gateway: the hook refuses it to the file tools and in shell text, `install`
writes it into Claude Code's sandbox and permission rules, and `doctor` reports the layers."""

import json
import os
import sys

import pytest

from helpers import launcher_by_path

PHIWARD = "phiward"  # the launcher by its path, set by launcher_by_path

from phiward import config, doctor, hidden, install
from phiward.core import DENY, FILE_READ, FILE_SEARCH, FILE_WRITE, SHELL, Action
from phiward.guards import protected_paths


def file_action(t, kind, path):
    cwd = str(t / "repo")
    return protected_paths.check(Action(kind, cwd, paths=[path]), config.load(cwd))


def shell(t, command, confined=False):
    cwd = str(t / "repo")
    return protected_paths.check(Action(SHELL, cwd, command=command, confined=confined),
                                 config.load(cwd))


@pytest.fixture()
def creds(tree):
    home = tree / "home"
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_fake").write_text("FAKE-KEY\n")
    (home / ".aws").mkdir()
    (home / ".aws" / "credentials").write_text("FAKE\n")
    (home / ".zsh_history").write_text("FAKE\n")
    return home


@pytest.mark.parametrize("rel", [".ssh/id_fake", ".aws/credentials", ".zsh_history",
                                 ".ssh/config"])
def test_the_file_tools_cannot_read_the_hidden_list(tree, creds, rel):
    assert file_action(tree, FILE_READ, str(creds / rel)).verdict == DENY
    assert file_action(tree, FILE_WRITE, str(creds / rel)).verdict == DENY


def test_a_search_of_the_ssh_folder_is_refused(tree, creds):
    assert file_action(tree, FILE_SEARCH, str(creds / ".ssh")).verdict == DENY


def test_a_kerberos_cache_by_name_is_refused(tree):
    p = f"/tmp/krb5cc_{os.getuid()}_newname"
    assert file_action(tree, FILE_READ, p).verdict == DENY


def test_a_link_in_the_project_to_a_key_is_refused(tree, creds):
    os.symlink(creds / ".ssh" / "id_fake", tree / "repo" / "k")
    assert file_action(tree, FILE_READ, str(tree / "repo" / "k")).verdict == DENY


@pytest.mark.parametrize("confined", [False, True])
def test_shell_text_naming_a_credential_is_refused(tree, creds, confined):
    assert shell(tree, "cat ~/.ssh/config", confined).verdict == DENY
    assert shell(tree, f"head {creds}/.aws/credentials", confined).verdict == DENY


def test_ordinary_project_work_is_untouched(tree, creds):
    assert file_action(tree, FILE_READ, str(tree / "repo" / "README.md")).verdict != DENY
    assert shell(tree, "wc -l README.md", True).verdict != DENY


def test_install_writes_the_hidden_list_into_sandbox_and_rules(tree, creds):
    cfg = config.load(str(tree / "repo"))
    w = install.wiring(cfg)
    # paths under the home folder are written ~/...: a settings file holds no user name
    assert "~/.ssh" in w["sandbox"]["filesystem"]["denyRead"]
    assert "Read(~/.ssh/**)" in w["permissions"]["deny"]
    assert "Edit(~/.ssh/**)" in w["permissions"]["deny"]
    assert f"Read(/{tree}/phi/**)" in w["permissions"]["deny"]
    assert "/tmp/krb5cc*" in w["sandbox"]["filesystem"]["denyRead"]
    merged = install.merge({"permissions": {"deny": ["Bash(rm *)"]}}, w)
    assert "Bash(rm *)" in merged["permissions"]["deny"]
    assert "Read(~/.ssh)" in merged["permissions"]["deny"]
    assert install.merge(merged, w) == merged  # merging again changes nothing


def test_doctor_reports_the_mode_and_missing_layers(tree, creds, monkeypatch):
    monkeypatch.delenv("PHIWARD_LAUNCH_DEPTH", raising=False)
    # an installed phiward on PATH: "wrapped" means the command is that program
    bin_ = tree / "bin"
    bin_.mkdir()
    (bin_ / "phiward").write_text("#!/bin/sh\n")
    (bin_ / "phiward").chmod(0o755)
    launcher_by_path(monkeypatch, sys.modules[__name__], bin_ / "phiward")
    monkeypatch.setenv("PATH", f"{bin_}:{os.environ.get('PATH', '')}")
    cfg = config.load(str(tree / "repo"))
    (tree / "repo" / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "plain": {"command": "npx", "args": ["some-server"]},
        "wrapped": {"command": PHIWARD,
                    "args": ["launch", "--entry", "00000000000000f1", "--", "npx", "x"]},
        "remote": {"type": "http", "url": "https://example.org/mcp"}}}))
    lines = doctor.mode_report(str(tree / "repo"), str(creds), cfg)
    text = "\n".join(lines)
    assert "mode: none" in text and "WARNING" in text  # not wired here
    assert "launch --`): plain." in text and text.rstrip().endswith("`phiward mcp wrap plain`"), \
        text  # only the unwrapped one is named


def test_doctor_under_launch_says_mode_b(tree, creds, monkeypatch):
    monkeypatch.setenv("PHIWARD_LAUNCH_DEPTH", "1")
    cfg = config.load(str(tree / "repo"))
    assert "mode: B" in doctor.mode_report(str(tree / "repo"), str(creds), cfg)[0]


def test_the_one_list_is_shared():
    from phiward import run, wholetool
    assert wholetool._credentials is hidden.credentials
    assert set(hidden.paths()) <= set(run.gateway_hidden(config.Config()))


# --- fixes to the hidden list ---------------------------------------------------------------------

def test_mode_a_keeps_claude_codes_own_folder_usable(tree, creds):
    claude = creds / ".claude"
    (claude / "projects" / "p" / "memory").mkdir(parents=True)
    for rel in ("projects/p/memory/MEMORY.md", "skills/s/SKILL.md", "plans/p.md"):
        assert file_action(tree, FILE_READ, str(claude / rel)).verdict != DENY, rel
    assert file_action(tree, FILE_READ, str(claude / ".credentials.json")).verdict == DENY
    assert file_action(tree, FILE_READ, str(creds / ".claude.json")).verdict == DENY


def test_a_project_settings_file_holds_no_user_name(tree, creds):
    w = install.wiring(config.load(str(tree / "repo")), project=True)
    text = json.dumps({"p": w["permissions"], "s": w["sandbox"]["filesystem"]["denyRead"]})
    hidden_part = [r for r in w["permissions"]["deny"] if str(tree / "phi") not in r]
    assert all(str(creds) not in r for r in hidden_part), hidden_part
    assert "/tmp/krb5cc" not in text


def test_monitor_commands_are_checked_as_shell():
    from phiward.adapters import claude
    from phiward.core import SHELL as S
    action, _ = claude.to_action({"tool_name": "Monitor", "tool_input": {"command": "cat ~/.ssh/x"},
                                  "cwd": "/"})
    assert action.kind == S
    assert install.MATCHERS == ["*"]  # every tool, Monitor too (round 14)


def test_doctor_reads_only_this_projects_mcp_servers(tree, creds, monkeypatch):
    monkeypatch.delenv("PHIWARD_LAUNCH_DEPTH", raising=False)
    (creds / ".claude.json").write_text(json.dumps({"projects": {
        "/somewhere/else": {"mcpServers": {"other": {"command": "npx", "args": ["x"]}}}}}))
    lines = doctor.mode_report(str(tree / "repo"), str(creds), config.load(str(tree / "repo")))
    assert "other" not in "\n".join(lines)


def test_a_non_file_ticket_cache_is_reported(monkeypatch):
    monkeypatch.setenv("KRB5CCNAME", "KEYRING:persistent:1000")
    assert hidden.non_file_tickets() == "KEYRING"
    monkeypatch.setenv("KRB5CCNAME", "FILE:/tmp/krb5cc_1000")
    assert hidden.non_file_tickets() == ""


def test_the_config_dirs_own_account_file_is_hidden(tree, creds, monkeypatch):
    conf = tree / "cfgdir"
    conf.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(conf))
    assert file_action(tree, FILE_READ, str(conf / ".claude.json")).verdict == DENY


def test_a_project_file_names_no_home_path_at_all(tree, creds, monkeypatch):
    monkeypatch.setenv("HOME", str(creds))
    w = install.wiring(config.load(str(tree / "repo")), project=True)
    text = json.dumps(w)
    assert str(creds) not in text, [x for x in json.dumps(w).split('"') if str(creds) in x][:5]
    cmd = w["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert cmd.endswith(" phiward hook claude'") and "not installed" in cmd


def test_an_unset_ticket_name_uses_the_configured_default(tree, monkeypatch):
    conf = tree / "krb5.conf"
    conf.write_text("[libdefaults]\n default_ccache_name = KEYRING:persistent:%{uid}\n")
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    monkeypatch.setenv("KRB5_CONFIG", str(conf))
    assert hidden.non_file_tickets() == "KEYRING"


def test_a_project_install_puts_this_machines_entries_in_the_local_file(tree, creds, monkeypatch):
    import subprocess
    import sys
    from pathlib import Path
    monkeypatch.setenv("KRB5CCNAME", "FILE:/tmp/krb5cc_test_phiward")
    from conftest import default_place_env
    src = str(Path(__file__).resolve().parents[1] / "src")
    r = subprocess.run([sys.executable, "-m", "phiward", "install", "claude", "--project",
                        "--write", "--yes"], cwd=str(tree / "repo"), capture_output=True,
                       text=True, env=dict(default_place_env(tree), PYTHONPATH=src))
    assert r.returncode == 0, r.stdout + r.stderr
    shared = json.loads((tree / "repo" / ".claude" / "settings.json").read_text())
    local = json.loads((tree / "repo" / ".claude" / "settings.local.json").read_text())
    assert "/tmp/krb5cc_test_phiward" not in json.dumps(shared)
    assert "/tmp/krb5cc_test_phiward" in local["sandbox"]["filesystem"]["denyRead"]
    assert "Read(//tmp/krb5cc_test_phiward)" in local["permissions"]["deny"]


def test_the_committed_file_holds_no_personal_root_and_the_local_file_does(tree, creds):
    cfg = config.load(str(tree / "repo"))
    shared = json.dumps(install.wiring(cfg, project=True, project_dir=str(tree / "repo")))
    local = install.local_wiring(cfg, str(tree / "repo"))
    assert str(tree / "phi") not in shared and "phiward.toml" not in shared
    assert str(tree / "phi") in json.dumps(local["sandbox"]["filesystem"]["denyRead"])
    assert any("phiward.toml" in x for x in local["sandbox"]["filesystem"]["denyWrite"])


def test_a_repo_root_inside_the_project_is_committed_as_relative(tree, creds):
    (tree / "repo" / "data").mkdir()
    (tree / "repo" / ".phiward.toml").write_text('[protected_paths]\nroots = ["%s"]\n'
                                                 % (tree / "repo" / "data"))
    cfg = config.load(str(tree / "repo"))
    w = install.wiring(cfg, project=True, project_dir=str(tree / "repo"))
    assert "./data" in w["sandbox"]["filesystem"]["denyRead"]
    assert "Read(./data/**)" in w["permissions"]["deny"]


def test_a_missing_phiward_gives_a_clear_refusal():
    import subprocess
    r = subprocess.run(["/bin/sh", "-c", install.PROJECT_HOOK.split("sh -c ", 1)[1].strip("'")],
                       capture_output=True, text=True, env={"PATH": "/nonexistent"})
    assert r.returncode == 2 and "phiward is not installed" in r.stderr
