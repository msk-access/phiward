"""Fixes from the pre-release reviews."""

import os
from pathlib import Path

from phiward import config, hidden, service
from phiward.core import DENY, FILE_READ, SHELL, Action
from phiward.guards import protected_paths


def user_cfg(extra):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + extra)


# --- gateway --------------------------------------------------------------------------------------

def test_mode_a_hides_the_write_to_folders(tree):
    # H1: what the gateway writes there is unmasked
    out = tree / "home" / "results"
    out.mkdir()
    user_cfg(f'\n[broker]\nwrite_to = ["{out}"]\n')
    cfg = config.load(str(tree / "repo"))
    assert str(out) in hidden.paths(None, cfg, session=True)
    assert str(out) not in hidden.paths(None, cfg)  # the gateway itself writes there
    d = protected_paths.check(Action(FILE_READ, str(tree / "repo"), paths=[str(out / "x")]), cfg)
    assert d.verdict == DENY


def test_a_repo_pack_list_adds_to_the_default(tree):
    # H2: a repo list used to replace the default genomics pack
    (tree / "repo" / ".phiward.toml").write_text('[sanitize]\npacks = ["dates"]\n')
    cfg = config.load(str(tree / "repo"))
    assert "genomics" in cfg.packs and "dates" in cfg.packs


def test_a_user_pack_list_is_the_users_choice(tree):
    user_cfg('\n[sanitize]\npacks = ["dates"]\n')
    cfg = config.load(str(tree / "repo"))
    assert cfg.packs == ["dates"]


def test_an_unquoted_glob_in_a_root_is_refused_when_the_shell_is_not_confined(tree):
    # H3: the agent's own shell would expand it into the request in the spool
    cfg = config.load(str(tree / "repo"))
    cmd = f"phiward run -- wc -l {tree}/phi/*"
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command=cmd, confined=False), cfg)
    assert d.verdict == DENY and "sh -c" in d.reason
    quoted = f"phiward run -- sh -c 'wc -l {tree}/phi/*'"
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command=quoted, confined=False), cfg)
    assert d.verdict != DENY


def test_the_service_path_drops_relative_and_shared_writable_entries(tree, monkeypatch):
    shared = tree / "shared"
    shared.mkdir()
    os.chmod(shared, 0o777)
    good = tree / "good"
    good.mkdir()
    os.chmod(good, 0o755)
    entries = service._safe_path_entries(f".:node_modules/.bin:{shared}:{good}:/usr/bin")
    assert entries == [str(good), "/usr/bin"]


def test_the_service_records_the_kerberos_variables(tree, monkeypatch):
    monkeypatch.setenv("KRB5CCNAME", "FILE:/tmp/krb5cc_custom")
    assert "KRB5CCNAME" in service.render("/opt/bin/phiward")


def test_systemd_drop_ins_are_guarded(tree):
    sf = service.service_file()
    if sf.endswith(".service"):
        assert sf + ".d" in config.guard_files()


# --- boundary -------------------------------------------------------------------------------------

def test_a_repository_the_session_made_is_reported(tree):
    from phiward import carryover
    proj = tree / "repo"
    before = carryover.project_state(str(proj))
    (proj / ".git" / "hooks").mkdir(parents=True)
    (proj / ".git" / "config").write_text("[core]\n\tfsmonitor = echo planted\n")
    (proj / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n")
    (proj / "src" / ".git").mkdir()
    (proj / "src" / ".git" / "config").write_text("[core]\n")
    lines = "\n".join(carryover.project_report(carryover.project_changes(
        before, carryover.project_state(str(proj)), "")))
    assert "files that run later" in lines
    for p in (".git/config", ".git/hooks/pre-commit", "src/.git/config"):
        assert p in lines, lines


def test_files_that_run_later_are_never_folded_into_a_count(tree):
    from phiward import carryover
    proj = tree / "repo"
    before = carryover.project_state(str(proj))
    for i in range(15):
        (proj / f"note{i}.txt").write_text("x")
    for n in (".Rprofile", ".pdbrc", "ipython_config.py"):
        (proj / n).write_text("x")
    tool = proj / "git"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    lines = "\n".join(carryover.project_report(carryover.project_changes(
        before, carryover.project_state(str(proj)), "")))
    for n in (".Rprofile", ".pdbrc", "ipython_config.py", "git (new)"):
        assert n in lines, lines


def test_an_unlisted_startup_file_is_found(tmp_path):
    from phiward import selfcheck
    (tmp_path / "evil.pth").write_text("import os; os.system('x')\n")
    (tmp_path / "_virtualenv.pth").write_text("import _virtualenv\n")
    assert selfcheck._startup_files(str(tmp_path)) == [
        "evil.pth: runs code at start"]


# --- last fixes -----------------------------------------------------------------------------------

def test_a_repository_planted_through_a_git_file_is_reported(tree):
    from phiward import carryover
    proj = tree / "repo"
    before = carryover.project_state(str(proj))
    (proj / "src" / ".git").write_text("gitdir: ../build/gd\n")
    gd = proj / "build" / "gd"
    (gd / "objects").mkdir(parents=True)
    (gd / "refs").mkdir()
    (gd / "HEAD").write_text("ref: refs/heads/main\n")
    (gd / "config").write_text("[core]\n\tfsmonitor = echo planted\n")
    (gd / "hooks").mkdir()
    (gd / "hooks" / "post-checkout").write_text("#!/bin/sh\n")
    for i in range(15):
        (proj / f"n{i}.txt").write_text("x")
    lines = "\n".join(carryover.project_report(carryover.project_changes(
        before, carryover.project_state(str(proj)), str(proj))))
    for p in ("src/.git", "build/gd/config", "build/gd/HEAD", "build/gd/hooks/post-checkout"):
        assert p in lines, lines


def test_a_flood_of_files_does_not_hide_instructions(tree):
    from phiward import carryover
    proj = tree / "repo"
    before = carryover.project_state(str(proj), limit=50)
    (proj / "zzz").mkdir()
    for i in range(80):
        (proj / "zzz" / f"f{i}").write_text("")
    (proj / ".claude" / "commands").mkdir(parents=True)
    (proj / ".claude" / "commands" / "evil.md").write_text("x")
    (proj / "src" / "CLAUDE.md").write_text("x")
    after = carryover.project_state(str(proj), limit=50)
    lines = "\n".join(carryover.project_report(carryover.project_changes(before, after, str(proj))))
    assert ".claude/commands/evil.md" in lines and "src/CLAUDE.md" in lines, lines
    assert "WARNING" in lines


def test_a_flood_past_the_scan_limit_is_walked_last(tree):
    # re-check of H2: at the scan limit the walk stops; breadth first, dot-folders first, the
    # instructions near the top are seen before a deep flood
    from phiward import carryover
    proj = tree / "repo"
    before = carryover.project_state(str(proj), limit=20, scan_limit=100)
    (proj / "zzz").mkdir()
    for i in range(120):
        (proj / "zzz" / f"f{i}").write_text("")
    (proj / ".claude" / "commands").mkdir(parents=True)
    (proj / ".claude" / "commands" / "evil.md").write_text("x")
    (proj / "src" / "CLAUDE.md").write_text("x")
    after = carryover.project_state(str(proj), limit=20, scan_limit=100)
    lines = "\n".join(carryover.project_report(carryover.project_changes(before, after, str(proj))))
    assert ".claude/commands/evil.md" in lines and "src/CLAUDE.md" in lines, lines


def test_a_repository_split_by_commondir_is_reported(tree):
    from phiward import carryover
    proj = tree / "repo"
    before = carryover.project_state(str(proj))
    common = proj / "build" / "common"
    (common / "objects").mkdir(parents=True)
    (common / "refs").mkdir()
    (common / "config").write_text("[core]\n\tfsmonitor = echo planted\n")
    lines = "\n".join(carryover.project_report(carryover.project_changes(
        before, carryover.project_state(str(proj)), str(proj))))
    assert "build/common/config" in lines and "files that run later" in lines, lines
