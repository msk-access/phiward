"""Git hooks: pre-commit, pre-push and install, run as real subprocesses in temp repos.

All data is made up. The sample ID below is fake.
"""

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

import pytest

SRC = str(Path(__file__).resolve().parent.parent / "src")
FAKE_ID = "P-9990001-T01-IM6"
FAKE_DIGITS = "9990001"

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


class Env:
    def __init__(self, root: Path):
        self.root = root
        self.home = root / "home"
        self.home.mkdir()
        self.config = root / "user.toml"
        self.config.write_text("")
        self.repo = root / "repo"

    def env(self) -> Dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(self.home),
            "PHIWARD_CONFIG": str(self.config),
            "PYTHONPATH": SRC,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "LANG": "C.UTF-8",
        }

    def git(self, *args: str, check: bool = True) -> "subprocess.CompletedProcess[str]":
        return subprocess.run(["git", *args], cwd=str(self.repo), env=self.env(),
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, check=check)

    def init(self, repo: Optional[Path] = None) -> None:
        if repo is not None:
            self.repo = repo
        self.repo.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q")
        self.git("config", "user.name", "Test User")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "commit.gpgsign", "false")

    def write(self, name: str, content: "str | bytes") -> None:
        p = self.repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)

    def stage(self, *names: str) -> None:
        self.git("add", "--", *names)

    def hook(self, *args: str, stdin: str = "") -> "subprocess.CompletedProcess[str]":
        return subprocess.run([sys.executable, "-m", "phiward", "git-hook", *args],
                              cwd=str(self.repo), env=self.env(), input=stdin,
                              capture_output=True, text=True)


@pytest.fixture
def ctx(tmp_path: Path) -> Env:
    e = Env(tmp_path)
    e.init()
    return e


def use_msk_pack(ctx: Env) -> None:
    ctx.config.write_text('[sanitize]\npacks = ["msk"]\n')


def out(r: "subprocess.CompletedProcess[str]") -> str:
    return r.stdout + r.stderr


def test_clean_commit_passes(ctx: Env) -> None:
    use_msk_pack(ctx)
    ctx.write("notes.txt", "hello world\nnothing here\n")
    ctx.stage("notes.txt")
    r = ctx.hook("pre-commit")
    assert r.returncode == 0, out(r)
    assert out(r) == ""


def test_added_line_with_sample_id_refused_without_leaking(ctx: Env) -> None:
    use_msk_pack(ctx)
    ctx.write("report.txt", "fine line\nsample %s was run\n" % FAKE_ID)
    ctx.stage("report.txt")
    r = ctx.hook("pre-commit")
    assert r.returncode == 1
    text = out(r)
    assert FAKE_ID not in text and FAKE_DIGITS not in text
    assert "was run" not in text
    assert "report.txt:2" in text
    assert "<SAMPLEID>" in text
    assert "--no-verify" in text


def test_default_pack_scan_runs_without_configuration(ctx: Env) -> None:
    # No packs configured at all: the default pack still scans. The default pack must not
    # flag plain prose.
    ctx.write("a.txt", "plain prose only\n")
    ctx.stage("a.txt")
    assert ctx.hook("pre-commit").returncode == 0


def test_file_name_with_id_refused_and_not_printed(ctx: Env) -> None:
    use_msk_pack(ctx)
    name = "%s.txt" % FAKE_ID
    ctx.write(name, "harmless content\n")
    ctx.stage(name)
    r = ctx.hook("pre-commit")
    assert r.returncode == 1
    text = out(r)
    assert FAKE_ID not in text and FAKE_DIGITS not in text
    assert name not in text
    assert "<SAMPLEID>" in text


def test_file_name_and_line_both_hold_id(ctx: Env) -> None:
    use_msk_pack(ctx)
    name = "x/%s/data.txt" % FAKE_ID
    ctx.write(name, "ok\nrow %s\n" % FAKE_ID)
    ctx.stage(name)
    r = ctx.hook("pre-commit")
    assert r.returncode == 1
    assert FAKE_ID not in out(r) and FAKE_DIGITS not in out(r)
    assert ":2:" in out(r)


def test_binary_file_content_skipped_name_checked(ctx: Env) -> None:
    use_msk_pack(ctx)
    ctx.write("blob.bin", b"\x00\x01\x02" + FAKE_ID.encode() + b"\x00")
    ctx.stage("blob.bin")
    assert ctx.hook("pre-commit").returncode == 0
    ctx.write("%s.bin" % FAKE_ID, b"\x00\x01\x02")
    ctx.stage("%s.bin" % FAKE_ID)
    r = ctx.hook("pre-commit")
    assert r.returncode == 1
    assert FAKE_ID not in out(r)


def test_only_added_lines_are_scanned(ctx: Env) -> None:
    use_msk_pack(ctx)
    ctx.write("old.txt", "keep\n")
    ctx.stage("old.txt")
    ctx.git("commit", "-q", "-m", "base")
    # removing a line is never refused; the removed content is not an added line
    ctx.write("old.txt", "keep\nmore clean text\n")
    ctx.stage("old.txt")
    assert ctx.hook("pre-commit").returncode == 0


def test_staged_file_inside_protected_root_refused(tmp_path: Path) -> None:
    e = Env(tmp_path)
    protected = tmp_path / "protected-root"
    e.init(protected / "repo")
    e.config.write_text('[protected_paths]\nroots = ["%s"]\n' % protected)
    e.write("ordinary.txt", "nothing special\n")
    e.stage("ordinary.txt")
    r = e.hook("pre-commit")
    assert r.returncode == 1
    assert "protected folder" in out(r)
    assert "nothing special" not in out(r)


def test_repo_outside_protected_root_passes(tmp_path: Path) -> None:
    e = Env(tmp_path)
    (tmp_path / "protected-root").mkdir()
    e.init(tmp_path / "elsewhere")
    e.config.write_text('[protected_paths]\nroots = ["%s"]\n' % (tmp_path / "protected-root"))
    e.write("ordinary.txt", "nothing special\n")
    e.stage("ordinary.txt")
    assert e.hook("pre-commit").returncode == 0


def test_bad_config_refuses_commit(ctx: Env) -> None:
    ctx.config.write_text("this is = = not toml [[[\n")
    ctx.write("a.txt", "fine\n")
    ctx.stage("a.txt")
    r = ctx.hook("pre-commit")
    assert r.returncode == 1
    assert "configuration has a problem" in out(r)


def test_missing_named_config_refuses_commit(ctx: Env) -> None:
    ctx.config.unlink()
    ctx.write("a.txt", "fine\n")
    ctx.stage("a.txt")
    assert ctx.hook("pre-commit").returncode == 1


def test_bad_config_refuses_push(ctx: Env) -> None:
    ctx.config.write_text("[nonsense]\nx = 1\n")
    r = ctx.hook("pre-push", "origin", "url", stdin="refs/heads/f %s refs/heads/f %s\n" % ("a" * 40, "0" * 40))
    assert r.returncode == 1


def test_unknown_subcommand_and_usage(ctx: Env) -> None:
    assert ctx.hook("nope").returncode == 2
    assert ctx.hook().returncode == 2
    assert ctx.hook("install", "--bogus").returncode == 2


def test_not_a_git_repo_fails_closed(tmp_path: Path) -> None:
    e = Env(tmp_path)
    e.repo = tmp_path / "plain"
    e.repo.mkdir()
    r = e.hook("pre-commit")
    assert r.returncode == 1
    assert "refused" in out(r)


def push_line(branch: str, local: str = "a" * 40) -> str:
    return "refs/heads/work %s refs/heads/%s %s\n" % (local, branch, "b" * 40)


def protect_main(ctx: Env) -> None:
    ctx.write(".phiward.toml", '[git]\nprotected_branches = ["main", "release"]\n')


def test_push_to_protected_branch_refused(ctx: Env) -> None:
    protect_main(ctx)
    r = ctx.hook("pre-push", "origin", "url", stdin=push_line("main"))
    assert r.returncode == 1
    assert "'main'" in out(r)
    assert ctx.hook("pre-push", stdin=push_line("release")).returncode == 1


def test_push_to_other_branch_passes(ctx: Env) -> None:
    protect_main(ctx)
    assert ctx.hook("pre-push", stdin=push_line("feature")).returncode == 0
    assert ctx.hook("pre-push", stdin=push_line("main-2")).returncode == 0
    assert ctx.hook("pre-push", stdin="refs/heads/main aaa refs/tags/main bbb\n").returncode == 0
    assert ctx.hook("pre-push", stdin="").returncode == 0


def test_push_deletion_of_protected_branch_refused(ctx: Env) -> None:
    protect_main(ctx)
    line = "(delete) %s refs/heads/main %s\n" % ("0" * 40, "b" * 40)
    assert ctx.hook("pre-push", stdin=line).returncode == 1


def test_push_with_no_protected_branches_passes(ctx: Env) -> None:
    assert ctx.hook("pre-push", stdin=push_line("main")).returncode == 0


def hooks_dir(ctx: Env) -> Path:
    return ctx.repo / ".git" / "hooks"


def test_install_writes_hooks(ctx: Env) -> None:
    r = ctx.hook("install")
    assert r.returncode == 0, out(r)
    for name in ("pre-commit", "pre-push"):
        p = hooks_dir(ctx) / name
        text = p.read_text()
        assert text.startswith("#!/bin/sh\n")
        assert 'exec phiward git-hook %s "$@"' % name in text
        assert 'python3 -m phiward git-hook %s "$@"' % name in text
        assert p.stat().st_mode & stat.S_IXUSR
        assert str(p) in r.stdout
    # again: our own hooks are replaced without --force
    assert ctx.hook("install").returncode == 0


def test_install_refuses_to_clobber_foreign_hook(ctx: Env) -> None:
    hooks_dir(ctx).mkdir(exist_ok=True)
    foreign = hooks_dir(ctx) / "pre-push"
    foreign.write_text("#!/bin/sh\necho mine\n")
    r = ctx.hook("install")
    assert r.returncode == 1
    assert foreign.read_text() == "#!/bin/sh\necho mine\n"
    assert not (hooks_dir(ctx) / "pre-commit").exists()  # nothing half-written
    r = ctx.hook("install", "--force")
    assert r.returncode == 0
    assert "phiward git-hook pre-push" in foreign.read_text()


@pytest.mark.parametrize("args", [("install", "--help"), ("install", "--force", "--help"),
                                  ("install", "-h", "--force")])
def test_help_after_install_prints_the_help_and_installs_nothing(ctx: Env, args) -> None:
    r = ctx.hook(*args)
    assert r.returncode == 0 and "Commands:" in r.stdout and not r.stderr, out(r)
    assert not (hooks_dir(ctx) / "pre-commit").exists() and not (hooks_dir(ctx) / "pre-push").exists()


def test_a_hook_given_help_still_checks_and_prints_no_help(ctx: Env) -> None:
    # git runs pre-commit and pre-push; an argument never turns their check off
    use_msk_pack(ctx)
    ctx.write("report.txt", "sample %s was run\n" % FAKE_ID)
    ctx.stage("report.txt")
    for args in (("pre-commit", "--help"), ("pre-commit", "-h")):
        r = ctx.hook(*args)
        assert r.returncode == 1 and "<SAMPLEID>" in out(r) and "Commands:" not in out(r), out(r)
    protect_main(ctx)
    for args in (("pre-push", "--help"), ("pre-push", "-h")):
        r = ctx.hook(*args, stdin=push_line("main"))
        assert r.returncode == 1 and "Commands:" not in out(r), out(r)


def test_install_respects_core_hooks_path(ctx: Env) -> None:
    ctx.git("config", "core.hooksPath", ".githooks")
    assert ctx.hook("install").returncode == 0
    assert (ctx.repo / ".githooks" / "pre-commit").is_file()
    assert not (hooks_dir(ctx) / "pre-commit").exists()


@pytest.mark.skipif(shutil.which("python3") is None, reason="python3 not on PATH")
def test_installed_hook_blocks_a_real_commit(ctx: Env) -> None:
    use_msk_pack(ctx)
    assert ctx.hook("install").returncode == 0
    ctx.write("leak.txt", "row %s\n" % FAKE_ID)
    ctx.stage("leak.txt")
    bad = ctx.git("commit", "-q", "-m", "x", check=False)
    assert bad.returncode != 0
    assert FAKE_ID not in bad.stdout
    ctx.write("leak.txt", "row removed\n")
    ctx.stage("leak.txt")
    good = ctx.git("commit", "-q", "-m", "y", check=False)
    assert good.returncode == 0, good.stdout
