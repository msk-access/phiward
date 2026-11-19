"""The agent harness: the files that tell AI coding agents how to work on phiward's own code
(AGENTS.md, CLAUDE.md, .agents/, .claude/, CONTRIBUTING.md, SECURITY.md). Small, public-safe, and
nothing in it that git or Claude Code runs. No git calls: the Linux check runs on an archive."""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# a source archive (sdist) carries the tests but not the harness: nothing to check there
pytestmark = pytest.mark.skipif((ROOT / "PKG-INFO").is_file(),
                                reason="a source archive: the harness is not in it")
# what stays on the maintainer's machine (.gitignore): never scanned, never required
LOCAL = (".agents/plans", ".agents/local", "CLAUDE.local.md", ".claude/settings.local.json",
         ".claude/worktrees")
SCANNED = ("AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md", "SECURITY.md", "CONTINUITY.md",
           "README.md", "CHANGELOG.md", ".agents", ".claude", ".github", "docs", "scripts",
           "plugin", "skills", "src", "tests", "tools")
TEXT = (".md", ".py", ".sh", ".json", ".toml", ".txt", ".yml", ".yaml")
HOME_OK = {"me", "you", "u", "tester", "x", "y", ".aws",
           "Shared"}  # the placeholders the docs use; /Users/Shared is macOS's shared folder


def _local(p: Path) -> bool:
    rel = p.relative_to(ROOT).as_posix()
    return any(rel == x or rel.startswith(x + "/") for x in LOCAL)


def _text_files():
    for top in SCANNED:
        p = ROOT / top
        files = [p] if p.is_file() else sorted(p.rglob("*")) if p.is_dir() else []
        for f in files:
            if f.is_file() and not _local(f) and "__pycache__" not in f.parts and \
                    (f.suffix in TEXT or f.name == "CODEOWNERS"):
                yield f


def test_agents_md_is_short():
    lines = (ROOT / "AGENTS.md").read_text().splitlines()
    assert len(lines) <= 75, len(lines)


def test_claude_md_imports_agents_md_and_the_working_principles():
    text = (ROOT / "CLAUDE.md").read_text()
    imports = re.findall(r"^@(\S+)$", text, re.M)
    assert imports[:1] == ["AGENTS.md"], imports
    assert ".agents/rules/working-principles.md" in imports, imports
    for i in imports:
        assert (ROOT / i).is_file(), i


def test_the_skills_are_plain_files_for_work_on_phiward():
    skills = ROOT / ".claude" / "skills"
    assert skills.is_dir() and not skills.is_symlink()
    found = sorted(skills.iterdir())
    assert found
    for d in found:
        if d.name == ".DS_Store":
            continue  # Finder's file on a Mac (never tracked: .gitignore)
        assert d.is_dir() and not d.is_symlink(), d
        assert d.name != "phiward", "that is the product skill's name"
        # only the instructions: no script beside them, nothing the skill runs
        assert sorted(f.name for f in d.iterdir() if f.name != ".DS_Store") == ["SKILL.md"], d
        text = (d / "SKILL.md").read_text()
        m = re.match(r"---\n(.*?)\n---\n", text, re.S)
        assert m, d
        lines = m.group(1).splitlines()
        assert all(re.match(r"(name|description): ", line) for line in lines), lines
        head = dict(line.split(": ", 1) for line in lines)
        assert head.get("name") == d.name, head
        assert head.get("description", "").strip('"').startswith(
            "For work on phiward's own code"), head
        # a skill's `!` line runs a command when it loads
        assert "!`" not in text, d
    for p in (ROOT / ".claude").rglob("*"):
        assert not p.is_symlink() or _local(p), p


def test_the_project_settings_only_deny():
    data = json.loads((ROOT / ".claude" / "settings.json").read_text())
    assert set(data) <= {"$schema", "permissions"}, data
    assert set(data["permissions"]) == {"deny"}, data
    deny = data["permissions"]["deny"]
    assert deny and all(isinstance(r, str) and r.startswith("Bash(git ") for r in deny), deny


def test_no_file_that_git_or_claude_code_runs():
    for p in (".githooks", ".claude/hooks", ".claude/commands", ".claude/agents"):
        assert not (ROOT / p).exists(), p


def test_codeowners_names_the_harness():
    text = (ROOT / ".github" / "CODEOWNERS").read_text()
    for p in ("/AGENTS.md", "/CLAUDE.md", "/.agents/", "/.claude/", "/.github/"):
        assert re.search(rf"^{re.escape(p)}\s+@", text, re.M), p


def test_local_files_stay_out_of_git():
    ignore = (ROOT / ".gitignore").read_text().splitlines()
    for line in (".agents/plans/", ".agents/local/", "CLAUDE.local.md",
                 ".claude/settings.local.json", ".claude/worktrees/"):
        assert line in ignore, line


def test_no_plan_files_are_in_the_tree():
    top = [p for p in ROOT.iterdir() if p.is_file()]
    for p in list(_text_files()) + top:
        assert not re.match(r"PLAN-.*\.md$", p.name), p


@pytest.mark.parametrize("pattern", [r"/Users/([A-Za-z0-9._-]+)", r"/home/([A-Za-z0-9._-]+)"])
def test_no_real_home_path_in_tracked_text(pattern):
    bad = []
    for p in _text_files():
        try:
            text = p.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for m in re.finditer(pattern, text):
            if m.group(1) not in HOME_OK:
                bad.append(f"{p.relative_to(ROOT)}: {m.group(0)}")
    assert not bad, bad
