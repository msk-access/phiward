"""Every relative link in the docs leads somewhere: the file exists, and an `#anchor` names a
heading in it (as GitHub makes heading anchors) or an `<a id="...">`. Web links are not fetched.
Every docs page, anchor and title that the code and the user files name exists."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# the agent harness's files too; a source archive carries only some of them (MANIFEST.in)
DOCS = sorted(p for p in [ROOT / "README.md", ROOT / "AGENTS.md", ROOT / "CHANGELOG.md",
                          ROOT / "CLAUDE.md", ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md",
                          ROOT / "CONTINUITY.md"]
              + list((ROOT / "docs").rglob("*.md")) + list((ROOT / "plugin").rglob("*.md"))
              + list((ROOT / ".agents").glob("*.md")) + list((ROOT / ".agents" / "rules").glob("*.md"))
              + list((ROOT / ".claude" / "skills").glob("*/SKILL.md"))
              if p.is_file())
_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_FENCE = re.compile(r"^(```|~~~)")
_HTML_ID = re.compile(r"<a\s+id=\"([^\"]+)\"")  # an anchor of its own, as a limit's ID


def _slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, markup and punctuation dropped (but `-` and
    `_`), each space a `-`."""
    text = re.sub(r"`([^`]*)`", r"\1", heading.strip())
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _anchors(path: Path) -> set:
    out, seen, fenced = set(), {}, False
    for line in path.read_text(encoding="utf-8").splitlines():
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            out.update(_HTML_ID.findall(line))
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m and not fenced:
            s = _slug(m.group(1))
            n = seen.get(s, 0)
            out.add(s if n == 0 else f"{s}-{n}")
            seen[s] = n + 1
    return out


def test_an_html_anchor_counts_as_an_anchor(tmp_path):
    # a limit keeps its ID when its wording changes: <a id="gap-9"></a> before it (MkDocs and
    # GitHub both link to it)
    page = tmp_path / "page.md"
    page.write_text('# Limits\n\n<a id="gap-9"></a>\n9. **Other names of a protected file.**\n')
    assert {"limits", "gap-9"} <= _anchors(page)


def _links(path: Path):
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        for m in _LINK.finditer(re.sub(r"`[^`]*`", "", line)):
            yield m.group(1)


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_relative_link_resolves(doc):
    bad = []
    for target in _links(doc):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("//"):
            continue  # a web link, mailto:
        file_part, _, anchor = target.partition("#")
        dest = (doc.parent / file_part).resolve() if file_part else doc
        if not dest.exists():
            bad.append(f"{target}: no such file")
            continue
        if anchor and dest.suffix == ".md" and anchor not in _anchors(dest):
            bad.append(f"{target}: no heading #{anchor}")
    assert not bad, bad


def test_the_test_index_names_every_test_file():
    index = (ROOT / "tests" / "README.md").read_text(encoding="utf-8")
    named = set(re.findall(r"\btest_\w+", index))
    files = {p.stem for p in (ROOT / "tests").glob("test_*.py")}
    assert files == named, (sorted(files - named), sorted(named - files))


# --- the docs that the code and the user files name ---------------------------------------------

# where phiward's messages, comments and user-facing files name a page of docs/
NAMERS = ("src", "plugin", "skills", "scripts", "tools", ".github")
_DOC_NAME = re.compile(r"docs/([a-z0-9-]+(?:/[a-z0-9.-]+)*\.md)(?:#([a-z0-9-]+))?")
_QUOTED = re.compile(r"docs/([a-z0-9-]+\.md),?\s+\"([^\"]+)\"")
# references to a part of a page by words, not by a quoted title: (the file that says it, its
# words, the page, the text that page must hold)
BY_WORDS = [
    ("src/phiward/doctor.py", "known gap 9", "threat-model.md", "9. **Other names of a protected file**"),
    ("src/phiward/claude_settings.py", "git's control files", "threat-model.md", "**Git's control files.**"),
    ("src/phiward/wholetool.py", "files that run later", "threat-model.md", "**Files that run later.**"),
    ("src/phiward/install.py", "the agent-run first setup", "setup.md", "The agent-run setup takes"),
]


def _namer_files():
    for top in NAMERS:
        for p in sorted((ROOT / top).rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts and "node_modules" not in p.parts \
                    and p.suffix in (".py", ".md", ".sh", ".yml", ".json") and p.name != "package-lock.json":
                yield p


def _flat(text: str) -> str:
    """Text as one line: comment marks and runs of spaces folded, for words split over lines."""
    return " ".join(re.sub(r"(?m)^\s*#\s?", "", text).split())


def test_every_doc_the_code_names_exists():
    bad, seen = [], 0
    for p in _namer_files():
        for m in _DOC_NAME.finditer(p.read_text(encoding="utf-8", errors="replace")):
            seen += 1
            page, anchor = ROOT / "docs" / m.group(1), m.group(2)
            if not page.is_file():
                bad.append(f"{p.relative_to(ROOT)}: docs/{m.group(1)}: no such file")
            elif anchor and anchor not in _anchors(page):
                bad.append(f"{p.relative_to(ROOT)}: docs/{m.group(1)}#{anchor}: no such anchor")
    assert seen > 30, seen  # the scan finds them (30 or more today)
    assert not bad, bad


def test_every_title_the_code_quotes_is_in_its_page():
    bad, seen = [], 0
    for p in _namer_files():
        for m in _QUOTED.finditer(_flat(p.read_text(encoding="utf-8", errors="replace"))):
            seen += 1
            text = _flat((ROOT / "docs" / m.group(1)).read_text(encoding="utf-8")).replace("**", "")
            if m.group(2).lower() not in text.lower():
                bad.append(f"{p.relative_to(ROOT)}: docs/{m.group(1)} has no \"{m.group(2)}\"")
    assert seen >= 6, seen
    assert not bad, bad


@pytest.mark.parametrize("namer,words,page,holds", BY_WORDS, ids=[w for _n, w, _p, _h in BY_WORDS])
def test_every_part_the_code_names_by_words_is_in_its_page(namer, words, page, holds):
    assert words in _flat((ROOT / namer).read_text(encoding="utf-8")), (namer, words)
    assert holds in (ROOT / "docs" / page).read_text(encoding="utf-8"), (page, holds)
