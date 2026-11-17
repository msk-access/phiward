"""Every relative link in the docs leads somewhere: the file exists, and an `#anchor` names a
heading in it (as GitHub makes heading anchors). Web links are not fetched."""

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
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m and not fenced:
            s = _slug(m.group(1))
            n = seen.get(s, 0)
            out.add(s if n == 0 else f"{s}-{n}")
            seen[s] = n + 1
    return out


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
