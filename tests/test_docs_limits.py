"""Every limit of docs/threat-model.md keeps a stable anchor, listed in tests/limit_ids.txt:
known-NAME for each "Known limits" bullet, gap-N for "Gaps of the hook alone", open-NAME for
Mode B's "Known open items", lN for Mode B's recorded limits. An ID is never renumbered or
reused. A limit cannot leave the page, or lose its anchor, without a change to that list, and a
new limit in those sections cannot be added without an anchor."""

import re
from pathlib import Path

from test_docs_links import _anchors

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "threat-model.md"
LIST = ROOT / "tests" / "limit_ids.txt"
LIMIT_ID = re.compile(r"^(gap-\d+b?|l\d+|known-[a-z0-9-]+|open-[a-z0-9-]+)$")
ANCHORED = re.compile(r'<a id="([a-z0-9-]+)"></a>')


def _listed():
    ids = [line.strip() for line in LIST.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(ids) == len(set(ids)), "an ID is listed twice"
    assert all(LIMIT_ID.match(i) for i in ids), ids
    return set(ids)


def test_every_listed_limit_has_its_anchor():
    assert _listed() - _anchors(PAGE) == set()


def test_every_limit_anchor_is_listed():
    html_ids = set(ANCHORED.findall(PAGE.read_text(encoding="utf-8")))
    assert {a for a in html_ids if LIMIT_ID.match(a)} - _listed() == set()


def test_launch_names_the_recorded_limits_as_the_threat_model_has_them():
    last = max(int(i[1:]) for i in _listed() if i.startswith("l"))
    text = (ROOT / "docs" / "launch.md").read_text(encoding="utf-8")
    assert f"L1–L{last}" in text


def _limit_items():
    """Each limit line: a top-level bullet of "Known limits" and of "Known open items", a numbered
    item of "Gaps of the hook alone", a row of the recorded-limits table."""
    lines = PAGE.read_text(encoding="utf-8").splitlines()
    known, gaps = lines.index("## Known limits"), lines.index("## Gaps of the hook alone")
    reduce = next(i for i, x in enumerate(lines) if x.startswith("## Reduce the risk"))
    opened = lines.index("**Known open items in this phase:**")
    items = [x for x in lines[known:gaps] if x.startswith("- ")]
    items += [x for x in lines[gaps:reduce] if re.match(r"^\d+b?\. ", x)]
    for x in lines[opened + 1:]:
        if not x:
            break
        if x.startswith("- "):
            items.append(x)
    items += [x for x in lines if re.match(r"^\| (<a id=\"l\d+\"></a>)?L\d+ \|", x)]
    return items


def test_every_limit_has_an_anchor():
    items = _limit_items()
    assert len(items) >= 60, len(items)  # the sections are found (69 limits today)
    bare = [x[:70] for x in items if not re.match(r'^(- |\d+b?\. |\| )<a id="[a-z0-9-]+"></a>', x)]
    assert not bare, bare
