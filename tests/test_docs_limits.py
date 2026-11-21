"""Each limit of docs/threat-model.md keeps a stable anchor, listed in tests/limit_ids.txt: gap-N
for "Gaps of the hook alone", lN for Mode B's recorded limits. An ID is never renumbered or
reused. So a limit cannot leave the page, or lose its anchor, without a change to that list."""

import re
from pathlib import Path

from test_docs_links import _anchors

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "threat-model.md"
LIST = ROOT / "tests" / "limit_ids.txt"
LIMIT_ID = re.compile(r"^(gap-\d+b?|l\d+)$")


def _listed():
    ids = [line.strip() for line in LIST.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(ids) == len(set(ids)), "an ID is listed twice"
    assert all(LIMIT_ID.match(i) for i in ids), ids
    return set(ids)


def test_every_listed_limit_has_its_anchor():
    assert _listed() - _anchors(PAGE) == set()


def test_every_limit_anchor_is_listed():
    assert {a for a in _anchors(PAGE) if LIMIT_ID.match(a)} - _listed() == set()


def test_launch_names_the_recorded_limits_as_the_threat_model_has_them():
    last = max(int(i[1:]) for i in _listed() if i.startswith("l"))
    text = (ROOT / "docs" / "launch.md").read_text(encoding="utf-8")
    assert f"L1–L{last}" in text
