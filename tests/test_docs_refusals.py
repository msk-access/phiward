"""docs/refusals.md quotes each refusal whose step this page documents, as the code says it, so
the docs and the messages stay in step. Backticks and line breaks are not compared."""

import re
from pathlib import Path

from phiward import copying, doctor, netproxy, session_note, wholetool

PAGE = Path(__file__).resolve().parents[1] / "docs" / "refusals.md"


def _plain(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("`", "")).strip()


MESSAGES = {
    "launch, no protected paths": wholetool.NO_PATHS,
    "launch, a wrapper": wholetool.CLAUDE_STEP,
    "launch, `--` on Linux": wholetool.DASH_DASH,
    "launch, a project folder": wholetool.PROJECT_STEP.split("{}")[1],
    "launch, a link": wholetool.LINK_STEP.split("{}")[1],
    "proxy, plain HTTP": netproxy.ONLY_CONNECT,
    "copy out of a root": copying.NOT_IN_ROOT,
    "doctor, read-only files under launch": doctor.RUNS_LATER_NOTE,
    "doctor, package caches": doctor.CACHE_NOTE,
    "session note, limits": session_note.LIMITS_GIT,
}


def test_the_page_quotes_each_message():
    page = _plain(PAGE.read_text(encoding="utf-8"))
    missing = [k for k, v in MESSAGES.items() if _plain(v) not in page]
    assert not missing, missing


def test_the_page_is_linked_from_setup_and_the_site():
    assert "refusals.md" in (PAGE.parent / "setup.md").read_text(encoding="utf-8")
    assert "refusals.md" in (PAGE.parents[1] / "mkdocs.yml").read_text(encoding="utf-8")
