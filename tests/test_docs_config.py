"""docs/configuration.md lists every key the loader takes, once, in one table, and its column
"Repo config" says "ignored" for exactly the keys a repo config may not set. The anchors that
other pages and the code's messages name stay on the page."""

import re
from pathlib import Path

from phiward import config
from test_docs_links import _anchors

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "configuration.md"
HEADER = "| Key | Type | Default | Repo config | What it does |"
KEY = re.compile(r"^\|\s*\[?`\[(\w+)\] (\w+)`")

# named by other pages, by the code's messages, or in this page
ANCHORS = ("where-the-files-are", "who-may-set-what", "protected_paths", "sanitize", "copy",
           "shell", "mcp-servers", "the-repo-config", "fail-closed")


def _rows():
    lines = PAGE.read_text(encoding="utf-8").splitlines()
    assert HEADER in lines, f"no table with the header {HEADER!r} in {PAGE.name}"
    rows = []
    for line in lines[lines.index(HEADER) + 2:]:
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip("|").split("|")]
        m = KEY.match(line)
        assert m, f"a row that names no key: {line}"
        rows.append(((m.group(1), m.group(2)), cells))
    return rows


def test_the_table_lists_every_key_once():
    keys = [k for k, _ in _rows()]
    assert len(keys) == len(set(keys)), "a key is listed twice"
    every = {(s, k) for s, ks in config.SCHEMA.items() for k in ks}
    assert set(keys) == every


def test_the_repo_column_says_ignored_for_exactly_the_user_only_keys():
    ignored = {k for k, cells in _rows() if cells[3].startswith("ignored")}
    assert ignored == config.USER_ONLY


def test_the_type_column_matches_the_schema():
    words = {"list": "list", "bool": "true or false", "int": "whole number", "str": "text",
             "choice": "one of"}
    for (s, k), cells in _rows():
        assert cells[1].startswith(words[config.SCHEMA[s][k]]), (s, k, cells[1])


def test_the_named_anchors_stay():
    assert set(ANCHORS) <= _anchors(PAGE)
