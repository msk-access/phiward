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


# where _merge keeps each key: a Config field (None: the key loads and does nothing)
FIELD = {
    ("protected_paths", "roots"): "roots", ("protected_paths", "patterns"): "patterns",
    ("protected_paths", "unresolved"): "unresolved",
    ("protected_paths", "snapshot_names"): "snapshot_names",
    ("sanitize", "packs"): "packs", ("sanitize", "names_from"): "names_from",
    ("sanitize", "patterns"): "sanitize_patterns", ("sanitize", "subjects"): "sanitize_subjects",
    ("sanitize", "inventory_limit"): "inventory_limit", ("sanitize", "table"): "sanitize_table",
    ("sanitize", "id_columns"): "sanitize_id_columns", ("sanitize", "examples"): "sanitize_examples",
    ("sanitize", "scan_allow"): "sanitize_scan_allow",
    ("copy", "remotes"): "remotes", ("copy", "ssh_config"): "ssh_config",
    ("copy", "push_limit_gib"): "push_limit_gib",
    ("remote", "hosts"): "remote_hosts", ("remote", "commands"): "remote_commands",
    ("remote", "roots"): "remote_roots", ("remote", "use_shared_connection"): "use_shared_connection",
    ("launch", "pass_env"): "launch_pass_env",
    ("broker", "write_to"): "write_to", ("broker", "net"): "net",
    ("broker", "commands"): "user_commands", ("broker", "max_output_lines"): "max_output_lines",
    ("network", "limit"): "network_limit", ("network", "allowed_domains"): "allowed_domains",
    ("git", "protected_branches"): "protected_branches",
    ("shell", "best_effort"): "shell_best_effort", ("shell", "strict"): None,
    ("shell", "commands"): None,
}
HOME = "/fake-home"
# a user's list and a project's list, for the keys a project may add to
ADDS = {
    ("protected_paths", "roots"): (["/fake/a"], ["/fake/b"]),
    ("protected_paths", "patterns"): (["/fake/*/a"], ["/fake/*/b"]),
    ("protected_paths", "snapshot_names"): ([".a"], [".b"]),
    ("sanitize", "packs"): (["genomics"], ["msk"]),
    ("git", "protected_branches"): (["main"], ["release"]),
}


def _after(user, repo):
    cfg = config.Config()
    config._merge(cfg, user, HOME, repo=False)
    config._merge(cfg, repo, HOME, repo=True)
    return cfg


def _default(sec, key):
    if (sec, key) == ("sanitize", "packs"):  # empty means the default packs
        from phiward.sanitize import DEFAULT_PACKS
        return DEFAULT_PACKS
    return getattr(config.Config(), FIELD[(sec, key)])


def test_every_key_has_its_field():
    assert set(FIELD) == {(s, k) for s, ks in config.SCHEMA.items() for k in ks}


def test_the_default_column_matches_the_code():
    for (s, k), cells in _rows():
        cell = cells[2]
        if FIELD[(s, k)] is None:
            assert cell.startswith("not set"), (s, k, cell)
            continue
        d = _default(s, k)
        if cell.startswith(("none", "not set")):
            assert d in ([], "", None), (s, k, cell, d)
        elif cell in ("true", "false"):
            assert d is (cell == "true"), (s, k, cell, d)
        elif cell.isdigit():
            assert d == int(cell) and not isinstance(d, bool), (s, k, cell, d)
        elif cell.startswith('`"'):
            assert cell == f'`"{d}"`', (s, k, cell, d)
        elif cell.startswith("`["):
            assert cell == "`[" + ", ".join(f'"{v}"' for v in d) + "]`", (s, k, cell, d)
        else:
            raise AssertionError(f"a default the test cannot read: {(s, k, cell)}")


def test_the_repo_column_says_what_the_code_does():
    for (s, k), cells in _rows():
        cell, kind, field = cells[3], config.SCHEMA[s][k], FIELD[(s, k)]
        if cell.startswith("ignored"):
            value = {"list": ["x"], "bool": True, "int": 1, "str": "none"}[kind]
            assert f"{s}.{k}" in _after({}, {s: {k: value}}).ignored, (s, k)
        elif cell.startswith("only lower"):
            d = _default(s, k)
            assert getattr(_after({s: {k: d}}, {s: {k: d + 1}}), field) == d, (s, k)
            assert getattr(_after({s: {k: d}}, {s: {k: d - 1}}), field) == d - 1, (s, k)
        elif cell.startswith("only stricter"):
            assert getattr(_after({s: {k: "ask"}}, {s: {k: "allow"}}), field) == "ask"
            assert getattr(_after({s: {k: "ask"}}, {s: {k: "deny"}}), field) == "deny"
        elif cell.startswith("adds"):
            assert (s, k) in ADDS, f"{(s, k)} says adds, but is not a list a project adds to"
            mine, theirs = ADDS[(s, k)]
            got = getattr(_after({s: {k: mine}}, {s: {k: theirs}}), field)
            assert set(mine + theirs) <= set(got), (s, k, got)
        elif cell.startswith("narrows"):
            cfg = _after({s: {k: ["wc"]}}, {s: {k: ["ls"]}})
            assert cfg.command_lists == [["wc"], ["ls"]] and cfg.user_commands == ["wc"]
        elif cell.startswith("loads, does nothing"):
            assert field is None and (s, k) not in config.USER_ONLY, (s, k)
            assert _after({}, {s: {k: True}}) == config.Config(), (s, k)
        else:
            raise AssertionError(f"a repo rule the test cannot read: {(s, k, cell)}")


def test_a_projects_packs_add_to_the_users_or_the_default_never_replace_them():
    cells = dict(_rows())[("sanitize", "packs")]
    assert "default" in cells[3] and "never replac" in cells[3], cells[3]
    from phiward.sanitize import DEFAULT_PACKS
    cfg = _after({}, {"sanitize": {"packs": ["msk", "/fake/p.toml"]}})
    assert set(DEFAULT_PACKS) | {"msk"} == set(cfg.packs)
    assert "sanitize.packs (files)" in cfg.ignored


def test_the_sample_is_the_safe_setting():
    text = PAGE.read_text(encoding="utf-8")
    sample = text.split("## Every key", 1)[1].split("```toml\n", 1)[1].split("```", 1)[0]
    data = config._toml.loads(sample)
    assert data["network"]["limit"] is True and data["network"]["allowed_domains"] == []
    assert data["broker"]["net"] is False and "write_to" not in data["broker"]
    assert data["broker"]["commands"]
