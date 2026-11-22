"""docs/endpoint-security.md, the page for security teams: its list of command lines.

The page holds one block of command-line shapes (after the `argv-shapes` marker): each entry
has an ID, one or more `argv` lines (the words as the kernel shows them, placeholders in `<>`)
and one `regex` line (a suggested command-line regex, or `-` for none). This file reads that
block (`shapes()`), and test_macos_processes.py compares it with what phiward starts.

Here, on every platform: the block parses; each ID has a row in the page's process table and the
table names no other; each regex compiles, starts with `^`, is at most 256 characters and
matches every shape of its entry (with made-up values for the placeholders); and no regex
matches inline code (`python -c`, `sh -c`, `sandbox-exec -p`), the project hook's fixed line
aside. Made-up names only."""

import re
import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "endpoint-security.md"
MARKER = "<!-- argv-shapes"
_ENTRY = re.compile(r"^([A-Z][0-9]+) +(argv|regex) +(.+?)\s*$")
_ROW = re.compile(r"^\| *([A-Z][0-9]+) *\|")


def shapes() -> dict:
    """{ID: {"argv": [shape, ...], "regex": text or None}} from the page's block."""
    text = PAGE.read_text(encoding="utf-8")
    start = text.index(MARKER)
    fence = text.index("```text\n", start) + len("```text\n")
    block = text[fence:text.index("\n```", fence)]
    out: dict = {}
    for line in block.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        m = _ENTRY.match(line)
        assert m, f"a line of the block that is not `ID argv|regex TEXT`: {line!r}"
        e = out.setdefault(m.group(1), {"argv": [], "regex": None, "has_regex": False})
        if m.group(2) == "argv":
            e["argv"].append(m.group(3))
        else:
            assert not e["has_regex"], f"{m.group(1)} has two regex lines"
            e["has_regex"] = True
            e["regex"] = None if m.group(3) == "-" else m.group(3)
    return out


def all_shapes() -> set:
    return {s for e in shapes().values() for s in e["argv"]}


def _awk_program() -> str:
    from phiward import install
    m = re.search(r'/usr/bin/awk ("(?:[^"\\]|\\.)*")', install.CLEAN_ENV)
    assert m
    return shlex.split(m.group(1))[0]


def _project_texts() -> dict:
    from phiward import install
    return {"<project-hook>": shlex.split(install.PROJECT_HOOK)[2],
            "<project-prompt-hook>": shlex.split(install.PROJECT_PROMPT_HOOK)[2],
            "<project-note>": shlex.split(install.PROJECT_NOTE)[2]}


# made-up values for the placeholders, as an endpoint tool would see them
SAMPLES = {
    "<python>": "/Users/me/.local/share/uv/tools/phiward/bin/python",
    "<PKG>": "/Users/me/.local/share/uv/tools/phiward/lib/python3.12/site-packages",
    "<plugin>": "/Users/me/.claude/plugins/cache/phiward/phiward/0.2.0",
    "<launcher>": "/Users/me/.local/bin/phiward",
    "<profile>": "/Users/me/.phiward/profiles/0123456789abcdef0123456789abcdef.sb",
    "<home>": "/Users/me",
    "<uid>": "501",
    "<entry>": "0123456789abcdef",
    "<path>": "/Users/me/data/FAKE-PT-0001",
    "<source>": "/Users/me/data/FAKE-PT-0001.bam",
    "<dest>": "/Users/me/data/copies/",
    "<ssh-config>": "/Users/me/.ssh/phiward-config",
    "<socket>": "/Users/me/.ssh/cm-hpc",
    "<host>": "hpc-login",
    "<remote-pull>": "tar -c -f - -C /work/me -- res",
    "<remote-push>": "",  # filled from remote.receive_script
    "<record>": "/Users/me/.local/share/uv/tools/phiward/lib/python3.12/site-packages/"
                "phiward-0.2.0.dist-info/RECORD",
    "<claude>": "/Users/me/.local/bin/claude",
    "<tool>": "/Users/me/.local/bin/claude",
    "<command>": "/usr/bin/wc",
    "<server>": "/usr/local/bin/made-up-server",
    "<arguments>": "rev-parse --show-toplevel",
    "<repo>": "/Users/me/src/made-up-repo",
    "...": "--made-up words",
}


def sample(shape: str) -> str:
    """The shape as one command line, its placeholders filled in."""
    from phiward import remote
    fill = dict(SAMPLES, **_project_texts(), **{"<awk-program>": _awk_program(),
                                                "<remote-push>": remote.receive_script(
                                                    "/work/me/proj")})
    return re.sub("|".join(re.escape(k) for k in sorted(fill, key=len, reverse=True)),
                  lambda m: fill[m.group(0)], shape)


def test_the_block_parses_and_each_entry_has_shapes_and_a_regex_line():
    got = shapes()
    assert got, "the page lists no command lines"
    for i, e in got.items():
        assert e["argv"], f"{i} has no argv line"
        assert e["has_regex"], f"{i} has no regex line (`-` for none)"
    assert len(all_shapes()) == sum(len(e["argv"]) for e in got.values()), \
        "a shape is listed twice"


def test_the_process_table_and_the_block_name_the_same_ids():
    rows = set()
    text = PAGE.read_text(encoding="utf-8")
    for line in text[:text.index(MARKER)].splitlines():
        m = _ROW.match(line)
        if m:
            rows.add(m.group(1))
    assert rows == set(shapes()), (sorted(rows - set(shapes())), sorted(set(shapes()) - rows))


def test_each_regex_is_short_anchored_and_matches_its_shapes():
    for i, e in shapes().items():
        rx = e["regex"]
        if rx is None:
            continue
        assert rx.startswith("^"), (i, rx)
        assert len(rx) <= 256, (i, len(rx))
        r = re.compile(rx)
        for s in e["argv"]:
            assert r.search(sample(s)), (i, rx, sample(s))


def test_no_regex_matches_inline_code():
    inline = [sample("<python> -c 'import os'"), sample("<python> -I -S -c 'import os'"),
              "/bin/sh -c 'echo made-up'", "sh -c 'echo made-up'",
              "/usr/bin/sandbox-exec -p '(version 1)(allow default)' /bin/ls",
              "/usr/bin/awk 'BEGIN{print 1}'", "/usr/bin/perl -e 'print 1'"]
    for i, e in shapes().items():
        if e["regex"] is None:
            continue
        for line in inline:
            assert not re.search(e["regex"], line), (i, e["regex"], line)


FIXED_TEXTS = ("<project-hook>", "<project-prompt-hook>", "<project-note>", "<awk-program>",
               "<remote-push>")


def test_a_line_with_fixed_code_in_it_gets_no_prefix_regex():
    """A regex for a command line that carries fixed code (the project hook, its awk program, a
    push's receiver) would also admit that code with more after it; the full text does not fit
    in 256 characters. So such a row has no regex (`-`), and the page says how to match it."""
    for i, e in shapes().items():
        if any(t in s for s in e["argv"] for t in FIXED_TEXTS):
            assert e["regex"] is None, (i, e["regex"])
    text = PAGE.read_text(encoding="utf-8")
    assert "exact" in text and "hash" in text, "the page says how to match those lines"
