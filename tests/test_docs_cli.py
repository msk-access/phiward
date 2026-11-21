"""docs/cli.md says what each command's help says: the same usage lines, and one row for each
subcommand and option of the help. Each help is the one `phiward COMMAND [SUB] --help` prints,
taken in-process. The flags of `mcp list|wrap|unwrap` are also checked against its parser; the
other parsers are written by hand, and nothing here checks the help against them."""

import contextlib
import io
import re
from pathlib import Path

import pytest

from phiward import cli, mcp_config

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "cli.md"

# each section of cli.md, and the help calls it follows: a subcommand's help is its command's
SECTIONS = {
    "phiward setup": [["setup"]],
    "phiward pin": [["pin"]],
    "phiward broker": [["broker"]],
    "phiward carryover": [["carryover"]] + [["carryover", s] for s in
                                            ("status", "add", "show", "accept", "reset")],
    "phiward pseudonymize": [["pseudonymize"]],
    "phiward init": [["init"]],
    "phiward install claude": [["install"], ["install", "claude"]],
    "phiward doctor": [["doctor"]],
    "phiward mcp list, wrap and unwrap": [["mcp", "list"], ["mcp", "wrap"], ["mcp", "unwrap"]],
    "phiward run": [["run"]],
    "phiward copy": [["copy"]],
    "phiward launch": [["launch"]],
    "phiward check": [["check"]],
    "phiward sanitize": [["sanitize"]],
    # what the tools run reads a payload or the repository and fails closed on anything else,
    # so `hook claude --help` and `git-hook pre-commit --help` are no help calls: the parent's is
    "phiward hook claude": [["hook"]],
    "phiward session-note claude": [["session-note"]],
    "phiward mcp": [["mcp"]],
    "phiward git-hook": [["git-hook"], ["git-hook", "install"]],
}
# the words of cli.USAGE that start each command's line, and its section
USAGE_LINES = {
    "setup": "phiward setup", "pin": "phiward pin", "broker": "phiward broker",
    "carryover": "phiward carryover", "pseudonymize": "phiward pseudonymize",
    "init": "phiward init", "install": "phiward install claude", "doctor": "phiward doctor",
    "mcp list|wrap|unwrap": "phiward mcp list, wrap and unwrap", "run": "phiward run",
    "copy": "phiward copy", "launch": "phiward launch", "check": "phiward check",
    "sanitize": "phiward sanitize", "hook": "phiward hook claude",
    "session-note": "phiward session-note claude", "mcp": "phiward mcp",
    "git-hook": "phiward git-hook",
}
_FLAG = re.compile(r"(?<![\w-])(--?[A-Za-z][\w-]*)")


@pytest.fixture()
def quiet_home(tmp_path, monkeypatch):
    """A made-up home and no config: a help call reads nothing of the operator's."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for v in ("PHIWARD_CONFIG", "PHIWARD_SPOOL", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
              "CLAUDE_CONFIG_DIR"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.chdir(tmp_path)


def _help(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(argv + ["--help"])
    assert rc == 0 and not err.getvalue(), (argv, rc, err.getvalue())
    assert out.getvalue(), (argv, "no help printed")
    return out.getvalue()


def _usage(text: str) -> list:
    """The usage lines: from the first `usage:` to the first line that does not go on with it."""
    lines = text.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("usage:"))
    out = [lines[start]]
    for ln in lines[start + 1:]:
        if not ln.startswith(" ") or not ln.strip():
            break
        out.append(ln)
    return [ln.rstrip() for ln in out]


def _block(text: str, title: str) -> list:
    """The names of a help block (`Options:`, `Commands:`): each line indented by two spaces
    starts an entry; its first word is a name, and so is each later word of its spec (the part
    before two spaces) that starts with `-`."""
    lines = text.splitlines()
    if title + ":" not in lines:
        return []
    names = []
    for ln in lines[lines.index(title + ":") + 1:]:
        if not ln.strip():
            break
        if ln.startswith("  ") and not ln.startswith("   "):
            spec = re.split(r"\s{2,}", ln.strip())[0].split()
            names.append(spec[0].rstrip(","))
            names += [w.rstrip(",") for w in spec[1:] if w.startswith("-")]
    return names


def _sections() -> dict:
    out, name = {}, None
    for ln in PAGE.read_text(encoding="utf-8").splitlines():
        if ln.startswith("#"):
            m = re.match(r"^### (phiward .+)$", ln)
            name = m.group(1) if m else None
            if name:
                out[name] = []
        elif name:
            out[name].append(ln)
    return out


def _page_usage(lines: list) -> list:
    start = lines.index("```text")
    end = lines.index("```", start + 1)
    return [ln.rstrip() for ln in lines[start + 1:end]]


def _page_names(lines: list) -> list:
    names = []
    for ln in lines:
        if ln.startswith("| `"):
            cell = ln.split("|")[1]
            names += [span.split()[0].rstrip(",") for span in re.findall(r"`([^`]+)`", cell)]
    return names


def test_the_page_has_one_section_for_each_command_the_cli_runs():
    dispatched = set(re.findall(r'cmd == "([a-z-]+)"', (ROOT / "src" / "phiward" / "cli.py")
                                .read_text()))
    assert set(_sections()) == set(SECTIONS)
    assert {s.split()[1] for s in SECTIONS} == dispatched


@pytest.mark.parametrize("section", list(SECTIONS))
def test_each_section_says_what_the_help_says(section, quiet_home):
    calls = SECTIONS[section]
    text = _help(calls[0])
    for argv in calls[1:]:  # a subcommand's --help is its command's
        assert _help(argv) == text, argv
    assert "Options:" in text.splitlines(), (section, "the help has no Options block")
    lines = _sections()[section]
    assert _page_usage(lines) == _usage(text), section
    help_names = _block(text, "Commands") + _block(text, "Options")
    assert sorted(set(_page_names(lines))) == sorted(set(help_names)), section


def test_every_flag_of_the_short_usage_is_in_its_command_help(quiet_home):
    found = {}
    current = None
    for ln in cli.USAGE.splitlines():
        if ln.startswith("  ") and not ln.startswith("   "):
            words = ln.split()
            key = " ".join(words[:2]) if " ".join(words[:2]) in USAGE_LINES else words[0]
            current = USAGE_LINES[key]
            found.setdefault(current, set())
            ln = ln.replace(key, "", 1)
        elif not ln.startswith("   "):
            current = None
        if current:
            found[current] |= set(_FLAG.findall(ln))
    assert set(found) == set(SECTIONS)
    for section, flags in found.items():
        text = _help(SECTIONS[section][0])
        assert flags <= set(_block(text, "Options")), (section, flags)


def test_the_mcp_flags_on_the_page_are_the_parsers(quiet_home):
    lines = _sections()["phiward mcp list, wrap and unwrap"]
    names = set(_page_names(lines))
    parser = {f for flags in mcp_config._FLAGS.values() for f in flags}
    assert names - {"-h", "--help"} - set(mcp_config._FLAGS) == parser
    assert set(mcp_config._FLAGS) <= names
