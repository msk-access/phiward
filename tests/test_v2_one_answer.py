"""One answer to "what would `phiward mcp wrap` do?": `mcp list`, `doctor`, the hook's advice and
`wrap` itself read the same state of each entry (wrapped, can wrap, listens on this machine, no
command, changed by its `cwd` or `env`, remote), so none of them suggests a step another refuses
or calls a no-op. `list` shows one line per entry, with its file. Made-up trees only."""

import io
import json
import os
import sys

import pytest

from phiward import config, doctor, mcp_config
from helpers import Tty, protect

BARE = {"command": "npx", "args": ["-y", "some-server"]}
HERE = {"type": "http", "url": "http://127.0.0.1:9/mcp"}
REMOTE = {"type": "http", "url": "https://mcp.example.invalid/x"}
NOCMD = {"command": "", "args": []}
RUN = {"command": "id"}


@pytest.fixture()
def t(tree, monkeypatch):
    b = tree / "bin"
    b.mkdir()
    (b / "phiward").write_text("#!/bin/sh\n")
    (b / "phiward").chmod(0o755)
    monkeypatch.setenv("PATH", f"{b}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tree / "repo"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.chdir(tree / "repo")
    monkeypatch.setattr(sys, "stdin", Tty())
    protect(tree, [], best_effort=False)
    return tree


def _wrapped(t, eid="00000000000000b1"):
    return {"command": str(t / "bin" / "phiward"),
            "args": ["launch", "--entry", eid, "--", "npx", "srv"]}


def _files(t, user=None, project=None):
    if user is not None:
        (t / "home" / ".claude.json").write_text(json.dumps({"mcpServers": user}))
    if project is not None:
        (t / "repo" / ".mcp.json").write_text(json.dumps({"mcpServers": project}))


def _hook(t, tool, name=None, source="user"):
    from phiward.adapters import claude
    p = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(t / "repo"),
         "permission_mode": "default", "tool_name": tool, "tool_input": RUN}
    if name is not None:
        p["mcp_server"] = {"name": name, "source": source}
    err = io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err), err.getvalue()


def _list(capsys):
    assert mcp_config.main(["list"]) == 0
    return capsys.readouterr().out


# --- the state of one entry ------------------------------------------------------------------------

def test_entry_state_names_each_kind(t):
    w = _wrapped(t)
    assert mcp_config.entry_state(w) == "wrapped"
    assert mcp_config.entry_state(BARE) == "bare"
    assert mcp_config.entry_state(REMOTE) == "remote"
    assert mcp_config.entry_state(HERE) == "here"
    assert mcp_config.entry_state(NOCMD) == "no-command"
    assert mcp_config.entry_state({"command": "a\0b"}) == "no-command"
    assert mcp_config.entry_state(dict(w, cwd="/tmp")) == "changed"
    assert mcp_config.entry_state(dict(w, env={"PATH": "/x"})) == "changed"
    # a bare entry with such a key is still one `wrap` can wrap (it then says to remove the key)
    assert mcp_config.entry_state(dict(BARE, cwd="/tmp")) == "bare"


# --- mcp list --------------------------------------------------------------------------------------

def test_list_shows_each_entry_with_its_file(t, capsys):
    _files(t, user={"dupe": _wrapped(t)}, project={"dupe": BARE})
    out = _list(capsys)
    lines = [ln for ln in out.splitlines() if ln.startswith("dupe")]
    assert len(lines) == 2, out
    assert any(".claude.json" in ln and "wrapped" in ln for ln in lines), out
    assert any(".mcp.json" in ln and "phiward mcp wrap dupe" in ln for ln in lines), out


def test_list_says_not_wrapped_in_place_of_bare(t, capsys):
    _files(t, user={"srv": BARE})
    out = _list(capsys)
    assert "BARE" not in out and "not wrapped" in out and "your rights" in out


def test_list_with_no_servers_says_so(t, capsys):
    out = _list(capsys)
    assert "no MCP servers" in out and ".claude.json" in out and ".mcp.json" in out


def test_list_offers_wrap_only_for_an_entry_wrap_would_change(t, capsys):
    # review (b): the other entry is remote, so there is nothing to wrap
    _files(t, user={"ide": HERE}, project={"ide": REMOTE})
    out = _list(capsys)
    assert "phiward mcp wrap" not in out, out
    assert "cannot be wrapped" in out


def test_list_says_a_wrappable_entry_leaves_the_name_bare_beside_one_that_cannot(t, capsys):
    _files(t, user={"ide": HERE}, project={"ide": BARE})
    out = _list(capsys)
    line = next(ln for ln in out.splitlines() if ".mcp.json" in ln)
    assert "phiward mcp wrap ide" in line and "stays" in line, out


def test_list_says_what_to_remove_from_a_changed_entry(t, capsys):
    _files(t, user={"srv": dict(_wrapped(t), cwd="/tmp")})
    out = _list(capsys)
    assert "cwd" in out and "phiward mcp wrap" not in out, out


# --- mcp wrap --------------------------------------------------------------------------------------

def test_wrap_names_the_file_of_an_entry_wrapped_already(t, capsys):
    _files(t, user={"dupe": _wrapped(t)}, project={"dupe": _wrapped(t, "00000000000000b2")})
    assert mcp_config.main(["wrap", "dupe", "--yes"]) == 0
    out = capsys.readouterr().out
    assert ".claude.json" in out and ".mcp.json" in out and "wrapped already" in out, out


def test_wrap_of_a_changed_entry_says_to_remove_the_key_not_wrapped_already(t, capsys):
    _files(t, user={"srv": dict(_wrapped(t), cwd="/tmp")})
    assert mcp_config.main(["wrap", "srv", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "wrapped already" not in out and "cwd" in out, out


# --- the hook's advice -----------------------------------------------------------------------------

def test_no_source_name_in_both_files_gets_no_wrap_advice(t):
    # review (a): both entries are wrapped; without a source the `.mcp.json` one counts as bare
    _files(t, user={"dupe": _wrapped(t)}, project={"dupe": _wrapped(t, "00000000000000b2")})
    code, err = _hook(t, "mcp__dupe__run_command")
    assert code == 2 and "phiward mcp wrap" not in err and ".mcp.json" in err, err


def test_advice_for_a_changed_entry_says_to_remove_the_key(t):
    _files(t, user={"srv": dict(_wrapped(t), cwd="/tmp")})
    code, err = _hook(t, "mcp__srv__run_command", "srv")
    assert code == 2 and "phiward mcp wrap" not in err and "cwd" in err, err


def test_advice_offers_wrap_for_a_plain_bare_entry(t):
    _files(t, user={"srv": BARE})
    code, err = _hook(t, "mcp__srv__run_command", "srv")
    assert code == 2 and "phiward mcp wrap srv" in err, err


# --- doctor ----------------------------------------------------------------------------------------

def _doctor(t):
    return "\n".join(doctor.mode_report(str(t / "repo"), str(t / "home"),
                                        config.load(str(t / "repo"))))


def test_doctor_does_not_offer_wrap_for_a_server_that_cannot_be_wrapped(t):
    _files(t, user={"ide": HERE, "srv": BARE})
    out = _doctor(t)
    assert "phiward mcp wrap srv" in out, out
    assert "phiward mcp wrap ide" not in out and "cannot be wrapped" in out and "ide" in out, out


def test_doctor_headless_lists_only_wrappable_names_for_wrap(t):
    _files(t, user={"ide": HERE, "srv": BARE})
    probs = "\n".join(doctor.headless_problems(str(t / "repo"), str(t / "home")))
    assert "srv" in probs and "cannot be wrapped" in probs, probs


# an entry whose `args` is not a list has no command phiward can read: the hook's advice says
# it cannot be wrapped, as `list` does, and never offers `wrap`
def test_advice_for_an_entry_with_args_that_are_not_a_list_does_not_offer_wrap(t, capsys):
    _files(t, user={"x": {"command": "srv", "args": "--flag"}})
    rc, err = _hook(t, "mcp__x__run_command", "x", "user")
    assert rc == 2
    assert "phiward mcp wrap" not in err and "cannot be wrapped" in err, err
    assert "cannot be wrapped" in _list(capsys)


# --- the docs say what `list` says -----------------------------------------------------------------

def _table_says():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / "docs" / "modes.md").read_text()
    start = text.index("| `list` says |")
    rows = [ln for ln in text[start:].splitlines()[2:] if ln.startswith("|")]
    out = []
    for ln in rows:
        out += [x.strip() for x in ln.split("|")[1].split(" / ")]
    return out


def test_every_list_answer_is_in_the_docs_table_and_back(t):
    from phiward.mcp_config import Entry, entry_text
    w = _wrapped(t)
    samples = {
        "wrapped": w, "remote": REMOTE, "bare": BARE, "here": HERE, "no-command": NOCMD,
        "changed": dict(w, cwd="/tmp"),
        "by name": dict(w, command="phiward"),
        "other launcher": dict(w, command=str(t / "elsewhere" / "phiward")),
        "no program": {"command": w["command"], "args": ["launch", "srv"]},
        "no id": {"command": w["command"], "args": ["launch", "--", "npx", "srv"]},
        "runner": {"command": "uvx", "args": ["phiward", "launch", "--", "npx", "srv"]},
        "options": {"command": w["command"],
                    "args": ["launch", "--memory", "--entry", "00000000000000b4", "--", "npx",
                             "srv"]},
        "python -m": {"command": sys.executable,
                      "args": ["-m", "phiward", "launch", "--entry", "00000000000000b3", "--",
                               "npx", "srv"]},
    }
    says = _table_says()
    used = set()
    home = str(t / "home")
    for kind, spec in samples.items():
        e = Entry("x", home + "/.claude.json", "user", spec, mcp_config.entry_state(spec))
        text = entry_text(e, home)
        hit = [s for s in says if s.replace("`", "") in text.replace("`", "")]
        assert hit, (kind, text)
        used.update(hit)
    copied = Entry("x", home + "/.claude.json", "user", w, "copied")
    used.update(s for s in says if s.replace("`", "") in entry_text(copied, home).replace("`", ""))
    assert set(says) == used, set(says) - used
