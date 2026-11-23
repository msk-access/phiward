"""`--resume` and `-c` under `phiward launch --tool claude`: this project's transcripts are kept
between sessions, by default.

- The tool's environment names one transcript folder (`CLAUDE_CODE_PROJECT_DIR_NAME`, the first
  16 hex digits of the sha256 of the project's real path); the operator's own value never wins.
- At the end, only `projects/<16 hex>/` of the session's config folder is copied into a store
  beside the trusted copy (`~/.phiward/carryover/claude/transcripts/`), never read as text:
  plain files and real folders only, without `memory/` and `mcp-tasks/` at any depth. Sessions
  that end one after the other are merged, never replaced.
- At the start, the store's folder for this project (only that one) is copied into the new
  session's config folder.
- `[launch] keep_transcripts = false` (user config only) turns it off; a resume flag then gets a
  NOTE.

Made-up data only (FAKE-PT-0001)."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from helpers import needs_confine, tool_py
from phiward import carryover, config, confine, wholetool


def _key(tree):
    return hashlib.sha256(os.fsencode(os.path.realpath(tree / "repo"))).hexdigest()[:16]


def base(tree):
    return tree / "home" / ".phiward" / "tools" / "claude"


def kept(tree):
    return tree / "home" / ".phiward" / "carryover" / "claude" / "transcripts"


def _store(tree):
    return carryover.Store("claude", str(tree / "home"))


def _user_config(text):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + text)


# --- config ---------------------------------------------------------------------------------------

def test_config_keep_transcripts_is_on_by_default(tree):
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem and cfg.launch_keep_transcripts is True


def test_config_the_user_config_turns_it_off(tree):
    _user_config("[launch]\nkeep_transcripts = false\n")
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem and cfg.launch_keep_transcripts is False


def test_config_a_repo_file_cannot_set_it(tree):
    (tree / "repo" / ".phiward.toml").write_text("[launch]\nkeep_transcripts = false\n")
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem and cfg.launch_keep_transcripts is True
    assert "launch.keep_transcripts" in cfg.ignored


def test_config_a_string_value_is_a_problem(tree):
    _user_config('[launch]\nkeep_transcripts = "no"\n')
    assert "keep_transcripts" in config.load(str(tree / "repo")).problem


# --- a1a and the environment: through build -------------------------------------------------------

@pytest.fixture
def build(tree, monkeypatch, capsys):
    # on this Mac the test's folder may be in the per-user temp folder, a write place
    monkeypatch.setattr(wholetool, "_darwin_user_dir", lambda name: "")

    def run(args, env=None):
        env = dict(os.environ) if env is None else env
        store = _store(tree)
        capsys.readouterr()
        cmd, child_env, fds, _project, _ready, proxy = wholetool.build(
            [tool_py(tree)] + list(args), str(tree / "repo"), env, wholetool.ADAPTERS["claude"],
            store=store)
        err = capsys.readouterr().err
        for fd in fds:
            os.close(fd)
        proxy.close()
        confine.release_profile(cmd)
        store.end(str(base(tree)))
        return child_env, err
    return run


NOTE = "keep_transcripts is off"


@needs_confine
@pytest.mark.parametrize("flag", ["--resume", "-r", "--continue", "-c"])
def test_a1a_a_resume_flag_with_transcripts_off_gets_the_note(tree, build, flag):
    _user_config("[launch]\nkeep_transcripts = false\n")
    _env, err = build([flag])
    assert NOTE in err and "[launch] keep_transcripts" in err, err


@needs_confine
def test_a1a_no_note_without_a_resume_flag(tree, build):
    _user_config("[launch]\nkeep_transcripts = false\n")
    _env, err = build(["-p", "hi"])
    assert NOTE not in err, err


@needs_confine
def test_a1a_no_note_with_the_default(tree, build):
    _env, err = build(["--resume"])
    assert NOTE not in err, err


@needs_confine
def test_a1b_the_tool_gets_this_projects_transcript_folder(tree, build):
    child_env, _err = build([])
    assert child_env["CLAUDE_CODE_PROJECT_DIR_NAME"] == _key(tree)


@needs_confine
def test_a1b_the_operators_own_value_does_not_win(tree, build):
    child_env, _err = build([], env=dict(os.environ, CLAUDE_CODE_PROJECT_DIR_NAME="x"))
    assert child_env["CLAUDE_CODE_PROJECT_DIR_NAME"] == _key(tree)


@needs_confine
def test_a1b_transcripts_off_keeps_nothing(tree, build):
    _user_config("[launch]\nkeep_transcripts = false\n")
    build([])
    rec = [json.loads(p.read_text()) for p in
           (tree / "home" / ".phiward" / "carryover" / "claude" / "sessions").glob("*.json")]
    assert all(not r.get("transcripts") for r in rec), rec


# --- a1b: the store, out at the end and in at the start ------------------------------------------

def _session(tree, name, key):
    s = _store(tree)
    run = base(tree) / "runs" / name
    msgs = s.start(str(base(tree)), str(run), transcripts=key)
    return s, run, msgs


def _plant(run, key):
    p = run / "config" / "projects" / key
    (p / "abc" / "tool-results").mkdir(parents=True)
    (p / "abc.jsonl").write_text("FAKE-PT-0001 masked\n")
    (p / "abc" / "tool-results" / "t1.txt").write_text("result\n")
    (p / "abc" / "mcp-tasks").mkdir()
    (p / "abc" / "mcp-tasks" / "m.json").write_text("{}\n")
    (p / "memory").mkdir()
    (p / "memory" / "MEMORY.md").write_text("planted\n")
    os.symlink("/etc/hosts", p / "x.jsonl")
    other = run / "config" / "projects" / "other"
    other.mkdir()
    (other / "y.jsonl").write_text("y\n")


def test_a1b_only_this_projects_plain_transcripts_come_back(tree):
    key = _key(tree)
    s, run, _ = _session(tree, "one", key)
    _plant(run, key)
    msgs = s.end(str(base(tree)))
    assert any("transcript" in m and "1" in m for m in msgs), msgs  # the link, dropped
    s2, run2, msgs2 = _session(tree, "two", key)
    try:
        q = run2 / "config" / "projects"
        assert (q / key / "abc.jsonl").read_text() == "FAKE-PT-0001 masked\n", msgs2
        assert (q / key / "abc" / "tool-results" / "t1.txt").read_text() == "result\n"
        assert not (q / key / "abc" / "mcp-tasks").exists()
        assert not (q / key / "memory").exists()
        assert not os.path.lexists(q / key / "x.jsonl")
        assert not (q / "other").exists()
    finally:
        s2.end(str(base(tree)))


def test_a1b_the_record_names_the_folder(tree):
    key = _key(tree)
    s, run, _ = _session(tree, "one", key)
    try:
        rec = json.loads((tree / "home" / ".phiward" / "carryover" / "claude" / "sessions" /
                          "one.json").read_text())
        assert rec["transcripts"] == key
    finally:
        s.end(str(base(tree)))


def test_a1b_another_projects_store_is_not_copied_in(tree):
    key = _key(tree)
    (kept(tree) / "0123456789abcdef").mkdir(parents=True)
    (kept(tree) / "0123456789abcdef" / "z.jsonl").write_text("other project\n")
    (kept(tree) / key).mkdir()
    (kept(tree) / key / "mine.jsonl").write_text("mine\n")
    s, run, _ = _session(tree, "one", key)
    try:
        q = run / "config" / "projects"
        assert (q / key / "mine.jsonl").read_text() == "mine\n"
        assert sorted(os.listdir(q)) == [key]
    finally:
        s.end(str(base(tree)))


def test_a1b_two_sessions_that_end_one_after_the_other_are_merged(tree):
    key = _key(tree)
    (kept(tree) / key).mkdir(parents=True)
    (kept(tree) / key / "old.jsonl").write_text("old\n")
    a, run_a, _ = _session(tree, "a", key)
    b, run_b, _ = _session(tree, "b", key)
    (run_a / "config" / "projects" / key / "a.jsonl").write_text("a\n")
    (run_b / "config" / "projects" / key / "b.jsonl").write_text("b\n")
    a.end(str(base(tree)))
    b.end(str(base(tree)))
    assert sorted(os.listdir(kept(tree) / key)) == ["a.jsonl", "b.jsonl", "old.jsonl"]


def test_a1b_a_file_is_replaced_only_by_a_newer_one(tree):
    key = _key(tree)
    (kept(tree) / key).mkdir(parents=True)
    f = kept(tree) / key / "s.jsonl"
    f.write_text("v1\n")
    os.utime(f, (1_000_000, 1_000_000))
    a, run_a, _ = _session(tree, "a", key)
    b, run_b, _ = _session(tree, "b", key)
    copied = run_a / "config" / "projects" / key / "s.jsonl"
    assert os.stat(copied).st_mtime == 1_000_000  # the time is kept at the copy
    copied.write_text("v1\nv2\n")  # a resumed session appends
    a.end(str(base(tree)))
    assert f.read_text() == "v1\nv2\n"
    b.end(str(base(tree)))  # b ends with the older copy: it does not win
    assert f.read_text() == "v1\nv2\n"


def test_a1b_a_session_that_turns_its_folder_into_a_link_gives_nothing(tree):
    key = _key(tree)
    (tree / "pub" / key).mkdir(parents=True)
    (tree / "pub" / key / "outside.jsonl").write_text("not the session's\n")
    s, run, _ = _session(tree, "one", key)
    proj = run / "config" / "projects"
    assert not proj.exists()  # an empty store gives no folder
    os.symlink(tree / "pub", proj)
    s.end(str(base(tree)))
    assert not (kept(tree) / key / "outside.jsonl").exists()


def test_a1b_without_a_key_nothing_is_kept(tree):
    key = _key(tree)
    s, run, _ = _session(tree, "one", "")
    p = run / "config" / "projects" / key
    p.mkdir(parents=True)
    (p / "abc.jsonl").write_text("x\n")
    s.end(str(base(tree)))
    assert not (kept(tree) / key).exists()


def test_a1b_status_lists_the_transcripts(tree):
    key = _key(tree)
    (kept(tree) / key).mkdir(parents=True)
    (kept(tree) / key / "a.jsonl").write_text("a\n")
    lines = "\n".join(_store(tree).status(str(base(tree))))
    assert str(kept(tree)) in lines and key in lines and "--resume" in lines, lines
