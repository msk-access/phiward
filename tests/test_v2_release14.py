"""Round 14: the whole-branch review's security and behaviour findings. Made-up trees only.

B1: the self-check child reads no compiled file from any folder: its bytecode prefix is one that
cannot exist (a folder another program could write would let it plant a .pyc the child runs)."""

import importlib.util
import json
import os
import subprocess
import sys

import pytest

from phiward import selfcheck


def _plant_json_pyc(prefix, marker):
    """An unchecked hash-based .pyc for `json`, under `prefix` as the child would look for it,
    that writes `marker`. Returns False when nothing can be planted there."""
    import importlib._bootstrap_external as be
    old = sys.pycache_prefix
    try:
        sys.pycache_prefix = prefix
        target = importlib.util.cache_from_source(json.__file__)
    finally:
        sys.pycache_prefix = old
    src = open(json.__file__).read()
    code = compile(f"open({str(marker)!r}, 'w').close()\n" + src, json.__file__, "exec")
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(be._code_to_hash_pyc(code, b"\0" * 8, checked=False))
    except OSError:
        return False
    return True


def _prefix(cmd):
    for i, a in enumerate(cmd):
        if a == "-X" and cmd[i + 1].startswith("pycache_prefix="):
            return cmd[i + 1].split("=", 1)[1]
    return None


def _record(tmp_path, monkeypatch):
    site = tmp_path / "site"
    (site / "phiward").mkdir(parents=True)
    dist = site / "phiward-0.dist-info"
    dist.mkdir()
    (dist / "RECORD").write_text("")
    monkeypatch.setattr(selfcheck, "_record_path", lambda: str(dist / "RECORD"))
    monkeypatch.setattr(selfcheck, "_running_package", lambda: str(site / "phiward"))


def test_the_check_child_runs_no_planted_compiled_file(tmp_path, monkeypatch):
    _record(tmp_path, monkeypatch)
    marker = tmp_path / "ran"
    real = subprocess.run
    seen = []

    def run(cmd, *a, **k):
        prefix = _prefix(cmd)
        seen.append(prefix)
        if prefix:
            _plant_json_pyc(prefix, marker)
        return real(cmd, *a, **k)
    monkeypatch.setattr(selfcheck.subprocess, "run", run)
    selfcheck.check_isolated()
    selfcheck.check_full_isolated()
    assert len(seen) == 2 and all(seen), seen
    assert not marker.exists(), "the check child ran a planted compiled file"
    # the prefix is no folder at all: nothing can be planted there
    assert not any(_plant_json_pyc(p, marker) for p in seen)


# --- B12: self-check edges


def test_a_negative_zero_constant_is_not_the_same_code():
    a, b = compile("x = -0.0", "f", "exec"), compile("x = 0.0", "f", "exec")
    assert not selfcheck._same_code(a, b)
    a, b = compile("x = -0j", "f", "exec"), compile("x = 0j", "f", "exec")
    assert not selfcheck._same_code(a, b)
    assert selfcheck._same_code(compile("x = 1.5", "f", "exec"), compile("x = 1.5", "g", "exec"))


def test_install_does_not_wait_on_a_fifo_named_like_a_module(tmp_path, monkeypatch):
    import threading
    home = tmp_path / "home"
    root = home / "venv"
    root.mkdir(parents=True)
    os.chmod(home, 0o755)
    (root / "ok.py").write_text("x = 1\n")
    os.mkfifo(root / "x.py")
    monkeypatch.setattr(selfcheck, "_home", lambda: str(home))
    places = selfcheck.Places(str(root), [str(root)], [], "", "")
    done = []
    t = threading.Thread(target=lambda: done.append(
        selfcheck.fix_modes(places, scripts=(), package_dir=str(home / "nope"))), daemon=True)
    t.start()
    t.join(15)
    assert done, "install waited on a FIFO"
    assert (root / "__pycache__").is_dir()


# --- B6: install writes no file through a planted link

WANT = {"hooks": {"PreToolUse": []}, "sandbox": {"filesystem": {"denyWrite": ["/x"]}}}


def test_install_writes_settings_never_through_a_planted_link(tmp_path):
    from phiward import install
    claude = tmp_path / "proj" / ".claude"
    claude.mkdir(parents=True)
    target = claude / "settings.json"
    target.write_text('{"a": 1}\n')
    outside = tmp_path / "outside"
    outside.mkdir()
    for name in ("settings.json.phiward.tmp", "settings.json.phiward.bak"):
        (outside / name).write_text("keep\n")
        os.symlink(outside / name, claude / name)
    assert install._write(str(target), WANT, [], ["--yes"]) == 0
    for name in ("settings.json.phiward.tmp", "settings.json.phiward.bak"):
        assert (outside / name).read_text() == "keep\n"
    assert json.loads(target.read_text())["sandbox"]["filesystem"]["denyWrite"] == ["/x"]


def test_install_refuses_settings_that_are_a_link(tmp_path):
    from phiward import install
    claude = tmp_path / "proj" / ".claude"
    claude.mkdir(parents=True)
    real = tmp_path / "real.json"
    real.write_text('{"a": 1}\n')
    os.symlink(real, claude / "settings.json")
    assert install._write(str(claude / "settings.json"), WANT, [], ["--yes"]) == 3
    assert real.read_text() == '{"a": 1}\n'


# --- B3: a search refusal names one correct step


def _search(tree, tool, inp):
    import io
    from phiward.adapters import claude
    p = {"session_id": "f", "hook_event_name": "PreToolUse", "cwd": str(tree / "repo"),
         "permission_mode": "default", "tool_name": tool, "tool_input": inp}
    err = io.StringIO()
    return claude.main(io.StringIO(json.dumps(p)), io.StringIO(), err), err.getvalue()


def _data_in_repo(tree):
    from helpers import protect
    (tree / "repo" / "data").mkdir()
    (tree / "repo" / "data" / "FAKE-PT-0009.csv").write_text("SECRET-CONTENT-0009\n")
    protect(tree, [], root="repo/data")


def test_a_search_limited_to_a_folder_without_protected_data_is_allowed(tree):
    _data_in_repo(tree)
    for tool, inp in (("Glob", {"pattern": "src/**/*.py"}),
                      ("Grep", {"pattern": "x", "path": "src"}),
                      ("Glob", {"pattern": "*.py", "path": str(tree / "repo" / "src")})):
        code, err = _search(tree, tool, inp)
        assert code == 0, (tool, inp, err)


def test_a_search_from_above_protected_data_names_the_narrower_path(tree):
    _data_in_repo(tree)
    for tool, inp in (("Grep", {"pattern": "def main"}), ("Grep", {"pattern": "x", "path": "."})):
        code, err = _search(tree, tool, inp)
        assert code == 2, (tool, inp)
        assert "`path`" in err and "phiward run" not in err, err
    # a pattern that lists protected files names them: the gateway is the step there
    code, err = _search(tree, "Glob", {"pattern": "**/*.csv"})
    assert code == 2 and "phiward run" in err, err


def test_a_search_into_protected_data_stays_refused(tree):
    _data_in_repo(tree)
    for pat in ("src/../data/*", "{src,data}/*", "*/*.csv", "data/*"):
        code, err = _search(tree, "Glob", {"pattern": pat})
        assert code == 2, (pat, err)


def test_a_refusal_with_its_own_step_gets_no_second_one(tree):
    code, err = _search(tree, "Glob", {"pattern": "*/../x", "path": str(tree / "repo")})
    assert code == 2 and "without the `..`" in err and "phiward run" not in err, err


# --- B2/B10: what Claude Code runs as code, and writes outside the sandbox's folders

MODES = ("default", "acceptEdits", "plan", "auto", "dontAsk", "bypassPermissions", None)
PROMPTING = ("default", "acceptEdits", "plan")


def _write(tree, path, mode="default", tool="Write", cwd=None, inp=None):
    import io
    from phiward.adapters import claude
    p = {"session_id": "f", "hook_event_name": "PreToolUse", "cwd": str(cwd or tree / "repo"),
         "tool_name": tool, "tool_input": inp or {"file_path": str(path), "content": "x"}}
    if mode is not None:
        p["permission_mode"] = mode
    out, err = io.StringIO(), io.StringIO()
    code = claude.main(io.StringIO(json.dumps(p)), out, err)
    asked = '"ask"' in out.getvalue()
    return ("deny" if code == 2 else "ask" if asked else "allow"), err.getvalue() + out.getvalue()


def test_settings_git_and_launchers_are_refused_in_every_mode(tree, monkeypatch):
    home, repo = tree / "home", tree / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    pathbin = tree / "pathbin"
    pathbin.mkdir()
    monkeypatch.setenv("PATH", f"{pathbin}:{os.environ['PATH']}")
    places = [repo / ".claude" / "settings.json", repo / ".claude" / "settings.local.json",
              home / ".claude" / "settings.json", repo / ".mcp.json", repo / "sub" / ".mcp.json",
              repo / ".git" / "config", repo / ".git" / "hooks" / "pre-commit",
              home / ".gitconfig", home / ".config" / "git" / "config", pathbin / "phiward"]
    for mode in MODES:
        for p in places:
            verdict, why = _write(tree, p, mode)
            assert verdict == "deny", (mode, p, why)


def test_a_shell_start_up_file_is_refused_when_the_project_is_the_home_folder(tree):
    verdict, why = _write(tree, tree / "home" / ".zshrc", "bypassPermissions", cwd=tree / "home")
    assert verdict == "deny", why


CODE = [(".claude", "skills", "x", "SKILL.md"), (".claude", "agents", "a.md"),
        (".claude", "commands", "c.md"), (".claude", "hooks", "h.sh"),
        (".claude", "workflows", "w.js"), (".claude", "plugins", "p", "hooks", "hooks.json"),
        (".claude", "routines", "r.md"), (".claude", "launch.json"),
        (".claude", "scheduled_tasks.json")]


def test_a_code_place_asks_where_the_session_prompts_and_is_refused_elsewhere(tree):
    for base in (tree / "repo", tree / "home"):
        for parts in CODE:
            p = base.joinpath(*parts)
            for mode in MODES:
                verdict, why = _write(tree, p, mode)
                assert verdict == ("ask" if mode in PROMPTING else "deny"), (mode, p, why)


def test_the_user_config_folder_under_another_name_is_a_code_place(tree, monkeypatch):
    cfgdir = tree / "repo" / "cfgdir"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfgdir))
    assert _write(tree, cfgdir / "skills" / "x" / "SKILL.md", "bypassPermissions")[0] == "deny"
    assert _write(tree, cfgdir / "settings.json", "default")[0] == "deny"


def test_a_worktree_is_not_a_code_place_but_its_own_claude_folder_is(tree):
    wt = tree / "repo" / ".claude" / "worktrees" / "wt"
    assert _write(tree, wt / "skills" / "a.py", "bypassPermissions")[0] == "allow"
    assert _write(tree, wt / ".claude" / "skills" / "x.md", "bypassPermissions")[0] == "deny"


def test_an_mcp_file_writer_meets_the_same_places(tree):
    for p in (tree / "home" / ".claude" / "skills" / "x" / "SKILL.md",
              tree / "repo" / ".claude" / "commands" / "c.md"):
        verdict, why = _write(tree, p, "bypassPermissions", tool="mcp__fs__write_file",
                              inp={"path": str(p), "content": "x"})
        assert verdict == "deny", (p, why)


def test_a_write_outside_the_sandboxs_folders_asks_or_is_refused(tree):
    p = tree / "home" / "notes.txt"
    assert _write(tree, p, "default")[0] == "ask"
    assert _write(tree, p, "bypassPermissions")[0] == "deny"
    assert _write(tree, p, "auto")[0] == "deny"
    assert _write(tree, tree / "repo" / "notes.txt", "bypassPermissions")[0] == "allow"


def test_claude_codes_memory_and_plans_are_written_in_every_mode(tree):
    home = tree / "home"
    for p in (home / ".claude" / "projects" / "p" / "memory" / "m.md",
              home / ".claude" / "agent-memory" / "a" / "m.md",
              home / ".claude" / "plans" / "plan.md"):
        assert _write(tree, p, "bypassPermissions")[0] == "allow", p


def test_a_project_cannot_name_the_home_folder_as_memory(tree):
    claude = tree / "repo" / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text(json.dumps({"autoMemoryDirectory": str(tree / "home")}))
    assert _write(tree, tree / "home" / "x.md", "bypassPermissions")[0] == "deny"


def test_the_ask_text_is_for_the_person_and_the_refusal_for_the_agent(tree):
    p = tree / "repo" / ".claude" / "skills" / "x" / "SKILL.md"
    verdict, text = _write(tree, p, "default")
    assert verdict == "ask" and "Allow" in text, text
    verdict, text = _write(tree, p, "bypassPermissions")
    assert verdict == "deny" and "operator" in text, text


def test_a_protected_path_outside_the_folders_is_refused_not_asked(tree):
    assert _write(tree, tree / "phi" / "new.txt", "default")[0] == "deny"


# --- B4: the hook sees every tool; tools that only carry text are not text-checked


def test_the_hook_is_wired_for_every_tool():
    from phiward import install
    assert install.MATCHERS == ["*"]
    plugin = json.loads(open(os.path.join(os.path.dirname(__file__), "..", "plugin", "hooks",
                                          "hooks.json")).read())
    assert [g["matcher"] for g in plugin["hooks"]["PreToolUse"]] == ["*"]


def test_an_older_wiring_is_replaced_not_doubled():
    from phiward import install
    old = {"hooks": {"PreToolUse": [
        {"matcher": m, "hooks": [{"type": "command", "command": "phiward hook claude",
                                  "onFailure": "block"}]}
        for m in ("Bash|Monitor|PowerShell", "Read|NotebookRead|Grep|Glob|LS")]}}
    entry = {"type": "command", "command": "phiward hook claude", "onFailure": "block"}
    want = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [entry]}]},
            "sandbox": {"filesystem": {}}}
    after = install.merge(old, want)
    assert sum(len(g["hooks"]) for g in after["hooks"]["PreToolUse"]) == 1
    assert [g["matcher"] for g in after["hooks"]["PreToolUse"]] == ["*"], after


def _tool(tree, tool, inp, mode="default"):
    return _write(tree, None, mode, tool=tool, inp=inp)


def test_an_mcp_resource_naming_protected_data_is_refused(tree):
    verdict, why = _tool(tree, "ReadMcpResourceTool",
                         {"server": "fs", "uri": f"file://{tree}/phi/FAKE-PT-0001.bam"})
    assert verdict == "deny", why


def test_tools_that_only_carry_text_are_not_text_checked(tree):
    for tool, inp in (("TodoWrite", {"todos": [{"content": f"count {tree}/phi/FAKE-PT-1.bam"}]}),
                      ("Agent", {"prompt": f"run phiward run -- wc -l {tree}/phi/x"}),
                      ("AskUserQuestion", {"questions": [{"question": f"use {tree}/phi?"}]}),
                      ("ExitPlanMode", {"plan": f"read {tree}/phi via the gateway"})):
        assert _tool(tree, tool, inp)[0] == "allow", tool


def test_tools_that_read_or_run_keep_the_check(tree):
    for tool, inp in (("Skill", {"skill": "x", "args": f"{tree}/phi/FAKE-PT-0001.bam"}),
                      ("LSP", {"filePath": f"{tree}/phi/FAKE-PT-0001.bam"}),
                      ("WebFetch", {"url": f"file://{tree}/phi/FAKE-PT-0001.bam"})):
        assert _tool(tree, tool, inp)[0] == "deny", tool


def test_doctor_names_an_older_wiring_that_covers_only_some_tools(tree):
    from helpers import user_settings
    from phiward import config, doctor, install
    entry = install.wiring(config.load(str(tree / "repo")))["hooks"]["PreToolUse"][0]["hooks"][0]
    user_settings(tree, {"hooks": {"PreToolUse": [
        {"matcher": m, "hooks": [entry]} for m in ("Bash|Monitor|PowerShell", "mcp__.*")]}})
    w = doctor.wiring_state(str(tree / "repo"), str(tree / "home"))
    assert any("only some tools" in p for p in w.problems), w.problems
    user_settings(tree, {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [entry]}]}})
    w = doctor.wiring_state(str(tree / "repo"), str(tree / "home"))
    assert not any("only some tools" in p for p in w.problems), w.problems


# --- B7: one rule for "inside"


def test_inside_is_one_rule_and_refuses_an_empty_folder():
    import pytest
    from phiward import pathid
    assert pathid.inside("/a/b", "/a") and pathid.inside("/a", "/a")
    assert not pathid.inside("/a", "/a", strict=True)
    assert not pathid.inside("/a/bc", "/a/b") and pathid.inside("/x", "/")
    for bad in ("", "a/b"):
        with pytest.raises(ValueError):
            pathid.inside("/a", bad)


def test_launch_refuses_a_project_that_is_no_absolute_folder():
    from phiward import wholetool
    assert wholetool._project_problem("", {"HOME": "/h"})


# --- B5: an escaped spelling of a name is masked too


def test_escaped_spellings_of_a_name_are_not_left_in_the_output():
    from phiward.sanitize import Sanitizer
    san = Sanitizer(entries=["Müller Hansi"])
    plain = san.clean("sample Müller Hansi done")
    assert "Müller" not in plain and "Hansi" not in plain, plain
    for line in ('"M\\303\\274ller Hansi/a.txt"',          # git's quoting
                 '{"sample": "M\\u00fcller Hansi"}',        # JSON
                 "b'M\\xc3\\xbcller Hansi'",                 # Python bytes
                 "'M\\xfcller Hansi'",                       # Python str repr
                 "file:///x/M%C3%BCller%20Hansi/a"):         # a URL
        out = san.clean(line)
        assert "ller Hansi" not in out and "ller%20Hansi" not in out, (line, out)


def test_ordinary_escapes_and_ascii_text_are_unchanged():
    from phiward.sanitize import Sanitizer
    san = Sanitizer(entries=["Müller Hansi"])
    for line in ('{"msg": "line one\\nline two", "path": "C:\\\\data"}', "100% done",
                 "printf '%s\\n' x", "caf\\u00e9 au lait"):
        assert san.clean(line) == line, line


# --- round 14 code review: a Claude folder by what it is, not its name


def test_a_linked_claude_folder_is_judged_where_it_leads(tree):
    repo = tree / "repo"
    (repo / "cfg").mkdir()
    os.symlink(repo / "cfg", repo / ".claude")
    for mode in ("default", "bypassPermissions"):
        assert _write(tree, repo / "cfg" / "settings.json", mode)[0] == "deny", mode
        assert _write(tree, repo / "cfg" / "settings.local.json", mode)[0] == "deny", mode
    assert _write(tree, repo / "cfg" / "skills" / "x" / "SKILL.md", "bypassPermissions")[0] == \
        "deny"
    assert _write(tree, repo / "cfg" / "skills" / "x" / "SKILL.md", "default")[0] == "ask"
    assert _write(tree, repo / "cfg" / "notes.md", "bypassPermissions")[0] == "allow"


def test_a_refusal_outside_the_folders_names_additional_directories(tree):
    verdict, why = _write(tree, tree / "home" / "notes.txt", "bypassPermissions")
    assert verdict == "deny" and "additionalDirectories" in why, why


def test_reading_a_skill_is_not_a_write(tree):
    skill = tree / "home" / ".claude" / "skills" / "s" / "SKILL.md"
    assert _tool(tree, "Skill", {"skill": "s", "args": str(skill)}, "bypassPermissions")[0] == \
        "allow"
    verdict, why = _tool(tree, "mcp__fs__read_text_file", {"path": str(skill)},
                         "bypassPermissions")
    assert verdict == "deny" and "names" in why and "writes" not in why, why


def test_a_hard_link_may_be_another_name_of_a_code_place(tree):
    skill = tree / "home" / ".claude" / "skills" / "s" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("x\n")
    os.link(skill, tree / "repo" / "notes.md")
    assert _write(tree, tree / "repo" / "notes.md", "bypassPermissions", tool="Edit",
                  inp={"file_path": str(tree / "repo" / "notes.md"), "old_string": "x",
                       "new_string": "y"})[0] == "deny"


def test_every_path_field_of_a_notebook_edit_is_judged(tree):
    inp = {"file_path": str(tree / "repo" / "a.ipynb"),
           "notebook_path": str(tree / "repo" / ".claude" / "agents" / "n.ipynb"),
           "new_source": "x"}
    assert _write(tree, None, "bypassPermissions", tool="NotebookEdit", inp=inp)[0] == "deny"


def test_a_worktree_config_is_refused(tree):
    (tree / "repo" / ".git").mkdir()
    assert _write(tree, tree / "repo" / ".git" / "config.worktree", "default")[0] == "deny"


def test_a_relative_xdg_config_home_is_ignored(monkeypatch):
    from phiward import config
    monkeypatch.delenv("PHIWARD_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", ".config")
    assert config.user_config_path().startswith("/")
    assert all(p.startswith("/") for p in config.guard_files())


def test_an_escape_beyond_unicode_does_not_raise():
    from phiward.sanitize import Sanitizer, unescape
    assert unescape("C:\\Users\\Uffffffff") == "C:\\Users\\Uffffffff"
    san = Sanitizer(entries=["Müller Hansi"])
    assert san.clean("C:\\Users\\Uffffffff ok") == "C:\\Users\\Uffffffff ok"


def test_a_claude_link_to_a_folder_not_made_yet_is_judged_where_it_leads(tree):
    repo = tree / "repo"
    os.symlink("cfg", repo / ".claude")  # dangling: cfg is made by the write itself
    for mode in ("default", "bypassPermissions"):
        assert _write(tree, repo / "cfg" / "settings.json", mode)[0] == "deny", mode
    assert _write(tree, repo / "cfg" / "skills" / "x" / "SKILL.md", "bypassPermissions")[0] == \
        "deny"


def test_links_inside_a_claude_folder_are_judged_where_they_lead(tree):
    repo, home = tree / "repo", tree / "home"
    claude = repo / ".claude"
    claude.mkdir()
    for d in ("agents_skills", "scripts", "conf"):
        (repo / d).mkdir()
    os.symlink("../agents_skills", claude / "skills")
    os.symlink("../scripts", claude / "hooks")
    (repo / "conf" / "claude.json").write_text("{}\n")
    os.symlink("../conf/claude.json", claude / "settings.local.json")
    assert _write(tree, repo / "agents_skills" / "x" / "SKILL.md", "bypassPermissions")[0] == "deny"
    assert _write(tree, repo / "scripts" / "h.sh", "bypassPermissions")[0] == "deny"
    for mode in ("default", "bypassPermissions"):
        assert _write(tree, repo / "conf" / "claude.json", mode)[0] == "deny", mode
    (home / ".claude").mkdir()
    (repo / "dot" / "skills").mkdir(parents=True)
    os.symlink(repo / "dot" / "skills", home / ".claude" / "skills")
    assert _write(tree, repo / "dot" / "skills" / "x" / "SKILL.md", "bypassPermissions")[0] == \
        "deny"
    verdict, why = _write(tree, repo / "README.md", "bypassPermissions")
    assert verdict == "allow", why


def test_a_refused_mcp_read_of_a_code_file_names_the_read_tool(tree):
    skill = tree / "home" / ".claude" / "skills" / "s" / "SKILL.md"
    verdict, why = _tool(tree, "mcp__fs__read_text_file", {"path": str(skill)},
                         "bypassPermissions")
    assert verdict == "deny" and "Read tool" in why, why


def test_a_hard_link_refusal_says_how_to_write_the_file(tree):
    f = tree / "repo" / "notes.md"
    f.write_text("x\n")
    os.link(f, tree / "repo" / "other.md")
    verdict, why = _write(tree, f, "bypassPermissions")
    assert verdict == "deny" and "mv " in why, why


def test_a_link_inside_a_code_folder_is_judged_where_it_leads(tree):
    repo, home = tree / "repo", tree / "home"
    uc = home / ".claude"
    for d in ("skills", "agents", "commands", "plugins/marketplaces"):
        (uc / d).mkdir(parents=True)
    (repo / "myskills" / "foo").mkdir(parents=True)
    os.symlink(repo / "myskills" / "foo", uc / "skills" / "foo")
    (repo / "dot").mkdir()
    (repo / "dot" / "rev.md").write_text("x\n")
    os.symlink(repo / "dot" / "rev.md", uc / "agents" / "rev.md")
    os.symlink(repo / "later", uc / "commands" / "c.md")
    (repo / "mkt").mkdir()
    os.symlink(repo / "mkt", uc / "plugins" / "marketplaces" / "local")
    pc = repo / ".claude" / "skills"
    pc.mkdir(parents=True)
    (repo / "shared" / "x").mkdir(parents=True)
    os.symlink("../../shared/x", pc / "x")
    for target in (repo / "myskills" / "foo" / "SKILL.md", repo / "dot" / "rev.md",
                   repo / "later", repo / "mkt" / "p" / "hooks" / "hooks.json",
                   repo / "shared" / "x" / "SKILL.md"):
        assert _write(tree, target, "bypassPermissions")[0] == "deny", target
        assert _write(tree, target, "default")[0] == "ask", target
    verdict, why = _tool(tree, "mcp__fs__write_file",
                         {"path": str(repo / "myskills" / "foo" / "SKILL.md")},
                         "bypassPermissions")
    assert verdict == "deny", why
    assert _write(tree, repo / "src" / "app.py", "bypassPermissions")[0] == "allow"


def test_the_hard_link_step_keeps_the_content(tree):
    f = tree / "repo" / "notes.md"
    f.write_text("x\n")
    os.link(f, tree / "repo" / "other.md")
    verdict, why = _write(tree, f, "bypassPermissions")
    assert verdict == "deny" and "cp " in why and "mv " in why, why


# --- round 14d: one list of code roots (links followed to a fixed point), for the hook and doctor


def test_links_are_followed_until_nothing_new(tree):
    repo, home = tree / "repo", tree / "home"
    (home / ".claude" / "skills").mkdir(parents=True)
    for d in ("a", "c", "z"):
        (repo / d).mkdir()
    os.symlink(repo / "a", home / ".claude" / "skills" / "foo")
    (repo / "c" / "S.md").write_text("x\n")
    os.symlink(repo / "c" / "S.md", repo / "a" / "SKILL.md")
    os.symlink(repo / "z", repo / "a" / "b")
    for target in (repo / "c" / "S.md", repo / "z" / "SKILL.md"):
        assert _write(tree, target, "bypassPermissions")[0] == "deny", target


def test_a_big_code_folder_does_not_hide_a_link(tree):
    repo, home = tree / "repo", tree / "home"
    big = home / ".claude" / "skills" / "aaa"
    big.mkdir(parents=True)
    for i in range(6000):
        (big / f"f{i}").write_text("")
    (repo / "t").mkdir()
    os.symlink(repo / "t", home / ".claude" / "skills" / "zzz")
    assert _write(tree, repo / "t" / "SKILL.md", "bypassPermissions")[0] == "deny"
    assert _write(tree, repo / "src" / "app.py", "bypassPermissions")[0] == "allow"


def test_a_symlink_to_a_hard_linked_file_is_seen(tree):
    h = tree / "repo" / "h"
    h.write_text("x\n")
    os.link(h, tree / "repo" / "h2")
    os.symlink(h, tree / "repo" / "s")
    assert _write(tree, tree / "repo" / "s", "bypassPermissions")[0] == "deny"


def test_an_mcp_listing_of_a_folder_that_holds_skills_is_allowed(tree):
    (tree / "repo" / ".claude" / "skills").mkdir(parents=True)
    for p in (tree / "repo", tree / "repo" / ".claude", tree / "home"):
        verdict, why = _tool(tree, "mcp__fs__list_directory", {"path": str(p)},
                             "bypassPermissions")
        assert verdict == "allow", (p, why)


def test_doctor_names_a_skill_the_projects_sessions_can_write(tree):
    from phiward import claude_settings
    repo, home = tree / "repo", tree / "home"
    (home / ".claude" / "skills").mkdir(parents=True)
    (repo / "myskills" / "foo").mkdir(parents=True)
    os.symlink(repo / "myskills" / "foo", home / ".claude" / "skills" / "foo")
    found = claude_settings.writable_code_roots(str(repo), str(home))
    assert [os.path.realpath(repo / "myskills" / "foo")] == [r for r, _l in found], found
    assert found[0][1] == str(home / ".claude" / "skills" / "foo")
    elsewhere = tree / "other"
    elsewhere.mkdir()
    assert claude_settings.writable_code_roots(str(elsewhere), str(home)) == []


def test_doctor_warns_about_a_skill_the_project_can_write(tree):
    from phiward import doctor
    repo, home = tree / "repo", tree / "home"
    (home / ".claude" / "skills").mkdir(parents=True)
    (repo / "myskills" / "foo").mkdir(parents=True)
    os.symlink(repo / "myskills" / "foo", home / ".claude" / "skills" / "foo")
    lines = doctor.code_root_lines(str(repo), str(home))
    assert len(lines) == 1 and "WARNING" in lines[0] and "copy" in lines[0], lines


# --- review of fa32a0c: a big linked tree, odd links, doctor's lines


def test_a_huge_linked_tree_is_code_but_does_not_stop_other_writes(tree, monkeypatch):
    from phiward import claude_settings, doctor
    monkeypatch.setattr(claude_settings, "TREE_WALK", 50)
    repo, home = tree / "repo", tree / "home"
    (home / ".claude" / "skills").mkdir(parents=True)
    big = repo / "bigskill"
    (big / "node_modules").mkdir(parents=True)
    for i in range(80):
        (big / "node_modules" / f"f{i}").write_text("")
    os.symlink(big, home / ".claude" / "skills" / "big")
    assert _write(tree, big / "SKILL.md", "bypassPermissions")[0] == "deny"
    assert _write(tree, repo / "src" / "app.py", "bypassPermissions")[0] == "allow"
    lines = doctor.code_root_lines(str(repo), str(home))
    assert any("not checked" in ln and "node_modules" in ln for ln in lines), lines


def test_a_skill_link_to_the_whole_disk_does_not_break_the_hook(tree):
    from phiward import doctor
    home = tree / "home"
    (home / ".claude" / "skills").mkdir(parents=True)
    os.symlink("/", home / ".claude" / "skills" / "root")
    verdict, why = _write(tree, tree / "repo" / "src" / "app.py", "bypassPermissions")
    assert verdict == "allow", why
    lines = doctor.code_root_lines(str(tree / "repo"), str(home))
    assert any("holds your home folder" in ln for ln in lines), lines


def test_many_linked_skills_are_one_doctor_line(tree):
    from phiward import doctor
    repo, home = tree / "repo", tree / "home"
    (home / ".claude" / "skills").mkdir(parents=True)
    for i in range(6):
        (repo / "skills" / f"s{i}").mkdir(parents=True)
        os.symlink(repo / "skills" / f"s{i}", home / ".claude" / "skills" / f"s{i}")
    lines = doctor.code_root_lines(str(repo), str(home))
    assert len(lines) == 1 and "6" in lines[0], lines


# --- review of a4fa062


def test_a_link_to_a_folder_that_holds_the_project_is_named_by_doctor(tree):
    from phiward import doctor
    repo, home = tree / "repo", tree / "home"
    (home / ".claude" / "skills").mkdir(parents=True)
    project = repo / "inner"
    project.mkdir()
    os.symlink(repo, home / ".claude" / "skills" / "d")  # holds the project, not the home folder
    lines = doctor.code_root_lines(str(project), str(home))
    assert any("holds this project" in ln and "remove the link" in ln for ln in lines), lines


def test_a_link_to_the_home_or_config_folder_in_another_case_is_too_wide(tree):
    from phiward import doctor
    home = tree / "home"
    (home / ".claude" / "skills").mkdir(parents=True)
    other = str(home).swapcase() if os.path.isdir(str(home).swapcase()) else str(home)
    os.symlink(other, home / ".claude" / "skills" / "h")
    os.symlink(home / ".claude", home / ".claude" / "skills" / "cfg")
    verdict, why = _write(tree, tree / "repo" / "src" / "app.py", "bypassPermissions")
    assert verdict == "allow", why
    mem = home / ".claude" / "projects" / "p" / "memory" / "m.md"
    assert _write(tree, mem, "bypassPermissions")[0] == "allow"
    lines = doctor.code_root_lines(str(tree / "repo"), str(home))
    assert sum("holds your home folder" in ln or "user config" in ln for ln in lines) >= 1, lines


def test_a_big_real_code_folder_gets_its_own_step(tree, monkeypatch):
    from phiward import claude_settings, doctor
    monkeypatch.setattr(claude_settings, "TREE_WALK", 20)
    skills = tree / "home" / ".claude" / "skills" / "s" / "node_modules"
    skills.mkdir(parents=True)
    for i in range(30):
        (skills / f"f{i}").write_text("")
    lines = doctor.code_root_lines(str(tree / "repo"), str(tree / "home"))
    assert lines and "(through )" not in lines[0] and "not checked" in lines[0], lines


# --- round 15 (UX): install writes the file doctor reads


def test_install_writes_the_user_settings_where_claude_code_reads_them(tree, monkeypatch):
    from phiward import install
    import sys
    from helpers import Tty
    cfgdir = tree / "home" / "cfgdir"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfgdir))
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.chdir(tree / "repo")
    assert install.main(["claude", "--user", "--write", "--yes"]) == 0
    assert (cfgdir / "settings.json").is_file()
    assert not (tree / "home" / ".claude" / "settings.json").exists()


def test_the_approval_question_defaults_to_yes_only_on_a_clean_first_run(tree):
    from phiward import setup_cmd
    home = tree / "home"
    lines = ["/usr/bin/wc  (new)", "/usr/bin/md5sum  (not installed)"]
    shown, default, found, missing = setup_cmd.approval(lines, str(home), before=False)
    assert default and (found, missing) == (1, 1) and shown == ["/usr/bin/wc  (new)"]
    assert not setup_cmd.approval(lines, str(home), before=True)[1]
    assert not setup_cmd.approval(["/usr/bin/wc  (changed)"], str(home), False)[1]
    mine = home / ".local" / "bin"
    mine.mkdir(parents=True)
    (mine / "wc").write_text("#!/bin/sh\n")
    shown, default, _f, _m = setup_cmd.approval([f"{mine / 'wc'}  (new)"], str(home), False)
    if os.path.isfile("/usr/bin/wc") or os.path.isfile("/bin/wc"):
        assert not default and "(shadows " in shown[0], shown


def test_the_step_for_a_python_another_account_can_change_reinstalls_for_real(tree):
    from phiward import __version__, selfcheck
    line = f"/opt/py/bin/: writable by others {selfcheck.OUTSIDE}"
    text = selfcheck.fix_text([line], "")
    assert f"uv tool install --force --python-preference only-managed phiward=={__version__}" \
        in text and "pipx uninstall" not in text, text
    venv = tree / "home" / ".local" / "pipx" / "venvs" / "phiward"
    pkg = venv / "lib" / "python3.12" / "site-packages" / "phiward"
    pkg.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("include-system-site-packages = false\n")
    (venv / "pipx_metadata.json").write_text("{}\n")
    assert "pipx uninstall phiward && uv tool install" in selfcheck.fix_text([line], str(pkg))


# --- round 15: doctor's checks of what settings run


def _settings(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def test_doctor_names_a_script_a_settings_file_runs_that_the_session_can_write(tree):
    from phiward import doctor
    repo, home = tree / "repo", tree / "home"
    (repo / "scripts").mkdir()
    (repo / "scripts" / "x.py").write_text("print(1)\n")
    (repo / "tools.sh").write_text("true\n")
    _settings(repo / ".claude" / "settings.json", {"hooks": {"PostToolUse": [{"hooks": [
        {"type": "command", "command": "python3 scripts/x.py"},
        {"type": "command", "command": "$CLAUDE_PROJECT_DIR/tools.sh --x"}]}]},
        "statusLine": {"type": "command", "command": "node ${CLAUDE_PLUGIN_ROOT}/s.js"}})
    lines = doctor.settings_script_lines(str(repo), str(home))
    assert len(lines) == 2 and all("WARNING" in ln for ln in lines), lines
    assert any("scripts/x.py" in ln for ln in lines) and any("tools.sh" in ln for ln in lines)


def test_phiwards_own_wiring_and_a_hooks_folder_give_no_warning(tree):
    from phiward import config, doctor, install
    repo, home = tree / "repo", tree / "home"
    (home / ".claude" / "hooks").mkdir(parents=True)
    (home / ".claude" / "hooks" / "h.sh").write_text("true\n")
    wiring = install.wiring(config.load(str(repo)))
    wiring["hooks"]["PostToolUse"] = [{"hooks": [
        {"type": "command", "command": "bash ~/.claude/hooks/h.sh"}]}]
    _settings(home / ".claude" / "settings.json", wiring)
    assert doctor.settings_script_lines(str(repo), str(home)) == []
    # the project's own .claude/hooks/ is not enough: its shell can write it (round 15b)
    (repo / ".claude" / "hooks").mkdir(parents=True)
    (repo / ".claude" / "hooks" / "p.sh").write_text("true\n")
    wiring["hooks"]["PostToolUse"][0]["hooks"].append(
        {"type": "command", "command": "bash .claude/hooks/p.sh"})
    _settings(home / ".claude" / "settings.json", wiring)
    lines = doctor.settings_script_lines(str(repo), str(home))
    assert len(lines) == 1 and "~/.claude/hooks/" in lines[0], lines


def test_a_permission_request_hook_is_a_note(tree):
    from phiward import doctor
    _settings(tree / "home" / ".claude" / "settings.json", {"hooks": {"PermissionRequest": [
        {"hooks": [{"type": "command", "command": "/usr/bin/true"}]}]}})
    lines = doctor.settings_script_lines(str(tree / "repo"), str(tree / "home"))
    assert len(lines) == 1 and lines[0].lstrip().startswith("NOTE:") and \
        "PermissionRequest" in lines[0], lines


def test_doctor_notes_a_project_without_init(tree):
    from phiward import doctor
    repo, home = tree / "repo", tree / "home"
    (repo / ".git").mkdir()
    lines = doctor.init_lines(str(repo), str(home))
    assert len(lines) == 1 and "NOTE" in lines[0] and "phiward init" in lines[0], lines
    _settings(repo / ".claude" / "settings.json",
              {"sandbox": {"filesystem": {"denyWrite": ["./.claude/settings.json"]}}})
    assert doctor.init_lines(str(repo), str(home)) == []
    assert doctor.init_lines(str(home), str(home)) == []


# --- round 15b


def test_doctor_with_no_config_names_setup_first_and_nothing_else(tree, monkeypatch, capsys):
    from pathlib import Path
    from phiward import doctor
    Path(os.environ["PHIWARD_CONFIG"]).write_text("")
    monkeypatch.chdir(tree / "repo")
    doctor.main([])
    out = capsys.readouterr().out
    assert "(cd ~ && phiward setup)" in out, out
    assert "phiward install claude" not in out and "broker --service" not in out, out


def test_a_project_wiring_upgrade_drops_the_older_hook(tree):
    from phiward import config, install
    old_hook = {"type": "command", "command": install.OLD_PROJECT_HOOKS[0], "onFailure": "block"}
    old = {"hooks": {"PreToolUse": [{"matcher": m, "hooks": [dict(old_hook)]}
                                    for m in ("Bash|Monitor|PowerShell", "mcp__.*")]}}
    new = install.merge(old, install.wiring(config.load(str(tree / "repo")), project=True))
    cmds = [h["command"] for g in new["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert cmds == [install.PROJECT_HOOK], cmds


def test_a_script_started_through_env_or_home_is_seen(tree):
    from phiward import doctor
    repo, home = tree / "repo", tree / "home"
    (repo / "x.py").write_text("print(1)\n")
    _settings(repo / ".claude" / "settings.json", {"hooks": {"Stop": [{"hooks": [
        {"type": "command", "command": "/usr/bin/env FOO=1 python3 x.py"}]}]}})
    assert len(doctor.settings_script_lines(str(repo), str(home))) == 1


def test_a_wiring_without_hooks_keeps_the_older_project_hook(tree):
    from phiward import config, install
    old_hook = {"type": "command", "command": install.OLD_PROJECT_HOOKS[0], "onFailure": "block"}
    old = {"hooks": {"PreToolUse": [{"matcher": "Bash|Monitor|PowerShell", "hooks": [old_hook]}]}}
    want = install.wiring(config.load(str(tree / "repo")), project=True)
    want["hooks"]["PreToolUse"] = []  # --no-hooks, as init runs it
    new = install.merge(old, want)
    cmds = [h["command"] for g in new["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert cmds == [install.OLD_PROJECT_HOOKS[0]], cmds


def test_doctor_with_no_config_still_names_a_selfcheck_problem(tree, monkeypatch, capsys):
    # setup cannot fix phiward's own install: its WARNING comes before setup's step
    from pathlib import Path
    from phiward import doctor
    Path(os.environ["PHIWARD_CONFIG"]).write_text("")
    monkeypatch.setattr(doctor, "selfcheck_lines",
                        lambda: ["WARNING: phiward's Python can be changed by another account: X"])
    monkeypatch.chdir(tree / "repo")
    doctor.main([])
    out = capsys.readouterr().out
    assert "phiward's Python can be changed" in out and "(cd ~ && phiward setup)" in out, out
    assert out.count("phiward's Python can be changed") == 1, out


def test_a_settings_script_step_is_not_circular_in_the_home_folder(tree):
    from phiward import doctor
    home = tree / "home"
    (home / ".claude" / "hooks").mkdir(parents=True)
    (home / ".claude" / "hooks" / "u.sh").write_text("true\n")
    _settings(home / ".claude" / "settings.json", {"hooks": {"Stop": [{"hooks": [
        {"type": "command", "command": "bash ~/.claude/hooks/u.sh"}]}]}})
    lines = doctor.settings_script_lines(str(home), str(home))
    assert len(lines) == 1 and "project folder" in lines[0], lines
    assert "move it into" not in lines[0], lines


def test_a_settings_script_step_names_the_user_folder_claude_reads(tree, monkeypatch):
    from phiward import doctor
    repo, home = tree / "repo", tree / "home"
    cfgdir = tree / "cc"
    cfgdir.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfgdir))
    (repo / "x.sh").write_text("true\n")
    _settings(cfgdir / "settings.json", {"hooks": {"Stop": [{"hooks": [
        {"type": "command", "command": "bash x.sh"}]}]}})
    lines = doctor.settings_script_lines(str(repo), str(home))
    assert len(lines) == 1 and str(cfgdir / "hooks") in lines[0], lines


@pytest.mark.parametrize("command", ["env -u FOO python3 x.py", "env -S 'python3 x.py'",
                                     "/usr/bin/env -uFOO -- python3 x.py",
                                     "env --unset=FOO -C /tmp python3 x.py"])
def test_a_script_started_through_env_options_is_seen(tree, command):
    from phiward import doctor
    repo, home = tree / "repo", tree / "home"
    (repo / "x.py").write_text("print(1)\n")
    _settings(repo / ".claude" / "settings.json", {"hooks": {"Stop": [{"hooks": [
        {"type": "command", "command": command}]}]}})
    assert len(doctor.settings_script_lines(str(repo), str(home))) == 1, command


def test_headless_with_no_config_names_setup(tree, monkeypatch):
    from pathlib import Path
    from phiward import doctor
    Path(os.environ["PHIWARD_CONFIG"]).write_text("")
    probs = doctor.headless_problems(str(tree / "repo"), str(tree / "home"))
    assert len(probs) == 1 and "(cd ~ && phiward setup)" in probs[0], probs
