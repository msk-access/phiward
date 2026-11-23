"""The leak test for typical sessions: a scripted session (tests/data/leak_session.jsonl) is
replayed through phiward's real entry points over a made-up project with planted values, and
everything that would reach the model provider is captured and checked (PLAN-PHI-TESTS step 2).

The entry points: the session note (`session-note claude`), the prompt scan (`prompt-scan
claude`), the PreToolUse hook (`hook claude`) before every tool call, the gateway (`phiward run`
through a broker), and phiward's MCP server (`phiward mcp`). No Claude Code and no token are
needed. The default `[shell] best_effort` (off) is kept: the made-up home holds the user settings
`install claude` writes, so the hook sees a shell that Claude Code confines. The replay cannot
run Claude Code's sandbox, so in Mode A plain shell steps stay in the project and the root is
read through the gateway only; the launch leg (Linux) has the kernel refuse plain reads of it.

Each planted value (tests/leak_values.py) has a kind from its rule's label, and an expected
outcome by where it sits and the channel (`leak_session.outcome`):
- under the root: refused (file tools, `@`, plain shell under launch), masked (gateway text, MCP:
  only placeholders are left, in text and table mode), and a number in a column that is not an
  identifier column is allowed by `--table`;
- in a prompt: an identifier of the user's packs and rules is blocked; entry names, details and
  positions are sent;
- in the project (`notes.md`): sent in Mode A, since the hook decides by path, and the session
  note warns of it (the project scan, step 3); under launch the scan refuses the start, so the
  launch leg allows `notes.md` by `[sanitize] scan_allow` and a step of its own expects the
  refusal.
"Absent" means absent in every form (raw, casefolded, NFKC, unescaped, letters and digits only,
and each run of 3 or more letters and digits that holds a digit). A control session over the same
project with the plants left out must find nothing, and each fault made through the config alone
must be found.

What the replay does not cover (docs/threat-model.md says each one):
- `CLAUDE.md` and other instruction files: Claude Code sends them at the start, with no hook
  (the project scan, tests/test_projectscan.py, reads them);
- the git status and file names in the system prompt (the project scan reads file names too);
- the user's own `!` commands: their output is sent, and no PreToolUse hook runs;
- MCP servers that are not wrapped (doctor warns);
- compaction and summaries (they rephrase only what was already sent);
- Claude Code's own sandbox in Mode A (the launch leg and the operator's sandbox check cover
  the kernel);
- IDs in project files outside the roots in Mode A: sent (the `notes.md` row; the note warns);
- Claude Code's own file tools: the replay's Read, Grep and Glob are models of them.
A hook "ask" is played as allowed (a yes), so the capture holds all that a yes would send.
"""

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import re

import pytest

import leak_session
import leak_values as lv
from helpers import fake_native_claude, git_repo, needs_confine, tool_py

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")
SUBJECTS = "WARNING: your user config enables no pack that masks subject or sample identifiers"
SCAN_NOTE = "phiward's project scan found <STUDYID> in 1 file"


def _plant(text: str, value) -> str:
    return leak_session.PLANT.sub(lambda m: value(m.group(1)), text)


def _build(base: Path, value) -> Path:
    """The made-up home H: H/data (the root: cohort.csv, logs/run.log, a folder per patient),
    H/repo (the project, a git repository with clean history), a pack file, and `phiward` on a
    PATH folder (the source checkout's)."""
    h = base / "h"
    data = h / "data"
    (data / "logs").mkdir(parents=True)
    (data / "cohort.csv").write_text(_plant(lv.COHORT, value))
    (data / "logs" / "run.log").write_text(_plant(lv.RUN_LOG, value))
    for i in range(1, 6):
        d = data / value(f"FAKE-PT-000{i}")
        d.mkdir()
        (d / "calls.vcf").write_text(lv.CALLS + ("##ERROR flagged\n" if i == 1 else ""))
    (data / value("FAKE-PT-0002") / value("FAKECANARY7.sorted.bam")).write_text("ERROR\n")
    repo = h / "repo"
    git_repo(repo)
    (repo / "analysis.py").write_text(lv.ANALYSIS)
    (repo / "README.md").write_text(lv.README)
    (repo / "notes.md").write_text(_plant(lv.NOTES, value))
    for args in (["add", "-A"], ["-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                 "commit", "-qm", "add the cohort analysis"]):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    for name, rules in (("study-pack.toml", lv.PACK_RULES), ("weak-pack.toml", lv.WEAK_RULES)):
        (h / name).write_text("[pack]\nidentifiers = [" + ", ".join(f"'{r}'" for r in rules)
                              + "]\n")
    shim = h / "bin" / "phiward"
    shim.parent.mkdir()
    shim.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} -c "
                    f"{shlex.quote(leak_session.LAUNCH)} \"$@\"\n")
    shim.chmod(0o755)
    fake_native_claude(base / "claude-py" / "claude", python=True)
    os.chmod(h, 0o755)
    return h


@pytest.fixture(scope="module")
def leak_tree(tmp_path_factory):
    return _build(tmp_path_factory.mktemp("leak").resolve(), lambda v: v)


@pytest.fixture(scope="module")
def control_tree(tmp_path_factory):
    return _build(tmp_path_factory.mktemp("control").resolve(), lv.neutral)


def config_text(h: Path, name: str) -> str:
    """The user config: `full` (packs, a pack file, a user pattern, their examples, table mode),
    `full-allow` (`full`, and `notes.md` allowed by `[sanitize] scan_allow`, so launch starts),
    `default` (no packs, no patterns), or a fault made through the config alone."""
    roots = f'[protected_paths]\nroots = ["{h / "data"}"]\n'
    if name == "default":
        return roots
    if name == "full-allow":
        return config_text(h, "full") + f'scan_allow = ["{h / "repo" / "notes.md"}"]\n'
    pack, pattern, examples = h / "study-pack.toml", lv.PATTERN, list(lv.EXAMPLES)
    if name == "a-pack-file-weakened":  # it masks no ZQ- value, and has no example
        pack, examples = h / "weak-pack.toml", ["FAKE-PT-0009"]
    elif name == "b-pattern-edited":  # \d{4} to \d{5}, its example removed
        pattern, examples = pattern.replace(r"\d{4}", r"\d{5}"), ["ZQ-777009", "ZQ-XYZ09"]
    elif name == "c-root-removed":
        roots = "[protected_paths]\nroots = []\n"
    return (roots + f'[sanitize]\npacks = ["genomics", "msk", "dates", "{pack}"]\n'
            f"patterns = ['{pattern}']\nexamples = {json.dumps(examples)}\ntable = true\n")


def _env(h: Path, name: str, spool: str) -> dict:
    env = {k: v for k, v in os.environ.items()
           if k not in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "CLAUDE_CONFIG_DIR")}
    env.update(HOME=str(h), PHIWARD_CONFIG=str(h / f"config-{name}.toml"), PHIWARD_SPOOL=spool,
               PHIWARD_BROKER_WAIT="10", PHIWARD_DIALOG="/nonexistent/phiward-test-dialog",
               PHIWARD_DEV="1", PHIWARD_SERVICE_RUNNER="none", PYTHONPATH=leak_session.SRC,
               CLAUDE_PROJECT_DIR=str(h / "repo"),
               PATH=f"{h / 'bin'}:{os.environ.get('PATH', os.defpath)}")
    return env


@pytest.fixture(scope="module")
def leak_broker():
    """`serve(H, NAME)`: the environment of a run under config NAME, with a broker of its own
    started for it (once per home and config; all are stopped at the end of the module)."""
    running = {}

    def serve(h: Path, name: str) -> dict:
        if (h, name) in running:
            return running[(h, name)][0]
        (h / f"config-{name}.toml").write_text(config_text(h, name))
        spool = tempfile.mkdtemp(prefix="plk-", dir="/tmp")
        os.rmdir(spool)  # the broker makes it, mode 0700
        env = _env(h, name, spool)
        log = open(h / f"broker-{name}.log", "w")
        p = subprocess.Popen([sys.executable, "-m", "phiward", "broker"], cwd=str(h),
                             stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                             env=env)
        running[(h, name)] = (env, p, log, spool)
        for _ in range(200):
            if os.path.exists(os.path.join(spool, "broker.alive")) or p.poll() is not None:
                break
            time.sleep(0.05)
        assert p.poll() is None, (h / f"broker-{name}.log").read_text()
        return env

    yield serve
    for _e, p, log, spool in running.values():
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
        log.close()
        shutil.rmtree(spool, ignore_errors=True)


def _subs(h: Path) -> dict:
    return {"REPO": str(h / "repo"), "DATA": str(h / "data"), "PY": sys.executable}


def play(h: Path, serve, name: str, value=lambda v: v, tools=None):
    """Replay the session in Mode A under config NAME (the prompts and, when `tools` names
    them, only those tool steps); (items, seconds)."""
    from phiward import config, install
    env = serve(h, name)
    steps = [s for s in leak_session.load(_subs(h), value)
             if tools is None or s.kind != "tool" or s.id in tools]
    start = time.monotonic()
    with pytest.MonkeyPatch.context() as mp:
        for k in [k for k in os.environ if k not in env]:
            mp.delenv(k)
        for k, v in env.items():
            mp.setenv(k, v)
        settings = h / ".claude" / "settings.json"
        settings.parent.mkdir(exist_ok=True)
        settings.write_text(json.dumps(install.wiring(config.load(str(h / "repo")))))
        items = leak_session.replay(steps, str(h / "repo"), str(h / "data"), env)
    took = time.monotonic() - start
    print(f"\n{name}: {len(steps)} steps in {took:.1f} s")
    return items, took


def leaks(h: Path, serve, name: str, features=lv.FULL, value=lambda v: v, tools=None):
    """The leaks and the missing values of a Mode A replay under config NAME."""
    items, _took = play(h, serve, name, value, tools)
    return leak_session.findings(items, lv.PLANTS, features)


def _show(items):
    return "\n".join(f"--- step {it.step} {it.channel} {it.verdict}\n{it.text}" for it in items)


_HOLE = r"((?:<[A-Z][A-Z0-9_]*>|[^A-Za-z0-9<>])+)"


def shown_masked(text: str, template: str, table: bool = False) -> list:
    """What is wrong with `text`, a gateway output of `template` under the full config: each
    template line must come out, in order, with its text kept and each planted value replaced
    by placeholders that hold its own (a gateway that drops or garbles lines fails). With
    `table`, a value in a column that is not an identifier column is kept as it is, and one in
    an identifier column needs a placeholder of any kind."""
    out, i, bad = text.splitlines(), 0, []
    for line in template.splitlines():
        parts = leak_session.PLANT.split(line)
        rx, want = "", []
        for k, part in enumerate(parts):
            p = lv.BY_VALUE.get(part) if k % 2 else None
            if p is None or (table and p.column == "other"):
                rx += re.escape(part)
            else:
                rx += _HOLE
                want.append("<" if table and p.column == "id" else lv.placeholder(p))
        pat = re.compile(rx)
        while i < len(out) and not pat.fullmatch(out[i]):
            i += 1
        if i == len(out):
            bad.append(f"no line of the output is the masked form of: {line!r}")
            i = 0
            continue
        m = pat.fullmatch(out[i])
        bad += [f"{w} missing in {out[i]!r}" for g, w in zip(m.groups(), want) if w not in g]
        i += 1
    return bad


# --- the legs --------------------------------------------------------------------------------

@needs_confine
@pytest.mark.parametrize("name,features", [("full", lv.FULL), ("default", lv.DEFAULT)])
def test_mode_a_a_typical_session_leaks_nothing(leak_tree, leak_broker, name, features):
    items, took = play(leak_tree, leak_broker, name)
    found, missing = leak_session.findings(items, lv.PLANTS, features)
    assert not found and not missing, "\n".join(found + missing) + "\n" + _show(items)
    steps = leak_session.load(_subs(leak_tree))
    by = {it.step: it for it in items}
    tool = {s.id: by[s.n] for s in steps if s.kind == "tool"}
    # the hook refused the Read and the Glob below the root and allowed the rest
    assert [it.verdict for it in tool.values()].count("deny") == 2, _show(items)
    assert tool["t05"].verdict == "deny" and tool["t05"].channel == "file"
    assert tool["t11c"].verdict == "deny" and "analysis.py" in tool["t11b"].text
    # the gateway ran (a gateway that fails would hide every value)
    for t in ("t06", "t07", "t08", "t09", "t10"):
        assert "exit=0" in tool[t].text, _show([tool[t]])
    assert ("exit=0" in tool["t07b"].text) is (name == "full"), _show([tool["t07b"]])
    mention = [by[s.n] for s in steps if s.kind == "prompt" and "@~/data/" in s.input]
    assert len(mention) == 1 and mention[0].verdict == "block"
    assert "below a protected root" in mention[0].text
    assert (SUBJECTS in tool["t14b"].text) is (name == "default"), _show([tool["t14b"]])
    # the project scan (step 3): the note warns of notes.md, by kind and count; the default
    # config has no subject rule, so its scan is off
    note = [it for it in items if it.channel == "note"]
    assert len(note) == 1 and (SCAN_NOTE in note[0].text) is (name == "full"), _show(note)
    from phiward import install
    settings = json.loads((leak_tree / ".claude" / "settings.json").read_text())
    assert settings["env"][install.MENTIONS_OFF] == "1"  # `@` mentions are off
    assert took < 120, took
    if name != "full":
        return
    # what came back is the data with each value masked by its own rule, line by line
    first = lv.COHORT.splitlines()[1]
    for t, template, table in (("t07", lv.COHORT, False), ("t07b", lv.COHORT, True),
                               ("t08", lv.RUN_LOG, False), ("t14", lv.COHORT, False),
                               ("t09", f"rows: 4\ngenes: 4\nfirst: {first}", False)):
        bad = shown_masked(tool[t].text, template, table)
        assert not bad, "\n".join(bad) + "\n" + _show([tool[t]])
    # names only (`ls`, `grep -l`): every line is placeholders alone, or the gateway's own note
    # in brackets (a fold of repeated lines, the counts), or its exit line
    for t in ("t06", "t10"):
        lines = tool[t].text.splitlines()
        names = [ln for ln in lines if "<" in ln and re.fullmatch(_HOLE, ln)]
        other = [ln for ln in lines if ln and ln not in names and not ln.startswith("[")
                 and not ln.startswith("run done: exit=0")]
        assert names and not other, _show([tool[t]])


@needs_confine
@pytest.mark.parametrize("name,features", [("full", lv.FULL), ("default", lv.DEFAULT)])
def test_a_control_session_with_no_plants_finds_nothing(control_tree, leak_broker, name,
                                                        features):
    found, _missing = leaks(control_tree, leak_broker, name, features, lv.neutral)
    assert not found, "\n".join(found)


@needs_confine
@pytest.mark.parametrize("fault,tools,channel", [
    # the pack file and the user pattern are found in the gateway's output, not only by the
    # prompt scan: ZQ-ABC12 and FAKE-PT-0007 in the log are masked by no other rule
    ("a-pack-file-weakened", {"t08"}, "gateway"),
    ("b-pattern-edited", {"t08"}, "gateway"),
    # with no root the gateway refuses every request: the hook lets the Read through
    ("c-root-removed", {"t05"}, "file"),
])
def test_a_fault_made_through_the_config_is_found(leak_tree, leak_broker, fault, tools,
                                                  channel):
    found, _missing = leaks(leak_tree, leak_broker, fault, tools=tools)
    assert any(f", {channel}: " in f for f in found), "\n".join(found) or fault
    print("\n".join(found[:5]))


@needs_confine
@linux
def test_launch_a_typical_session_leaks_nothing(leak_tree, leak_broker):
    """Mode B: the same steps inside `phiward launch --tool claude`, where the kernel refuses
    plain reads of the root (open, listdir, `ls`, `cat`, a wrapped MCP server). `notes.md` is
    allowed by `[sanitize] scan_allow` (`full-allow`), or the project scan would refuse the
    launch (test_launch_refuses_a_project_file_that_holds_an_id)."""
    if str(leak_tree).startswith("/tmp/"):
        pytest.skip("Linux: the tree is under the session's own /tmp; run with --basetemp")
    from phiward import config, install
    h = leak_tree
    env = leak_broker(h, "full-allow")
    env = {k: v for k, v in env.items() if k != "CLAUDE_PROJECT_DIR"}
    with pytest.MonkeyPatch.context() as mp:
        for k, v in env.items():
            mp.setenv(k, v)
        (h / ".claude").mkdir(exist_ok=True)
        (h / ".claude" / "settings.json").write_text(
            json.dumps(install.wiring(config.load(str(h / "repo")))))
    steps = leak_session.load(_subs(h))
    played = [[s.n, s.kind, s.name, s.input] for s in steps
              if s.kind == "prompt" or s.name in ("Bash", "Read")]
    data = str(h / "data")
    extra = [["shell", f"ls {data}"], ["shell", f"cat {data}/cohort.csv"], ["listdir", data],
             ["open", f"{data}/cohort.csv"], ["wrapped", f"{data}/cohort.csv"]]
    code = (f"import json, sys; sys.path.insert(0, {str(leak_session.TESTS)!r}); "
            "import leak_session; "
            f"leak_session.launched(json.loads({json.dumps(played)!r}), "
            f"json.loads({json.dumps(extra)!r}))")
    start = time.monotonic()
    r = subprocess.run([sys.executable, "-m", "phiward", "launch", "--tool", "claude", "--",
                        tool_py(h.parent), "-c", code], cwd=str(h / "repo"), env=env,
                       capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL)
    print(f"\nlaunch: {time.monotonic() - start:.1f} s")
    got = [json.loads(ln[len("CAPTURE "):]) for ln in r.stdout.splitlines()
           if ln.startswith("CAPTURE ")]
    assert len(got) == 1, r.stdout[-3000:] + r.stderr[-3000:]
    by_n = {s.n: s for s in steps}
    items = []
    for n, channel, text, verdict in got[0]:
        s = by_n.get(n)
        if s is None:  # the launch leg's own reads of the root
            items.append(leak_session.Item(n, "kernel", text, verdict, ("root",)))
            continue
        ch = channel or leak_session.shell_channel(s.input["command"])
        items.append(leak_session.Item(n, ch, text, verdict, leak_session.sees(s, data),
                                       s.input if s.kind == "prompt" else ""))
    found, missing = leak_session.findings(items, lv.PLANTS, lv.FULL)
    assert not found and not missing, "\n".join(found + missing) + "\n" + _show(items)
    gate = [it for it in items if it.channel == "gateway"]
    assert gate and all("exit=0" in it.text for it in gate), _show(gate)
    kernel = [it for it in items if it.channel == "kernel"]
    assert len(kernel) == 5 and not any("patient_id" in it.text for it in kernel), _show(kernel)


@needs_confine
def test_launch_refuses_a_project_file_that_holds_an_id(leak_tree, leak_broker):
    """The project scan (step 3): `notes.md` holds a study ID outside the root, so `phiward
    launch` refuses at the start, before the tool runs, and says only the kind and the count."""
    h = leak_tree
    env = {k: v for k, v in leak_broker(h, "full").items() if k != "CLAUDE_PROJECT_DIR"}
    r = subprocess.run([sys.executable, "-m", "phiward", "launch", "--tool", "claude", "--",
                        tool_py(h.parent), "-c", "print('TOOL RAN')"], cwd=str(h / "repo"),
                       env=env, capture_output=True, text=True, timeout=120,
                       stdin=subprocess.DEVNULL)
    assert r.returncode == 126 and "TOOL RAN" not in r.stdout, r.stdout + r.stderr
    assert "phiward launch: the project scan found <STUDYID> in 1 file:" in r.stderr, r.stderr
    item = leak_session.Item(0, "kernel", r.stdout + r.stderr, "deny", ("root",))
    found, _missing = leak_session.findings([item], lv.PLANTS, lv.FULL)
    assert not found, "\n".join(found)


# --- the values and the session ------------------------------------------------------------

def test_each_built_in_rule_masks_a_planted_value():
    """Each rule of each built-in pack, with its pack alone, fully masks at least one planted
    value, with its own placeholder: a new rule fails here until it has a value."""
    from phiward import config, sanitize
    packs = sorted(p.stem for p in (Path(sanitize.__file__).parent / "packs").glob("*.toml"))
    assert packs == ["dates", "genomics", "msk"], packs  # a new pack needs values too
    untested = []
    for name in packs:
        pack = sanitize.load_pack(name)
        san = sanitize.Sanitizer.from_config(config.Config(packs=[name]))
        for i, (rx, repl) in enumerate(pack.paths + pack.identifiers + pack.positions, 1):
            if not any(rx.search(p.value) and repl in san.clean(p.value) and
                       not any(c.isalnum() for c in sanitize._PLACEHOLDER.sub("",
                                                                         san.clean(p.value)))
                       for p in lv.PLANTS if p.needs == name):
                untested.append(f"{name} rule {i} ({repl})")
    assert not untested, untested


def test_no_tool_input_holds_a_planted_value(tmp_path):
    steps = leak_session.load({"REPO": "/r", "DATA": "/d", "PY": "py"})
    pastes = [s for s in steps if s.kind == "prompt" and s.tag == "paste"]
    assert len(pastes) == 4 and all(any(p.value in s.input for p in lv.PLANTS) for s in pastes)
    others = json.dumps([s.input for s in steps if s.tag != "paste"], ensure_ascii=False)
    assert not [p.value for p in lv.PLANTS if p.value in others]
    bad = tmp_path / "s.jsonl"
    bad.write_text(json.dumps({"type": "assistant", "message": {"content": [
        {"type": "tool_use", "name": "Read", "input": {"file_path": "/d/«FAKE-PT-0001»"}}]}}))
    with pytest.raises(ValueError, match="planted value"):
        leak_session.load({}, path=bad)
