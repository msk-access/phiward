"""The prompt scan (promptscan.py): would the sanitizer change the prompt? Every value here is
made up (FAKE-PT-0001, P-9990001-T01-IM6); the user config is a tmp file named by
PHIWARD_CONFIG, with HOME in a tmp folder."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import needs_confine
from phiward import config, inventory, promptscan, sanitize

MSK = '[sanitize]\npacks = ["genomics", "msk"]\n'


@pytest.fixture()
def place(tmp_path, monkeypatch):
    """home/ with the root home/data (FAKE-PT-0001.txt in it), and home/repo, the working
    folder, with src/main.py and a link `leak` to the file in the root."""
    t = tmp_path.resolve()
    home = t / "home"
    data = home / "data"
    (data / "FAKE-PT-0001").mkdir(parents=True)
    (data / "FAKE-PT-0001.txt").write_text("SECRET-CONTENT-0001\n")
    repo = home / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "main.py").write_text("print('hi')\n")
    os.symlink(data / "FAKE-PT-0001.txt", repo / "leak")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    def verdict(text, user="", cwd=repo, repo_cfg=None, roots=(data,)):
        cfg_file = t / "user.toml"
        listed = ", ".join(f'"{r}"' for r in roots)
        cfg_file.write_text(f"[protected_paths]\nroots = [{listed}]\n" + user)
        monkeypatch.setenv("PHIWARD_CONFIG", str(cfg_file))
        if repo_cfg is not None:
            (repo / ".phiward.toml").write_text(repo_cfg)
        cfg = config.load(str(cwd))
        return promptscan.prompt_verdict(text, cfg, str(cwd))

    verdict.home, verdict.data, verdict.repo = home, data, repo
    return verdict


ORDINARY = [
    "Add a --verbose flag to the CLI and update the tests",
    "why does pytest fail on test_parse with a KeyError?",
    "see pages 2–3 of the design doc",                      # an en dash (Review 3 H1)
    "why does Sample7.sorted.bam fail at chr1:1234567",     # details, positions (default packs)
    "the run printed 12345678 reads",
    "FAKE-PT-0001",                                         # an entry name alone: not checked
    "rename @src/main.py and fix @pytest.fixture usage; bump @types/node",
    "mail a@b.org about https://x.org/a/b",
    "git status shows src/main.py modified",
]


@pytest.mark.parametrize("text", ORDINARY)
def test_ordinary_prompts_clear(place, text):
    v = place(text)
    assert not v.blocked and v.kinds == () and v.why == ""


def test_pack_ids_and_user_patterns_block(place):
    v = place("check P-9990001-T01-IM6 please", MSK)
    assert v.blocked and v.kinds == ("<SAMPLEID>",)
    assert not place("check P-9990001-T01-IM6 please").blocked  # msk is not a default
    user = "[sanitize]\npatterns = ['ZQX-FAKE\\d+ => <CODE>']\n"
    assert place("see ZQX-FAKE42", user).kinds == ("<CODE>",)
    # a user rule is an identifier whatever its placeholder (Review 3 H2)
    v = place("see ZQX123", "[sanitize]\npatterns = ['ZQX\\d+ => <BAMFILE>']\n")
    assert v.blocked and v.kinds == ("<BAMFILE>",)


def test_dates_block_when_the_dates_pack_is_on(place):
    assert not place("the 2026-11-22 release").blocked
    on = '[sanitize]\npacks = ["genomics", "dates"]\n'
    assert place("the 2026-11-22 release", on).kinds == ("<DATE>",)


def test_a_repo_pattern_does_not_block_and_a_repo_root_does(place):
    pat = "[sanitize]\npatterns = ['ZQX-FAKE\\d+ => <CODE>']\n"
    # [sanitize] patterns are USER_ONLY: a repo file's are ignored
    assert not place("see ZQX-FAKE42", repo_cfg=pat).blocked
    assert place("see ZQX-FAKE42", pat).blocked
    other = place.home / "other"
    other.mkdir()
    v = place(f"open {other}/FAKE-PT-0009/x",
              repo_cfg=f'[protected_paths]\nroots = ["{other}"]\n')
    assert v.blocked and v.kinds == ("<PROTECTED>",)


def test_paths_block_in_every_spelling(place):
    d = place.data
    for text in (f"open {d}/FAKE-PT-0001/x", f"what is in {d}",          # the bare root too
                 "open ~/data/FAKE-PT-0001/x", "open $HOME/data/FAKE-PT-0001/x",
                 "open ${HOME}/data/FAKE-PT-0001/x", "../data/FAKE-PT-0001/x",
                 f'look at @"{d}/x y"', "look at ./leak", "look at (./leak)."):
        v = place(text)
        assert v.blocked and v.kinds == ("<PROTECTED>",), text
    for text in ("open data/FAKE-PT-0001/x", "@data/FAKE-PT-0001.txt", "@data/f.txt#L1-5",
                 "see `data/FAKE-PT-0001/x`:"):
        assert place(text, cwd=place.home).blocked, text


def test_remote_roots_count(place):
    user = '[remote]\nroots = ["/fake/hpc/phi"]\n'
    assert place("cat /fake/hpc/phi/FAKE-PT-0001.bam", user).kinds == ("<PROTECTED>",)


def test_derived_roots_do_not_count(place):
    """A root inside a git work tree makes its .git protected; the scan uses the configured
    roots and patterns only (Review 3 M2, D3)."""
    (place.repo / ".git").mkdir()
    inner = place.repo / "data"
    inner.mkdir()
    v = place("why is .git/index.lock there", roots=(place.data, inner))
    assert not v.blocked
    # the .git is a derived root, which output masking protects
    assert str(place.repo / ".git") in config.load(str(place.repo)).all_roots
    assert place("see data/FAKE-PT-0001/x", roots=(place.data, inner)).blocked


def test_no_names_and_no_inventory(place, monkeypatch, tmp_path):
    names = tmp_path / "names.tsv"
    names.write_text("1\t/x/FAKE-PT-0007/y\n")

    def boom(*_a, **_k):
        raise AssertionError("must not run")

    monkeypatch.setattr(inventory, "build", boom)
    monkeypatch.setattr(sanitize, "_read_names_file", boom)
    v = place("FAKE-PT-0007 and FAKE-PT-0001", f'[sanitize]\nnames_from = ["{names}"]\n')
    assert not v.blocked


def test_fails_closed_with_a_reason(place, monkeypatch, tmp_path):
    missing = tmp_path / "gone.toml"
    v = place("hello", f'[sanitize]\npacks = ["{missing}"]\n')
    assert v.blocked and "gone.toml" in v.why and v.why.endswith("run `phiward doctor`.")
    v = place("hello", "[sanitize\n")
    assert v.blocked and "config" in v.why and v.why.endswith("run `phiward doctor`.")
    v = place("hello", repo_cfg="[sanitize\n")
    assert v.blocked and "repo config" in v.why and v.why.endswith("run `phiward doctor`.")
    (place.repo / ".phiward.toml").unlink()
    v = place("x" * (promptscan.MAX_BYTES + 1))
    assert v.blocked and "too long" in v.why
    monkeypatch.setattr(sanitize.Sanitizer, "clean", lambda *a, **k: 1 / 0)
    v = place("hello")
    assert v.blocked and "could not run" in v.why


def test_withheld_text_blocks(place):
    v = place("see P%2D9990001%2DT01%2DIM6", MSK)
    assert v.blocked and v.kinds


SECRETS = ("FAKE-PT", "9990001", "ZQX", "x y", "2026-11-22", "leak", "fake/hpc")


@pytest.mark.parametrize("text,user", [
    ("check P-9990001-T01-IM6", MSK), ("see ZQX-FAKE42", "[sanitize]\npatterns = ['ZQX-FAKE\\d+ => <CODE>']\n"),
    ("open ~/data/FAKE-PT-0001/x", ""), ('@"{d}/x y"', ""), ("look at ./leak", ""),
    ("the 2026-11-22 release", '[sanitize]\npacks = ["dates"]\n'),
    ("cat /fake/hpc/phi/FAKE-PT-0001.bam", '[remote]\nroots = ["/fake/hpc/phi"]\n'),
    ("see P%2D9990001%2DT01%2DIM6", MSK),
])
def test_kinds_and_why_never_hold_input_text(place, text, user):
    v = place(text.replace("{d}", str(place.data)), user)
    assert v.blocked
    said = v.why + " ".join(v.kinds)
    assert not any(s in said for s in SECRETS) and str(place.data) not in said


# --- the corpus: ordinary prompts clear, made-up identifiers and paths block ---------------------

DATA = Path(__file__).with_name("data")
CORPUS = [ln for f in ("prompt_corpus.txt", "prompt_corpus_second.txt")
          for ln in (DATA / f).read_text(encoding="utf-8").splitlines()
          if ln.strip() and not ln.startswith("#")]
# Pack rules that hit ordinary prompts: each is a pack follow-up (it over-masks output too),
# never a filter in the scan. <DATE> blocks by design when the dates pack is on.
KNOWN_PACK_FOLLOW_UPS = {"<DONOR>", "<CMOID>", "<PATIENTPATH>", "<CLINICALPATH>"}
BY_DESIGN = {"<DATE>"}


def test_the_corpus_is_big_enough():
    assert len(CORPUS) >= 350 and len(set(CORPUS)) == len(CORPUS)


def test_no_ordinary_prompt_blocks_with_the_default_packs(place):
    hits = [(t, place(t).kinds) for t in CORPUS if place(t).blocked]
    assert hits == []


def test_no_ordinary_prompt_blocks_with_the_msk_pack(place):
    hits = [(t, place(t, MSK).kinds) for t in CORPUS if place(t, MSK).blocked]
    assert hits == []


def test_ordinary_prompts_hit_only_the_known_rules_with_every_pack(place):
    every = '[sanitize]\npacks = ["genomics", "msk", "dates"]\n'
    hits = {t: place(t, every).kinds for t in CORPUS}
    unknown = {t: k for t, k in hits.items()
               if set(k) - KNOWN_PACK_FOLLOW_UPS - BY_DESIGN}
    assert unknown == {}
    assert not [t for t, k in hits.items() if k == () and place(t, every).blocked]


def test_made_up_identifiers_and_paths_all_block(place):
    d = place.data
    user = MSK[:-1] + "\npatterns = ['ZQX-FAKE\\d+ => <CODE>']\n"
    lines = [f"cat {d}/FAKE-PT-{n:04d}/calls.vcf" for n in range(1, 6)] + [
        f"look at @{d}/FAKE-PT-0001.txt#L1-5", f"diff {d}/a {d}/b", f"ls '{d}/FAKE PT 7'",
        "head ~/data/FAKE-PT-0002/x.tsv", "wc -l $HOME/data/FAKE-PT-0003",
        "check P-9990001-T01-IM6 and P-9990002-N01-IM6", "is s_C_FAKE01_P001_d done?",
        "the code ZQX-FAKE7 failed", "see AB999999-T for the stem", "P%2D9990001%2DT01",
    ]
    assert [ln for ln in lines if not place(ln, user).blocked] == []


# --- speed: the hook runs before every prompt ---------------------------------------------------

def _p95(place, text, user="", runs=20):
    import time
    code = (f"import sys; sys.path.insert(0, {str(Path(promptscan.__file__).parents[1])!r}); "
            "from phiward.cli import main; sys.exit(main())")
    cfg_file = place.home.parent / "user.toml"
    cfg_file.write_text(f'[protected_paths]\nroots = ["{place.data}"]\n'
                        'snapshot_names = [".snapshot", ".zfs"]\n' + user)
    env = {"HOME": str(place.home), "PHIWARD_CONFIG": str(cfg_file), "PATH": os.environ["PATH"]}
    payload = json.dumps(_prompt(place, text))
    took = []
    for _ in range(runs):
        t = time.perf_counter()
        r = subprocess.run([sys.executable, "-I", "-S", "-c", code, "prompt-scan", "claude"],
                           input=payload, capture_output=True, text=True, env=env,
                           cwd=str(place.repo), timeout=60)
        took.append(time.perf_counter() - t)
        assert r.returncode in ((0, 2) if user else (0,)), r.stdout + r.stderr
    return sorted(took)[int(0.95 * (runs - 1))]


def _ordinary_text(size):
    out, i = [], 0
    while sum(len(x) + 1 for x in out) < size:
        out.append(CORPUS[i % len(CORPUS)])
        i += 1
    return "\n".join(out)


@pytest.fixture()
def in_a_work_tree(place):
    """The root inside a made-up git work tree: config.load then finds its .git, as it does on
    every prompt (Review 3 M4)."""
    (place.home / ".git").mkdir()
    return place


@pytest.mark.slow
def test_the_prompt_scan_is_quick(in_a_work_tree, capsys):
    place = in_a_work_tree
    small, big = _p95(place, _ordinary_text(4096)), _p95(place, _ordinary_text(65536), runs=10)
    msk = _p95(place, _ordinary_text(65536), MSK[:-1] + "\n", runs=5)
    with capsys.disabled():
        print(f"\nprompt-scan p95: 4 KB {small * 1000:.0f} ms, 64 KB {big * 1000:.0f} ms, "
              f"64 KB with msk {msk * 1000:.0f} ms (reported, not asserted)")
    assert small <= 0.25 and big <= 1.0


def test_the_prompt_scan_does_not_walk_the_root(in_a_work_tree, monkeypatch):
    """No folder at or below a root is listed (os.walk lists through os.scandir), and the
    inventory never runs: the size of a root cannot matter."""
    place = in_a_work_tree
    (place.data / "sub").mkdir()
    listed = []
    for name in ("scandir", "listdir"):
        real = getattr(os, name)

        def spy(path=".", _real=real):
            listed.append(os.fspath(path) if not isinstance(path, int) else path)
            return _real(path)
        monkeypatch.setattr(os, name, spy)

    def boom(*_a, **_k):
        raise AssertionError("the inventory ran")

    monkeypatch.setattr(inventory, "build", boom)
    for text in (_ordinary_text(4096), f"open {place.data}/sub/x", "see data/sub and ~/data"):
        place(text, MSK)
    root = str(place.data)
    assert [p for p in listed if isinstance(p, str) and
            (p == root or p.startswith(root + "/"))] == []


def _scan(place, payload, user=""):
    cfg_file = place.home.parent / "user.toml"
    cfg_file.write_text(f'[protected_paths]\nroots = ["{place.data}"]\n' + user)
    env = {"HOME": str(place.home), "PHIWARD_CONFIG": str(cfg_file), "PATH": os.environ["PATH"],
           "PYTHONPATH": str(Path(promptscan.__file__).parents[1]), "PHIWARD_DEV": "1"}
    data = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run([sys.executable, "-m", "phiward", "prompt-scan", "claude"],
                          input=data, capture_output=True, text=True, env=env,
                          cwd=str(place.repo), timeout=60)


def _prompt(place, text):
    return {"hook_event_name": "UserPromptSubmit", "prompt": text, "cwd": str(place.repo),
            "session_id": "s", "transcript_path": "/dev/null", "permission_mode": "default"}


def _blocked_json(r):
    assert r.returncode == 2, (r.stdout, r.stderr)
    reply = json.loads(r.stdout)
    assert reply["decision"] == "block" and reply["reason"]
    assert reply["hookSpecificOutput"] == {"hookEventName": "UserPromptSubmit",
                                           "suppressOriginalPrompt": True}
    assert r.stderr.strip() == reply["reason"]
    return reply


def test_prompt_scan_blocks_with_json_and_names_the_kind_only(place):
    r = _scan(place, _prompt(place, "check P-9990001-T01-IM6"), MSK)
    reply = _blocked_json(r)
    assert "<SAMPLEID>" in reply["reason"] and "9990001" not in r.stdout + r.stderr


def test_prompt_scan_clears_with_silence(place):
    r = _scan(place, _prompt(place, "fix the failing test in src/main.py"))
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")


@pytest.mark.parametrize("payload", [
    "not json", "[1, 2]", {"hook_event_name": "UserPromptSubmit", "cwd": "/"},
    {"hook_event_name": "UserPromptSubmit", "prompt": 7, "cwd": "/"},
    {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/x"},
     "prompt": "hi", "cwd": "/"},
])
def test_prompt_scan_blocks_what_it_cannot_read(place, payload):
    _blocked_json(_scan(place, payload))


def test_the_tool_hooks_refuse_a_prompt_event(place, monkeypatch):
    from phiward import fasthook
    from phiward.adapters import claude
    payload = json.dumps(_prompt(place, "hello"))
    out, err = io.StringIO(), io.StringIO()
    assert claude.main(io.StringIO(payload), out, err) == 2 and err.getvalue()
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    monkeypatch.setenv("PHIWARD_HOOK_ROOTS", json.dumps([str(place.data)]))
    assert fasthook.main() == 2
    # a payload with no event name (Copilot's form) still goes the old way
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(
        {"toolName": "bash", "toolArgs": {"command": "ls"}, "cwd": str(place.repo)})))
    assert fasthook.main() == 0


# --- Mode A wiring ------------------------------------------------------------------------------

def _prompt_entries(w):
    return [h for g in w["hooks"]["UserPromptSubmit"] for h in g["hooks"]]


def test_the_wiring_has_the_prompt_entry(tree):
    from phiward import install
    cfg = config.load(str(tree / "repo"))
    user = _prompt_entries(install.wiring(cfg))
    assert len(user) == 1 and user[0]["timeout"] == 10 and user[0]["onFailure"] == "block"
    assert user[0]["command"] == install.isolated_command(sys.executable, "prompt-scan")
    assert install.isolated_python(user[0]["command"], "prompt-scan") == sys.executable
    proj = _prompt_entries(install.wiring(cfg, project=True, project_dir=str(tree / "repo")))
    assert proj == [{"type": "command", "command": install.PROJECT_PROMPT_HOOK, "timeout": 10,
                     "onFailure": "block"}]


def test_merge_keeps_the_operators_prompt_hooks_and_replaces_older_forms(tree):
    from phiward import install
    w = install.wiring(config.load(str(tree / "repo")))
    mine = {"type": "command", "command": "/opt/tools/my-prompt-log"}
    old = {"type": "command", "command": "/usr/local/bin/phiward prompt-scan claude"}
    current = {"hooks": {"UserPromptSubmit": [{"hooks": [mine]}, {"hooks": [old]}]}}
    m = install.merge(current, w)
    got = _prompt_entries(m)
    assert mine in got and old not in got
    assert sum(1 for h in got if "prompt-scan" in h["command"]) == 1
    assert install.merge(m, w) == m


def test_the_plugin_hooks_are_the_project_wiring_for_every_event(tree):
    from phiward import install
    root = Path(__file__).resolve().parents[1]
    plugin = json.loads((root / "plugin" / "hooks" / "hooks.json").read_text())
    want = install.wiring(config.load(str(tree / "repo")), project=True,
                          project_dir=str(tree / "repo"))["hooks"]
    assert plugin["hooks"] == want
    assert "prompt" in plugin["description"]


@pytest.mark.parametrize("broken", ["phiward", "awk"])
def test_the_project_prompt_hook_blocks_with_json_when_it_cannot_run(tmp_path, broken):
    from phiward import install
    cmd = install.PROJECT_PROMPT_HOOK
    env = {"PATH": str(tmp_path)}  # no phiward on PATH
    if broken == "awk":
        # a phiward on PATH, and an awk that cannot start
        (tmp_path / "phiward").write_text("#!/bin/sh\nexit 0\n")
        (tmp_path / "phiward").chmod(0o755)
        cmd = cmd.replace("/usr/bin/awk", str(tmp_path / "no-awk"))
        env["PATH"] = f"{tmp_path}:/usr/bin:/bin"
    r = subprocess.run(cmd, shell=True, input="{}", capture_output=True, text=True, env=env,
                       timeout=30)
    assert r.returncode == 2, (r.stdout, r.stderr)
    reply = json.loads(r.stdout)
    assert reply["decision"] == "block" and "every prompt" in reply["reason"]
    assert reply["hookSpecificOutput"]["suppressOriginalPrompt"] is True


def test_the_user_prompt_hook_blocks_with_json_when_awk_cannot_run(tmp_path):
    from phiward import install
    cmd = install.isolated_command(sys.executable, "prompt-scan")
    assert install.isolated_python(cmd, "prompt-scan") == sys.executable
    cmd = cmd.replace("/usr/bin/awk", str(tmp_path / "no-awk"))
    r = subprocess.run(cmd, shell=True, input="{}", capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin"}, timeout=30)
    assert r.returncode == 2, (r.stdout, r.stderr)
    reply = json.loads(r.stdout)
    assert reply["decision"] == "block" and "every prompt" in reply["reason"]
    assert reply["hookSpecificOutput"]["suppressOriginalPrompt"] is True


# --- Mode B: the entry beside the fast hook in the session's own settings -----------------------

def _launch_settings(folder, data=None):
    from phiward import wholetool
    if data is not None:
        (folder / "settings.json").write_text(json.dumps(data))
    fd = os.open(str(folder), os.O_RDONLY)
    try:
        wholetool.ADAPTERS["claude"].turn_own_sandbox_off(fd)
    finally:
        os.close(fd)
    return json.loads((folder / "settings.json").read_text())


def test_launch_writes_the_prompt_entry_and_replaces_its_own(tmp_path):
    mine = {"type": "command", "command": "/opt/tools/my-prompt-log"}
    decoy = {"type": "command", "command": "/usr/bin/true phiward prompt-scan claude"}
    s = _launch_settings(tmp_path, {"hooks": {"UserPromptSubmit": [{"hooks": [mine]},
                                                                   {"hooks": [decoy]}]}})
    got = _prompt_entries(s)
    ours = [h for h in got if "prompt-scan claude" in h["command"]]
    assert mine in got and decoy not in got and len(ours) == 1
    assert ours[0]["timeout"] == 10 and ours[0]["onFailure"] == "block"
    assert " -I -S -c " in ours[0]["command"]
    assert _launch_settings(tmp_path) == s  # once, however often it runs


# the prompts are written into the code, not given as arguments: on Linux, launch adds
# `--settings JSON` to the tool's arguments (Claude Code's own sandbox inside the profile)
LAUNCHED_SCAN = """
import json, os, subprocess, sys
s = json.load(open(os.path.join(os.environ["CLAUDE_CONFIG_DIR"], "settings.json")))
cmd = [h["command"] for g in s["hooks"]["UserPromptSubmit"] for h in g["hooks"]
       if "prompt-scan claude" in h["command"]]
for text in TEXTS:
    p = {"hook_event_name": "UserPromptSubmit", "prompt": text, "cwd": os.getcwd()}
    r = subprocess.run(cmd[0], shell=True, input=json.dumps(p), capture_output=True, text=True)
    print("RESULT", json.dumps([r.returncode, r.stdout]))
"""


def _launched(tree, *texts):
    from helpers import tool_py
    code = f"TEXTS = {list(texts)!r}\n" + LAUNCHED_SCAN
    r = subprocess.run([sys.executable, "-m", "phiward", "launch", "--tool", "claude", "--",
                        tool_py(tree), "-c", code], cwd=str(tree / "repo"),
                       capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL,
                       env=dict(os.environ, PYTHONPATH=str(Path(promptscan.__file__).parents[1])))
    got = [json.loads(ln[len("RESULT "):]) for ln in r.stdout.splitlines()
           if ln.startswith("RESULT ")]
    assert len(got) == len(texts), r.stdout + r.stderr
    return got


def _user_config(text):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text().replace("[protected_paths]\n", text + "[protected_paths]\n"))


@needs_confine
def test_the_launched_prompt_scan_works_with_the_roots_unreadable(tree):
    _user_config('[sanitize]\npacks = ["genomics", "msk"]\n')
    clear, pack = _launched(tree, "fix the bug in src/app.py", "check P-9990001-T01-IM6")
    assert clear == [0, ""]
    assert pack[0] == 2 and "<SAMPLEID>" in json.loads(pack[1])["reason"]


@needs_confine
def test_the_launched_prompt_scan_names_a_pack_file_it_cannot_read(tree):
    pack = tree / "phi" / "mine.toml"
    pack.write_text("[pack]\nidentifiers = ['ZQX\\\\d+ => <CODE>']\n")
    _user_config(f'[sanitize]\npacks = ["genomics", "{pack}"]\n')
    (got,) = _launched(tree, "fix the bug in src/app.py")
    assert got[0] == 2 and "mine.toml" in json.loads(got[1])["reason"]


# --- doctor -------------------------------------------------------------------------------------

def _state(tree, user):
    from helpers import user_settings
    from phiward import doctor
    user_settings(tree, user)
    return doctor.wiring_state(str(tree / "repo"), str(tree / "home"))


def _user_wiring(tree):
    from phiward import install
    return install.wiring(config.load(str(tree / "repo")))


def test_doctor_wants_the_prompt_entry_where_phiward_is_wired(tree):
    w = _user_wiring(tree)
    assert not any("prompt" in p for p in _state(tree, w).problems)
    only_tools = {"hooks": {"PreToolUse": w["hooks"]["PreToolUse"]}}
    assert any("prompt" in p for p in _state(tree, only_tools).problems)
    for bad in ({"onFailure": None}, {"async": True}, {"if": "x"}):
        entry = dict(_prompt_entries(w)[0], **bad)
        entry = {k: v for k, v in entry.items() if v is not None}
        data = dict(w, hooks=dict(w["hooks"], UserPromptSubmit=[{"hooks": [entry]}]))
        assert any("prompt" in p for p in _state(tree, data).problems), bad
    # a decoy at any path named phiward is not phiward's prompt check
    decoy = {"type": "command", "command": f"{tree}/pub/phiward prompt-scan claude",
             "timeout": 10, "onFailure": "block"}
    data = dict(w, hooks=dict(w["hooks"], UserPromptSubmit=[{"hooks": [decoy]}]))
    assert any("not its prompt check" in p for p in _state(tree, data).problems)


@pytest.mark.parametrize("event,kind", [("UserPromptSubmit", "prompt"),
                                        ("UserPromptSubmit", "http"),
                                        ("UserPromptExpansion", "command")])
def test_doctor_warns_of_other_prompt_hooks_without_a_problem(tree, event, kind):
    w = _user_wiring(tree)
    (tree / "repo" / ".claude").mkdir(exist_ok=True)
    other = {"type": kind, "command": "/opt/tools/FAKE-HOOK-SECRET", "url": "https://x.org/h",
             "prompt": "FAKE-HOOK-SECRET"}
    (tree / "repo" / ".claude" / "settings.json").write_text(json.dumps(
        {"hooks": {event: [{"hooks": [other]}]}}))
    s = _state(tree, w)
    said = [ln for ln in s.lines if "WARNING" in ln and event in ln]
    assert said and "project" in said[0] and kind in said[0]
    assert "FAKE-HOOK-SECRET" not in "\n".join(s.lines + s.problems)
    assert not any(event in p for p in s.problems)


def test_doctor_warns_of_a_prompt_hook_in_an_enabled_plugin(tree):
    w = _user_wiring(tree)
    root = tree / "home" / ".claude" / "plugins" / "cache" / "mkt" / "logger" / "1.0"
    (root / "hooks").mkdir(parents=True)
    (root / "hooks" / "hooks.json").write_text(json.dumps({"hooks": {"UserPromptSubmit": [
        {"hooks": [{"type": "http", "url": "https://x.org/FAKE-HOOK-SECRET"}]}]}}))
    (tree / "home" / ".claude" / "plugins" / "installed_plugins.json").write_text(json.dumps(
        {"version": 2, "plugins": {"logger@mkt": [{"scope": "user", "installPath": str(root)}]}}))
    s = _state(tree, dict(w, enabledPlugins={"logger@mkt": True}))
    said = [ln for ln in s.lines if "WARNING" in ln and "logger@mkt" in ln]
    assert said and "http" in said[0] and "FAKE-HOOK-SECRET" not in "\n".join(s.lines)
    assert not any("logger" in p for p in s.problems)


def test_doctor_warns_of_a_user_pack_file_under_a_root(tree):
    from phiward import doctor
    pack = tree / "phi" / "mine.toml"
    pack.write_text("[pack]\nidentifiers = ['ZQX\\\\d+ => <CODE>']\n")
    first = Path(os.environ["PHIWARD_CONFIG"]).read_text()
    _user_config(f'[sanitize]\npacks = ["genomics", "{pack}"]\n')
    lines = doctor.pack_lines(config.load(str(tree / "repo")))
    assert len(lines) == 1 and lines[0].startswith("WARNING") and "launch" in lines[0]
    outside = tree / "pub" / "mine.toml"
    outside.write_text(pack.read_text())
    Path(os.environ["PHIWARD_CONFIG"]).write_text(first)
    _user_config(f'[sanitize]\npacks = ["genomics", "{outside}"]\n')
    assert doctor.pack_lines(config.load(str(tree / "repo"))) == []
