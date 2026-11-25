"""The project scan (`projectscan`): subject and sample IDs in the project's own files and file
names, outside the protected roots, found at launch (it refuses), by doctor (a WARNING; with
`--headless` a problem) and by the SessionStart note (a warning only), PLAN-PHI-TESTS step 3.

The scan uses the subject rules only (the effective packs and the user's patterns, less files,
reads and dates; no roots, entries or names), walks the project once without git, follows no
link, and says counts, kinds and masked paths only. Made-up values only.
"""

import ast
import gzip
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import leak_session
from helpers import Tty, git_repo
from phiward import config, doctor, projectscan, run, sanitize, session_note, wholetool

SRC = str(Path(__file__).resolve().parents[1] / "src")
LAUNCH = ("import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; "
          "from phiward.cli import main; sys.exit(main())")
PATTERN = r"FAKE-PT-\d{4} => <SUBJECT>"
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")
FIX = ("move the data under a protected root, pseudonymize it (phiward pseudonymize), or allow "
       "the files ([sanitize] scan_allow); phiward doctor --show-paths lists them")


def ag(args, cwd, timeout=120):
    e = {k: v for k, v in os.environ.items() if k != "CLAUDE_PROJECT_DIR"}
    e["PYTHONPATH"] = SRC
    r = subprocess.run([sys.executable, "-c", LAUNCH] + args, cwd=str(cwd), capture_output=True,
                       text=True, env=e, timeout=timeout, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


def lst(vals):
    return "[" + ", ".join(f"'{v}'" for v in vals) + "]"  # TOML literal strings


def scan_cfg(packs=("genomics", "msk", "dates"), patterns=(PATTERN,), allow=()):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + "[sanitize]\n" + f"packs = {lst(packs)}\n"
                 + (f"patterns = {lst(patterns)}\n" if patterns else "")
                 + (f"scan_allow = {lst(allow)}\n" if allow else ""))


def scan(tree, deadline=None):
    repo = str(tree / "repo")
    return projectscan.scan(config.load(repo), repo, deadline)


def hits(r):
    return {(p, n): k for p, n, k in r.hits}


def never_shown(text, values):
    for v in values:
        assert not leak_session._forms(v, text), (v, leak_session._forms(v, text), text)


IDS = ["FAKE-PT-0001", "FAKE-PT-0002", "FAKE-PT-0003", "FAKE-PT-0004", "P-9990001-T01-IM6"]


# --- 1. what is found ---------------------------------------------------------------------------

def test_ids_in_tracked_untracked_and_ignored_files_and_in_a_name_are_found(tree):
    scan_cfg()
    repo = tree / "repo"
    git_repo(repo)
    (repo / ".gitignore").write_text("data/\n")
    (repo / "tracked.txt").write_text("see FAKE-PT-0001\n")
    for args in (["add", "-A"], ["-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                 "commit", "-qm", "t"]):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    (repo / "FAKE-PT-0002.csv").write_text("x\n")
    (repo / "untracked.txt").write_text("a\nb FAKE-PT-0003\n")
    (repo / "data").mkdir()
    (repo / "data" / "cohort.csv").write_text("id\nFAKE-PT-0004\n")
    r = scan(tree)
    assert r.error == "" and r.complete and not r.off, r
    assert hits(r) == {("tracked.txt", 1): ("<SUBJECT>",), ("<SUBJECT>.csv", 0): ("<SUBJECT>",),
                       ("untracked.txt", 2): ("<SUBJECT>",),
                       ("data/cohort.csv", 2): ("<SUBJECT>",)}, r.hits
    assert r.skipped[projectscan.SKIPPED] == 1  # .git


def test_the_instruction_files_are_read_first(tree):
    scan_cfg(packs=["msk"], patterns=())
    repo = tree / "repo"
    (repo / "AAA.txt").write_text("P-9990002-T01-IM6\n")
    (repo / "CLAUDE.md").write_text("# notes\n\nsample P-9990001-T01-IM6\n")
    (repo / ".claude").mkdir()
    (repo / ".claude" / "x.md").write_text("C-FAKE01\n")
    r = scan(tree)
    assert r.hits == [("CLAUDE.md", 3, ("<SAMPLEID>",)), (".claude/x.md", 1, ("<CMOID>",)),
                      ("AAA.txt", 1, ("<SAMPLEID>",))], r.hits


def test_no_finding_for_positions_numbers_files_dates_roots_or_the_repo_config(tree):
    scan_cfg()
    repo = tree / "repo"
    (repo / "README.md").write_text("chr7:55249071 has 12,345,678 reads in sample.sorted.bam\n")
    (repo / "CHANGELOG.md").write_text("## 1.0 (2024-03-05)\n")
    (repo / "load.py").write_text(f'DATA = "{tree}/phi"\nARM = "{tree}/runs/run1/panel"\n')
    (repo / ".phiward.toml").write_text(f'[sanitize]\npacks = ["msk"]\n'
                                        f'[protected_paths]\nroots = ["{tree}/phi"]\n')
    r = scan(tree)
    assert r.hits == [] and r.error == "" and r.complete and r.files >= 5, r


def test_with_no_subject_rule_the_scan_is_off(tree):
    (tree / "repo" / "x.txt").write_text("FAKE-PT-0001 P-9990001-T01-IM6\n")
    r = scan(tree)  # the default pack only: files and reads, no subject rule
    assert r.off and r.hits == [] and r.error == "", r


def test_a_repo_file_can_add_a_built_in_pack_to_the_scan(tree):
    repo = tree / "repo"
    (repo / ".phiward.toml").write_text('[sanitize]\npacks = ["msk"]\n')
    (repo / "x.txt").write_text("P-9990001-T01-IM6\n")
    assert hits(scan(tree)) == {("x.txt", 1): ("<SAMPLEID>",)}


# --- 2. what is skipped, and counted -----------------------------------------------------------

def test_skipped_folders_binaries_long_lines_and_link_targets(tree):
    scan_cfg()
    repo = tree / "repo"
    for d in ("node_modules", ".venv"):
        (repo / d).mkdir()
        (repo / d / "x.txt").write_text("FAKE-PT-0001\n")
    (repo / "blob.bin").write_bytes(b"FAKE-PT-0002\x00\x01\x02")
    (repo / "min.js").write_text("x" * (run.MAX_LINE + 1) + " FAKE-PT-0003\nok\n")
    (tree / "pub" / "ids.txt").write_text("FAKE-PT-0004\n")
    os.symlink(tree / "pub", repo / "FAKE-PT-0005")  # a link out: its name only
    r = scan(tree)
    assert hits(r) == {("<SUBJECT>", 0): ("<SUBJECT>",)}, r.hits
    assert r.skipped[projectscan.SKIPPED] == 2
    assert r.skipped[projectscan.BINARY] == 1
    assert r.skipped[projectscan.LONG] == 1


def test_the_line_limit_is_the_gateways():
    assert projectscan.MAX_LINE == run.MAX_LINE


def test_a_protected_folder_inside_the_project_is_not_read(tree):
    repo = tree / "repo"
    (repo / "inner").mkdir()
    (repo / "inner" / "x.txt").write_text("FAKE-PT-0001\n")
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text().replace(f'roots = ["{tree}/phi"]',
                                       f'roots = ["{tree}/phi", "{repo}/inner"]'))
    scan_cfg()
    r = scan(tree)
    assert r.hits == [] and r.skipped[projectscan.PROTECTED] == 1, r


def test_a_folder_over_the_entry_cap_is_not_fully_scanned(tree, monkeypatch):
    scan_cfg()
    monkeypatch.setattr(projectscan, "ENTRY_CAP", 6)  # the project's top holds 5
    d = tree / "repo" / "many"
    d.mkdir()
    for i in range(7):
        (d / f"f{i}.txt").write_text("x\n")
    r = scan(tree)
    assert r.skipped[projectscan.CAPPED] == 1, r


# --- 3. what is read ----------------------------------------------------------------------------

def test_gzip_bgzf_and_utf16_are_read_and_the_head_is_1_mib(tree):
    scan_cfg()
    repo = tree / "repo"
    with gzip.open(repo / "calls.csv.gz", "wt") as fh:
        fh.write("id\nFAKE-PT-0001\n")
    # two gzip members, as BGZF writes them: the ID is in the second
    (repo / "two.vcf.gz").write_bytes(gzip.compress(b"#h\n") + gzip.compress(b"FAKE-PT-0002\n"))
    (repo / "excel.txt").write_bytes("id\tx\nFAKE-PT-0003\t1\n".encode("utf-16"))
    (repo / "big.csv").write_text("a\n" * (projectscan.HEAD // 2) + "FAKE-PT-0004\n")
    r = scan(tree)
    assert hits(r) == {("calls.csv.gz", 2): ("<SUBJECT>",), ("two.vcf.gz", 2): ("<SUBJECT>",),
                       ("excel.txt", 2): ("<SUBJECT>",)}, r.hits
    assert r.skipped[projectscan.HEAD_ONLY] == 1


def test_under_a_budget_the_head_is_64_kib(tree):
    scan_cfg()
    (tree / "repo" / "mid.csv").write_text("a\n" * (projectscan.HEAD_BUDGET // 2)
                                           + "FAKE-PT-0001\n")
    r = scan(tree, time.monotonic() + 600)
    assert r.hits == [] and r.skipped[projectscan.HEAD_ONLY] == 1, r
    assert hits(scan(tree)) == {("mid.csv", projectscan.HEAD_BUDGET // 2 + 1): ("<SUBJECT>",)}


def test_a_folder_named_after_an_id_counts_once(tree):
    scan_cfg()
    d = tree / "repo" / "FAKE-PT-0001" / "sub"
    d.mkdir(parents=True)
    for i in range(5):
        (d / f"f{i}.txt").write_text("x\n")
    (d / "FAKE-PT-0002.txt").write_text("x\n")
    assert sorted(p for p, _n, _k in scan(tree).hits) == [
        "<SUBJECT>", "<SUBJECT>/sub/<SUBJECT>.txt"]


def test_the_plain_skip_is_exact(tree):
    """A plain line that no rule matches as written is one `clean` leaves as it is, over made-up
    lines built from pieces of IDs, separators, escapes and other characters."""
    import random
    scan_cfg(packs=["genomics", "msk", "dates"], patterns=(PATTERN, r"^ZQ\d{3}$ => <CODE>"))
    san = sanitize.subject_sanitizer(config.load(str(tree / "repo")))
    # what the skip rests on: no protected paths, entry names or name tokens in the scan's
    # sanitizer, so only its rules can change a plain line
    assert san.protected is None and san.entries is None and san.re_names is None
    searches = [rx.search for rx, _r in san.path_rules + san.id_rules]
    pieces = ["FAKE", "-", "PT", "0001", "P-", "9990001", "-T01", "-IM6", "C-", "FAKE01", "s_C_",
              "AB123456", "-T", "Donor", "x7", "ZQ", "123", " ", "\t", "_", ".", "/", ",", "a",
              "‐", "Ｆ", "\\x2d", "%2D", "\\u002d", "\x1b[0m", "​", "\x00", "\x7f"]
    rnd = random.Random(7)
    skipped = 0
    for _ in range(20000):
        line = "".join(rnd.choice(pieces) for _k in range(rnd.randint(1, 8)))
        if projectscan.plain(line) and not any(s(line) for s in searches):
            skipped += 1
            assert san.clean(line) == sanitize.normalize(line) == line, repr(line)
    assert 1000 < skipped < 20000, skipped


def test_an_escaped_id_is_found(tree):
    scan_cfg()
    (tree / "repo" / "x.json").write_text('{"id": "FAKE\\u002dPT-0001"}\n')
    assert ("x.json", 1) in hits(scan(tree))


# --- 4. scan_allow ------------------------------------------------------------------------------

def test_scan_allow_a_folder_allows_the_files_below_it(tree):
    repo = tree / "repo"
    (repo / "tests" / "fixtures").mkdir(parents=True)
    (repo / "tests" / "fixtures" / "FAKE-PT-0001.csv").write_text("FAKE-PT-0001\n")
    (repo / "notes.txt").write_text("FAKE-PT-0002\n")
    scan_cfg(allow=[f"{repo}/tests"])
    r = scan(tree)
    assert hits(r) == {("notes.txt", 1): ("<SUBJECT>",)}, r.hits
    assert r.skipped[projectscan.ALLOWED] == 1


def test_scan_allow_takes_a_tilde(tree):
    home = tree / "home"
    (home / "proj").mkdir()
    scan_cfg(allow=["~/proj"])
    assert config.load(str(tree / "repo")).sanitize_scan_allow == [str(home / "proj")]


def test_scan_allow_in_a_repo_file_is_ignored(tree):
    repo = tree / "repo"
    (repo / ".phiward.toml").write_text(f'[sanitize]\nscan_allow = ["{repo}"]\n')
    cfg = config.load(str(repo))
    assert "sanitize.scan_allow" in cfg.ignored and cfg.sanitize_scan_allow == []


def test_a_relative_scan_allow_entry_is_a_config_problem(tree):
    scan_cfg(allow=["tests"])
    assert "scan_allow" in config.load(str(tree / "repo")).problem


# --- 5. launch ----------------------------------------------------------------------------------

def _build(tree, server=False):
    return wholetool.build(["/bin/echo", "x"], str(tree / "repo"), dict(os.environ),
                           wholetool.ADAPTERS["generic"], server=server)


def _try_build(tree, server=False):
    try:
        cmd, *_rest = _build(tree, server=server)
    except wholetool.LaunchError as exc:
        return str(exc)
    from phiward import confine
    confine.release_profile(cmd)
    return ""


def _plant(tree):
    (tree / "repo" / "notes.md").write_text("# notes\nFAKE-PT-0001\n")
    (tree / "repo" / "FAKE-PT-0002.txt").write_text("x\n")


def test_launch_refuses_on_a_finding_before_any_run_folder(tree):
    scan_cfg()
    _plant(tree)
    folder = wholetool.tool_folder(wholetool.ADAPTERS["generic"], dict(os.environ))
    with pytest.raises(wholetool.LaunchError) as exc:
        _build(tree)
    msg = str(exc.value)
    assert msg == ("the project scan found <SUBJECT> in 1 file, <SUBJECT> in 1 file name: "
                   + FIX), msg
    assert not os.path.exists(folder)
    never_shown(msg, IDS)


def test_launch_starts_on_a_clean_project(tree):
    scan_cfg()
    assert "project scan" not in _try_build(tree)


def test_launch_over_its_budget_warns_and_starts(tree, monkeypatch, capsys):
    scan_cfg()
    _plant(tree)
    monkeypatch.setattr(projectscan, "deadline", lambda: 0.0)
    assert "project scan" not in _try_build(tree)
    err = capsys.readouterr().err
    assert ("phiward launch: NOTE: the project scan stopped at its 2 s limit after 0 files; run "
            "phiward doctor for the full scan") in err, err


class _Clock:
    """A clock that moves 1 ms each time it is read: a budget runs out after a known number of
    looks, whatever the machine's speed."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        self.now += 0.001
        return self.now


def test_under_a_tiny_budget_claude_md_is_still_read_and_launch_refuses(tree, monkeypatch):
    scan_cfg(packs=["msk"], patterns=())
    repo = tree / "repo"
    for i in range(3000):
        d = repo / "pkg" / f"d{i // 100}"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"m{i}.py").write_text("x = 1\n")
    (repo / "CLAUDE.md").write_text("# a\nP-9990001-T01-IM6\n")
    monkeypatch.setattr(projectscan, "time", _Clock())
    monkeypatch.setattr(projectscan, "BUDGET", 0.05)
    r = scan(tree, projectscan.deadline())
    assert not r.complete and ("CLAUDE.md", 2) in hits(r), r
    with pytest.raises(wholetool.LaunchError) as exc:
        _build(tree)
    assert str(exc.value).startswith("the project scan found <SAMPLEID> in 1 file:")


def test_launch_notes_what_a_finished_scan_did_not_read(tree, capsys):
    scan_cfg()
    (tree / "repo" / "min.js").write_text("x" * (run.MAX_LINE + 1) + "\n")
    assert "project scan" not in _try_build(tree)
    err = capsys.readouterr().err
    # under launch's 64 KiB head, the long line is cut by the head first
    assert ("phiward launch: NOTE: the project scan did not read all of the project (1 files "
            "read only to their head); phiward doctor gives the counts") in err, err


@pytest.mark.parametrize("raised", [sanitize.SanitizerError("FAKE-PT-0001"),
                                    RuntimeError("FAKE-PT-0001")])
def test_a_scan_that_cannot_run_makes_launch_refuse(tree, monkeypatch, raised):
    scan_cfg()

    def boom(*_a, **_k):
        raise raised
    monkeypatch.setattr(sanitize, "subject_sanitizer", boom)
    with pytest.raises(wholetool.LaunchError) as exc:
        _build(tree)
    assert str(exc.value) == "the project scan could not run; run phiward doctor"


def test_a_wrapped_server_is_not_scanned(tree):
    scan_cfg()
    _plant(tree)
    assert "project scan" not in _try_build(tree, server=True)


# --- 6. doctor and the session note -------------------------------------------------------------

def test_doctor_warns_with_counts_and_kinds_and_keeps_its_exit_status(tree):
    scan_cfg()
    code0, out0 = ag(["doctor"], tree / "repo")
    assert "project scan: ok (" in out0, out0
    _plant(tree)
    code, out = ag(["doctor"], tree / "repo")
    assert code == code0, out
    assert ("WARNING: project scan: found <SUBJECT> in 1 file, <SUBJECT> in 1 file name; "
            "`phiward doctor --show-paths` in your own terminal lists them.") in out, out
    never_shown(out, IDS)


def test_doctor_says_the_scan_is_off_with_no_subject_rule(tree):
    _code, out = ag(["doctor"], tree / "repo")
    assert "project scan: off (no rule for subject or sample identifiers)" in out, out


def test_doctor_show_paths_lists_masked_paths_and_line_numbers(tree, capsys, monkeypatch):
    scan_cfg()
    repo = tree / "repo"
    (repo / "data").mkdir()
    (repo / "data" / "FAKE-PT-0001.csv").write_text("x\nFAKE-PT-0002\n")
    (repo / "CLAUDE.md").write_text("# a\n\nP-9990001-T01-IM6\n")
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.chdir(repo)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    doctor.main(["--show-paths"])
    out = capsys.readouterr().out
    lines = out.splitlines()
    at = next(i for i, ln in enumerate(lines) if ln.startswith("WARNING: project scan: found"))
    listed = []
    for ln in lines[at + 1:]:
        if not ln.startswith("  "):
            break
        listed.append(ln)
    assert listed == ["  CLAUDE.md: line 3: <SAMPLEID>", "  data/<SUBJECT>.csv: name: <SUBJECT>",
                      "  data/<SUBJECT>.csv: line 2: <SUBJECT>"], out
    never_shown("\n".join(listed), IDS)


def test_headless_lists_the_finding(tree):
    scan_cfg()
    _plant(tree)
    code, out = ag(["doctor", "--headless"], tree / "repo")
    assert code == 1, out
    assert "- the project scan found <SUBJECT> in 1 file, <SUBJECT> in 1 file name" in out, out
    never_shown(out, IDS)


def test_doctor_in_the_home_folder_skips_the_scan(tree):
    scan_cfg()
    (tree / "home" / "x.txt").write_text("FAKE-PT-0001\n")
    _code, out = ag(["doctor"], tree / "home")
    assert "project scan: skipped (not a project folder)" in out, out
    assert "project scan: found" not in out


def _note(tree, capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"cwd": str(tree / "repo")})))
    assert session_note.main(["claude"]) == 0
    return json.loads(capsys.readouterr().out)["hookSpecificOutput"]["additionalContext"]


def test_the_session_note_warns_with_counts_only(tree, capsys, monkeypatch):
    scan_cfg()
    _plant(tree)
    ctx = _note(tree, capsys, monkeypatch)
    assert "phiward's project scan found <SUBJECT> in 1 file, <SUBJECT> in 1 file name" in ctx
    never_shown(ctx, IDS)


def test_the_session_note_says_nothing_of_a_clean_project(tree, capsys, monkeypatch):
    scan_cfg()
    assert "project scan" not in _note(tree, capsys, monkeypatch)


def test_under_launch_the_note_does_not_scan_again(tree, capsys, monkeypatch):
    scan_cfg()
    _plant(tree)

    called = []
    monkeypatch.setattr(wholetool, "already_confined", lambda env: True)
    monkeypatch.setattr(projectscan, "scan", lambda *a, **k: called.append(a))
    ctx = _note(tree, capsys, monkeypatch)
    assert "Rules for this session" in ctx and "project scan" not in ctx and not called


def test_a_scan_error_never_stops_the_session_note(tree, capsys, monkeypatch):
    scan_cfg()
    _plant(tree)

    def boom(*_a, **_k):
        raise RuntimeError("FAKE-PT-0001")
    monkeypatch.setattr(sanitize, "subject_sanitizer", boom)
    ctx = _note(tree, capsys, monkeypatch)
    assert "Rules for this session" in ctx and "FAKE-PT-0001" not in ctx


# --- 7. no git --------------------------------------------------------------------------------

def test_the_scan_runs_no_program():
    src = Path(projectscan.__file__).read_text()
    mods = set()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Import):
            mods |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module:
            mods.add(n.module.split(".")[0])
    assert not mods & {"subprocess", "pty", "multiprocessing", "shutil"}, mods
    for word in ("system(", "popen", "exec", "spawn", "fork"):
        assert word not in src, word


@linux
def test_a_git_fsmonitor_in_the_project_does_not_run(tree):
    """Plants a program that git would run: Linux (the container) only, AGENTS.md."""
    scan_cfg()
    repo = tree / "repo"
    git_repo(repo)
    mark = tree / "pub" / "fsmonitor-ran"
    prog = tree / "pub" / "fsmonitor.sh"
    prog.write_text(f"#!/bin/sh\ntouch {mark}\n")
    prog.chmod(0o755)
    subprocess.run(["git", "config", "core.fsmonitor", str(prog)], cwd=repo, check=True)
    (repo / "x.txt").write_text("FAKE-PT-0001\n")
    assert ("x.txt", 1) in hits(scan(tree))
    assert not mark.exists()


# --- 8. speed -----------------------------------------------------------------------------------

SOURCE = "".join(f"def f{i}(x):\n    return x + {i}  # a made-up module line\n"
                 for i in range(50))  # about 4 KB


def test_where_the_time_goes(tree):
    """A measurement, printed: the cost per line of the scan's steps on made-up source lines."""
    scan_cfg()
    san = sanitize.subject_sanitizer(config.load(str(tree / "repo")))
    lines = SOURCE.split("\n") * 500
    text = "\n".join(lines)

    def per_line(f):
        start = time.perf_counter()
        f()
        return (time.perf_counter() - start) / len(lines) * 1e6

    rules = san.path_rules + san.id_rules
    print(f"\n{len(lines)} lines, {len(rules)} rules; us per line:")
    print(f"  normalize: {per_line(lambda: [sanitize.normalize(x) for x in lines]):.2f}")
    print(f"  clean: {per_line(lambda: [san.clean(x) for x in lines]):.2f}")
    print(f"  any rule, per line: "
          f"{per_line(lambda: [any(rx.search(x) for rx, _r in rules) for x in lines]):.2f}")
    for rx, r in rules:
        print(f"  {r} over the whole text: {per_line(lambda rx=rx: rx.search(text)):.3f}")
    s = projectscan._Scan(san, str(tree / "repo"), config.load(str(tree / "repo")), None)
    print(f"  the scan's check (plain skip, else clean): "
          f"{per_line(lambda: [s.kinds(x) for x in lines]):.2f}")


def test_a_large_made_up_project_keeps_the_launch_budget(tree):
    scan_cfg()
    repo = tree / "repo"
    for i in range(5000):
        d = repo / "pkg" / f"d{i // 100}"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"m{i}.py").write_text(SOURCE)
    data = repo / "data"
    data.mkdir()
    row = "".join(f"{i},GENE{i % 50},{i * 7}\n" for i in range(100))
    for i in range(10):
        (data / f"table{i}.csv").write_text(row * (2 * 1024 * 1024 // len(row)))
    cfg = config.load(str(repo))
    start = time.monotonic()
    full = projectscan.scan(cfg, str(repo))
    took_full = time.monotonic() - start
    start = time.monotonic()
    r = projectscan.scan(cfg, str(repo), projectscan.deadline())
    took = time.monotonic() - start
    print(f"\nproject scan: full {full.files} files in {took_full:.2f} s; with the budget "
          f"{r.files} of {r.listed} listed files in {took:.2f} s (complete: {r.complete})")
    assert full.complete and full.hits == [] and full.files == 5000 + 10 + 2, full.files
    assert took <= projectscan.BUDGET + 0.5, took
    assert r.complete or r.files < full.files
    # the small files come first: most of the project is read within the budget. How much fits
    # depends on the machine: this tree is read whole on a laptop. GitHub's macOS runners vary:
    # the same code read 62 to 77% of it when the full scan took 4.4 to 5.1 s, and 32 to 47%
    # when it took 6.0 to 8.0 s. So CI scales by the machine: the share of the files read is at
    # least the share of the full scan's time that the budget allows (1.3 to 1.7 times it in
    # those runs)
    share = min(0.9, projectscan.BUDGET / took_full) if os.environ.get("CI") else 0.9
    assert r.files >= share * full.files, (r.files, full.files, took_full)
