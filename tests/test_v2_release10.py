"""Round 10: one helper picks the lines a refusal shows (those its step fixes); doctor's
second WARNING appears only when its step differs from the first's; the package check folds
the package's own files of yours outside home into one tree line, so its step is one command.
Made-up trees only."""

import os
import re
import subprocess


from phiward import doctor, selfcheck


MINE = selfcheck.OUTSIDE_MINE


# --- L1, R2: the lines shown are those the step fixes


def test_the_lines_shown_are_those_the_step_fixes():
    problems = [selfcheck.HOME_PROBLEM, "x.py: changed since install",
                "~/.local/x/: writable by others"]
    assert selfcheck.shown(problems) == [selfcheck.HOME_PROBLEM]
    head = selfcheck.refusal(problems)
    assert "changed since install" not in head and selfcheck.HOME_PROBLEM in head, head
    many = [f"~/f{i}: writable by others" for i in range(5)]
    assert selfcheck.shown(many + [selfcheck.MORE]) == many[:3]


# --- L1, L2, R1: a second WARNING only when its step differs


def _doctor(monkeypatch, package, python):
    monkeypatch.setattr(selfcheck, "check_full_isolated", lambda: (True, package, python))
    return doctor.selfcheck_lines()


def test_a_second_warning_never_repeats_the_first(monkeypatch):
    lines = _doctor(monkeypatch, [selfcheck.HOME_PROBLEM, "~/.local/x/: writable by others"],
                    [selfcheck.HOME_PROBLEM, f"/opt/py/lib/: writable by others {MINE}"])
    assert len(lines) == 1 and "chmod go-w ~" in lines[0], lines


def test_a_second_warning_with_its_own_step_shows_its_own_lines(monkeypatch):
    lines = _doctor(monkeypatch, ["cli.py: changed since install"],
                    ["~/.local/: writable by others"])
    assert len(lines) == 2, lines
    assert "reinstall" in lines[0] and "changed since install" in lines[0], lines
    assert "~/.local/" in lines[1] and "install claude" in lines[1], lines
    assert len(_doctor(monkeypatch, [], ["~/.local/: writable by others"])) == 1


def test_the_hint_for_more_is_kept(monkeypatch):
    tree_line = f"/opt/py/lib/: 3 entries {selfcheck.TREE_WHY} {MINE}"
    lines = _doctor(monkeypatch, [tree_line], [tree_line, selfcheck.MORE])
    assert len(lines) == 2, lines
    assert "run `phiward doctor` again" in lines[1], lines


# --- L3: the package's own files outside home are one tree line, one step, one round


def test_a_package_outside_home_is_one_tree_line_and_one_round(tree, home):
    site = tree / "opt" / "venv" / "lib" / "python3.12" / "site-packages"
    pkg = site / "phiward"
    files = []
    for i in range(60):
        f = pkg / f"sub{i // 20}" / f"m{i}.py"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(f"x = {i}\n")
        os.chmod(f, 0o664)
        files.append((str(f), "sha256=" + selfcheck._sha256_b64(str(f))))
    for d in [pkg] + [pkg / f"sub{j}" for j in range(3)]:
        os.chmod(d, 0o775)
    _ok, problems = selfcheck.check(files, str(pkg))
    real = os.path.realpath(pkg)
    tree_lines = [p for p in problems if selfcheck.TREE_WHY in p]
    assert tree_lines == [f"{real}/: 64 entries {selfcheck.TREE_WHY} {MINE}"], problems
    assert selfcheck.MORE not in problems, problems
    text = selfcheck.fix_text(problems, str(pkg))
    assert text.count("(cd ") == 1 and not re.search(r"m\d+\.py", text), text
    for cmd in re.findall(r"`([^`]+)`", text):
        if cmd.startswith(("chmod ", "(cd ")):
            subprocess.run(["sh", "-c", cmd], check=True)
    assert selfcheck.check(files, str(pkg)) == (True, [])
