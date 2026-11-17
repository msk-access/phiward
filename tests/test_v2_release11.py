"""Round 11: a refusal names the tree line first and says how many more lines its step fixes;
the tree step skips only a root's own top-level site-packages (no venv comparison); the package
check reads a file with a mode fault too, and never waits on one that is not a regular file.
Made-up trees only."""

import os
import stat
import subprocess
import time


from phiward import selfcheck
from helpers import write_file


MINE = selfcheck.OUTSIDE_MINE


# --- L1: the tree line first, and how many more


def test_a_refusal_names_the_tree_line_and_how_many_more():
    ways = [f"/opt/t/{n}/: writable by others {MINE}" for n in ("a", "b", "c", "d")]
    tree_line = f"/opt/t/a/b/c/d/phiward/: 6 entries {selfcheck.TREE_WHY} {MINE}"
    head = selfcheck.refusal(ways + [tree_line])
    assert tree_line in head and "and 2 more" in head, head
    assert selfcheck.shown(ways + [tree_line])[0] == tree_line
    full = [f"~/f{i}: writable by others" for i in range(selfcheck.MAX_PROBLEMS)]
    assert selfcheck._listed(full + [selfcheck.MORE]).endswith(
        f"; and at least {selfcheck.MAX_PROBLEMS - 3} more")
    # MORE of another kind is not this kind's
    assert "more" not in selfcheck._listed([selfcheck.HOME_PROBLEM, selfcheck.MORE])


# --- L2: the step skips only the root's own top-level site-packages


def test_a_venv_root_step_compiles_its_site_packages(tree, home):
    venv = tree / "opt" / "venv"
    write_file(venv / "lib" / "python3.12" / "site-packages" / "pkg" / "m.py", mode=0o664)
    step = selfcheck._tree_step(str(venv), False)
    subprocess.run(["sh", "-c", step], check=True)
    assert (venv / "lib" / "python3.12" / "site-packages" / "pkg" / "__pycache__").is_dir()


def test_a_base_root_skips_only_its_top_level_site_packages(tree, home):
    root = tree / "opt" / "lib"
    top = write_file(root / "site-packages" / "x.py", mode=0o664)
    write_file(root / "test" / "site-packages" / "y.py")
    subprocess.run(["sh", "-c", selfcheck._tree_step(str(root), True)], check=True)
    assert not (root / "site-packages" / "__pycache__").exists()
    assert stat.S_IMODE(os.stat(top).st_mode) == 0o664
    assert (root / "test" / "site-packages" / "__pycache__").is_dir()


# --- L3: a file with a mode fault is read too


def _pkg(base, n=3, mode=0o664):
    pkg = base / "venv" / "lib" / "python3.12" / "site-packages" / "phiward"
    files = []
    for i in range(n):
        f = write_file(pkg / f"m{i}.py", mode=mode, text=f"x = {i}\n")
        files.append((str(f), "sha256=" + selfcheck._sha256_b64(str(f))))
    return pkg, files


def test_a_changed_file_with_a_mode_fault_is_named_in_the_same_round(tree, home):
    pkg, files = _pkg(tree / "opt")
    with open(files[0][0], "a") as fh:
        fh.write("y = 2\n")
    _ok, problems = selfcheck.check(files, str(pkg))
    assert any(selfcheck.TREE_WHY in p for p in problems), problems
    assert "m0.py: changed since install" in problems, problems


def test_inside_home_a_changed_and_writable_file_gets_the_reinstall_step(home):
    pkg, files = _pkg(home)
    with open(files[0][0], "a") as fh:
        fh.write("y = 2\n")
    _ok, problems = selfcheck.check(files, str(pkg))
    assert "reinstall" in selfcheck.fix_text(problems, str(pkg)), problems


def test_a_fifo_in_the_package_is_named_and_never_waited_on(tree, home):
    pkg, files = _pkg(tree / "pkgs", mode=0o644)
    os.remove(files[1][0])
    os.mkfifo(files[1][0], 0o644)
    cache = pkg / "__pycache__"
    cache.mkdir()
    os.mkfifo(cache / "m2.cpython-312.pyc", 0o644)
    start = time.monotonic()
    _ok, problems = selfcheck.check(files, str(pkg))
    assert time.monotonic() - start < 5
    assert "m1.py: not a regular file" in problems, problems
    assert "m2.cpython-312.pyc: not a regular file" in problems, problems
