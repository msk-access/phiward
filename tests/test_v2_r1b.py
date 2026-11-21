"""More fixes to `launch`. A fake agent runs under `phiward launch`."""

import os
import pty
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import CONFINE_WHY

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
pytestmark = pytest.mark.skipif(CONFINE_WHY is not None, reason=f"no confinement: {CONFINE_WHY}")
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")


def launch(tree, code, cwd=None, extra=(), env_extra=None):
    env = dict(os.environ, PYTHONPATH=SRC)
    env.update(env_extra or {})
    r = subprocess.run([PY, "-m", "phiward", "launch", *extra, "--", PY, "-c", code],
                       cwd=str(cwd or tree / "repo"), capture_output=True, text=True, env=env,
                       timeout=120, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


def reads(path):
    return (f"try:\n    print('CONTENT', open({path!r}).read())\nexcept OSError as e:\n"
            f"    print('REFUSED', e.errno)\n")


# --- 1, 2: Linux binds never follow planted links; masks last ---------------------------------

@linux
@pytest.mark.parametrize("target", ["kube", "root"])
def test_1_a_planted_gitdir_link_does_not_mount_outside_files(tree, target):
    home = tree / "home"
    (home / ".kube").mkdir()
    (home / ".kube" / "config").write_text("KUBE-SECRET-TOKEN\n")
    (tree / "phi" / "config").write_text("SECRET-PHI\n")
    sub = tree / "repo" / "sub"
    sub.mkdir()
    dest = (home / ".kube") if target == "kube" else (tree / "phi")
    os.symlink(os.path.relpath(dest, tree / "repo"), tree / "repo" / "k")
    (sub / ".git").write_text("gitdir: ../k\n")  # planted by an earlier session
    _, out = launch(tree, reads(str(tree / "repo" / "k" / "config")))
    assert "KUBE-SECRET" not in out and "SECRET-PHI" not in out, out


@linux
def test_2_masks_are_applied_after_git_binds(tree):
    g = tree / "repo" / ".git"
    (g / "worktrees" / "phi").mkdir(parents=True)
    (g / "config").write_text("[core]\n")
    (g / "worktrees" / "phi" / "index").write_text("FAKE-PT-0007.txt\n")
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text().replace('roots = ["', f'roots = ["{g}/worktrees/phi", "'))
    _, out = launch(tree, reads(str(g / "worktrees" / "phi" / "index")))
    assert "FAKE-PT-0007" not in out, out


@linux
def test_3_the_session_check_never_reads_through_a_planted_link(tree):
    g = tree / "repo" / ".git"
    g.mkdir()
    (g / "config").write_text("[core]\n")
    sub = tree / "repo" / "s"
    sub.mkdir()
    os.symlink(os.path.relpath(tree / "phi", sub), sub / "q")
    (sub / ".git").write_text("gitdir: q\n")
    _, out = launch(tree, "print('RAN')")
    assert "FAKE-PT" not in out, out


# --- 4: macOS terminals -----------------------------------------------------------------------

@macos
def test_4_another_terminal_cannot_be_read(tree):
    master, slave = pty.openpty()
    name = os.ttyname(slave)
    try:
        _, out = launch(tree, f"import os\ntry:\n    fd = os.open({name!r}, os.O_RDONLY | os.O_NONBLOCK)\n"
                              "    print('OPENED')\nexcept OSError as e:\n    print('REFUSED', e.errno)\n")
    finally:
        os.close(master)
        os.close(slave)
    assert "REFUSED" in out, out


# --- 5: more folders that cannot be the project -------------------------------------------------

@macos
def test_5_library_cannot_be_the_project(tree):
    lib = tree / "home" / "Library"
    lib.mkdir()
    code, out = launch(tree, "print('RAN')", cwd=lib)
    assert code != 0 and "nothing runs" in out, out


def test_5_a_folder_on_path_cannot_be_the_project(tree):
    b = tree / "pub" / "bin"
    b.mkdir(parents=True)
    code, out = launch(tree, "print('RAN')", cwd=tree / "pub",
                       env_extra={"PATH": f"{b}:{os.environ['PATH']}"})
    assert code != 0 and "nothing runs" in out, out


# --- 6: names printed to the operator's terminal are escaped ------------------------------------

@linux
def test_6_printed_names_are_escaped(tree):
    g = tree / "repo" / ".git"
    (g / "worktrees").mkdir(parents=True)
    (g / "config").write_text("[core]\n")
    code = f"open({str(g / 'worktrees' / 'x')!r} + '\\x1b]0;evil\\x07', 'w').write('x')"
    _, out = launch(tree, code)
    assert "\x1b" not in out, repr(out)


# --- 7: environment by allow-list ---------------------------------------------------------------

@pytest.mark.parametrize("var", ["GITHUB_PAT", "OP_SESSION_abc", "BW_SESSION", "DATABASE_URL",
                                 "SENTRY_DSN", "SLACK_WEBHOOK_URL", "MYSQL_PWD", "CI_JOB_JWT",
                                 "KUBECONFIG", "SOME_RANDOM_THING"])
def test_7_only_listed_variables_reach_the_tool(tree, var):
    _, out = launch(tree, f"import os; print('HAS', {var!r} in os.environ)", env_extra={var: "FAKE"})
    assert "HAS False" in out, out


# the proxy variables are launch's own now (test_v2_launch_network.py, test_4_*)
@pytest.mark.parametrize("var", ["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS",
                                 "LANG", "TERM", "EDITOR", "ANTHROPIC_API_KEY", "CLAUDE_CODE_USE_BEDROCK"])
def test_7_ordinary_and_the_tools_own_variables_pass(tree, var):
    _, out = launch(tree, f"import os; print('HAS', {var!r} in os.environ)", env_extra={var: "x"})
    assert "HAS True" in out, out


def test_7_the_operator_can_pass_more_variables(tree):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + '[launch]\npass_env = ["AWS_PROFILE"]\n')
    _, out = launch(tree, "import os; print('HAS', 'AWS_PROFILE' in os.environ)",
                    env_extra={"AWS_PROFILE": "bedrock"})
    assert "HAS True" in out, out


# --- 8, 9, 10: over-blocking --------------------------------------------------------------------

@macos
def test_8_compiling_works_and_the_operators_python_stays_first(tree):
    src = tree / "repo" / "a.c"
    src.write_text("int main(void){return 0;}\n")
    code = (f"import subprocess, shutil\nr = subprocess.run(['cc', {str(src)!r}, '-o', {str(tree / 'repo' / 'a.out')!r}],"
            " capture_output=True, text=True)\nprint('CC', r.returncode, r.stderr[-200:])\n"
            "print('PY', shutil.which('python3'))\n")
    outside = subprocess.run(["/usr/bin/which", "python3"], capture_output=True, text=True).stdout.strip()
    _, out = launch(tree, code)
    assert "CC 0" in out, out
    assert f"PY {outside}" in out, out


def test_9_tmux_gets_its_own_folder(tree):
    _, out = launch(tree, "import os; print('TMUX', os.environ.get('TMUX_TMPDIR', ''))")
    assert "/.phiward/tools/" in out, out


def test_10_claude_folder_exists_and_is_read_only_as_a_whole(tree):
    # .claude is made at start, and nothing in it can be saved: a list of names in it misses the
    # next place Claude Code runs code from (test_v2_runs_later.py)
    code = (f"import os\nprint('EXISTS', os.path.isdir({str(tree / 'repo' / '.claude')!r}))\n"
            f"try:\n    open({str(tree / 'repo' / '.claude' / 'notes.md')!r}, 'w').write('x')\n"
            "    print('SAVED')\nexcept OSError:\n    print('REFUSED')\n")
    _, out = launch(tree, code)
    assert "EXISTS True" in out and "REFUSED" in out and "SAVED" not in out, out


def test_10_claude_shared_settings_stay_read_only(tree):
    (tree / "repo" / ".claude").mkdir()
    (tree / "repo" / ".claude" / "settings.json").write_text("{}\n")
    _, out = launch(tree, f"open({str(tree / 'repo' / '.claude' / 'settings.json')!r}, 'w').write('x')")
    assert "Errno" in out or "Permission" in out or "Read-only" in out, out
