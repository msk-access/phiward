"""The fixes that make `launch` a usable beta. A fake agent runs under `phiward launch`."""

import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from helpers import CONFINE_WHY

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
pytestmark = pytest.mark.skipif(CONFINE_WHY is not None, reason=f"no confinement: {CONFINE_WHY}")
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")


def launch(tree, code, cwd="repo", extra=(), env_extra=None):
    env = dict(os.environ, PYTHONPATH=SRC)
    env.update(env_extra or {})
    r = subprocess.run([PY, "-m", "phiward", "launch", *extra, "--", PY, "-c", code],
                       cwd=str(cwd if isinstance(cwd, Path) else tree / cwd), capture_output=True,
                       text=True, env=env, timeout=120, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


def tries(path, mode="w"):
    return (f"try:\n    f = open({path!r}, {mode!r})\n    f.write('x') if 'r' not in {mode!r} else print(f.read())\n"
            f"    print('DONE')\nexcept OSError as e:\n    print('REFUSED', e.errno)\n")


# --- escapes --------------------------------------------------------------------------------------

@pytest.mark.parametrize("where", ["home", "home/.config", "/"])
def test_r1_launch_refuses_home_and_above_as_the_project(tree, where):
    cwd = Path("/") if where == "/" else tree / where
    cwd.mkdir(parents=True, exist_ok=True)
    code, out = launch(tree, "print('RAN')", cwd=cwd)
    assert code != 0 and "nothing runs" in out, out


@linux
def test_r2_a_linked_tool_tmp_does_not_widen_the_next_session(tree):
    folder = tree / "home" / ".phiward" / "tools" / "generic"
    launch(tree, "print('first')")
    tmp = folder / "tmp"
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)  # each run has its own tmp; this one is unused
    os.symlink(tree / "home", tmp)  # planted by a session
    code, out = launch(tree, tries("/tmp/.bashrc"))
    assert not (tree / "home" / ".bashrc").exists(), out


@linux
def test_r8_the_session_check_never_follows_links(tree):
    g = tree / "repo" / ".git"
    g.mkdir()
    (g / "config").write_text("[core]\n")
    os.symlink("/", g / "worktrees")  # planted
    code, out = launch(tree, "print('RAN')")
    assert len(out) < 4000 and "FAKE-PT" not in out, out[:500]


# --- over-blocking --------------------------------------------------------------------------------

@macos
def test_r9_names_resolve(tree):
    _, out = launch(tree, "import socket\ntry:\n    socket.getaddrinfo('localhost', 80)\n    print('RESOLVED')\n"
                          "except OSError as e:\n    print('FAILED', e)\n")
    assert "RESOLVED" in out, out
    # a name only the resolver knows: when this machine resolves it, the session must too
    # (without a network the host fails as well, and there is nothing to compare)
    import socket
    try:
        socket.getaddrinfo("apple.com", 443)
    except OSError:
        return
    _, out = launch(tree, "import socket\ntry:\n    socket.getaddrinfo('apple.com', 443)\n    print('RESOLVED')\n"
                          "except OSError as e:\n    print('FAILED', e)\n")
    assert "RESOLVED" in out, out


@macos
@pytest.mark.xfail(reason="new ptys need the pty relay (D4); only the session's own ttys are "
                          "open", strict=True)
def test_r10_new_ptys_work(tree):
    _, out = launch(tree, "import pty, os\nm, s = pty.openpty()\nos.write(m, b'x')\nprint('PTY OK')\n")
    assert "PTY OK" in out, out


def test_r11_git_init_in_a_subfolder_works(tree):
    sub = tree / "repo" / "newrepo"
    sub.mkdir()
    code = f"import subprocess\nr = subprocess.run(['git', 'init', '-q', {str(sub)!r}], capture_output=True, text=True)\nprint('RC', r.returncode, r.stderr)\n"
    _, out = launch(tree, code)
    assert "RC 0" in out, out


# --- files that run later, as far as they are covered ---------------------------------------------

def test_r3_a_submodule_git_file_and_its_gitdir_are_read_only(tree):
    g = tree / "repo" / ".git"
    (g / "modules" / "sm").mkdir(parents=True)
    (g / "config").write_text("[core]\n")
    (g / "modules" / "sm" / "config").write_text("[core]\n")
    (tree / "repo" / "sm").mkdir()
    (tree / "repo" / "sm" / ".git").write_text("gitdir: ../.git/modules/sm\n")
    _, out = launch(tree, tries(str(tree / "repo" / "sm" / ".git")))
    assert "REFUSED" in out, out


def test_r3_an_existing_nested_repo_is_covered(tree):
    n = tree / "repo" / "vendor" / "lib" / ".git"
    (n / "hooks").mkdir(parents=True)
    (n / "config").write_text("[core]\n")
    _, out = launch(tree, tries(str(n / "config")))
    assert "REFUSED" in out, out


@macos
def test_r5_xcrun_cache_is_not_writable_and_not_used(tree):
    t = subprocess.run(["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"], capture_output=True, text=True).stdout.strip()
    _, out = launch(tree, tries(os.path.join(t, "xcrun_db")) + "import os; print('NOCACHE', os.environ.get('xcrun_nocache'))\n")
    assert "REFUSED" in out and "NOCACHE 1" in out, out


# --- credentials ----------------------------------------------------------------------------------

@pytest.mark.parametrize("var", ["AWS_SECRET_ACCESS_KEY", "GH_TOKEN", "GITHUB_TOKEN", "HF_TOKEN",
                                 "VAULT_TOKEN", "MY_SERVICE_API_KEY", "DB_PASSWORD"])
def test_r13_token_variables_are_removed(tree, var):
    _, out = launch(tree, f"import os; print('HAS', {var!r} in os.environ)", env_extra={var: "FAKE"})
    assert "HAS False" in out, out


def test_r13_the_tools_own_api_key_is_kept(tree):
    _, out = launch(tree, "import os; print('HAS', 'ANTHROPIC_API_KEY' in os.environ)",
                    env_extra={"ANTHROPIC_API_KEY": "FAKE"})
    assert "HAS True" in out, out


@pytest.mark.parametrize("rel", [".claude.json", ".claude/settings.json", ".vault-token", ".s3cfg",
                                 ".boto", ".config/op/config", ".terraform.d/credentials.tfrc.json"])
def test_r13_more_credential_files_are_denied(tree, rel):
    f = tree / "home" / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("FAKE-CREDENTIAL\n")
    _, out = launch(tree, tries(str(f), "r"))
    assert "FAKE-CREDENTIAL" not in out, out


@linux
def test_r7_a_socket_with_a_space_in_its_path_is_covered(tree):
    path = str(tree / "home" / "my sock")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)

    def serve():
        try:
            srv.accept()[0].sendall(b"PEER")
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()
    code = (f"import socket\ns=socket.socket(socket.AF_UNIX)\ntry:\n    s.connect({path!r})\n"
            "    print('GOT', s.recv(4))\nexcept OSError as e:\n    print('REFUSED', e.errno)\n")
    try:
        _, out = launch(tree, code)
    finally:
        srv.close()
    assert "GOT" not in out, out
