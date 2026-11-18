"""Shared fixtures: a made-up folder tree with obviously fake identifiers, and a config that
protects part of it. Nothing here reads the operator's own config or data."""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
# On macOS pytest's default temp root is the per-user temp folder, which `launch` lets the tool
# write; the made-up trees go under /private/tmp instead, so write tests see the real rule
if sys.platform == "darwin" and "PYTEST_DEBUG_TEMPROOT" not in os.environ:
    os.makedirs("/private/tmp/phiward-tests", exist_ok=True)
    os.environ["PYTEST_DEBUG_TEMPROOT"] = "/private/tmp/phiward-tests"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
# The made-up launcher folders (`tree/bin`) must be PATH folders phiward trusts as the
# launcher's: ones no other account can write (`service._safe_path_entries`). Under a umask of
# 002 (Debian's default for a user with a private group) a new folder is group-writable.
os.umask(0o022)
# the confinement self-test runs once, here, with the operator's own HOME and PATH (not inside
# a test that made them up)
import helpers  # noqa: E402,F401


# --- skips that hide tests ---------------------------------------------------------------------
# A test that starts to skip loses its coverage without a failure. With PHIWARD_CHECK_SKIPS=1
# (CI), a skip that is not in tests/expected_skips_<platform>.txt fails the run;
# PHIWARD_WRITE_SKIPS=FILE writes this run's skips there, to make or update a list.
_SKIPPED: list = []


def pytest_runtest_logreport(report):
    if report.skipped and not hasattr(report, "wasxfail"):
        _SKIPPED.append(report.nodeid)


def pytest_collectreport(report):
    if report.skipped:  # a whole module skipped while collected (importorskip at the top)
        _SKIPPED.append(report.nodeid)


def _expected_skips() -> list:
    f = Path(__file__).with_name(f"expected_skips_{sys.platform}.txt")
    if not f.exists():
        return []
    return [ln.strip() for ln in f.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get("PHIWARD_WRITE_SKIPS")
    if out:
        Path(out).write_text("".join(n + "\n" for n in sorted(set(_SKIPPED))))
    if os.environ.get("PHIWARD_CHECK_SKIPS") != "1":
        return
    from fnmatch import fnmatchcase
    want = _expected_skips()
    exact = set(want)
    # a line is a test id as written (ids hold `[...]`, which fnmatch would read as a class);
    # only a line with `*` is a pattern
    wild = [w.replace("[", "[[]") for w in want if "*" in w]
    new = sorted({n for n in _SKIPPED
                  if n not in exact and not any(fnmatchcase(n, w) for w in wild)})
    if new:
        print(f"\n{len(new)} test(s) skipped that tests/expected_skips_{sys.platform}.txt does "
              "not expect (a skip hides a test):", file=sys.stderr)
        for n in new:
            print(f"  {n}", file=sys.stderr)
        session.exitstatus = 1
    # a listed test that ran: only for exact lines, in a run of the whole suite
    whole_run = not session.config.option.keyword and not session.config.option.markexpr and \
        [os.path.basename(a.rstrip("/")) for a in session.config.args] in ([], ["tests"])
    stale = sorted(set(w for w in want if "*" not in w) - set(_SKIPPED))
    if stale and whole_run:
        print(f"\nNOTE: {len(stale)} test(s) in tests/expected_skips_{sys.platform}.txt ran "
              "this time; remove them from the list if they now always run.", file=sys.stderr)


@pytest.fixture(autouse=True)
def _no_real_claude(monkeypatch):
    """Tests never run the real `claude` (not even `claude --version`): the version is unknown
    unless a test sets one."""
    from phiward import claude_settings
    monkeypatch.setattr(claude_settings, "claude_version", lambda: None)
    # nor a real login service: `service.load` runs nothing, also in child processes
    monkeypatch.setenv("PHIWARD_SERVICE_RUNNER", "none")


@pytest.fixture()
def tree(tmp_path, monkeypatch):
    """A fake tree:

    T/phi/                      protected root (FAKE-PT-0001.bam, sub/FAKE-PT-0002.bam)
    T/runs/run1/panel/          protected by the pattern T/runs/*/panel (x.maf)
    T/runs/run1/public/         not protected (ok.txt)
    T/runs/run2/panel/, public/ the same shape
    T/repo/                     the agent's working folder (README.md, src/app.py)
    T/links/to_arm -> T/runs/run1/panel
    T/repo/runlink -> T/runs/run1/public   (runlink/../panel is protected)
    T/repo/leak.txt -> T/phi/FAKE-PT-0001.bam
    T/pub/                      an open folder (a place protected data must not reach)
    T/home/                     $HOME for the test

    Every protected file holds SECRET-CONTENT-<n>, so a test can look for it in any output.
    """
    t = tmp_path.resolve()
    (t / "phi" / "sub").mkdir(parents=True)
    (t / "phi" / "FAKE-PT-0001.bam").write_text("SECRET-CONTENT-0001\n")
    (t / "phi" / "sub" / "FAKE-PT-0002.bam").write_text("SECRET-CONTENT-0002\n")
    for run in ("run1", "run2"):
        (t / "runs" / run / "panel").mkdir(parents=True)
        (t / "runs" / run / "public").mkdir(parents=True)
        (t / "runs" / run / "panel" / "FAKE-PT-0003.maf").write_text("SECRET-CONTENT-0003\n")
        (t / "runs" / run / "panel" / "x.maf").write_text("SECRET-CONTENT-0004\n")
        (t / "runs" / run / "public" / "ok.txt").write_text("ok\n")
    (t / "repo" / "src").mkdir(parents=True)
    (t / "repo" / "README.md").write_text("readme\n")
    (t / "repo" / "src" / "app.py").write_text("print('hi')\n")
    (t / "links").mkdir()
    os.symlink(t / "runs" / "run1" / "panel", t / "links" / "to_arm")
    # links inside the open repo: one to an open folder next to a protected arm, one to a file
    os.symlink(t / "runs" / "run1" / "public", t / "repo" / "runlink")
    os.symlink(t / "phi" / "FAKE-PT-0001.bam", t / "repo" / "leak.txt")
    (t / "pub").mkdir()
    home = t / "home"
    home.mkdir()
    cfg = home / "phiward.toml"
    # `[shell] best_effort`: most tests check the hook's text check, which it keeps (by default
    # every unconfined shell call is refused: test_v2_round16.py). It comes first, so a test
    # that appends a key adds it to [protected_paths]
    cfg.write_text(
        "[shell]\nbest_effort = true\n"
        "[protected_paths]\n"
        f'roots = ["{t}/phi"]\n'
        f'patterns = ["{t}/runs/*/panel"]\n'
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PHIWARD_CONFIG", str(cfg))
    monkeypatch.setenv("PHIWARD_DEV", "1")  # tests run from the source checkout
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    yield t
    if sys.platform.startswith("linux"):
        # on Linux `launch` binds every entry next to a protected root into the session's view
        # (bwrap takes at most 9000 arguments): the trees of earlier tests must not pile up
        # beside this one in pytest's temp folder
        # any depth (a test's session may leave a deep quarantine; shutil.rmtree recursed before
        # Python 3.12): phiward's own remover
        # after the test's own replacements are undone (a test may replace os.lstat)
        monkeypatch.undo()
        from phiward import safeio
        safeio.remove_tree(str(t))


@pytest.fixture(autouse=True)
def _temp_is_the_machine(monkeypatch):
    """The made-up trees lie under the temp folder, which Claude Code lets the agent write
    (claude_settings.agent_writable): in tests it stands for the rest of the machine. A test of
    that rule sets `claude_settings._temp_roots` itself."""
    from phiward import claude_settings
    monkeypatch.setattr(claude_settings, "_temp_roots", lambda: [])


@pytest.fixture
def home(tree, monkeypatch):
    """The tree's home folder (mode 0755) as the home folder the self-check sees
    (`selfcheck._home`). A file with its own `home` fixture uses that one."""
    from phiward import selfcheck
    h = tree / "home"
    os.chmod(h, 0o755)
    monkeypatch.setattr(selfcheck, "_home", lambda: str(h))
    return h


@pytest.fixture()
def launchers(tree, monkeypatch):
    """Stand-in `phiward launch` processes for wrapped MCP servers, as Claude Code runs them:
    `start(argv_hash, plugin=ROOT)` starts a live child of this test process (a `sleep`) and
    writes its launcher record (of a plugin's server when ROOT, its CLAUDE_PLUGIN_ROOT, is given); `start_config()` does so for every wrapped entry of the config files. The
    hook's Claude Code is this process (its ancestors are made to start here). Each child is
    ended at the end of the test (only the processes this fixture started)."""
    import subprocess
    from phiward import mcp_config, procinfo
    real = procinfo.ancestors
    monkeypatch.setattr(procinfo, "ancestors",
                        lambda pid=None, depth=4: ([os.getpid()] + real(os.getpid(), depth - 1))
                        if pid is None else real(pid, depth))
    procs = []

    class Launchers:
        def start(self, h, ppid=None, mode=0o600, plugin="", view=None):
            p = subprocess.Popen(["sleep", "300"])
            procs.append(p)
            got = procinfo.info(p.pid)
            assert got is not None
            folder = mcp_config.launched_dir()
            os.makedirs(folder, mode=0o700, exist_ok=True)
            os.chmod(folder, 0o700)
            path = os.path.join(folder, f"{p.pid}.json")
            with open(path, "w") as fh:
                json.dump({"pid": p.pid, "ppid": got[0] if ppid is None else ppid,
                           "start": got[1], "argv": h,
                           "plugin": mcp_config.plugin_hash(plugin),
                           # the profile the hook would build here, unless a test gives another
                           "view": mcp_config.view_hash(dict(os.environ), os.environ.get(
                               "CLAUDE_PROJECT_DIR") or str(tree / "repo"))
                           if view is None else view}, fh)
            os.chmod(path, mode)
            return p

        def start_config(self):
            project = os.environ.get("CLAUDE_PROJECT_DIR") or str(tree / "repo")
            for h in _launch_hashes(project, str(tree / "home")):
                self.start(h)

    yield Launchers()
    for p in procs:
        p.kill()
        p.wait()


@pytest.fixture()
def broker(tree, monkeypatch):
    """A running `phiward broker` with a short private spool (no terminal: grants are
    refused). Yields a function that restarts it with extra arguments and a stdin."""
    import subprocess
    import tempfile
    import time

    spool = tempfile.mkdtemp(prefix="ags-", dir="/tmp")
    os.rmdir(spool)  # the broker makes it, mode 0700
    monkeypatch.setenv("PHIWARD_SPOOL", spool)
    monkeypatch.setenv("PHIWARD_BROKER_WAIT", "3")
    # never a real dialog on the operator's screen; a test that wants one names its own program
    monkeypatch.setenv("PHIWARD_DIALOG", "/nonexistent/phiward-test-dialog")
    procs = []

    def start(args=(), stdin=subprocess.DEVNULL):
        for p in procs:
            p.terminate()
            p.wait(timeout=10)
        procs.clear()
        env = dict(os.environ, PYTHONPATH=str(SRC))
        p = subprocess.Popen([sys.executable, "-m", "phiward", "broker"] + list(args),
                             cwd=str(tree / "home"), stdin=stdin, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, env=env)
        procs.append(p)
        alive = os.path.join(spool, "broker.alive")
        for _ in range(100):
            if os.path.exists(alive) or p.poll() is not None:
                break
            time.sleep(0.05)
        assert p.poll() is None, p.stdout.read().decode() if p.stdout else ""
        return p

    start.spool = spool  # type: ignore[attr-defined]
    start()
    yield start
    for p in procs:
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
    shutil.rmtree(spool, ignore_errors=True)


def default_place_env(tree):
    """An environment that uses the default config place (no PHIWARD_CONFIG, no PHIWARD_SPOOL),
    as a real user's does: commands that an agent may run refuse those overrides without a
    terminal. The tree's config is copied to ~/.config/phiward/config.toml."""
    home = tree / "home"
    dest = home / ".config" / "phiward"
    dest.mkdir(parents=True, exist_ok=True)
    src = os.environ.get("PHIWARD_CONFIG")
    if src and os.path.isfile(src):
        shutil.copy(src, dest / "config.toml")
    env = {k: v for k, v in os.environ.items()
           if k not in ("PHIWARD_CONFIG", "PHIWARD_SPOOL", "XDG_CONFIG_HOME", "XDG_CACHE_HOME")}
    env["HOME"] = str(home)
    return env


def _launch_hashes(project, home):
    """The launch hash of each wrapped entry of the config scopes, filled in: what Claude Code
    starts a launcher with for each."""
    from phiward import mcp_config
    env = mcp_config._fill_env(project)
    return [h for h in (mcp_config._hash_of(e.spec, env)
                        for e in mcp_config.entries(project, home) if e.state == "wrapped") if h]
