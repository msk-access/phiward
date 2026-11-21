"""Files that other tools run later: `launch` keeps them read-only for the tool and for a
wrapped MCP server, as a whole and at any depth; Mode A's macOS shell cannot write a nested
`.vscode` or `.idea`; the network limit holds exactly the configured hosts. Made-up trees only
(`FAKE-PT-0001`)."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import CONFINE_WHY, user_settings

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
LINUX = sys.platform.startswith("linux")
needs_confine = pytest.mark.skipif(CONFINE_WHY is not None, reason=f"no confinement: {CONFINE_WHY}")
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
linux = pytest.mark.skipif(not LINUX, reason="Linux")
ENTRY = ("--entry", "0123456789abcdef")

# the one list, written out here on purpose: a name dropped from the code fails this test
DIRS = (".claude", ".vscode", ".idea", ".cursor", ".gemini", ".codex")
FILES = (".mcp.json", ".gitmodules", ".ripgreprc", ".Rprofile", ".Renviron")
# on Linux, `launch` makes these at start when they are missing (and `.mcp.json` as a placeholder)
MADE_ON_LINUX = (".claude", ".vscode", ".idea", ".mcp.json")
READ_ONLY = ("EPERM", "EROFS", "EACCES")


def _launch(tree, code, extra=(), pre=""):
    """`phiward launch [extra] -- python -c code` in the repo; `pre`: Python run in the launcher
    before it starts (a smaller walk bound)."""
    env = dict(os.environ, PYTHONPATH=SRC)
    if pre:
        argv = [PY, "-c", pre + "\nimport sys\nfrom phiward.cli import main\n"
                "sys.exit(main(sys.argv[1:]))", "launch", *extra, "--", PY, "-c", code]
    else:
        argv = [PY, "-m", "phiward", "launch", *extra, "--", PY, "-c", code]
    r = subprocess.run(argv, cwd=str(tree / "repo"), capture_output=True, text=True, env=env,
                       timeout=120, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


def _tries(paths):
    """Write each path (its folders made first); print DONE or the errno's name."""
    return ("import errno, os\nfor p in %r:\n    try:\n        d = os.path.dirname(p)\n"
            "        os.makedirs(d, exist_ok=True)\n        open(p, 'w').write('x')\n"
            "        print('DONE', p)\n    except OSError as e:\n"
            "        print('REFUSED', errno.errorcode.get(e.errno, e.errno), p)\n" % (list(paths),))


def _refused(out, path):
    return any(f"REFUSED {code} {path}" in out for code in READ_ONLY)


def _target(repo, entry):
    return repo / entry / "x" if entry in DIRS else repo / entry


# --- 1. every entry, for the tool and the server, existing and missing -------------------------

@needs_confine
@pytest.mark.parametrize("state", ["existing", "missing"])
@pytest.mark.parametrize("who", ["tool", "server"])
@pytest.mark.parametrize("entry", DIRS + FILES)
def test_every_file_that_runs_later_is_read_only(tree, entry, who, state):
    repo = tree / "repo"
    if state == "existing":
        if entry in DIRS:
            (repo / entry).mkdir(exist_ok=True)
            (repo / entry / "old.json").write_text("{}\n")
        else:
            (repo / entry).write_text("# FAKE-PT-0001 made-up\n")
    target = _target(repo, entry)
    ok = repo / "src" / "ok.py"
    code, out = _launch(tree, _tries([str(target), str(ok)]), ENTRY if who == "server" else ())
    assert f"DONE {ok}" in out, out
    if LINUX and state == "missing" and entry not in MADE_ON_LINUX:
        # a stated limit on Linux: a missing one cannot be bound; it is reported after the session
        assert entry in out.split("the session changed", 1)[-1], out
        return
    assert _refused(out, target), out


@needs_confine
def test_launch_makes_claude_and_on_linux_the_editor_folders(tree):
    repo = tree / "repo"
    _launch(tree, "print('RAN')")
    assert (repo / ".claude").is_dir() and not (repo / ".claude").is_symlink()
    for d in (".vscode", ".idea"):
        assert (repo / d).is_dir() == LINUX, d


@needs_confine
def test_claude_folder_is_read_only_as_a_whole(tree):
    # replaces test_v2_r1b::test_10_claude_folder_exists_and_other_files_in_it_can_be_saved
    repo = tree / "repo"
    targets = [repo / ".claude" / "notes.md", repo / ".claude" / "skills" / "x" / "SKILL.md",
               repo / ".claude" / "agents" / "a.md", repo / ".claude" / "worktrees" / "w" / "f",
               repo / ".claude" / "scheduled_tasks.json"]
    _, out = _launch(tree, _tries([str(t) for t in targets]))
    for t in targets:
        assert _refused(out, t), (t, out)


# --- 2. links inside the folders -----------------------------------------------------------------

def _linked_skills(tree):
    repo = tree / "repo"
    (repo / "shared" / "skills" / "x").mkdir(parents=True)
    (repo / "shared" / "skills" / "x" / "SKILL.md").write_text("made-up\n")
    (repo / ".claude").mkdir(exist_ok=True)
    os.symlink("../shared/skills", repo / ".claude" / "skills")
    return repo


@needs_confine
@pytest.mark.parametrize("who", ["tool", "server"])
def test_a_link_target_inside_the_folder_is_read_only(tree, who):
    repo = _linked_skills(tree)
    targets = [repo / "shared" / "skills" / "x" / "SKILL.md",
               repo / ".claude" / "skills" / "x" / "SKILL.md",
               repo / "shared" / "skills" / "y" / "SKILL.md"]
    _, out = _launch(tree, _tries([str(t) for t in targets] + [str(repo / "src" / "ok.py")]),
                     ENTRY if who == "server" else ())
    assert f"DONE {repo / 'src' / 'ok.py'}" in out, out
    for t in targets:
        assert _refused(out, t), (t, out)


@needs_confine
def test_a_linked_file_in_an_editor_folder_is_read_only(tree):
    repo = tree / "repo"
    (repo / "conf").mkdir()
    (repo / "conf" / "extensions.json").write_text("{}\n")
    (repo / ".vscode").mkdir()
    os.symlink("../conf/extensions.json", repo / ".vscode" / "extensions.json")
    t = repo / "conf" / "extensions.json"
    _, out = _launch(tree, _tries([str(t)]))
    assert _refused(out, t), out


@needs_confine
def test_a_link_walk_past_its_bound_refuses_the_start(tree):
    repo = _linked_skills(tree)
    for i in range(30):
        (repo / "shared" / "skills" / f"s{i}").mkdir()
    code, out = _launch(tree, "print('RAN')",
                        pre="from phiward import claude_settings\nclaude_settings.TREE_WALK = 5")
    assert "RAN" not in out and code != 0, out
    assert "nothing runs" in out and str(repo / "shared" / "skills") in out, out


@needs_confine
def test_a_link_to_a_folder_that_holds_the_project_refuses_the_start(tree):
    repo = tree / "repo"
    (repo / ".vscode").mkdir()
    os.symlink("../..", repo / ".vscode" / "up")
    code, out = _launch(tree, "print('RAN')")
    assert "RAN" not in out and code != 0, out


# --- 3. nested folders ---------------------------------------------------------------------------

NESTED = ("sub/.claude/agents/x.md", "sub/.vscode/tasks.json", "sub/.idea/x.xml",
          "a/b/.mcp.json", "lib/.Rprofile")


@needs_confine
@pytest.mark.parametrize("who", ["tool", "server"])
def test_nested_ones_that_exist_at_start_are_read_only(tree, who):
    repo = tree / "repo"
    for rel in NESTED:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text("{}\n")
    targets = [repo / rel for rel in NESTED]
    _, out = _launch(tree, _tries([str(t) for t in targets]), ENTRY if who == "server" else ())
    for t in targets:
        assert _refused(out, t), (t, out)


@needs_confine
def test_nested_ones_made_in_the_session(tree):
    repo = tree / "repo"
    targets = [repo / "new" / rel for rel in NESTED]
    _, out = _launch(tree, _tries([str(t) for t in targets]))
    report = out.split("the session changed", 1)[-1]
    for t in targets:
        if LINUX:  # a stated limit there: reported after the session
            assert os.path.relpath(t, repo) in report, (t, out)
        else:
            assert _refused(out, t), (t, out)


# trees of installed code, which runs anyway: protecting a `.vscode` in them adds nothing
SKIPPED = ("node_modules/pkg/.vscode/settings.json",
           ".venv/lib/python3.12/site-packages/x/.idea/a.xml",
           "renv/library/R-4.4/x86_64/pkg/.Rprofile", "target/debug/.vscode/x.json")


@needs_confine
@pytest.mark.parametrize("who", ["tool", "server"])
def test_installed_trees_stay_writable_and_project_ones_do_not(tree, who):
    repo = tree / "repo"
    for rel in SKIPPED + ("sub/.vscode/tasks.json",):  # there at the start: a reinstall
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text("{}\n")
    targets = [repo / rel for rel in SKIPPED]
    real = repo / "sub" / ".vscode" / "tasks.json"
    _, out = _launch(tree, _tries([str(t) for t in targets] + [str(real)]),
                     ENTRY if who == "server" else ())
    for t in targets:
        assert f"DONE {t}" in out, (t, out)
    assert _refused(out, real), out


@needs_confine
@pytest.mark.slow
def test_big_claude_worktrees_do_not_stop_the_start(tree):
    nm = tree / "repo" / ".claude" / "worktrees" / "w" / "node_modules"
    for i in range(60):
        d = nm / f"p{i}"
        d.mkdir(parents=True)
        for j in range(1000):
            (d / f"f{j}.js").write_text("")
    code, out = _launch(tree, "print('RAN')")
    assert "RAN" in out, out


@needs_confine
def test_a_walk_that_stops_says_where(tree):
    repo = tree / "repo"
    for i in range(10):
        (repo / f"d{i}" / "e").mkdir(parents=True)
    code, out = _launch(tree, "print('RAN')",
                        pre="from phiward import wholetool\nwholetool.RUNS_LATER_WALK = 5")
    assert "RAN" in out, out
    start, report = out.split("RAN", 1)
    for part in (start, report):
        assert "stopped" in part and str(repo) in part, out


# --- 4. the wrapped server on Linux: the editor folders and files too -----------------------------

@needs_confine
def test_a_wrapped_server_cannot_write_idea_or_gitmodules(tree):
    repo = tree / "repo"
    (repo / ".idea").mkdir()
    (repo / ".idea" / "x.xml").write_text("<x/>\n")
    (repo / ".gitmodules").write_text("")
    (repo / ".ripgreprc").write_text("")
    targets = [repo / ".idea" / "x.xml", repo / ".gitmodules", repo / ".ripgreprc"]
    _, out = _launch(tree, _tries([str(t) for t in targets]), ENTRY)
    for t in targets:
        assert _refused(out, t), (t, out)


# --- 5. the exit report ------------------------------------------------------------------------

@pytest.mark.parametrize("rel", ["sub/.idea/x", "sub/.mcp.json", ".ripgreprc", ".cursor/hooks.json",
                                 ".gemini/settings.json", ".codex/config.toml", "a/.vscode/x.json",
                                 "sub/.claude/settings.json"])
def test_the_report_lists_them_as_settings(rel):
    from phiward import carryover
    assert carryover._rank(rel) == 2, rel


@pytest.mark.parametrize("rel", [".Rprofile", "lib/.Renviron", "sub/.gitmodules"])
def test_the_report_lists_the_list_s_other_files_as_files_that_run_later(rel):
    from phiward import carryover
    assert carryover._rank(rel) == 1, rel


@pytest.mark.parametrize("rel", [".tool-versions", ".envrc", ".devcontainer/devcontainer.json",
                                 ".husky/pre-commit", ".pre-commit-config.yaml",
                                 ".github/workflows/ci.yml", ".gitlab-ci.yml"])
def test_the_report_lists_report_only_entries(rel):
    from phiward import carryover
    assert carryover._rank(rel) <= 2, rel


# --- the one list ---------------------------------------------------------------------------------

def test_the_one_list_and_what_is_derived_from_it():
    from phiward import claude_settings as cs
    assert cs.RUNS_LATER_DIRS == DIRS and cs.RUNS_LATER_FILES == FILES
    assert set(cs.WORKSPACE_CODE_DIRS) == set(DIRS) - {".claude"}
    assert set(cs.WORKSPACE_CODE_FILES) == set(FILES) - {".mcp.json"}


def test_the_hook_asks_before_a_file_tool_writes_the_new_editor_folders(tree):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_v2_release18 import _write
    repo = tree / "repo"
    for p in (repo / ".cursor" / "hooks.json", repo / "sub" / ".gemini" / "settings.json",
              repo / ".codex" / "config.toml", repo / ".Rprofile"):
        assert _write(tree, p, "default")[0] == "ask", p
    assert _write(tree, repo / ".claude" / "worktrees" / "w" / "f.py", "default")[0] == "allow"


# --- Mode A: nested .vscode and .idea are left to the hook ---------------------------------------

NESTED_GLOBS = ("~/**/.vscode", "~/**/.vscode/**", "~/**/.idea", "~/**/.idea/**",
                "~/**/.claude/skills/**", "~/**/.claude/agents/**", "~/**/.claude/hooks/**",
                "~/**/.claude/commands/**", "~/**/.claude/settings.json",
                "~/**/.claude/settings.local.json")


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_mode_a_has_no_nested_globs(tree, monkeypatch, platform):
    # they would deny `npm install` and `git pull` in every project under the home folder
    from phiward import claude_settings, config, install
    cfg = config.load(str(tree / "repo"))
    cases = [install.wiring(cfg, version=(2, 0, 0))]
    monkeypatch.setattr(sys, "platform", platform)
    cases.append(install.wiring(cfg, version=claude_settings.VERSION_PATTERNS))
    for w in cases:
        deny = w["sandbox"]["filesystem"]["denyWrite"]
        assert not any(g in deny for g in NESTED_GLOBS), deny


def test_mode_a_docs_say_what_claude_code_denies_itself():
    root = Path(__file__).resolve().parents[1]
    src = (root / "src" / "phiward" / "claude_settings.py").read_text()
    tm = (root / "docs" / "threat-model.md").read_text()
    assert "Claude Code's sandbox denies them to the shell" not in src
    assert "the working folder's own `.vscode` and `.idea`" in tm, "threat model"
    assert "install` adds it" not in tm and "`.vscode` and `.idea` folder under your home" not in tm


# --- the network limit ----------------------------------------------------------------------------

def _add(text):
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + "\n" + text)


def test_an_empty_list_is_written_as_an_empty_list(tree):
    from phiward import config, install
    _add("[network]\nlimit = true\n")
    w = install.wiring(config.load(str(tree / "repo")))
    assert w["sandbox"]["network"] == {"strictAllowlist": True, "allowedDomains": []}


def test_merge_replaces_the_users_own_domains(tree):
    from phiward import config, install
    _add("[network]\nlimit = true\n")
    w = install.wiring(config.load(str(tree / "repo")))
    have = {"sandbox": {"network": {"strictAllowlist": False, "allowedDomains": ["mine.example"]}}}
    m = install.merge(have, w)
    assert m["sandbox"]["network"] == {"strictAllowlist": True, "allowedDomains": []}


def test_install_prints_each_host_it_removes(tree, capsys, monkeypatch):
    from phiward import install
    _add('[network]\nlimit = true\nallowed_domains = ["github.com"]\n')
    user_settings(tree, {"sandbox": {"network": {"allowedDomains": ["mine.example",
                                                                    "other.example",
                                                                    "github.com"]}}})
    from helpers import Tty
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.chdir(tree / "repo")
    assert install.main(["claude", "--user", "--write", "--yes"]) == 0
    out = capsys.readouterr()
    text = out.out + out.err
    data = json.loads((tree / "home" / ".claude" / "settings.json").read_text())
    assert data["sandbox"]["network"]["allowedDomains"] == ["github.com"], text
    for host in ("mine.example", "other.example"):
        assert f"removed {host}" in text, text
    assert "removed github.com" not in text


@pytest.mark.parametrize("level", ["user", "project", "managed"])
def test_doctor_warns_when_webfetch_rules_add_hosts(tree, monkeypatch, level):
    from phiward import claude_settings, config, doctor
    _add("[network]\nlimit = true\n")
    rule = {"permissions": {"allow": ["WebFetch(domain:fake.example)"]}}
    strict = {"sandbox": {"network": {"strictAllowlist": True, "allowedDomains": []}}}
    managed = tree / "managed" / "managed-settings.json"
    managed.parent.mkdir()
    monkeypatch.setattr(claude_settings, "MANAGED", [str(managed)])
    user_settings(tree, dict(strict, **(rule if level == "user" else {})))
    if level == "project":
        (tree / "repo" / ".claude").mkdir(exist_ok=True)
        (tree / "repo" / ".claude" / "settings.json").write_text(json.dumps(rule))
    if level == "managed":
        managed.write_text(json.dumps(rule))
    cfg = config.load(str(tree / "repo"))
    text = "\n".join(doctor.network_report(str(tree / "repo"), str(tree / "home"), cfg))
    assert "WARNING" in text and "fake.example" in text and f"{level} settings" in text, text


# --- R: renv works under launch, and .Rprofile stays read-only (Linux container) -----------------

def _renv_ready():
    if not shutil.which("Rscript"):
        return "no Rscript here (the operator's sandbox check covers renv instead)"
    r = subprocess.run(["Rscript", "-e", "quit(status = !requireNamespace('renv', quietly = TRUE))"],
                       capture_output=True, timeout=120)
    return None if r.returncode == 0 else "renv is not installed here"


@linux
@needs_confine
def test_renv_restore_and_r_run_under_launch(tree):
    why = _renv_ready()
    if why:
        pytest.skip(why)
    repo = tree / "repo"
    # a made-up package as the local source: no network
    pkg = tree / "pkgsrc" / "fakepkg"
    (pkg / "R").mkdir(parents=True)
    (pkg / "DESCRIPTION").write_text("Package: fakepkg\nVersion: 0.0.1\nTitle: Made Up\n"
                                     "Description: Made up.\nLicense: MIT\nAuthors@R: NULL\n"
                                     "Author: nobody\nMaintainer: nobody <n@example.invalid>\n")
    (pkg / "NAMESPACE").write_text("export(fake)\n")
    (pkg / "R" / "fake.R").write_text("fake <- function() 'FAKE-PT-0001'\n")
    subprocess.run(["R", "CMD", "build", "--no-build-vignettes", str(pkg)], cwd=str(tree / "pkgsrc"),
                   check=True, capture_output=True, timeout=300)
    local = repo / "renv" / "local"
    local.mkdir(parents=True)
    shutil.copy(tree / "pkgsrc" / "fakepkg_0.0.1.tar.gz", local)
    env = dict(os.environ, RENV_CONFIG_AUTOLOADER_ENABLED="TRUE",
               RENV_PATHS_ROOT=str(tree / "renv-root"), RENV_CONFIG_REPOS_OVERRIDE="file:///nonexistent")
    # renv::init() writes .Rprofile: run once outside launch, as the docs say
    r = subprocess.run(["Rscript", "-e", "renv::init(bare = TRUE, restart = FALSE)"], cwd=str(repo),
                       env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (repo / ".Rprofile").is_file()
    (repo / "renv.lock").write_text(json.dumps({
        "R": {"Version": "4.0.0", "Repositories": []},
        "Packages": {"fakepkg": {"Package": "fakepkg", "Version": "0.0.1", "Source": "Local",
                                 "RemoteType": "local", "RemoteUrl": str(local / "fakepkg_0.0.1.tar.gz")}}}))
    os.environ.update({k: env[k] for k in ("RENV_PATHS_ROOT", "RENV_CONFIG_REPOS_OVERRIDE")})
    code = ("import errno, subprocess, sys\n"
            "r = subprocess.run(['Rscript', '-e', 'renv::restore(prompt = FALSE)'])\n"
            "print('RESTORE', r.returncode)\n"
            "r = subprocess.run(['Rscript', '-e', 'x <- 1; cat(fakepkg::fake())'])\n"
            "print('RUN', r.returncode)\n"
            "try:\n    open('.Rprofile', 'a').write('x')\n    print('DONE')\n"
            "except OSError as e:\n    print('REFUSED', errno.errorcode.get(e.errno))\n")
    try:
        _, out = _launch(tree, code)
    finally:
        for k in ("RENV_PATHS_ROOT", "RENV_CONFIG_REPOS_OVERRIDE"):
            os.environ.pop(k, None)
    assert "RESTORE 0" in out and "RUN 0" in out, out
    assert "REFUSED EPERM" in out or "REFUSED EROFS" in out, out
