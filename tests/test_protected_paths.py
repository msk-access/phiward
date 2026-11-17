"""The protected-paths guard on the narrow rule.

A command that touches a protected path (inside one, or above one) is allowed in two forms only:
`<one simple command> 2>&1 | phiward sanitize [opts]`, and `phiward copy SRC... DST`.
File tools on, or above, a protected path are refused. The first cases are seven path-guard holes
found in an external code review; they were written before the guard and failed first.
"""

import pytest

from phiward import config
from phiward.core import ALLOW, ASK, DENY, FILE_READ, FILE_SEARCH, FILE_WRITE, OTHER, SHELL, Action
from phiward.guards import protected_paths


def decide(t, command, cwd="repo", can_ask=True):
    cwd = str(t / cwd) if not str(cwd).startswith("/") else cwd
    cfg = config.load(cwd)
    return protected_paths.check(Action(SHELL, cwd, command=command, can_ask=can_ask), cfg)


def verdict(t, command, cwd="repo"):
    return decide(t, command, cwd).verdict


# --- The seven holes found in an external code review ---------------------------------------------

def test_hole_1_copy_errors_print_patient_names(tree):
    # cp prints the missing source's path on stderr; rsync | tail forwards error lines
    assert verdict(tree, f"cp {tree}/phi/missing.bam {tree}/phi/out.bam") == DENY
    assert verdict(tree, f"rsync -a {tree}/phi/ {tree}/phi/copy/ 2>&1 | tail -3") == DENY


def test_hole_2_quiet_commands_print_protected_paths(tree):
    assert verdict(tree, f"cd {tree}/phi && pwd") == DENY
    assert verdict(tree, f"cd {tree}/phi/missing") == DENY


def test_hole_3_extra_grep_patterns_hide_a_recursive_search(tree):
    # run from a folder that holds a protected arm: -e SNP is a pattern, not a path
    assert verdict(tree, "grep -r -e ALT -e SNP", cwd="runs/run1") == DENY
    assert verdict(tree, "grep -r -e ALT -e SNP .", cwd="runs") == DENY


def test_hole_4_find_exec_passes_a_depth_limit(tree):
    assert verdict(tree, f"find {tree}/runs/run1 -maxdepth 1 -exec ls {{}} +") == DENY


def test_hole_5_brace_destination_escapes_protected_folders(tree):
    cmd = f"cp -R {tree}/phi/FAKE-PT-0001.bam {tree}/runs/run2/{{panel,public}}/"
    assert verdict(tree, cmd) == DENY


def test_hole_6_wildcard_through_a_link_reaches_a_protected_arm(tree):
    assert verdict(tree, f"cat {tree}/links/*/x.maf") == DENY
    assert verdict(tree, f"cat {tree}/links/to_arm/x.maf") == DENY


def test_hole_7_redirect_errors_print_protected_paths(tree):
    assert verdict(tree, f"cat {tree}/phi/x > {tree}/phi/missing/out.txt 2>&1") == DENY
    cmd = f"phiward run -- python3 s.py {tree}/phi/x > {tree}/phi/missing/o 2>&1"
    assert verdict(tree, cmd) == DENY


# --- More ways to touch a protected path -----------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "cat {t}/phi/FAKE-PT-0001.bam",
    "ls {t}/phi",
    "ls {t}",                       # above a root
    "ls -R {t}/runs",               # above a pattern match
    "head ~/../phi/FAKE-PT-0001.bam",
    "cat $HOME/../phi/FAKE-PT-0001.bam",
    "cat ${{HOME}}/../phi/FAKE-PT-0001.bam",
    "cat {t}/ph{{i,x}}/FAKE-PT-0001.bam",
    "cat {t}/p?i/*.bam",
    "cat '{t}/phi/FAKE-PT-0001.bam'",
    'cat "{t}/phi"/FAKE-PT-0001.bam',
    "cat {t}/ph''i/FAKE-PT-0001.bam",
    "wc -l --files0-from={t}/phi/list",
    "python3 -c 'open(\"{t}/phi/FAKE-PT-0001.bam\")'",
    "cat <<EOF\n{t}/phi/FAKE-PT-0001.bam\nEOF",
    "X={t}/phi; ls $X",
    "echo ok; cat {t}/phi/FAKE-PT-0001.bam",
    "cat ../phi/FAKE-PT-0001.bam",
    "cd .. && cat phi/FAKE-PT-0001.bam",
    "cat $(ls {t}/phi)",
    "cat `ls {t}/phi`",
    "diff <(ls {t}/phi) /dev/null",
    "find / -name '*.bam'",
    "du -a ~/..",
    "cat {t}/runs/run9/panel/x.maf",    # a pattern match that does not exist yet
    # first review, cases for the text layer
    "ls runlink/../panel",              # a link, then ..: the kernel's reading, not the lexical one
    "cat leak.txt",                     # a link in an open folder to a protected file
    "tar -C../phi -cf - .",             # a glued option value
    "make -C{t}/phi",
    "cat ~+/../phi/FAKE-PT-0001.bam",   # ~+ is the working folder
])
def test_touching_commands_are_refused(tree, cmd):
    assert verdict(tree, cmd.format(t=tree)) == DENY


def test_a_working_folder_inside_a_root_touches_every_command(tree):
    assert verdict(tree, "ls", cwd="phi") == DENY
    assert verdict(tree, "git status", cwd="phi/sub") == DENY


# --- The gateway: the only way to touch protected data ------------------------------------

@pytest.mark.parametrize("cmd", [
    "phiward run -- python3 -I probe.py {t}/phi/FAKE-PT-0001.bam",
    "phiward run --table --names-from {t}/repo/runs.tsv -- samtools view {t}/phi/x.bam",
    "phiward run -- ls {t}/phi",
    "phiward run -- sh -c 'ls {t}/ph{{i,x}}/*.bam'",  # the gateway expands, inside its profile
    "phiward run -- cat ~/../phi/FAKE-PT-0001.bam",
    "phiward run -- ls {t}/phi\n",                  # a trailing newline only
    "phiward copy {t}/phi/FAKE-PT-0001.bam {t}/runs/run1/panel/",
    "phiward copy {t}/repo/README.md {t}/phi/",
])
def test_gateway_calls_are_allowed(tree, cmd):
    assert verdict(tree, cmd.format(t=tree)) == ALLOW


@pytest.mark.parametrize("cmd", [
    "phiward run --write-to {t}/pub -- python3 p.py {t}/phi",
    "phiward run --net -- python3 p.py {t}/phi",
    "phiward run --write-to {t}/pub --net -- python3 p.py",
])
def test_gateway_grants_are_left_to_the_broker(tree, cmd):
    # the hook does not ask: the broker asks the operator on its own terminal
    assert verdict(tree, cmd.format(t=tree)) == ALLOW


@pytest.mark.parametrize("cmd", [
    # the old sanitized-pipe form: it controlled output, not writes
    "python3 -I probe.py {t}/phi/FAKE-PT-0001.bam 2>&1 | phiward sanitize",
    "cp -R {t}/phi {t}/pub/copy 2>&1 | phiward sanitize",
    "ls {t}/phi 2>&1 | phiward sanitize",
    # a gateway call that is not the whole command
    "phiward run -- ls {t}/phi; cat {t}/phi/FAKE-PT-0001.bam",
    "phiward run -- ls {t}/phi && ls {t}/phi",
    "phiward run -- ls {t}/phi | head",
    "phiward run -- ls {t}/phi > out.txt",
    "phiward run -- ls $(cat {t}/phi/list)",
    "FOO=1 phiward run -- ls {t}/phi",
    "cd {t}/phi && phiward run -- ls",
    # a gateway call not in the documented form
    "phiward run -- true\ncat {t}/phi/FAKE-PT-0001.bam",  # a newline starts a 2nd command
    "python3 -m phiward run -- ls {t}/phi",          # only the bare head is a gateway call
    "/usr/local/bin/phiward run -- ls {t}/phi",
    "./phiward run -- ls {t}/phi",
    "phiward run ls {t}/phi",                         # no "--"
    "phiward run --bogus -- ls {t}/phi",
    "phiward copy {t}/phi/FAKE-PT-0001.bam",          # no destination
])
def test_everything_else_that_touches_is_refused(tree, cmd):
    assert verdict(tree, cmd.format(t=tree)) == DENY


def test_a_grant_where_the_tool_cannot_ask_is_still_allowed(tree):
    # the hook never asks for grants any more, so a tool that cannot ask changes nothing
    from phiward.core import dispatch
    cwd = str(tree / "repo")
    act = Action(SHELL, cwd, command=f"phiward run --net -- ls {tree}/phi", can_ask=False)
    d = dispatch(act, config.load(cwd), {"p": protected_paths.check})
    assert d.verdict == ALLOW


# --- Normal work is not touched (the friction measure) ---------------------------------------

MUST_ALLOW = [
    "git status", "git diff --stat", "git log --oneline -5", "git add -A && git commit -m 'x'",
    "git commit -m \"$(cat <<'EOF'\nfix: a thing\nEOF\n)\"",
    "python3 -m pytest -q", "pytest tests/ -k foo", "ruff check src", "ls", "ls -la src",
    "cat README.md", "head -5 src/app.py", "grep -rn TODO src", "grep -r -e ALT -e SNP src",
    "find . -name '*.py'", "wc -l src/*.py", "mkdir -p build && cp README.md build/",
    "echo $PATH", "echo hello | tr a-z A-Z", "for f in src/*.py; do wc -l $f; done",
    "python3 -c 'print(1)'", "pip install -e .", "npm test", "make", "cd src && ls",
    "rm -f build/x", "diff README.md src/app.py", "sort README.md | uniq -c",
    "cat /etc/hosts", "ls /usr", "env | sort", "which python3", "date", "uname -a",
    "gh pr view 1", "git push origin feat/x", "true && false || echo done", "sleep 1",
    "tar -czf out.tgz src",
]


@pytest.mark.parametrize("cmd", MUST_ALLOW)
def test_normal_work_is_allowed(tree, cmd):
    assert verdict(tree, cmd) == ALLOW


def test_moving_above_a_root_counts_as_touching(tree):
    # after `cd ..` the working folder holds a protected root; a recursive tool could reach it
    assert verdict(tree, "cd .. && ls repo") == DENY


def test_relative_words_follow_the_cd_before_them(tree):
    # a line of plain steps reads each step from the folder the steps before it left: src/..
    # is the repo; any other line reads every step from every folder it names, so `..` is
    # also read from the starting folder (here above a root)
    assert verdict(tree, "cd src && ls ..") == ALLOW
    assert verdict(tree, "cd src || ls ..") == DENY
    assert verdict(tree, "(cd src; ls ..)") == DENY


def test_naming_a_root_in_text_counts_as_touching(tree):
    # The guard does not know echo from cat; text that names a protected path touches it.
    assert verdict(tree, f"echo '{tree}/phi is protected'") == DENY


def test_case_folding_on_macos(tree):
    import sys
    if sys.platform != "darwin":
        pytest.skip("letter case matters on Linux")
    assert verdict(tree, f"cat {str(tree).upper()}/PHI/FAKE-PT-0001.bam") == DENY


# --- A confined shell (the kernel is the boundary) -------------------------------------------

def confined(t, command, cwd="repo"):
    cwd = str(t / cwd)
    return protected_paths.check(Action(SHELL, cwd, command=command, confined=True),
                                 config.load(cwd)).verdict


@pytest.mark.parametrize("cmd,cwd", [
    ("ls ..", "repo"), ("grep -r x .", "runs"), ("ls /", "repo"), ("tr / _ < README.md", "repo"),
    ("echo $VIRTUAL_ENV_NOT_SET", "repo"), ("for i in {{1..500}}; do :; done", "repo"),
    ("cd .. && ls repo", "repo"), ("cd src && ls ..", "repo"),
])
def test_confined_shell_refuses_less(tree, cmd, cwd):
    assert confined(tree, cmd.format(t=tree), cwd) == ALLOW


def test_confined_shell_still_refuses_a_named_protected_path(tree):
    # the kernel would deny it anyway; the guard says what to do instead
    assert confined(tree, f"cat {tree}/phi/FAKE-PT-0001.bam") == DENY
    assert confined(tree, "cat ../phi/FAKE-PT-0001.bam") == DENY


def test_file_tools_are_strict_even_when_the_shell_is_confined(tree):
    cwd = str(tree / "repo")
    act = Action(FILE_READ, cwd, paths=(f"{tree}/phi/FAKE-PT-0001.bam",), confined=True)
    assert protected_paths.check(act, config.load(cwd)).verdict == DENY


# --- Words the guard cannot resolve ----------------------------------------------------------

UNRESOLVED = ["cat $PHI_DIR/x", "ls ${UNKNOWN_VAR}", "cat $(printf %s $UNSET_X)", "ls ~-/x"]


def _write_user_config(t, extra):
    path = t / "home" / "phiward.toml"
    path.write_text(path.read_text() + extra)


@pytest.mark.parametrize("cmd", UNRESOLVED)
def test_unresolved_default_is_deny(tree, cmd):
    assert verdict(tree, cmd) == DENY


@pytest.mark.parametrize("cmd", UNRESOLVED)
def test_unresolved_ask(tree, cmd):
    _write_user_config(tree, 'unresolved = "ask"\n')
    assert decide(tree, cmd).verdict == ASK
    # a tool that cannot ask (or a mode that skips prompts) turns ask into deny upstream;
    # the guard itself still says ask
    assert decide(tree, cmd, can_ask=False).verdict == ASK


@pytest.mark.parametrize("cmd", UNRESOLVED)
def test_unresolved_allow(tree, cmd):
    _write_user_config(tree, 'unresolved = "allow"\n')
    assert verdict(tree, cmd) == ALLOW


def test_unresolved_never_loosens_a_touching_command(tree):
    _write_user_config(tree, 'unresolved = "allow"\n')
    assert verdict(tree, f"cat {tree}/phi/x $UNKNOWN") == DENY


def test_known_variables_are_resolved(tree, monkeypatch):
    monkeypatch.setenv("FAKE_DATA_DIR", str(tree / "phi"))
    assert verdict(tree, "ls $FAKE_DATA_DIR") == DENY
    monkeypatch.setenv("FAKE_DATA_DIR", str(tree / "repo"))
    assert verdict(tree, "ls $FAKE_DATA_DIR") == ALLOW


def test_no_protected_paths_guards_only_credentials(tree, monkeypatch):
    empty = tree / "home" / "empty.toml"
    empty.write_text("")
    monkeypatch.setenv("PHIWARD_CONFIG", str(empty))
    # nothing is protected yet but the hidden list: a path that is not one passes
    assert verdict(tree, f"cat {tree}/phi/FAKE-PT-0001.bam") == ALLOW
    # without the sandbox a variable the guard cannot see could name a credential
    assert verdict(tree, "cat $PHI_DIR/x") == DENY


# --- Config: fail closed, tighten only -------------------------------------------------------

def test_a_config_that_does_not_parse_refuses_everything(tree):
    _write_user_config(tree, "roots = [unclosed\n")
    d = decide(tree, "git status")
    assert d.verdict == DENY and "config" in d.reason.lower()


def test_a_repo_config_cannot_weaken_the_user_config(tree):
    (tree / "repo" / ".phiward.toml").write_text('[protected_paths]\nunresolved = "allow"\n')
    assert verdict(tree, "cat $PHI_DIR/x") == DENY  # the user's value (default deny) holds
    assert verdict(tree, f"cat {tree}/phi/x") == DENY


def test_a_repo_config_can_tighten(tree):
    _write_user_config(tree, 'unresolved = "allow"\n')
    (tree / "repo" / ".phiward.toml").write_text(
        f'[protected_paths]\nunresolved = "ask"\nroots = ["{tree}/secret"]\n')
    assert verdict(tree, "cat $PHI_DIR/x") == ASK
    assert verdict(tree, "cat ../secret/a.txt") == DENY


# --- File tools ------------------------------------------------------------------------------

def file_decide(t, kind, paths, cwd="repo", tool=""):
    cwd = str(t / cwd)
    return protected_paths.check(Action(kind, cwd, paths=tuple(paths), tool=tool), config.load(cwd)).verdict


@pytest.mark.parametrize("kind,paths,expected", [
    (FILE_READ, ["{t}/phi/FAKE-PT-0001.bam"], DENY),
    (FILE_READ, ["{t}/links/to_arm/x.maf"], DENY),
    (FILE_READ, ["../phi/FAKE-PT-0001.bam"], DENY),
    (FILE_READ, ["runlink/../panel/x.maf"], DENY),     # first review: link, then ..
    (FILE_READ, ["leak.txt"], DENY),                   # a link to a protected file
    (FILE_SEARCH, ["runlink/.."], DENY),               # above the protected arm
    (FILE_READ, ["README.md"], ALLOW),
    (FILE_SEARCH, ["{t}"], DENY),                  # a recursive search from above a root
    (FILE_SEARCH, ["{t}/runs/*/panel/*.maf"], DENY),
    (FILE_SEARCH, ["src"], ALLOW),
    (FILE_SEARCH, ["."], ALLOW),
    (FILE_WRITE, ["{t}/phi/new.txt"], DENY),       # an edit shows a snippet of the file
    (FILE_WRITE, ["src/new.py"], ALLOW),
    (OTHER, [], ALLOW),
])
def test_file_tools(tree, kind, paths, expected):
    assert file_decide(tree, kind, [p.format(t=tree) for p in paths]) == expected


def test_a_search_with_no_path_uses_the_working_folder(tree):
    assert file_decide(tree, FILE_SEARCH, [], cwd="runs") == DENY
    assert file_decide(tree, FILE_SEARCH, [], cwd="repo") == ALLOW


def test_other_tools_are_checked_by_their_text(tree):
    cwd = str(tree / "repo")
    act = Action(OTHER, cwd, text=(f"read {tree}/phi/FAKE-PT-0001.bam",), tool="mcp__fs__read")
    assert protected_paths.check(act, config.load(cwd)).verdict == DENY


def test_the_reason_never_lists_files_found_on_disk(tree):
    # a glob expands on disk; the reason must not show what it found
    d = decide(tree, f"cat {tree}/phi/*.bam")
    assert d.verdict == DENY and "FAKE-PT-0001" not in d.reason
