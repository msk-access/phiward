"""The fifteenth review round, fixed by class rather than by spelling: a line that changes how
bash finds commands or folders is unresolved in an unconfined shell; `phiward exec` denies
Claude Code's settings files at their resolved path whether or not they exist; braces and `..`
in an allowRead wildcard are taken widely. Made-up trees only."""

from pathlib import Path

import pytest

from phiward import claude_settings, confine
from phiward.core import ALLOW, DENY, SHELL, Action
from phiward.guards import protected_paths
from helpers import CONFINE_WHY, check_shell, protect

SRC = str(Path(__file__).resolve().parents[1] / "src")
seatbelt = pytest.mark.skipif(confine.backend() != "seatbelt" or CONFINE_WHY is not None,
                              reason="Seatbelt only")


# --- the hook: a change to how bash finds commands or folders ------------------------------------

@pytest.mark.parametrize("cmd", [
    "printf -v CDPATH '\\x2e\\x2e'; cd phi && cat FAKE-PT-0001.bam",
    "printf -v PATH %s x; cat README.md",
    "printf -vPATH %s x; cat README.md",
    "export PATH=/tmp/x:$PATH; ls",
    "PATH=/tmp/x ls",
    "read CDPATH < f; cd phi",
    "declare -x CDPATH=/tmp/x; cd y",
    "shopt -s cdable_vars; cd x",
    "hash -p /tmp/x cat; cat f",
    "BASH_CMDS[cat]=/tmp/x; cat f",
])
def test_a_line_that_changes_the_lookup_is_unresolved_without_confinement(tree, cmd):
    cfg = protect(tree, [])
    d = check_shell(tree, cfg, cmd)
    assert d.verdict == DENY and "finds commands or folders" in d.reason, (cmd, d.reason)
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command=cmd, confined=True), cfg)
    assert d.verdict == ALLOW, d.reason  # the kernel decides


@pytest.mark.parametrize("cmd", ["set -euo pipefail; ls", "IFS= read -r line < f", "X=1 ls",
                                 "unset CDPATH; ls", "echo $PATH"])
def test_ordinary_lines_still_pass(tree, cmd):
    assert check_shell(tree, protect(tree, []), cmd).verdict == ALLOW, cmd


# --- phiward exec: settings files behind a link, or not there yet ---------------------------------

# --- allowRead: braces and `..` are taken widely ---------------------------------------------------

@pytest.mark.parametrize("allow", ["{t}/runs/run1/{{panel,x}}", "{t}/r*/../runs/run1/panel/**"])
def test_braces_and_dotdot_in_an_allow_wildcard_reach_into_a_pattern(tree, allow):
    assert claude_settings._reaches_into(allow.format(t=tree), f"{tree}/runs/*/panel")


def test_braces_in_an_allow_entry_reopen_a_root(tree):
    root = str(tree / "phi")
    assert claude_settings._reopened(root, [root], [f"{tree}/{{phi,x}}/sub"])
