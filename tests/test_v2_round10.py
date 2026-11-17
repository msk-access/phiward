"""The tenth review round: the hook's pattern regex in code and heredocs (a folder name with
`&`), patterns with several wildcards in one name, quoting after a protected path, a TZ with a
relative path, and long paths that made the hook and the sanitizer slow. Made-up trees only."""

import subprocess
import time

import pytest

from phiward import install
from phiward.core import ALLOW, DENY
from phiward.sanitize import Sanitizer
from helpers import check_shell, gone, protect


# --- H1: a folder name with `&`, `;` or `|`, named in code or a heredoc ------------------------

@pytest.mark.parametrize("name", ["R&D", "a;b", "x|y"])
def test_a_protected_folder_with_a_shell_character_is_refused_in_code(tree, name):
    panel = tree / "runs" / name / "panel"
    panel.mkdir(parents=True)
    (panel / "FAKE-PT-9.maf").write_text("SECRET-CONTENT-9\n")
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    f = panel / "FAKE-PT-9.maf"
    assert check_shell(tree, cfg, f'python3 -c "print(open(\'{f}\').read())"').verdict == DENY
    assert check_shell(tree, cfg, f"python3 - <<'EOF'\nprint(open('{f}').read())\nEOF").verdict == DENY


@pytest.mark.parametrize("cmd", [
    "ls {t}/pat/phi_a.txt && echo done_raw",
    "ls {t}/pat/phi_a.txt; echo x_raw",
])
def test_separate_commands_are_still_not_one_protected_path(tree, cmd):
    (tree / "pat").mkdir()
    (tree / "pat" / "phi_a.txt").write_text("ok\n")
    cfg = protect(tree, [f"{tree}/pat/phi_*_raw"])
    assert check_shell(tree, cfg, cmd.format(t=tree)).verdict == ALLOW


# --- H2: a pattern with several wildcards in one name -------------------------------------------

@pytest.mark.parametrize("pattern", ["{t}/data/*phi*", "{t}/data/*_raw_*", "{t}/data/s*_*_raw"])
def test_a_pattern_with_several_wildcards_leaves_other_names_alone(tree, pattern):
    data = tree / "data"
    (data / "public").mkdir(parents=True)
    (data / "src_raw").mkdir()
    (data / "notes.txt").write_text("ok\n")
    cfg = protect(tree, [pattern.format(t=tree)])
    for cmd in (f"cat {data}/notes.txt", f"ls {data}/public", f"ls {data}/src_raw"):
        assert check_shell(tree, cfg, cmd).verdict == ALLOW, cmd
    san = Sanitizer.from_config(cfg)
    for line in (f"{data}/notes.txt", f"{data}/public/x", f"{data}/src_raw"):
        # the part below the test's tree (a temp path with a long number is masked as <NUM>)
        assert san.clean(line).endswith(line[len(str(tree)):]), line


@pytest.mark.parametrize("pattern,name", [("{t}/data/*phi*", "xphiZorro"),
                                          ("{t}/data/*_raw_*", "a_raw_Zorro"),
                                          ("{t}/data/s*_*_raw", "s1_Zorro_raw")])
def test_a_pattern_with_several_wildcards_still_matches_its_names(tree, pattern, name):
    cfg = protect(tree, [pattern.format(t=tree)])
    line = f"{tree}/data/{name}/f.txt"
    gone(Sanitizer.from_config(cfg).clean(line), "Zorro")
    assert check_shell(tree, cfg, f"echo {line}").verdict == DENY


# --- M1: quoting after a protected path ---------------------------------------------------------

@pytest.mark.parametrize("entries", [True, False])
@pytest.mark.parametrize("tail,words", [
    ("O'\\''Brien Pat'", "Brien Pat"),
    ("Ann'\"'\"'Zorro", "Zorro"),
    ("Ann''Zorro", "Zorro"),
    ("Ann'' Zorro", "Zorro"),
    ("Ann' 'Zorro", "Zorro"),
    ("Ann&&Zorro", "Zorro"),
    ("Ann'-Zorro", "Zorro"),
    ("Ann(-Zorro", "Zorro"),
    ("Ann|.Zorro", "Zorro"),
    ("Ann)(Zorro", "Zorro"),
])
def test_quoting_after_a_protected_path_does_not_leak_the_name(tree, entries, tail, words):
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    san = Sanitizer.from_config(cfg, entries=entries)
    gone(san.clean(f"'{tree}/phi/{tail}"), words)


# --- M2: a TZ that names a file by a relative path ----------------------------------------------

def test_a_tz_with_a_relative_path_is_cleared(tree):
    fake = tree / "fakepython"
    fake.write_text("#!/bin/sh\n/usr/bin/env\n")
    fake.chmod(0o755)
    cmd = install.isolated_command(str(fake), "hook")
    for tz in ("../../../tmp/x/Fake", ":../../tmp/x/Fake", "a/../../x"):
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                             env={"PATH": "/usr/bin:/bin", "TZ": tz}).stdout
        assert "TZ=" not in out, (tz, out)
        assert install.cleared("TZ", tz), tz
    assert not install.cleared("TZ", "Europe/Paris") and not install.cleared("TZ", "::/x")


# --- M3: long paths -----------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", ["echo " + "/a" * 2000 + "/", "cat " + "/a/.." * 1000 + "/x"])
def test_the_hook_checks_a_long_path_quickly(tree, cmd):
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    start = time.monotonic()
    check_shell(tree, cfg, cmd)
    assert time.monotonic() - start < 3


def test_the_hook_checks_a_repeated_protected_prefix_quickly(tree):
    cfg = protect(tree, [f"{tree}/runs/*/panel"])
    start = time.monotonic()
    d = check_shell(tree, cfg, "echo " + (str(tree) + "/") * 500)
    assert time.monotonic() - start < 5, d


def test_the_sanitizer_masks_a_long_path_line_quickly(tree):
    san = Sanitizer.from_config(protect(tree, [f"{tree}/runs/*/panel"]))
    start = time.monotonic()
    san.clean((str(tree) + "/") * 500)
    san.clean("x" * 30000 + ".bam")
    assert time.monotonic() - start < 3


def test_the_bam_rule_still_masks_a_file_token(tree):
    san = Sanitizer.from_config(protect(tree, [f"{tree}/runs/*/panel"]))
    assert san.clean("see /tmp/x/Sample7.sorted.bam now") == "see <BAMFILE> now"
    assert san.clean("a=Sample7.bam,b") == "a=<BAMFILE>,b"
