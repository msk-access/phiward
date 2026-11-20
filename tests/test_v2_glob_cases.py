"""Every known glob case, in the three places a glob is decided (docs/threat-model.md):

- C, the shell inside Claude Code's sandbox: the kernel stops reads of protected paths and
  credentials, so the hook decides from the pattern alone and never lists the disk;
- U, a shell without the sandbox: the hook is the only guard (best effort);
- F, a file tool (Glob, Grep, Read): the hook, then Claude Code's deny rules.

Three kinds of test: a corpus of the cases the three reviews before v0.2.0b1 reproduced, with the
verdict each place must give; an oracle test (two trees that differ only inside a protected
folder must get the same verdict for every glob); and a cost test. Made-up data only."""

import os
import random
import shutil
import sys
import time
from pathlib import Path

import pytest

from phiward import config
from phiward.core import ALLOW, DENY, FILE_SEARCH, SHELL, Action
from phiward.guards import protected_paths

MODES = ("C", "U", "F")


def verdict(tree: Path, mode: str, cmd: str = "", path: str = "") -> str:
    cfg = config.load(str(tree / "repo"))
    cwd = str(tree / "repo")
    if mode == "F":
        act = Action(FILE_SEARCH, cwd, paths=(path,))
    else:
        act = Action(SHELL, cwd, command=cmd, confined=(mode == "C"))
    return protected_paths.check(act, cfg).verdict


def _link(tree, name, target):
    p = tree / "repo" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, p)


def _many(folder: Path, n: int, kind: str = "file", prefix: str = "f", suffix: str = ""):
    folder.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        p = folder / f"{prefix}{i:05d}{suffix}"
        p.mkdir() if kind == "dir" else p.write_text("")


# --- the corpus ------------------------------------------------------------------------------
# (id, setup, shell command, file-tool glob, expected verdict for C, U, F; None: not checked)
# `{t}` is the made-up tree, `{h}` its home folder.

def _none(tree):
    pass


def _lnk_to_root(tree):
    _link(tree, "lnk", tree / "phi")


def _up_to_tree(tree):
    _link(tree, "up", tree)


def _star_links(tree):  # round 2 H1: links under ** to an existing and a missing name
    _link(tree, "d1/g", tree / "phi" / "sub")
    _link(tree, "d1/h", tree / "phi" / "NOPE")


def _big_with_link(tree):  # round 2 H3a: many entries, one link into the root
    _many(tree / "repo" / "big", 4200)
    os.symlink(tree / "phi", tree / "repo" / "big" / "zlink")


def _big_txt_with_link(tree):
    _many(tree / "repo" / "big", 4200, suffix=".txt")
    os.symlink(tree / "phi" / "FAKE-PT-0001.bam", tree / "repo" / "big" / "zz.txt")


def _dot_link(tree):  # a dot link, reached with dot globbing
    _link(tree, ".hid", tree / "phi")


def _netrc_behind_many(tree):  # round 3 H1: a credential after 4200 names that sort first
    h = tree / "home"
    (h / ".netrc").write_text("machine example.invalid\n")
    for i in range(4200):
        (h / f".n{i:05d}").write_text("")


def _chain(tree):  # round 3 H3: a link to a folder that holds a link into the root
    (tree / "repo" / "u").mkdir()
    os.symlink(tree / "phi" / "FAKE-PT-0001.bam", tree / "repo" / "u" / "xl")
    _link(tree, "l", tree / "repo" / "u")


def _node_modules(tree):  # round 3 H2: an ordinary large repository (no link into a root)
    (tree / "repo" / "leak.txt").unlink()
    _many(tree / "repo" / "node_modules", 5000, kind="dir", prefix="pkg")
    (tree / "repo" / "src" / "app.py").write_text("x\n")


def _node_modules_and_a_link(tree):
    _many(tree / "repo" / "node_modules", 50, kind="dir", prefix="pkg")


def _d_e_lnk(tree):  # a link two folders down, reached after `cd d*` and `cd e`
    _link(tree, "d1/e/lnk", tree / "phi")


def _nfd_link(tree):  # a link whose name is stored decomposed (NFD)
    import unicodedata
    _link(tree, "d/" + unicodedata.normalize("NFD", "café"), tree / "phi")


_LOCKED = []  # folders a setup made unlistable: opened again after the test


@pytest.fixture(autouse=True)
def _unlock():
    yield
    while _LOCKED:
        try:
            os.chmod(_LOCKED.pop(), 0o755)
        except FileNotFoundError:
            pass  # the tree is gone already (Linux: the tree fixture removes it)


def _xonly(tree):  # a folder that can be passed through, not listed
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root lists any folder")
    _link(tree, "work/xonly/lk", tree / "phi")
    os.chmod(tree / "repo" / "work" / "xonly", 0o100)
    _LOCKED.append(tree / "repo" / "work" / "xonly")


def _fresh(tree):
    (tree / "pub" / "x" / "y").mkdir(parents=True)


def _sub_lnk(tree):  # a link one folder down, reached after a `cd`
    _link(tree, "sub/lnk", tree / "phi")


def _ssh(tree):  # a made-up key on the hidden list
    (tree / "home" / ".ssh").mkdir()
    (tree / "home" / ".ssh" / "id_rsa").write_text("FAKE-KEY\n")


CORPUS = [
    # round 1: a glob into a root, the same answer for a name that is and is not there
    ("r1-p-star-F", _none, "echo {t}/p*/F*", "{t}/p*/F*", DENY, DENY, DENY),
    ("r1-p-star-G", _none, "echo {t}/p*/G*", "{t}/p*/G*", DENY, DENY, DENY),
    ("r1-range-in", _none, "echo {t}/phi/FAKE-PT-000[0-4]*", "{t}/phi/FAKE-PT-000[0-4]*",
     DENY, DENY, DENY),
    ("r1-range-out", _none, "echo {t}/phi/FAKE-PT-000[5-9]*", "{t}/phi/FAKE-PT-000[5-9]*",
     DENY, DENY, DENY),
    ("r1-cd", _none, "cd {t}/p*/s* && pwd", None, DENY, DENY, None),
    ("r1-double-star", _none, "echo {t}/**/FAKE-PT-0002.bam", "{t}/**/FAKE-PT-0002.bam",
     DENY, DENY, DENY),
    ("r1-double-star-nope", _none, "echo {t}/**/NOPE-0002.bam", "{t}/**/NOPE-0002.bam",
     DENY, DENY, DENY),
    ("r1-link-F", _lnk_to_root, "echo lnk/F*", "{t}/repo/lnk/F*", DENY, DENY, DENY),
    ("r1-link-G", _lnk_to_root, "echo lnk/G*", "{t}/repo/lnk/G*", DENY, DENY, DENY),
    ("r1-link-star", _lnk_to_root, "echo l*/F*", "{t}/repo/l*/F*", ALLOW, DENY, DENY),
    ("r1-up", _up_to_tree, "echo up/p*/G*", "{t}/repo/up/p*/G*", DENY, DENY, DENY),
    ("r1-cannot-reach", _none, "echo {t}/pu*/x*", "{t}/pu*/x*", ALLOW, ALLOW, ALLOW),
    ("r1-src", _none, "ls src/*.py", "{t}/repo/src/*.py", ALLOW, ALLOW, ALLOW),
    ("r1-leak-link", _none, "cat lea*", "{t}/repo/lea*", ALLOW, DENY, DENY),
    # round 2: brackets, links under **, size, dot globbing, ordinary globs
    ("r2-not-P", _none, "cat {t}/[!P]hi/FAKE*", "{t}/[!P]hi/FAKE*", DENY, DENY, DENY),
    ("r2-caret", _none, "cat {t}/[^x]hi/FAKE*", "{t}/[^x]hi/FAKE*", DENY, DENY, DENY),
    ("r2-class", _none, "cat {t}/[[:alpha:]]hi/FAKE*", "{t}/[[:alpha:]]hi/FAKE*",
     DENY, DENY, DENY),
    ("r2-pP", _none, "cat {t}/[pP]hi/FAKE*", "{t}/[pP]hi/FAKE*", DENY, DENY, DENY),
    ("r2-q", _none, "cat {t}/?hi/FAKE*", "{t}/?hi/FAKE*", DENY, DENY, DENY),
    ("r2-star-link-zzz", _star_links, "cat d1/**/zzz", "{t}/repo/d1/**/zzz", ALLOW, DENY, DENY),
    ("r2-star-link-all", _star_links, "cat d1/**", "{t}/repo/d1/**", ALLOW, DENY, DENY),
    ("r2-big-z", _big_with_link, "cat big/z*/FAKE*", "{t}/repo/big/z*/FAKE*", ALLOW, DENY, DENY),
    ("r2-big-star", _big_with_link, "cat big/*/FAKE*", "{t}/repo/big/*/FAKE*", ALLOW, DENY, DENY),
    ("r2-big-last", _big_txt_with_link, "ls big/*.txt", "{t}/repo/big/*.txt", ALLOW, DENY, DENY),
    ("r2-big-plain", lambda t: _many(t / "repo" / "big", 4200, suffix=".txt"), "ls big/*.txt",
     "{t}/repo/big/*.txt", ALLOW, ALLOW, ALLOW),
    ("r2-dotglob", _dot_link, "shopt -s dotglob; cat */FAKE*", None, ALLOW, DENY, None),
    ("r2-globignore", _dot_link, "GLOBIGNORE=x; cat */FAKE*", None, ALLOW, DENY, None),
    ("r2-tmp-log", _none, "ls /tmp/*.log", None, ALLOW, None, None),
    ("r2-home-star", _none, "ls ~/*", None, ALLOW, None, None),
    ("r2-du-home", _none, "du -sh ~/*", None, ALLOW, None, None),
    ("r2-var-tmp", _none, "ls /var/tmp/*.sock", None, ALLOW, None, None),
    ("r2-rm-tmp", _none, "rm -f /tmp/build-*.tmp", None, ALLOW, None, None),
    # round 3: a credential behind many names, ** in a large repo, a chain of links, hidden
    # dot globbing
    ("r3-netrc", _netrc_behind_many, "cat ~/.n*", "{h}/.n*", ALLOW, DENY, DENY),
    ("r3-node-modules-glob", _node_modules, "ls **/*.py", "{t}/repo/**/*.py", ALLOW, ALLOW, ALLOW),
    # outside the sandbox, `**` is refused in a tree with a link into a protected folder: the
    # shell would walk into it only if it is a folder, and only the root knows that
    ("r3-double-star-with-a-link", _node_modules_and_a_link, "ls **/*.py", "{t}/repo/**/*.py",
     ALLOW, DENY, DENY),
    ("r3-chain-star", _chain, "cat **/x*", "{t}/repo/**/x*", ALLOW, DENY, DENY),
    ("r3-chain-dot", _chain, "cat ./**/x*", None, ALLOW, DENY, None),
    ("r3-chain-name", _chain, "cat **/xl", "{t}/repo/**/xl", ALLOW, DENY, DENY),
    ("r3-chain-one", _chain, "cat */x*", "{t}/repo/*/x*", ALLOW, DENY, DENY),
    ("r3-dotglob-escaped", _dot_link, "shopt -s dot\\glob; cat */FAKE*", None, ALLOW, DENY, None),
    ("r3-dotglob-quoted", _dot_link, "shopt -s dot''glob; cat */FAKE*", None, ALLOW, DENY, None),
    ("r3-zsh-globdots", _dot_link, "setopt glo_bdots; cat */FAKE*", None, ALLOW, DENY, None),
    # round 4: `.` after a wildcard, Unicode and case, a prefix through a root, a folder that
    # cannot be listed, a second `cd`, braces and groups, split words, `..` after a glob `cd`
    ("r4-dot-pattern", _none, "cat {t}/ru*/./run1/panel/x.maf", "{t}/ru*/./run1/panel/x.maf",
     DENY, DENY, DENY),
    ("r4-dot-root", _none, "cat {tp}/{tn}/./phi/FAKE-PT-0001.bam",
     "{tp}/{tn}/./phi/FAKE-PT-0001.bam", DENY, DENY, DENY),
    ("r4-dot-cd", _d_e_lnk, "cd d* && cd ./e && cat lnk/FAKE-PT-0001.bam", None, ALLOW, DENY, None),
    ("mac-r4-nfc-name", _nfd_link, "cat d*/café/FAKE-PT-0001.bam", "{t}/repo/d*/café/FAKE-PT-0001.bam",
     ALLOW, DENY, DENY),
    ("mac-r4-upper-name", _nfd_link, "cat d*/CAFÉ/FAKE-PT-0001.bam",
     "{t}/repo/d*/CAFÉ/FAKE-PT-0001.bam", ALLOW, DENY, DENY),
    ("r4-prefix-sub", _none, "ls ../phi/sub/../../repo/*.md", "{t}/phi/sub/../../repo/*.md",
     DENY, DENY, DENY),
    ("r4-prefix-nope", _none, "ls ../phi/NOPE/../../repo/*.md", "{t}/phi/NOPE/../../repo/*.md",
     DENY, DENY, DENY),
    ("r4-xonly", _xonly, "cat work/x*/lk/sub/FAKE-PT-0002.bam",
     "{t}/repo/work/x*/lk/sub/FAKE-PT-0002.bam", ALLOW, DENY, DENY),
    ("r4-second-cd", _d_e_lnk, "cd d* && cd e && cat lnk/FAKE-PT-0001.bam", None, ALLOW, DENY, None),
    ("r4-brace-root", _none, "echo {t}/{{phi,zz}}/x", "{t}/{{phi,zz}}/*", DENY, DENY, DENY),
    ("r4-brace-inside", _none, "echo {t}/ph{{i,}}/x", "{t}/ph{{i,}}/*", DENY, DENY, DENY),
    ("r4-brace-pattern", _none, None, "{t}/runs/*/{{panel,zz}}/x.maf", None, None, DENY),
    ("r4-backslash", _none, None, "{t}/ph\\i/*", None, None, DENY),
    ("r4-extglob", _none, None, "{t}/@(phi)/*", None, None, DENY),
    ("r4-zsh-group", _none, "cat {t}/(phi|zz)/FAKE-PT-0001.bam", None, ALLOW, DENY, None),
    ("r4-zsh-group-relative", _d_e_lnk, "cat d1/e/(lnk|zz)/FAKE-PT-0001.bam", None,
     ALLOW, DENY, None),
    ("r4-subshell-is-not-a-group", _none, "(cd src && ls)", None, ALLOW, ALLOW, None),
    ("r4-cd-glob-dotdot", _none, "cd src* && cat ../README.md", None, ALLOW, DENY, None),
    ("r4-split-sub", _none, "cat ../ph$(echo i)/FAKE-PT-0001.bam", None, ALLOW, DENY, None),
    ("r4-split-backticks", _none, "cat ../ph`echo i`/FAKE-PT-0001.bam", None, ALLOW, DENY, None),
    ("r4-split-bound", _none, "x=i; cat ../ph${{x}}/FAKE-PT-0001.bam", None, ALLOW, DENY, None),
    ("r4-split-ansi", _none, "cat ../ph$'\\x69'/FAKE-PT-0001.bam", None, ALLOW, DENY, None),
    ("r4-pwd", _none, "cat $PWD/../phi/FAKE-PT-0001.bam", None, DENY, DENY, None),
    ("r4-fresh-link", _fresh, "ln -s ../pub/x/y s && cat s/../../../phi/FAKE-PT-0001.bam", None,
     ALLOW, DENY, None),
    # round 5: words made only of `$(...)`, `$'...'` or several variables; `${HOME<modifier>}`;
    # a bare `cd`; groups in heredocs and comments; nested groups; `..` past a wildcard
    ("r5-dot-plain-root", _none, "cat {t}/./phi/FAKE-PT-0001.bam", "{t}/./phi/F*",
     DENY, DENY, DENY),
    # a word that is exactly one `$(...)`: its command is checked; a command that prints a
    # path is the interpreter case the threat model accepts (else every heredoc commit
    # message would be refused without the sandbox)
    ("r5-only-sub", _none, "cat $(printf '%b' '..\\057ph\\0151/FAKE-PT-0001.bam')", None,
     ALLOW, ALLOW, None),
    ("r5-commit-message", _none, "git commit -m \"$(cat <<'EOF'\nfix(x): y\nEOF\n)\"", None,
     ALLOW, ALLOW, None),
    ("r5-ansi-escaped-quote", _none, "echo $'a\\'b' f(x)", None, ALLOW, DENY, None),
    ("r5-only-ansi", _none, "cat $'..\\x2fph\\x69/FAKE-PT-0001.bam'", None, ALLOW, DENY, None),
    ("r5-two-vars", _none, "X=../ph; Y=i/FAKE-PT-0001.bam; cat $X$Y", None, ALLOW, DENY, None),
    ("r5-one-var-in", _none, "X=../phi/FAKE-PT-0001.bam; cat $X", None, DENY, DENY, None),
    ("r5-one-var-out", _none, "X=src; ls $X", None, ALLOW, ALLOW, None),
    ("r5-home-default", _ssh, "cat ${{HOME:-x}}/.ssh/id_rsa", None, ALLOW, DENY, None),
    ("r5-home-suffix", _ssh, "cat ${{HOME%/}}/.ssh/id_rsa", None, ALLOW, DENY, None),
    ("r5-bare-cd", _ssh, "cd; cat .ssh/id_rsa", None, DENY, DENY, None),
    ("r5-bare-cd-dashes", _ssh, "cd -- ; cat .ssh/id_rsa", None, DENY, DENY, None),
    ("r5-bare-cd-subshell", _ssh, "(cd; cat .ssh/id_rsa)", None, DENY, DENY, None),
    ("r5-bare-cd-and", _ssh, "true && cd && cat .ssh/id_rsa", None, DENY, DENY, None),
    ("r5-cd-back", _none, "cd /tmp; cd -; cat README.md", None, ALLOW, DENY, None),
    ("r5-heredoc-group", _none, "cat <<EOF\nf(x)\nEOF", None, ALLOW, ALLOW, None),
    ("r5-comment-group", _none, "ls # note f(x)", None, ALLOW, ALLOW, None),
    ("r5-python-heredoc", _none, "python3 - <<'EOF'\nprint(len([1]))\nEOF", None,
     ALLOW, ALLOW, None),
    ("r5-nested-group", _none, None, "{t}/@(@(phi)|zzz)/*", None, None, DENY),
    ("r5-nested-group-inner", _none, None, "{t}/@(ph@(i))/*", None, None, DENY),
    ("r5-group-with-slash", _none, None, "{t}/(phi/sub|zz)/*", None, None, DENY),
    ("r5-dotdot-past-wildcard", _none, "cat {t}/repo/*/../../phi/FAKE-PT-0001.bam",
     "{t}/repo/*/../../phi/F*", DENY, DENY, DENY),
    # round 6: a `cd` after a shell keyword, in a group or a function
    ("r6-brace-cd", _sub_lnk, "{{ cd sub; cat lnk/FAKE-PT-0001.bam; }}", None, DENY, DENY, None),
    ("r6-then-cd", _sub_lnk, "if true; then cd sub; cat lnk/FAKE-PT-0001.bam; fi", None,
     DENY, DENY, None),
    ("r6-do-cd", _sub_lnk, "for d in sub; do cd $d; done; cat lnk/FAKE-PT-0001.bam", None,
     ALLOW, DENY, None),
    ("r6-time-cd", _sub_lnk, "time cd sub; cat lnk/FAKE-PT-0001.bam", None, DENY, DENY, None),
    ("r6-builtin-cd", _sub_lnk, "builtin cd sub && cat lnk/FAKE-PT-0001.bam", None,
     DENY, DENY, None),
    ("r6-command-cd", _sub_lnk, "command cd sub && cat lnk/FAKE-PT-0001.bam", None,
     DENY, DENY, None),
    ("r6-bang-cd", _sub_lnk, "! cd sub; cat lnk/FAKE-PT-0001.bam", None, DENY, DENY, None),
    ("r6-function-cd", _sub_lnk, "f() {{ cd sub && cat lnk/FAKE-PT-0001.bam; }}; f", None,
     DENY, DENY, None),
    ("r6-function-glued-cd", _sub_lnk, "f(){{ cd sub && cat lnk/FAKE-PT-0001.bam; }}; f", None,
     DENY, DENY, None),
    ("r6-brace-home", _ssh, "{{ cd; cat .ssh/id_rsa; }}", None, DENY, DENY, None),
    ("r6-then-cd-back", _none, "if true; then cd -; fi; cat README.md", None, ALLOW, DENY, None),
    # round 6: what the text check closes without the sandbox (best effort)
    ("r6-special-joined", _none, "set -- i; cat ../ph$1/FAKE-PT-0001.bam", None,
     ALLOW, DENY, None),
    ("r6-special-default", _none, "cat ../ph${{1:-i}}/FAKE-PT-0001.bam", None, ALLOW, DENY, None),
    ("r6-last-argument", _none, "echo i >/dev/null; cat ../ph$_/FAKE-PT-0001.bam", None,
     ALLOW, DENY, None),
    ("r6-arithmetic", _none, "cat ../phi$((0))/FAKE-PT-0001.bam", None, DENY, DENY, None),
    ("r6-old-arithmetic", _none, "cat ../ph$[1]i/FAKE-PT-0001.bam", None, DENY, DENY, None),
    ("r6-plus-equals", _none, "X=../ph; X+=i/FAKE-PT-0001.bam; cat $X", None, ALLOW, DENY, None),
    ("r6-printf-v", _none, "printf -v X %s%s ../ph i/FAKE-PT-0001.bam; cat $X", None,
     ALLOW, DENY, None),
    ("r6-declare-twice", _none, "declare X=../ph X+=i/FAKE-PT-0001.bam; cat \"$X\"", None,
     ALLOW, DENY, None),
    ("r6-bash-c", _none, "bash -c 'cat ../phi/FAKE-PT-0001.bam'", None, DENY, DENY, None),
    ("r6-eval", _none, "eval 'cat ../phi/FAKE-PT-0001.bam'", None, DENY, DENY, None),
    ("r6-sh-heredoc", _none, "sh <<'EOF'\ncat ../phi/FAKE-PT-0001.bam\nEOF", None,
     DENY, DENY, None),
    ("r6-env-chdir", _none, "env -C src cat ../../phi/FAKE-PT-0001.bam", None, DENY, DENY, None),
    ("r6-git-C", _none, "git -C src diff --no-index ../../phi/FAKE-PT-0001.bam /dev/null", None,
     DENY, DENY, None),
    ("r6-tar-C", _none, "tar -C src -cf - ../../phi", None, DENY, DENY, None),
    ("r6-make-directory", _none, "make --directory=src -f ../../phi/FAKE-PT-0001.bam", None,
     DENY, DENY, None),
    ("r6-find-execdir", _none, "find src -maxdepth 0 -execdir cat ../../phi/FAKE-PT-0001.bam \\;",
     None, ALLOW, DENY, None),
    ("r6-dot-glob", _none, "cat .*/phi/FAKE-PT-0001.bam", None, ALLOW, DENY, None),
    ("r6-ls-dot-glob-next-to-a-root", _none, "ls .*", None, ALLOW, DENY, None),
    ("r6-ls-dot-glob", _none, "cd src && ls .*", None, ALLOW, ALLOW, None),
    ("r6-link-made-here", _none, "ln -s ../../phi src/l && cat src/l/FAKE-PT-0001.bam", None,
     ALLOW, DENY, None),
    ("r6-link-made-deeper", _none,
     "mkdir -p a/b && ln -s ../../../phi a/b/l && cat a/b/l/FAKE-PT-0001.bam", None,
     ALLOW, DENY, None),
    # round 6: ordinary commands the text check lets through again
    ("r6-folder-made-here", _none, "mkdir -p out && echo x > out/a && cat out/a", None,
     ALLOW, ALLOW, None),
    ("r6-echo-date", _none, "echo \"Done: $(date)\"", None, ALLOW, ALLOW, None),
    ("r6-echo-commit", _none, "x=$(git rev-parse HEAD); echo \"commit: $x\"", None,
     ALLOW, ALLOW, None),
    ("r6-echo-count", _none, "n=$(ls | wc -l); echo \"$n files\"", None, ALLOW, ALLOW, None),
    # round 7: a loop variable joined to other text is built like any variable the line sets
    ("r6-for-copy", _none, "for f in src/*.py; do cp \"$f\" \"$f.bak\"; done", None,
     ALLOW, DENY, None),
    ("r7-for-whole-word", _none, "for f in src/*.py; do wc -l \"$f\"; done", None,
     ALLOW, ALLOW, None),
    ("r7-for-joined", _none, "for X in i; do cat ../ph$X/FAKE-PT-0001.bam; done", None,
     ALLOW, DENY, None),
    ("r7-echo-redefined", _none, "echo() {{ cat \"$@\"; }}; echo ../ph$(echo i)/FAKE-PT-0001.bam",
     None, ALLOW, DENY, None),
    ("r7-echo-inside", _none, "cat $(echo ../ph$(echo i)/FAKE-PT-0001.bam)", None,
     ALLOW, DENY, None),
    ("r7-echo-piped", _none, "echo ../ph$(echo i)/FAKE-PT-0001.bam | xargs cat", None,
     ALLOW, DENY, None),
    ("r7-echo-text", _none, "echo \"${{X%.*}} has ${{#X}} letters\"", None, ALLOW, ALLOW, None),
    ("r6-pwd", _none, "docker run -v \"$(pwd)\":/w img", None, ALLOW, ALLOW, None),
    ("r6-cd-toplevel", _none, "cd \"$(git rev-parse --show-toplevel)\" && ls", None,
     ALLOW, ALLOW, None),
    ("r6-function-glued", _none, "f(){{ echo hi; }}; f", None, ALLOW, ALLOW, None),
    ("r6-ifs", _none, "IFS=/ read a b <<< \"x/y\"", None, ALLOW, ALLOW, None),
    ("r6-array-length", _none, "arr=(a b c); echo \"${{#arr[@]}}\"", None, ALLOW, ALLOW, None),
]


# only the places a row gives a verdict for (no skip that could hide a test)
_CASES = [pytest.param(row, mode, id=f"{row[0]}-{mode}") for row in CORPUS
          for mode, expect in zip(MODES, row[4:])
          if expect is not None and (row[3] if mode == "F" else row[2]) is not None]


@pytest.mark.parametrize("row,mode", _CASES)
def test_the_corpus(tree, row, mode):
    rid, setup, cmd, path, *want = row
    expect = dict(zip(MODES, want))[mode]
    if rid.startswith("mac-") and sys.platform != "darwin":
        pytest.skip("macOS folds case and Unicode form")
    setup(tree)
    f = {"t": str(tree), "h": str(tree / "home"), "tp": str(tree.parent), "tn": tree.name[:-1] + "?"}
    got = verdict(tree, mode, (cmd or "").format(**f), (path or "").format(**f))
    assert got == expect, f"{rid} in {mode}: {got}"


def test_no_credentials_only_dotglob_slips_through(tree):
    # no protected paths yet (the first setup): the credentials still count
    Path(os.environ["PHIWARD_CONFIG"]).write_text("")
    (tree / "home" / ".netrc").write_text("x\n")
    assert verdict(tree, "U", "shopt -s dotglob; cat ~/*") == DENY


# --- the oracle: two trees that differ only inside a root ------------------------------------

PARTS = ["p*", "phi", "*", "?hi", "[!P]hi", "[[:alpha:]]hi", "**", "sub", "s*", "F*", "G*",
         ".*", "x*", "FAKE-PT-000[0-4]*", "NOPE*", ".", "p{{h,x}}i", "PHI", "Sub"]


def _globs(seed: int, n: int):
    rnd = random.Random(seed)
    for _ in range(n):
        base = rnd.choice(["{t}", "{t}/repo", "{t}/repo/l1", "{t}/repo/d"])
        parts = [rnd.choice(PARTS) for _ in range(rnd.randint(1, 3))]
        yield base + "/" + "/".join(parts)


def _twin(root: Path, which: int):
    """Two contents for the same root: names and kinds differ, nothing else."""
    if which:
        (root / "G-EXTRA").mkdir()
        (root / "NOPE-0003.bam").write_text("x")
        shutil.rmtree(root / "sub")
        (root / "sub").write_text("now a file")


def _links(tree):
    _link(tree, "l1", tree / "phi")
    _link(tree, "d/a", tree / "phi" / "G-EXTRA")
    _link(tree, "d/b", tree / "phi" / "sub")
    (tree / "repo" / "u").mkdir()
    os.symlink(tree / "phi" / "NOPE-0003.bam", tree / "repo" / "u" / "x1")
    _link(tree, "d/c", tree / "repo" / "u")


@pytest.mark.slow
@pytest.mark.parametrize("mode", MODES)
def test_the_verdict_never_depends_on_what_a_root_holds(tree, mode):
    _links(tree)
    globs = list(_globs(seed=7, n=250))
    first = {}
    for which in (0, 1):
        if which:
            _twin(tree / "phi", 1)
        for g in globs:
            p = g.format(t=str(tree))
            v = verdict(tree, mode, f"echo {p}", p)
            if which == 0:
                first[g] = v
            else:
                assert v == first[g], f"{mode}: {g} gave {first[g]} and then {v}"


# --- the cost: well under the hook's 10 s, and never a cut-short list ------------------------

@pytest.mark.parametrize("mode", MODES)
def test_a_large_repository_is_checked_fast(tree, mode):
    _node_modules(tree)
    start = time.monotonic()
    v = verdict(tree, mode, "ls **/*.py", f"{tree}/repo/**/*.py")
    took = time.monotonic() - start
    assert v == ALLOW and took < 5.0, (v, took)


def test_a_tree_past_the_budget_is_refused_not_cut_short(tree, monkeypatch):
    from phiward import paths
    monkeypatch.setattr(paths, "GLOB_BUDGET", 500)
    (tree / "repo" / "leak.txt").unlink()
    _many(tree / "repo" / "node_modules", 600, kind="dir", prefix="pkg")
    cfg = config.load(str(tree / "repo"))
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command="ls **/x"), cfg)
    assert d.verdict == DENY and "more entries than the guard checks" in d.reason


def test_the_budget_counts_names_listed_not_names_matched(tree, monkeypatch):
    from phiward import paths
    monkeypatch.setattr(paths, "GLOB_BUDGET", 500)
    _many(tree / "repo" / "big", 600)  # 600 names listed, none matches x*
    cfg = config.load(str(tree / "repo"))
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command="ls big/x*"), cfg)
    assert d.verdict == DENY and "more entries than the guard checks" in d.reason


def test_nested_groups_are_read_with_no_protected_paths_configured(tree):
    Path(os.environ["PHIWARD_CONFIG"]).write_text("")
    _ssh(tree)
    cfg = config.load(str(tree / "repo"))
    for p in (f"{tree}/home/@(@(.ssh)|zz)/id_rsa", f"{tree}/home/@(.ss@(h))/id_rsa"):
        d = protected_paths.check(Action(FILE_SEARCH, str(tree / "repo"), paths=(p,)), cfg)
        assert d.verdict == DENY, p


def test_a_root_with_a_number_for_a_name_is_not_spelled_by_arithmetic(tree):
    (tree / "data" / "2024").mkdir(parents=True)
    Path(os.environ["PHIWARD_CONFIG"]).write_text(
        f'[protected_paths]\nroots = ["{tree}/data/2024"]\n')
    for cmd in (f"cat {tree}/data/$((2000+24))/f", f"cat {tree}/data/20$[2*12]/f",
                f"cd {tree}/data/$[2000+24]; cat f"):
        assert verdict(tree, "U", cmd) == DENY, cmd


def test_a_project_under_home_can_cd_then_use_dotdot(tree):
    proj = tree / "home" / "proj"
    (proj / "build").mkdir(parents=True)
    cfg = config.load(str(proj))
    for cmd in ("cd build && cmake ..", "cd build && make -C .. test"):
        d = protected_paths.check(Action(SHELL, str(proj), command=cmd), cfg)
        assert d.verdict == ALLOW, (cmd, d.reason)
    d = protected_paths.check(Action(SHELL, str(proj), command="cd build || ls .."), cfg)
    assert d.verdict == DENY  # not a plain sequence: `..` may still be read from proj


def test_each_folder_is_listed_once(tree, monkeypatch):
    from phiward import paths
    (tree / "repo" / "leak.txt").unlink()
    _many(tree / "repo" / "a", 50, suffix=".py")
    listed = []
    real = os.scandir
    monkeypatch.setattr(paths.os, "scandir", lambda p: (listed.append(p), real(p))[1])
    assert verdict(tree, "U", "ls **/*.py") == ALLOW
    assert any(str(p).startswith(str(tree / "repo" / "a")) for p in listed), listed
    assert len(listed) == len(set(listed)), listed


@pytest.mark.slow
def test_an_ordinary_large_repository_fits_the_budget(tree):
    (tree / "repo" / "leak.txt").unlink()
    for d in range(2000):
        _many(tree / "repo" / "pkg" / f"m{d:04d}", 40, suffix=".py")
    start = time.monotonic()
    for mode in ("U", "F"):
        assert verdict(tree, mode, "ls **/*.py", f"{tree}/repo/**/*.py") == ALLOW, mode
    assert time.monotonic() - start < 15.0


def test_many_double_stars_are_refused_fast(tree, monkeypatch):
    from phiward import paths
    monkeypatch.setattr(paths, "GLOB_BUDGET", 20000)
    (tree / "repo" / "leak.txt").unlink()
    _many(tree / "repo" / "a", 2000)
    start = time.monotonic()
    cfg = config.load(str(tree / "repo"))
    d = protected_paths.check(Action(SHELL, str(tree / "repo"),
                                     command="ls " + "/".join(["**"] * 40) + "/x"), cfg)
    assert d.verdict == DENY and "more entries than the guard checks" in d.reason, d.reason
    assert time.monotonic() - start < 5.0


def test_a_deeply_nested_group_is_refused(tree):
    p = f"{tree}/" + "@(" * 300 + "phi" + ")" * 300 + "/x"
    d = protected_paths.check(Action(FILE_SEARCH, str(tree / "repo"), paths=(p,)),
                              config.load(str(tree / "repo")))
    assert d.verdict == DENY and "nested deeper" in d.reason, d.reason


@pytest.mark.slow
@pytest.mark.parametrize("mode", MODES)
def test_many_links_are_checked_fast(tree, mode):
    (tree / "repo" / "leak.txt").unlink()
    b = tree / "repo" / "nm" / ".bin"
    b.mkdir(parents=True)
    for i in range(20000):
        os.symlink(f"../pkg{i}/cli.js", b / f"tool{i}")
    start = time.monotonic()
    v = verdict(tree, mode, "ls **/*.py", f"{tree}/repo/**/*.py")
    took = time.monotonic() - start
    assert v == ALLOW and took < 5.0, (v, took)


def test_a_file_root_with_a_non_ascii_name_is_found_by_a_wildcard(tree):
    (tree / "data").mkdir()
    (tree / "data" / "secrét.txt").write_text("x")
    Path(os.environ["PHIWARD_CONFIG"]).write_text(f'[protected_paths]\nroots = ["{tree}/data/secrét.txt"]\n')
    for cmd in (f"cat {tree}/data/secr?t.txt", f"cat {tree}/dat?/secr?t.txt"):
        assert verdict(tree, "U", cmd) == DENY, cmd


def test_before_setup_a_sandboxed_shell_lists_the_home_folder(tree):
    Path(os.environ["PHIWARD_CONFIG"]).write_text("")
    assert verdict(tree, "C", "ls ~/*") == ALLOW
