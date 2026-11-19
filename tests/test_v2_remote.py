"""`phiward run --remote HOST -- CMD`: the broker runs CMD on an HPC host with the
operator's ssh setup; only listed hosts and programs; output masked, remote roots included.
A fake ssh prints lines: no test connects anywhere."""

import io
import os
import stat
from pathlib import Path

import pytest

from phiward import copying, run
from helpers import needs_confine


def user_cfg(extra):
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + extra)


def remote_cfg(shared=False):
    # the tests that use a fake ssh without a shared connection take the older way
    user_cfg('[remote]\nhosts = ["hpc-test"]\ncommands = ["squeue", "wc"]\nroots = ["/data/protected"]\n'
             f'use_shared_connection = {"true" if shared else "false"}\n')


def test_parse_remote():
    a = run.parse(["--remote", "hpc-test", "--", "squeue", "-u", "me"])
    assert a.remote == "hpc-test" and a.cmd == ["squeue", "-u", "me"]
    assert run.parse(["--remote", "a", "--remote", "b", "--", "x"]) is None


@pytest.mark.parametrize("argv,why", [
    (["--remote", "other", "--", "squeue"], "[remote] hosts"),
    (["--remote", "hpc-test", "--", "rm", "-rf", "/data"], "[remote] commands"),
    (["--remote", "hpc-test", "--", "/usr/bin/squeue"], "[remote] commands"),
    (["--remote", "hpc-test", "--net", "--", "squeue"], "no --write-to or --net"),
])
def test_refusals(tree, argv, why):
    remote_cfg()
    out = io.StringIO()
    assert run.execute(argv, str(tree / "repo"), dict(os.environ), out) == 2
    assert why in out.getvalue(), out.getvalue()


def test_a_repo_config_cannot_grant_remote_hosts(tree):
    (tree / "repo" / ".phiward.toml").write_text('[remote]\nhosts = ["evil"]\ncommands = ["sh"]\n')
    out = io.StringIO()
    assert run.execute(["--remote", "evil", "--", "sh"], str(tree / "repo"), dict(os.environ), out) == 2


def test_every_word_is_quoted_for_the_remote_shell(tree, monkeypatch):
    monkeypatch.setattr(copying, "system_program", lambda name: "/usr/bin/ssh")
    from phiward import config, remote
    cfg = config.load(str(tree / "repo"))
    cfg.use_shared_connection = False  # the plain ssh route (its options are what is checked)
    rt, why = remote.route(cfg, "hpc-test")
    assert rt is not None, why
    cmd = run._remote_argv(rt, "hpc-test", ["wc", "-l", "a; rm -rf ~", "$(id)"])
    assert cmd[-1] == "wc -l 'a; rm -rf ~' '$(id)'"
    assert "BatchMode=yes" in cmd and "ProxyCommand=none" in cmd and "-T" in cmd


@needs_confine
def test_remote_output_is_masked(tree, monkeypatch):
    remote_cfg()
    fake = tree / "pub" / "fake-ssh"
    fake.parent.mkdir(exist_ok=True)
    fake.write_text("#!/bin/sh\necho \"ran: $(eval echo \\${$#})\"\n"
                    "echo '42 /data/protected/P-9990001-T01/sample.bam'\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(copying, "system_program", lambda name: str(fake))
    out = io.StringIO()
    code = run.execute(["--remote", "hpc-test", "--", "wc", "-l", "x"], str(tree / "repo"),
                       dict(os.environ), out)
    text = out.getvalue()
    assert code == 0, text
    assert "ran: wc -l x" in text and "42 <PROTECTED>" in text, text
    assert "/data/protected" not in text and "P-9990001" not in text, text


# --- remote paths and the remote shell ------------------------------------------------------------

@pytest.mark.parametrize("word", ["!#:1", "a!b", "x\ny", "x\ry", "tab\there", "\x1b[31m", "\x7f"])
def test_words_a_csh_login_shell_would_expand_are_refused(tree, word):
    # tcsh expands `!` even inside single quotes, and a newline ends a quoted word there:
    # quoting cannot make these plain text on every login shell
    remote_cfg()
    out = io.StringIO()
    argv = ["--remote", "hpc-test", "--", "wc", "-l", word]
    assert run.execute(argv, str(tree / "repo"), dict(os.environ), out) == 2
    assert "a character the remote shell may expand" in out.getvalue(), out.getvalue()


@pytest.mark.parametrize("dst", [
    "hpc-test:/work/me/x;id", "hpc-test:/work/me/$(id)", "hpc-test:/work/me/`id`",
    "hpc-test:/work/me/a b", "hpc-test:/work/me/a|b", "hpc-test:/work/me/a&b",
    "hpc-test:/work/me/a'b", "hpc-test:/work/me/a\"b", "hpc-test:/work/me/a\\b",
    "hpc-test:/work/me/a>b", "hpc-test:/work/me/*", "hpc-test:/work/me/a!b",
    "hpc-test:/work/me/~x", "hpc-test:/work/me/a\nb",
])
def test_a_remote_path_with_shell_characters_is_refused(tree, dst):
    # openrsync passes the remote path to the remote shell as it is
    from phiward import config
    # a remote root, so the push case is refused for its characters, not for a missing root
    user_cfg('[copy]\nremotes = ["hpc-test:/work/me"]\n[remote]\nroots = ["/work/me"]\n')
    (tree / "repo" / "f.txt").write_text("x\n")
    cfg = config.load(str(tree / "repo"))
    assert copying.plan(["f.txt", dst], str(tree / "repo"), cfg) is not None
    assert copying.plan([dst, str(tree / "phi")], str(tree / "repo"), cfg) is not None


def test_a_remote_spelling_rsync_reads_as_remote_is_checked(tree):
    # `host:path` without a leading slash is remote to rsync too; it must not pass as local
    from phiward import config
    user_cfg('[copy]\nremotes = ["hpc-test:/work/me"]\n')
    cfg = config.load(str(tree / "repo"))
    assert copying.plan(["evil:x;id", str(tree / "phi")], str(tree / "repo"), cfg) is not None
    assert copying.plan(["hpc-test:work/me/f", str(tree / "phi")], str(tree / "repo"), cfg) is not None


def test_a_plain_remote_path_is_still_allowed(tree):
    from phiward import config
    user_cfg('[copy]\nremotes = ["hpc-test:/work/me"]\n[remote]\nroots = ["/work/me"]\n')
    (tree / "repo" / "f.txt").write_text("x\n")
    cfg = config.load(str(tree / "repo"))
    assert copying.plan(["f.txt", "hpc-test:/work/me/sub/run-1.2_a+b"], str(tree / "repo"), cfg) is None


# --- masking and names files ----------------------------------------------------------------------

@pytest.mark.parametrize("line", ["10 /data/protected/a b.bam", "//data//protected/x",
                                  "/data/./protected/FAKE-PT-1 c", "du /data/protected"])
def test_remote_roots_are_masked_in_any_spelling(line):
    assert "protected" not in run.remote_root_regex("/data/protected").sub("<P>", line)


def test_a_neighbour_of_a_remote_root_stays(tmp_path):
    rx = run.remote_root_regex("/data/protected")
    assert rx.sub("<P>", "/data/protected2/ok") == "/data/protected2/ok"


def test_table_mode_is_the_operators_choice(tree):
    remote_cfg()
    out = io.StringIO()
    assert run.execute(["--remote", "hpc-test", "--table", "--", "wc", "-l", "f"],
                       str(tree / "repo"), dict(os.environ), out) == 2
    assert "[sanitize] table = true" in out.getvalue()
    out = io.StringIO()
    assert run.execute(["--table", "--", "wc", "-l", "f"], str(tree / "repo"), dict(os.environ), out) == 2
    assert "[sanitize] table = true" in out.getvalue()


def test_a_repo_config_cannot_turn_table_mode_on(tree):
    from phiward import config
    (tree / "repo" / ".phiward.toml").write_text("[sanitize]\ntable = true\n")
    assert not config.load(str(tree / "repo")).sanitize_table


@pytest.mark.parametrize("where", ["home/.ssh/id_fake", "repo/names.tsv", "pub/n.tsv"])
def test_a_names_file_outside_the_protected_paths_is_refused(tree, where):
    f = tree / where
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("FAKE-SECRET-TOKEN\n")
    out = io.StringIO()
    assert run.execute(["--names-from", str(f), "--", "wc", "-l", "README.md"],
                       str(tree / "repo"), dict(os.environ), out) == 2
    assert "inside a protected path" in out.getvalue()


def test_a_names_file_inside_a_protected_root_is_accepted(tree):
    from phiward import config
    (tree / "phi" / "samples.tsv").write_text("runs/FAKE-PT-0001/x.bam\n")
    a = run.parse(["--names-from", str(tree / "phi" / "samples.tsv"), "--", "wc"])
    assert run._sanitizer_options(a, str(tree / "repo"), config.load(str(tree / "repo")))[0] == ""


# --- more gateway fixes ---------------------------------------------------------------------------

@needs_confine
def test_a_gateway_command_cannot_read_credentials(tree):
    ssh = tree / "home" / ".ssh"
    ssh.mkdir()
    (ssh / "id_fake").write_text("FAKE-PRIVATE-KEY\n")
    out = io.StringIO()
    run.execute(["--", "cat", str(ssh / "id_fake")], str(tree / "repo"), dict(os.environ), out)
    assert "FAKE-PRIVATE-KEY" not in out.getvalue(), out.getvalue()


def test_a_names_file_through_a_link_or_with_two_names_is_refused(tree):
    from phiward import config
    cfg = config.load(str(tree / "repo"))
    (tree / "phi" / "n.tsv").write_text("runs/FAKE-PT-0001/x.bam\n")
    os.symlink(tree / "phi", tree / "repo" / "d")
    os.link(tree / "phi" / "n.tsv", tree / "phi" / "n2.tsv")
    for n in (str(tree / "phi" / "n.tsv"), "d/n.tsv"):
        a = run.parse(["--names-from", n, "--", "wc"])
        assert run._sanitizer_options(a, str(tree / "repo"), cfg)[0] == run.NAMES_OUTSIDE


def test_remote_roots_are_masked_before_local_entry_names(tree, monkeypatch):
    (tree / "phi" / "cohortx").mkdir()
    user_cfg('[remote]\nhosts = ["hpc-test"]\ncommands = ["wc"]\nroots = ["/gpfs/cohortx"]\n'
             'use_shared_connection = false\n')
    fake = tree / "pub" / "fake-ssh"
    fake.parent.mkdir(exist_ok=True)
    fake.write_text("#!/bin/sh\necho '12 /gpfs/cohortx/P-0012345-T01-IM6/sample a.bam'\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(copying, "system_program", lambda name: str(fake))
    out = io.StringIO()
    run.execute(["--remote", "hpc-test", "--", "wc", "-l", "x"], str(tree / "repo"),
                dict(os.environ), out)
    assert "12 <PROTECTED>" in out.getvalue() and "0012345" not in out.getvalue(), out.getvalue()


def test_a_copy_of_a_credential_is_refused(tree):
    from phiward import config
    user_cfg('[copy]\nremotes = ["hpc-test:/work/me"]\n')
    (tree / "home" / ".ssh").mkdir()
    (tree / "home" / ".ssh" / "id_fake").write_text("k\n")
    cfg = config.load(str(tree / "repo"))
    for src in (str(tree / "home" / ".ssh" / "id_fake"), str(tree / "home")):
        assert "credential" in (copying.plan([src, "hpc-test:/work/me/x"], str(tree / "repo"), cfg) or "")


# --- a push lands only under [remote] roots (issue #4) -------------------------------------------------

@pytest.mark.parametrize("roots,dst,ok", [
    ('', "hpc-test:/work/me/x", False),                       # no remote root: every push refused
    ('roots = ["/work/me/masked"]\n', "hpc-test:/work/me/x", False),
    ('roots = ["/work/me/masked"]\n', "hpc-test:/work/me/masked/x", True),
    ('roots = ["/work/me"]\n', "hpc-test:/work/me", True),
    ('roots = ["/work/me/a"]\n', "hpc-test:/work/me/ab", False),  # a prefix by text is not a root
])
def test_a_push_goes_only_under_remote_roots(tree, roots, dst, ok):
    from phiward import config
    user_cfg('[copy]\nremotes = ["hpc-test:/work/me"]\n' + ("[remote]\n" + roots if roots else ""))
    (tree / "repo" / "f.txt").write_text("x\n")
    cfg = config.load(str(tree / "repo"))
    why = copying.plan(["f.txt", dst], str(tree / "repo"), cfg)
    assert (why is None) is ok, why
    if not ok:
        assert "[remote] roots" in why
        out = io.StringIO()  # a dry run says the same
        assert copying.execute(["--dry-run", "f.txt", dst], str(tree / "repo"), dict(os.environ), out) == 2
        assert "[remote] roots" in out.getvalue()


def test_a_pull_needs_no_remote_root(tree):
    from phiward import config
    user_cfg('[copy]\nremotes = ["hpc-test:/work/me"]\n')
    cfg = config.load(str(tree / "repo"))
    assert copying.plan(["hpc-test:/work/me/res", str(tree / "phi")], str(tree / "repo"), cfg) is None


def test_doctor_warns_about_a_copy_remote_without_a_remote_root(tree, capsys, monkeypatch):
    from phiward import doctor
    user_cfg('[copy]\nremotes = ["hpc-test:/work/me"]\n')
    monkeypatch.chdir(tree / "repo")
    doctor.main([])
    out = capsys.readouterr().out
    assert "WARNING: 1 copy remote(s) are not under [remote] roots" in out, out
    user_cfg('[remote]\nroots = ["/work"]\n')
    doctor.main([])
    assert "not under [remote] roots" not in capsys.readouterr().out


def test_setup_makes_each_copy_remote_a_remote_root(tree, tmp_path):
    from phiward import config
    from test_v2_release_review import _drive_setup
    cfg_path = tmp_path / "config.toml"
    answers = ["3", str(tree / "phi"), "",    # profile, roots
               "", "",                        # patterns, write places
               "",                            # programs
               "n",                           # network for gateway commands
               "hpc-test:/work/me", "",       # copy remotes
               "n", "1", "n",                 # shell network, subject identifiers, HPC
               "y", "n", "n"]                 # write, wire, service
    code, out = _drive_setup(tree, answers, cfg_path)
    assert code == 0, out[-800:]
    cfg = config.load(str(tree / "repo"), env=dict(os.environ, PHIWARD_CONFIG=str(cfg_path)))
    assert cfg.remotes == ["hpc-test:/work/me"] and cfg.remote_roots == ["/work/me"]
