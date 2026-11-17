"""Fixes from the final review before the first public release."""

import os
from pathlib import Path

import pytest

from phiward import config, install
from phiward.core import DENY, FILE_WRITE, Action
from phiward.guards import protected_paths
from helpers import CONFINE_WHY


def _case_insensitive(folder: Path) -> bool:
    probe = folder / "phiward-Case-Probe"
    probe.write_text("x")
    try:
        return (folder / "PHIWARD-CASE-PROBE").exists()
    finally:
        probe.unlink()


def _write(tree, path):
    cfg = config.load(str(tree / "repo"))
    return protected_paths.check(Action(FILE_WRITE, str(tree / "repo"), paths=[str(path)]), cfg)


# --- the user config, written through another spelling ----------------------------------------

def test_the_user_config_is_refused_in_any_letter_case(tree):
    user = Path(os.environ["PHIWARD_CONFIG"])
    if not _case_insensitive(user.parent):
        pytest.skip("the file system tells letter cases apart: no case twin exists")
    assert _write(tree, user).verdict == DENY
    twin = user.parent / user.name.upper()
    assert _write(tree, twin).verdict == DENY


def test_a_case_twin_of_the_config_folder_is_refused(tree, monkeypatch):
    # the default place: the folder itself is guarded, so a new file in it is too
    home = tree / "home"
    cfgdir = home / ".config" / "phiward"
    cfgdir.mkdir(parents=True, exist_ok=True)
    (cfgdir / "config.toml").write_text(Path(os.environ["PHIWARD_CONFIG"]).read_text())
    monkeypatch.delenv("PHIWARD_CONFIG")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    if not _case_insensitive(cfgdir):
        pytest.skip("the file system tells letter cases apart: no case twin exists")
    for p in (cfgdir / "config.toml", home / ".config" / "PHIWARD" / "config.toml",
              home / ".Config" / "Phiward" / "new.toml"):
        assert _write(tree, p).verdict == DENY, p


def test_another_name_for_the_config_file_is_refused(tree):
    # the same file under another name: compared by what it is, not how it is spelled
    user = Path(os.environ["PHIWARD_CONFIG"])
    alias = tree / "repo" / "notes.toml"
    os.link(user, alias)
    assert _write(tree, alias).verdict == DENY


def test_the_config_is_refused_before_any_config_exists(tree, monkeypatch):
    # the first setup: nothing protects the config yet, so the file tools may not write it
    home = tree / "home"
    monkeypatch.delenv("PHIWARD_CONFIG")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    target = home / ".config" / "phiward" / "config.toml"
    assert not target.exists()
    cfg = config.load(str(tree / "repo"))
    assert not cfg.has_protected_paths
    d = protected_paths.check(Action(FILE_WRITE, str(tree / "repo"), paths=[str(target)]), cfg)
    assert d.verdict == DENY


def test_install_writes_edit_deny_rules_for_the_guard_files(tree):
    cfg = config.load(str(tree / "repo"))
    want = install.wiring(cfg)
    deny = want["permissions"]["deny"]
    user = os.environ["PHIWARD_CONFIG"]
    home = os.environ.get("HOME", "")
    spelled = "~" + user[len(home):] if home and user.startswith(home + "/") else "/" + user
    assert f"Edit({spelled})" in deny


# --- the broker takes the config it started with ----------------------------------------------

class _Spool:
    def exists(self, name):
        return False


def test_the_broker_refuses_requests_after_the_config_changes(tree):
    import io
    from phiward import broker
    b = broker.Broker(_Spool(), io.StringIO())
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + '\n[broker]\nnet = true\n')
    out = io.StringIO()
    code = b.execute("r1", {"cmd": "run", "args": ["--net", "--", "true"],
                            "cwd": str(tree / "repo")}, out)
    assert code == 3
    assert "changed since the broker started" in out.getvalue()


def test_the_broker_runs_requests_while_the_config_is_unchanged(tree, monkeypatch):
    import io
    from phiward import broker, run
    seen = []
    monkeypatch.setattr(run, "execute", lambda *a, **k: seen.append(a) or 0)
    b = broker.Broker(_Spool(), io.StringIO())
    code = b.execute("r1", {"cmd": "run", "args": ["--", "true"], "cwd": str(tree / "repo")},
                     io.StringIO())
    assert code == 0 and seen


# --- HPC: a remote names a work folder; a push plants nothing that runs at login ----------------

@pytest.mark.parametrize("remote,ok", [
    ("hpc:/", False), ("hpc:/home", False), ("hpc:/data", False), ("hpc:/home/u", False),
    ("hpc:/Users/u", False), ("hpc:/work/u/project", True), ("hpc:/scratch/u", True),
    ("hpc:/data/lab/u/test", True),
])
def test_a_copy_remote_must_name_a_work_folder(remote, ok):
    from phiward import copying, setup_cmd
    assert (setup_cmd.check_remote(remote) == "") is ok
    host_path = remote.split(":", 1)[1].rstrip("/") + "/x"
    assert copying._remote_ok("hpc:" + host_path, [remote]) is ok


def test_a_push_skips_files_that_run_at_login(tmp_path):
    from phiward import remote
    src = tmp_path / "payload"
    (src / ".ssh").mkdir(parents=True)
    (src / ".ssh" / "authorized_keys").write_text("key")
    (src / ".bashrc").write_text("evil")
    (src / "sub").mkdir()
    (src / "sub" / ".envrc").write_text("evil")
    (src / "results.tsv").write_text("ok")
    (src / "sub" / ".gitignore").write_text("ok")
    seen = []
    counts = remote.Counts()
    fd = os.open(src, os.O_RDONLY)
    try:
        remote._walk(fd, "", counts, 1 << 30, lambda n, f, st: seen.append(n))
    finally:
        os.close(fd)
    assert "results.tsv" in seen and "sub/.gitignore" in seen
    for bad in (".ssh", ".ssh/authorized_keys", ".bashrc", "sub/.envrc"):
        assert bad not in seen, bad
    assert counts.skipped >= 3


def test_a_push_source_named_like_a_login_file_is_skipped(tmp_path):
    from phiward import remote
    f = tmp_path / ".bashrc"
    f.write_text("evil")
    seen, counts = [], remote.Counts()
    fd = os.open(f, os.O_RDONLY)
    try:
        remote._walk(fd, ".bashrc", counts, 1 << 30, lambda n, d, st: seen.append(n))
    finally:
        os.close(fd)
    assert seen == [] and counts.skipped == 1 and counts.files == 0


# --- the login service and install: what they take from the caller's environment ---------------

def test_kerberos_variables_keep_their_type_prefix(monkeypatch, tmp_path):
    from phiward import service
    monkeypatch.setenv("KRB5CCNAME", "DIR:/home/u/.krb")
    monkeypatch.setenv("KRB5_CONFIG", str(tmp_path / "krb5.conf"))
    env = dict(service._env())
    assert env["KRB5CCNAME"] == "DIR:/home/u/.krb"
    assert env["KRB5_CONFIG"] == str(tmp_path / "krb5.conf")


def test_the_service_path_skips_folders_inside_a_project(tmp_path, monkeypatch):
    from phiward import service
    home = tmp_path / "home"
    proj = home / "proj"  # projects live below the home folder
    venv_bin = proj / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    (proj / ".git").mkdir()
    other = tmp_path / "tools" / "bin"
    other.mkdir(parents=True)
    for d in (venv_bin, other, home, proj, proj / ".venv", tmp_path / "tools"):
        os.chmod(d, 0o755)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(home)  # run from the home folder, as the docs say
    got = service._safe_path_entries(f"{venv_bin}:{other}")
    assert str(venv_bin) not in got and str(other) in got
    monkeypatch.chdir(proj)
    assert str(venv_bin) not in service._safe_path_entries(f"{venv_bin}:{other}")


# --- operator-only commands that change what launch sessions trust -----------------------------

@pytest.mark.parametrize("args", [["add", "x"], ["accept", "abc"], ["reset"]])
def test_carryover_changes_need_a_terminal(args, monkeypatch, capsys):
    from phiward import carryover
    monkeypatch.setattr("sys.stdin", open(os.devnull))
    assert carryover.main(args + ["--tool", "claude"]) == 2
    assert "own terminal" in capsys.readouterr().err


def test_a_remote_word_with_a_backslash_is_refused():
    # fish reads \' and \\ as escapes even inside single quotes
    from phiward import run
    assert run._UNQUOTABLE.search("x\\")
    assert run._UNQUOTABLE.search("a\\'b")
    assert not run._UNQUOTABLE.search("plain-word_1.txt")


# --- the re-check of these fixes ---------------------------------------------------------------

def test_the_broker_sees_a_change_behind_a_linked_config(tree, monkeypatch):
    import io
    from phiward import broker
    real = tree / "dotfiles" / "phiward.toml"
    real.parent.mkdir()
    user = Path(os.environ["PHIWARD_CONFIG"])
    real.write_text(user.read_text())
    link = tree / "home" / "linked.toml"
    link.symlink_to(real)
    monkeypatch.setenv("PHIWARD_CONFIG", str(link))
    b = broker.Broker(_Spool(), io.StringIO())
    real.write_text(real.read_text() + "\n[broker]\nnet = true\n")
    out = io.StringIO()
    assert b.execute("r1", {"cmd": "run", "args": ["--", "true"], "cwd": str(tree / "repo")},
                     out) == 3


def test_the_broker_keeps_working_after_a_same_content_save(tree, monkeypatch):
    import io
    from phiward import broker, run
    monkeypatch.setattr(run, "execute", lambda *a, **k: 0)
    b = broker.Broker(_Spool(), io.StringIO())
    user = Path(os.environ["PHIWARD_CONFIG"])
    text = user.read_text()
    tmp = user.with_name("x.tmp")
    tmp.write_text(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, user)  # an editor's atomic save, or `phiward setup` writing the same text
    assert b.execute("r1", {"cmd": "run", "args": ["--", "true"], "cwd": str(tree / "repo")},
                     io.StringIO()) == 0


def test_the_broker_sees_a_change_to_a_names_file(tree):
    import io
    from phiward import broker
    names = tree / "phi" / "names.txt"
    names.write_text("FAKE-PT-0001\n")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + f'\n[sanitize]\nnames_from = ["{names}"]\n')
    b = broker.Broker(_Spool(), io.StringIO())
    names.write_text("zzzz\n")
    out = io.StringIO()
    assert b.execute("r1", {"cmd": "run", "args": ["--", "true"], "cwd": str(tree / "repo")},
                     out) == 3
    assert "changed since the broker started" in out.getvalue()


def test_a_root_at_or_above_home_is_never_a_write_place(tree, monkeypatch):
    from phiward import config as cfgmod
    home = tree / "home"
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    assert cfgmod.runs_later_problem(str(home))
    assert cfgmod.runs_later_problem(str(tree))
    assert not cfgmod.runs_later_problem(str(tree / "phi"))


@pytest.mark.parametrize("remote", ["hpc:/gpfs/home/u", "hpc:/lila/home/u", "hpc:/home1/u",
                                    "hpc:/work/u/.ssh", "hpc:/work/u/x/.config"])
def test_more_home_like_remotes_and_dot_destinations_are_refused(remote):
    from phiward import copying, setup_cmd
    assert setup_cmd.check_remote(remote) != ""
    assert not copying._remote_ok(remote + "/x", [remote])


def test_a_copy_into_a_dot_folder_of_an_allowed_remote_is_refused():
    from phiward import copying
    assert copying._remote_ok("hpc:/work/u/project/results", ["hpc:/work/u/project"])
    assert not copying._remote_ok("hpc:/work/u/project/.ssh", ["hpc:/work/u/project"])
    assert not copying._remote_ok("hpc:/work/u/project/sub/.git/hooks", ["hpc:/work/u/project"])


def test_a_push_skips_every_dot_name_at_the_top_of_the_destination(tmp_path):
    from phiward import remote
    src = tmp_path / "payload"
    src.mkdir()
    for n in (".gitconfig", ".bash_aliases", ".vimrc", "results.tsv"):
        (src / n).write_text("x")
    (src / "sub").mkdir()
    (src / "sub" / ".gitignore").write_text("ok")
    seen, counts = [], remote.Counts()
    fd = os.open(src, os.O_RDONLY)
    try:
        remote._walk(fd, "", counts, 1 << 30, lambda n, d, st: seen.append(n))
    finally:
        os.close(fd)
    assert "results.tsv" in seen and "sub/.gitignore" in seen
    for bad in (".gitconfig", ".bash_aliases", ".vimrc"):
        assert bad not in seen


def test_the_service_path_keeps_home_tools_when_run_from_home(tmp_path, monkeypatch):
    from phiward import service
    home = tmp_path / "home"
    local_bin = home / ".local" / "bin"
    local_bin.mkdir(parents=True)
    (home / ".git").mkdir()  # a dotfiles repository in the home folder
    for d in (home, home / ".local", local_bin):
        os.chmod(d, 0o755)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(home)
    assert str(local_bin) in service._safe_path_entries(str(local_bin))


def test_dot_dot_after_a_linked_folder_is_resolved_like_the_kernel(tree, monkeypatch):
    home = tree / "home"
    cfgdir = home / ".config" / "phiward"
    cfgdir.mkdir(parents=True, exist_ok=True)
    (cfgdir / "config.toml").write_text(Path(os.environ["PHIWARD_CONFIG"]).read_text())
    monkeypatch.delenv("PHIWARD_CONFIG")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    (tree / "repo" / "lnk").symlink_to(cfgdir)
    d = _write(tree, tree / "repo" / "lnk" / ".." / "phiward" / "config.toml")
    assert d.verdict == DENY


# --- the gateway writes only where the operator granted it -------------------------------------

def _capture_writes(monkeypatch):
    from phiward import confine
    seen = {}

    def fake(argv, writable, patterns, *a, **k):
        seen["writable"], seen["patterns"] = list(writable), list(patterns)
        raise confine.ConfineError("captured")
    monkeypatch.setattr(confine, "gateway_command", fake)
    return seen


def test_a_gateway_run_writes_only_its_scratch_and_grants(tree, monkeypatch):
    import io
    from phiward import run
    from phiward.sanitize import Sanitizer
    seen = _capture_writes(monkeypatch)
    cfg = config.load(str(tree / "repo"))
    try:
        run.run_confined(["true"], cfg, Sanitizer.from_config(cfg), [], False, io.StringIO())
    except Exception:  # noqa: BLE001 - the fake stops it after the capture
        pass
    assert seen["patterns"] == []
    for r in cfg.user_roots:
        assert all(not w.startswith(os.path.realpath(r)) for w in seen["writable"]), r


def test_a_grant_may_sit_inside_a_root_but_not_above_one(tree):
    inside = tree / "phi" / "results"
    inside.mkdir()
    user = Path(os.environ["PHIWARD_CONFIG"])
    base = user.read_text()
    user.write_text(base + f'\n[broker]\nwrite_to = ["{inside}"]\n')
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem, cfg.problem
    assert any(w.endswith("/phi/results") for w in cfg.write_to)
    user.write_text(base + f'\n[broker]\nwrite_to = ["{tree}"]\n')
    assert config.load(str(tree / "repo")).problem


def test_a_grant_that_holds_a_names_file_is_refused(tree):
    out = tree / "phi" / "results"
    out.mkdir()
    names = out / "names.txt"
    names.write_text("FAKE-PT-0001\n")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + f'\n[sanitize]\nnames_from = ["{names}"]\n'
                    f'\n[broker]\nwrite_to = ["{out}"]\n')
    assert "names" in config.load(str(tree / "repo")).problem


def test_a_grant_where_code_runs_later_is_refused(tree, monkeypatch):
    bindir = tree / "home" / "bin"
    bindir.mkdir()
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + f'\n[broker]\nwrite_to = ["{bindir}"]\n')
    assert config.load(str(tree / "repo")).problem


# --- a push checks on the cluster that its destination is not the home folder -----------------

def _remote_push(tmp_path, dest, home):
    import io
    import subprocess
    import tarfile
    from phiward import remote
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("results.tsv")
        data = b"count\t3\n"
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    script = remote.receive_script(str(dest))
    return subprocess.run(["/bin/sh", "-c", script], input=buf.getvalue(), capture_output=True,
                          env={"HOME": str(home), "PATH": "/usr/bin:/bin"}, timeout=30)


@pytest.mark.parametrize("where", ["home", "above", "root", "linked-home"])
def test_a_push_refuses_the_remote_home_folder_or_above(tmp_path, where):
    home = tmp_path / "gpfs" / "homes" / "s" / "alice"
    home.mkdir(parents=True)
    (tmp_path / "work").mkdir()
    link = tmp_path / "work" / "me"
    link.symlink_to(home)
    dest = {"home": home, "above": home.parent, "root": Path("/"), "linked-home": link}[where]
    r = _remote_push(tmp_path, dest, home)
    assert r.returncode != 0
    assert not (home / "results.tsv").exists()


def test_a_push_below_the_remote_home_folder_works(tmp_path):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    dest = home / "project" / "in"
    r = _remote_push(tmp_path, dest, home)
    assert r.returncode == 0, r.stderr
    assert (dest / "results.tsv").read_text() == "count\t3\n"


@pytest.mark.skipif(not os.path.isdir("/System/Volumes/Data/private"), reason="macOS firmlinks")
def test_the_config_is_refused_through_the_data_volume_before_its_folder_exists(tree, monkeypatch):
    home = tree / "home"
    monkeypatch.delenv("PHIWARD_CONFIG")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    real = os.path.realpath(home)
    target = "/System/Volumes/Data" + real + "/.config/phiward/config.toml"
    assert not os.path.exists(os.path.dirname(target))
    cfg = config.load(str(tree / "repo"))
    d = protected_paths.check(Action(FILE_WRITE, str(tree / "repo"), paths=[target]), cfg)
    assert d.verdict == DENY


def test_the_service_path_keeps_a_tool_folder_in_a_git_tree_outside_home(tmp_path, monkeypatch):
    # Apple Silicon Homebrew keeps /opt/homebrew/.git
    from phiward import service
    home = tmp_path / "home"
    home.mkdir()
    brew = tmp_path / "opt" / "homebrew"
    (brew / "bin").mkdir(parents=True)
    (brew / ".git").mkdir()
    for d in (tmp_path / "opt", brew, brew / "bin", home):
        os.chmod(d, 0o755)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(home)
    assert str(brew / "bin") in service._safe_path_entries(str(brew / "bin"))


# --- a copy's destination: inside a root, by its real path, with no link on the way -------------

def _place(tree, dst):
    from phiward import copying
    cfg = config.load(str(tree / "repo"))
    return copying.dest_place(dst, str(tree / "repo"), cfg)


def test_a_copy_destination_through_a_link_out_of_the_root_is_refused(tree):
    out = tree / "repo" / "out"
    out.mkdir()
    (tree / "phi" / "sub").mkdir(exist_ok=True)
    (tree / "phi" / "sub" / "evil").symlink_to(out)
    _, why = _place(tree, str(tree / "phi" / "sub" / "evil") + "/")
    assert why


def test_a_copy_destination_that_holds_a_names_file_is_refused(tree):
    names = tree / "phi" / "names.txt"
    names.write_text("FAKE-PT-0001\n")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + f'\n[sanitize]\nnames_from = ["{names}"]\n')
    _, why = _place(tree, str(names))
    assert why


def test_a_copy_destination_outside_every_root_is_refused(tree):
    _, why = _place(tree, str(tree / "repo" / "x"))
    assert why


def test_a_copy_into_a_root_works(tree):
    (tree / "phi" / "sub").mkdir(exist_ok=True)
    for dst in (tree / "phi" / "sub" / "new.bam", tree / "phi" / "sub", tree / "phi" / "x.bam"):
        place, why = _place(tree, str(dst))
        assert not why, (dst, why)


def test_a_copy_destination_must_be_inside_a_root_not_a_pattern_match(tree):
    (tree / "runs" / "run9" / "panel").mkdir(parents=True, exist_ok=True)
    _, why = _place(tree, str(tree / "runs" / "run9" / "panel") + "/")
    assert why


def test_a_copy_destination_through_a_claude_folder_is_refused(tree):
    (tree / "phi" / "proj" / ".claude").mkdir(parents=True)
    _, why = _place(tree, str(tree / "phi" / "proj" / ".claude") + "/")
    assert why


def test_a_local_copy_and_a_pull_leave_claude_folders_out():
    from phiward import copying, remote
    cmd = copying.rsync_command(["a", "b"], False)
    if cmd is not None:
        assert "--exclude=.claude/" in cmd
    assert ".claude" in remote.EXTRACT_PY


def test_the_destination_checks_compare_by_identity(tree, monkeypatch):
    # a volume that ignores letter case on Linux: compared by device and inode, not by name
    from phiward import copying
    names = tree / "phi" / "sub" / "names.txt"
    names.parent.mkdir(exist_ok=True)
    names.write_text("x\n")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + f'\n[sanitize]\nnames_from = ["{names}"]\n')
    monkeypatch.setattr(config, "_folded", lambda p: [os.path.normpath(p)])  # no case folding
    config.load(str(tree / "repo"))
    assert copying._holds(str(tree / "phi" / "sub"), str(names))
    assert not copying._holds(str(tree / "repo"), str(names))


# --- the last items before the release ----------------------------------------------------------

def test_a_local_copy_makes_missing_destination_folders(tree):
    import io
    from phiward import copying
    if CONFINE_WHY is not None:
        pytest.skip("no confinement backend")
    out = io.StringIO()
    dst = tree / "phi" / "new1" / "new2"
    code = copying.execute([str(tree / "phi" / "FAKE-PT-0001.bam"), str(dst) + "/"],
                           str(tree / "repo"), dict(os.environ), out)
    assert code == 0, out.getvalue()
    assert (dst / "FAKE-PT-0001.bam").exists()


def test_the_cp_fallback_refuses_folders(tree, monkeypatch):
    import io
    from phiward import copying
    real = copying.system_program
    monkeypatch.setattr(copying, "system_program",
                        lambda n: None if n == "rsync" else real(n))
    src = tree / "repo" / "proj"
    (src / ".claude").mkdir(parents=True)
    (src / ".claude" / "settings.json").write_text("{}")
    (tree / "phi" / "copies").mkdir()
    out = io.StringIO()
    code = copying.execute([str(src), str(tree / "phi" / "copies") + "/"], str(tree / "repo"),
                           dict(os.environ), out)
    assert code == 2 and "rsync" in out.getvalue()
    assert not (tree / "phi" / "copies" / "proj").exists()


@pytest.mark.skipif(not os.path.isdir("/System/Volumes/Data/private"), reason="macOS firmlinks")
def test_a_copy_place_is_in_the_file_systems_own_spelling(tree):
    (tree / "phi" / "sub").mkdir(exist_ok=True)
    real = os.path.realpath(tree / "phi" / "sub")
    place, why = _place(tree, "/System/Volumes/Data" + real + "/")
    assert not why and not place.startswith("/System/Volumes/Data"), (place, why)


def test_install_denies_every_kerberos_pattern_the_hook_refuses(tree):
    from phiward import hidden
    cfg = config.load(str(tree / "repo"))
    deny = install.wiring(cfg)["sandbox"]["filesystem"]["denyRead"]
    for pat in hidden.KRB5_NAME_PATTERNS:
        assert pat in deny, pat


def test_coverage_counts_only_rules_in_the_file_systems_own_spelling(tmp_path):
    # "covered by the sandbox" relaxes the hook, so a rule counts only in the spelling the
    # kernel compares: the canonical one, exactly
    import unicodedata
    from phiward import claude_settings, pathid
    folder = tmp_path / unicodedata.normalize("NFC", "Caf\u00e9")
    folder.mkdir()
    canon = pathid.canon(str(folder))
    assert claude_settings._covers([canon], str(folder))
    assert claude_settings._covers([os.path.dirname(canon)], str(folder))
    nfd = os.path.dirname(canon) + "/" + unicodedata.normalize("NFD", os.path.basename(canon))
    twin = os.path.dirname(canon) + "/" + os.path.basename(canon).lower()
    for spelled in (nfd, twin):
        if spelled != canon:
            assert not claude_settings._covers([spelled], str(folder)), spelled


def test_install_writes_sandbox_entries_in_the_canonical_spelling(tree, monkeypatch):
    real = tree / "phi"
    if not os.path.exists(str(tree / "PHI")):
        pytest.skip("the file system tells letter cases apart")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text().replace(str(real), str(tree / "PHI")))
    cfg = config.load(str(tree / "repo"))
    deny = install.wiring(cfg)["sandbox"]["filesystem"]["denyRead"]
    assert any(d.endswith("/phi") for d in deny) and not any(d.endswith("/PHI") for d in deny)


# --- usability: refusals say what to do next ----------------------------------------------------

def test_a_refused_write_says_how_to_get_a_grant(tree):
    import io
    from phiward import run
    if CONFINE_WHY is not None:
        pytest.skip("no confinement backend")
    out = io.StringIO()
    code = run.execute(["--", "sh", "-c", "echo x > ../phi/new.txt"], str(tree / "repo"),
                       dict(os.environ), out)
    assert code != 0 and not (tree / "phi" / "new.txt").exists()
    assert "--write-to" in out.getvalue() and "phiward setup" in out.getvalue()


# --- the Fable reviews -------------------------------------------------------------------------

def test_other_launch_sessions_folders_are_hidden_from_the_gateway_and_mode_a(tree):
    from phiward import hidden
    tools = os.path.join(os.environ["HOME"], ".phiward", "tools")
    cfg = config.load(str(tree / "repo"))
    assert tools in hidden.paths(dict(os.environ), cfg)                # the gateway
    assert tools in hidden.paths(None, cfg, session=True)             # the hook and install
    deny = install.wiring(cfg)["sandbox"]["filesystem"]["denyRead"]
    assert any(d.endswith("/.phiward/tools") for d in deny)
    d = protected_paths.check(Action(FILE_WRITE, str(tree / "repo"),
                                     paths=[tools + "/claude/runs/x/config/.credentials.json"]), cfg)
    assert d.verdict == DENY


def test_an_unquoted_wildcard_in_a_gateway_call_is_refused_without_a_sandbox(tree):
    from phiward.core import SHELL
    (tree / "repo" / "lnk").symlink_to(tree / "phi")
    cfg = config.load(str(tree / "repo"))
    cmd = "phiward run -- wc -l ./*/*.bam"
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command=cmd, confined=False), cfg)
    assert d.verdict == DENY
    quoted = "phiward run -- sh -c 'wc -l ./*/*.bam'"
    d = protected_paths.check(Action(SHELL, str(tree / "repo"), command=quoted, confined=False), cfg)
    assert d.verdict != DENY


def test_a_call_that_asks_to_leave_the_sandbox_counts_as_unconfined(tree, monkeypatch):
    import io
    import json as _json
    from phiward import adapters
    from phiward.adapters import claude
    from phiward.core import ALLOWED
    seen = []
    monkeypatch.setattr(adapters, "decide", lambda a, claude_sandbox=False:
                        seen.append(claude_sandbox) or ALLOWED)
    base = {"tool_name": "Bash", "permission_mode": "default", "cwd": str(tree / "repo"),
            "hook_event_name": "PreToolUse", "tool_input": {"command": "ls"}}
    leave = dict(base, tool_input={"command": "ls", "dangerouslyDisableSandbox": True})
    for p in (base, leave):
        claude.main(io.StringIO(_json.dumps(p)), io.StringIO(), io.StringIO())
    assert seen == [True, False]


def test_every_copy_of_the_version_agrees():
    import json as _json
    import re as _re
    from phiward import __version__
    root = Path(__file__).resolve().parents[1]
    py = (root / "pyproject.toml").read_text()
    assert 'dynamic = ["version"]' in py and 'version = {attr = "phiward.__version__"}' in py
    assert _json.loads((root / "plugin/.claude-plugin/plugin.json").read_text())["version"] == __version__
    market = _json.loads((root / ".claude-plugin/marketplace.json").read_text())
    assert all(p["version"] == __version__ for p in market["plugins"])
    for doc in ("README.md", "docs/quickstart.md", "docs/setup.md", "docs/plugins.md",
                "plugin/commands/setup.md"):
        text = (root / doc).read_text()
        tags = set(_re.findall(r"phiward@v([0-9][0-9a-z.]*)", text))
        tags |= set(_re.findall(r"phiward==([0-9][0-9a-z.]*)", text))
        tags |= set(_re.findall(r"phiward#v([0-9][0-9a-z.]*)", text))
        assert tags <= {__version__}, (doc, tags)


# --- copies never replace existing files; pushes send no executable bit -------------------------

def test_a_push_sends_files_without_the_executable_bit(tmp_path):
    import io
    import tarfile
    from phiward import remote
    src = tmp_path / "proj"
    src.mkdir()
    script = src / "run.sh"
    script.write_text("echo hi\n")
    os.chmod(script, 0o755)
    buf = io.BytesIO()
    remote.feeder(remote.resolve([str(src) + "/"], str(tmp_path)), 1 << 30, remote.Counts())(buf)
    buf.seek(0)
    with tarfile.open(fileobj=buf) as t:
        modes = {m.name: m.mode for m in t.getmembers()}
    assert modes["run.sh"] == 0o644


def test_a_push_keeps_existing_remote_files(tmp_path):
    home = tmp_path / "home" / "alice"
    dest = home / "work"
    dest.mkdir(parents=True)
    (dest / "results.tsv").write_text("mine\n")
    r = _remote_push(tmp_path, dest, home)
    assert (dest / "results.tsv").read_text() == "mine\n", r.stderr


def test_a_local_copy_keeps_existing_files(tree):
    import io
    from phiward import copying
    if CONFINE_WHY is not None:
        pytest.skip("no confinement backend")
    (tree / "phi" / "copies").mkdir()
    keep = tree / "phi" / "copies" / "run.sh"
    keep.write_text("the operator's script\n")
    new = tree / "repo" / "run.sh"
    new.write_text("evil\n")
    out = io.StringIO()
    copying.execute([str(new), str(tree / "phi" / "copies") + "/"], str(tree / "repo"),
                    dict(os.environ), out)
    assert keep.read_text() == "the operator's script\n"


# --- the agent sees success or failure only; the operator's log has the real status ------------

def test_the_agent_sees_only_success_or_failure(tree):
    import io
    from phiward import run
    if CONFINE_WHY is not None:
        pytest.skip("no confinement backend")
    logged = []
    run.log.fn = logged.append
    try:
        out = io.StringIO()
        code = run.execute(["--", "sh", "-c", "exit 42"], str(tree / "repo"), dict(os.environ),
                           out)
    finally:
        run.log.fn = None
    assert code == 1
    text = out.getvalue()
    assert "exit=1" in text and "42" not in text and "lines=" not in text
    assert any("exit 42" in m for m in logged)
    out = io.StringIO()
    assert run.execute(["--", "sh", "-c", "exit 0"], str(tree / "repo"), dict(os.environ), out) == 0
    assert "exit=0" in out.getvalue()


def test_the_service_logs_to_a_folder_no_session_reads(tree):
    from phiward import hidden, service
    folder = service.log_folder()
    assert folder in service.render("/usr/local/bin/phiward")
    cfg = config.load(str(tree / "repo"))
    assert folder in hidden.paths(dict(os.environ), cfg)
    assert folder in hidden.paths(None, cfg, session=True)


# --- [broker] commands: the programs gateway commands may run (strict mode) ---------------------

def _run(tree, words):
    import io
    from phiward import run
    out = io.StringIO()
    code = run.execute(["--"] + words, str(tree / "repo"), dict(os.environ), out)
    return code, out.getvalue()


def test_without_a_program_list_any_program_runs(tree):
    if CONFINE_WHY is not None:
        pytest.skip("no confinement backend")
    assert _run(tree, ["true"])[0] == 0


def test_with_a_program_list_only_listed_programs_run(tree):
    if CONFINE_WHY is not None:
        pytest.skip("no confinement backend")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + '\n[broker]\ncommands = ["wc", "true"]\n')
    assert _run(tree, ["true"])[0] == 0
    code, out = _run(tree, ["sh", "-c", "true"])
    assert code == 2 and "[broker] commands" in out
    code, out = _run(tree, ["python3", "-c", "print(1)"])
    assert code == 2


def test_a_repo_program_list_can_only_narrow_the_users(tree):
    if CONFINE_WHY is not None:
        pytest.skip("no confinement backend")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + '\n[broker]\ncommands = ["wc", "true"]\n')
    (tree / "repo" / ".phiward.toml").write_text('[broker]\ncommands = ["true", "sh"]\n')
    assert _run(tree, ["true"])[0] == 0
    assert _run(tree, ["sh", "-c", "true"])[0] == 2   # the repo list cannot add sh
    assert _run(tree, ["wc", "-l", "/dev/null"])[0] == 2  # the repo list leaves wc out


# --- the re-check of the program list and the copies ------------------------------------------

def _tool(folder, name, body="#!/bin/sh\necho tool\n"):
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / name
    p.write_text(body)
    os.chmod(p, 0o755)
    os.chmod(folder, 0o755)
    return p


def test_a_listed_program_changed_after_the_broker_starts_stops_the_broker(tree, monkeypatch):
    import io
    import time
    from phiward import broker
    bindir = tree / "tools" / "bin"
    tool = _tool(bindir, "mytool")
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + '\n[broker]\ncommands = ["mytool"]\n')
    from phiward import pin
    pin.write_pins(config.load(str(tree / "repo")))  # approved, as setup does
    b = broker.Broker(_Spool(), io.StringIO())
    time.sleep(0.01)
    tool.write_text("#!/bin/sh\necho evil\n")  # rewritten in place
    out = io.StringIO()
    assert b.execute("r1", {"cmd": "run", "args": ["--", "mytool"], "cwd": str(tree / "repo")},
                     out) == 3
    assert "changed since the broker started" in out.getvalue()


def test_a_new_program_of_a_listed_name_earlier_on_path_stops_the_broker(tree, monkeypatch):
    import io
    from phiward import broker
    later = tree / "tools" / "bin"
    _tool(later, "mytool")
    first = tree / "tools" / "first"
    first.mkdir(parents=True)
    os.chmod(first, 0o755)
    monkeypatch.setenv("PATH", f"{first}:{later}:/usr/bin:/bin")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + '\n[broker]\ncommands = ["mytool"]\n')
    from phiward import pin
    pin.write_pins(config.load(str(tree / "repo")))  # approved, as setup does
    b = broker.Broker(_Spool(), io.StringIO())
    _tool(first, "mytool", "#!/bin/sh\necho evil\n")
    assert b.execute("r1", {"cmd": "run", "args": ["--", "mytool"], "cwd": str(tree / "repo")},
                     io.StringIO()) == 3


def test_a_preset_and_a_scripts_folder_in_the_program_list(tree, monkeypatch):
    from phiward import run
    scripts = tree / "home" / "pipelines" / "bin"
    mine = _tool(scripts, "count_reads.sh")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + f'\n[broker]\ncommands = ["@counts", "{scripts}/"]\n')
    cfg = config.load(str(tree / "repo"))
    assert run.program_listed("wc", "/usr/bin/wc", cfg)
    assert not run.program_listed("python3", "/usr/bin/python3", cfg)
    assert run.program_listed(str(mine), os.path.realpath(mine), cfg)
    other = _tool(tree / "repo", "evil.sh")
    assert not run.program_listed(str(other), os.path.realpath(other), cfg)


def test_listed_scripts_are_protected_from_agent_writes(tree):
    scripts = tree / "home" / "pipelines" / "bin"
    _tool(scripts, "count_reads.sh")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + f'\n[broker]\ncommands = ["{scripts}/"]\n')
    cfg = config.load(str(tree / "repo"))
    deny = install.wiring(cfg)["sandbox"]["filesystem"]["denyWrite"]
    assert any(d.rstrip("/").endswith("pipelines/bin") for d in deny), deny[:5]
    d = protected_paths.check(Action(FILE_WRITE, str(tree / "repo"),
                                     paths=[str(scripts / "count_reads.sh")]), cfg)
    assert d.verdict == DENY


def test_doctor_warns_about_listed_programs_that_run_other_code(tree, capsys):
    from phiward import doctor
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + '\n[broker]\ncommands = ["wc", "git", "python3"]\n')
    doctor.main([])
    out = capsys.readouterr().out
    assert "can run other code" in out


def test_no_preset_holds_a_program_that_runs_other_code():
    for name, progs in config.COMMAND_PRESETS.items():
        assert not set(progs) & config.LAUNCHERS, name


def test_a_local_copy_refuses_to_change_the_type_of_what_exists(tree):
    import io
    from phiward import copying
    if CONFINE_WHY is not None:
        pytest.skip("no confinement backend")
    dst = tree / "phi" / "copies"
    dst.mkdir()
    keep = dst / "run.sh"
    keep.write_text("the operator's script\n")
    src = tree / "repo" / "run.sh"
    src.mkdir()
    (src / "x").write_text("x")
    out = io.StringIO()
    code = copying.execute([str(tree / "repo" / "run.sh"), str(dst) + "/"], str(tree / "repo"),
                           dict(os.environ), out)
    assert code == 2 and keep.is_file() and keep.read_text() == "the operator's script\n"


def test_a_local_copy_carries_no_modes_and_no_links(tree):
    from phiward import copying
    cmd = copying.rsync_command(["a", "b"], False)
    if cmd is None:
        pytest.skip("no rsync")
    assert "-a" not in cmd and "-rt" in cmd and "--ignore-existing" in cmd


def test_the_pull_extractor_keeps_what_exists_and_skips_what_is_unsafe(tmp_path):
    import io
    import subprocess
    import sys
    import tarfile
    from phiward import remote
    dest = tmp_path / "dest"
    (dest / "keepdir").mkdir(parents=True)
    os.chmod(dest / "keepdir", 0o700)
    (dest / "old.txt").write_text("mine\n")

    def add(t, name, data=b"x", kind=tarfile.REGTYPE, mode=0o755, link=""):
        ti = tarfile.TarInfo(name)
        ti.type, ti.mode, ti.linkname = kind, mode, link
        ti.size = len(data) if kind == tarfile.REGTYPE else 0
        t.addfile(ti, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        add(t, "keepdir", kind=tarfile.REGTYPE)          # a file over an existing folder
        add(t, "old.txt", b"evil\n")                     # an existing file
        add(t, "new/res.tsv", b"count\t3\n")             # a new file in a new folder
        add(t, "../escape.txt")                          # outside
        add(t, "/abs.txt", b"a\n")                       # absolute: lands inside, stripped
        add(t, "lnk", kind=tarfile.SYMTYPE, link="/etc")  # a link
        add(t, "proj/.claude/settings.json", b"{}")       # a .claude folder
    r = subprocess.run([sys.executable, "-I", "-c", remote.EXTRACT_PY, str(dest)],
                       input=buf.getvalue(), capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert (dest / "keepdir").is_dir() and (os.stat(dest / "keepdir").st_mode & 0o777) == 0o700
    assert (dest / "old.txt").read_text() == "mine\n"
    assert (dest / "new" / "res.tsv").read_text() == "count\t3\n"
    assert os.stat(dest / "new" / "res.tsv").st_mode & 0o777 == 0o644
    assert not (tmp_path / "escape.txt").exists()
    assert (dest / "abs.txt").read_text() == "a\n"
    assert not os.path.lexists(dest / "lnk")
    assert not (dest / "proj" / ".claude").exists()


# --- defaults that lower the overhead ---------------------------------------------------------

def test_a_single_write_place_needs_no_write_to(tree):
    import io
    from phiward import run
    if CONFINE_WHY is not None:
        pytest.skip("no confinement backend")
    res = tree / "phi" / "results"
    res.mkdir()
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + f'\n[broker]\nwrite_to = ["{res}"]\n')
    out = io.StringIO()
    code = run.execute(["--", "sh", "-c", f"echo 3 > {res}/n.txt"], str(tree / "repo"),
                       dict(os.environ), out)
    assert code == 0, out.getvalue()
    assert (res / "n.txt").read_text() == "3\n"


def test_the_service_loads_or_restarts_itself(monkeypatch):
    from phiward import service
    calls = []

    class R:
        def __init__(self, rc):
            self.returncode = rc

    def fake(cmd, **k):
        calls.append(cmd)
        loaded = "print" in cmd or "is-enabled" in cmd
        return R(0 if loaded else 0)
    assert service.load("/x/svc", runner=fake)
    if __import__("sys").platform == "darwin":
        assert any("kickstart" in c for c in calls)   # already loaded: restarted
    else:
        assert any("restart" in c for c in calls)
    calls.clear()

    def fake_new(cmd, **k):
        calls.append(cmd)
        return R(1 if ("print" in cmd or "is-enabled" in cmd) else 0)
    assert service.load("/x/svc", runner=fake_new)
    if __import__("sys").platform == "darwin":
        assert any("bootstrap" in c for c in calls)
    else:
        assert any("enable" in c for c in calls)


def _drive_setup(tree, answers, cfg_path, extra=(), timeout=40):
    import pty
    import select
    import subprocess
    import sys
    import time
    launch = ("import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; "
              "from phiward.cli import main; sys.exit(main())")
    src = str(Path(__file__).resolve().parents[1] / "src")
    master, slave = pty.openpty()
    env = dict(os.environ, PYTHONPATH=src, PHIWARD_CONFIG=str(cfg_path))
    p = subprocess.Popen([sys.executable, "-c", launch, "setup", *extra],
                         cwd=str(tree / "repo"), stdin=slave, stdout=slave, stderr=slave, env=env)
    os.close(slave)
    seen, left, end = b"", list(answers), time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.2)
        if r:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            seen += chunk
            if left and seen.rstrip().endswith((b"]", b">")):
                os.write(master, left.pop(0).encode() + b"\n")
        elif p.poll() is not None:
            break
    p.wait(timeout=10)
    os.close(master)
    return p.returncode, seen.decode("utf-8", "replace")


def test_setup_profile_for_real_data_sets_strict_defaults(tree, tmp_path):
    cfg_path = tmp_path / "cfg" / "config.toml"
    cfg_path.parent.mkdir()
    answers = ["1", str(tree / "phi"), "",      # profile, roots
               "",                              # results folder: the suggestion
               "",                              # no scripts folder
               "n",                             # no limit on the shell's network
               "y", "hpc", "login.example.org", "alice", "/work/alice/proj",  # HPC
               "",                              # cluster folders to mask: the work folder
               "y", "y", "n", "n"]              # write, approve programs, wire, service
    code, out = _drive_setup(tree, answers, cfg_path)
    assert code == 0, out
    cfg = config.load(str(tree / "repo"), env=dict(os.environ, PHIWARD_CONFIG=str(cfg_path)))
    assert not cfg.problem, cfg.problem
    assert (tree / "phi" / "phiward-results").is_dir()
    assert cfg.write_to and cfg.write_to[0].endswith("phiward-results")
    assert cfg.command_lists == [["@genomics"]]
    assert cfg.net is False
    assert cfg.remotes == ["hpc:/work/alice/proj"] and cfg.remote_hosts == ["hpc"]
    assert cfg.remote_roots == ["/work/alice/proj"]
    assert "kinit" in out and "add only the three Control lines" in out
    assert "Approve these" in out and "(new)" in out
    from phiward import pin
    pe = dict(os.environ, PHIWARD_CONFIG=str(cfg_path))
    assert pin.unapproved(cfg, pe) == []  # approved after the yes
    ssh = (cfg_path.parent / "ssh_config").read_text()
    assert "HostName login.example.org" in ssh and "ControlMaster no" in ssh
    assert "ControlPersist 8h" in out  # the lines for ~/.ssh/config


def test_setup_profile_for_made_up_data_keeps_open_defaults(tree, tmp_path):
    cfg_path = tmp_path / "config.toml"
    code, out = _drive_setup(tree, ["2", str(tree / "phi"), "", "", "y", "n", "n"], cfg_path)
    assert code == 0, out
    cfg = config.load(str(tree / "repo"), env=dict(os.environ, PHIWARD_CONFIG=str(cfg_path)))
    assert not cfg.problem and cfg.command_lists == [] and cfg.write_to


def test_setup_from_a_team_template(tree, tmp_path):
    team = tmp_path / "team.toml"
    team.write_text('[broker]\ncommands = ["@counts"]\n\n[remote]\ncommands = ["squeue"]\n')
    cfg_path = tmp_path / "config.toml"
    answers = ["y",                           # use the team settings
               "3", str(tree / "phi"), "",   # profile, roots
               "",                            # patterns
               "",                            # write places
               "n", "",                       # programs: keep the team's list, add none
               "n", "", "n", "n",             # network, remotes, shell network, HPC
               "y", "y", "n", "n"]            # write, approve programs, wire, service
    code, out = _drive_setup(tree, answers, cfg_path, extra=("--from", str(team)))
    assert code == 0, out
    cfg = config.load(str(tree / "repo"), env=dict(os.environ, PHIWARD_CONFIG=str(cfg_path)))
    assert cfg.command_lists == [["@counts"]] and cfg.remote_commands == ["squeue"]
    assert "Team template" in out


def test_setup_refuses_a_team_template_with_unknown_keys(tree, tmp_path):
    team = tmp_path / "team.toml"
    team.write_text('[broker]\nsomething = true\n')
    code, out = _drive_setup(tree, [], tmp_path / "config.toml", extra=("--from", str(team)))
    assert code == 2 and "does not know" in out


# --- the review of the defaults -------------------------------------------------------------

@pytest.mark.parametrize("body", [
    '[broker]\nnet = true\n',
    '[broker]\nwrite_to = ["/tmp"]\n',
    '[copy]\nssh_config = "/tmp/x"\n',
    '[launch]\npass_env = ["KRB5CCNAME"]\n',
    '[sanitize]\nnames_from = ["/tmp/n"]\n',
    '[copy]\nremotes = ["hpc:/work/x/y"]\n',
    '[sanitize]\npacks = ["/tmp/pack.toml"]\n',
])
def test_a_team_template_may_not_carry_grants(tree, tmp_path, body):
    team = tmp_path / "team.toml"
    team.write_text(body)
    code, out = _drive_setup(tree, [], tmp_path / "config.toml", extra=("--from", str(team)))
    assert code == 2 and "team template" in out.lower()


def test_a_team_template_inside_a_project_is_refused(tree, tmp_path):
    (tree / "repo" / ".git").mkdir(exist_ok=True)
    team = tree / "repo" / "team.toml"
    team.write_text('[broker]\ncommands = ["@counts"]\n')
    code, out = _drive_setup(tree, [], tmp_path / "config.toml", extra=("--from", str(team)))
    assert code == 2 and "project" in out.lower()


def test_a_team_template_is_shown_and_must_be_approved(tree, tmp_path):
    team = tmp_path / "team.toml"
    team.write_text('[broker]\ncommands = ["@counts"]\n')
    # "n" to the team settings: setup stops before any question
    code, out = _drive_setup(tree, ["n"], tmp_path / "config.toml", extra=("--from", str(team)))
    assert "commands" in out and "@counts" in out
    assert not (tmp_path / "config.toml").exists()


def test_listed_programs_run_only_after_the_operator_approves_them(tree, monkeypatch):
    import io
    from phiward import broker, pin, run
    monkeypatch.setattr(run, "execute", lambda *a, **k: 0)
    bindir = tree / "tools" / "bin"
    tool = _tool(bindir, "mytool")
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + '\n[broker]\ncommands = ["mytool"]\n')
    req = {"cmd": "run", "args": ["--", "mytool"], "cwd": str(tree / "repo")}
    out = io.StringIO()
    assert broker.Broker(_Spool(), io.StringIO()).execute("r1", req, out) == 3  # not approved yet
    assert "phiward pin" in out.getvalue()
    pin.write_pins(config.load(str(tree / "repo")))
    assert broker.Broker(_Spool(), io.StringIO()).execute("r2", req, io.StringIO()) == 0
    tool.write_text("#!/bin/sh\necho other\n")  # changed, then the broker restarts
    out = io.StringIO()
    assert broker.Broker(_Spool(), io.StringIO()).execute("r3", req, out) == 3
    assert "phiward pin" in out.getvalue()


def test_install_protects_listed_programs_in_the_home_folder(tree, monkeypatch):
    bindir = tree / "home" / "miniconda3" / "bin"
    _tool(bindir, "samtools")
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + '\n[broker]\ncommands = ["samtools"]\n')
    cfg = config.load(str(tree / "repo"))
    deny = install.wiring(cfg)["sandbox"]["filesystem"]["denyWrite"]
    assert any(d.endswith("miniconda3/bin/samtools") for d in deny)


def test_the_presets_hold_no_program_that_can_be_told_to_start_another():
    for progs in config.COMMAND_PRESETS.values():
        assert "fastqc" not in progs and "multiqc" not in progs


def test_the_default_write_place_must_be_inside_a_root(tree):
    import io
    from phiward import run
    if CONFINE_WHY is not None:
        pytest.skip("no confinement backend")
    out_of_root = tree / "pub" / "res"
    out_of_root.mkdir(parents=True)
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + f'\n[broker]\nwrite_to = ["{out_of_root}"]\n')
    out = io.StringIO()
    run.execute(["--", "sh", "-c", f"echo x > {out_of_root}/n.txt"], str(tree / "repo"),
                dict(os.environ), out)
    assert not (out_of_root / "n.txt").exists()  # outside a root: --write-to is needed


def test_claude_folders_in_any_letter_case_are_left_out(tree, tmp_path):
    import io
    import subprocess
    import sys
    import tarfile
    from phiward import copying, remote
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        ti = tarfile.TarInfo("proj/.Claude/settings.json")
        ti.size = 2
        t.addfile(ti, io.BytesIO(b"{}"))
    dest = tmp_path / "d"
    r = subprocess.run([sys.executable, "-I", "-c", remote.EXTRACT_PY, str(dest)],
                       input=buf.getvalue(), capture_output=True, timeout=30)
    assert r.returncode == 0 and not (dest / "proj" / ".Claude").exists()
    src = tree / "repo" / "proj"
    (src / ".CLAUDE").mkdir(parents=True)
    assert copying.holds_claude([str(src)], str(tree / "repo"))


def test_a_program_listed_by_name_is_called_by_its_name(tree, monkeypatch):
    # round 18d: a full path no longer stands for a bare listed name (each way of matching a
    # path to the name opened a bypass: a relative path, a link swapped after the check); the
    # agent calls the name, and a path is listed as a path
    from phiward import run
    bindir = tree / "tools" / "bin"
    tool = _tool(bindir, "mytool")
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + '\n[broker]\ncommands = ["mytool"]\n')
    cfg = config.load(str(tree / "repo"))
    assert run.program_listed("mytool", os.path.realpath(tool), cfg)
    assert not run.program_listed(str(tool), os.path.realpath(tool), cfg)
    other = _tool(tree / "elsewhere", "mytool")
    assert not run.program_listed(str(other), os.path.realpath(other), cfg)


@pytest.mark.skipif(__import__("sys").platform != "darwin", reason="the macOS admin group")
def test_only_homebrews_admin_group_folders_stay_on_the_broker_path(tmp_path, monkeypatch):
    import grp
    from phiward import service
    try:
        admin = grp.getgrnam("admin").gr_gid
    except KeyError:
        pytest.skip("no admin group")
    if admin not in os.getgroups():
        pytest.skip("not in the admin group")
    brew = tmp_path / "opt" / "homebrew" / "bin"
    brew.mkdir(parents=True)
    os.chown(brew, -1, admin)
    os.chmod(brew, 0o775)
    away = tmp_path / "away"
    away.mkdir()
    monkeypatch.chdir(away)
    # an admin-group folder outside Homebrew's own places is not trusted
    assert str(brew) not in service._safe_path_entries(str(brew))
    from phiward import selfcheck
    st = os.stat(brew)
    assert not selfcheck._homebrew_admin(str(brew), st)
    assert selfcheck.safe_path(str(brew)) is not None


# --- the re-check of program approval ---------------------------------------------------------

def test_a_scripts_folder_is_fingerprinted_with_its_helpers(tree, monkeypatch):
    from phiward import pin
    scripts = tree / "home" / "pipelines" / "bin"
    _tool(scripts, "count.sh")
    helper = _tool(scripts / "lib", "h.sh")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + f'\n[broker]\ncommands = ["{scripts}/"]\n')
    cfg = config.load(str(tree / "repo"))
    pin.write_pins(cfg)
    assert pin.unapproved(cfg) == []
    helper.write_text("#!/bin/sh\necho other\n")
    assert any(p.endswith("lib/h.sh") for p in pin.unapproved(cfg))


def test_a_scripts_folder_too_large_to_fingerprint_is_never_approved(tree, monkeypatch):
    from phiward import broker, pin
    scripts = tree / "home" / "big"
    scripts.mkdir(parents=True)
    monkeypatch.setattr(broker, "FOLDER_LIMIT", 5)
    for i in range(7):
        (scripts / f"s{i}.sh").write_text("x")
    user = Path(os.environ["PHIWARD_CONFIG"])
    user.write_text(user.read_text() + f'\n[broker]\ncommands = ["{scripts}/"]\n')
    cfg = config.load(str(tree / "repo"))
    pin.write_pins(cfg)
    assert pin.unapproved(cfg)


def test_pin_uses_the_running_brokers_path(tree, monkeypatch):
    from phiward import broker
    monkeypatch.setattr(broker, "read_status", lambda spool=None: {"path": "/broker/bin:/usr/bin"})
    assert broker.program_path() == "/broker/bin:/usr/bin"
    monkeypatch.setattr(broker, "read_status", lambda spool=None: {})
    assert broker.program_path() == broker.command_env().get("PATH", "")


@pytest.mark.parametrize("body,why", [
    ('[broker]\ncommands = ["wc\\u001b[2K"]\n', "control"),
    ('[remote]\nhosts = "evil"\n', "list"),
    ('[broker]\nmax_output_lines = 100000000\n', "lower"),
    ('[copy]\npush_limit_gib = 100000\n', "lower"),
    ('[broker]\ncommands = ["/bin/"]\n', "place"),
])
def test_a_team_template_is_checked_before_it_is_shown(tree, tmp_path, body, why):
    team = tmp_path / "team.toml"
    team.write_text(body)
    code, out = _drive_setup(tree, [], tmp_path / "config.toml", extra=("--from", str(team)))
    assert code == 2 and why in out.lower(), out[-300:]
    assert "\x1b[2K" not in out


def test_a_team_template_next_to_a_claude_folder_is_refused(tree, tmp_path):
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    team = proj / "team.toml"
    team.write_text('[broker]\ncommands = ["@counts"]\n')
    code, out = _drive_setup(tree, [], tmp_path / "config.toml", extra=("--from", str(team)))
    assert code == 2 and "project" in out.lower()


def test_a_team_templates_remote_programs_that_run_code_are_warned_about(tree, tmp_path):
    team = tmp_path / "team.toml"
    team.write_text('[remote]\ncommands = ["squeue", "bash"]\n')
    code, out = _drive_setup(tree, ["n"], tmp_path / "config.toml", extra=("--from", str(team)))
    assert "WARNING" in out and "bash" in out


def test_values_with_control_characters_are_escaped_when_shown():
    from phiward import setup_cmd
    assert "\x1b" not in setup_cmd._value(["a\x1b[1Ab"])


def test_an_hpc_rerun_offers_the_current_settings(tree, tmp_path):
    cfg_path = tmp_path / "cfg" / "config.toml"
    cfg_path.parent.mkdir()
    first = ["1", str(tree / "phi"), "", "", "", "n",
             "y", "hpc", "login.example.org", "alice", "/work/alice/proj", "",
             "y", "y", "n", "n"]
    code, out = _drive_setup(tree, first, cfg_path)
    assert code == 0, out
    # a re-run: Enter keeps each HPC answer; the programs are approved already
    again = ["1", "n", "",            # profile; keep the roots
             "",                      # no scripts folder (the results folder exists)
             "n",                     # no limit on the shell's network
             "y", "", "", "", "", "",  # HPC: Enter keeps each answer
             "y", "n", "n"]           # write, wire, service
    code, out = _drive_setup(tree, again, cfg_path)
    assert code == 0, out[-600:]
    assert "[login.example.org]" in out and "already has `Host hpc`" in out
    cfg = config.load(str(tree / "repo"), env=dict(os.environ, PHIWARD_CONFIG=str(cfg_path)))
    assert cfg.remotes == ["hpc:/work/alice/proj"]
