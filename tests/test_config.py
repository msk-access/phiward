"""The TOML subset reader and the layered, tighten-only config."""

import sys

import pytest

from phiward import _toml, config

SAMPLES = [
    "",
    "# only a comment\n",
    '[protected_paths]\nroots = ["/a/b", \'~/c\']\nunresolved = "ask"\n',
    '[protected_paths]\nroots = [\n  "/a",  # one\n  "/b",\n]\n[git]\nprotected_branches = ["main"]\n',
    '[sanitize]\npacks = ["genomics"]\npatterns = [\'\\bFAKE-\\d+ => <ID>\']\n',
    '[a.b]\nx = 1\ny = true\nz = "q\\"uote\\u00e9"\n',
    'key = "v"\n"quoted key" = \'lit\'\n',
]


@pytest.mark.parametrize("text", SAMPLES)
def test_toml_subset_matches_tomllib(text):
    tomllib = pytest.importorskip("tomllib") if sys.version_info >= (3, 11) else None
    got = _toml.loads(text)
    if tomllib is not None:
        assert got == tomllib.loads(text)


@pytest.mark.parametrize("text", [
    "[[arr]]\n", 'x = """multi"""\n', "x = 1.5\n", "x = 2026-11-02\n", "x = {a = 1}\n",
    "x = 1\nx = 2\n", "[t]\n[t]\n", "x = \"unclosed\n", "x = [1, 2\n", "x =\n", "= 1\n",
])
def test_toml_outside_the_subset_is_an_error(text):
    with pytest.raises(_toml.TomlError):
        _toml.loads(text)


def write(path, text):
    path.write_text(text)
    return path


def test_no_config_no_effect(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("PHIWARD_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    cfg = config.load(str(tmp_path))
    assert not cfg.active and not cfg.problem and cfg.files == []


@pytest.mark.parametrize("text,needle", [
    ("[protected_paths]\nroots = [\"relative/x\"]\n", "absolute"),
    ("[protected_paths]\nroots = [\"/\"]\n", "below /"),
    ("[protected_paths]\nroots = [\"/a/../b\"]\n", ".."),
    ("[protected_paths]\nroots = [\"/a/*\"]\n", "wildcard"),
    ("[protected_paths]\nroots = [\"$DATA/x\"]\n", "absolute"),
    ("[protected_paths]\nunresolved = \"maybe\"\n", "one of"),
    ("[protected_paths]\nroots = \"/a\"\n", "list"),
    ("[protected_paths]\nroot = [\"/a\"]\n", "unknown key"),
    ("[elsewhere]\n", "unknown section"),
    ("[protected_paths\n", "does not parse"),
])
def test_bad_configs_fail_closed(tmp_path, monkeypatch, text, needle):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PHIWARD_CONFIG", str(write(tmp_path / "c.toml", text)))
    cfg = config.load(str(tmp_path))
    assert cfg.problem and needle in cfg.problem and cfg.active


def test_named_config_that_does_not_exist_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("PHIWARD_CONFIG", str(tmp_path / "missing.toml"))
    assert config.load(str(tmp_path)).problem


@pytest.mark.parametrize("user,repo,want", [
    (None, None, "deny"), ("allow", None, "allow"), ("ask", None, "ask"),
    (None, "allow", "deny"), (None, "ask", "deny"), ("allow", "ask", "ask"),
    ("ask", "allow", "ask"), ("allow", "deny", "deny"), ("deny", "allow", "deny"),
])
def test_unresolved_is_tighten_only(tmp_path, monkeypatch, user, repo, want):
    monkeypatch.setenv("HOME", str(tmp_path))
    body = "[protected_paths]\nroots = [\"/fake/root\"]\n"
    if user:
        body += f'unresolved = "{user}"\n'
    monkeypatch.setenv("PHIWARD_CONFIG", str(write(tmp_path / "user.toml", body)))
    proj = tmp_path / "proj"
    proj.mkdir()
    if repo:
        write(proj / ".phiward.toml", f'[protected_paths]\nunresolved = "{repo}"\n')
    assert config.load(str(proj)).unresolved == want


def test_a_repo_adds_but_never_removes(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PHIWARD_CONFIG", str(write(
        tmp_path / "user.toml", '[protected_paths]\nroots = ["/fake/a"]\n[sanitize]\npacks = ["msk"]\n')))
    proj = tmp_path / "proj"
    (proj / "sub").mkdir(parents=True)
    write(proj / ".phiward.toml",
          '[protected_paths]\nroots = ["/fake/b"]\n[sanitize]\npacks = []\n[git]\n'
          'protected_branches = ["main"]\n')
    cfg = config.load(str(proj / "sub"))  # found from a subfolder
    assert cfg.roots == ["/fake/a", "/fake/b"]
    assert cfg.packs == ["msk"] and cfg.protected_branches == ["main"]


def test_tilde_and_home_in_roots(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", "/fake/home")
    monkeypatch.setenv("PHIWARD_CONFIG", str(write(
        tmp_path / "u.toml", '[protected_paths]\nroots = ["~/x", "$HOME/y"]\n')))
    assert config.load(str(tmp_path)).roots == ["/fake/home/x", "/fake/home/y"]


@pytest.mark.parametrize("entry,ok", [("~/x", False), ("x", False), ("/x", True)])
def test_a_remote_root_must_be_absolute(tmp_path, monkeypatch, entry, ok):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PHIWARD_CONFIG", str(write(
        tmp_path / "c.toml", f'[remote]\nroots = ["/ok", "{entry}"]\n')))
    cfg = config.load(str(tmp_path))
    if ok:
        assert not cfg.problem and cfg.remote_roots == ["/ok", "/x"]
        return
    assert cfg.active and cfg.problem
    assert "[remote] roots entry 2" in cfg.problem and "absolute path" in cfg.problem
    assert entry not in cfg.problem.replace("[remote] roots entry 2", "")  # no value shown


def test_doctor_reports_a_relative_remote_root(tmp_path, monkeypatch, capsys):
    from phiward.cli import main
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PHIWARD_CONFIG", str(write(
        tmp_path / "c.toml", '[remote]\nroots = ["~/fakedata"]\n')))
    monkeypatch.chdir(tmp_path)
    main(["doctor"])
    out = capsys.readouterr().out
    assert "PROBLEM: [remote] roots entry 1" in out and "fakedata" not in out, out
