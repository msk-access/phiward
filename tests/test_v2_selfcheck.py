"""The trusted runtime checks its own files before launch starts a tool."""

import base64
import hashlib
import os

import pytest

from phiward import selfcheck


def rec(path):
    h = base64.urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).rstrip(b"=").decode()
    return (str(path), f"sha256={h}")


def test_unchanged_files_pass(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("x = 1\n")
    os.chmod(f, 0o644)
    os.chmod(tmp_path, 0o755)
    assert selfcheck.check([rec(f)]) == (True, [])


def test_a_changed_file_is_found(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("x = 1\n")
    os.chmod(f, 0o644)  # (a group-writable umask would be reported first)
    os.chmod(tmp_path, 0o755)
    r = rec(f)
    f.write_text("x = 2  # planted\n")
    ok, problems = selfcheck.check([r])
    assert problems and "changed since install" in problems[0]


def test_a_file_others_can_write_is_found(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("x = 1\n")
    os.chmod(f, 0o666)
    ok, problems = selfcheck.check([rec(f)])
    assert problems and "writable by others" in problems[0]


def test_a_link_is_found(tmp_path):
    real = tmp_path / "real.py"
    real.write_text("x = 1\n")
    link = tmp_path / "a.py"
    os.symlink(real, link)
    ok, problems = selfcheck.check([(str(link), "sha256=x")])
    assert problems and "a link" in problems[0]


def test_a_source_checkout_is_not_refused():
    installed, problems = selfcheck.check()
    assert problems == [] or installed


# --- compiled files and startup files -------------------------------------------------------------

def _pkg(tmp_path):
    pkg = tmp_path / "phiward"
    pkg.mkdir()
    os.chmod(tmp_path, 0o755)
    os.chmod(pkg, 0o755)
    src = pkg / "cli.py"
    src.write_text("def main():\n    return 'real'\n")
    os.chmod(src, 0o644)
    return pkg, src


def _compiled(src, body, flags=0):
    import importlib.util
    import marshal
    import sys
    cache = src.parent / "__pycache__"
    cache.mkdir(exist_ok=True)
    st = os.stat(src)
    code = compile(body, str(src), "exec", dont_inherit=True)
    header = importlib.util.MAGIC_NUMBER + flags.to_bytes(4, "little")
    header += (int(st.st_mtime) & 0xFFFFFFFF).to_bytes(4, "little") + \
        (st.st_size & 0xFFFFFFFF).to_bytes(4, "little")
    pyc = cache / f"cli.{sys.implementation.cache_tag}.pyc"
    pyc.write_bytes(header + marshal.dumps(code))
    os.chmod(pyc, 0o644)
    return pyc


def test_a_planted_compiled_file_is_found(tmp_path):
    pkg, src = _pkg(tmp_path)
    _compiled(src, "def main():\n    return 'planted'\n")
    ok, problems = selfcheck.check([rec(src)], str(pkg))
    assert any("does not match its source" in p for p in problems), problems


def test_an_unchecked_hash_compiled_file_is_found(tmp_path):
    pkg, src = _pkg(tmp_path)
    _compiled(src, "import os\n", flags=1)  # Python runs this one without looking at the source
    ok, problems = selfcheck.check([rec(src)], str(pkg))
    assert any("does not match its source" in p for p in problems), problems


def test_a_compiled_file_of_the_same_source_passes(tmp_path):
    import py_compile
    pkg, src = _pkg(tmp_path)
    py_compile.compile(str(src), doraise=True)
    for f in (pkg / "__pycache__").iterdir():
        os.chmod(f, 0o644)
    os.chmod(pkg / "__pycache__", 0o755)
    assert selfcheck.check([rec(src)], str(pkg)) == (True, [])


def test_a_file_the_record_does_not_list_is_found(tmp_path):
    pkg, src = _pkg(tmp_path)
    (pkg / "cli.cpython-312-darwin.so").write_bytes(b"\x7fELF")
    ok, problems = selfcheck.check([rec(src)], str(pkg))
    assert any("not in the install record" in p for p in problems), problems


def test_a_record_without_package_files_is_not_an_install(tmp_path):
    info = tmp_path / "phiward-0.2.0b1.dist-info"
    info.mkdir()
    (info / "RECORD").write_text("__editable__.phiward.pth,sha256=x,10\n")
    assert selfcheck._record_check(str(info / "RECORD")) == (False, [])


def test_the_isolated_check_runs_this_file_as_a_script(tmp_path, monkeypatch):
    info = tmp_path / "phiward-0.2.0b1.dist-info"
    info.mkdir()
    pkg, src = _pkg(tmp_path)
    h = rec(src)[1]
    (info / "RECORD").write_text(f"phiward/cli.py,{h},30\n")
    (pkg / "evil.pth").write_text("import os\n")
    monkeypatch.setattr(selfcheck, "_record_path", lambda: str(info / "RECORD"))
    monkeypatch.setattr(selfcheck, "_running_package", lambda: str(pkg))
    ok, problems = selfcheck.check_isolated()
    assert ok and problems == ["evil.pth: not in the install record"], problems


# --- more self-check fixes ------------------------------------------------------------------------

def test_a_linked_folder_in_the_package_is_found(tmp_path):
    pkg, src = _pkg(tmp_path)
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "__init__.py").write_text("x = 1\n")
    os.symlink(evil, pkg / "cli")
    ok, problems = selfcheck.check([rec(src)], str(pkg))
    assert "cli/: a link in the package" in problems, problems


@pytest.mark.parametrize("level", [1, 2])
def test_optimized_compiled_files_of_the_same_source_pass(tmp_path, level):
    import py_compile
    pkg, src = _pkg(tmp_path)
    src.write_text('"""doc"""\ndef main():\n    assert True\n    return "real"\n')
    os.chmod(src, 0o644)
    py_compile.compile(str(src), doraise=True, optimize=level)
    for f in (pkg / "__pycache__").iterdir():
        os.chmod(f, 0o644)
    os.chmod(pkg / "__pycache__", 0o755)
    assert selfcheck.check([rec(src)], str(pkg)) == (True, [])


def test_a_record_of_another_copy_counts_as_no_install(tmp_path, monkeypatch):
    info = tmp_path / "phiward-0.2.0b1.dist-info"
    info.mkdir()
    (info / "RECORD").write_text("phiward/cli.py,sha256=x,1\n")
    monkeypatch.setattr(selfcheck, "_record_path", lambda: str(info / "RECORD"))
    assert selfcheck.check_isolated() == (False, [])
