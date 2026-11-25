"""On an older Linux C library (RHEL 8, glibc 2.28) Python's os.chmod with dir_fd and
follow_symlinks=False raises ValueError, not NotImplementedError. carry-over must then give a
folder back its owner bits by descriptor anyway (the entry was checked as a real folder and no
longer changes), not crash. Found on a real RHEL 8 run of scripts/sandbox-check. Made-up trees."""

import os

import pytest

from phiward import carryover


@pytest.fixture()
def old_glibc(monkeypatch):
    real = os.chmod

    def chmod(path, mode, *, dir_fd=None, follow_symlinks=True):
        if dir_fd is not None and not follow_symlinks:
            raise ValueError("chmod: cannot use dir_fd and follow_symlinks together")
        return real(path, mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
    monkeypatch.setattr(os, "chmod", chmod)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the mode")
def test_a_locked_folder_is_made_movable(tmp_path, old_glibc):
    (tmp_path / "run").mkdir()
    (tmp_path / "run" / "x").write_text("made-up\n")
    os.chmod(tmp_path / "run", 0)
    fd = os.open(str(tmp_path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        carryover._movable(fd, "run")  # must not raise
    finally:
        os.close(fd)
    assert (tmp_path / "run" / "x").read_text() == "made-up\n"


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the mode")
def test_a_locked_folder_is_removed(tmp_path, old_glibc):
    (tmp_path / "t" / "deep").mkdir(parents=True)
    (tmp_path / "t" / "deep" / "x").write_text("made-up\n")
    os.chmod(tmp_path / "t" / "deep", 0)
    carryover._remove(str(tmp_path / "t"))
    assert not (tmp_path / "t").exists()
