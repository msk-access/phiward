"""The macOS profiles also deny mounting file systems and creating launchd jobs.

Static: both generated profiles hold the two denies (runs everywhere). Behaviour: under each
profile, a mount and a launchd job are refused. The behaviour tests run on GitHub's macOS
runners only: a mount or a launchd job on a maintainer's machine is something its security
tooling may see, and a failed cleanup would leave one behind. Made-up names only.
"""

import os
import subprocess
import sys
import uuid

import pytest

from phiward import confine, config, wholetool

DENIES = ("(deny file-mount)", "(deny job-creation)")
ci_macos = pytest.mark.skipif(
    sys.platform != "darwin" or not os.environ.get("GITHUB_ACTIONS"),
    reason="macOS on GitHub Actions only: a mount or a launchd job is not tried on a "
           "maintainer's machine (its security tooling may flag it, a failed cleanup would "
           "leave one behind)")


def _tool_profile(tmp_path):
    folder = str(tmp_path / "tool")
    return wholetool.seatbelt_tool_profile(
        config.Config(), [str(tmp_path / "proj")], str(tmp_path / "proj"), {}, folder,
        str(tmp_path / "canary"))


def test_the_gateway_profile_denies_mounts_and_launchd_jobs():
    prof = confine.seatbelt_gateway_profile([], [], False)
    for d in DENIES:
        assert d in prof, d


def test_the_tool_profile_denies_mounts_and_launchd_jobs(tmp_path):
    prof = _tool_profile(tmp_path)
    for d in DENIES:
        assert d in prof, d


def _under(prof, argv):
    return subprocess.run([confine.SANDBOX_EXEC, "-p", prof] + argv,
                          capture_output=True, text=True, timeout=60)


def _check(prof, tmp_path):
    label = "test.phiward.fake-" + uuid.uuid4().hex[:12]
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    marker = tmp_path / "marker-FAKE-PT-0001.txt"
    plist = tmp_path / (label + ".plist")
    plist.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>'
        f"<key>Label</key><string>{label}</string><key>ProgramArguments</key><array>"
        f"<string>/bin/sh</string><string>-c</string><string>echo made-up-text > {marker}"
        "</string></array><key>RunAtLoad</key><true/></dict></plist>\n")
    uid = str(os.getuid())
    try:
        m = _under(prof, ["/sbin/mount_devfs", "devfs", str(mnt)])
        assert m.returncode != 0, "the mount was allowed: " + m.stdout + m.stderr
        _under(prof, ["/bin/launchctl", "submit", "-l", label + ".s", "--", "/bin/sh", "-c",
                      f"echo made-up-text > {marker}"])
        j = _under(prof, ["/bin/launchctl", "bootstrap", "gui/" + uid, str(plist)])
        assert j.returncode != 0, "the job was allowed: " + j.stdout + j.stderr
        import time
        time.sleep(2)
        assert not marker.exists(), "a launchd job ran"
    finally:  # nothing stays behind: not a mount, not a job
        for argv in (["/sbin/umount", "-f", str(mnt)],
                     ["/bin/launchctl", "bootout", f"gui/{uid}/{label}"],
                     ["/bin/launchctl", "remove", label + ".s"]):
            subprocess.run(argv, capture_output=True, timeout=30)


@ci_macos
def test_the_gateway_profile_refuses_a_mount_and_a_launchd_job(tmp_path):
    _check(confine.seatbelt_gateway_profile([], [], False), tmp_path)


@ci_macos
def test_the_tool_profile_refuses_a_mount_and_a_launchd_job(tmp_path):
    _check(_tool_profile(tmp_path), tmp_path)
