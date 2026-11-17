"""What no session may read besides protected data:
histories, the Trash, the gateway's write_to folders (unmasked output), other tools' logins,
SSH keys named outside ~/.ssh, and the keytabs and caches krb5.conf names."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from phiward import config, wholetool
from helpers import needs_confine

SRC = str(Path(__file__).resolve().parents[1] / "src")


def launch_reads(tree, path):
    code = (f"try:\n    print('READ', open({str(path)!r}).read())\n"
            "except OSError as e:\n    print('REFUSED', e.errno)\n")
    env = dict(os.environ, PYTHONPATH=SRC)
    r = subprocess.run([sys.executable, "-m", "phiward", "launch", "--", sys.executable, "-c", code],
                       cwd=str(tree / "repo"), capture_output=True, text=True, env=env, timeout=60)
    return r.stdout + r.stderr


def out_of_tmp(tree):
    if sys.platform.startswith("linux") and str(tree).startswith("/tmp/"):
        pytest.skip("Linux: the tree is under the session's own /tmp; run with --basetemp")


@needs_confine
@pytest.mark.parametrize("rel", [".zsh_history", ".bash_history", ".Rhistory", ".python_history",
                                 ".Trash/FAKE-PT-0001.bam", ".codex/auth.json",
                                 ".local/share/Trash/files/x"])
def test_histories_trash_and_other_logins_are_not_readable(tree, rel):
    out_of_tmp(tree)
    f = tree / "home" / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("SECRET-HISTORY\n")
    out = launch_reads(tree, f)
    assert "SECRET-HISTORY" not in out, out


@needs_confine
def test_a_write_to_folder_is_not_readable(tree):
    out_of_tmp(tree)
    w = tree / "results"
    w.mkdir()
    (w / "out.tsv").write_text("SECRET-RESULT\n")
    cfg = Path(os.environ["PHIWARD_CONFIG"])
    cfg.write_text(cfg.read_text() + f'\n[broker]\nwrite_to = ["{w}"]\n')
    out = launch_reads(tree, w / "out.tsv")
    assert "SECRET-RESULT" not in out, out


def test_an_identity_file_named_in_the_ssh_config_is_hidden(tree):
    (tree / "home" / ".ssh").mkdir()
    (tree / "home" / ".ssh" / "config").write_text(
        "Host hpc\n  IdentityFile ~/keys/hpc_ed25519\n  IdentityFile \"/opt/keys/k\"\n"
        "  IdentityFile %d/other\n  CertificateFile=/opt/keys/k-cert.pub\n")
    env = dict(os.environ)
    found = wholetool._credentials(env, config.load(str(tree / "repo")))
    home = str(tree / "home")
    for p in (home + "/keys/hpc_ed25519", "/opt/keys/k", home + "/other", "/opt/keys/k-cert.pub"):
        assert p in found, (p, found)


def test_keytabs_and_caches_from_krb5_conf_are_hidden(tree):
    conf = tree / "krb5.conf"
    conf.write_text("[libdefaults]\n  default_ccache_name = FILE:/var/krb/cc_%{uid}\n"
                    "  default_client_keytab_name = /etc/keytabs/%{uid}.keytab\n"
                    "  default_ccache_name = KEYRING:persistent:%{uid}\n")
    env = dict(os.environ, KRB5_CONFIG=str(conf), KRB5_CLIENT_KTNAME="FILE:/srv/kt/me.keytab")
    found = wholetool._kerberos_caches(env)
    uid = os.getuid()
    for p in (f"/var/krb/cc_{uid}", f"/etc/keytabs/{uid}.keytab", "/srv/kt/me.keytab"):
        assert p in found, (p, found)
    assert not any(p.startswith("KEYRING") or "persistent" in p for p in found)


def test_the_hook_root_list_is_not_passed_to_the_tool():
    assert not wholetool._keep_env("PHIWARD_HOOK_ROOTS")
    assert wholetool._keep_env("PHIWARD_SPOOL")


def test_ssh_includes_quotes_and_tokens(tree):
    ssh = tree / "home" / ".ssh"
    (ssh / "conf.d").mkdir(parents=True)
    (ssh / "config").write_text("Include conf.d/*\n")
    (ssh / "conf.d" / "hpc").write_text(
        'Host hpc\n  IdentityFile "/opt/my keys/k"\n  IdentityFile /opt/keys/%h/id\n'
        "  IdentityFile ${HOME}/k2\n")
    found = wholetool._credentials(dict(os.environ), config.load(str(tree / "repo")))
    home = str(tree / "home")
    for p in ("/opt/my keys/k", "/opt/keys", home + "/k2"):
        assert p in found, (p, found)


def test_krb5_includedir_and_tokens(tree):
    d = tree / "krb5.conf.d"
    d.mkdir()
    (tree / "krb5.conf").write_text(f"includedir {d}\n")
    (d / "ccache").write_text("[libdefaults]\n default_ccache_name = FILE:/srv/cc/%{username}/c\n"
                              " default_keytab_name = /srv/kt/%{weird}/k\n")
    env = dict(os.environ, KRB5_CONFIG=str(tree / "krb5.conf"), USER="fakeuser")
    found = wholetool._kerberos_caches(env)
    assert "/srv/cc/fakeuser/c" in found and "/srv/kt" in found, found
