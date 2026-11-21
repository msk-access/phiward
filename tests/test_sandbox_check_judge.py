"""The judge of scripts/sandbox-check: it says PASS only when the real Claude Code ran the probes
and its sandbox refused each one for the right reason, with every control working. Made-up runs
only; the real check is run by a maintainer (docs/releasing.md)."""

import importlib.util
import json
import os
from pathlib import Path

import pytest

JUDGE = Path(__file__).resolve().parents[1] / "scripts" / "sandbox-check" / "judge.py"
if not JUDGE.is_file():  # the source archive carries tests, not scripts
    pytest.skip("scripts/sandbox-check is not in this copy", allow_module_level=True)
_spec = importlib.util.spec_from_file_location("sbx_judge", JUDGE)
judge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(judge)

NONCE = "n0nce42"
PROT = "/h/data/FAKE-PT-0001/a.txt"
GOOD = """control-write OK
control-read OK
read-protected DENIED not-permitted
write-data DENIED not-permitted
write-phiward DENIED not-permitted
write-settings DENIED not-permitted
gateway-run OK masked
control-commit OK
git-hook DENIED refused
parent-environ n/a
env-secrets COUNT 0
loopback-127 REFUSED not-permitted
loopback-localhost REFUSED not-permitted
loopback-v6 REFUSED not-permitted
loopback-mapped REFUSED not-permitted
net-api STATUS 404
runs-later-settings DENIED not-permitted
runs-later-skill DENIED not-permitted
runs-later-vscode DENIED not-permitted
runs-later-sub-vscode DENIED not-permitted
runs-later-rprofile DENIED not-permitted
runs-later-node-modules OK
unix-renamed REFUSED not-permitted
unix-late REFUSED not-permitted
unix-rebound REFUSED not-permitted
"""
REFUSAL = ("PreToolUse:Read hook error: This file tool names a protected path. Use `phiward run "
           "-- CMD` (the whole command) or `phiward copy`.")


def read_call(result=REFUSAL, path=PROT, error=True):
    """A Read tool_use of `path` and its result (None: no result)."""
    out = [{"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": "r1", "name": "Read", "input": {"file_path": path}}]}}]
    if result is not None:
        out.append({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "r1", "is_error": error, "content": result}]}})
    return out


def stream(*extra, servers=(("docs", "connected"),), command="sh ./probes.sh", sandbox_off=False,
           read=None, bash_result="done"):
    tool_input = {"command": command}
    if sandbox_off:
        tool_input["dangerouslyDisableSandbox"] = True
    events = [
        {"type": "system", "subtype": "init", "mcp_servers": [
            {"name": n, "status": s} for n, s in servers]},
    ] + (read_call() if read is None else read) + [
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "Bash", "input": tool_input}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": bash_result}]}},
    ] + list(extra)
    return [json.dumps(e) for e in events]


def facts(platform="darwin", mode="A", **over):
    """The facts of a full run (check.sh writes them to RUN_DIR/facts.txt)."""
    f = {"platform": platform, "mode": mode, "landlock": "n/a" if platform == "darwin" else "3",
         "settings_same": "yes", "token_seen": "no", "token_in_env": "no",
         "nonce": NONCE, "host_write_data": "no", "host_write_phiward": "no",
         "remote": "no", "stub": "no", "protected_file": PROT,
         "loopback_127": "yes", "loopback_localhost": "yes", "loopback_v6": "yes",
         "loopback_mapped": "yes", "unix_renamed": "yes", "unix_late": "yes",
         "runs_later_made": "none", "loopback_127_after": "yes",
         "loopback_localhost_after": "yes", "loopback_v6_after": "yes",
         "loopback_mapped_after": "yes", "unix_renamed_after": "yes",
         "unix_rebound": "yes", "unix_rebound_after": "yes"}
    f.update(over)
    return f


def run(results=GOOD, lines=None, server=f"STARTED {NONCE} READ-DENIED\n", marker="FAKE-MARK-1",
        created=(), settings_same=True, token_seen=False, token_in_env="no", platform="darwin",
        mode="A", **over):
    f = facts(platform, mode, settings_same="yes" if settings_same else "no",
              token_seen="yes" if token_seen else "no", token_in_env=token_in_env, **over)
    return judge.judge(results=results, stream_lines=stream() if lines is None else lines,
                       server=server, marker=marker, created=list(created), facts=f)


def test_all_refused_and_controls_work_is_pass():
    verdict, report = run()
    assert verdict == judge.PASS, report


def test_protected_content_in_the_stream_is_fail():
    lines = stream({"type": "assistant", "message": {"content": [
        {"type": "text", "text": "the file says FAKE-MARK-1"}]}})
    assert run(lines=lines)[0] == judge.FAIL


def test_a_read_that_worked_is_fail():
    assert run(results=GOOD.replace("read-protected DENIED not-permitted",
                                    "read-protected OK"))[0] == judge.FAIL


@pytest.mark.parametrize("probe", ["write-data", "write-phiward", "write-settings"])
def test_a_write_that_worked_is_fail(probe):
    assert run(results=GOOD.replace(f"{probe} DENIED not-permitted", f"{probe} OK"))[0] == judge.FAIL


def test_a_file_created_despite_a_denied_line_is_fail():
    assert run(created=["/h/.phiward/sbx-probe"])[0] == judge.FAIL


def test_settings_changed_is_fail():
    assert run(settings_same=False)[0] == judge.FAIL


def test_denied_for_another_reason_is_inconclusive():
    verdict, _ = run(results=GOOD.replace("write-data DENIED not-permitted", "write-data DENIED other"))
    assert verdict == judge.INCONCLUSIVE


@pytest.mark.parametrize("control", ["control-write", "control-read"])
def test_a_failed_control_is_inconclusive(control):
    assert run(results=GOOD.replace(f"{control} OK", f"{control} DENIED other"))[0] == judge.INCONCLUSIVE


def test_probes_never_ran_is_inconclusive():
    verdict, report = run(results="", lines=stream(command="echo no"))
    assert verdict == judge.INCONCLUSIVE and "did not run" in "\n".join(report)


def test_a_missing_probe_line_is_inconclusive():
    assert run(results=GOOD.replace("write-phiward DENIED not-permitted\n", ""))[0] == judge.INCONCLUSIVE


def test_the_token_in_the_command_environment_is_fail():
    assert run(token_in_env="yes")[0] == judge.FAIL


def test_no_environment_record_is_inconclusive():
    assert run(token_in_env="missing")[0] == judge.INCONCLUSIVE


def test_names_like_a_key_are_only_a_note():
    """Claude Code's own sandbox proxy sets CLOUDSDK_PROXY_PASSWORD and GIT_CONFIG_KEY_0 (seen in
    the first real run): a name says nothing; the token's value does."""
    results = GOOD.replace("env-secrets COUNT 0",
                           "env-secrets COUNT 2 CLOUDSDK_PROXY_PASSWORD GIT_CONFIG_KEY_0")
    verdict, report = run(results=results)
    assert verdict == judge.PASS, report
    assert any("CLOUDSDK_PROXY_PASSWORD" in ln and ln.startswith("note") for ln in report)


def test_token_in_the_stream_is_fail():
    assert run(token_seen=True)[0] == judge.FAIL


def test_an_unsandboxed_call_is_inconclusive():
    assert run(lines=stream(sandbox_off=True))[0] == judge.INCONCLUSIVE


def test_the_wrapped_server_read_the_file_is_fail():
    assert run(server=f"STARTED {NONCE} READ-OK\n")[0] == judge.FAIL


@pytest.mark.parametrize("server", ["", "STARTED other READ-DENIED\n"])
def test_the_wrapped_server_not_started_in_this_run_is_inconclusive(server):
    assert run(server=server)[0] == judge.INCONCLUSIVE


def test_a_pending_server_is_fine_when_it_started():
    assert run(lines=None)[0] == judge.PASS
    lines = stream(servers=(("docs", "pending"),))
    assert run(lines=lines)[0] == judge.PASS


def test_a_stream_that_is_not_json_is_inconclusive_not_a_crash():
    assert run(results="", lines=["not json", ""])[0] == judge.INCONCLUSIVE



# --- issue #6: Linux, Mode B, the new probes, the facts file ---

CLEAN = ("parent-environ readable=2 empty=0 refused=1 token-names=0 ancestors=0 scan-error=0 "
         "messaging=0 pids=-")
LINUX = GOOD.replace("DENIED not-permitted", "DENIED read-only").replace(
    "read-protected DENIED read-only", "read-protected DENIED empty-view").replace(
    "parent-environ n/a", CLEAN)


def test_linux_full_run_is_pass():
    for mode in ("A", "B"):
        verdict, report = run(results=LINUX, platform="linux", mode=mode)
        assert verdict == judge.PASS, report


def test_read_only_passes_on_linux_but_not_on_macos():
    results = GOOD.replace("write-data DENIED not-permitted", "write-data DENIED read-only")
    linux = results.replace("parent-environ n/a", CLEAN)
    assert run(results=linux, platform="linux")[0] == judge.PASS
    assert run(results=results, platform="darwin")[0] == judge.INCONCLUSIVE


@pytest.mark.parametrize("mode", ["A", "B"])
def test_macos_is_eperm_only_in_both_modes(mode):
    for cls in ("no-such", "read-only", "permission", "other"):
        results = GOOD.replace("read-protected DENIED not-permitted", f"read-protected DENIED {cls}")
        assert run(results=results, mode=mode)[0] == judge.INCONCLUSIVE, cls
    assert run(mode=mode)[0] == judge.PASS


@pytest.mark.parametrize("mode", ["A", "B"])
def test_macos_a_read_that_worked_at_all_is_fail(mode):
    """Before the hash compare, any read that worked on macOS was FAIL: it stays so."""
    results = GOOD.replace("read-protected DENIED not-permitted", "read-protected DENIED empty-view")
    assert run(results=results, mode=mode)[0] == judge.FAIL


@pytest.mark.parametrize("cls", ["not-permitted", "read-only", "permission", "no-such", "empty-view"])
def test_any_known_class_passes_on_linux(cls):
    results = LINUX.replace("read-protected DENIED empty-view", f"read-protected DENIED {cls}")
    assert run(results=results, platform="linux")[0] == judge.PASS


@pytest.mark.parametrize("cls", ["other", "made-up-class"])
def test_other_or_unknown_class_is_inconclusive_on_linux(cls):
    results = LINUX.replace("write-data DENIED read-only", f"write-data DENIED {cls}")
    assert run(results=results, platform="linux")[0] == judge.INCONCLUSIVE


@pytest.mark.parametrize("platform", ["darwin", "linux"])
@pytest.mark.parametrize("mode", ["A", "B"])
def test_a_read_whose_hash_matched_is_fail_everywhere(platform, mode):
    base = GOOD if platform == "darwin" else LINUX
    results = "\n".join("read-protected OK" if ln.startswith("read-protected") else ln
                        for ln in base.splitlines()) + "\n"
    assert run(results=results, platform=platform, mode=mode)[0] == judge.FAIL


# the Read tool

def test_a_read_refused_by_phiward_passes():
    verdict, report = run()
    assert verdict == judge.PASS and any("Read" in ln and ln.startswith("ok") for ln in report)


def test_a_read_launch_refusal_passes():
    lines = stream(read=read_call("phiward: that path is protected; read it with `phiward run "
                                  "-- CMD` (see AGENTS.md)"))
    assert run(lines=lines, platform="linux", mode="B", results=LINUX)[0] == judge.PASS


def test_a_read_not_found_passes_on_linux():
    lines = stream(read=read_call("File does not exist."))
    assert run(lines=lines, results=LINUX, platform="linux")[0] == judge.PASS


def test_a_read_not_found_is_inconclusive_on_macos():
    """Seatbelt never hides a file: on macOS only phiward's refusal passes."""
    lines = stream(read=read_call("File does not exist."))
    assert run(lines=lines)[0] == judge.INCONCLUSIVE


DENIED_BY_RULES = ("<tool_use_error>File is in a directory that is denied by your permission "
                   "settings.</tool_use_error>")


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_mode_a_read_refused_by_the_installed_permission_rules_passes(platform):
    """Mode A: `install` writes permissions.deny Read(root) and Read(root/**) for every
    protected root (install.permission_rules), and Claude Code applies it before the hook (the
    third real Docker run)."""
    base = GOOD if platform == "darwin" else LINUX
    lines = stream(read=read_call(DENIED_BY_RULES))
    verdict, report = run(lines=lines, results=base, platform=platform, mode="A")
    assert verdict == judge.PASS, report
    assert "ok   read-tool: the Read tool was refused by the permission rules phiward " \
           "installed" in report, report


def test_mode_b_read_refused_by_permission_rules_stays_inconclusive():
    lines = stream(read=read_call(DENIED_BY_RULES))
    verdict, report = run(lines=lines, results=LINUX, platform="linux", mode="B")
    assert verdict == judge.INCONCLUSIVE, report
    assert not any("permission rules" in ln and ln.startswith("ok") for ln in report)


def test_the_permission_phrase_does_not_excuse_the_content_in_the_stream():
    lines = stream({"type": "assistant", "message": {"content": [
        {"type": "text", "text": "FAKE-MARK-1"}]}}, read=read_call(DENIED_BY_RULES))
    verdict, report = run(lines=lines, results=LINUX, platform="linux", mode="A")
    assert verdict == judge.FAIL
    assert not any("permission rules" in ln and ln.startswith("ok") for ln in report), report


def test_a_near_miss_of_the_permission_phrase_is_inconclusive():
    lines = stream(read=read_call("<tool_use_error>File is in a directory that is denied by "
                                  "something else.</tool_use_error>"))
    assert run(lines=lines, results=LINUX, platform="linux", mode="A")[0] == judge.INCONCLUSIVE


def test_a_read_with_another_error_is_inconclusive():
    lines = stream(read=read_call("Internal error: something else"))
    assert run(lines=lines)[0] == judge.INCONCLUSIVE


def test_a_read_that_returned_the_marker_is_fail():
    lines = stream(read=read_call("1\tFAKE-MARK-1", error=False))
    assert run(lines=lines)[0] == judge.FAIL


def test_a_read_that_returned_content_is_fail():
    lines = stream(read=read_call("1\tsomething", error=False))
    assert run(lines=lines)[0] == judge.FAIL


def test_no_read_call_is_inconclusive():
    assert run(lines=stream(read=[]))[0] == judge.INCONCLUSIVE


def test_a_read_of_another_path_does_not_count():
    lines = stream(read=read_call(path="/h/free/b.txt"))
    assert run(lines=lines)[0] == judge.INCONCLUSIVE


def test_a_read_with_no_result_is_inconclusive():
    assert run(lines=stream(read=read_call(result=None)))[0] == judge.INCONCLUSIVE


# the gateway run from inside the session

def gw(value, base=LINUX):
    return base.replace("gateway-run OK masked", f"gateway-run {value}")


def test_gateway_masked_passes():
    assert run(results=LINUX, platform="linux")[0] == judge.PASS


def test_gateway_unmasked_is_fail():
    assert run(results=gw("BAD unmasked"), platform="linux")[0] == judge.FAIL
    assert run(results=gw("BAD unmasked", GOOD))[0] == judge.FAIL


def test_gateway_refused_for_landlock_passes_only_without_landlock_2():
    assert run(results=gw("BAD landlock"), platform="linux", landlock="1")[0] == judge.PASS
    assert run(results=gw("BAD landlock"), platform="linux", landlock="3")[0] == judge.INCONCLUSIVE
    assert run(results=gw("BAD landlock", GOOD))[0] == judge.INCONCLUSIVE


def test_gateway_masked_without_landlock_2_is_inconclusive():
    assert run(results=LINUX, platform="linux", landlock="0")[0] == judge.INCONCLUSIVE


@pytest.mark.parametrize("landlock", ["", "unknown"])
def test_gateway_with_no_landlock_fact_on_linux_is_inconclusive(landlock):
    assert run(results=LINUX, platform="linux", landlock=landlock)[0] == judge.INCONCLUSIVE


def test_gateway_other_error_is_inconclusive():
    assert run(results=gw("BAD other"), platform="linux")[0] == judge.INCONCLUSIVE


@pytest.mark.parametrize("why", ["no-broker", "stopped", "not-found", "refused", "failed",
                                 "other"])
def test_gateway_other_error_notes_its_class_only(why):
    """A rerun must show why `phiward run` failed in the session: probes.sh records one word
    from a fixed list (never any text of the output), and the judge prints it."""
    verdict, report = run(results=gw("BAD other") + f"gateway-why {why}\n", platform="linux")
    assert verdict == judge.INCONCLUSIVE
    assert any(ln.startswith(f"note gateway-run: {why}") for ln in report), report


@pytest.mark.parametrize("err", ["permission-denied", "read-only", "not-permitted", "no-such",
                                 "python-fatal", "traceback", "landlock", "bwrap", "gateway",
                                 "none"])
def test_gateway_notes_its_exit_code_and_error_class(err):
    results = gw("BAD other") + f"gateway-why other\ngateway-exit 1\ngateway-error {err}\n"
    verdict, report = run(results=results, platform="linux")
    assert verdict == judge.INCONCLUSIVE
    assert f"note gateway-run: other, exit 1, error {err}" in report, report


@pytest.mark.parametrize("code, err", [("x1", "none"), ("1", "FAKE-PT-0001"), ("1234", "none"),
                                       ("", "")])
def test_gateway_exit_or_class_not_in_the_list_is_never_printed(code, err):
    results = gw("BAD other") + f"gateway-why other\ngateway-exit {code}\ngateway-error {err}\n"
    verdict, report = run(results=results, platform="linux")
    note = [ln for ln in report if ln.startswith("note gateway-run:")]
    assert note and "unknown" in note[0], report
    assert not any("FAKE-PT" in ln or "x1" in ln or "1234" in ln for ln in report), report


@pytest.mark.parametrize("why", ["FAKE-PT-0001", "no-broker FAKE-PT-0001", "a.txt", ""])
def test_gateway_class_not_in_the_list_is_never_printed(why):
    verdict, report = run(results=gw("BAD other") + f"gateway-why {why}\n", platform="linux")
    assert any(ln.startswith("note gateway-run: unknown") for ln in report), report
    assert not any("FAKE-PT" in ln or "a.txt" in ln for ln in report), report


def test_gateway_class_is_not_printed_when_the_gateway_masked():
    results = LINUX + "gateway-why other\n"
    verdict, report = run(results=results, platform="linux")
    assert verdict == judge.PASS and not any(ln.startswith("note gateway-run") for ln in report)


PROBES = JUDGE.parent / "probes.sh"
NAMES = JUDGE.parent / "token-names.txt"
NO_BROKER = ("run refused: no phiward broker is running. The operator starts one with "
             "`phiward broker` in a terminal outside the agent.")
# a made-up phiward per class: what it prints (the real phrases of src/phiward), and its exit
FAKES = {
    "no-broker": (NO_BROKER, 3),
    "stopped": ("run stopped: the broker stopped before the command finished", 3),
    "refused": ("run refused: the phiward config cannot be used (run phiward doctor)", 3),
    "failed": ("run done: exit=1 (the command failed; its exit status is in the operator's "
               "broker log)", 1),
    "other": ("wc: FAKE-PT-0001/a.txt%2D ~/FAKE-PT-00 Traceback: something", 1),
}


def _probes(tmp_path, fake, proc=None, foreign=False, names=True, grep_fails=False,
            xtrace=False):
    """probes.sh in a made-up tree, with `fake` as phiward (None: no phiward on PATH), and
    `proc` as its /proc (a made-up one: {pid: environment dict, or None for an environ it cannot
    read, or "dir" for one that opens but cannot be read}; the probe's own process is "self",
    a child of 1; `foreign`: /proc/$$ is another
    process; `names`: copy token-names.txt beside it; `grep_fails`: a grep that exits 2 on the
    token-name pattern, as an awk that exits 2 on it; `names` may also be the file's text; `xtrace`: run it as sh -x).
    Its stderr is in tmp_path/"stderr.txt".
    Made-up folders only; a git repository of its own in tmp_path, no hook. -> (results, text)"""
    import shutil
    import subprocess
    if shutil.which("git") is None:
        pytest.skip("needs git")
    proj, data, free, fbin = (tmp_path / n for n in ("proj", "data", "free", "bin"))
    for d in (proj, data / "FAKE-PT-0001", free, fbin):
        d.mkdir(parents=True)
    prot = data / "FAKE-PT-0001" / "a.txt"
    prot.write_text("FAKE-MARK-1\n")
    (tmp_path / ".phiward").mkdir()
    (tmp_path / ".phiward" / "sbx-sentinel").write_text("")
    (tmp_path / "settings.json").write_text("{}\n")
    (free / "b.txt").write_text("FREE-MARK-1\n")
    shutil.copy(PROBES, proj / "probes.sh")
    if isinstance(names, str):
        (proj / "token-names.txt").write_bytes(names.encode())
    elif names:
        shutil.copy(NAMES, proj / "token-names.txt")
    if grep_fails:
        (fbin / "awk").write_text('#!/bin/sh\ncase "$*" in *CLAUDE_CODE_OAUTH_TOKEN*) exit 2 ;; '
                                  'esac\nexec /usr/bin/awk "$@"\n')
        (fbin / "awk").chmod(0o755)
    if fake is not None:
        text, code = fake
        (fbin / "phiward").write_text(f"#!/bin/sh\ncat >&2 <<'EOF'\n{text}\nEOF\nexit {code}\n")
        (fbin / "phiward").chmod(0o755)
    (proj / "paths.txt").write_text("".join(f"{k} {v}\n" for k, v in (
        ("mode", "A"), ("free", free), ("free-marker", "FREE-MARK-1"), ("protected-file", prot),
        ("protected-hash", "0"), ("data", data), ("phiward", tmp_path / ".phiward"),
        ("settings", tmp_path / "settings.json"), ("fake-id", "P-9990001-T01-IM6"),
        ("nonce", "n0"), ("remote", "no"))))
    cmd = ["sh", "./probes.sh"]
    if proc is not None:
        root = tmp_path / "proc"
        for pid, env in {"self": {"PATH": "/x"}, **proc}.items():
            (root / str(pid)).mkdir(parents=True)
            ppid = 0 if str(pid) == "1" else 1
            (root / str(pid) / "status").write_text(f"Name:\tx\nPPid:\t{ppid}\n")
            if env == "dir":
                (root / str(pid) / "environ").mkdir()
            elif env is not None:
                (root / str(pid) / "environ").write_text(
                    "".join(f"{k}={v}\0" for k, v in env.items()))
        with open(proj / "paths.txt", "a") as fh:
            fh.write(f"proc {root}\n")
        # the probe's own PID is the "self" entry, as in a real /proc (exec keeps the PID); a
        # foreign /proc has another process there
        link = "cp -R" if foreign else "ln -s"
        x = " -x" if xtrace else ""
        cmd = ["sh", "-c", f'{link} "{root}/self" "{root}/$$" && exec sh{x} ./probes.sh']
    env = {"PATH": f"{fbin}:/usr/bin:/bin", "HOME": str(tmp_path),
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "init", "-q"], cwd=proj, env=env, check=True)
    r = subprocess.run(cmd, cwd=proj, env=env, capture_output=True, text=True, timeout=60)
    (tmp_path / "stderr.txt").write_text(r.stderr)
    assert "probes-done" in r.stdout, r.stderr
    text = (proj / "results.txt").read_text()
    return dict(ln.split(" ", 1) for ln in text.splitlines() if " " in ln), text


# a made-up failing phiward per error class: (its output, its exit code); the names in it are
# made up and must never reach results.txt
ERRORS = {
    "permission-denied": ("PermissionError: [Errno 13] Permission denied: '/w/FAKE-PT-0001'", 1),
    "read-only": ("OSError: [Errno 30] Read-only file system: '/w/FAKE-PT-0001'", 1),
    "not-permitted": ("OSError: [Errno 1] Operation not permitted: '/w/FAKE-PT-0001'", 1),
    "no-such": ("FileNotFoundError: [Errno 2] No such file or directory: '/w/FAKE-PT-0001'", 1),
    "python-fatal": ("Fatal Python error: init_fs_encoding: FAKE-PT-0001", 1),
    "traceback": ("Traceback (most recent call last):\n  File \"/w/FAKE-PT-0001.py\"\nKeyError", 1),
    "landlock": ("phiward gateway: Landlock cannot add a rule; nothing runs FAKE-PT-0001", 0),
    "bwrap": ("bwrap: Can't mount proc on /newroot/proc FAKE-PT-0001", 1),
    "gateway": ("phiward gateway: the command could not start FAKE-PT-0001", 0),
    "none": ("something FAKE-PT-0001", 2),
}


@pytest.mark.parametrize("err", sorted(ERRORS))
def test_probes_record_the_exit_code_and_error_class_only(tmp_path, err):
    text, code = ERRORS[err]
    lines, kept = _probes(tmp_path, (text, code))
    assert lines["gateway-run"] == "BAD other", lines
    assert lines["gateway-error"] == err, lines
    assert lines["gateway-exit"] == str(code), lines
    assert "FAKE-PT-0001" not in kept and "Errno" not in kept, kept


@pytest.mark.parametrize("why", sorted(FAKES) + ["not-found"])
def test_probes_record_only_the_class_of_phiward_runs_failure(tmp_path, why):
    """Each made-up failure gives its word, and no text of the output reaches results.txt (the
    "other" output holds made-up names in spellings no matching would catch)."""
    lines, text = _probes(tmp_path, FAKES.get(why))
    assert lines["gateway-run"] == "BAD other"
    assert lines["gateway-why"] == why, lines
    assert "gateway-err" not in lines
    for bit in ("FAKE-PT-00", "a.txt", "%2D", "Traceback", "broker log", "doctor"):
        assert bit not in text, (bit, text)


def test_probes_see_the_targets_when_nothing_hides_them(tmp_path):
    lines, _ = _probes(tmp_path, FAKES["refused"])
    assert lines["hidden-phiward"] == "present" and lines["hidden-settings"] == "present", lines


def test_probes_see_hidden_targets_as_hidden(tmp_path):
    """No ~/.phiward and an empty settings file (as an empty view or /dev/null shows them)."""
    import shutil
    import subprocess
    proj = tmp_path / "proj"
    proj.mkdir()
    shutil.copy(PROBES, proj / "probes.sh")
    (tmp_path / "settings.json").write_text("")
    (proj / "paths.txt").write_text(f"mode A\nphiward {tmp_path / '.phiward'}\n"
                                    f"settings {tmp_path / 'settings.json'}\n")
    subprocess.run(["sh", "./probes.sh"], cwd=proj, capture_output=True, timeout=60,
                   env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)})
    lines = dict(ln.split(" ", 1) for ln in (proj / "results.txt").read_text().splitlines()
                 if " " in ln)
    assert lines["hidden-phiward"] == "hidden" and lines["hidden-settings"] == "hidden", lines


# git

def test_a_failed_control_commit_is_inconclusive():
    results = GOOD.replace("control-commit OK", "control-commit DENIED other")
    assert run(results=results)[0] == judge.INCONCLUSIVE


@pytest.mark.parametrize("value", ["OK", "DENIED leaked"])
def test_a_commit_the_hook_let_through_or_leaked_is_fail(value):
    results = GOOD.replace("git-hook DENIED refused", f"git-hook {value}")
    assert run(results=results)[0] == judge.FAIL


def test_a_hook_refusal_for_another_reason_is_inconclusive():
    results = GOOD.replace("git-hook DENIED refused", "git-hook DENIED other")
    assert run(results=results)[0] == judge.INCONCLUSIVE


# doctor, before the first session and after the last

def test_doctor_clean_is_pass():
    assert judge.doctor("ready\n", "ready\n")[0] == judge.PASS


def test_a_new_doctor_warning_after_is_fail():
    assert judge.doctor("ready\n", "WARNING: the hook is gone\n")[0] == judge.FAIL


def test_a_doctor_warning_before_is_inconclusive():
    assert judge.doctor("WARNING: x\n", "WARNING: x\n")[0] == judge.INCONCLUSIVE


@pytest.mark.parametrize("before, after", [(None, "ready\n"), ("ready\n", None), ("", "")])
def test_no_doctor_output_is_inconclusive(before, after):
    assert judge.doctor(before, after)[0] == judge.INCONCLUSIVE


# Mode B

HIDDEN = "hidden-phiward hidden\nhidden-settings hidden\n"


@pytest.mark.parametrize("mode", ["A", "B"])
@pytest.mark.parametrize("probe", ["write-data", "write-phiward", "write-settings"])
def test_linux_write_ok_into_a_hidden_target_with_no_host_file_is_a_note(probe, mode):
    """On Linux both sandboxes may put an empty, writable view over a target they hide (Mode A's
    real run: the read said "no such file", the touch worked): a write there that never reaches
    the host harms nothing, when the same run shows the target hidden (the protected file not
    found or empty, the sentinel in ~/.phiward missing, the settings empty)."""
    results = LINUX.replace(f"{probe} DENIED read-only", f"{probe} OK") + HIDDEN
    verdict, report = run(results=results, platform="linux", mode=mode)
    assert verdict == judge.PASS, report
    assert any(ln.startswith("note") and probe in ln and "nothing reached the host" in ln
               for ln in report), report


@pytest.mark.parametrize("mode", ["A", "B"])
@pytest.mark.parametrize("probe, evidence", [
    ("write-data", "read-protected DENIED read-only"),     # the data folder was not hidden
    ("write-data", "read-protected DENIED permission"),
    ("write-phiward", "hidden-phiward present"),
    ("write-phiward", "hidden-phiward unreadable"),
    ("write-phiward", None),                               # no evidence line at all
    ("write-settings", "hidden-settings present"),
    ("write-settings", "hidden-settings unreadable"),
    ("write-settings", None),
])
def test_linux_write_ok_without_evidence_the_target_was_hidden_is_fail(probe, evidence, mode):
    """A write that worked, with nothing in the run to show the target hidden, is a hole on its
    face: FAIL, as before, even when no file is found on the host."""
    results = LINUX.replace(f"{probe} DENIED read-only", f"{probe} OK") + HIDDEN
    key = probe.replace("write-", "hidden-")
    if probe == "write-data":
        results = results.replace("read-protected DENIED empty-view", evidence)
    else:
        results = "".join(ln + "\n" for ln in results.splitlines() if not ln.startswith(key + " "))
        if evidence:
            results += evidence + "\n"
    verdict, report = run(results=results, platform="linux", mode=mode)
    assert verdict == judge.FAIL, report
    assert any(ln.startswith(f"FAIL {probe}: OK: it got through, but nothing reached the host")
               and "hidden" in ln for ln in report), report


@pytest.mark.parametrize("cls", ["no-such", "empty-view"])
def test_write_data_is_excused_by_a_hidden_protected_read(cls):
    results = LINUX.replace("write-data DENIED read-only", "write-data OK").replace(
        "read-protected DENIED empty-view", f"read-protected DENIED {cls}")
    assert run(results=results, platform="linux")[0] == judge.PASS


@pytest.mark.parametrize("probe", ["write-data", "write-phiward"])
def test_the_host_fact_right_after_the_session_decides(probe):
    """check.sh records, right after each session, whether that mode's probe file was on the
    host: a file seen then is FAIL even if it was gone when the judge ran; a missing record of a
    write that worked is never PASS."""
    key = "host_" + probe.replace("-", "_")
    results = LINUX.replace(f"{probe} DENIED read-only", f"{probe} OK") + HIDDEN
    verdict, report = run(results=results, platform="linux", **{key: "yes"})
    assert verdict == judge.FAIL
    assert f"FAIL {probe}: OK: it got through, and the file reached the host" in report, report
    verdict, report = run(results=LINUX, platform="linux", **{key: "yes"})
    assert verdict == judge.FAIL, report  # refused, yet the file was there
    verdict, report = run(results=results, platform="linux", **{key: "missing"})
    assert verdict == judge.INCONCLUSIVE, report


@pytest.mark.parametrize("mode", ["A", "B"])
def test_linux_write_ok_with_a_host_file_is_fail_and_says_so(mode):
    results = LINUX.replace("write-data DENIED read-only", "write-data OK")
    verdict, report = run(results=results, platform="linux", mode=mode,
                          created=[f"/h/data/sbx-probe-{mode}"])
    assert verdict == judge.FAIL
    assert "FAIL write-data: OK: it got through, and the file reached the host" in report, report
    verdict, report = run(results=LINUX.replace("write-settings DENIED read-only",
                                                "write-settings OK"),
                          platform="linux", mode=mode, settings_same=False)
    assert verdict == judge.FAIL
    assert "FAIL write-settings: OK: it got through, and the file reached the host" in report


def test_a_write_that_worked_on_macos_says_whether_it_reached_the_host():
    """macOS never excuses a write that worked, but the report still gives the host fact."""
    results = GOOD.replace("write-data DENIED not-permitted", "write-data OK")
    verdict, report = run(results=results)
    assert verdict == judge.FAIL
    assert "FAIL write-data: OK: it got through, but nothing reached the host" in report, report
    verdict, report = run(results=results, created=["/h/data/sbx-probe-A"])
    assert "FAIL write-data: OK: it got through, and the file reached the host" in report, report


def _main_run(tmp_path, results, planted):
    """main() on a made-up home: the run folder of Mode A, and the probe files in `planted`."""
    home = tmp_path / "h"
    (home / "data").mkdir(parents=True)
    (home / ".phiward").mkdir()
    for rel in planted:
        (home / rel).write_text("")
    run_dir = tmp_path / "j" / "run-A"
    run_dir.mkdir(parents=True)
    (run_dir / "results.txt").write_text(results)
    (run_dir / "stream.jsonl").write_text("\n".join(stream()) + "\n")
    (run_dir / "server.out").write_text(f"STARTED {NONCE} READ-DENIED\n")
    (run_dir / "facts.txt").write_text("".join(
        f"{k} {v}\n" for k, v in facts("linux", "A").items()))
    return judge.main(["judge.py", str(home), "FAKE-MARK-1", str(run_dir)])


def test_main_looks_for_this_modes_probe_file_only(tmp_path, capsys):
    """Mode A's probe file is sbx-probe-A: Mode B's file on the host is not Mode A's write."""
    results = LINUX.replace("write-data DENIED read-only", "write-data OK")
    _main_run(tmp_path / "1", results, ["data/sbx-probe-B"])
    out = capsys.readouterr().out
    assert "note write-data: the write worked inside the sandbox (Mode A), and nothing reached " \
           "the host" in out, out
    assert "PASS Mode A" in out
    _main_run(tmp_path / "2", results, ["data/sbx-probe-A"])
    out = capsys.readouterr().out
    assert "FAIL write-data: OK: it got through, and the file reached the host" in out, out
    assert "FAIL Mode A" in out


def test_mode_b_macos_write_ok_is_fail():
    results = GOOD.replace("write-data DENIED not-permitted", "write-data OK")
    assert run(results=results, mode="B")[0] == judge.FAIL


def test_mode_b_namespace_error_is_inconclusive_with_that_reason():
    lines = stream(bash_result="bwrap: No permissions to creating new namespace, likely because "
                               "the kernel does not allow non-privileged user namespaces")
    verdict, report = run(results="", lines=lines, platform="linux", mode="B")
    assert verdict == judge.INCONCLUSIVE
    assert any("nested sandbox could not start" in ln for ln in report)


# the required set, from the facts

CORE = ["control-write", "control-read", "read-protected", "write-data", "write-phiward",
        "write-settings", "gateway-run", "control-commit", "git-hook", "parent-environ",
        "env-secrets", "loopback-127", "loopback-localhost", "loopback-v6", "loopback-mapped",
        "net-api", "runs-later-settings", "runs-later-skill", "runs-later-vscode",
        "runs-later-sub-vscode", "runs-later-rprofile", "runs-later-node-modules",
        "unix-renamed", "unix-late", "unix-rebound"]


@pytest.mark.parametrize("probe", CORE)
def test_each_required_probe_missing_is_inconclusive(probe):
    results = "".join(ln + "\n" for ln in GOOD.splitlines() if not ln.startswith(probe + " "))
    verdict, report = run(results=results)
    assert verdict == judge.INCONCLUSIVE and any(probe in ln for ln in report), report


@pytest.mark.parametrize("key", ["settings_same", "token_seen", "token_in_env", "nonce",
                                 "platform", "mode", "protected_file", "host_write_data",
                                 "host_write_phiward", "loopback_127", "loopback_localhost",
                                 "loopback_v6", "loopback_mapped", "unix_renamed", "unix_late",
                                 "runs_later_made", "loopback_127_after",
                                 "loopback_localhost_after", "loopback_v6_after",
                                 "loopback_mapped_after", "unix_renamed_after",
                                 "unix_rebound", "unix_rebound_after"])
def test_each_required_fact_missing_is_inconclusive(key):
    f = facts()
    del f[key]
    verdict, _ = judge.judge(results=GOOD, stream_lines=stream(),
                             server=f"STARTED {NONCE} READ-DENIED\n", marker="FAKE-MARK-1",
                             created=[], facts=f)
    assert verdict == judge.INCONCLUSIVE


@pytest.mark.parametrize("f", [None, {}])
def test_no_facts_is_inconclusive(f):
    verdict, _ = judge.judge(results=GOOD, stream_lines=stream(),
                             server=f"STARTED {NONCE} READ-DENIED\n", marker="FAKE-MARK-1",
                             created=[], facts=f)
    assert verdict == judge.INCONCLUSIVE


@pytest.mark.parametrize("over", [{"platform": "windows"}, {"mode": "C"}])
def test_an_unknown_platform_or_mode_is_inconclusive(over):
    assert run(**over)[0] == judge.INCONCLUSIVE


def test_facts_can_add_a_required_item_but_not_remove_one():
    assert run(required="extra-probe")[0] == judge.INCONCLUSIVE
    results = GOOD.replace("git-hook DENIED refused\n", "")
    assert run(results=results, required="control-write")[0] == judge.INCONCLUSIVE


def test_no_fact_skips_the_git_probes():
    """The stub runs only in the container now, with the git probes: no fact removes them."""
    results = GOOD.replace("control-commit OK\n", "").replace("git-hook DENIED refused\n", "")
    assert run(results=results, stub="yes", git="no")[0] == judge.INCONCLUSIVE


# the remote probes

REMOTE = GOOD + """remote-push OK
remote-run OK masked
remote-pull OK
remote-pull-out DENIED other
remote-own-socket DENIED other
"""


def remote(results=REMOTE, **over):
    over.setdefault("pulled_ok", "yes")
    return run(results=results, remote="yes", **over)


def test_remote_no_needs_no_remote_line():
    assert run()[0] == judge.PASS


def test_remote_full_run_is_pass():
    verdict, report = remote()
    assert verdict == judge.PASS, report


@pytest.mark.parametrize("probe", ["remote-push", "remote-run", "remote-pull", "remote-pull-out",
                                   "remote-own-socket"])
def test_remote_yes_needs_every_remote_line(probe):
    results = "".join(ln + "\n" for ln in REMOTE.splitlines() if not ln.startswith(probe + " "))
    assert remote(results=results)[0] == judge.INCONCLUSIVE


@pytest.mark.parametrize("probe", ["remote-push", "remote-pull"])
def test_a_failed_push_or_pull_is_inconclusive(probe):
    results = REMOTE.replace(f"{probe} OK", f"{probe} DENIED other")
    assert remote(results=results)[0] == judge.INCONCLUSIVE


def test_remote_run_unmasked_is_fail_and_failed_is_inconclusive():
    assert remote(results=REMOTE.replace("remote-run OK masked", "remote-run BAD unmasked"))[0] \
        == judge.FAIL
    assert remote(results=REMOTE.replace("remote-run OK masked", "remote-run BAD other"))[0] \
        == judge.INCONCLUSIVE


def test_a_pull_out_of_the_roots_that_worked_is_fail():
    assert remote(results=REMOTE.replace("remote-pull-out DENIED other", "remote-pull-out OK"))[0] \
        == judge.FAIL


def test_the_own_socket_reachable_is_fail():
    results = REMOTE.replace("remote-own-socket DENIED other", "remote-own-socket OK")
    assert remote(results=results)[0] == judge.FAIL


@pytest.mark.parametrize("pulled", ["no", None])
def test_pulled_file_not_right_is_inconclusive(pulled):
    over = {} if pulled is None else {"pulled_ok": pulled}
    if pulled is None:
        f = facts(remote="yes")
        verdict, _ = judge.judge(results=REMOTE, stream_lines=stream(),
                                 server=f"STARTED {NONCE} READ-DENIED\n", marker="FAKE-MARK-1",
                                 created=[], facts=f)
    else:
        verdict, _ = remote(**over)
    assert verdict == judge.INCONCLUSIVE


# the token in another process's environment: the probe scans every /proc entry and records only
# counts and PIDs; a token variable's name in a readable environ is FAIL

def pe(value, base=None):
    return (LINUX if base is None else base).replace(CLEAN, f"parent-environ {value}")


def scan(readable=2, refused=1, named=0, ancestors=0, error=0, pids="-", messaging=0, empty=0):
    return (f"readable={readable} empty={empty} refused={refused} token-names={named} "
            f"ancestors={ancestors} scan-error={error} messaging={messaging} pids={pids}")


@pytest.mark.parametrize("mode", ["A", "B"])
def test_a_token_name_in_a_readable_environ_is_fail(mode):
    verdict, report = run(results=pe(scan(3, 0, 2, 1, 0, "1,9")), platform="linux", mode=mode)
    assert verdict == judge.FAIL, report
    assert any(ln.startswith("FAIL") and "2 processes" in ln and "1 of them" in ln
               and "ancestor" in ln and "PID 1" in ln and "PID 9" in ln for ln in report), report


def test_a_token_name_is_fail_even_with_a_scan_error():
    assert run(results=pe(scan(3, 0, 1, 0, 1, "9")), platform="linux")[0] == judge.FAIL


def test_no_token_name_in_any_readable_environ_passes():
    verdict, report = run(results=LINUX, platform="linux")
    assert verdict == judge.PASS, report
    assert any(ln.startswith("ok") and "2 readable, 1 refused" in ln for ln in report), report


@pytest.mark.parametrize("value", [
    scan(0, 0), scan(0, 5),                 # nothing readable: the reader may be broken
    scan(2, 1, error=1),                    # a step of the read failed
    "foreign-proc", "n/a", "readable", "unreadable", "not-found", "own-pid-ns",
    scan(pids="x"), "readable=1 refused=0 token-names=0 pids=-",  # older forms
    "readable=2 refused=1 token-names=0 ancestors=0 scan-error=0 pids=-",
    "readable=2 refused=1 token-names=0 ancestors=0 scan-error=0 messaging=0 pids=-",
    scan(0, 0, empty=3),                    # only empty environs were read
    "readable=1 refused=0 token-names=0", ""])
def test_a_scan_that_read_nothing_failed_or_cannot_be_read_is_inconclusive(value):
    verdict, report = run(results=pe(value), platform="linux")
    assert verdict == judge.INCONCLUSIVE, report


def test_the_stand_in_holds_the_made_up_token_a_note():
    """The stub runs with no sandbox of its own: its token is visible, a note."""
    verdict, report = run(results=pe(scan(3, 0, 1, 1, 0, "5")), platform="linux", stub="yes")
    assert verdict == judge.PASS, report
    assert any(ln.startswith("note") and "stand-in" in ln for ln in report), report


TOKEN_ENV = {"PATH": "/x", "CLAUDE_CODE_OAUTH_TOKEN": "FAKE-TOKEN-1"}


def test_probe_the_reviewers_shape_bwrap_as_pid_1_holds_the_token(tmp_path):
    """bwrap as PID 1 of the sandbox's namespace, which started with the variable and then
    unset it in its own process: its environ still holds it. PID 1 is the probe's ancestor."""
    proc = {1: TOKEN_ENV, 3: {"PATH": "/x", "TERM": "dumb"}}
    lines, text = _probes(tmp_path, FAKES["refused"], proc=proc)
    assert lines["parent-environ"] == scan(2, 0, 1, 1, 0, "1"), lines
    verdict, _ = run(results=pe(lines["parent-environ"]), platform="linux")
    assert verdict == judge.FAIL


def _names():
    return [ln.strip() for ln in NAMES.read_text().splitlines()
            if ln.strip() and not ln.startswith("#")]


def test_the_name_list_holds_claude_codes_documented_credentials():
    """One list (token-names.txt), from code.claude.com/docs/en/env-vars and authentication."""
    names = _names()
    for n in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
              "CLAUDE_CODE_OAUTH_REFRESH_TOKEN", "AWS_BEARER_TOKEN_BEDROCK",
              "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "ANTHROPIC_AWS_API_KEY",
              "ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_FOUNDRY_AUTH_TOKEN"):
        assert n in names, n
    assert "CLAUDE_CODE_SESSION_ACCESS_TOKEN" not in names
    # Claude Code gives it to Bash commands on purpose: counted apart, never a FAIL
    assert "CLAUDE_CODE_MESSAGING_TOKEN" not in names
    assert "CLAUDE_CODE_MESSAGING_TOKEN" in NAMES.read_text()
    assert len(names) == len(set(names)) and all(n.isupper() or "_" in n for n in names)
    probes = PROBES.read_text()
    assert not any(n in probes for n in names), "the probe holds a list of its own"


@pytest.mark.parametrize("name", [
    "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "AWS_SESSION_TOKEN", "MCP_CLIENT_SECRET",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN", "ANTHROPIC_FOUNDRY_AUTH_TOKEN"])
def test_probe_any_process_with_a_listed_name_counts_however_it_is_named(tmp_path, name):
    """No test of which process is claude: a process with a renamed title, or seen by its
    command line only, counts by its environ."""
    proc = {1: {"PATH": "/x"}, 9: {"PATH": "/x", name: "FAKE-VALUE-1"}}
    lines, text = _probes(tmp_path, FAKES["refused"], proc=proc)
    assert lines["parent-environ"] == scan(2, 0, 1, 0, 0, "9"), lines
    assert "FAKE-VALUE-1" not in text and name not in text, text


def test_probe_nothing_readable_holds_a_name(tmp_path):
    proc = {1: {"PATH": "/x"}, 4: None, 7: {"PATH": "/x", "MY_TOKENISH": "FAKE-VALUE-2"}}
    lines, text = _probes(tmp_path, FAKES["refused"], proc=proc)
    assert lines["parent-environ"] == scan(2, 1, 0, 0, 0, "-"), lines
    assert run(results=pe(lines["parent-environ"]), platform="linux")[0] == judge.PASS
    assert "FAKE-VALUE-2" not in text and "MY_TOKENISH" not in text


def test_probe_counts_the_messaging_token_apart(tmp_path):
    """Claude Code exports CLAUDE_CODE_MESSAGING_TOKEN to Bash commands on purpose (env-vars
    docs): its presence is a count of its own, and the run still passes, with a note."""
    proc = {1: {"PATH": "/x"}, 9: {"PATH": "/x", "CLAUDE_CODE_MESSAGING_TOKEN": "FAKE-MSG-1"}}
    lines, text = _probes(tmp_path, FAKES["refused"], proc=proc)
    assert lines["parent-environ"] == scan(2, 0, 0, 0, 0, "-", messaging=1), lines
    assert "FAKE-MSG-1" not in text
    verdict, report = run(results=pe(lines["parent-environ"]), platform="linux")
    assert verdict == judge.PASS, report
    assert any(ln.startswith("note") and "CLAUDE_CODE_MESSAGING_TOKEN" in ln and "1 process" in ln
               for ln in report), report


def test_no_messaging_note_when_none_holds_it():
    verdict, report = run(results=LINUX, platform="linux")
    assert not any("MESSAGING" in ln for ln in report), report


def test_probe_under_xtrace_never_shows_a_value(tmp_path):
    """`sh -x ./probes.sh` (or an inherited xtrace): no environ value passes through the shell,
    and the probe turns xtrace off first."""
    proc = {1: TOKEN_ENV, 9: {"PATH": "/x", "OTHER": "FAKE-VALUE-3",
                              "CLAUDE_CODE_MESSAGING_TOKEN": "FAKE-MSG-2"}}
    lines, _ = _probes(tmp_path, FAKES["refused"], proc=proc, xtrace=True)
    err = (tmp_path / "stderr.txt").read_text()
    for value in ("FAKE-TOKEN-1", "FAKE-VALUE-3", "FAKE-MSG-2"):
        assert value not in err, err[-2000:]
    assert lines["parent-environ"] == scan(2, 0, 1, 1, 0, "1", messaging=1), lines
    first = [ln for ln in PROBES.read_text().splitlines() if ln and not ln.startswith("#")][0]
    assert first.startswith("set +x"), first


def test_probe_reads_each_environ_once():
    """One open per environ, in one pipeline: a later open cannot fail unseen."""
    text = PROBES.read_text()
    scan = text[text.index("parent-environ readable") - 4000:]
    assert scan.count('"$d/environ"') == 1, scan.count('"$d/environ"')


def test_probe_a_failed_read_of_an_environ_is_a_scan_error(tmp_path):
    """An environ that opens and then fails mid-read (here: a directory) is a scan error."""
    lines, _ = _probes(tmp_path, FAKES["refused"], proc={1: {"PATH": "/x"}, 4: "dir"})
    assert "scan-error=1" in lines["parent-environ"], lines


def test_probe_an_empty_environ_is_not_a_read(tmp_path):
    lines, _ = _probes(tmp_path, FAKES["refused"], proc={1: {}, 4: None})
    assert lines["parent-environ"] == scan(0, 1, 0, 0, 0, "-", empty=1), lines
    assert run(results=pe(lines["parent-environ"]), platform="linux")[0] == judge.INCONCLUSIVE


@pytest.mark.parametrize("text", ["ANTHROPIC_API_KEY\r\nCLAUDE_CODE_OAUTH_TOKEN\r\n",
                                  "ANTHROPIC_API_KEY\nlower_case\n",
                                  "ANTHROPIC_API_KEY\nBAD-NAME\n",
                                  "# only a comment\n"])
def test_probe_refuses_a_name_list_it_cannot_use_whole(tmp_path, text):
    """A CRLF line or a name that is not ^[A-Z][A-Z0-9_]*$ is refused, never dropped."""
    lines, _ = _probes(tmp_path, FAKES["refused"], proc={1: TOKEN_ENV}, names=text)
    assert "scan-error=1" in lines["parent-environ"], lines
    assert run(results=pe(lines["parent-environ"]), platform="linux")[0] != judge.PASS


def test_the_name_list_holds_the_header_and_github_names():
    names = _names()
    for n in ("ANTHROPIC_CUSTOM_HEADERS", "OTEL_EXPORTER_OTLP_HEADERS", "GH_TOKEN",
              "GITHUB_TOKEN"):
        assert n in names, n


def test_a_probe_line_twice_is_inconclusive():
    """The session can append to results.txt: a second line of any probe is never trusted."""
    forged = LINUX + f"{CLEAN}\n"
    verdict, report = run(results=pe(scan(3, 0, 1, 0, 0, "9")) + f"{CLEAN}\n", platform="linux")
    assert verdict != judge.PASS, report
    verdict, report = run(results=forged, platform="linux")
    assert verdict == judge.INCONCLUSIVE, report
    assert any("parent-environ" in ln and "2 times" in ln for ln in report), report


@pytest.mark.parametrize("command", ["sh -x ./probes.sh", "cd . && sh ./probes.sh",
                                     "sh ./probes.sh; cat results.txt", "bash ./probes.sh"])
def test_only_the_exact_probe_command_counts(command):
    verdict, report = run(results=LINUX, lines=stream(command=command), platform="linux")
    assert verdict == judge.INCONCLUSIVE, report


def _bash(tid, command):
    return [{"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": tid, "name": "Bash", "input": {"command": command}}]}},
            {"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": tid, "content": ""}]}}]


def test_a_second_bash_call_is_inconclusive():
    """A second call can rewrite results.txt in place (no duplicate line): one Bash call only."""
    after = _bash("t2", "sed -i 's/^read-protected .*/read-protected DENIED not-permitted/' "
                        "results.txt")
    verdict, report = run(lines=stream(*after))
    assert verdict == judge.INCONCLUSIVE, report
    assert any("2 Bash calls" in ln for ln in report), report


def test_a_bash_call_before_the_probes_is_inconclusive():
    """A first call could edit probes.sh before the exact command runs."""
    events = [json.loads(x) for x in stream()]
    events[1:1] = _bash("t0", "sed -i 's/x/y/' probes.sh")
    verdict, report = run(lines=[json.dumps(e) for e in events])
    assert verdict == judge.INCONCLUSIVE, report


def test_probe_a_refused_read_prints_nothing(tmp_path):
    _probes(tmp_path, FAKES["refused"], proc={1: {"PATH": "/x"}, 4: None})
    assert "environ" not in (tmp_path / "stderr.txt").read_text()


def test_probe_a_matcher_error_is_a_scan_error_not_no_name(tmp_path):
    lines, _ = _probes(tmp_path, FAKES["refused"], proc={1: {"PATH": "/x"}}, grep_fails=True)
    assert lines["parent-environ"] == scan(0, 0, 0, 0, 1, "-"), lines
    assert run(results=pe(lines["parent-environ"]), platform="linux")[0] == judge.INCONCLUSIVE


def test_probe_without_the_name_list_is_a_scan_error(tmp_path):
    lines, _ = _probes(tmp_path, FAKES["refused"], proc={1: TOKEN_ENV}, names=False)
    assert "scan-error=1" in lines["parent-environ"], lines
    assert run(results=pe(lines["parent-environ"]), platform="linux")[0] != judge.PASS


def test_probe_an_empty_proc_is_inconclusive(tmp_path):
    lines, _ = _probes(tmp_path, FAKES["refused"], proc={})
    assert lines["parent-environ"] == scan(0, 0, 0, 0, 0, "-"), lines
    assert run(results=pe(lines["parent-environ"]), platform="linux")[0] == judge.INCONCLUSIVE


def test_probe_records_nothing_from_a_proc_that_is_not_its_own(tmp_path):
    """/proc/$$ must be this process (/proc/self): else the scan reads another view."""
    lines, _ = _probes(tmp_path, FAKES["refused"], proc={1: TOKEN_ENV}, foreign=True)
    assert lines["parent-environ"] == "foreign-proc", lines


def test_claude_environ_n_a_on_macos_passes():
    assert run()[0] == judge.PASS


def test_parent_environ_fact_is_not_used():
    """The session writes no environment to disk now: an old fact changes nothing."""
    verdict, report = run(results=LINUX, platform="linux", parent_environ="yes")
    assert verdict == judge.PASS and not any("documented limit" in ln for ln in report)


# Linux Mode B: the wrapped MCP server is required and starts (its launch inside the session runs
# it directly); a server that did not start is not excused by a known cause any more

def test_linux_mode_b_server_is_required_like_everywhere_else():
    verdict, report = run(results=LINUX, platform="linux", mode="B", server="")
    assert verdict == judge.INCONCLUSIVE
    assert "???? the wrapped MCP server did not start in this run" in report, report
    assert not any("~/.phiward" in ln for ln in report), report
    verdict, report = run(results=LINUX, platform="linux", mode="B")
    assert "ok   the wrapped MCP server started and could not read the protected file" in report


def test_doctor_lists_a_warning_before_also_when_it_fails():
    verdict, report = judge.doctor("WARNING: a\n", "WARNING: a\nWARNING: b\n")
    assert verdict == judge.FAIL
    assert any(ln.startswith("???? doctor: a warning before") for ln in report)


# the overall line: PASS only if every mode and doctor passed

def test_overall():
    P, F, I = judge.PASS, judge.FAIL, judge.INCONCLUSIVE
    assert judge.overall([P, P, P]) == P
    assert judge.overall([P, I, P]) == I
    assert judge.overall([I, F, P]) == F
    assert judge.overall([]) == I


# the facts file

def test_read_facts():
    assert judge.read_facts("platform linux\nmode B\nrequired a b\n\n") == {
        "platform": "linux", "mode": "B", "required": "a b"}


# the token is redacted from every kept file before the judge reads it

LAUNCH = JUDGE.parent / "launch.py"


def _launch_module():
    spec = importlib.util.spec_from_file_location("sbx_launch2", LAUNCH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # no side effects on import
    return mod


TOKEN = "FAKE-TOKEN-0011223344556677"


def _run_dir(tmp_path, stream_text):
    h = tmp_path / "h"
    for m in ("A", "B"):
        (h / f"run-{m}").mkdir(parents=True)
        (h / f"run-{m}" / "stream.jsonl").write_text(stream_text)
        (h / f"run-{m}" / "facts.txt").write_text(f"mode {m}\n")
        (h / f"run-{m}" / "results.txt").write_text(f"x {TOKEN}\n")  # never kept
    (h / "report.txt").write_text(f"note the Bash call returned: {TOKEN}\nPASS\n")
    return h


def test_keep_writes_only_the_report_streams_and_facts_redacted(tmp_path):
    h = _run_dir(tmp_path, f'{{"t": "{TOKEN}"}}\n')
    out = tmp_path / "out"
    out.mkdir()
    text = _launch_module().keep(TOKEN, str(h / "report.txt"),
                                 [str(h / "run-A"), str(h / "run-B")], str(out))
    assert TOKEN not in text and "<TOKEN>" in text
    assert sorted(os.listdir(out)) == ["facts-A.txt", "facts-B.txt", "report.txt",
                                       "stream-A.jsonl", "stream-B.jsonl"]
    for f in os.listdir(out):
        assert TOKEN not in (out / f).read_text()


def test_keep_with_no_folder_writes_nothing(tmp_path):
    h = _run_dir(tmp_path, "plain\n")
    text = _launch_module().keep(TOKEN, str(h / "report.txt"), [str(h / "run-A")], None)
    assert TOKEN not in text


def test_keep_fails_closed_when_the_token_survives(tmp_path):
    """A token whose replacement makes it again: nothing is written, and it raises."""
    token = "X<TOKEN>X"
    h = _run_dir(tmp_path, "XX<TOKEN>XX\n")
    out = tmp_path / "out"
    out.mkdir()
    launch = _launch_module()
    with pytest.raises(launch.KeepError):
        launch.keep(token, str(h / "report.txt"), [str(h / "run-A")], str(out))
    assert os.listdir(out) == []


def test_keep_command_says_nothing_kept_on_failure(tmp_path):
    import subprocess
    import sys
    h = _run_dir(tmp_path, "XX<TOKEN>XX\n")
    out = tmp_path / "out"
    out.mkdir()
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY")}
    r = subprocess.run([sys.executable, str(LAUNCH), "--keep", str(out), str(h / "report.txt"),
                        str(h / "run-A")], input=b"X<TOKEN>X\n", capture_output=True, env=env)
    assert r.returncode != 0
    assert b"redaction failed: nothing kept" in r.stderr
    assert b"XX" not in r.stdout and os.listdir(out) == []


def test_keep_command_prints_the_redacted_report(tmp_path):
    import subprocess
    import sys
    h = _run_dir(tmp_path, f"{TOKEN}\n")
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY")}
    r = subprocess.run([sys.executable, str(LAUNCH), "--keep", "-", str(h / "report.txt"),
                        str(h / "run-A")], input=(TOKEN + "\n").encode(), capture_output=True,
                       env=env)
    assert r.returncode == 0, r.stderr
    assert TOKEN.encode() not in r.stdout and b"<TOKEN>" in r.stdout


CHILD = """import os, sys, time
print(os.environ["CLAUDE_CODE_OAUTH_TOKEN"], flush=True)
open(sys.argv[1], "w").write(str(os.getpid()))
time.sleep(60)
"""


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _setup_launch(tmp_path):
    home, run_dir = tmp_path / "h", tmp_path / "h" / "run-A"
    (home / "proj").mkdir(parents=True)
    run_dir.mkdir()
    (home / "proj" / "env.txt").write_text(f"CLAUDE_CODE_OAUTH_TOKEN={TOKEN}\n")
    child, pidfile = tmp_path / "child.py", tmp_path / "pid"
    child.write_text(CHILD)
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY")}
    return home, run_dir, child, pidfile, env


@pytest.mark.parametrize("sig, code", [("SIGINT", 130), ("SIGTERM", 143), ("SIGHUP", 129)])
def test_an_interrupted_launch_stops_claude_and_records(tmp_path, sig, code):
    """Ctrl-C, SIGTERM or a closed terminal on launch.py: the session is stopped, the records
    written and env.txt removed; the exit code is 128 + the signal."""
    import signal
    import subprocess
    import sys
    import time
    home, run_dir, child, pidfile, env = _setup_launch(tmp_path)
    p = subprocess.Popen([sys.executable, str(LAUNCH), str(home), str(run_dir), "60", "--",
                          sys.executable, str(child), str(pidfile)],
                         stdin=subprocess.PIPE, env=env)
    p.stdin.write((TOKEN + "\n").encode())
    p.stdin.close()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and not pidfile.exists():
        time.sleep(0.05)
    time.sleep(0.2)
    p.send_signal(getattr(signal, sig))
    assert p.wait(timeout=30) == code
    time.sleep(0.2)
    assert not _alive(int(pidfile.read_text())), "claude kept running"
    assert not (home / "proj" / "env.txt").exists()
    assert (run_dir / "token-seen").read_text().strip() == "yes"
    assert (run_dir / "token-in-env").read_text().strip() == "yes"


FORK_WINDOW = """import importlib.util, os, signal, subprocess, sys
spec = importlib.util.spec_from_file_location("l", sys.argv[1])
launch = importlib.util.module_from_spec(spec); spec.loader.exec_module(launch)
real = subprocess.Popen
def popen(*a, **k):  # the signal arrives between the handler and the assignment of p
    os.kill(os.getpid(), signal.SIGTERM)
    return real(*a, **k)
launch.subprocess.Popen = popen
sys.exit(launch.main(["launch.py"] + sys.argv[2:]))
"""


def test_a_signal_in_the_fork_window_still_stops_claude(tmp_path):
    import subprocess
    import sys
    home, run_dir, child, pidfile, env = _setup_launch(tmp_path)
    r = subprocess.run([sys.executable, "-c", FORK_WINDOW, str(LAUNCH), str(home), str(run_dir),
                        "60", "--", sys.executable, str(child), str(pidfile)],
                       input=(TOKEN + "\n").encode(), env=env, timeout=60)
    assert r.returncode == 143
    if pidfile.exists():
        import time
        time.sleep(0.2)
        assert not _alive(int(pidfile.read_text())), "claude kept running"
    assert (run_dir / "token-seen").exists()



def test_keep_writes_nothing_when_interrupted(tmp_path, monkeypatch):
    """Any failure while writing, a KeyboardInterrupt too: no file is left, final or partial."""
    h = _run_dir(tmp_path, f"{TOKEN}\n")
    out = tmp_path / "out"
    out.mkdir()
    launch = _launch_module()
    calls = []

    def rename(a, b):
        calls.append(a)
        if len(calls) == 2:
            raise KeyboardInterrupt
        os.replace(a, b)
    monkeypatch.setattr(launch.os, "rename", rename)
    with pytest.raises(KeyboardInterrupt):
        launch.keep(TOKEN, str(h / "report.txt"), [str(h / "run-A")], str(out))
    assert os.listdir(out) == []


API_CHILD = """import os
print("api" if os.environ.get("ANTHROPIC_API_KEY") else "none",
      "oauth" if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN") else "none", flush=True)
"""


@pytest.mark.parametrize("line, want", [(f"ANTHROPIC_API_KEY={TOKEN}", "api none"),
                                        (TOKEN, "none oauth")])
def test_the_token_on_stdin_names_its_variable(tmp_path, line, want):
    """check.sh unsets the token variables and passes the token on stdin, with its name when it
    is an API key."""
    import subprocess
    import sys
    home, run_dir, child, _pidfile, env = _setup_launch(tmp_path)
    child.write_text(API_CHILD)
    r = subprocess.run([sys.executable, str(LAUNCH), str(home), str(run_dir), "30", "--",
                        sys.executable, str(child)], input=(line + "\n").encode(), env=env,
                       timeout=60)
    assert r.returncode == 0
    assert (run_dir / "stream.jsonl").read_text().strip() == want


def test_the_stream_is_written_by_launch_after_the_session(tmp_path):
    """The session's output reaches the stream file through launch.py, which writes it after
    the session is stopped: the session never holds the file."""
    import subprocess
    import sys
    home, run_dir, child, _pidfile, env = _setup_launch(tmp_path)
    child.write_text('import os, sys\nprint(os.readlink("/proc/self/fd/1") '
                     'if os.path.exists("/proc/self/fd/1") else "pipe-check", flush=True)\n'
                     'import stat\nprint("pipe" if stat.S_ISFIFO(os.fstat(1).st_mode) '
                     'else "file", flush=True)\n')
    r = subprocess.run([sys.executable, str(LAUNCH), str(home), str(run_dir), "30", "--",
                        sys.executable, str(child)], input=(TOKEN + "\n").encode(), env=env,
                       timeout=60)
    assert r.returncode == 0
    assert (run_dir / "stream.jsonl").read_text().splitlines()[-1] == "pipe"



def test_keep_never_removes_a_file_it_did_not_make(tmp_path):
    h = _run_dir(tmp_path, f"{TOKEN}\n")
    out = tmp_path / "out"
    out.mkdir()
    theirs = out / ".stream-A.jsonl.part"
    theirs.write_text("not ours\n")
    with pytest.raises(FileExistsError):
        _launch_module().keep(TOKEN, str(h / "report.txt"), [str(h / "run-A")], str(out))
    assert theirs.read_text() == "not ours\n"
    assert sorted(os.listdir(out)) == [".stream-A.jsonl.part"]


CLEANUP = JUDGE.parent / "cleanup.sh"
DRIVER = """. "$1"
H=$2; J=$3; lpid=""; broker=""; tty_mode=""
trap cleanup EXIT
trap 'stopped INT 130' INT
trap 'stopped TERM 143' TERM
trap 'stopped HUP 129' HUP
echo ready
exit 0
"""


def test_a_second_signal_during_the_cleanup_does_not_cut_it_short(tmp_path):
    """Two Ctrl-C while the cleanup waits: it still removes both folders (one with a folder
    the session made unwritable)."""
    import signal
    import subprocess
    import time
    h, j = tmp_path / "h", tmp_path / "j"
    (h / "locked").mkdir(parents=True)
    (h / "locked" / "f").write_text("x")
    (h / "locked").chmod(0o500)
    j.mkdir()
    driver = tmp_path / "driver.sh"
    driver.write_text(DRIVER)
    env = dict(os.environ, SBX_CLEANUP_WAIT="1")
    p = subprocess.Popen(["sh", str(driver), str(CLEANUP), str(h), str(j)],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    assert p.stdout.readline().strip() == b"ready"
    time.sleep(0.3)  # in the cleanup's wait now
    p.send_signal(signal.SIGINT)
    time.sleep(0.3)
    p.send_signal(signal.SIGINT)
    p.wait(timeout=30)
    assert not h.exists() and not j.exists()


PLACES = JUDGE.parent / "places.sh"
SRC = Path(__file__).resolve().parents[1] / "src"
PLACES_DRIVER = '. "$1"; shift; "$@"\n'


def _places(tmp_path, *args, env=None):
    """Run one of places.sh's checks (check.sh sources it) on made-up folders: nothing is built."""
    import subprocess
    driver = tmp_path / "places-driver.sh"
    driver.write_text(PLACES_DRIVER)
    return subprocess.run(["sh", str(driver), str(PLACES)] + [str(a) for a in args],
                          capture_output=True, text=True, timeout=60,
                          env=env or dict(os.environ))


def _made_up_home(tmp_path):
    """A made-up home folder with a base below it (as on a cluster: ~/phiward-sbx/run)."""
    home = (tmp_path / "home" / "fake-user").resolve()
    base = home / "phiward-sbx" / "run"
    base.mkdir(parents=True)
    return home, base


def test_a_base_below_a_clean_home_passes(tmp_path):
    home, base = _made_up_home(tmp_path)
    r = _places(tmp_path, "sbx_base_check", base, f"{home}\n{home}")
    assert r.returncode == 0, r.stderr


def test_the_home_folder_itself_is_refused_as_the_base(tmp_path):
    home, _base = _made_up_home(tmp_path)
    r = _places(tmp_path, "sbx_base_check", home, str(home))
    assert r.returncode == 2
    assert "SBX_BASE may not be your home folder" in r.stderr


@pytest.mark.parametrize("name", ["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".claude", ".git",
                                  ".mcp.json", ".phiward.toml", ".agent-guards.toml"])
@pytest.mark.parametrize("where", ["home", "between", "base"])
def test_a_name_claude_code_or_phiward_picks_up_above_the_base_is_refused(tmp_path, name, where):
    """Claude Code reads CLAUDE.md, CLAUDE.local.md and .claude/rules from every folder above the
    session's, and phiward the settings of every .claude or .git above a call: a real one there
    would be read into the test session."""
    home, base = _made_up_home(tmp_path)
    at = {"home": home, "between": base.parent, "base": base}[where]
    if name in (".claude", ".git"):
        (at / name).mkdir()
    else:
        (at / name).write_text("made up\n")
    r = _places(tmp_path, "sbx_base_check", base, str(home))
    assert r.returncode == 2
    assert f"{at}/{name}" in r.stderr


def test_another_spelling_of_the_home_folder_is_refused(tmp_path):
    """The home folder is known by identity, not by its spelling (macOS folds letter case)."""
    home, _base = _made_up_home(tmp_path)
    other = home.parent / home.name.upper()
    if not other.exists():
        pytest.skip("a volume that keeps letter case apart")
    r = _places(tmp_path, "sbx_base_check", other, str(home))
    assert r.returncode == 2
    assert "SBX_BASE may not be your home folder" in r.stderr
    t = home / "phiward-sbx" / "run" / "tools"
    t.mkdir()
    r = _places(tmp_path, "sbx_tools_place", t, home.parent / "FAKE-USER" / "phiward-sbx" / "run")
    assert r.returncode == 2


def test_a_link_by_such_a_name_is_refused_too(tmp_path):
    home, base = _made_up_home(tmp_path)
    (home / ".claude").symlink_to(tmp_path / "nowhere")
    r = _places(tmp_path, "sbx_base_check", base, str(home))
    assert r.returncode == 2


@pytest.mark.parametrize("tools", ["relative/bin", "/no/such/folder-FAKE"])
def test_sbx_tools_must_be_an_existing_absolute_folder(tmp_path, tools):
    _home, base = _made_up_home(tmp_path)
    r = _places(tmp_path, "sbx_tools_place", tools, base)
    assert r.returncode == 2
    assert "SBX_TOOLS" in r.stderr


@pytest.mark.parametrize("rel", [".", "phiward-sbx-FAKE/bin", ".."])
def test_sbx_tools_in_or_above_the_base_is_refused(tmp_path, rel):
    """The check's home and judge's folder are made in SBX_BASE: SBX_TOOLS may not be there, or
    hold them."""
    _home, base = _made_up_home(tmp_path)
    t = base / rel
    t.mkdir(parents=True, exist_ok=True)
    r = _places(tmp_path, "sbx_tools_place", t, base)
    assert r.returncode == 2
    assert "SBX_TOOLS" in r.stderr


def _socat(folder):
    """A made-up socat (it is never run)."""
    f = folder / "socat"
    f.write_text("#!/bin/sh\nexit 1\n")
    f.chmod(0o755)
    return f


def test_sbx_tools_next_to_the_base_is_placed(tmp_path):
    home, base = _made_up_home(tmp_path)
    t = home / "phiward-sbx" / "tools" / "bin"
    t.mkdir(parents=True)
    _socat(t)
    r = _places(tmp_path, "sbx_tools_place", t, base)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == str(t)


@pytest.mark.parametrize("extra", ["bwrap", "git", "sh", ".hidden", "socat.d"])
def test_sbx_tools_holds_only_socat(tmp_path, extra):
    """Any other name could shadow a program the sandbox or the check runs (bwrap, git, sh)."""
    home, base = _made_up_home(tmp_path)
    t = home / "phiward-sbx" / "tools" / "bin"
    t.mkdir(parents=True)
    _socat(t)
    (t / extra).write_text("made up\n")
    r = _places(tmp_path, "sbx_tools_place", t, base)
    assert r.returncode == 2
    assert "SBX_TOOLS may hold only socat" in r.stderr


def test_sbx_tools_without_socat_is_refused(tmp_path):
    home, base = _made_up_home(tmp_path)
    t = home / "phiward-sbx" / "tools" / "bin"
    t.mkdir(parents=True)
    r = _places(tmp_path, "sbx_tools_place", t, base)
    assert r.returncode == 2
    assert "SBX_TOOLS holds no socat" in r.stderr


def _phiward_env(tmp_path):
    """The installed phiward of the check, made up: src on PYTHONPATH, a made-up home."""
    home = tmp_path / "check-home"
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    return home, dict(os.environ, HOME=str(home), TMPDIR=str(home / "tmp"), PYTHONPATH=str(SRC))


def _tools_safe(tmp_path, tools):
    """The check runs it before the build: the source tree's phiward, by an isolated Python
    (-I, so no PYTHONPATH), with the check's home."""
    import sys
    home, env = _phiward_env(tmp_path)
    env.pop("PYTHONPATH")
    return _places(tmp_path, "sbx_tools_safe", sys.executable, SRC, home, tools, env=env)


@pytest.fixture
def outside_temp():
    """A made-up folder outside every temp folder phiward knows. The tests' own folders are in
    /tmp, which every account may write (sticky, mode 1777) and which phiward counts as a temp
    folder, so a PATH folder or a wheel there is refused for that alone. On macOS: the per-user
    temp folder, which the check's run does not count as one (its TMPDIR is the made-up home's).
    Where TMPDIR is /tmp (Linux): a new folder in your home folder. Made 0700, removed after."""
    import shutil
    import tempfile
    base = os.environ.get("TMPDIR", "")
    tmp = os.path.realpath("/tmp")
    if not base or os.path.realpath(base) == tmp or os.path.realpath(base).startswith(tmp + "/"):
        base = str(Path.home())
    d = Path(tempfile.mkdtemp(prefix="phiward-sbx-tools-", dir=base)).resolve()
    d.chmod(0o700)
    yield d
    for p in [d] + list(d.rglob("*")):
        if p.is_dir():
            p.chmod(0o755)
    shutil.rmtree(d)


@pytest.mark.parametrize("bad", ["tools", "parent"])
def test_sbx_tools_writable_by_group_is_refused(tmp_path, outside_temp, bad):
    """phiward's own rule for a PATH folder (service.path_entries, selfcheck.safe_path): the
    folder and every folder above it are the user's or root's, and no group can write them."""
    t = outside_temp / "share" / "tools"
    t.mkdir(parents=True)
    t.parent.chmod(0o755)
    t.chmod(0o755)
    _socat(t)
    (t if bad == "tools" else t.parent).chmod(0o775)
    r = _tools_safe(tmp_path, t)
    assert r.returncode == 2
    assert "SBX_TOOLS" in r.stderr and "writable" in r.stderr


def test_sbx_tools_in_a_temp_folder_is_refused(tmp_path):
    """The session may write the temp folders: a program planted there would run as a tool."""
    home, _env = _phiward_env(tmp_path)
    t = home / "tmp" / "tools"
    t.mkdir(parents=True)
    _socat(t)
    r = _tools_safe(tmp_path, t.resolve())
    assert r.returncode == 2
    assert "SBX_TOOLS is not a safe PATH folder (a temp folder" in r.stderr


def test_a_safe_sbx_tools_passes(tmp_path, outside_temp):
    t = outside_temp / "own" / "tools"
    t.mkdir(parents=True)
    t.parent.chmod(0o755)
    t.chmod(0o755)
    _socat(t)
    r = _tools_safe(tmp_path, t)
    assert r.returncode == 0, r.stderr


def test_a_socat_others_can_write_is_refused(tmp_path, outside_temp):
    """The folder is safe, the file in it is not (umask 002 on a cluster): another account could
    replace what Claude Code's sandbox runs."""
    t = outside_temp / "own" / "tools"
    t.mkdir(parents=True)
    t.parent.chmod(0o755)
    t.chmod(0o755)
    _socat(t).chmod(0o666)
    r = _tools_safe(tmp_path, t)
    assert r.returncode == 2
    assert "socat" in r.stderr and "writable" in r.stderr


def test_a_socat_linked_into_a_folder_others_can_write_is_refused(tmp_path, outside_temp):
    t = outside_temp / "own" / "tools"
    t.mkdir(parents=True)
    t.parent.chmod(0o755)
    t.chmod(0o755)
    shared = outside_temp / "shared"
    shared.mkdir()
    real = _socat(shared)
    shared.chmod(0o777)
    (t / "socat").symlink_to(real)
    r = _tools_safe(tmp_path, t)
    assert r.returncode == 2
    assert "socat" in r.stderr and "writable" in r.stderr


@pytest.mark.parametrize("tools, want", [
    ("", "/h/bin:/h/.local/bin:/usr/bin:/bin"),
    ("/opt/FAKE-tools/bin", "/h/bin:/h/.local/bin:/opt/FAKE-tools/bin:/usr/bin:/bin")])
def test_the_session_path_puts_sbx_tools_before_the_system_folders(tmp_path, tools, want):
    r = _places(tmp_path, "session_path", "/h", tools, "/usr/bin:/bin")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == want


@pytest.mark.parametrize("variant, canon", [("claude.md", "CLAUDE.md"), (".Claude", ".claude"),
                                            ("agents.MD", "AGENTS.md"), (".Claude-link", ".claude")])
def test_a_name_in_other_letter_case_is_refused_where_case_is_ignored(tmp_path, variant, canon):
    """On a volume that ignores letter case (macOS), Claude Code finds claude.md as CLAUDE.md."""
    home, base = _made_up_home(tmp_path)
    if variant == ".Claude-link":
        (home / ".Claude").symlink_to(tmp_path / "nowhere")  # a dangling link
    elif variant == ".Claude":
        (home / variant).mkdir()
    else:
        (home / variant).write_text("made up\n")
    if not os.path.lexists(home / canon):
        pytest.skip("a volume that keeps letter case apart")
    r = _places(tmp_path, "sbx_base_check", base, str(home))
    assert r.returncode == 2



def test_the_passwd_home_is_found_for_this_account(tmp_path):
    import pwd
    r = _places(tmp_path, "sbx_passwd_home")
    assert r.returncode == 0, r.stderr
    assert os.path.samefile(r.stdout.rstrip("\n"), pwd.getpwuid(os.getuid()).pw_dir)


def test_no_passwd_home_is_refused(tmp_path):
    """When the account database names no home folder, the check cannot tell where yours is."""
    import shutil
    fake = tmp_path / "bin"
    fake.mkdir()
    for tool in ("getent", "dscl"):
        (fake / tool).write_text("#!/bin/sh\nexit 2\n")
        (fake / tool).chmod(0o755)
    for tool in ("id", "sh"):
        (fake / tool).symlink_to(shutil.which(tool))
    r = _places(tmp_path, "sbx_passwd_home", env=dict(os.environ, PATH=str(fake)))
    assert r.returncode == 2
    assert "home folder" in r.stderr


def test_launch_takes_the_token_from_stdin_only(tmp_path):
    """check.sh takes the token at its prompt only and passes it on stdin: a token variable in
    launch.py's environment is not used (nor passed on)."""
    import subprocess
    import sys
    home, run_dir, child, _pidfile, env = _setup_launch(tmp_path)
    child.write_text(API_CHILD)
    env["CLAUDE_CODE_OAUTH_TOKEN"] = "FAKE-ENV-TOKEN"
    r = subprocess.run([sys.executable, str(LAUNCH), str(home), str(run_dir), "30", "--",
                        sys.executable, str(child)], input=f"ANTHROPIC_API_KEY={TOKEN}\n".encode(),
                       env=env, timeout=60)
    assert r.returncode == 0
    assert (run_dir / "stream.jsonl").read_text().strip() == "api none"


def _programs_safe(tmp_path, *progs):
    import sys
    home, env = _phiward_env(tmp_path)
    env.pop("PYTHONPATH")
    return _places(tmp_path, "sbx_programs_safe", sys.executable, SRC, *progs, env=env)


def test_a_claude_others_can_write_is_refused(tmp_path, outside_temp):
    """claude gets the token, and uv builds what runs: found through your PATH, each must pass
    phiward's rule (selfcheck.safe_path), as SBX_TOOLS does."""
    d = outside_temp / "bin"
    d.mkdir()
    d.chmod(0o755)
    claude = _socat(d).rename(d / "claude")
    d.chmod(0o775)
    r = _programs_safe(tmp_path, claude)
    assert r.returncode == 2
    assert "claude" in r.stderr and "writable" in r.stderr


def test_safe_programs_pass(tmp_path, outside_temp):
    d = outside_temp / "bin"
    d.mkdir()
    d.chmod(0o755)
    claude = _socat(d).rename(d / "claude")
    r = _programs_safe(tmp_path, claude)
    assert r.returncode == 0, r.stderr


def _wheel_check(tmp_path, wheel, digest):
    import sys
    home, env = _phiward_env(tmp_path)
    env.pop("PYTHONPATH")
    return _places(tmp_path, "sbx_wheel_check", sys.executable, SRC, wheel, digest, env=env)


def test_a_wheel_with_another_sha256_is_refused(tmp_path, outside_temp):
    import hashlib
    w = outside_temp / "phiward-0-py3-none-any.whl"
    w.write_bytes(b"made up")
    w.chmod(0o644)
    r = _wheel_check(tmp_path, w, hashlib.sha256(b"other").hexdigest())
    assert r.returncode == 2
    assert "sha256" in r.stderr
    r = _wheel_check(tmp_path, w, hashlib.sha256(b"made up").hexdigest())
    assert r.returncode == 0, r.stderr


def test_a_wheel_others_can_write_is_refused(tmp_path, outside_temp):
    import hashlib
    w = outside_temp / "phiward-0-py3-none-any.whl"
    w.write_bytes(b"made up")
    w.chmod(0o664)
    r = _wheel_check(tmp_path, w, hashlib.sha256(b"made up").hexdigest())
    assert r.returncode == 2
    assert "writable" in r.stderr


@pytest.mark.parametrize("digest", ["", "abc", "Z" * 64])
def test_a_wheel_needs_its_sha256(tmp_path, digest):
    w = tmp_path / "phiward-0-py3-none-any.whl"
    w.write_bytes(b"made up")
    r = _wheel_check(tmp_path, w, digest)
    assert r.returncode == 2
    assert "SBX_WHEEL_SHA256" in r.stderr


# --- the new guards: loopback, the network under launch, files that run later, unix sockets ---

LOOPBACK = ["loopback-127", "loopback-localhost", "loopback-v6", "loopback-mapped"]
RUNS_LATER = ["runs-later-settings", "runs-later-skill", "runs-later-vscode",
              "runs-later-sub-vscode", "runs-later-rprofile"]
UNIX = ["unix-renamed", "unix-late", "unix-rebound"]


def _set(results, name, value):
    """`results` with the line of probe `name` replaced by `name value`."""
    out = [ln for ln in results.splitlines() if not ln.startswith(name + " ")]
    return "\n".join(out + [f"{name} {value}"]) + "\n"


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_mode_b_with_every_new_guard_holding_is_pass(platform):
    results = GOOD if platform == "darwin" else LINUX
    verdict, report = run(results=results, platform=platform, mode="B")
    assert verdict == judge.PASS, report
    for name in LOOPBACK + RUNS_LATER + UNIX + ["net-api", "runs-later-node-modules"]:
        assert any(ln.startswith(f"ok   {name}:") for ln in report), (name, report)


@pytest.mark.parametrize("name", LOOPBACK)
@pytest.mark.parametrize("value", ["RESPONSE 222", "RESPONSE 403", "RESPONSE other"])
def test_mode_b_any_loopback_response_is_fail(name, value):
    verdict, report = run(results=_set(GOOD, name, value), mode="B")
    assert verdict == judge.FAIL, report
    assert any(ln.startswith(f"FAIL {name}:") for ln in report), report


@pytest.mark.parametrize("name", LOOPBACK)
def test_mode_a_loopback_is_only_noted(name):
    """Mode A makes no loopback promise (docs): the outcome is recorded, never a verdict."""
    verdict, report = run(results=_set(GOOD, name, "RESPONSE 222"), mode="A")
    assert verdict == judge.PASS, report
    assert any(ln.startswith(f"note {name}: RESPONSE 222") for ln in report), report


@pytest.mark.parametrize("name", ["loopback-127", "loopback-localhost"])
def test_mode_b_loopback_refused_but_the_server_did_not_answer_outside_is_inconclusive(name):
    """A refusal proves nothing when the made-up server did not answer from outside either."""
    verdict, report = run(mode="B", **{name.replace("-", "_"): "no"})
    assert verdict == judge.INCONCLUSIVE, report


@pytest.mark.parametrize("name", ["loopback-v6", "loopback-mapped"])
def test_mode_b_no_ipv6_loopback_on_the_machine_is_a_note(name):
    verdict, report = run(mode="B", **{name.replace("-", "_"): "no"})
    assert verdict == judge.PASS, report
    assert any(ln.startswith(f"note {name}:") and "not tested" in ln for ln in report), report
    # but a response is still a response
    verdict, _ = run(results=_set(GOOD, name, "RESPONSE 222"), mode="B",
                     **{name.replace("-", "_"): "no"})
    assert verdict == judge.FAIL


@pytest.mark.parametrize("value", ["REFUSED other", "n/a", "REFUSED FAKE-PT-0001", "OK"])
def test_mode_b_loopback_unknown_value_is_inconclusive(value):
    verdict, _ = run(results=_set(GOOD, "loopback-127", value), mode="B")
    assert verdict == judge.INCONCLUSIVE


def test_mode_b_bash_with_no_network_is_inconclusive():
    """A request to api.anthropic.com must get an HTTP status (any): else launch broke Bash's
    network, a typical-use break, not a hole."""
    for value in ("FAILED tunnel", "FAILED refused", "n/a"):
        verdict, report = run(results=_set(LINUX, "net-api", value), mode="B", platform="linux")
        assert verdict == judge.INCONCLUSIVE, (value, report)
    verdict, report = run(results=_set(LINUX, "net-api", "STATUS 401"), mode="B",
                          platform="linux")
    assert verdict == judge.PASS, report
    verdict, report = run(results=_set(GOOD, "net-api", "FAILED tunnel"), mode="A")
    assert verdict == judge.PASS, report
    assert any(ln.startswith("note net-api: FAILED tunnel") for ln in report), report


@pytest.mark.parametrize("name", RUNS_LATER)
def test_mode_b_a_file_that_runs_later_written_is_fail(name):
    verdict, report = run(results=_set(GOOD, name, "OK"), mode="B")
    assert verdict == judge.FAIL, report
    assert any(ln.startswith(f"FAIL {name}:") for ln in report), report


@pytest.mark.parametrize("name", RUNS_LATER)
@pytest.mark.parametrize("value", ["DENIED no-such", "DENIED empty-view", "DENIED other", "n/a"])
def test_mode_b_a_file_that_runs_later_refused_for_another_reason_is_inconclusive(name, value):
    """The check makes each target's folder first: a missing one proves nothing."""
    verdict, _ = run(results=_set(LINUX, name, value), mode="B", platform="linux")
    assert verdict == judge.INCONCLUSIVE


def test_mode_b_macos_refuses_files_that_run_later_with_eperm_only():
    verdict, _ = run(results=_set(GOOD, "runs-later-vscode", "DENIED read-only"), mode="B")
    assert verdict == judge.INCONCLUSIVE


def test_mode_b_installed_trees_stay_writable():
    verdict, report = run(results=_set(GOOD, "runs-later-node-modules", "DENIED not-permitted"),
                          mode="B")
    assert verdict == judge.INCONCLUSIVE, report
    assert any("runs-later-node-modules" in ln and "typical" in ln for ln in report), report


def test_mode_b_a_file_that_runs_later_made_on_the_host_is_fail():
    """check.sh records which targets were on the host right after the session, though the
    line says refused."""
    verdict, report = run(mode="B", runs_later_made="vscode skill")
    assert verdict == judge.FAIL, report
    verdict, report = run(mode="A", runs_later_made="vscode skill")
    assert verdict == judge.PASS, report


def test_mode_a_files_that_run_later_are_only_noted():
    results = GOOD
    for name in RUNS_LATER:
        results = _set(results, name, "OK")
    verdict, report = run(results=results, mode="A")
    assert verdict == judge.PASS, report
    assert sum(ln.startswith("note runs-later-") for ln in report) >= len(RUNS_LATER), report


@pytest.mark.parametrize("name", UNIX)
def test_mode_b_a_unix_socket_outside_connected_is_fail(name):
    verdict, report = run(results=_set(LINUX, name, "CONNECTED"), mode="B", platform="linux")
    assert verdict == judge.FAIL, report
    assert any(ln.startswith(f"FAIL {name}:") for ln in report), report
    verdict, report = run(results=_set(LINUX, name, "CONNECTED"), mode="A", platform="linux")
    assert verdict == judge.PASS, report


@pytest.mark.parametrize("name", UNIX)
def test_mode_b_unix_refused_but_the_socket_was_not_there_is_inconclusive(name):
    verdict, _ = run(mode="B", **{name.replace("-", "_"): "no"})
    assert verdict == judge.INCONCLUSIVE


# the made-up servers (netsrv.py) and the probes' client (net.py): real sockets on this
# machine's loopback and in a short temporary folder, made-up data only

NETSRV = JUDGE.parent / "netsrv.py"
NET = JUDGE.parent / "net.py"


def _short_dir():
    """A new private folder with a short path (a unix socket's path is at most 104 bytes)."""
    import tempfile
    return tempfile.mkdtemp(prefix="sbx", dir="/tmp")


@pytest.fixture
def netsrv():
    """netsrv.py started as check.sh starts it -> (state dict, sockdir, project, state path)."""
    import shutil
    import subprocess
    import sys
    import time
    base = _short_dir()
    sock, proj = os.path.join(base, "s"), os.path.join(base, "p")
    os.mkdir(sock, 0o700)
    os.mkdir(proj)
    state = os.path.join(base, "state")
    p = subprocess.Popen([sys.executable, "-I", "-S", str(NETSRV), state, sock, proj,
                          str(os.getpid())],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if os.path.exists(state) and "ready\n" in open(state).read():
                break
            time.sleep(0.1)
        yield _state(state), sock, proj, state
    finally:
        p.kill()
        p.wait(timeout=10)
        shutil.rmtree(base, ignore_errors=True)


def _state(path):
    with open(path) as fh:
        return dict(ln.split(" ", 1) for ln in fh.read().splitlines() if " " in ln)


def _net(*args):
    import subprocess
    import sys
    r = subprocess.run([sys.executable, "-I", "-S", str(NET)] + [str(a) for a in args],
                       capture_output=True, text=True, timeout=60,
                       env={"PATH": "/usr/bin:/bin"})
    return r.stdout.strip(), r


def test_netsrv_answers_on_loopback_and_net_prints_only_the_status(netsrv):
    state, _sock, _proj, _ = netsrv
    port = state["port"]
    for host in ("127.0.0.1", "localhost", "::ffff:127.0.0.1"):
        out, r = _net("tcp", host, port)
        assert out == "RESPONSE 222", (host, out, r.stderr)
        assert "FAKE-PT" not in r.stdout + r.stderr
    if state["v6"] == "yes":
        assert _net("tcp", "::1", port)[0] == "RESPONSE 222"


def test_net_classes_a_closed_port_and_a_missing_socket():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert _net("tcp", "127.0.0.1", port)[0] == "REFUSED refused"
    assert _net("unix", "/nonexistent/sbx.sock")[0] == "REFUSED no-such"
    assert _net("https", f"https://127.0.0.1:{port}/")[0] == "FAILED refused"


def test_netsrv_renames_its_socket_and_binds_the_late_one_on_the_ready_file(netsrv):
    import time
    state, sock, proj, path = netsrv
    renamed = state["renamed"]
    assert renamed == os.path.join(sock, "cm.sock")
    assert sorted(os.listdir(sock)) == ["cm.sock"]  # bound under another name, then renamed
    out, r = _net("unix", renamed)
    assert out == "CONNECTED" and "FAKE-PT" not in r.stdout + r.stderr
    late = os.path.join(sock, "late-B.sock")
    assert not os.path.exists(late)
    open(os.path.join(proj, "unix-ready-B"), "w").close()
    for _ in range(100):
        if "late-B" in _state(path):
            break
        time.sleep(0.1)
    assert _state(path)["late-B"] == late
    assert _net("unix", late)[0] == "CONNECTED"
    assert not os.path.exists(os.path.join(sock, "late-A.sock"))


def test_netsrv_stops_when_its_parent_is_gone():
    """A `kill -9` of check.sh skips the cleanup: the made-up servers end with it."""
    import shutil
    import subprocess
    import sys
    import time
    base = _short_dir()
    try:
        os.mkdir(os.path.join(base, "s"), 0o700)
        os.mkdir(os.path.join(base, "p"))
        # a parent shell that starts it and exits at once
        r = subprocess.run(["sh", "-c", f'"{sys.executable}" -I -S "{NETSRV}" "{base}/state" '
                                        f'"{base}/s" "{base}/p" "$$" >/dev/null 2>&1 & echo $!'],
                           capture_output=True, text=True, timeout=30)
        pid = int(r.stdout.strip())
        for _ in range(100):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            os.kill(pid, 9)
            pytest.fail("netsrv outlived its parent")
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_probes_record_the_new_probes_with_fixed_words_only(tmp_path, netsrv):
    """probes.sh against the made-up servers, with nothing confining it: every server answers
    (as in Mode A with the stand-in), and no byte the servers sent reaches results.txt."""
    import shutil
    import subprocess
    import sys
    state, sock, proj_s, _ = netsrv
    proj = Path(proj_s)
    shutil.copy(PROBES, proj / "probes.sh")
    shutil.copy(NET, proj / "net.py")
    for d in (".claude", ".vscode", "sub/.vscode", "node_modules/pkg/.vscode"):
        (proj / d).mkdir(parents=True)
    (proj / ".Rprofile").write_text("# made up\n")
    (proj / "paths.txt").write_text("".join(f"{k} {v}\n" for k, v in (
        ("mode", "B"), ("python", sys.executable), ("loopback-port", state["port"]),
        ("net-url", "https://127.0.0.1:1/"), ("unix-renamed", state["renamed"]),
        ("unix-late", os.path.join(sock, "late-B.sock")), ("unix-rebound", state["rebound"]))))
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_CONFIG_NOSYSTEM": "1"}
    r = subprocess.run(["sh", "./probes.sh"], cwd=proj, env=env, capture_output=True, text=True,
                       timeout=120)
    assert "probes-done" in r.stdout, r.stderr
    text = (proj / "results.txt").read_text()
    lines = dict(ln.split(" ", 1) for ln in text.splitlines() if " " in ln)
    for name in ("loopback-127", "loopback-localhost", "loopback-mapped"):
        assert lines[name] == "RESPONSE 222", (name, text)
    if state["v6"] == "yes":
        assert lines["loopback-v6"] == "RESPONSE 222", text
    assert lines["net-api"] == "FAILED refused", text
    for name in RUNS_LATER + ["runs-later-node-modules"]:
        assert lines[name] == "OK", (name, text)
    assert (proj / ".claude" / "skills" / "x" / "SKILL.md").exists()
    # a write to .Rprofile leaves a marker, so check.sh can see it on the host
    assert (proj / ".Rprofile").read_text() != "# made up\n"
    assert lines["unix-renamed"] == "CONNECTED", text
    assert lines["unix-late"] == "CONNECTED", text
    assert lines["unix-rebound"] == "CONNECTED", text
    assert "FAKE-PT" not in text


def test_probes_skip_the_network_probes_they_have_no_target_for(tmp_path):
    """No target in paths.txt: no line (the judge then says INCONCLUSIVE), and no wait."""
    lines, _ = _probes(tmp_path, FAKES["refused"])
    for name in LOOPBACK + UNIX + ["net-api"]:
        assert name not in lines, lines


def test_the_cleanup_stops_the_made_up_servers(tmp_path):
    """cleanup.sh stops netsrv (its pid in `netsrv`), also when the check fails."""
    import subprocess
    import time
    h, j = tmp_path / "h", tmp_path / "j"
    h.mkdir()
    j.mkdir()
    driver = tmp_path / "driver.sh"
    driver.write_text('. "$1"\nH=$2; J=$3; lpid=""; broker=""; tty_mode=""\n'
                      'sleep 300 >/dev/null 2>&1 & netsrv=$!\necho "$netsrv"\ntrap cleanup EXIT\nexit 2\n')
    r = subprocess.run(["sh", str(driver), str(CLEANUP), str(h), str(j)], capture_output=True,
                       text=True, timeout=60, env=dict(os.environ, SBX_CLEANUP_WAIT="0"))
    assert r.returncode == 2
    pid = int(r.stdout.split()[0])
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(pid, 9)
        pytest.fail("the made-up servers outlived the cleanup")


# --- review round: the servers checked after the session, a hidden socket, the stub's
# expectations from the kit and the host ---

@pytest.mark.parametrize("name", LOOPBACK + ["unix-renamed", "unix-rebound"])
def test_mode_b_a_server_that_died_during_the_session_is_inconclusive(name):
    """The made-up servers are asked again from outside right after the session: a refusal
    from a server that was gone proves nothing."""
    verdict, report = run(mode="B", **{name.replace("-", "_") + "_after": "no"})
    assert verdict == judge.INCONCLUSIVE, report
    assert any(name in ln and "after the session" in ln for ln in report), report


@pytest.mark.parametrize("name", UNIX)
def test_mode_b_a_hidden_unix_socket_is_inconclusive(name):
    """The socket answered from outside, so "no such" inside is hidden, not refused."""
    verdict, report = run(results=_set(LINUX, name, "REFUSED no-such"), mode="B",
                          platform="linux")
    assert verdict == judge.INCONCLUSIVE, report
    assert any(name in ln and "hidden" in ln for ln in report), report


STUB_EXPECT = JUDGE.parent / "stub-expect.sh"
OK_B = "\n".join(f"ok   {n}: refused (refused)" for n in LOOPBACK + UNIX) + "\nPASS Mode B\n"


def _fail_lines(names):
    return "".join(f"FAIL {n}: RESPONSE 222: the session reached this machine's loopback\n"
                   if n.startswith("loopback") else
                   f"FAIL {n}: CONNECTED: the session reached a unix socket outside\n"
                   for n in names)


def _stub_expect(tmp_path, report, proxy=False, unix=False, abi="6"):
    """stub-expect.sh's check of Mode B's report, for a made-up kit (`proxy`: it has
    netproxy.py; `unix`: its code has Landlock's RESOLVE_UNIX) on a host of Landlock `abi`."""
    import subprocess
    import tempfile
    tmp_path = Path(tempfile.mkdtemp(dir=tmp_path))  # one folder per call
    kit = tmp_path / "kit"
    (kit / "src" / "phiward").mkdir(parents=True)
    (kit / "src" / "phiward" / "wholetool.py").write_text(
        "LANDLOCK_ACCESS_FS_RESOLVE_UNIX = 1 << 16\n" if unix else "X = 1\n")
    if proxy:
        (kit / "src" / "phiward" / "netproxy.py").write_text("X = 1\n")
    rep = tmp_path / "mode-B.txt"
    rep.write_text(report)
    return subprocess.run(["sh", "-c", '. "$1"; sbx_newer_expect "$2" "$3" "$4"', "sh",
                           str(STUB_EXPECT), str(rep), str(kit), abi],
                          capture_output=True, text=True, timeout=60)


def test_stub_a_kit_with_the_proxy_whose_loopback_gets_through_fails(tmp_path):
    """The review's case: netproxy.py in the kit, but the profile lets loopback through."""
    report = OK_B.replace("ok   loopback-127: refused (refused)\n", "") \
        .replace("PASS Mode B", "FAIL Mode B") + _fail_lines(["loopback-127"])
    r = _stub_expect(tmp_path, report, proxy=True)
    assert r.returncode != 0, r.stdout


def test_stub_a_kit_without_the_proxy_labels_loopback(tmp_path):
    report = "\n".join(f"ok   {n}: refused (refused)" for n in UNIX) + "\n" + \
        _fail_lines(LOOPBACK) + "FAIL Mode B\n"
    r = _stub_expect(tmp_path, report, unix=True, abi="9")
    assert r.returncode == 0, r.stdout
    assert r.stdout.count("kit has no proxy") == 4, r.stdout


@pytest.mark.parametrize("unix,abi,expected", [(True, "9", 1), (True, "10", 1), (True, "6", 0),
                                               (False, "9", 0), (True, "n/a", 0)])
def test_stub_unix_sockets_must_be_refused_only_with_resolve_unix_and_abi_9(tmp_path, unix, abi,
                                                                           expected):
    report = "\n".join(f"ok   {n}: refused (refused)" for n in LOOPBACK) + "\n" + \
        _fail_lines(UNIX) + "FAIL Mode B\n"
    r = _stub_expect(tmp_path, report, proxy=True, unix=unix, abi=abi)
    assert (r.returncode != 0) == bool(expected), r.stdout
    if not expected:
        assert r.stdout.count("relies on Claude Code's sandbox (not in the stub)") == 3, r.stdout
        assert "missing guard" not in r.stdout


@pytest.mark.parametrize("extra", ["FAIL runs-later-vscode: OK: a file that runs later was written\n",
                                   "???? net-api: FAILED tunnel: Bash has no network\n",
                                   "FAIL files that run later were on the host right after the "
                                   "session: .Rprofile\n"])
def test_stub_any_other_failure_fails(tmp_path, extra):
    r = _stub_expect(tmp_path, OK_B.replace("PASS Mode B", "FAIL Mode B") + extra, proxy=True,
                     unix=True, abi="9")
    assert r.returncode != 0, r.stdout


def test_stub_every_guard_holding_passes(tmp_path):
    r = _stub_expect(tmp_path, OK_B, proxy=True, unix=True, abi="9")
    assert r.returncode == 0, r.stdout
    r = _stub_expect(tmp_path, OK_B.replace("PASS Mode B", "FAIL Mode B"), proxy=True,
                     unix=True, abi="9")
    assert r.returncode != 0, r.stdout  # the verdict must match the lines


def test_netsrv_binds_its_socket_again_at_the_same_path_on_the_ready_file(netsrv):
    """unix-rebound: bound before the session, removed and bound again at the same path once the
    session runs."""
    import time
    state, sock, proj, path = netsrv
    rebound = state["rebound"]
    assert rebound == os.path.join(sock, "rebound.sock")
    before = os.stat(rebound).st_ino
    assert _net("unix", rebound)[0] == "CONNECTED"
    open(os.path.join(proj, "unix-ready-A"), "w").close()
    for _ in range(100):
        if "rebound-A" in _state(path):
            break
        time.sleep(0.1)
    assert _state(path)["rebound-A"] == rebound
    assert os.stat(rebound).st_ino != before
    assert _net("unix", rebound)[0] == "CONNECTED"
