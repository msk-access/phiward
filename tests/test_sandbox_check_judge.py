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
         "remote": "no", "stub": "no", "protected_file": PROT}
    f.update(over)
    return f


def run(results=GOOD, lines=None, server=f"STARTED {NONCE} READ-DENIED\n", marker="FAKE-MARK-1",
        created=(), settings_same=True, token_seen=False, token_in_env="no", platform="darwin",
        mode="A", data_names=("FAKE-PT-0001", "a.txt"), **over):
    f = facts(platform, mode, settings_same="yes" if settings_same else "no",
              token_seen="yes" if token_seen else "no", token_in_env=token_in_env, **over)
    return judge.judge(results=results, stream_lines=stream() if lines is None else lines,
                       server=server, marker=marker, created=list(created), facts=f,
                       data_names=data_names)


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

LINUX = GOOD.replace("DENIED not-permitted", "DENIED read-only").replace(
    "read-protected DENIED read-only", "read-protected DENIED empty-view").replace(
    "parent-environ n/a", "parent-environ unreadable")


def test_linux_full_run_is_pass():
    for mode in ("A", "B"):
        verdict, report = run(results=LINUX, platform="linux", mode=mode)
        assert verdict == judge.PASS, report


def test_read_only_passes_on_linux_but_not_on_macos():
    results = GOOD.replace("write-data DENIED not-permitted", "write-data DENIED read-only")
    linux = results.replace("parent-environ n/a", "parent-environ unreadable")
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


def test_gateway_other_error_prints_what_phiward_run_said():
    """A rerun must show why `phiward run` failed in the session: probes.sh keeps the first lines
    of its output; the judge prints them as a note (and the report then goes through launch.py's
    redaction of the token, as every kept file)."""
    results = gw("BAD other") + "gateway-err phiward: cannot start the broker | try   again\n"
    verdict, report = run(results=results, platform="linux")
    assert verdict == judge.INCONCLUSIVE
    assert "note gateway-run said: phiward: cannot start the broker | try again" in report, report
    long = "x" * 1000
    verdict, report = run(results=gw("BAD other") + f"gateway-err {long}\n", platform="linux")
    said = [ln for ln in report if ln.startswith("note gateway-run said:")]
    assert said and len(said[0]) <= 330, said


@pytest.mark.parametrize("text", [
    "wc: FAKE-PT-0001/a.txt: x",           # another spelling of the protected path
    "1 ~/data/FAKE-PT-0001/a.txt",         # the home as ~
    "cannot open a.txt",                   # the protected file's name
    "FAKE-PT-0001: no such folder",        # an entry under the data folder
    "the data folder is busy",             # the data folder's name
    "see ~/ for more",
    "it said FAKE-MARK-1",                 # the protected content
])
def test_gateway_error_text_that_names_protected_data_is_withheld(text):
    verdict, report = run(results=gw("BAD other") + f"gateway-err {text}\n", platform="linux")
    said = [ln for ln in report if ln.startswith("note gateway-run said:")]
    assert said == ["note gateway-run said: (withheld: it may name protected data)"], report
    assert not any(text in ln for ln in report), report


def test_gateway_error_text_is_withheld_when_the_data_names_are_unknown():
    """Fail closed: without the list of names under the data folder nothing is printed."""
    results = gw("BAD other") + "gateway-err phiward: cannot start the broker\n"
    verdict, report = run(results=results, platform="linux", data_names=None)
    assert "note gateway-run said: (withheld: it may name protected data)" in report, report


def test_gateway_error_text_is_not_printed_when_the_gateway_masked():
    results = LINUX + "gateway-err something\n"
    verdict, report = run(results=results, platform="linux")
    assert verdict == judge.PASS and not any("said" in ln for ln in report), report


PROBES = JUDGE.parent / "probes.sh"
FAKE_PHIWARD = """#!/bin/sh
echo "phiward: the broker is not running" >&2
printf 'phiward: start it\tfirst\n' >&2
echo "a third line, not kept" >&2
exit 1
"""


def test_probes_keep_the_first_lines_of_phiward_runs_error_and_look_for_the_targets(tmp_path):
    """probes.sh, with a made-up phiward that fails: results.txt holds gateway-run BAD other and
    gateway-err with the first two lines of its output, on one line, no control character (the
    judge decides whether to print it). With nothing hiding them, the sentinel in ~/.phiward and
    the settings are seen: present. Made-up folders only; a git repository of its own in
    tmp_path, no hook."""
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
    (fbin / "phiward").write_text(FAKE_PHIWARD)
    (fbin / "phiward").chmod(0o755)
    (proj / "paths.txt").write_text("".join(f"{k} {v}\n" for k, v in (
        ("mode", "A"), ("free", free), ("free-marker", "FREE-MARK-1"), ("protected-file", prot),
        ("protected-hash", "0"), ("data", data), ("phiward", tmp_path / ".phiward"),
        ("settings", tmp_path / "settings.json"), ("fake-id", "P-9990001-T01-IM6"),
        ("claude-exe", "/nonexistent/claude"), ("claude-link", "/nonexistent/claude"),
        ("nonce", "n0"), ("remote", "no"))))
    env = {"PATH": f"{fbin}:/usr/bin:/bin", "HOME": str(tmp_path),
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "init", "-q"], cwd=proj, env=env, check=True)
    r = subprocess.run(["sh", "./probes.sh"], cwd=proj, env=env, capture_output=True, text=True,
                       timeout=60)
    assert "probes-done" in r.stdout, r.stderr
    lines = dict(ln.split(" ", 1) for ln in (proj / "results.txt").read_text().splitlines()
                 if " " in ln)
    assert lines["gateway-run"] == "BAD other"
    assert lines["gateway-err"] == ("phiward: the broker is not running | phiward: start it "
                                    "first"), lines
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
        "env-secrets"]


@pytest.mark.parametrize("probe", CORE)
def test_each_required_probe_missing_is_inconclusive(probe):
    results = "".join(ln + "\n" for ln in GOOD.splitlines() if not ln.startswith(probe + " "))
    verdict, report = run(results=results)
    assert verdict == judge.INCONCLUSIVE and any(probe in ln for ln in report), report


@pytest.mark.parametrize("key", ["settings_same", "token_seen", "token_in_env", "nonce",
                                 "platform", "mode", "protected_file", "host_write_data",
                                 "host_write_phiward"])
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


# the token in the parent's environment: the documented limit, a note only

def test_claude_environ_readable_is_a_note_and_still_pass():
    results = LINUX.replace("parent-environ unreadable", "parent-environ readable")
    verdict, report = run(results=results, platform="linux")
    assert verdict == judge.PASS, report
    assert any(ln.startswith("note") and "/proc" in ln and "documented limit" in ln
               for ln in report)


def test_claude_environ_unreadable_passes():
    verdict, report = run(results=LINUX, platform="linux")
    assert verdict == judge.PASS, report


@pytest.mark.parametrize("value", ["not-found", "n/a", "made-up"])
def test_claude_environ_not_found_in_a_real_linux_run_is_inconclusive(value):
    """Fail closed: the probe did not find the claude process (another install, a hidden PID)."""
    results = LINUX.replace("parent-environ unreadable", f"parent-environ {value}")
    assert run(results=results, platform="linux")[0] == judge.INCONCLUSIVE
    verdict, report = run(results=results, platform="linux", stub="yes")
    assert verdict == judge.PASS, report


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
