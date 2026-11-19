"""The judge of scripts/sandbox-check: it says PASS only when the real Claude Code ran the probes
and its sandbox refused each one for the right reason, with every control working. Made-up runs
only; the real check is run by a maintainer (docs/releasing.md)."""

import importlib.util
import json
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
         "parent_environ": "n/a" if platform == "darwin" else "no", "nonce": NONCE,
         "remote": "no", "stub": "no", "protected_file": PROT}
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

LINUX = GOOD.replace("DENIED not-permitted", "DENIED read-only").replace(
    "read-protected DENIED read-only", "read-protected DENIED empty-view").replace(
    "parent-environ n/a", "parent-environ saved")


def test_linux_full_run_is_pass():
    for mode in ("A", "B"):
        verdict, report = run(results=LINUX, platform="linux", mode=mode)
        assert verdict == judge.PASS, report


def test_read_only_passes_on_linux_but_not_on_macos():
    results = GOOD.replace("write-data DENIED not-permitted", "write-data DENIED read-only")
    assert run(results=results, platform="linux")[0] == judge.PASS
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


def test_a_read_not_found_passes():
    lines = stream(read=read_call("File does not exist."))
    assert run(lines=lines)[0] == judge.PASS


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

@pytest.mark.parametrize("probe", ["write-data", "write-phiward", "write-settings"])
def test_mode_b_linux_write_ok_with_no_host_file_is_a_note(probe):
    results = LINUX.replace(f"{probe} DENIED read-only", f"{probe} OK")
    verdict, report = run(results=results, platform="linux", mode="B")
    assert verdict == judge.PASS, report
    assert any(ln.startswith("note") and probe in ln for ln in report)


def test_mode_b_write_ok_with_a_host_file_is_fail():
    results = LINUX.replace("write-data DENIED read-only", "write-data OK")
    assert run(results=results, platform="linux", mode="B",
               created=["/h/data/sbx-probe-B"])[0] == judge.FAIL
    assert run(results=LINUX.replace("write-settings DENIED read-only", "write-settings OK"),
               platform="linux", mode="B", settings_same=False)[0] == judge.FAIL


def test_mode_a_write_ok_is_fail_even_with_no_host_file():
    results = LINUX.replace("write-data DENIED read-only", "write-data OK")
    assert run(results=results, platform="linux", mode="A")[0] == judge.FAIL


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
                                 "platform", "mode", "protected_file"])
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


def test_a_stub_run_may_skip_the_git_probes():
    results = GOOD.replace("control-commit OK\n", "").replace("git-hook DENIED refused\n", "")
    assert run(results=results, stub="yes", git="no")[0] == judge.PASS
    assert run(results=results, stub="no", git="no")[0] == judge.INCONCLUSIVE


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

def test_parent_environ_yes_is_a_note_and_still_pass():
    verdict, report = run(results=LINUX, platform="linux", parent_environ="yes")
    assert verdict == judge.PASS, report
    assert any(ln.startswith("note") and "parent" in ln for ln in report)


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


def test_redact_replaces_the_token_and_says_it_was_there(tmp_path):
    spec = importlib.util.spec_from_file_location("sbx_launch", LAUNCH)
    launch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launch)  # no side effects on import
    f = tmp_path / "stream.jsonl"
    token = "FAKE-TOKEN-0123456789abcdef"
    f.write_text(f'{{"x": "{token}"}}\nand {token} again\n')
    assert launch.redact(str(f), token) is True
    text = f.read_text()
    assert token not in text and text.count("<TOKEN>") == 2
    assert launch.redact(str(f), token) is False
