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
GOOD = """control-write OK
control-read OK
read-protected DENIED not-permitted
write-data DENIED not-permitted
write-phiward DENIED not-permitted
write-settings DENIED not-permitted
env-secrets COUNT 0
"""


def stream(*extra, servers=(("docs", "connected"),), command="sh ./probes.sh", sandbox_off=False):
    tool_input = {"command": command}
    if sandbox_off:
        tool_input["dangerouslyDisableSandbox"] = True
    events = [
        {"type": "system", "subtype": "init", "mcp_servers": [
            {"name": n, "status": s} for n, s in servers]},
        {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "Bash", "input": tool_input}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "done"}]}},
    ] + list(extra)
    return [json.dumps(e) for e in events]


def run(results=GOOD, lines=None, server=f"STARTED {NONCE} READ-DENIED\n", marker="FAKE-MARK-1",
        created=(), settings_same=True, token_seen=False, token_in_env="no"):
    return judge.judge(results=results, stream_lines=stream() if lines is None else lines,
                       server=server, nonce=NONCE, marker=marker, created=list(created),
                       settings_same=settings_same, token_seen=token_seen,
                       token_in_env=token_in_env)


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
