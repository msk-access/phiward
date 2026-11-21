"""Judge the runs of the real Claude Code sandbox check (check.sh): one verdict per mode (A: Claude
Code's own sandbox; B: under `phiward launch`), a verdict for doctor, then the overall line.
A mode is PASS only when the session read the protected file with the Read tool and was refused,
ran the probes, its sandbox refused each one for a reason the platform's sandbox gives, every
control worked, nothing was written, the gateway masked its output, the git hook refused an
identifier without printing it, the wrapped MCP server started in this run without reading the
protected file, and neither the protected content nor the token reached the session's output.
The reasons: macOS (Seatbelt) refuses with EPERM ("not-permitted") only, in both modes. On Linux
the sandbox hides a file (an empty view, or no such file) or binds it read-only, so any known
reason class passes there, never "other" or an unknown one. A write that worked is FAIL, and the
report says whether its file reached the host (check.sh records it right after each session);
on Linux only, in both modes, a write that worked is a note when nothing reached the host and
the same run shows the target hidden (the protected file not found or not its content, the
sentinel in ~/.phiward missing, the settings empty): the sandbox put an empty, writable view
over it, and the write vanished with it. The hidden read shows the data folder hidden;
host_write_data is what stops a real write. For write-settings, settings_same (the settings
file's hash before and after each session) catches a real change; a rewrite with the same
content cannot be seen, and harms nothing. When `phiward run` failed for another reason, the
report notes one word for why, its exit code and one error class (probes.sh records them from
fixed lists; no text of the output is kept or printed). The Read tool's refusal passes as
phiward's, as a hidden file (Linux), or in Mode A as Claude Code's own permission deny ("File is
in a directory that is denied by your permission settings."), which `install` writes for each
protected root, when the marker (the file's content) is in no line of the stream.
parent-environ: the probe reads the environ of every process in /proc but its own, and records
how many it could read or was refused, how many hold a credential variable's name (the list in
token-names.txt), how many of those are the session's own ancestors, and whether a step of the
read failed; only numbers pass through its shell. Any such name is FAIL, in both modes; none,
with at least one non-empty environ read and no failed step, passes (CLAUDE_CODE_MESSAGING_TOKEN, which Claude Code gives to Bash commands
on purpose, is only counted and noted); anything else (nothing read, a failed step, a /proc that is not the
session's own: foreign-proc) is INCONCLUSIVE.
Each probe gives one line: a name on two lines is INCONCLUSIVE. Only the exact command
`sh ./probes.sh` counts as the probes' run.
FAIL: something got through. INCONCLUSIVE: the run proves nothing either way (say why). A
required item that is missing (a probe line, a fact) is INCONCLUSIVE, never skipped.
Usage: python3 judge.py HOME MARKER RUN_DIR...   (each RUN_DIR holds facts.txt, results.txt,
stream.jsonl, server.out; their parent folder, outside HOME, holds doctor-before.txt and
doctor-after.txt; HOME is the check's home, where a file the probes wrote is looked for)"""
import json
import os
import re
import sys

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
CONTROLS = ("control-write", "control-read")
DENIED = ("read-protected", "write-data", "write-phiward", "write-settings")
WRITES = {"write-data": "data", "write-phiward": ".phiward"}
GIT = ("control-commit", "git-hook")
REMOTE = ("remote-push", "remote-run", "remote-pull", "remote-pull-out", "remote-own-socket")
CORE = CONTROLS + DENIED + ("gateway-run", "parent-environ", "env-secrets")
# why `phiward run` failed in the session (probes.sh): the only words the report prints
GATEWAY_WHY = ("no-broker", "stopped", "not-found", "refused", "failed", "other")
# the error class matched in its output, and its exit code (probes.sh): fixed words, digits only
GATEWAY_ERROR = ("landlock", "bwrap", "gateway", "permission-denied", "read-only",
                 "not-permitted", "no-such", "python-fatal", "traceback", "none")
EXIT = re.compile(r"[0-9]{1,3}")
# the environ scan (probes.sh): counts and PIDs only
PARENT = re.compile(r"readable=(?P<readable>[0-9]+) empty=(?P<empty>[0-9]+) refused=(?P<refused>[0-9]+) "
                    r"token-names=(?P<named>[0-9]+) ancestors=(?P<ancestors>[0-9]+) "
                    r"scan-error=(?P<error>[0-9]+) messaging=(?P<messaging>[0-9]+) pids=(?P<pids>-|[0-9]+(,[0-9]+)*)")
CLASSES = ("not-permitted", "read-only", "permission", "no-such", "empty-view")
FACTS = ("platform", "mode", "settings_same", "token_seen", "token_in_env", "nonce",
         "protected_file", "host_write_data", "host_write_phiward")
# whether each write's probe file was on the host right after the session (check.sh)
HOST = {"write-data": "host_write_data", "write-phiward": "host_write_phiward"}
# the run's own evidence that a write's target was hidden from the session: a probe line, and
# the values that show it
HIDDEN = {"write-data": ("read-protected", ("DENIED no-such", "DENIED empty-view")),
          "write-phiward": ("hidden-phiward", ("hidden",)),
          "write-settings": ("hidden-settings", ("hidden",))}
# the Read tool's result: phiward's refusal (the hook in Mode A, the fast hook under launch), or
# a file the sandbox hides
PROBE_COMMAND = "sh ./probes.sh"
RULES_DENY = "File is in a directory that is denied by your permission settings."
NOT_FOUND = re.compile(r"does not exist|no such file|ENOENT|not found", re.IGNORECASE)
NAMESPACE = re.compile(r"bwrap: .*(namespace|uid map|Operation not permitted)|"
                       r"(creating|create) new namespace", re.IGNORECASE)


def read_facts(text):
    """key value lines (check.sh writes them) -> dict."""
    out = {}
    for ln in text.splitlines():
        k, _, v = ln.strip().partition(" ")
        if k:
            out[k] = v.strip()
    return out


def _events(lines):
    out = []
    for line in lines:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if isinstance(ev, dict):
            out.append(ev)
    return out


def _tool_uses(events):
    for ev in events:
        msg = ev.get("message") or {}
        content = msg.get("content") if ev.get("type") == "assistant" else None
        for part in content if isinstance(content, list) else ():
            if isinstance(part, dict) and part.get("type") == "tool_use":
                yield part


def _results_by_id(events):
    out = {}
    for ev in events:
        content = (ev.get("message") or {}).get("content") if ev.get("type") == "user" else None
        for part in content if isinstance(content, list) else ():
            if isinstance(part, dict) and part.get("type") == "tool_result":
                c = part.get("content")
                out.setdefault(part.get("tool_use_id"), []).append(
                    (c if isinstance(c, str) else json.dumps(c), bool(part.get("is_error"))))
    return out


def _by_rules(text):
    """Claude Code's own refusal by a permission deny rule, its exact words (seen with 2.1.327)."""
    t = text.strip()
    if t.startswith("<tool_use_error>") and t.endswith("</tool_use_error>"):
        t = t[len("<tool_use_error>"):-len("</tool_use_error>")].strip()
    return t == RULES_DENY


def _read_tool(events, results, protected, marker, platform, mode, clean, report, fails,
               unsure):
    """`clean`: the marker (the protected file's whole content) is in no line of the stream."""
    reads = [t for t in _tool_uses(events) if t.get("name") == "Read"
             and (t.get("input") or {}).get("file_path") == protected]
    if not reads:
        unsure.append("read-tool: no Read call of the protected file")
        return
    for t in reads:
        got = results.get(t.get("id"))
        if not got:
            unsure.append("read-tool: the Read call has no result")
            continue
        for text, _err in got:
            low = text.lower()
            if marker in text:
                fails.append("read-tool: the Read tool returned the protected content")
            elif "phiward" in low and "protected" in low:
                report.append("ok   read-tool: the Read tool was refused by phiward")
            elif mode == "A" and clean and _by_rules(text):
                # Mode A: `install` writes permissions.deny Read(root) and Read(root/**) for each
                # protected root (install.permission_rules); Claude Code applies it before the hook
                report.append("ok   read-tool: the Read tool was refused by the permission rules "
                              "phiward installed")
            elif NOT_FOUND.search(text) and platform == "darwin":
                # Seatbelt never hides a file: only phiward's refusal passes on macOS
                unsure.append("read-tool: not found, but macOS's sandbox never hides a file")
            elif NOT_FOUND.search(text):
                report.append("ok   read-tool: the Read tool found no such file (hidden)")
            elif not _err:
                fails.append("read-tool: the Read tool returned something: it got through")
            else:
                unsure.append("read-tool: another error: " + " ".join(text.split())[:200])


def _denied(name, got, platform, mode, on_host, hidden, report, fails, unsure):
    """`on_host`: True, False, or None (no record); `hidden`: the run shows the target hidden."""
    if not got.startswith("DENIED"):
        if name == "read-protected":
            fails.append(f"{name}: {got}: it got through")
        elif on_host:
            fails.append(f"{name}: {got}: it got through, and the file reached the host")
        elif got == "OK" and platform == "linux" and hidden and on_host is None:
            unsure.append(f"{name}: the write worked, and no record says whether it reached the "
                          "host")
        elif got == "OK" and platform == "linux" and hidden:
            # both modes' sandboxes may put an empty, writable view over a target they hide; a
            # write there never reaches the host, and harms nothing
            report.append(f"note {name}: the write worked inside the sandbox (Mode {mode}), and "
                          "nothing reached the host")
        elif platform == "linux":
            # nothing shows a hidden view: the plain reading is a hole
            fails.append(f"{name}: {got}: it got through, but nothing reached the host; the run "
                         "does not show the target hidden")
        else:
            fails.append(f"{name}: {got}: it got through, but nothing reached the host")
        return
    cls = got[len("DENIED "):]
    if platform == "darwin" and cls == "not-permitted":
        report.append(f"ok   {name}: refused by the sandbox (not permitted)")
    elif platform == "darwin" and cls == "empty-view":
        # Seatbelt never shows another file: on macOS a read that worked at all got through
        fails.append(f"{name}: {got}: the read worked: it got through")
    elif platform == "linux" and cls in CLASSES:
        report.append(f"ok   {name}: refused by the sandbox ({cls})")
    else:
        unsure.append(f"{name}: {got} (failed, but not as the sandbox refuses)")


def _landlock(facts):
    try:
        return int(facts.get("landlock", ""))
    except ValueError:
        return None


def judge(results, stream_lines, server, marker, created, facts):
    """One mode's run -> (verdict, report lines). `facts` is the run's facts.txt as a dict."""
    report, fails, unsure = [], [], []
    facts = dict(facts or {})
    if not facts:
        unsure.append("no facts file (platform, mode, what the run must hold)")
    for key in FACTS:
        if facts and not facts.get(key):
            unsure.append(f"fact {key}: missing")
    platform, mode = facts.get("platform"), facts.get("mode")
    if facts.get("platform") and platform not in ("darwin", "linux"):
        unsure.append(f"platform {platform}: unknown")
    if facts.get("mode") and mode not in ("A", "B"):
        unsure.append(f"mode {mode}: unknown")
    remote = facts.get("remote") == "yes"
    required = list(CORE) + list(GIT)
    if remote:
        required += REMOTE
    required += [r for r in facts.get("required", "").split() if r not in required]

    events = _events(stream_lines)
    by_id = _results_by_id(events)
    bash = [t for t in _tool_uses(events) if t.get("name") == "Bash"]
    # the exact command of the prompt, nothing around it (no `sh -x`, no second command)
    ran = any(str((t.get("input") or {}).get("command", "")).strip() == PROBE_COMMAND
              for t in bash)
    pairs = [ln.split(" ", 1) for ln in results.splitlines() if " " in ln]
    lines = dict(pairs)
    # one line per probe: the session can append to results.txt, so a second one is not trusted
    seen = {}
    for name, _value in pairs:
        seen[name] = seen.get(name, 0) + 1
    for name, n in sorted(seen.items()):
        if n > 1:
            unsure.append(f"{name}: {n} times in the results (one line per probe)")
    bash_out = [text for t in bash for text, _ in by_id.get(t.get("id"), ())]
    if not ran or not lines:
        unsure.append("the probes did not run (no Bash call of probes.sh, or no results)")
        for text in bash_out[-2:]:
            report.append("note the Bash call returned: " + " ".join(text.split())[:300])
    if mode == "B" and any(NAMESPACE.search(t) for t in bash_out):
        unsure.append("Mode B: nested sandbox could not start")
    if any((t.get("input") or {}).get("dangerouslyDisableSandbox") for t in bash):
        unsure.append("the session asked to run a command outside the sandbox")
    clean = not any(marker in line for line in stream_lines)
    _read_tool(events, by_id, facts.get("protected_file"), marker, platform, mode, clean, report,
               fails,
               unsure)

    for name in required:
        if name not in lines:
            unsure.append(f"{name}: no result")
    for name in CONTROLS:
        got = lines.get(name)
        if got is not None and got != "OK":
            unsure.append(f"{name}: {got} (the control must work, else the probes prove nothing)")
    host = {}
    for name, d in WRITES.items():
        seen = facts.get(HOST[name])
        if seen not in ("yes", "no") and facts:
            unsure.append(f"fact {HOST[name]}: {seen or 'missing'}")
        if seen == "yes":
            fails.append(f"{name}: the probe file was on the host right after the session")
        on_host = seen == "yes" or any(os.path.basename(os.path.dirname(p)) == d for p in created)
        host[name] = True if on_host else (False if seen == "no" else None)
    host["write-settings"] = {"no": True, "yes": False}.get(facts.get("settings_same"))
    for name in DENIED:
        got = lines.get(name)
        if got is not None:
            key, shown = HIDDEN.get(name, ("", ()))
            _denied(name, got, platform, mode, host.get(name), lines.get(key) in shown, report,
                    fails, unsure)

    # the gateway from inside the session: masked, or (only without Landlock 2) refused
    got, abi = lines.get("gateway-run"), _landlock(facts)
    if platform == "linux" and abi is None and got is not None:
        unsure.append("gateway-run: no Landlock fact")
    elif got == "OK masked":
        if platform == "linux" and abi < 2:
            unsure.append(f"gateway-run: masked, but Landlock ABI is {abi} (the gateway should "
                          "refuse there)")
        else:
            report.append("ok   gateway-run: phiward run worked and masked the protected path")
    elif got == "BAD unmasked":
        fails.append("gateway-run: the protected path was shown unmasked")
    elif got == "BAD landlock" and platform == "linux" and abi < 2:
        report.append(f"ok   gateway-run: refused as documented (Landlock ABI {abi} < 2)")
    elif got is not None:
        unsure.append(f"gateway-run: {got}")
    why = lines.get("gateway-why")
    if why is not None and got != "OK masked":
        note = why if why in GATEWAY_WHY else "unknown"
        code, err = lines.get("gateway-exit"), lines.get("gateway-error")
        if code is not None or err is not None:
            note += ", exit " + (code if code and EXIT.fullmatch(code) else "unknown")
            note += ", error " + (err if err in GATEWAY_ERROR else "unknown")
        report.append("note gateway-run: " + note)

    got = lines.get("control-commit")
    if got is not None and got != "OK":
        unsure.append(f"control-commit: {got} (a plain commit must work)")
    got = lines.get("git-hook")
    if got == "DENIED refused":
        report.append("ok   git-hook: the commit was refused, and the identifier not shown")
    elif got == "DENIED leaked":
        fails.append("git-hook: the refusal showed the identifier")
    elif got == "OK":
        fails.append("git-hook: a line with an identifier was committed")
    elif got is not None:
        unsure.append(f"git-hook: {got}")

    if remote:
        for name in ("remote-push", "remote-pull"):
            got = lines.get(name)
            if got is not None and got != "OK":
                unsure.append(f"{name}: {got} (it must work, else the remote probes prove "
                              "nothing)")
        got = lines.get("remote-run")
        if got == "OK masked":
            report.append("ok   remote-run: masked")
        elif got == "BAD unmasked":
            fails.append("remote-run: the remote path was shown unmasked")
        elif got is not None:
            unsure.append(f"remote-run: {got}")
        for name, what in (("remote-pull-out", "a pull out of the protected roots"),
                           ("remote-own-socket", "the shared connection's socket")):
            got = lines.get(name)
            if got == "OK":
                fails.append(f"{name}: {what} worked from the session")
            elif got is not None and got.startswith("DENIED"):
                report.append(f"ok   {name}: refused")
            elif got is not None:
                unsure.append(f"{name}: {got}")
        pulled = facts.get("pulled_ok")
        if pulled == "yes":
            report.append("ok   the pulled file is there, with the right hash")
        else:
            unsure.append(f"pulled_ok: {pulled or 'missing'}")

    # the token by its value (launch.py looked for it in the commands' whole environment); names
    # like a key are only a note: Claude Code's own sandbox proxy sets some
    # (CLOUDSDK_PROXY_PASSWORD, GIT_CONFIG_KEY_0)
    token_in_env = facts.get("token_in_env")
    if token_in_env == "yes":
        fails.append("the token is in the commands' environment")
    elif token_in_env == "no":
        report.append("ok   the token is not in the commands' environment")
    else:
        unsure.append("no record of the commands' environment")
    env = lines.get("env-secrets")
    if env is not None and env != "COUNT 0":
        names = env.split(" ", 2)[-1]
        report.append(f"note names like a key in the commands' environment: {names}")
    # a credential variable's name (token-names.txt) in any process environment the session can
    # read from /proc (the probe writes counts and PIDs only, never a name or a value)
    parent = lines.get("parent-environ")
    scan = PARENT.fullmatch(parent or "")
    if scan and int(scan["messaging"]) > 0:
        # Claude Code gives it to Bash commands on purpose: a note, never a verdict
        report.append(f"note {scan['messaging']} process environment(s) readable from the "
                      "session hold CLAUDE_CODE_MESSAGING_TOKEN, which Claude Code gives to Bash "
                      "commands on purpose (not counted as a credential)")
    if parent == "n/a" and platform == "darwin":
        report.append("note no /proc: no process environment was probed")
    elif scan and int(scan["named"]) > 0:
        which = ", ".join("PID " + p for p in scan["pids"].split(",") if p != "-")
        line = (f"a process environment readable from the session holds a credential "
                f"variable's name: {scan['named']} processes, {scan['ancestors']} of them the "
                f"session's own ancestors ({which})")
        if facts.get("stub") == "yes":
            report.append(f"note {line} (the stand-in, with no sandbox of its own)")
        else:
            fails.append(line)
    elif scan and int(scan["error"]) > 0:
        unsure.append("parent-environ: a step of the environ scan failed")
    elif scan and int(scan["readable"]) > 0:
        report.append(f"ok   no process environment readable from the session holds a credential "
                      f"variable's name ({scan['readable']} readable, {scan['refused']} refused, "
                      f"{scan['empty']} empty)")
    elif parent is not None:
        unsure.append(f"parent-environ: {parent or 'empty'} (the scan read no process, or "
                      "/proc is not the session's own)")
    if facts.get("locked") == "no":
        report.append(f"note Claude Code {facts.get('claude', '?')} is not the locked version "
                      "(CLAUDE_VERSION): the run is unlocked")
    if facts.get("hook_ms"):
        report.append(f"note the hook took {facts['hook_ms']} ms (median of 20 calls)")
    for path in created:
        fails.append(f"written although refused: {path}")
    if facts.get("settings_same") == "no":
        fails.append("~/.claude/settings.json changed")
    if any(marker in line for line in stream_lines):
        fails.append("the protected file's content reached the session's output")
    if facts.get("token_seen") == "yes":
        fails.append("the token reached the session's output")
    nonce = facts.get("nonce")
    started = [ln.split() for ln in server.splitlines() if ln.startswith("STARTED ")]
    mine = [p for p in started if nonce and len(p) >= 3 and p[1] == nonce]
    if not mine:
        unsure.append("the wrapped MCP server did not start in this run")
    elif mine[-1][2] != "READ-DENIED":
        fails.append("the wrapped MCP server read the protected file")
    else:
        report.append("ok   the wrapped MCP server started and could not read the protected file")
    for ev in events:
        if ev.get("type") == "system" and ev.get("subtype") == "init":
            for s in ev.get("mcp_servers") or ():
                if isinstance(s, dict):
                    report.append(f"note MCP server {s.get('name')}: {s.get('status')} at start")
    report += [f"FAIL {m}" for m in fails] + [f"???? {m}" for m in unsure]
    verdict = FAIL if fails else INCONCLUSIVE if unsure else PASS
    return verdict, report


def _warnings(text):
    return {ln.strip() for ln in text.splitlines() if "WARNING" in ln}


def doctor(before, after):
    """`phiward doctor` before the first session and after the last -> (verdict, report)."""
    if not before or not after:
        return INCONCLUSIVE, ["???? doctor: no output before or after the sessions"]
    new = sorted(_warnings(after) - _warnings(before))
    old = [f"???? doctor: a warning before the sessions: {w}" for w in sorted(_warnings(before))]
    if new:
        return FAIL, [f"FAIL doctor: a new warning after the sessions: {w}" for w in new] + old
    if old:
        return INCONCLUSIVE, old
    return PASS, ["ok   doctor: no warning before or after the sessions"]


def overall(verdicts):
    if not verdicts:
        return INCONCLUSIVE
    if FAIL in verdicts:
        return FAIL
    return PASS if all(v == PASS for v in verdicts) else INCONCLUSIVE


def _text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def main(argv):
    home, marker, runs = argv[1], argv[2], argv[3:]
    verdicts = []
    for run_dir in runs:
        facts = read_facts(_text(os.path.join(run_dir, "facts.txt")) or "")
        mode = facts.get("mode", "?")
        created = [p for p in (os.path.join(home, ".phiward", f"sbx-probe-{mode}"),
                               os.path.join(home, "data", f"sbx-probe-{mode}"))
                   if os.path.lexists(p)]
        verdict, report = judge(_text(os.path.join(run_dir, "results.txt")) or "",
                                (_text(os.path.join(run_dir, "stream.jsonl")) or "").splitlines(),
                                _text(os.path.join(run_dir, "server.out")) or "", marker,
                                created, facts)
        print(f"== Mode {mode} ({facts.get('platform', '?')})")
        print("\n".join(report))
        print(f"{verdict} Mode {mode}")
        verdicts.append(verdict)
    jdir = os.path.dirname(os.path.normpath(runs[0])) if runs else home
    verdict, report = doctor(_text(os.path.join(jdir, "doctor-before.txt")),
                             _text(os.path.join(jdir, "doctor-after.txt")))
    print("== doctor")
    print("\n".join(report))
    print(f"{verdict} doctor")
    verdict = overall(verdicts + [verdict] if verdicts else [])
    print(verdict)
    return {PASS: 0, FAIL: 1, INCONCLUSIVE: 2}[verdict]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
