"""The replay of a typical session for the leak test (tests/test_leak_typical.py).

The session is tests/data/leak_session.jsonl, in Claude Code's stream-json shape (an `init`
line, `user` prompts, `assistant` tool uses), so a recorded session over the same made-up project
can be replayed too. In it `{REPO}`, `{DATA}` and `{PY}` stand for the project, the protected root
and this Python; «VALUE» marks a planted value (in a prompt tagged `paste` only: an agent knows
only what it was shown, so no tool input holds one).

Each step goes through phiward's own entry point, the way Claude Code would call it, and what
would reach the model is captured as an `Item`: the session note, a prompt (or the reason it was
not sent), a file tool's result (or the hook's reason), a shell command's output, an MCP tool's
answer. `launched` plays the steps inside `phiward launch` (Mode B) with the standard library only.
"""

import io
import json
import os
import re
import subprocess
import sys
import unicodedata
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, NamedTuple, Tuple

TESTS = Path(__file__).resolve().parent
SRC = str(TESTS.parent / "src")
SESSION = TESTS / "data" / "leak_session.jsonl"
MCP_READER = str(TESTS / "probes" / "mcp_reader.py")
# a phiward command run from the source checkout, as the `phiward` on PATH
LAUNCH = ("import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]; "
          f"sys.path.insert(0, {SRC!r}); from phiward.cli import main; sys.exit(main())")
PLANT = re.compile("«([^»]*)»")


class Step(NamedTuple):
    n: int
    kind: str  # start, prompt, tool
    name: str  # the tool's name; "" for the others
    input: Any  # the tool's input, or the prompt
    tag: str  # "paste" for a prompt that holds a planted value on purpose
    id: str = ""  # a tool use's id


class Item(NamedTuple):
    step: int
    channel: str  # note, prompt, file, shell, gateway, table, mcp, doctor, kernel
    text: str  # what would reach the model
    verdict: str  # allow, deny, block, sent
    sees: Tuple[str, ...]  # the places the step reads: root, project, prompt
    src: str = ""  # a prompt's own text


def _fill(x: Any, subs: Dict[str, str], value: Callable[[str], str]) -> Any:
    if isinstance(x, str):
        for k, v in subs.items():
            x = x.replace("{" + k + "}", v)
        return PLANT.sub(lambda m: value(m.group(1)), x)
    if isinstance(x, list):
        return [_fill(v, subs, value) for v in x]
    if isinstance(x, dict):
        return {k: _fill(v, subs, value) for k, v in x.items()}
    return x


def load(subs: Dict[str, str], value: Callable[[str], str] = lambda v: v,
         path: Path = SESSION) -> List[Step]:
    """The session's steps, with `subs` filled in and each «VALUE» replaced by `value(VALUE)`.
    A tool input that holds a «VALUE» is refused (the input rule)."""
    steps: List[Step] = []
    for n, line in enumerate(path.read_text().splitlines()):
        if not line.strip():
            continue
        msg = json.loads(line)
        if msg["type"] == "system":
            steps.append(Step(n, "start", "", None, ""))
        elif msg["type"] == "user":
            steps.append(Step(n, "prompt", "", _fill(msg["message"]["content"], subs, value),
                              msg.get("phiward_tag", "")))
        elif msg["type"] == "assistant":
            for part in msg["message"]["content"]:
                if part.get("type") != "tool_use":
                    continue
                if PLANT.search(json.dumps(part["input"], ensure_ascii=False)):
                    raise ValueError(f"line {n + 1}: a tool input holds a planted value")
                steps.append(Step(n, "tool", part["name"], _fill(part["input"], subs, value), "",
                                  part.get("id", "")))
    return steps


def sees(step: Step, data: str) -> Tuple[str, ...]:
    """The places a step reads: the root when it names it (also as `~/data`), else the project;
    a prompt reads its own text."""
    text = json.dumps(step.input, ensure_ascii=False)
    root = data in text or "~/data" in text
    if step.kind == "prompt":
        return ("prompt",) + (("root",) if root else ())
    return ("root",) if root else ("project",)


def shell_channel(command: str) -> str:
    from phiward import gateway
    words = gateway.whole_command(command)
    if words and words[0] == "run":
        head = words[1:words.index("--")] if "--" in words else words[1:]
        return "table" if "--table" in head else "gateway"
    return "shell"


# ---- Mode A: phiward's entry points, as Claude Code calls them --------------------------------

def _hook(tool: str, inp: Any, repo: str) -> Tuple[int, str]:
    from phiward.adapters import claude
    payload = {"hook_event_name": "PreToolUse", "cwd": repo, "permission_mode": "default",
               "tool_name": tool, "tool_input": inp, "session_id": "leak-test"}
    out, err = io.StringIO(), io.StringIO()
    return claude.main(io.StringIO(json.dumps(payload)), out, err), err.getvalue()


def _grep(inp: Dict[str, Any]) -> str:
    rx = re.compile(inp["pattern"])
    lines = []
    for folder, dirs, files in os.walk(inp["path"]):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for f in sorted(files):
            p = os.path.join(folder, f)
            try:
                text = open(p, encoding="utf-8").read()
            except (OSError, UnicodeDecodeError):
                continue
            lines += [f"{p}:{i}:{ln}" for i, ln in enumerate(text.splitlines(), 1)
                      if rx.search(ln)]
    return "\n".join(lines)


class _Mcp:
    """`phiward mcp` over stdio, started the first time a step calls it."""

    def __init__(self, repo: str, env: Dict[str, str]):
        self.p = subprocess.Popen([sys.executable, "-c", LAUNCH, "mcp"], cwd=repo, env=env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.n = 0
        self.call("initialize", {"protocolVersion": "2025-06-18"})

    def call(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method,
                                       "params": params}) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def close(self) -> None:
        self.p.stdin.close()
        self.p.wait(timeout=60)


def replay(steps: List[Step], repo: str, data: str, env: Dict[str, str]) -> List[Item]:
    """Play `steps` in Mode A. The in-process entry points (the hook, the prompt scan, the
    session note) read os.environ, which the caller sets to `env`; commands get `env`."""
    from phiward import promptscan, session_note
    items: List[Item] = []
    mcp = None
    try:
        for s in steps:
            where = sees(s, data)
            if s.kind == "start":
                out = io.StringIO()
                old = sys.stdin
                sys.stdin = io.StringIO(json.dumps({"hook_event_name": "SessionStart",
                                                    "cwd": repo}))
                try:
                    with redirect_stdout(out):
                        session_note.main(["claude"])
                finally:
                    sys.stdin = old
                items.append(Item(s.n, "note", out.getvalue(), "sent", ()))
            elif s.kind == "prompt":
                v = promptscan._claude_verdict(json.dumps({
                    "hook_event_name": "UserPromptSubmit", "prompt": s.input, "cwd": repo}))
                items.append(Item(s.n, "prompt", v.why if v.blocked else s.input,
                                  "block" if v.blocked else "sent", where, s.input))
            else:
                code, why = _hook(s.name, s.input, repo)
                if code == 2:
                    items.append(Item(s.n, _tool_channel(s), why, "deny", where))
                    continue
                if s.name == "Read":
                    text = open(s.input["file_path"], encoding="utf-8").read()
                elif s.name == "Grep":
                    text = _grep(s.input)
                elif s.name == "Bash":
                    r = subprocess.run(["sh", "-c", s.input["command"]], cwd=repo, env=env,
                                       capture_output=True, text=True, timeout=180,
                                       stdin=subprocess.DEVNULL)
                    text = r.stdout + r.stderr
                else:
                    mcp = mcp or _Mcp(repo, env)
                    res = mcp.call("tools/call", {"name": s.name.split("__")[-1],
                                                  "arguments": s.input})
                    text = "\n".join(c.get("text", "") for c in res["result"]["content"])
                items.append(Item(s.n, _tool_channel(s), text, "allow", where))
    finally:
        if mcp:
            mcp.close()
    return items


def _tool_channel(s: Step) -> str:
    if s.name == "Bash":
        return shell_channel(s.input["command"])
    if s.name == "mcp__phiward__phiward_doctor":
        return "doctor"
    if s.name.startswith("mcp__"):
        return "mcp"
    return "file"


# ---- Mode B: inside `phiward launch` (standard library only) ----------------------------------

def launched(steps: List[List[Any]], extra: List[List[str]]) -> None:
    """Play the prompts, the shell commands and the Reads inside a launched session, then the
    launch leg's own reads of the root (`extra`: [kind, path]); print the capture as JSON.
    `steps` are [n, kind, name, input]."""
    s = json.load(open(os.path.join(os.environ["CLAUDE_CONFIG_DIR"], "settings.json")))
    scan = [[h["command"]] + h["args"] for g in s["hooks"]["UserPromptSubmit"]
            for h in g["hooks"] if h.get("args", [])[-2:] == ["prompt-scan", "claude"]][0]
    out: List[List[Any]] = []
    for n, kind, name, inp in steps:
        if kind == "prompt":
            p = {"hook_event_name": "UserPromptSubmit", "prompt": inp, "cwd": os.getcwd()}
            r = subprocess.run(scan, input=json.dumps(p), capture_output=True, text=True)
            out.append([n, "prompt", json.loads(r.stdout)["reason"] if r.returncode == 2
                        else inp, "block" if r.returncode == 2 else "sent"])
        elif name == "Bash":
            r = subprocess.run(["sh", "-c", inp["command"]], capture_output=True, text=True,
                               timeout=180, stdin=subprocess.DEVNULL)
            out.append([n, "", r.stdout + r.stderr, "allow"])
        elif name == "Read":
            out.append([n, "file", _read(inp["file_path"]), "allow"])
    for i, (kind, path) in enumerate(extra):
        n = 1000 + i
        if kind == "shell":
            r = subprocess.run(["sh", "-c", path], capture_output=True, text=True, timeout=60,
                               stdin=subprocess.DEVNULL)
            text = r.stdout + r.stderr
        elif kind == "listdir":
            try:
                text = "\n".join(os.listdir(path))
            except OSError as exc:
                text = f"error: {exc.strerror}"
        elif kind == "open":
            text = _read(path)
        else:
            text = _wrapped_read(path)
        out.append([n, "kernel", text, "allow"])
    print("CAPTURE " + json.dumps(out))


def _read(path: str) -> str:
    try:
        return open(path, encoding="utf-8").read()
    except OSError as exc:
        return f"error: {exc.strerror}"


def _wrapped_read(path: str) -> str:
    """`read_file` of tests/probes/mcp_reader.py, wrapped in `phiward launch --` as an MCP
    server of the session."""
    p = subprocess.Popen([sys.executable, "-c", LAUNCH, "launch", "--", sys.executable, "-I",
                          MCP_READER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        for i, (method, params) in enumerate((
                ("initialize", {}),
                ("tools/call", {"name": "read_file", "arguments": {"path": path}}))):
            p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method,
                                      "params": params}) + "\n")
            p.stdin.flush()
            line = p.stdout.readline()
            if not line:
                return "error: the wrapped server did not answer"
        return "\n".join(c.get("text", "") for c in json.loads(line)["result"]["content"])
    finally:
        p.stdin.close()
        p.wait(timeout=60)


# ---- what leaked ------------------------------------------------------------------------------

ABSENT, PRESENT = "absent", "present"
_ALNUM = re.compile(r"[^0-9a-z]")


def outcome(plant: Any, place: str, channel: str, features: FrozenSet[str]):
    """The expected outcome of `plant` at `place` in `channel` (the table of PLAN-PHI-TESTS
    step 2), or None when the config does not check it."""
    kind = plant.kind_in(features)
    if kind is None:
        return None
    if place == "root":
        if channel == "table" and kind == "position" and plant.column == "other" \
                and "table" in features:
            return PRESENT  # a number in a column that is not an identifier column
        return ABSENT  # refused (hook, kernel) or masked (gateway, MCP), or blocked (prompt)
    if place == "prompt":
        return ABSENT if kind == "identifier" else PRESENT  # entries, details, positions: sent
    return PRESENT  # the project: sent (the hook decides by path; a stated gap until step 3)


def _forms(value: str, text: str) -> List[str]:
    """The forms of `value` found in `text`: raw, casefolded, NFKC, unescaped, letters and digits
    only (5 or more characters with a letter), and each run of 3 or more letters and digits that
    holds a digit (H3: `P-<NUM>-T01-IM6` leaves `T01`)."""
    from phiward import sanitize
    found = []
    nfkc = lambda t: unicodedata.normalize("NFKC", t)  # noqa: E731
    if value in text:
        found.append("raw")
    if value.casefold() in text.casefold():
        found.append("casefolded")
    if nfkc(value) in nfkc(text):
        found.append("NFKC")
    if value in sanitize.unescape(text):
        found.append("unescaped")
    if len(value) >= 5 and any(c.isalpha() for c in value):
        if _ALNUM.sub("", nfkc(value).casefold()) in _ALNUM.sub("", nfkc(text).casefold()):
            found.append("letters and digits")
    for run in re.findall(r"[A-Za-z0-9]{3,}", value):
        if any(c.isdigit() for c in run) and re.search(
                rf"(?<![A-Za-z0-9]){re.escape(run)}(?![A-Za-z0-9])", text, re.I):
            found.append(f"part {run}")
    return found


def findings(items: Iterable[Item], plants: List[Any], features: FrozenSet[str]
             ) -> Tuple[List[str], List[str]]:
    """(leaks, missing): a planted value found where it must be absent, in any form; and a value
    that must be sent or allowed but never reached the capture (the replay saw nothing)."""
    leaks: List[str] = []
    want: Dict[Tuple[str, str], bool] = {}
    for it in items:
        allowed, absent = [], []
        for p in plants:
            places = [w for w in it.sees if w != "prompt" or p.value in it.src]
            got = [outcome(p, w, it.channel, features) for w in places if w in p.places]
            if PRESENT in got:
                allowed.append(p)
                for w in places:
                    if w in p.places and outcome(p, w, it.channel, features) == PRESENT:
                        want[(p.value, w)] = want.get((p.value, w), False) or p.value in it.text
            elif p.kind_in(features) is not None:
                absent.append(p)
        text = it.text
        for p in sorted(allowed, key=lambda q: len(q.value), reverse=True):
            text = text.replace(p.value, " ")  # what may be shown is taken out first
        for p in absent:
            forms = _forms(p.value, text)
            if forms:
                leaks.append(f"step {it.step}, {it.channel}: {p.kind_in(features)} "
                             f"{p.value!r} found ({', '.join(forms)})")
    missing = [f"{v!r} at {w}: expected to be sent, never reached the capture"
               for (v, w), seen in want.items() if not seen]
    return leaks, missing
