"""The Claude Code adapter (PreToolUse). It also reads the payloads of Copilot, which runs the
hooks in a repository's `.claude/settings.json` with its own tool names and camelCase fields.

Reply: allow is silence (exit 0, no output: "staying silent doesn't approve" the call); deny is
exit 2 with the reason on stderr, which wins over any JSON; ask is the tool's JSON ask reply.
Any fault in here denies (exit 2): a bug must not let an action through.
"""

import json
import re
import os
from typing import Any, Dict, Iterable, List, Optional, TextIO, Tuple

from phiward import pathid
from phiward.core import (ASK, DENY, DOCTOR_STEP, FILE_READ, FILE_SEARCH, FILE_WRITE, OTHER,
                           REWIRE_STEP, SHELL, Action)

# phiward's own MCP tools, as a user server (`phiward`) or from the plugin
PHIWARD_MCP = re.compile(r"mcp__(?:plugin_phiward_)?phiward__phiward_(?:run|copy|remote|check|doctor)")
# Monitor runs shell commands too (Claude Code's sandbox covers it like Bash)
SHELL_TOOLS = {"Bash", "bash", "Monitor"}
# tools with a shell in their name that run no command: they read or stop one already started
NOT_SHELLS = {"bashoutput", "killshell", "killbash", "read_bash", "stop_bash", "list_bash"}
# a tool outside Claude Code's sandbox that runs commands, by the words of its name (its last
# part, split on `_`, `-` and camelCase): a shell word, or an action with what it acts on
SHELL_WORDS = {"bash", "shell", "pwsh", "powershell", "terminal", "exec", "execute", "eval",
               "sh", "zsh", "repl", "osascript", "applescript", "subprocess"}
EXEC_WORDS = {"exec", "execute", "eval"}
RUN_VERBS = {"run", "start", "spawn", "launch", "create", "invoke"}
RUN_OBJECTS = {"command", "commands", "cmd", "script", "scripts", "process", "program", "code",
               "python", "node"}
IO_VERBS = {"interact", "send", "write"}  # input to a running process or terminal
IO_OBJECTS = {"process", "keys", "stdin", "terminal"}
# a first word that only reads or stops (`read_terminal`, `search_shell_history`), unless an
# action follows (`list_and_execute`)
READ_VERBS = {"read", "list", "get", "show", "kill", "stop", "close", "clear", "tail", "search"}
# JavaScript in a browser page runs there, not in this machine's shell: only by the names the
# operator's tools carry (the tool's or its server's), never by the agent's input
JS_WORDS = {"javascript", "js"}
PAGE_WORDS = {"browser", "page", "tab", "chrome", "playwright", "puppeteer", "firefox"}
LOCAL_RUNNERS = {"bash", "shell", "terminal", "command", "commands", "cmd", "script", "process",
                 "python", "node", "repl", "subprocess", "osascript", "applescript"}
# the fields a tool that only names a terminal may take and still run nothing
TERMINAL_FIELDS = {"cwd", "title", "name", "profile"}
# the one form such a tool may take for a gateway call: one command field, or one argv list,
# and nothing that changes what runs; other fields only from this list, each of its type
COMMAND_FIELDS = ("command", "cmd", "script", "input")
HARMLESS_FIELDS = {"description": str, "explanation": str, "title": str,
                   "timeout": (int, float), "timeout_ms": (int, float),
                   "isBackground": bool, "is_background": bool}


def _name_words(tool: str) -> List[str]:
    part = tool.rsplit("__", 1)[-1] if tool.startswith("mcp__") else tool
    part = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", part)
    return [w.casefold() for w in re.split(r"[_\-\s.]+", part) if w]


APP_FLAGS = {"_consent"}  # the app's own yes-or-no fields that run nothing


def _app_flag(key: Any, value: Any) -> bool:
    """A field the app adds for itself (`_consent`), holding only a yes or no. Any other field,
    `_`-prefixed or not, may change what runs."""
    return key in APP_FLAGS and isinstance(value, bool)


def says_shell(tool: str, inp: Optional[Dict[str, Any]] = None) -> bool:
    """Whether a tool's name says it runs commands on this machine (Copilot's `run_in_terminal`
    and `write_bash`, an MCP server's `run_command`, `execute_command`, `executeCode`,
    `start_process`, `run_python`, `send_keys`). `inp`: the tool's input, which decides for a
    name that only names a terminal (`open_terminal_tab` runs a command only when given one)."""
    inp = inp or {}
    if tool.lower() in NOT_SHELLS:
        return False
    words = _name_words(tool)
    if not words:
        return False
    ws, rest = set(words), set(words[1:])
    acts = RUN_VERBS | IO_VERBS | EXEC_WORDS
    if words[0] in READ_VERBS and not rest & acts:
        return False
    server = set(_name_words(tool.split("__")[1])) if tool.startswith("mcp__") and \
        tool.count("__") >= 2 else set()
    if ws & JS_WORDS and (ws | server) & PAGE_WORDS and not ws & LOCAL_RUNNERS:
        return False
    shell = ws & SHELL_WORDS
    if shell:
        given = {k for k in inp if not _app_flag(k, inp[k])}
        if shell <= {"terminal"} and not ws & acts and given <= TERMINAL_FIELDS:
            return False  # names a terminal and is given nothing to run (`open_terminal_tab`)
        return True
    return bool(ws & RUN_VERBS and ws & RUN_OBJECTS) or bool(ws & IO_VERBS and ws & IO_OBJECTS)


def exact_command(inp: Dict[str, Any], cwd: str) -> Tuple[str, str]:
    """(the command, "") when a shell tool's input has the one exact form; else ("", why)."""
    import shlex
    found: List[str] = []
    for k, v in inp.items():
        if k in COMMAND_FIELDS:
            if not isinstance(v, str):
                return "", f"its `{k}` is not one string"
            found.append(v)
        elif k == "argv":
            if not (isinstance(v, list) and v and all(isinstance(a, str) for a in v)):
                return "", "its `argv` is not one list of strings"
            found.append(shlex.join(v))
        elif k == "cwd":
            if not (isinstance(v, str) and os.path.normpath(v) == os.path.normpath(cwd)):
                return "", "it names another folder to run in (`cwd`)"
        elif _app_flag(k, v):
            continue  # the app's own flag (`_consent`): a yes or no, it runs nothing
        elif k not in HARMLESS_FIELDS:
            return "", f"it has a field that can change what runs (`{k}`)"
        elif isinstance(v, bool) and HARMLESS_FIELDS[k] is not bool or \
                not isinstance(v, HARMLESS_FIELDS[k]):
            return "", f"its `{k}` is not of the expected type"
    if len(found) != 1:
        return "", "it does not hold exactly one command"
    body = found[0][:-1] if found[0].endswith("\n") else found[0]
    items = inp["argv"] if isinstance(inp.get("argv"), list) else [body]
    if any(re.search(r"[\x00-\x1f\x7f\x85\u2028\u2029]", x) for x in items):
        # a server may run each line on its own, or join argv into a shell line
        return "", "its command holds a line break or another control character"
    return found[0], ""


READ_TOOLS = {"Read", "NotebookRead", "view"}
SEARCH_TOOLS = {"Grep", "Glob", "LS", "grep", "glob"}
WRITE_TOOLS = {"Edit", "MultiEdit", "Write", "NotebookEdit", "create", "edit"}
# the modes in which Claude Code is known to show the person an "ask" (its docs): in any other
# (auto, a missing or a future mode) an ask is refused, so it never passes unseen
ASK_MODES = {"default", "acceptEdits", "plan"}
# Claude Code's built-in tools that run nothing and read no file: their input is text for the
# model, the person or a subagent (a subagent's own tool calls reach the hook), so a path in it
# is not checked. Closed, exact names; a Claude Code payload only.
TEXT_ONLY_TOOLS = {"Agent", "Task", "TodoWrite", "TaskCreate", "TaskUpdate", "TaskList",
                   "TaskGet", "AskUserQuestion", "EnterPlanMode", "ExitPlanMode",
                   "SubagentHandback", "SendMessage", "ToolSearch"}


# the app's own tools that start the project's code outside Claude Code's sandbox (checked in the
# desktop app: the preview ran `launch.json`'s command unsandboxed), by exact name, and for the
# simulator's `control` by its action. What each one starts goes into the prompt. Decided name by
# name from the app's tool list; a tool that only steers a page or a session is not here
APP_STARTERS = {
    "mcp__Claude_Browser__preview_start": "the command that .claude/launch.json names",
    "mcp__Claude_Code_iOS_Simulator__build": "the project's build, with its build scripts",
    "mcp__ccd_directory__change_directory": "a session in another folder, which phiward's "
                                            "settings checks do not see",
    "mcp__ccd_directory__request_directory": "a session in another folder, which phiward's "
                                             "settings checks do not see",
}
APP_STARTER_ACTIONS = {("mcp__Claude_Code_iOS_Simulator__control", "launch"):
                       "an app built from the project"}
# tools that name files or folders by these keys: the app's browsers (a `file:` URL) and tools
# that are not MCP tools (Copilot's `list_dir`, `str_replace_editor`). Judged as a search: a
# folder above protected data is refused, as for Grep
APP_FILE_SERVERS = {"Claude_Browser", "claude-in-chrome", "Control_Chrome"}
PATH_KEYS = ("path", "filePath", "file_path", "dir", "directory", "uri", "url")
PATH_LIST_KEYS = ("paths", "filePaths", "files")
# Copilot's workspace searches, which take no folder: they search the working folder
WORKSPACE_SEARCHES = {"grep_search", "file_search", "semantic_search"}


def _named_paths(inp: Dict[str, Any], urls_only: bool = False) -> List[str]:
    """The paths a tool's input names by PATH_KEYS and PATH_LIST_KEYS: plain paths, and the path
    of a `file:` URL (also behind `view-source:`), percent-decoded, spelled as a browser reads
    it (tabs and line breaks dropped, control characters and spaces at the ends stripped, `\\`
    as `/`). A web URL names no path; `urls_only` (a browser): only `file:` URLs count."""
    from urllib.parse import unquote, urlparse
    vals: List[str] = []
    if urls_only:
        # a browser: every URL field at any depth (a batch's actions[].input.url)
        vals = list(_url_fields(inp))
    for k in PATH_KEYS:
        if isinstance(inp.get(k), str):
            vals.append(inp[k])
    for k in PATH_LIST_KEYS:
        if isinstance(inp.get(k), list):
            vals += [v for v in inp[k] if isinstance(v, str)]
    out: List[str] = []
    for v in vals:
        # a URL as a browser reads it: tabs and line breaks dropped, control characters and
        # spaces at the ends stripped, `\\` as `/`. A plain path is taken as it is
        url = re.sub(r"[\t\r\n]", "", v).strip("".join(chr(c) for c in range(0x21)))
        low = url.lower()
        while low.startswith("view-source:"):
            url = url[len("view-source:"):].strip("".join(chr(c) for c in range(0x21)))
            low = url.lower()
        if low.startswith("file:"):
            path = unquote(urlparse(url.replace("\\", "/")).path) or "/"
            out.append(path if path.startswith("/") else "/" + path)  # always absolute
            continue
        if urls_only or re.match(WEB_SCHEMES, v.strip().lower()):
            continue  # https:, about:, data: name no file here; a browser's plain value either
        if v:
            out.append(v)
    return out


# URL schemes that name no file on this machine; anything else with a colon (`k:v`) is a name
WEB_SCHEMES = r"^(https?|ftps?|wss?|data|about|mailto|chrome|edge|blob|javascript):"
URL_KEYS = ("url", "uri", "href", "src", "target", "path", "filePath", "file_path")


def _url_fields(value: Any) -> Iterable[str]:
    """The values of URL_KEYS at any depth of a tool's input (not every string: a search
    pattern or a page's text is no address)."""
    if isinstance(value, dict):
        for k, v in value.items():
            if k in URL_KEYS and isinstance(v, str):
                yield v
            else:
                yield from _url_fields(v)
    elif isinstance(value, list):
        for v in value:
            yield from _url_fields(v)


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def to_action(payload: Dict[str, Any]) -> Tuple[Action, bool]:
    """The Action, and whether the payload is Copilot's camelCase form."""
    camel = "toolName" in payload and "tool_name" not in payload
    tool = payload.get("tool_name") or payload.get("toolName") or ""
    inp = payload.get("tool_input")
    if inp is None:
        inp = payload.get("toolArgs", {})
        if isinstance(inp, str):
            inp = json.loads(inp) if inp.strip() else {}
    if not isinstance(inp, dict):
        raise ValueError("tool input is not an object")
    cwd = payload.get("cwd") or os.getcwd()
    # Copilot's payload has no mode and shows its ask; Claude Code's, only in ASK_MODES
    can_ask = camel or payload.get("permission_mode") in ASK_MODES
    text = tuple(_strings(inp))
    if not camel and tool in TEXT_ONLY_TOOLS:
        return Action(OTHER, cwd, text=(), tool=tool, can_ask=can_ask), camel
    if tool in SHELL_TOOLS:
        return Action(SHELL, cwd, command=str(inp.get("command", "")), tool=tool,
                      can_ask=can_ask), camel
    # every path field a file tool's input holds (a payload with two is judged by both)
    named = tuple(dict.fromkeys(str(inp[k]) for k in ("file_path", "notebook_path", "path")
                                if isinstance(inp.get(k), str) and inp.get(k)))
    if tool in READ_TOOLS:
        return Action(FILE_READ, cwd, paths=named, text=text, tool=tool,
                      can_ask=can_ask), camel
    if tool in SEARCH_TOOLS:
        base = inp.get("path") or cwd
        # what the search reads: Grep, the folder it walks; Glob, only what its pattern lists
        # below the folder (a Glob limited to `src/**` never lists the rest of the folder)
        ps: List[str] = [base]
        if tool in ("Glob", "glob") and inp.get("pattern"):
            ps = [os.path.join(base, inp["pattern"])]
        return Action(FILE_SEARCH, cwd, paths=tuple(ps), text=text, tool=tool,
                      can_ask=can_ask), camel
    if tool in WRITE_TOOLS:
        return Action(FILE_WRITE, cwd, paths=named, text=text, tool=tool,
                      can_ask=can_ask, claude_code=not camel), camel
    # the paths a tool names by its path fields: one more check of the action, never another
    # kind of action (a shell or a writer keeps its own rules)
    searches: Tuple[str, ...] = ()
    app_server = (tool or "").split("__")[1] if (tool or "").count("__") >= 2 else ""
    if not (tool or "").startswith("mcp__") or app_server in APP_FILE_SERVERS:
        named_any = _named_paths(inp, urls_only=app_server in APP_FILE_SERVERS)
        if not named_any and tool in WORKSPACE_SEARCHES:
            named_any = [cwd]  # a search with no folder searches the working folder
        searches = tuple(named_any)
    starts = APP_STARTERS.get(tool or "") or APP_STARTER_ACTIONS.get(
        (tool or "", inp.get("action") if isinstance(inp.get("action"), str) else ""), "")
    if starts:
        return Action(OTHER, cwd, text=text, tool=tool, can_ask=can_ask, starts=starts,
                      searches=searches), camel
    if PHIWARD_MCP.fullmatch(tool or ""):
        # phiward's own gateway tools: they name protected paths by design, as a
        # `phiward run` command does; the broker checks them. An MCP server that only pretends
        # to be phiward is code with the operator's rights already (Mode A) or confined (Mode B)
        return Action(OTHER, cwd, text=(), tool=tool, can_ask=can_ask), camel
    # a tool of an MCP server wrapped in `phiward launch --` runs in the kernel profile: only the
    # text check. A shell-named tool of any other server (or Copilot's terminal tools) runs
    # commands with the operator's rights: one exact gateway call at most
    from phiward import mcp_config
    home = pathid.home()
    project = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
    # which server: by the source Claude Code names (2.1.274 and newer), else by name in the
    # operator's own config only
    sourced = "mcp_server" in payload and (tool or "").startswith("mcp__")
    if sourced:
        configured: Optional[mcp_config.Server] = mcp_config.classify(
            payload.get("mcp_server"), tool or "", project, home)
    else:
        configured = mcp_config.server_of(tool or "", project, home, trust_project=False)
    # wrapped only when it really runs wrapped: a live launcher of its command, a child of this
    # Claude Code (a server wrapped in the config after it started still runs bare)
    server = mcp_config.trusted(configured, project, home)
    if (server is None or not server.wrapped) and says_shell(tool or "", inp):
        cmd, why = exact_command(inp, cwd)
        return Action(SHELL, cwd, command=cmd, text=text, tool=tool, can_ask=can_ask,
                      shape=why, advice=_advice(tool or "", configured, sourced,
                                                 _states(configured, project, home)),
                      searches=searches), camel
    # anything else (MCP tools, web tools): its text is checked
    return Action(OTHER, cwd, text=text, tool=tool, can_ask=can_ask,
                  remote=bool(server is not None and server.remote), searches=searches), camel


def _states(configured: Any, project: str, home: str) -> Tuple[set, List[str]]:
    """The states of a server's entries (`mcp_config.entry_state`), and what changes what runs in
    a `changed` one: from the entries Claude Code named, else the operator's own scopes."""
    from phiward import mcp_config
    if configured is None:
        return set(), []
    specs: List[Any] = []
    for text in configured.specs:
        try:
            specs.append(json.loads(text))
        except ValueError:
            pass
    if not configured.specs:
        specs = [e.spec for e in mcp_config.entries(project, home)
                 if e.name == configured.name and e.scope in ("user", "local")]
    states = {mcp_config.placed_state(x, project, home) for x in specs}
    keys: List[str] = []
    for x in specs:
        if mcp_config.entry_state(x) == "changed":
            keys += [k for k in mcp_config._changed_by(x) if k not in keys]
    return states, keys


def _advice(tool: str, configured: Any, sourced: bool,
            states: Tuple[set, List[str]] = (set(), [])) -> str:
    """What the operator can do about a refused shell-named tool, by where its server is from and
    what its entries are (`_states`): the same answer as `phiward mcp list` gives."""
    from phiward import mcp_config
    found, keys = states
    if not tool.startswith("mcp__"):
        return "Work on protected data through the gateway."
    old = ("" if sourced else
           " (This Claude Code does not say which server a tool belongs to, so a server of "
           f"`.mcp.json` counts as bare: update Claude Code to "
           f"{'.'.join(map(str, mcp_config.MIN_SOURCE_VERSION))} or newer.)")
    if configured is None:
        return ("phiward cannot see this server's command (a plugin's, a managed or a connector "
                "server), so it cannot be wrapped: use a gateway call in Bash (`phiward run -- "
                "CMD`) instead." + old)
    name = mcp_config.shown(configured.name)
    src = configured.source
    if getattr(configured, "untrusted", False) and not sourced:
        return (f"`{name}` is defined in the project's `.mcp.json`, which counts as bare when "
                "Claude Code does not say which server a tool belongs to: its command tools may "
                "make only gateway calls: use one in Bash (`phiward run -- CMD`)." + old)
    if getattr(configured, "here", False):
        return (f"`{name}` listens on this machine (its URL): it runs outside Claude Code, so "
                "phiward cannot wrap it. Its command tools may make only gateway calls: use one "
                "in Bash (`phiward run -- CMD`)." + old)
    if getattr(configured, "unwrappable", False):
        return (f"`{name}` has no command phiward can read, so it cannot be wrapped. Its command "
                "tools may make only gateway calls: use one in Bash (`phiward run -- CMD`)." + old)
    if "changed" in found:
        return (f"`{name}` runs under `phiward launch`, but its entry sets {', '.join(keys)}, "
                "which changes what runs, so it counts as not wrapped: the operator can remove "
                "that from its entry, then start Claude Code again." + old)
    stuck = mcp_config.cannot_wrap_why(found) if found else ""
    if stuck:
        # as `phiward mcp list` says it: no entry of the name that `wrap` can change
        return (f"`{name}` {stuck}, so it cannot be wrapped. Its command tools may make only "
                "gateway calls: use one in Bash (`phiward run -- CMD`)." + old)
    if "copied" in found:
        return (f"`{name}` has an entry id that another entry has too (a copy), so phiward cannot "
                f"tell their launchers apart: the operator gives it its own (`phiward mcp wrap "
                f"{name}`), then starts Claude Code again." + old)
    if configured.wrapped:
        return ("Its server is wrapped in the config, but it still runs as it was started, or "
                "its profile was built from other settings (its entry's `env`, or the phiward "
                "config or your credentials changed since it started): the operator starts "
                "Claude Code again." + old)
    if sourced and src == "plugin" and configured.specs:
        return (f"`{name}` is a plugin's server, which phiward does not wrap (an update replaces "
                "the plugin's files): use a gateway call in Bash (`phiward run -- CMD`) instead.")
    if (sourced and src in mcp_config.CONFIG_SOURCES and configured.specs) or not sourced:
        return (f"The operator can wrap its server (`phiward mcp wrap {name}`), then start Claude "
                "Code again." + old)
    return (f"phiward cannot see this server's command (`{name}`, source `{mcp_config.shown(src)}`"
            "), so it cannot be wrapped: use a gateway call in Bash (`phiward run -- CMD`) "
            "instead.")


def main(fin: TextIO, fout: TextIO, ferr: TextIO) -> int:
    try:
        from phiward.adapters import decide
        payload = json.load(fin)
        if not isinstance(payload, dict):
            raise ValueError("payload is not an object")
        if payload.get("hook_event_name", "PreToolUse") != "PreToolUse":
            # a tool hook wired to another event: refuse, never judge it as a tool call
            ferr.write("phiward: `hook claude` is a PreToolUse hook; this event is refused: "
                       f"{REWIRE_STEP}.\n")
            return 2
        action, camel = to_action(payload)
        # Only Claude Code's own payload (it carries permission_mode) can be confined by Claude
        # Code's sandbox; Copilot runs the same hooks without it.
        # A call that asks to run outside the sandbox is judged as unconfined, whatever the
        # settings say.
        ti = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
        leaves = ti.get("dangerouslyDisableSandbox") not in (None, False)
        claude_code = not camel and "permission_mode" in payload
        d = decide(action, claude_sandbox=claude_code and not leaves)
    except Exception as exc:  # noqa: BLE001 - fail closed
        ferr.write(f"phiward: the hook could not decide ({type(exc).__name__}), so the "
                   f"action is refused; {DOCTOR_STEP}.\n")
        return 2
    if d.verdict == DENY:
        ferr.write(f"phiward [{d.guard}]: {d.reason}\n")
        return 2
    if d.verdict == ASK:
        if camel:
            reply = {"permissionDecision": "ask", "permissionDecisionReason": d.reason}
        else:
            reply = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                            "permissionDecision": "ask",
                                            "permissionDecisionReason": d.reason}}
        fout.write(json.dumps(reply) + "\n")
    return 0
