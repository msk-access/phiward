"""`phiward mcp`: phiward's gateway as an MCP server (stdio), for Claude Code and other tools.

Tools:
- `phiward_run(command, write_to?, net?)`: `phiward run -- COMMAND...`, masked output;
- `phiward_copy(sources, destination, dry_run?)`: `phiward copy`;
- `phiward_remote(host, command)`: `phiward run --remote HOST -- COMMAND...`;
- `phiward_check(command)`: what the guard decides for a shell command;
- `phiward_doctor()`: the setup check.

It is a client of the broker, like the `phiward` command: it writes a request into the spool,
and the broker checks it against the user config, runs it outside the agent, and masks what
comes back. Nothing here reads protected data. Arguments are lists, so there is no shell and no
quoting. The working folder of a request is the server's (the project Claude Code started it in).
"""
# The code uses the standard library only.

import io
import json
import sys
from typing import Any, Dict, List, Optional

PROTOCOL = "2025-06-18"

_STR_LIST = {"type": "array", "items": {"type": "string"}}
TOOLS: List[Dict[str, Any]] = [
    {"name": "phiward_run",
     "description": ("Run a command on protected data through phiward's gateway. The output is "
                     "masked (paths, names and identifiers become placeholders). Print counts "
                     "and summaries, never records. `command` is the program and its arguments "
                     "as a list (no shell)."),
     "inputSchema": {"type": "object", "required": ["command"],
                     "properties": {"command": _STR_LIST,
                                    "write_to": _STR_LIST,
                                    "net": {"type": "boolean"}}}},
    {"name": "phiward_copy",
     "description": ("Copy files without printing names: to a protected folder, or to or from an "
                     "approved HPC remote (host:/path)."),
     "inputSchema": {"type": "object", "required": ["sources", "destination"],
                     "properties": {"sources": _STR_LIST, "destination": {"type": "string"},
                                    "dry_run": {"type": "boolean"}}}},
    {"name": "phiward_remote",
     "description": ("Run an approved program on an approved HPC host through the operator's "
                     "shared SSH connection; the output is masked."),
     "inputSchema": {"type": "object", "required": ["host", "command"],
                     "properties": {"host": {"type": "string"}, "command": _STR_LIST}}},
    {"name": "phiward_check",
     "description": "Say whether phiward's guard allows a shell command (allow, ask or deny).",
     "inputSchema": {"type": "object", "required": ["command"],
                     "properties": {"command": {"type": "string"}}}},
    {"name": "phiward_doctor",
     "description": "Check phiward's setup for this project: the mode, each layer, warnings.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def _strs(v: Any) -> Optional[List[str]]:
    return v if isinstance(v, list) and all(isinstance(x, str) for x in v) else None


def _capture(fn) -> "tuple":
    buf = io.StringIO()
    try:
        code = fn(buf)
    except SystemExit as exc:  # a command's main may exit
        code = exc.code if isinstance(exc.code, int) else 1
    except Exception as exc:  # noqa: BLE001 - a tool error, never a traceback (it can name paths)
        buf.write(f"phiward failed ({type(exc).__name__})\n")
        code = 3
    return code or 0, buf.getvalue()


def call(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    from phiward import broker
    code, text = 2, ""
    if name == "phiward_run":
        cmd = _strs(args.get("command"))
        if not cmd:
            text = "phiward_run: `command` must be a non-empty list of strings\n"
        else:
            argv: List[str] = []
            for w in _strs(args.get("write_to")) or []:
                argv += ["--write-to", w]
            if args.get("net") is True:
                argv.append("--net")
            code, text = _capture(lambda out: broker.client("run", argv + ["--"] + cmd, out))
    elif name == "phiward_copy":
        srcs, dst = _strs(args.get("sources")), args.get("destination")
        if not srcs or not isinstance(dst, str):
            text = "phiward_copy: give `sources` (a list) and `destination`\n"
        else:
            argv = (["--dry-run"] if args.get("dry_run") is True else []) + srcs + [dst]
            code, text = _capture(lambda out: broker.client("copy", argv, out))
    elif name == "phiward_remote":
        host, cmd = args.get("host"), _strs(args.get("command"))
        if not isinstance(host, str) or not cmd:
            text = "phiward_remote: give `host` and `command` (a list)\n"
        else:
            code, text = _capture(
                lambda out: broker.client("run", ["--remote", host, "--"] + cmd, out))
    elif name == "phiward_check":
        command = args.get("command")
        if not isinstance(command, str):
            text = "phiward_check: give `command` (a string)\n"
        else:
            from phiward.adapters import run_check

            def check(out):
                old = sys.stdout
                sys.stdout = out
                try:
                    return run_check(["--", command])
                finally:
                    sys.stdout = old
            code, text = _capture(check)
    elif name == "phiward_doctor":
        from phiward import doctor

        def doc(out):
            old = sys.stdout
            sys.stdout = out
            try:
                return doctor.main([])
            finally:
                sys.stdout = old
        code, text = _capture(doc)
    else:
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True}
    return {"content": [{"type": "text", "text": text or f"(exit {code})"}], "isError": code != 0}


def _reply(mid: Any, result: Any = None, error: Optional[Dict[str, Any]] = None) -> None:
    msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": mid}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main(argv: List[str]) -> int:
    if argv[:1] in (["wrap"], ["unwrap"], ["list"]):
        # the operator's command; with no arguments this is the MCP server (Claude Code starts it)
        from phiward import mcp_config
        return mcp_config.main(argv)
    if argv[:1] in (["-h"], ["--help"]):
        sys.stdout.write("usage: phiward mcp   (an MCP server on stdin and stdout)\n"
                         "       phiward mcp list|wrap|unwrap ...   your own MCP servers: see "
                         "`phiward mcp list --help`\n\n" + (__doc__ or ""))
        return 0
    if not argv and sys.stdin.isatty():
        # typed in a terminal: this is the server Claude Code starts, not a command for you
        sys.stderr.write("phiward mcp is phiward's own MCP server, which Claude Code starts. To see "
                         "and wrap your MCP servers: `phiward mcp list`.\n")
        return 2
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if not isinstance(msg, dict):
            continue
        method, mid = msg.get("method"), msg.get("id")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if method == "initialize":
            _reply(mid, {"protocolVersion": params.get("protocolVersion", PROTOCOL),
                         "capabilities": {"tools": {}},
                         "serverInfo": {"name": "phiward", "version": _version()}})
        elif method == "tools/list":
            _reply(mid, {"tools": TOOLS})
        elif method == "tools/call":
            args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            _reply(mid, call(str(params.get("name", "")), args))
        elif method == "ping":
            _reply(mid, {})
        elif mid is not None:
            _reply(mid, error={"code": -32601, "message": f"unknown method: {method}"})
    return 0


def _version() -> str:
    try:
        from phiward import __version__
        return __version__
    except ImportError:
        return "0"
