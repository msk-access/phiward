"""A tiny stdio MCP server for tests (standard library only): one tool, `read_file(path)`,
that returns the file's text. Wrapped in `phiward launch --`, it must work for ordinary files
and fail for protected ones."""

import json
import sys


def reply(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        reply(mid, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "reader", "version": "0"}})
    elif method == "tools/list":
        reply(mid, {"tools": [{"name": "read_file", "description": "read a file",
                               "inputSchema": {"type": "object",
                                               "properties": {"path": {"type": "string"}},
                                               "required": ["path"]}}]})
    elif method == "tools/call":
        path = msg["params"]["arguments"]["path"]
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read(4096)
            reply(mid, {"content": [{"type": "text", "text": text}]})
        except OSError as exc:
            reply(mid, {"content": [{"type": "text", "text": f"error: {exc.strerror}"}],
                        "isError": True})
    elif mid is not None:
        reply(mid, error={"code": -32601, "message": "unknown method"})
