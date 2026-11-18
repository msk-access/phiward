"""A tiny stdio MCP server for the sandbox check: it tries to read the made-up protected file
named in srv-target.txt (next to this file, so the server's entry names no protected path),
writes "STARTED NONCE READ-DENIED|READ-OK" to OUT, and answers initialize, tools/list and ping.
Usage (as the wrapped entry runs it): python3 srv.py OUT NONCE"""
import json
import os
import sys

out, nonce = sys.argv[1:3]
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "srv-target.txt")) as fh:
    protected = fh.read().strip()
try:
    with open(protected) as fh:
        fh.read(1)
    got = "READ-OK"
except OSError:
    got = "READ-DENIED"
with open(out, "a") as fh:
    fh.write(f"STARTED {nonce} {got}\n")
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if "id" not in msg:  # a notification
        continue
    method = msg.get("method")
    if method == "initialize":
        version = (msg.get("params") or {}).get("protocolVersion") or "2025-06-18"
        result = {"protocolVersion": version, "capabilities": {"tools": {}},
                  "serverInfo": {"name": "sbx-probe", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": []}
    elif method == "ping":
        result = {}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                          "error": {"code": -32601, "message": "unknown method"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
