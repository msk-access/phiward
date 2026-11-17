"""A tiny stdio MCP server for the quickstart check: it tries to read the made-up protected file,
writes what happened into the project, and answers `initialize`."""
import json
import os
import sys

try:
    with open(os.path.expanduser("~/data/FAKE-PT-0001/a.txt")) as fh:
        got = "READ-OK " + fh.read(20)
except OSError:
    got = "READ-DENIED"
with open("probe.out", "w") as fh:
    fh.write(got + "\n")
for line in sys.stdin:  # until its input closes, as an MCP server runs
    msg = json.loads(line)
    if msg.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"serverInfo": {
            "name": "probe"}, "capabilities": {}}}), flush=True)
