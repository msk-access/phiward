"""An MCP server wrapped in `phiward launch --` (Mode A). Claude Code starts it with
pipes; it must answer the protocol, read project files, and be refused protected data and the
hidden list. Two may run at once."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import CONFINE_WHY

SRC = str(Path(__file__).resolve().parents[1] / "src")
SERVER = str(Path(__file__).resolve().parent / "probes" / "mcp_reader.py")
pytestmark = pytest.mark.skipif(CONFINE_WHY is not None, reason=f"no confinement: {CONFINE_WHY}")


def start(tree):
    env = dict(os.environ, PYTHONPATH=SRC, PHIWARD_DEV="1")
    return subprocess.Popen([sys.executable, "-m", "phiward", "launch", "--", sys.executable,
                             "-I", SERVER], cwd=str(tree / "repo"), env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)


def call(p, mid, method, params=None):
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": mid, "method": method,
                              "params": params or {}}) + "\n")
    p.stdin.flush()
    return json.loads(p.stdout.readline())


def read(p, mid, path):
    r = call(p, mid, "tools/call", {"name": "read_file", "arguments": {"path": str(path)}})
    return r["result"]["content"][0]["text"]


def test_a_wrapped_mcp_server_works_and_cannot_read_protected_data(tree):
    if sys.platform.startswith("linux") and str(tree).startswith("/tmp/"):
        pytest.skip("Linux: the tree is under the session's own /tmp; run with --basetemp")
    key = tree / "home" / ".ssh" / "id_fake"
    key.parent.mkdir()
    key.write_text("FAKE-KEY\n")
    servers = [start(tree), start(tree)]
    try:
        for i, p in enumerate(servers):
            assert "result" in call(p, 1, "initialize"), p.stderr.read()
            assert read(p, 2, tree / "repo" / "README.md").strip() == "readme"
            assert "SECRET" not in read(p, 3, tree / "phi" / "FAKE-PT-0001.bam")
            assert "FAKE-KEY" not in read(p, 4, key)
    finally:
        for p in servers:
            try:
                p.stdin.close()
            except BrokenPipeError:
                pass
            code = p.wait(timeout=60)
            assert code == 0, (code, p.stderr.read())
