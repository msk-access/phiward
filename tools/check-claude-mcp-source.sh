#!/usr/bin/env bash
# What Claude Code tells a PreToolUse hook about an MCP server, and how it starts the server.
# The operator runs this in their own terminal (it runs `claude -p` once, with their login):
#
#     bash tools/check-claude-mcp-source.sh
#
# It makes a temporary project with a tiny stdio MCP server (`probe`, in `.mcp.json`), the same
# server in a throwaway plugin loaded for this one session (`--plugin-dir`: nothing is
# installed), and a logging PreToolUse hook (given with --settings: no settings file of yours is
# changed), asks Claude Code to call both servers' one tool, and prints:
#   - the Claude Code version;
#   - the `mcp_server` object the hook received (phiward trusts by its `source`, Claude Code
#     2.1.274 or newer);
#   - the parent chain of the hook and of the server: phiward's launcher record needs the server's
#     parent to be the Claude Code process, which is also an ancestor of the hook;
#   - whether each server got CLAUDE_PLUGIN_ROOT in its environment: phiward tells a plugin's
#     launcher from a configured one's by it (the plugin's should, the configured one should not).
# Nothing else is printed (no prompts, no file contents). The folder is removed at the end
# (KEEP=1 keeps it).
set -euo pipefail

command -v claude >/dev/null || { echo "claude is not on PATH"; exit 2; }
PY=$(command -v python3) || { echo "python3 is not on PATH"; exit 2; }
T=$(mktemp -d "${TMPDIR:-/tmp}/phiward-mcp-check.XXXXXX")
T=$(cd "$T" && pwd -P)
trap '[ "${KEEP:-}" = 1 ] && echo "kept: $T" || rm -rf "$T"' EXIT
mkdir -p "$T/proj"

cat > "$T/chain.py" <<'EOF'
import os, subprocess, sys
def chain(pid, n=6):
    out = []
    for _ in range(n):
        try:
            line = subprocess.run(["ps", "-o", "ppid=,comm=", "-p", str(pid)], capture_output=True,
                                  text=True).stdout.strip()
        except OSError:
            break
        if not line:
            break
        ppid, comm = line.split(None, 1)
        out.append({"pid": pid, "comm": os.path.basename(comm)})
        pid = int(ppid)
        if pid <= 1:
            out.append({"pid": pid, "comm": "init"})
            break
    return out
EOF

cat > "$T/server.py" <<'EOF'
import json, os, sys
sys.path.insert(0, os.environ.get("PROBE_LIB") or sys.argv[2])
from chain import chain
root = os.environ.get("CLAUDE_PLUGIN_ROOT")
data = os.environ.get("CLAUDE_PLUGIN_DATA")
home = os.path.expanduser("~")
with open(sys.argv[1], "w") as fh:
    json.dump({"chain": chain(os.getpid()), "plugin_root_set": root is not None,
               "plugin_data": None if data is None else ("~" + data[len(home):]
                                                         if data.startswith(home) else data),
               "plugin_root_exact": None if root is None else root == os.path.dirname(
                   os.path.abspath(__file__)),
               "plugin_root_is_its_folder": bool(root) and os.path.realpath(root) ==
               os.path.dirname(os.path.realpath(__file__))}, fh)
def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    try:
        req = json.loads(line)
    except ValueError:
        continue
    m, i = req.get("method"), req.get("id")
    if i is None:
        continue
    if m == "initialize":
        send({"jsonrpc": "2.0", "id": i, "result": {
            "protocolVersion": req.get("params", {}).get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}}, "serverInfo": {"name": "probe", "version": "1"}}})
    elif m == "tools/list":
        send({"jsonrpc": "2.0", "id": i, "result": {"tools": [{
            "name": "ping_probe", "description": "Returns pong.",
            "inputSchema": {"type": "object", "properties": {}}}]}})
    elif m == "tools/call":
        send({"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": "pong"}]}})
    else:
        send({"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "no such method"}})
EOF

cat > "$T/hook.py" <<'EOF'
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chain import chain
p = json.load(sys.stdin)
tool = str(p.get("tool_name", ""))
kind = "hook.log" if tool.startswith("mcp__probe__") else (
    "hook-plugin.log" if tool.startswith("mcp__plugin_phiwardprobe_probe__") else None)
if kind:
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), kind), "w") as fh:
        json.dump({"tool_name": p.get("tool_name"), "mcp_server": p.get("mcp_server", "(absent)"),
                   "chain": chain(os.getpid())}, fh)
EOF

printf '{"mcpServers": {"probe": {"command": "%s", "args": ["%s", "%s", "%s"]}}}\n' \
  "$PY" "$T/server.py" "$T/server.log" "$T" > "$T/proj/.mcp.json"
mkdir -p "$T/plug/.claude-plugin"
cp "$T/server.py" "$T/plug/server.py"
printf '{"name": "phiwardprobe", "version": "0.0.1", "description": "phiward check probe"}\n' \
  > "$T/plug/.claude-plugin/plugin.json"
printf '{"mcpServers": {"probe": {"command": "%s", "args": ["${CLAUDE_PLUGIN_ROOT}/server.py", "%s", "%s"]}}}\n' \
  "$PY" "$T/plugin-server.log" "$T" > "$T/plug/.mcp.json"
printf '{"hooks": {"PreToolUse": [{"matcher": "mcp__.*probe.*", "hooks": [{"type": "command", "command": "%s %s"}]}]}}\n' \
  "$PY" "$T/hook.py" > "$T/settings.json"

echo "claude: $(claude --version 2>/dev/null | head -1)"
( cd "$T/proj" && claude -p "Call the tool mcp__probe__ping_probe once and the tool \
mcp__plugin_phiwardprobe_probe__ping_probe once, then reply with one word." \
    --settings "$T/settings.json" --plugin-dir "$T/plug" \
    --allowedTools "mcp__probe__ping_probe,mcp__plugin_phiwardprobe_probe__ping_probe" \
    >/dev/null 2>&1 ) || true

"$PY" - "$T" <<'EOF'
import json, os, sys
t = sys.argv[1]
def load(n):
    try:
        return json.load(open(os.path.join(t, n)))
    except (OSError, ValueError):
        return None
hook, server = load("hook.log"), load("server.log")
if hook is None:
    print("The hook was not called for the probe tool (was the tool used? is .mcp.json loaded?).")
else:
    print("mcp_server in the hook input:", json.dumps(hook["mcp_server"]))
    print("hook chain:  ", " <- ".join(f"{c['comm']}({c['pid']})" for c in hook["chain"]))
if server is None:
    print("The probe server did not start.")
else:
    print("server chain:", " <- ".join(f"{c['comm']}({c['pid']})" for c in server["chain"]))
if hook and server and len(server["chain"]) > 1:
    parent = server["chain"][1]["pid"]
    pids = [c["pid"] for c in hook["chain"]]
    depth = pids.index(parent) if parent in pids else None
    print("the server's parent is the hook's ancestor at depth:", depth,
          "(phiward needs 1 to 3)" if depth is not None else "(not an ancestor)")
if server is not None:
    print("configured server has CLAUDE_PLUGIN_ROOT:", server.get("plugin_root_set"),
          "(phiward needs False)")
plug, plug_hook = load("plugin-server.log"), load("hook-plugin.log")
if plug_hook is not None:
    print("mcp_server for the plugin's tool:", json.dumps(plug_hook["mcp_server"]))
if plug is None:
    print("The plugin's probe server did not start (is --plugin-dir supported here?).")
else:
    print("plugin server has CLAUDE_PLUGIN_ROOT:", plug.get("plugin_root_set"),
          "and it is its folder:", plug.get("plugin_root_is_its_folder"), "(phiward needs True);",
          "spelled exactly as the folder:", plug.get("plugin_root_exact"))
    print("plugin server's CLAUDE_PLUGIN_DATA:", plug.get("plugin_data"),
          "(phiward expects ~/.claude/plugins/data/<id>, no trailing /)")
EOF
