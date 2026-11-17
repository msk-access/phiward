"""Start the `docs` entry of ~/.claude.json as Claude Code does (its command and args, in the
project folder, JSON-RPC over stdin and stdout), say whether it answered `initialize`, and, while
it runs, ask the hook about one of its tools as this process's child (this process stands in for
Claude Code): from the project, and from a session opened in the home folder. The hook must
trust the wrapped server in both (exit 0)."""
import json
import os
import subprocess

home, project = os.path.expanduser("~"), os.getcwd()
e = json.load(open(os.path.join(home, ".claude.json")))["mcpServers"]["docs"]
p = subprocess.Popen([e["command"]] + e.get("args", []), stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
p.stdin.flush()
line = p.stdout.readline()
print("answered" if '"result"' in line else "no answer")
for where in (project, home):
    payload = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": where,
               "permission_mode": "default", "tool_name": "mcp__docs__run_command",
               "tool_input": {"command": "id"},
               "mcp_server": {"name": "docs", "source": "user"}}
    r = subprocess.run(["phiward", "hook", "claude"], input=json.dumps(payload), text=True,
                       capture_output=True, cwd=where,
                       env=dict(os.environ, CLAUDE_PROJECT_DIR=where))
    print(f"hook from {'home' if where == home else 'project'}: exit {r.returncode}",
          r.stderr.strip()[-200:])
p.stdin.close()
err = p.stderr.read()
p.wait(timeout=60)
print("server stderr:", err.strip()[-300:])
