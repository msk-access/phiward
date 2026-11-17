"""Ask the hook about a plain Bash command from a session in the folder `argv[1]`, and print its
exit status and what it said."""
import json
import os
import subprocess
import sys

where = sys.argv[1]
payload = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": where,
           "permission_mode": "default", "tool_name": "Bash", "tool_input": {"command": "ls"}}
r = subprocess.run(["phiward", "hook", "claude"], input=json.dumps(payload), text=True,
                   capture_output=True, cwd=where,
                   env=dict(os.environ, CLAUDE_PROJECT_DIR=where))  # as Claude Code sets it
print("hook exit", r.returncode, r.stdout.strip()[-400:], r.stderr.strip()[-400:])
