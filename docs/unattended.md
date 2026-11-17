# Agents with nobody watching: headless, the Agent SDK, scheduled runs, CI

- **For:** you, the operator, when an agent runs with no person at each step.
- **Before:** the [quick start](quickstart.md) is done.
- **You will have:** guarded unattended runs, and a list of what holds and what does not.

An agentic workflow is a script that calls `claude -p`, an app built on the Claude Agent SDK, a
scheduled or long-running agent, or several agents working together. phiward fits these well where
it runs on **your own machine**, because nothing in it asks at run time. The grants are set ahead of
time in your user config, and what they do not allow is refused. The limits of each mode are in
[modes.md](modes.md) and [threat-model.md](threat-model.md).

## Before every unattended run

```bash
phiward doctor --headless
```

It exits with 0 when a Claude Code session in this folder would be guarded, and with 1 and the
reasons when not. Put it first in the script. It checks that:

- your user (or managed) settings run phiward's isolated hook on every tool. That is the `/bin/sh -c
  '...; exec <python> -I -m phiward hook claude'` that `phiward install claude --user --write`
  writes. The plugin's and project hooks alone are not enough here, because a project's `env.PATH`
  can replace them;
- the program the hook names is there, every entry blocks on failure and has no `async` or
  `if`, and every tool is covered (the matcher `*`);
- no settings file Claude Code may read turns hooks off (`disableAllHooks`, managed
  `allowManagedHooksOnly`) and the project's settings set no `env` that changes the hook;
- the permission deny rules for protected and hidden paths are there;
- Claude Code's sandbox confines the shell (on Linux, bubblewrap and socat are installed);
- the broker is running.

With protected patterns, the shell counts as confined only on macOS (Claude Code 2.1.236 or
newer, after `install claude --user --write`). Otherwise `--headless` reports it as not ready,
because the hook then refuses shell commands other than gateway calls.

## What fits

| Workflow | Set it up like this | What holds |
|---|---|---|
| `claude -p` in a script, cron job or LaunchAgent, on your machine | `(cd ~ && phiward install claude --user --write)` and the broker service, as for interactive use. **Never `--bare`.** | The same as an interactive session (Mode A). A refusal holds in every permission mode, `bypassPermissions` and `dontAsk` included. |
| An Agent SDK app (Python, TypeScript) on your machine | Leave `settingSources` at its default, or pass `settings` from `phiward install claude --json` (below). Add the callback below as a second check. | Mode A, as above. |
| The agent reads untrusted input (web pages, other people's files) | Run it under Mode B: `phiward launch --tool claude --report ~/phiward-runs/run.json -- claude -p "..."`. Read the report. | The whole tool in phiward's kernel profile. |
| Subagents, an orchestrator with workers | Nothing extra. Hooks, the sandbox and deny rules apply to a subagent's tool calls too. | As for the session that started them. |
| A scheduled agent that uses HPC | The shared SSH connection must be open, and your Kerberos ticket valid, when it runs. | `run --remote` is refused (fails closed) when they have expired. |

## What does not fit

- **`claude --bare`, or an SDK app with `settingSources: []` and nothing in its place.** They
  load none of phiward's wiring: no hook, no sandbox block, no deny rules. Nothing says so.
  Claude Code's docs recommend `--bare` for scripts; do not use it for work beside protected
  data.
- **CI runners and containers that hold the data.** The broker must run outside the agent, as
  you; in CI every other step runs as the same user, can read the data and can change your
  config. A broker inside a container usually cannot start its confinement, and refuses.
- **A repository you have not read.** `claude -p` shows no trust prompt: a cloned repository's
  project settings (hooks, `env`, permission rules) apply at once. Run `phiward doctor
  --headless` in that folder first; the hook refuses every call when the project's `env` would
  change it, and the checks above name the rest.
- **GitHub-hosted runners, cloud sessions, SLURM jobs.** There is no operator side there. Keep
  protected data away from them. Only the identifier check works without data:
  `phiward sanitize --check FILE`.

## An Agent SDK app

Two layers, use both.

**1. The wiring as settings.** An app that loads no settings file still gets phiward's hook,
sandbox block and deny rules from one JSON file:

```bash
phiward install claude --json > ~/.config/phiward/sdk-settings.json
```

Run it in your own terminal (it prints every protected path, so it refuses without one). Put
the file next to your user config: that folder is protected from agent writes (with
`PHIWARD_CONFIG` somewhere else, beside that file). Pass it as the `settings` option (Python
`ClaudeAgentOptions(settings=...)`, TypeScript `options.settings`). Write it again after you
change your phiward config.

**2. A PreToolUse callback.** It runs phiward's own hook on each tool call, so the decision is
the same as in a Claude Code session. It judges the shell as not sandboxed (the hook is
strictest then), because it cannot know which settings your app loaded. It refuses everything
when phiward is missing. Copy it into your app; do not install phiward into the app's own
environment (the agent may be able to change files there).

<!-- sdk-callback-python -->
```python
import asyncio
import json
import shutil

# your `uv tool install`, outside this app; give its full path if the app's PATH holds folders
# the agent can write (a project's .venv/bin)
PHIWARD = shutil.which("phiward")


def _deny(why):
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": "deny",
                                   "permissionDecisionReason": why}}


async def phiward_guard(input_data, tool_use_id, context):
    """PreToolUse callback: phiward's hook decides. Every failure refuses the call."""
    if PHIWARD is None:
        return _deny("phiward is not installed, so every tool call is refused")
    proc = None
    try:
        payload = dict(input_data)
        payload.pop("permission_mode", None)  # judge the shell as not sandboxed
        proc = await asyncio.create_subprocess_exec(
            PHIWARD, "hook", "claude", stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(json.dumps(payload).encode()), 30)
        if proc.returncode != 0:
            return _deny(err.decode("utf-8", "replace").strip() or "phiward refused the call")
        reply = json.loads(out) if out.strip() else {}
        decision = reply.get("hookSpecificOutput", {}).get("permissionDecision")
        if decision == "ask":
            return _deny(reply["hookSpecificOutput"].get("permissionDecisionReason",
                                                         "phiward would ask") + " (nobody to ask)")
        return reply if decision in (None, "deny") else _deny("phiward's reply was not understood")
    except Exception as exc:  # noqa: BLE001 - every failure refuses the call
        if proc is not None and proc.returncode is None:
            proc.kill()
        return _deny(f"phiward's hook did not answer ({type(exc).__name__})")
```

Register it for every tool:

```python
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

options = ClaudeAgentOptions(
    settings="/Users/me/.config/phiward/sdk-settings.json",
    hooks={"PreToolUse": [HookMatcher(matcher=".*", hooks=[phiward_guard], on_failure="block")]},
)
```

In TypeScript, the same callback:

<!-- sdk-callback-js -->
```js
import { spawn, execFileSync } from "node:child_process";

// phiward from your `uv tool install`, found once, outside this app
let PHIWARD = null;
try { PHIWARD = execFileSync("sh", ["-c", "command -v phiward"]).toString().trim() || null; } catch { PHIWARD = null; }

const deny = (why) => ({ hookSpecificOutput: { hookEventName: "PreToolUse",
  permissionDecision: "deny", permissionDecisionReason: why } });

export async function phiwardGuard(input) {
  if (!PHIWARD) return deny("phiward is not installed, so every tool call is refused");
  const payload = { ...input };
  delete payload.permission_mode; // judge the shell as not sandboxed
  return await new Promise((resolve) => {
    let out = "", err = "";
    const p = spawn(PHIWARD, ["hook", "claude"], { stdio: ["pipe", "pipe", "pipe"] });
    p.stdin.on("error", () => {}); // the hook may exit before it reads; its exit decides
    const timer = setTimeout(() => { p.kill(); resolve(deny("phiward's hook did not answer")); }, 30000);
    p.on("error", () => { clearTimeout(timer); resolve(deny("phiward is not installed, so every tool call is refused")); });
    p.stdout.on("data", (d) => { out += d; });
    p.stderr.on("data", (d) => { err += d; });
    p.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) return resolve(deny(err.trim() || "phiward refused the call"));
      let reply = {};
      try { reply = out.trim() ? JSON.parse(out) : {}; } catch { return resolve(deny("phiward's reply could not be read")); }
      const decision = reply.hookSpecificOutput?.permissionDecision;
      if (decision === "ask") {
        return resolve(deny((reply.hookSpecificOutput.permissionDecisionReason || "phiward would ask") + " (nobody to ask)"));
      }
      resolve(decision === undefined || decision === "deny" ? reply : deny("phiward's reply was not understood"));
    });
    p.stdin.end(JSON.stringify(payload));
  });
}
```

Register it with `hooks: { PreToolUse: [{ matcher: ".*", hooks: [phiwardGuard], onFailure: "block" }] }`.

The app's own code, and the tools you write into it, run as you and are not guarded by
phiward: keep protected data out of them, or reach it through the gateway (`phiward run`).

## Mode B with nobody watching

```bash
phiward launch --tool claude --report ~/phiward-runs/run.json -- claude -p "count the reads per sample"
```

`launch` passes the arguments after `--` to the tool and needs no terminal. Give the tool its login
in `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` (the agent can read it).

`--report` writes a JSON file whenever `launch` ends, also when nothing could run. A report that
says `needs_review: true` is written before the tool starts, so a crash or a signal leaves one too.
Give a file path outside every place the session can write (the project, the spool, the temp folder,
`~/.phiward`, in any spelling). It must not be a file that controls the guards (phiward's config or
code, Claude Code's settings, a hidden credential). Otherwise nothing runs. The file is written new
and moved into place, so nothing the session left at that path is opened. When the place is refused,
nothing is written. For `launch` inside `launch` it is written with `exit: null` before the tool
takes over the process (the outer `launch` reports the run). It holds:

- `exit`: the tool's exit status;
- `ran`: whether the tool started;
- `needs_review`: true when the tool did not run, or the session changed instructions (they
  wait in quarantine), files that run later (build files, git hooks, CI workflows), settings,
  or git control files, or the project had more entries than launch compares. Other changed
  files are counted, not flagged;
- `project_changed`: the changed project files by kind (`instructions`, `runs_later`,
  `settings`, `other`);
- `carryover`: the lines about the session's instructions and quarantine;
- `git_control_changed`: the git control files that changed (Linux);
- `notes`: every line `launch` printed at the end.

A script should stop, and a person should read the notes, when `needs_review` is true. Accept
nothing from quarantine without reading it (`phiward carryover show`).

## Risks that grow when nobody watches

- **Prompt injection.** A page or file the agent reads can tell it what to do, and nobody sees it
  happen. phiward still keeps it from reading protected data, but what it can read it can send: the
  network is open by default. In Mode A, `[network] limit` keeps shell commands to the hosts you
  list ([configuration.md](configuration.md)). The WebFetch tool, MCP servers and Mode B stay open.
- **Masked output is still content.** Gateway output hides names and identifiers, not other
  content. Write the gateway commands an agent may run so that they print counts and summaries,
  and limit them with `[broker] commands`.
- **Long runs add up.** Each gateway call returns up to `[broker] max_output_lines` lines; many
  calls return many lines. Set a lower limit for unattended runs, and cap the run itself
  (`claude -p --max-turns N`, the SDK's `max_budget_usd`).
- **Several agents share one broker and one spool.** Requests carry no agent identity, and an
  agent can change another agent's reply in the spool (it is the same user). One agent's masked
  output passed to another is ordinary text to phiward.
- **Secrets in the environment.** Mode A hides credential files, not environment variables. Do
  not put tokens an agent should not have into the environment of the run.
