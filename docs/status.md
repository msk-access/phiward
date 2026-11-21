# Status

phiward is a beta. This page lists what has been tested, on made-up data, and what has not been
tested yet. It lists only results that passed. The source of each line is the threat model's
[summary](threat-model.md#for-reviewers-the-summary), which has the detail. Read the
[threat model](threat-model.md) before you rely on phiward for real data.

## What passed

| Platform | What passed |
|---|---|
| macOS | Mode A: the real Claude Code desktop app, wired by `install claude`: reads of protected data and credentials refused, `ssh` to HPC failed, normal work unaffected. Mode A with the plugin only: reads refused by the hook (no sandbox or permission rules without `install`). Mode B: the real Claude Code under `phiward launch`. A small stdio MCP server wrapped in `phiward launch`. HPC through the shared SSH connection, against a real cluster. The full test suite. |
| Linux | The full test suite, with bubblewrap. The published `@modelcontextprotocol/server-filesystem` 2.3.0, wrapped in `phiward launch`: it read ordinary files and could neither read nor list a protected folder. |

## Not tested yet

- the real Claude Code on Linux (only the test suite);
- `phiward launch` driven from the app with Remote Control;
- a published MCP server under `launch` on macOS (on Linux it was);
- a protected folder on a mounted HPC volume;
- `[network] limit` in a live Claude Code session (the settings it writes are tested; Claude
  Code enforces them);
- other agent tools than Claude Code.
