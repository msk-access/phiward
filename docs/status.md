# Status

phiward is a beta. This page lists what has been tested, on made-up data, and what has not been
tested yet. It lists only results that passed. Each line names its source; the threat model's
[summary](threat-model.md#for-reviewers-the-summary) has the detail. Read the
[threat model](threat-model.md) before you rely on phiward for real data.

## Read this first

- **On Linux, the full check has passed only in Docker.** The maintainer's sandbox check has
  passed in Docker since 2026-11-22. On a real Linux machine, only Mode A has passed: on a RHEL 8
  compute node on 2026-11-25 ([threat model](threat-model.md#for-reviewers-the-summary)).
- **On RHEL 8 (kernel 4.18) the gateway cannot run.** That kernel has no Landlock, and
  `phiward run` refuses to run without it. The hook and Claude Code's sandbox work there: every
  Mode A line of the release check passed on such a node ([hpc.md](hpc.md)).

## What passed

| Platform | What passed |
|---|---|
| macOS | The maintainer's sandbox check with the real Claude Code (2026-11-25): every line passed except Mode B's wrapped MCP server, which cannot start in the check's own home folder; with the account's own home folder, in a macOS virtual machine, it started and could not read the protected file. Mode A: the real Claude Code desktop app, wired by `install claude`: reads of protected data and credentials refused, `ssh` to HPC failed, normal work unaffected. Mode A with the plugin only, in the desktop app: reads refused by the hook (no sandbox or permission rules without `install`). Mode B: the real Claude Code under `phiward launch`. A small stdio MCP server wrapped in `phiward launch`. HPC through the shared SSH connection, against a real cluster. The full test suite. |
| Linux | The maintainer's sandbox check with the real Claude Code, in Docker (since 2026-11-22). Mode A of the same check on a RHEL 8 compute node (kernel 4.18, bubblewrap 0.4.0, x86_64; 2026-11-25): the protected file hidden, writes to phiward's folder and the settings refused, a session with permission prompts off refused, new unix sockets refused; the gateway refused there (no Landlock), as documented. The full test suite, with bubblewrap. The published `@modelcontextprotocol/server-filesystem` 2.3.0, wrapped in `phiward launch`: it read ordinary files and could neither read nor list a protected folder. |

Source: the threat model, "What was tested".

## Not tested yet

From the threat model, "Not tested":

- the full check, the gateway included, on a real Linux machine with Landlock (it has passed only
  in Docker);
- `phiward launch` driven from the app with Remote Control;
- a published MCP server under `launch` on macOS (on Linux it was);
- a protected folder on a mounted HPC volume;
- `[network] limit` in a live Claude Code session (the settings it writes are tested; Claude
  Code enforces them);
- other agent tools than Claude Code.

From other pages:

- **Claude Code's real sandbox** is not tested by phiward's test suite: the suite never runs the
  real `claude`. The release check does, run by the operator. It does not cover MCP tools,
  WebFetch, IDEs on Linux, remote with `use_shared_connection = false`, NFS home folders, or
  Kerberos tickets (on RHEL 8 it ran Mode A only); and the first check after your own install is yours
  ([threat model, known limits](threat-model.md#known-limits)).
- **A plugin carried over into `launch`** (such as ECC) is not tested yet
  ([plugins.md](plugins.md)).
- **Keychain-backed tokens under Mode B** are not checked yet: prefer Mode A's test result for
  them ([launch.md](launch.md)).
- **Keystroke injection** (TIOCSTI) was confirmed under a profile like phiward's old one, and is
  not tested under Claude Code's own sandbox ([gap 5](threat-model.md#gap-5)).
