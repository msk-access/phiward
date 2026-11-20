# How phiward is laid out

phiward keeps protected data (PHI, and the credentials that would reach it) out of what an AI
coding agent sends to its model provider. It has layers; each one stops what the others cannot.
What each layer covers, and what no layer covers, is in
[docs/threat-model.md](../../docs/threat-model.md). How the modes fit together:
[docs/modes.md](../../docs/modes.md).

## The layers

| Layer | What it does | Main modules |
|---|---|---|
| The hook (Mode A) | Claude Code's PreToolUse hook: refuses tool calls that name protected paths, credentials or guard files; asks before writes to code that runs later | `adapters/claude.py`, `guards/protected_paths.py`, `paths.py`, `pathmatch.py`, `shell.py`, `hidden.py` |
| Claude Code's sandbox (Mode A) | The settings `install` writes: denyRead, denyWrite and deny rules, from the same lists | `install.py`, `claude_settings.py` |
| The gateway | `phiward run` and `phiward copy`: a broker outside the agent runs the command in a kernel profile and masks the output | `broker.py`, `run.py`, `copying.py`, `confine.py`, `sanitize.py`, `inventory.py`, `gateway.py` |
| `phiward launch` (Mode B) | The whole agent tool in a kernel profile, with carry-over of its settings | `wholetool.py`, `carryover.py` |
| MCP servers | `phiward mcp wrap` runs a server under `launch`; the hook trusts a wrapped server only while its launcher runs | `mcp_config.py`, `mcp.py` |
| HPC | Remote runs and copies through the operator's own SSH connection | `remote.py` |
| Pseudonymized tables | `phiward pseudonymize`, the operator's: a copy of one table (TSV, CSV, `.txt`, MAF, each also gzip) with its ID columns coded, the key in `~/.phiward/backups/keys` | `pseudonymize.py` |
| phiward's own install | The self-check of phiward's Python and files; `doctor`, `setup`, `init`, `pin`, the login service | `selfcheck.py`, `doctor.py`, `setup_cmd.py`, `init.py`, `pin.py`, `service.py` |

## Shared pieces

- `config.py`: the user config and a repository's `.phiward.toml` (a repo file can only add
  protection), the guard files, the program presets.
- `pathid.py`, `fsinfo.py`, `safeio.py`, `procinfo.py`: path identity, file-system facts, writes
  that never follow a link, process facts.
- `core.py`: the `Action` every guard judges. `cli.py`: the commands. `fasthook.py`: the hook
  under `phiward launch`, a quick first layer before the kernel. `session_note.py`: the note at the start of a session. `githooks.py`: the git hooks
  `init` installs in users' repositories. `_toml.py`: the config file reader (Python 3.9 has no
TOML reader). `names.py`: phiward's own program and module names (`agent-guards` stays an alias
during the beta).

How one tool call and one gateway request are decided, step by step:
[docs/developer.md](../../docs/developer.md).

## Where the tests are

[tests/README.md](../../tests/README.md) lists which test files cover which feature.
