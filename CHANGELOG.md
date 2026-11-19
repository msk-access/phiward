# Changelog

All notable changes to phiward. Dates are UTC. Versions follow semantic versioning; until
1.0, a minor version may change behaviour.

## [0.2.0b2] - unreleased

### Changed

- The `genomics` pack's number rule masks a run of 5 or more digits next to a comma too
  (`1234567,7654321` becomes `<NUM>,<NUM>`), as the docs say; only a decimal such as
  `12345.678` keeps its digits.
- `phiward copy` makes each local path absolute once, and every check and the copy itself use
  that path. A local path with a `..` part, or one that starts with `~` (quoted), or an empty
  one, is refused: give the full path.

## [0.2.0b1] - 2026-11-18 (beta)

The first public release. phiward keeps protected data (for example patient data) out of what
an AI coding agent sends to its model provider. Read
[docs/threat-model.md](docs/threat-model.md) before you rely on it, and
[docs/release-notes/v0.2.0b1.md](docs/release-notes/v0.2.0b1.md) for what is tested.

### Added
- **Mode A**, a Claude Code session wired by `phiward install claude --user --write`: a hook
  on every tool, Claude Code's sandbox settings and permission rules for the protected roots
  and patterns, credentials and histories (the hidden list), and the files that run later
  (settings, skills, hooks, git's control files, editor settings).
- **Mode B**, `phiward launch`: the whole agent tool in a kernel profile (macOS Seatbelt,
  Linux bubblewrap), with stateless carry-over and quarantine (`phiward carryover`).
- **The gateway**: `phiward run -- CMD` and `phiward copy` run through a broker outside the
  agent, in a kernel profile, and print masked output (protected paths, entry names,
  identifiers). `[broker] commands` limits the programs; grants for write places and the
  network come from the user config only.
- **MCP servers**: `phiward mcp list|wrap|unwrap` runs a local server in the kernel profile; the
  hook trusts a wrapped server only while it runs so, with the profile the hook would build.
- **HPC** through your own shared SSH connection: `phiward run --remote HOST -- CMD`, and
  copies to and from approved remotes.
- **Setup and checks**: `phiward setup` (profiles, a results folder, a program list, the login
  service), `phiward init` for a project, `phiward doctor` (also `--headless` for unattended
  agents), the Claude Code plugin (`/phiward:setup`) and a start-of-session note.
- **Sanitizer packs** (`genomics`, `dates`, and an example institution pack) and your own
  names files and patterns.

### Upgrading from agent-guards (a private pre-release)
Uninstall agent-guards, install phiward, move `~/.config/agent-guards` to
`~/.config/phiward` (and a repo's `.agent-guards.toml` to `.phiward.toml`), then run
`phiward setup` (choice 1), `phiward mcp list` and `phiward doctor`. The `agent-guards` command
stays as an alias during the beta.

### Limits
What phiward does not protect, and every known gap, is in
[docs/threat-model.md](docs/threat-model.md).
- Out of the box, masking inside file contents covers only sequence and alignment file names,
  read names and loci (the `genomics` pack). Subject and sample identifiers inside files are
  masked only with a pack that has them (the `msk` example), your own `[sanitize] patterns` or
  `names_from`. The gateway masks entry names under the protected roots (4 characters or
  longer). Planned for 0.2.0b2: setup asks, doctor warns, and the output says what was masked
  ([#3](https://github.com/msk-access/phiward/issues/3),
  [#5](https://github.com/msk-access/phiward/issues/5)).
