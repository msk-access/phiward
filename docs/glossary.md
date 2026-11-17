# Glossary

The words that phiward's pages use, in alphabetical order.

- **Broker**: the program that runs gateway requests outside the agent, as you, and masks what
  comes back. You start it (best as a login service: `phiward broker --service --write`). The
  agent cannot start or change it.
- **Carry-over, trusted copy, quarantine** (Mode B only): each `phiward launch` session starts
  from a **trusted copy** of the agent tool's settings, skills and MCP servers, which you fill
  with `phiward carryover add`. What a session changes there goes to **quarantine**. Nothing
  from quarantine is used until you accept it (`phiward carryover accept`).
- **Config**: phiward's own settings, a TOML file (`~/.config/phiward/config.toml`, written by
  `phiward setup`): your protected roots, grants and the like. Not Claude Code's settings; those
  are the **wiring**. See [configuration.md](configuration.md).
- **Confined**: a shell, or a program, whose reads the kernel limits (Claude Code's sandbox, or
  phiward's kernel profile). The hook refuses every command of a shell that is not confined but
  a whole gateway call.
- **Derived protected folders**: folders that phiward protects without being in your config:
  its own cache folder, and the `.git` of a repository that holds a protected root.
- **Gateway**: `phiward run`, `phiward copy` and `phiward run --remote`. The only way the agent
  works on protected data. The broker runs each request and masks the output.
- **Gateway call, whole command**: a `phiward run -- CMD` or `phiward copy` written as the
  entire command, with fixed words: no `cd X &&` before it, no `| head` or `> file` after it, no
  `$(...)` or variable. Only that form runs where the shell is not confined.
- **Grant**: a capability you give the gateway in your own config. `write_to` lets a gateway
  command write in a folder; `net` lets it use the network. The default is none. Nothing asks
  you at run time: what the config does not grant is refused.
- **Hidden list**: credentials, Kerberos ticket caches and keytabs, SSH keys, shell histories,
  other logins and the like, which no agent may read, in addition to your protected roots.
- **Hook**: a command that Claude Code runs before each tool call (phiward's guard) or when a
  session starts (phiward's note on the rules).
- **Kernel profile**: a set of rules that the operating system enforces on a program and every
  program it starts (on macOS Seatbelt; on Linux bubblewrap, seccomp and Landlock). The program
  cannot switch them off. Mode B runs the whole agent tool in one.
- **Masking**: the gateway replaces protected paths, file names and identifiers in output with
  placeholders such as `<PROTECTED>`. It does not hide other content, so print counts and
  summaries, not records. The part of phiward that masks is the **sanitizer**.
- **MCP server**: a program that gives an agent tool more tools (Model Context Protocol).
  phiward has one, `phiward mcp`, whose tools are the gateway.
- **MCP server: wrapped, not wrapped, remote**: a **wrapped** server runs under
  `phiward launch --`, in the kernel profile, so it cannot read protected data. A **not wrapped**
  one (shown as "not wrapped (runs with your rights)") can read what you can; its tools that run
  commands may make only gateway calls. A **remote** one runs on another machine and nothing
  here. `phiward mcp list` says which each of yours is. See [modes.md](modes.md#wrap-an-mcp-server-mode-a).
- **Mode A**: a normal Claude Code session (the desktop app, an IDE or a terminal), wired by
  `phiward install claude`. Claude Code's own sandbox and permission rules, plus phiward's hook,
  keep protected data out. See [modes.md](modes.md).
- **Mode B**: the whole agent tool run under `phiward launch`, in phiward's kernel profile.
  Terminal only. See [launch.md](launch.md).
- **Operator**: you, the person who installs phiward and owns the config. The agent's rules use
  this word.
- **Pack**: a built-in or own list of identifier patterns to mask (for example `genomics`).
- **Plugin**: a bundle of hooks, skills, commands and MCP servers that Claude Code installs in
  one step. See [plugins.md](plugins.md).
- **Protected root**: a folder whose contents the agent may not read. You list them in your
  config.
- **Remote Control**: a Claude Code feature that lets you drive a session that runs in a
  terminal from the desktop app, the web or a phone.
- **Scope, source** (MCP servers): where a server's definition lives. Your own **user**
  scope (`~/.claude.json`), this project's **local** entry in it, the repository's **project**
  file (`.mcp.json`), or a **plugin**. Claude Code tells the hook each tool's **source**
  (2.1.274 and newer); an older one does not, and then a `.mcp.json` server counts as not
  wrapped.
- **Shared SSH connection**: one SSH connection to a cluster that you open yourself
  (`ssh -fN hpc`). phiward's HPC requests join it through its control socket, so they need no
  key or ticket of their own. See [hpc.md](hpc.md).
- **Skill**: written guidance that an agent loads when it needs it. phiward's skill tells the
  agent how to work through the gateway.
- **Spool**: the folder where the agent leaves requests for the broker (`~/.phiward-spool`).
- **Wiring**: what `phiward install claude` writes into Claude Code's settings: the hooks, the
  sandbox rules and the permission rules. **User wiring** (`--user`) covers every session in every
  folder; **project wiring** covers one project.
