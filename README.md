# phiward

phiward keeps protected data (for example patient data) and your credentials out of what an AI
coding agent sends to its model provider. The agent's tools send their output to the provider,
and that output can hold file contents, sample identifiers or file names. With phiward, the
agent works on protected data only through a **gateway** that masks names and identifiers.

**Why it exists, and how it differs from sandboxes, containers and PII tools:**
[docs/why.md](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/why.md).

**Start here:** [docs/quickstart.md](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/quickstart.md). Three steps: install phiward, set it up
(with Claude Code's help or by hand), and check it. In short:

```bash
uv tool install --python-preference only-managed phiward==0.2.0b1
```

then in Claude Code, `/plugin marketplace add msk-access/phiward#v0.2.0b1`,
`/plugin install phiward@phiward` and `/phiward:setup`.

> **Status: v0.2.0b1, a beta.** Tested with the real Claude Code on macOS, in the desktop app
> and in the terminal, and against a real HPC cluster. On Linux, only the test suite has run
> (no real Claude Code session yet). Read
> [docs/threat-model.md](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/threat-model.md) before you rely on it for real data.

It is a Python package with no dependencies. It makes no network connection of its own and
has no telemetry. It needs Python 3.9 or
newer, macOS or Linux, and Claude Code 2.1.295 or newer.

## How it works

```text
  The AI agent's tools                                What reaches the model provider
  (Read, Grep, Bash, MCP, ...)
          |
          |  not protected (the project, your prompts)
          +---------------------------------------->  as before, unchanged
          |
          |  a protected folder or a credential?
          v
  phiward's hook + the sandbox ---- refused ------->  only the refusal and its reason
          |
          |  work on protected data
          v
  The gateway (phiward run / copy)
    a broker outside the agent runs the command
    in a kernel sandbox, then masks the output  ---->  the command's output, names and
                                                       identifiers masked (so print
                                                       counts, not records)
```

- **Two modes.** Mode A, the default: a normal Claude Code session (the desktop app, an IDE, a
  terminal), wired by `phiward install claude`. Claude Code's own sandbox confines Bash; the file
  tools are refused protected data and credentials by phiward's hook and by permission rules.
  Mode B, the stronger one: `phiward launch` runs the whole agent tool in phiward's kernel
  profile (macOS Seatbelt, Linux bubblewrap). Terminal only for now. See
  [docs/modes.md](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/modes.md).
- **The gateway.** The agent works on protected data only through `phiward run -- CMD` and
  `phiward copy`. The broker runs them outside the agent, as you, and masks the output:
  protected paths, file names and identifiers become placeholders. HPC goes through
  `phiward run --remote` and `phiward copy`, over your own shared SSH connection
  ([docs/hpc.md](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/hpc.md)).
- **Git hooks** refuse commits that hold protected names or identifiers.

## What it does not do

- Masking hides names and identifiers, not other content: through the gateway, print counts and
  summaries, not records, and hide small counts (see "Small counts" in docs/daily-use.md).
- Out of the box, masking inside file contents covers only sequence and alignment file names,
  read names and loci (the `genomics` pack). Subject and sample identifiers inside files are
  masked only with a pack that has them (the `msk` example), your own `[sanitize] patterns` or
  `names_from`. The gateway masks entry names under the protected roots (4 characters or
  longer). `phiward setup` asks which rules apply, `phiward doctor` warns while none does, and
  `phiward run` ends with a note that counts the placeholders shown
  ([#3](https://github.com/msk-access/phiward/issues/3),
  [#5](https://github.com/msk-access/phiward/issues/5)).
- In Mode A, the file tools are refused inside Claude Code, not by the kernel; hooks and MCP
  servers that are not wrapped run with your rights; credentials that are not files (the macOS
  Keychain, some Kerberos caches, tokens in your environment) are not hidden by a file list.
- The network is open by default: an agent can send what it can read. In Mode A, `[network] limit`
  (suggested by `phiward setup`) limits shell commands to listed hosts, so `git push` and `pip
  install` fail until you list their hosts; WebFetch, MCP servers and Mode B stay open.
- Protection follows the path: protected data moved out of a protected folder is not protected.
  `phiward copy` writes only inside a protected root of your user config, or under a remote root
  you listed; data you move another way (your own `cp`, a download) is not protected there.

[docs/threat-model.md](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/threat-model.md) lists every limit.

## Documentation

**Use phiward**
- [Quick start](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/quickstart.md): install, set up, check (start here).
- [Daily use](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/daily-use.md): working with the agent on protected data; what to do when a
  command is refused.
- [HPC](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/hpc.md), [plugins](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/plugins.md),
  [agents with nobody watching](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/unattended.md), [Mode B: `phiward launch`](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/launch.md).
- [Setup in detail](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/setup.md), [configuration](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/configuration.md),
  [glossary](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/glossary.md).

**Decide whether phiward is enough for your data**
- [Why phiward](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/why.md): what exists already, and the gap it fills.
- [The two modes](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/modes.md): what each one confines.
- [The threat model](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/threat-model.md): what is protected, what is not, every known
  limit (a summary for reviewers comes first).

**Change phiward**
- [CONTRIBUTING.md](https://github.com/msk-access/phiward/blob/v0.2.0b1/CONTRIBUTING.md) and [the developer guide](https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/developer.md): set up,
  run the tests, how a decision is made.
- [AGENTS.md](https://github.com/msk-access/phiward/blob/v0.2.0b1/AGENTS.md): the rules for AI agents that work on phiward's code.

In a project that uses phiward, `phiward init` adds the rules for agents to that project's
`AGENTS.md` (the text is in [src/phiward/data/agents-section.md](https://github.com/msk-access/phiward/blob/v0.2.0b1/src/phiward/data/agents-section.md)),
and [skills/phiward/SKILL.md](https://github.com/msk-access/phiward/blob/v0.2.0b1/skills/phiward/SKILL.md) is the skill.

## Licence

AGPL-3.0-only. See [LICENSE](https://github.com/msk-access/phiward/blob/v0.2.0b1/LICENSE). Design credits are in [NOTICE](https://github.com/msk-access/phiward/blob/v0.2.0b1/NOTICE).
