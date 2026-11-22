# Why phiward: what exists, and the gap it fills

**For:** anyone who decides whether phiward is needed, beside sandboxes, containers and PII tools.

## The problem

An AI coding agent sends what its tools print to a model provider: file contents, command
output, file names. In research on patient data, that output can hold protected health
information (PHI), sample identifiers or file names that are identifiers themselves. Often there
is no agreement with the provider that allows this.

People who work beside such data still want the agent's help: to write and run analyses, to
check results, to submit jobs to an HPC cluster. So the question is not only "how do I keep the
agent away from the data?", but also "how does the agent still work on the data, without
seeing it?".

## What exists

This list is from each project's own documentation, read in November 2026. Check them again
before you choose; they change fast.

| Kind | Examples | What it gives | What it does not give for this problem |
|---|---|---|---|
| The agent tool's own sandbox and permission rules | Claude Code's sandbox, permission deny rules and managed settings | Bash in a kernel sandbox; file tools refused listed paths; an organization can force settings | You write every path and credential by hand, per tool. No way to work on protected data with masked results. Nothing for HPC. |
| Sandboxes around a whole command | Anthropic's `sandbox-runtime`, `nono`, `landrun` | A kernel profile (Seatbelt, bubblewrap, Landlock) around any program; network proxies | A general sandbox: no model of protected data inside a readable project, no masked way back to the data, nothing for HPC. |
| Containers and VMs | Docker Sandboxes, dev containers, Apptainer | Strong isolation; a session that is thrown away | The data must stay outside. Docker does not run on most HPC systems. Work on the data itself is not possible from inside. |
| Code-only PHI guards | `phi-guard` | A container that holds only the committed code; an egress firewall; masking by a cloud service | Made for work **away** from PHI, by design. No masked way to run analyses on it. Nothing for HPC or mounted data. |
| PII detection and redaction | Presidio, LLM Guard, MCP PII proxies | Finds and masks personal data in text, often with language models | Sees only the text it is given. The agent's shell and file tools go around an MCP proxy. Nothing stops the agent from reading the data first. |
| Secret scanners | gitleaks and similar | Find credentials in commits | Not about tool output or PHI. |

## The gap phiward fills

phiward is for **work beside protected data**: the agent helps with the analysis, and the data
does not reach the model provider.

It is built for an honest user, and for an agent that is honest but can be misled by text it
reads (prompt injection). It is not built to stop a determined attacker who already runs code on
the machine ([threat model](threat-model.md#for-reviewers-the-summary)).

1. **Protected data by folder, for the whole tool.** You name the folders that hold protected
   data once. phiward writes that into Claude Code's sandbox and permission rules (Mode A), or
   runs the whole tool in its own kernel profile (Mode B), together with a list of credential
   files that no agent may read.
2. **A masked way to work on the data.** The agent does not read protected data; it asks the
   **gateway** (`phiward run`, `phiward copy`). Your **broker** runs the command outside the
   agent, as you, and masks the output: protected paths, the names of files under them, and
   identifier patterns become placeholders. Ask for counts and summaries: masking hides names and
   identifiers, not other content.
3. **HPC without giving the agent your login.** `phiward run --remote` and `phiward copy` go
   through your own shared SSH connection. No request reads your key or Kerberos ticket, and only
   the hosts and programs you list are allowed.
4. **Easy for a team.** One setup command, a guided setup inside Claude Code
   (`/phiward:setup`), `phiward init` for a project, and a check (`phiward doctor`) that says
   what is missing.
5. **Local and deterministic.** No cloud service, no language model in the masking, no
   network. Python's standard library only.

## What phiward reuses, and what it does not do

- It reuses the operating system's sandboxes (Seatbelt on macOS; bubblewrap, seccomp and
  Landlock on Linux), Claude Code's own sandbox and permission rules, and the system `ssh`,
  `tar` and `rsync`.
- It filters the network only where Claude Code's own sandbox can: with `[network] limit`, the
  shell commands of a Mode A session reach only the hosts you list. The WebFetch tool, MCP
  servers and Mode B stay open: an agent can still send what it can read there. A network proxy
  such as the one in `sandbox-runtime` could add that later.
- Masking hides names and identifiers, not other content in a record. Gateway commands should
  print counts and summaries.

All limits are in [threat-model.md](threat-model.md).

## Sources

- Claude Code settings and sandbox: https://code.claude.com/docs/en/settings
- sandbox-runtime: https://github.com/anthropic-experimental/sandbox-runtime
- nono: https://github.com/always-further/nono
- landrun: https://github.com/Zouuup/landrun
- Docker Sandboxes: https://docs.docker.com/ai/sandboxes/
- phi-guard: https://github.com/matthewevans/phi-guard
- Presidio: https://github.com/microsoft/presidio
- LLM Guard: https://github.com/protectai/llm-guard
- gitleaks: https://github.com/gitleaks/gitleaks

Next: [the two modes](modes.md), then [the threat model](threat-model.md).
