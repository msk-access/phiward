# Roadmap

This page says where phiward is going. The goal stays the same: keep protected health information
(PHI) and other protected data out of what an AI coding agent sends to its model provider, and keep
the agent useful for real research work.

The plan can change. What is built is in the CHANGELOG. What is not protected is in the
[threat model](threat-model.md).

## How we choose

1. Protect first what typical use reaches.
2. Remove the friction that makes someone turn a guard off.
3. Give an institution the evidence it needs to approve agent use.
4. Keep it small: take a mechanism away before you add one. Use the Python standard library only.
   When a check cannot decide, refuse.

## Next: 0.2.0, trust and evidence

- **Easy to adopt:**
  - setup and `phiward doctor` say first what this machine can run (Mode A, the gateway,
    Mode B), and give one step for each part that cannot;
  - setup keeps only the programs it finds, and offers to make the folders of `uv`, `claude`
    and phiward writable by you alone;
  - with the plugin and no config, a session says to type `/phiward:setup`;
  - `phiward doctor --json`, so an agent can read the state and the next step (the
    configuration report below uses the same format);
  - doctor warns when the plugin and the package have different versions.
- **A full review of the threat model.** Before 0.2.0, the threat model is reviewed end to end, and
  each limit is stated with what you can do about it.
- **A local decision log, on by default.** It records each refusal and each gateway run: the date,
  the layer, the decision and the rule. It never records a path or a value, and the agent cannot reach
  it. If the log cannot be written, no decision changes.
- **A configuration report.** `phiward doctor` writes a report that a machine can read, for an IRB or
  a security review. It lists the version, the mode, the layers that are on, the packs, the pinned
  programs, the network limit and the limits that apply.
- **A wider masking check.** It also tests what the hook answers for a made-up path, and tests the
  network limit with one allowed host and one refused host.
- **Check results with each release.** The release notes say which sandbox checks passed, and on
  which platform.
- **Pages for reviewers:**
  - a page for IRB and compliance reviewers;
  - a note on what phiward is not (a BAA, an IRB approval or a data use agreement), and why you still
    need it when you have one;
  - a page on the usual rules HPC centres set for AI agents;
  - a page for your first week.
- **A host allow list for `phiward launch`.** Launch's proxy uses the same `[network] limit` and
  `allowed_domains` as Mode A.
- **Tokens in the environment kept from the sandboxed shell,** where Claude Code supports it.
- **The last typical refusals,** each with a clear next step:
  - doctor says when the config changed since the broker started;
  - a write to a file that runs later gets a one-line answer;
  - "don't ask again" and similar answers can stay under launch;
  - a linked file that phiward should allow (from a dotfile manager, for example) works, or is
    refused with a step.
- **Small fixes to stated limits:**
  - the hook-only gaps that have small fixes;
  - `MODULEPATH` and `PYTHONPATH` under launch;
  - a warning for Claude Code versions that do not protect project settings themselves.
- **Real machines:** the full check on a recent Linux kernel; Mode A on RHEL 8 clusters, with the
  result in the release notes; and the macOS check in a virtual machine, with the account's own
  home folder.

## Then: 0.3, research workflows

- **A shorter loop for reviewed scripts.** Today, each edit of an analysis script that runs on
  protected data takes four steps: read, move, pin and restart the broker. The goal is one reviewed
  step, with no restart. The review stays.
- **Pipelines and notebooks.** phiward names the places where Nextflow and Snakemake write their
  logs, and the notebooks that keep saved outputs. The git hook checks notebook outputs. One page
  covers both workflows.
- **Output control:**
  - small-count suppression in `run --table`, opt-in, with a threshold you choose;
  - a Safe Harbor pack, off by default;
  - a starter pack for common ID shapes;
  - flowcell and instrument IDs;
  - a measure of recall on a made-up corpus.
- **Lab rollout:** one config for the whole lab, from a managed place, that can only tighten
  protection; a page for organizations (managed Claude Code settings, a plugin turned on for
  everyone); a Linux dev container for a first trial.
- **macOS profiles tested on a set of real research workloads.**

## Later, or when asked

- other agent tools: Cursor first, then Codex and Gemini CLI;
- masking the results of wrapped MCP servers, and a mode that keeps gateway output smaller;
- an optional local detector that can only mask more, and is never a dependency;
- network limits beyond the shell in Mode A (WebFetch, MCP servers);
- a page on using WSL2 on Windows;
- a new docs theme before MkDocs Material reaches its end of life.
