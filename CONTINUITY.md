# Where the work stands

Updated at each milestone, not each session. Details are in the pull requests and issues.

## Goal

v0.2.0 stable, "trust and evidence" ([docs/roadmap.md](docs/roadmap.md)). v0.2.0b2, the second
beta, is on PyPI since 2026-11-25 (v0.2.0b1 since 2026-11-18).

## Just finished

- The 0.2.0b2 release: the CHANGELOG, the release notes, the public roadmap, and the release on
  PyPI and GitHub.
- The release checks (2026-11-25), on made-up data:
  - the sandbox check with the real Claude Code passed on Linux in Docker, and on macOS except
    Mode B's wrapped MCP server, which cannot start in the check's own home folder (#87); with
    the account's own home folder, in a macOS virtual machine, it passed;
  - Mode A passed on a RHEL 8 compute node (kernel 4.18, bubblewrap 0.4.0); the gateway refused
    there (no Landlock), as documented;
  - the quick start's 14 runs and its macOS run passed.
- Fixes found by those checks: doctor's broker-PATH step (#85), phiward's own exec-form hooks
  (#86), Mode A on bubblewrap below 0.5 where the KCM socket exists (#89, #90), the docs for a
  RHEL 8 node and a cluster before install (#88), the docs of what passed (#91).

## Next

1. One check of what a machine can do, made once and read by every layer: what bubblewrap can
   mount, the Landlock ABI, whether Claude Code's filter for new unix sockets works. install,
   the hook, doctor, the gateway and setup's first screen read the same result; the gateway
   refuses at its start with a clear reason. Design and review first.
2. 0.2.0b3, "easy to adopt": setup and doctor say first what this machine can run, setup keeps
   only the programs it finds, the plugin says when setup has not run, `doctor --json`, a
   warning when the plugin and the package versions differ.
3. Issue #6: the full sandbox check, the gateway included, on a real Linux machine with
   Landlock ABI 2 or newer (kernel 5.19 or newer).
4. Test timing under load: a few tests wait a fixed 10 s for a process and fail on a busy CI
   runner.
5. Then on GitHub: rulesets on `main`, `develop` and `v*` tags, private vulnerability reporting.

## Waiting on the maintainer

- The go-ahead for each publishing step, and a real Linux machine with a new enough kernel for
  #6.
- A CI path for docs-only changes (a `.github/workflows` change: asked first).
