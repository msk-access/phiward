# Where the work stands

Updated at each milestone, not each session. Details are in the pull requests and issues.

## Goal

v0.2.0b2, the second beta (v0.2.0b1 is on PyPI since 2026-11-18). Its changes are merged on
`develop`; the release text and docs are in progress.

## Just finished

- Issues #2 to #5, and `phiward pseudonymize` (PRs 23 to 27), then code hygiene (PRs 28 to 35).
- The checks of what reaches the provider: the prompt scan and `@` mentions off (#54, #57), the
  masking check (#64), the project scan (#68), the leak test for typical sessions (#65).
- `phiward launch`: the network proxy that refuses this machine and private addresses (#49),
  files that run later read-only (#50), unix sockets on Linux (#51), macOS without a helper
  (#58), `[launch] write_to` (#73), and its fixes (#38, #74, #75, #76).
- Mode A: `excludedCommands` gets the text check (#69), `[no_phi] folders` (#72, #78).
- The hooks run from files in the package (#62); the macOS gateway profile is a file (#56);
  `phiward copy` puts no code in a command line (#60).
- Refusals that name their step (#71, #80); the broker's version in doctor (#79); doctor's
  launch section uses launch's own folder checks (#81).
- The sandbox check runs on Linux too (#40, #44, #47, #48). On Linux, the maintainer's sandbox
  check has passed in Docker since 2026-11-22.

## Next

1. The release text and docs for 0.2.0b2: the CHANGELOG's "What changes for you", the release
   notes, the doc fixes and a public roadmap ([docs/roadmap.md](docs/roadmap.md)).
2. The 0.2.0b2 release, as [docs/releasing.md](docs/releasing.md) says.
3. Issue #6: the sandbox check on a real Linux machine with Landlock ABI 2 or newer (kernel 5.19
   or newer), and the RHEL 8 run on the HPC nodes.
4. Then on GitHub: rulesets on `main`, `develop` and `v*` tags, private vulnerability reporting.
5. Refusals that need a change in behaviour, not a message:
   - T4: under launch, the fast hook answers a file-tool write to a file that runs later with
     one line, before the kernel's bare EPERM;
   - T6: in Linux's inner mode, merge a user's `--settings` whose `sandbox` keys only tighten,
     instead of refusing it (a guard: review first);
   - T19: doctor tells when the config changed since the broker started. The broker's status
     file holds no config fingerprint yet, so the broker must record one first.

## Waiting on the maintainer

- The go-ahead for each publishing step, and a real Linux machine with a new enough kernel for
  #6.
