# Where the work stands

Updated at each milestone, not each session. Details are in the pull requests and issues.

## Goal

v0.2.0b2, the second beta (v0.2.0b1 is on PyPI since 2026-11-18).

## Just finished

- Issues #2 to #5 for 0.2.0b2, and `phiward pseudonymize` (#1 was declined as asked; the
  command is the operator's own) for CSV/TSV, text, MAF, VCF, JSON and Markdown, each also
  gzip-compressed (PRs 23 to 27).
- Code hygiene after that work (PRs 28 to 35): the docs, the tests and the Linux skip list, the
  renames, a stderr thread fix in `phiward copy`, folded duplicate rules, one gzip read-back,
  the duplicate-ID rule that matches the scan, and a ruff config in `pyproject.toml`.

## Next

1. The launch races that make CI flaky: an entry under `/var/tmp`, or a descriptor, vanishes
   between the listing and bubblewrap's mount. Launch refuses (fail-closed); the fix removes the
   race.
2. Issue #6: the sandbox check on a Linux machine with Landlock ABI 2 or newer (kernel 5.19 or
   newer), and the RHEL 8 run on the HPC nodes.
3. The 0.2.0b2 release, as [docs/releasing.md](docs/releasing.md) says.
4. Then on GitHub: rulesets on `main`, `develop` and `v*` tags, private vulnerability reporting.
5. Refusals left by the refusals PR (c), each a change in behaviour, not a message:
   - T4: under launch, the fast hook answers a file-tool write to a file that runs later with
     one line, before the kernel's bare EPERM;
   - T6: in Linux's inner mode, merge a user's `--settings` whose `sandbox` keys only tighten,
     instead of refusing it (a guard: review first);
   - T19: doctor tells when the config changed since the broker started. The broker's status
     file holds no config fingerprint yet, so the broker must record one first.

## Waiting on the maintainer

- The go-ahead for each publishing step, and a Linux machine with a new enough kernel for #6.
