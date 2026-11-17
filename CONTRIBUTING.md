# Contributing to phiward

Thank you for helping. phiward keeps protected health information (PHI) out of what an AI coding
agent sends to its model provider, so every change is held to a few firm rules.

## Set up

```bash
git clone https://github.com/msk-access/phiward
cd phiward
uv run --with pytest --with pytest-timeout python -m pytest --timeout=300
```

You need [uv](https://docs.astral.sh/uv/) and macOS or Linux (with bubblewrap for the confinement
tests on Linux). [tests/README.md](tests/README.md) says how to run parts of the suite.
[docs/developer.md](docs/developer.md) says how to run phiward from a checkout without touching
your own setup, and how a decision is made.

## Rules

- **Made-up data only.** Never use real patient data, real configs or real credentials, also not
  to show a bug. Use names such as `FAKE-PT-0001`.
- **The standard library only;** the code runs on Python 3.9 and later.
- **A fix to a guard starts with a test that fails** (red), then the fix.
- **Do not change what an existing test expects** without saying in the pull request what it
  asserted and why that is now wrong.
- **Docs change with the code**, in plain, short English.

[AGENTS.md](AGENTS.md) has the full list; it is also what AI coding agents read in this
repository.

## A pull request

- Open it against `main`. CI runs the whole suite on Linux and macOS, Python 3.9 to 3.14, so you do
  not need every system yourself.
- Some checks need a maintainer's machine (the Linux suites in Docker, the quickstart check, the
  install check on macOS); a maintainer runs them before a release.
- A change to `AGENTS.md`, `CLAUDE.md`, `.agents/` or `.claude/` changes what every agent here is
  told: say why in the pull request. A maintainer reviews these files first.

## Reporting a vulnerability

Not in an issue: see [SECURITY.md](SECURITY.md).

## Licence

phiward is licensed under the GNU Affero General Public License, version 3 only
([LICENSE](LICENSE)). By contributing, you agree that your contribution is licensed under it too.
