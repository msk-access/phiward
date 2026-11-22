# Working on phiward

phiward keeps protected health information (PHI) and other protected data out of what an AI
coding agent sends to its model provider. This file is for agents (and people) that change
phiward's own code. Every line here is read on every turn: depth lives in the linked files.

Not this file: `src/phiward/data/agents-section.md` is what `phiward init` adds to users'
projects (do not run `phiward init` in this repository); `skills/phiward/` and `plugin/` are what
users install. The skills for work on phiward's own code are in `.claude/skills/`.

## Rules that do not bend

- Never read real data, real configs or real credentials, also not to test a fix. Tests use
  made-up trees and names only (`FAKE-PT-0001`; see `tests/conftest.py`).
- Use the Python standard library only; add no dependencies. The code runs on Python 3.9+.
- Keep the guards fail-closed: when a check cannot decide, it refuses.
- For a fix to a guard, write the test first and see it fail (red). Then fix the code at the
  source: remove a mechanism before you add a check.
- Never change what an existing test expects without saying, in the change, what it asserted,
  why that is now wrong, and what replaces it.
- Keep the docs, the help text and the code in agreement, in the same change.

## How a change is made

A plan, a review of the plan, red tests, the fix, the checks (the `qa-check` skill), then a fresh
review of the diff: [.agents/rules/review-rounds.md](.agents/rules/review-rounds.md), which also
says how a reviewer is briefed. How the code is laid out:
[.agents/rules/architecture.md](.agents/rules/architecture.md). How to work (think first,
simplicity, surgical changes, verifiable goals):
[.agents/rules/working-principles.md](.agents/rules/working-principles.md).

## Tests and checks

- Run the suite from the repository root as [tests/README.md](tests/README.md) says:
  `uv run --with pytest --with pytest-timeout python -m pytest --timeout=300
  --basetemp=/tmp/phiward-pt`.
- On Linux, the confinement tests need bubblewrap (`bwrap`); CI sets
  `PHIWARD_REQUIRE_CONFINE=1`, so there a missing backend fails the run.
- Experiments that plant git commands, hooks or other files that run later belong in a Linux
  container, never on a maintainer's own machine.

## Docs

- Plain, short English: short sentences, one idea in each, the active voice.
- Releases: [docs/releasing.md](docs/releasing.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

## Git and safety

- Work on a branch and open a pull request to `main`. Never push, tag or publish without the
  maintainer's yes, and never skip the git hooks (`--no-verify`).
- A change to this file, `CLAUDE.md`, `.agents/` or `.claude/` is an instruction to every
  agent that works here: read such a diff on GitHub before you open a session on that branch.
- A vulnerability in phiward is reported privately ([SECURITY.md](SECURITY.md)), never in an
  issue, a commit message or a tracked file, until it is fixed.

## Memory

- Decided behaviour, and ideas that were turned down (do not propose them again without a new
  reason): [.agents/decisions.md](.agents/decisions.md).
- What went wrong and where it was fixed: [.agents/learnings.md](.agents/learnings.md).
- Where the work stands: [CONTINUITY.md](CONTINUITY.md). Plans stay local (`.agents/plans/`).
