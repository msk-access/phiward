# Review rounds

How a change to a guard is planned, checked and reviewed. A review round finds what the author
did not see; it is not a formality.

## The round

1. **Plan.** What changes, at the source, and how it is checked. Prefer removing a mechanism to
   adding a check.
2. **Review the plan** (a fresh reviewer, adversarial). Revise the plan before any code.
3. **Red tests, then the fix.** Each test fails before the fix and passes after it.
4. **All checks** (the `qa-check` skill). Read every exit code.
5. **A fresh review of the diff.** Fix what it finds, at the source. A fix that opens a new hole
   twice in a row is a sign to remove the mechanism, not to patch it again.
6. **Report:** what changed, what was checked and how, what is left, and every existing test whose
   expectation changed (what it asserted, why that is now wrong).

A new check may only add refusals: it never changes what kind of action a tool is, and never
turns a refusal into an ask.

## Briefing a reviewer

A brief is the reviewer's only context. It states:
- the scope (a commit range, the files, the earlier findings it answers);
- the invariants to check, each one plainly ("the file that starts is the file the operator
  approved"), and asks for a test per invariant that does not hold;
- the rules of work below.

Brief by the invariants to check, not by "find a bypass": the reviewer does the same work, and the
brief says what correct means.

## Rules of work for every reviewer and every experiment

- Made-up data only (`FAKE-PT-0001`). Never read real data, real configs, `~/.claude*`, the
  operator's `~/.phiward` or any credential.
- Work on a copy (`git clone` or `cp -R`), never in the repository; never `git worktree add` on it.
- A scratch `HOME` for anything that runs phiward. Never run `setup`, `broker --service`, `pin`,
  `carryover` or `install` against the real home folder, and never start a login service.
- Never run the real `claude`; use a stub on `PATH`. Of the sandbox check, run only
  `sh scripts/sandbox-check/linux.sh --stub` (in its container); the operator runs the rest.
- Experiments that plant git commands or hooks, or files that run later, run inside a Linux
  container (`--network none`), not on the maintainer's machine, where they look like an attack
  to the machine's own monitoring.
- Kill only processes you started. Remove what you planted when you are done.

## After the round

- A reviewer's repro tests become regression tests: keep the scenario, assert the fixed
  behaviour, put them in the suite.
- A finding that is not fixed is stated in docs/threat-model.md, or reported privately
  ([SECURITY.md](../../SECURITY.md)) until it is fixed.
