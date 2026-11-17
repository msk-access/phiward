---
name: review-round
description: "For work on phiward's own code: run a review round (plan, review of the plan, red tests, fix, checks, fresh review) and brief a reviewer by the invariants to check, with made-up data and experiments in a Linux container."
---

# review-round

The round and the rules of work are in
[.agents/rules/review-rounds.md](../../../.agents/rules/review-rounds.md): read it first.

## A reviewer's brief, in this order

1. **What phiward is:** it keeps protected health information (PHI) out of what an AI coding
   agent sends to its model provider. The files to read first: `README.md`,
   `docs/threat-model.md`, and the area's docs.
2. **Scope:** the commit range (`git diff A..B`), the files, the earlier findings it answers.
3. **The invariants**, numbered, each in one sentence. Ask: for each, does it hold; if not, a test
   that shows it, and the smallest change at the source.
4. **Ordinary use that must keep working** (the documented examples).
5. **Rules of work:** copy the list "Rules of work for every reviewer and every experiment"
   from `.agents/rules/review-rounds.md` into the brief, whole.
6. **Output:** a review file (per invariant: holds or not, file:line, the test, its result, the
   fix), a test file, and a short summary that says plainly whether the invariants hold.

## After it

- Turn each repro test into a regression test that asserts the fixed behaviour.
- Remove the reviewer's scratch copies and anything it planted.
