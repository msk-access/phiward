# phiward: the Claude Code entry

> The shared rules are in `AGENTS.md`, which every agent tool reads. This file imports it, so
> Claude Code reads the same rules, then the working principles. Claude-only notes are below.

@AGENTS.md

@.agents/rules/working-principles.md

## Claude Code only

- Skills for work on phiward's own code: `.claude/skills/` (`qa-check`, `review-round`).
- `.claude/settings.json` only denies some git commands (the usual forms of a push to `main`, a
  push of all tags, `git tag -a/-s/-d`). It is a tripwire, not a boundary: the control is on
  GitHub (rulesets on `main` and on `v*` tags).
- On a machine where phiward is installed, a session cannot write `.claude/settings.json`, and is
  asked before it writes a skill: prepare the change and let the maintainer apply it.
- Subagents: choose the model by the task (Fable or Opus for adversarial reviews and design,
  Sonnet for routine edits, Haiku for mechanical scans) and say which.
- Brief a reviewer by the invariants to check, as in `.agents/rules/review-rounds.md`.
