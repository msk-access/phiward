---
description: Check phiward's setup for this project and explain each warning in plain words
allowed-tools: Bash(phiward doctor)
---

Run `phiward doctor` (the whole command, nothing before or after it) and report its result to
the user in plain words:

1. Say which mode this session is in (Mode A: a Claude Code session wired by phiward; Mode B:
   `phiward launch`) and whether the guards are on.
2. For each `WARNING` or `PROBLEM` line, say what it means and the one command or change that
   fixes it, as the line says. Do not run fixes yourself: `phiward setup`, `phiward install`,
   `phiward pin` and changes to settings files are for the user, in their own terminal.
3. If phiward is not installed or the command is not found, say so and point to the quick start
   (`docs/quickstart.md` in https://github.com/msk-access/phiward).

Do not read protected data or credentials to check anything; doctor reports what is needed.
