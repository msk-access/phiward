---
description: How to work with protected data and HPC through phiward in this session
---

Explain to the user, briefly and in plain words, how this session works with protected data
under phiward. Use what follows; do not read protected folders or credentials to find out more.

- Protected folders and credentials cannot be read directly: the guards refuse it, and a refusal
  is a decision, not a fault.
- Protected data is worked on only through phiward's gateway, which is the intended route:
  `phiward run -- CMD [ARG]...` runs a command and masks its output (names, paths and
  identifiers become placeholders); `phiward copy SRC... DST` copies without printing names.
- Scripts run through the gateway must print counts and summaries, never records: masking
  hides names and identifiers, not other content.
- HPC: never ssh directly. `phiward run --remote HOST -- CMD` runs an approved program on an
  approved host through the user's shared SSH connection; `phiward copy` moves files to and from
  approved folders.
- If a gateway call says no broker is running, the user starts it (`phiward broker`, or its
  login service). If something needs a grant (a write place, the network), the user adds it to
  their own config.

Then offer to run `/phiward:doctor` to check the setup.
