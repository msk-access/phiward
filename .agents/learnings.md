# Learnings

What went wrong, its one cause, and the file changed so that it cannot happen again. Newest at the
top. Causes: **rule** (a rule or skill said the wrong thing), **trigger** (the right rule did not
apply, or the wrong one did), **design** (the code's mechanism was the cause), **environment** (a
fault outside this repository: nothing here changes).

- **Linux launches failed about one CI run in three** (`bwrap: Can't find source path
  /proc/self/fd/N`, `Can't get type of source ...`) when systemd removed a folder in `/var/tmp`.
  Cause: design (the view bound each entry by descriptor, taking the descriptor to fix the file;
  bwrap reads the name back from it and mounts that name, and cannot mount a removed one).
  Fixed in: `src/phiward/wholetool.py` (the view's entries by name with `--ro-bind-try`, and the
  helper checks inside the session that each bind is what was checked).
- **The scan's forms of a cell were fixed round after round**: Unicode dashes, escapes after
  NFKC, separators, digits, each in its own place and each found by a later review. Cause: design
  (each form was added to the code that first missed it, not to the one function that lists the
  forms). Fixed in: this entry; the forms are in `_forms` (and `_md_readings`) of
  `src/phiward/pseudonymize.py`: a new form goes there, in that one function, with its test.
- **The sandbox check counted a refusal only when its text said "not permitted".** Linux's
  sandboxes refuse otherwise: a hidden file (no such file, or an empty view) and a read-only bind
  (EROFS). Cause: design (the probe matched Seatbelt's EPERM text). Fixed in:
  `scripts/sandbox-check/probes.sh` (reason classes; a read compares a hash) and `judge.py`
  (the classes that pass, per platform: EPERM only on macOS).
- **A token prompt under util-linux `su -c` has no controlling terminal**, so `stty -g <
  /dev/tty` fails under `set -e`. Cause: environment. Fixed in: `scripts/sandbox-check/linux.sh`
  (`docker run --user tester`, no `su`).
- **OpenSSH finds `~` from passwd, not from `$HOME`**: a plain `ssh` in a check's scratch home
  would still use the operator's real keys and ticket. Cause: environment. Fixed in:
  `scripts/sandbox-check/check.sh` (an ssh config of its own: no identity, no GSSAPI,
  BatchMode, `ControlMaster no`; it never reads `~/.ssh/config`).
- **A test's git experiment set off the maintainer's antivirus monitor.** Cause: rule (experiments
  that plant git commands ran on a maintainer's machine). Fixed in: `.agents/rules/review-rounds.md` (such
  experiments run in a Linux container).
- **A reviewer brief was turned away as off-limits.** Cause: rule (the brief asked to "find
  bypasses" instead of saying what correct means). Fixed in: `.agents/rules/review-rounds.md` (brief by the invariants to check).
- **A new path check turned refusals into allows.** Cause: design (the check changed what kind of
  action a tool was). Fixed in: `adapters/claude.py` (path fields are an extra check of the action)
  and `.agents/rules/review-rounds.md` (a new check only adds refusals).
- **The program-list rules needed a fix in five review rounds in a row.** Cause: design (the code
  matched a path to a listed name, and read a link again between the check and the start). Fixed
  in: `run.py` (the listed entry is the file that runs) and `.agents/decisions.md`.
