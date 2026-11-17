# Learnings

What went wrong, its one cause, and the file changed so that it cannot happen again. Newest at the
top. Causes: **rule** (a rule or skill said the wrong thing), **trigger** (the right rule did not
apply, or the wrong one did), **design** (the code's mechanism was the cause), **environment** (a
fault outside this repository: nothing here changes).

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
