# Decisions

What the maintainer decided, and ideas that were turned down. Read before you propose a change in
one of these areas; propose a turned-down idea again only with a new reason. One entry per
decision, newest at the top of its section. Public text: no names, hosts or paths of anyone.

## Decided

- **`phiward run --table` reads CSV/TSV by column.** Cells under an identifier header (a
  built-in glob list plus `[sanitize] id_columns`, user config only, additive) are masked whole;
  plain numbers pass only in parsed cells of other columns; every other line is text mode.
  `[sanitize] table = true` still gates it and stays off by default. The git hook and
  `phiward sanitize --table` keep the per-line meaning. (Why: the column, not the shape, tells an
  identifier from a measurement. Cost: a forged header or an unmatched column still passes
  numbers; stated in the threat model.)
- **The built-in ID column list is broad and cannot be shortened** (some numeric columns show
  `<IDCOL>`).
- **One table per output.** The header may only be the first non-empty line, and never looks
  like data (no 3-digit run, no identifier rule match). The first line that is not a row that
  fits (an empty line, another field count, a quote or escape, no plain-number cell, as in a
  second header) ends column mode for the rest of the output. (Why: two rounds of rules for a
  second header leaked; the mechanism was removed. Cost: a first line of data is read as a
  header, stated in the threat model.)
- **When `--table` finds no header, one fixed note says so** (no count).
- **Which CI cells run when.** A pull request runs Python 3.9 and 3.14 on Ubuntu 24.04 and macOS,
  and 3.14 on the newest Ubuntu (5 cells); a push to develop and a release run every version from
  3.9 to 3.14 (13 cells). The short list is chosen only for a `pull_request` event, never by the
  branch or ref. A push to main runs nothing: its tag runs the suite before publishing. (Every
  cell runs the whole suite. The reason is the queue: macOS runners are shared and few, and runs
  waited 11 to 47 minutes for them. What it costs: a bug only on 3.10 to 3.13 is found at the
  merge into develop, not on the pull request.)
- **A program list entry is the file that runs.** Under `[broker] commands`, a bare name runs what
  the broker's `PATH` finds, called by that name alone; a path entry is a real file (no link, no
  `..` on it) and runs as itself; a folder entry runs a name in that folder. A repository's list
  only narrows the user's. (Every earlier rule that matched a path to a name, or kept the name
  given, opened a hole.)
- **What is checked is what starts.** A file is read once; a link is never followed again between a
  check and its use.
- **A session in the home folder is not confined.** Its sandbox may write the places that start
  programs later (`~/.config`, `~/.local/bin`, `~/Library/LaunchAgents`).
- **Copies never replace an existing file** (local copies, pulls, pushes).
- **The agent sees only success or failure** of a gateway command (`exit=0` or `exit=1`); the real
  status and counts go to the broker's log.
- **Protected roots are read only for gateway commands;** they write only in `[broker] write_to`.
- **The network is open by default** in both modes; `[network] limit` narrows the shell's.
- **The standard library only;** no dependency is added, also not for tests (beyond pytest and
  pytest-timeout).
- **Plans stay local** (`.agents/plans/`); findings that are not fixed yet are reported privately.

## Turned down

- **Parsing quoted CSV in `run --table`:** one more parser in a guard; a quoted row is text mode.
  Revisit with a real need.
- **`phiward sanitize --table` by column:** the hook and manual use stay per line.
- **A repo file adding ID columns:** `id_columns` is user config only for now, though it would
  only add masks.
- **Regex header matching:** globs only.
- **Running the tests in parallel (pytest-xdist):** a new test dependency, and timing tests depend
  on running alone.
- **Regrouping the test files by feature:** helpers of the same name differ from file to file, so a
  move can change what a test checks. `tests/README.md` indexes the files instead.
- **A separate quick CI matrix:** CI runs the whole suite on every cell. (A pull request runs
  fewer cells, never fewer tests: see "Which CI cells run when".)
- **A supervisor that kills a gateway command's leftover processes on macOS:** the command can kill
  the supervisor first; the limit is stated in the threat model.
- **Repository roots only inside the repository:** a repo config protects folders next to it
  (`../secret`); the name listing this allows is stated in the threat model.
