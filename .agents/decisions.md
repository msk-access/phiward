# Decisions

What the maintainer decided, and ideas that were turned down. Read before you propose a change in
one of these areas; propose a turned-down idea again only with a new reason. One entry per
decision, newest at the top of its section. Public text: no names, hosts or paths of anyone.

## Decided

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

- **Running the tests in parallel (pytest-xdist):** a new test dependency, and timing tests depend
  on running alone.
- **Regrouping the test files by feature:** helpers of the same name differ from file to file, so a
  move can change what a test checks. `tests/README.md` indexes the files instead.
- **A separate quick CI matrix:** CI runs the whole suite on every cell.
- **A supervisor that kills a gateway command's leftover processes on macOS:** the command can kill
  the supervisor first; the limit is stated in the threat model.
- **Repository roots only inside the repository:** a repo config protects folders next to it
  (`../secret`); the name listing this allows is stated in the threat model.
