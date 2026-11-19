# Decisions

What the maintainer decided, and ideas that were turned down. Read before you propose a change in
one of these areas; propose a turned-down idea again only with a new reason. One entry per
decision, newest at the top of its section. Public text: no names, hosts or paths of anyone.

## Decided

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
- **Linux: a launch knows it is inside a session by a seccomp fingerprint.** The tool's filter
  answers syscall 360 (unassigned on x86_64 and aarch64) with errno 3917; only that exact errno
  counts, and the launch then runs its command directly, as on macOS. A filter is set by the
  kernel, inherited and never removed, so only an ancestor can make it.

## Turned down

- **Running the tests in parallel (pytest-xdist):** a new test dependency, and timing tests depend
  on running alone.
- **Regrouping the test files by feature:** helpers of the same name differ from file to file, so a
  move can change what a test checks. `tests/README.md` indexes the files instead.
- **A separate quick CI matrix:** CI runs the whole suite on every cell. (A pull request runs
  fewer cells, never fewer tests: see "Which CI cells run when".)
- **A supervisor that kills a gateway command's leftover processes on macOS:** the command can kill
  the supervisor first; the limit is stated in the threat model.
- **Generic /proc signals for "inside a session" on Linux** (`NoNewPrivs`, `Seccomp: 2`, a user
  or PID namespace): Docker, systemd and Claude Code's own sandbox show them too, so a launch
  there would skip its own profile. The seccomp fingerprint is used instead.
- **Falling back to a private run folder when `~/.phiward` cannot be written:** that also happens
  outside a session (read-only or root-squashed home folders), where the server's caches would
  go to a folder the agent can write. Refuse instead.
- **Repository roots only inside the repository:** a repo config protects folders next to it
  (`../secret`); the name listing this allows is stated in the threat model.
