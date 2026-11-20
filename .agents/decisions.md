# Decisions

What the maintainer decided, and ideas that were turned down. Read before you propose a change in
one of these areas; propose a turned-down idea again only with a new reason. One entry per
decision, newest at the top of its section. Public text: no names, hosts or paths of anyone.

## Decided

- **`phiward pseudonymize` is the operator's own command.** It joins `gateway.OPERATOR_ONLY` and
  refuses without a tty on stdin and stdout; the boundary is the key folder,
  `~/.phiward/backups/keys`, below a folder hidden in all three modes and made at install (it
  refuses until then). Codes are `S` and 4 digits drawn with `secrets` from the unused ones; a
  key is only appended to. The output is a new file only inside a user protected root, rows
  shuffled by default (`--keep-order`); every ID-glob column is coded, dropped or kept by name;
  messages give the row count only. One key per ID kind. (Why: the agent can read the
  operator's terminal, gateway commands read roots, and counts of new IDs confirm planted
  guesses. Cost: refused before install; masked reads only.)
- **`phiward pseudonymize` reads more kinds by the extension chain.** `.tsv`, `.csv`, `.txt`
  (a TSV of 2 or more columns: free text is refused) and `.maf`, each also `.gz`; the content
  must fit the chain, and OUT has the same one. gzip is read in chunks up to 1 GiB expanded
  and written with `gzip.compress(mtime=0)` (no input header field), checked by reading it
  back. A MAF keeps only a `#version` line with a number and its coded headers; the operator names
  the barcode columns and keeps the other ID-glob columns by name. One scan of the whole
  output (codes, headers and the kept line included) replaces the scan of kept cells; the draw
  skips a code it would flag. Any exception in reading or writing is one fixed refusal.
  Parquet is never read (convert it first); bgzip, VCF, JSON and Markdown come in later steps.
  (Why: one shape for every kind, and what is written is what was scanned. Cost: a long
  `--keep` for a MAF; Parquet needs a step.)
- **`phiward run --table` reads CSV/TSV by column.** Cells under an identifier header (a
  built-in glob list plus `[sanitize] id_columns`, user config only, additive) are masked whole;
  plain numbers pass only in parsed cells of other columns; every other line is text mode.
  `[sanitize] table = true` still gates it and stays off by default. The git hook and
  `phiward sanitize --table` keep the per-line meaning. (Why: the column, not the shape, tells an
  identifier from a measurement. Cost: a forged header or an unmatched column still passes
  numbers; stated in the threat model.)
- **The built-in ID column list is broad and cannot be shortened** (some numeric columns show
  `<IDCOL>`).
- **One table per output.** The header may only be the first non-empty line, never looks like
  data (no 3-digit run, no identifier rule match), and names an identifier column (else the
  output is text: a table without one keeps no numbers; prose with commas is not a header). The first line that is not a row that
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
- **Linux: a launch knows it is inside a session by a seccomp fingerprint.** The tool's filter
  answers syscall 360 (unassigned on x86_64 and aarch64) with errno 3917; only that exact errno
  counts, and the launch then runs its command directly, as on macOS. Any process may install such a filter on itself and its children, so the fingerprint is not a secret: forging it needs code running in the launcher or one of its ancestors, and such code could skip `launch` anyway.
  Any launch inside a session, also for another project, runs under the outer profile (that
  project's repo config is not applied), as on macOS.

## Turned down

- **A pseudonymized table outside the protected roots after a check that nothing would be
  masked:** false assurance; the check does not see names in free text, zip codes, ages or rare
  diagnoses.
- **The pseudonymize key in a protected root, or in a new hidden folder:** gateway commands read
  roots (a key line no rule matches comes back whole), and a hidden path made after a profile was
  built is not hidden from it.
- **Parquet in `phiward pseudonymize`** (an optional `pyarrow`, or a reader by hand): a large
  native library in the process that holds the key folder, or thousands of lines over
  untrusted bytes. The operator converts it to TSV.
- **Free text in `phiward pseudonymize`** (`.txt` prose, replacing the key's IDs as tokens):
  the scan finds only IDs phiward knows, so a name or another subject's ID would stay beside
  the codes.
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
- **Generic /proc signals for "inside a session" on Linux** (`NoNewPrivs`, `Seccomp: 2`, a user
  or PID namespace): Docker, systemd and Claude Code's own sandbox show them too, so a launch
  there would skip its own profile. The seccomp fingerprint is used instead.
- **Falling back to a private run folder when `~/.phiward` cannot be written:** that also happens
  outside a session (read-only or root-squashed home folders), where the server's caches would
  go to a folder the agent can write. Refuse instead.
- **Repository roots only inside the repository:** a repo config protects folders next to it
  (`../secret`); the name listing this allows is stated in the threat model.
