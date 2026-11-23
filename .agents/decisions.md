# Decisions

What the maintainer decided, and ideas that were turned down. Read before you propose a change in
one of these areas; propose a turned-down idea again only with a new reason. One entry per
decision, newest at the top of its section. Public text: no names, hosts or paths of anyone.

## Decided

- **The project scan walks the project itself, with no git.** One `os.scandir` walk, following
  no link, covers tracked, untracked and git-ignored files alike (a copied CSV sits in an
  ignored `data/`). (Why no git: `git ls-files` reads the project's `.git/config`
  (`core.fsmonitor`) and `git log -p` runs its diff drivers and textconv; both run code an
  agent may have written, outside any sandbox. Cost: no history and no commit messages; the
  pre-commit hook covers new commits.) It uses subject kinds only (`sanitize.subject_sanitizer`:
  the effective packs, so a repo file can only add refusals, and the user's patterns; no
  dates, positions, numbers, roots, entry names or `names_from`, which a project holds
  everywhere). Launch refuses on a finding (2 s; over it, warn and start); doctor scans with no
  limit and warns, `--headless` fails; in Mode A the SessionStart note warns within 2 s and
  never stops a session. Output: kinds, counts, and masked paths only with `--show-paths`.
  `[sanitize] scan_allow` is user config only, by absolute path (a hash was turned down: test
  fixtures change often). Under a budget the walk lists every name first, then reads the
  instruction files and then the smallest files, 64 KiB each: the rules' regexes are most of
  the cost (about 0.4 us per 40-character line per rule), so a line no rule matches as written
  skips the sanitizer's other steps only when it is plain (ASCII, no control character, `\` or
  `%`), where that skip is exact (a test checks it).
- **The masking check tests the user's own rules by their own examples.** `[sanitize]
  examples` is user config only and holds made-up values; phiward never makes examples from a
  regex (such a value only proves the regex matches itself), and the built-in packs' values live
  in the tests (the self-check covers the installed packs). A value passes only when nothing but
  placeholders is left of it, in text and table mode, and the prompt scan blocks it; a made-up
  path below each root, protected pattern and remote root is cleaned too. The words name
  indexes only. Doctor warns, launch refuses, `--headless` lists it; the broker checks once at
  its start and refuses every request while it fails (a fixed config is a changed config, so
  the restart checks again). Any error is a failure. (Why: a rule edited or weakened still
  loads, and nothing else would notice. Cost: a config that started before may be refused.)
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
  Parquet is never read (convert it first).
  (Why: one shape for every kind, and what is written is what was scanned. Cost: a long
  `--keep` for a MAF; Parquet needs a step.)
- **`phiward pseudonymize` codes Markdown pipe tables.** Only tables and blank lines; every
  other line is free text, refused (decision C). Each line of a table starts and ends with
  `|`, and the second is the alignment row. A line with a backslash or a backtick is refused
  (an escaped pipe or a code span has no safe split), and so is a line with `<`, `[` or `]`
  (no inline HTML, links or images: parsing them as CommonMark does was tried in review and
  removed), a body row of alignment cells only (two tables with no blank line between them),
  and a header with emphasis or an entity (it would dodge the ID-glob rule). Each table goes through the table rules
  (`build`) with the names its header holds; each name is in some table; one draw knows the
  IDs and values of all tables. Only a table with a coded column is shuffled. The scan reads
  each cell raw and in each round of NFKC, `sanitize.unescape` and `html.unescape` (a
  superset of the entities CommonMark decodes), each also with emphasis marks removed; a
  cell still changing after 4 rounds is the one fixed refusal. In every kind, the scan reads
  every Unicode dash (Pd, and U+2212, U+2043, U+02D7, U+30FC) as `-`, and an ID of 5 or
  more characters with a letter is also matched with every character but letters and digits
  removed from it and the field; digit-only IDs are never joined. Two IDs are twins (refused)
  exactly when they share a form the scan reads (`_twin_forms`: each of `_forms`, and the
  letters and digits only of a long one with a letter): one rule, the scan's forms, so two IDs
  that are the same once normalized never get two codes (Arabic-Indic digits, `%2D`,
  `FAKE PT 0001`, `FAKE.PT.0001` were missed before). One ID inside a longer one
  (`FAKE-PT-0001`, `FAKE-PT-00011`) is not a twin. Cost: a key that already holds a twin
  pair cannot code either ID again; start a new key.
  (Why: the same rules as a table, and a cell's rendered or decoded form is what a reader
  sees. Cost: tables with escaped pipes or code spans, and reports with prose, are refused.)
- **`phiward pseudonymize` codes JSON values at key paths.** `--columns`, `--drop` and
  `--keep` take paths (`.` a key, `[]` every element; keys matched exactly). A coded value is
  a string or an integer (a string code); `null` stays; other kinds are refused. Keys that are
  IDs are refused, not coded (decision F): every key passes the sanitizer unchanged and the
  scan. The ID-glob rule applies to scalar paths only (`samples[]`, `samples[].id`; a `[]` at
  the end of a path is dropped for this): a key that holds only objects or arrays needs no
  name (a rule for containers was tried in review and removed). `--drop` takes a container
  whole. A path that matches nothing or meets another kind of value is refused. Only the
  array at the last `[]` of a coded path that goes on to a key is shuffled, and that is
  refused when an array of the same length sits beside it (pairing by position), unless
  `--keep-order`, which stays one switch for the whole run; a coded path ending in `[]` needs
  `--keep-order`. Duplicate keys, `NaN`, `Infinity`, a number out of range, more than 4300
  digits, nesting past 100 and a lone surrogate are the one fixed refusal; any top level is
  taken. The scan also reads a whole number as its integer (`1234.0`). Output:
  `json.dumps(ensure_ascii=False, indent=2)`, read back and compared with the kinds; the run
  prints a fixed line, no count (decision G). `main` turns any unexpected exception into one
  fixed text, and a new key file a failed run made is removed. (Why: the same rules as a
  table, with the path as the header. Cost: keys with `.` or `[` cannot be named.)
- **`phiward pseudonymize` codes a VCF's sample names.** All of them, with no `--columns`,
  `--drop` or `--keep`. A name that is a word (a short stop list), has no digit or is under 3
  characters is refused; `--keep-samples N` keeps one by sample number, out of the key, with
  no name typed (decision J). The `##` lines come from an allow list (`fileformat`, `INFO`,
  `FORMAT`, `FILTER`, `ALT`), each passing the sanitizer unchanged; `contig` keeps its `ID`
  only (decision K). The `#CHROM` line keeps its fixed headers and the codes take the sample
  names' places (decision E). Records keep their order and values; the sample columns are
  shuffled, one permutation for every line. The scan reads each tab field whole and split on
  `; , = | :`, and the draw avoids each of those parts. The stop list is matched on the
  NFKC, case-folded name. Two IDs with one NFKC, case-folded form but other text (in the
  input, or in the input and the key) are refused, in every kind (one rule, in the draw). A
  BGZF input must end with the EOF block. BGZF in gives BGZF out (blocks of 0xff00 bytes, the EOF block), plain gzip
  gives plain gzip, a mix is refused (decision H); 1 GiB in memory, no streaming path
  (decision I). (Why: a word in the key links unrelated subjects; `tabix` needs sorted
  records and BGZF. Cost: provenance in dropped lines; genotypes stay.)
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

- **For the Linux view's entries: a retry, `--ro-bind-fd`, or binding them by descriptor.** bwrap
  (0.9.0) reads a descriptor's name back and mounts that name, also with `--ro-bind-fd`, and
  cannot mount a removed entry by descriptor. A retry hides the race. The entries are bound by
  name with `--ro-bind-try`, and the helper checks the view before the tool runs.
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
