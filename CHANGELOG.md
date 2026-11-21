# Changelog

All notable changes to phiward. Dates are UTC. Versions follow semantic versioning; until
1.0, a minor version may change behaviour.

## [0.2.0b2] - unreleased

### Added

- `phiward pseudonymize` (the operator's, in a terminal) makes a copy of one CSV/TSV table with
  the identifier columns you name coded (`S0042`: drawn at random, the same code for the same ID
  in every table of one key). The key stays in `~/.phiward/backups/keys`, hidden from every
  session, launch and gateway command; the copy is a new file inside a protected root, its rows
  shuffled by default. Every column that looks like an identifier must be coded, dropped or
  kept by name. The hook refuses it as an agent command, and its messages give the row count
  only (issue #1). It reads `.tsv`, `.csv`, `.txt` (a TSV of 2 or more columns) and MAF
  (`.maf`: only a `#version` line with a number is kept, the coded barcode columns keep their
  headers), each also gzip-compressed (`.tsv.gz`, read up to 1 GiB expanded; the copy is gzip
  with no name or time, checked by reading it back). The extensions decide the kind and the
  content must fit them; OUT has the same extensions. No field of the copy, codes, headers and
  the kept line included, may hold an ID of the run or the key, also in another Unicode form
  or escaped. VCF (`.vcf`, `.vcf.gz`): the sample names are coded, with no `--columns`; only
  the `fileformat`, `INFO`, `FORMAT`, `FILTER`, `ALT` and `contig` (its ID only) `##` lines
  are kept; a sample name that is a word (`TUMOR`), has no digit or is under 3 characters is
  refused unless kept by number with `--keep-samples N`; the records keep their order and the
  sample columns are shuffled. A bgzip (BGZF) input, which must end with its EOF block, gives
  a BGZF copy that `tabix` indexes. Two IDs that are the same once normalized (another letter case,
  Unicode form, dash, digits or escape, or for an ID with a letter other separators) are
  refused, in every kind. JSON (`.json`, `.json.gz`): `--columns` takes key paths
  (`samples[].id`, `patient.mrn`); a string or an integer there gets a code, `null` stays;
  every key that looks like an identifier and holds values is named by its path; a key
  twice, `NaN`, `Infinity`, a lone surrogate and deep nesting are refused; the array of
  objects at the last `[]` of a coded path is shuffled (refused beside an array of the same
  length, unless `--keep-order`), and a path ending in `[]` needs `--keep-order`. Any
  unexpected error of a run is one fixed refusal, and a new key the failed run made is
  removed. Markdown (`.md`, `.md.gz`): only pipe tables and blank lines (any other line is
  free text, refused); a line with a backslash, a backtick, `<`, `[` or `]`, a second
  alignment row in a table and a header with emphasis or an entity are refused; each table
  follows the table rules with the names its header holds, one code per ID across tables; the
  rows of a coded table are shuffled; the scan also reads each cell with its HTML entities
  decoded and its emphasis removed. In every kind, the scan reads Unicode
  dashes as `-`, and an ID with a letter is also found with its separators removed
  (`FAKE PT 0001`); the twin rule uses the scan's own forms. Parquet is not read (convert it
  to TSV first).
- `phiward run` (and `run --remote`) ends with a note that counts the placeholders in the
  lines shown and the lines the sanitizer withheld. From 20 shown lines with no identifier
  placeholder, it says so (issue #5). The broker log gets the same counts. Copies get no note.
- `phiward setup` asks, in every profile, which rules mask subject and sample identifiers:
  none (recorded as `[sanitize] subjects = "none"`, never the default), the `msk` example pack,
  or your own patterns. `phiward doctor` warns while the user config has none of these;
  `doctor --headless` prints a NOTE and stays ready (issue #3). A script that looks for WARNING
  in doctor's output sees this one until it is answered.
- `phiward run --table` reads CSV/TSV output by column (issue #2): a cell under an identifier
  header (a built-in list, plus `[sanitize] id_columns` in the user config) is masked whole as
  `<IDCOL>`, whatever its shape; a plain number passes only in a parsed cell of another column.
  One table per output, its header the first line, which must name an identifier column (else
  the whole output is text: a table without one keeps no numbers); from the first line that is
  not a row of it, the rest is masked as text. `phiward sanitize --table` and the git hooks keep the
  per-line meaning.

- The release check with the real Claude Code (`scripts/sandbox-check`) runs on Linux too:
  `check.sh` on a real machine (`SBX_BASE`), or `linux.sh` in a container with Claude Code
  pinned by a lock file. One session per mode (`MODES`, A and B), new probes (the Read tool,
  `phiward run` from the session, the git hook, the parents' environment, doctor before and
  after, and with `REMOTE` push, run and pull through the shared connection), reason classes
  per platform, a facts file, and a verdict per mode. The token is replaced by `<TOKEN>` in
  every kept file. `--stub` checks the plumbing with a stand-in claude (issue #6).
- A command reference: [docs/cli.md](docs/cli.md). A test fails when it and a command's help
  disagree.

### Fixed

- `--help` after a subcommand prints the help and changes nothing (`carryover status --help`,
  `install claude --help`, `git-hook install --help`); before, it printed the usage as an error
  or refused without a terminal. Every command's help lists its options.
- Linux: `phiward launch` no longer fails to start (`bwrap: Can't get type of source ...`,
  `Can't find source path /proc/self/fd/N`) when the host removes an entry of a rebuilt folder
  while the session starts (systemd's private folders in `/var/tmp`, on GitHub's runners). The
  entry is left out of the view. A short window stays: an entry removed between bubblewrap's own
  check and its mount still stops the start (`Can't bind mount ...`). The session's view is now
  checked against what was checked before the tool starts; an entry the host replaces while the
  session starts stops the start (nothing runs; start again).
- Linux: a wrapped MCP server inside `phiward launch` (Mode B) now starts. Its own launch used
  to wrap itself again and fail on the read-only `~/.phiward`. The session's seccomp filter now
  answers one unused system call (360) with an error number nothing else returns (3917); a
  launch that sees exactly that runs its command directly, as on macOS. Anything else builds
  the full profile, and refuses where `~/.phiward` cannot be written. The sandbox check's stub
  run expects `PASS Mode B` on Linux.
- `date` is a placeholder word: a names file with a path part `date` no longer turns the dates
  pack's `<DATE>` into `<<NAME>>`.
- On Linux with an older C library (RHEL 8), carry-over no longer crashes when it gives a
  session's folder back its owner bits (a refused `phiward launch` ended with a traceback).
- Two tests of the output cap restart the broker after changing the config, so they test the
  cap; before, every run in them was refused and their bounds held trivially.
- Linux: before a `phiward run` or `phiward copy` command starts, the gateway confirms that each
  folder and file it binds (the write places, a `.claude` folder in one, the ssh config, the
  shared connection's socket) is, inside, the same file it found at that name before the start
  (a link not followed), mounted at that name. Anything it cannot confirm, an error included,
  stops the request (nothing runs). Some settings that ran before now stop the request: a
  hidden path at or above a write place or at its `.claude` (before, the command ran with it
  masked or without writes there), and a bind listed twice.

### Changed

- `phiward run --table` is stricter: output without a header line (or with a line before the
  header, a warning on stderr too) is now masked as text, with a note that says so; before, every
  number in it was kept.

- A push (`phiward copy` to a remote) goes only under `[remote] roots`, where remote output is
  masked; with no remote root, every push is refused (issue #4). `phiward setup` makes each copy
  remote's folder a remote root, and `phiward doctor` warns about a copy remote without one.
- The `genomics` pack's number rule masks a run of 5 or more digits next to a comma too
  (`1234567,7654321` becomes `<NUM>,<NUM>`), as the docs say; only a decimal such as
  `12345.678` keeps its digits.
- `phiward copy` makes each local path absolute once, and every check and the copy itself use
  that path. A local path with a `..` part, or one that starts with `~` (quoted), or an empty
  one, is refused: give the full path.
- Identifier rules (packs and `[sanitize] patterns`) match in any letter case, and the `msk`
  pack's rules also match an ID right after `_`. Where a file or identifier rule matches the text
  around a name under a root, the name reads as that rule's placeholder, as a name that does not
  exist would; nothing is masked less than before. Some ordinary words now match the `msk` rules (`c-string`, `donor-derived`); the git
  hook refuses them as identifiers.
- Entry names now match across dashes, digits and separators. The sanitizer reads every dash
  (U+2010, U+2013, U+2212, ...) as `-`, in lines and names alike, and prints the masked line in
  that form; pack rules written with `-` match those spellings too. Other decimal digits
  (Arabic-Indic `٠١`, ...) are matched as ASCII digits, by entry names and by pack rules, and
  printed as written (Python 3.9 knows fewer of them than later versions). A name of 5 or more
  letters and digits, with a letter, is also masked with its separators (`-`, `_`, `.`, a
  space) changed or left out: `FAKE-PT-0001` masks `FAKE_PT_0001`, `FAKE PT 0001` and
  `FAKEPT0001`. Shorter names, digits-only names and names with a separator at either end are
  matched as written only; a name whose stem is matched that way (`FAKE-PT-0001.bam`) is
  matched whole as written only, so its extension stays for the file rules. The masks the
  sanitizer made before are all kept; the hits in other spellings, and each rule's own matches
  on the line, are added to them, so a line is never masked less than before. Overlapping masks
  become one placeholder: a mask made as before that covers them all keeps its placeholder,
  else a rule's match that covers them all, else `<PROTECTED>`, then `<ENTRY>`, then the
  placeholder of the first. Every mask takes the whole of a number it starts or ends inside
  (`C-PLE12345`, `Donor-1,234,567`, `SAM_PLE12:00`). The `msk` CMO rule takes
  the whole run (`C-\w{6,}`), and the `genomics` read-name rule takes a first field with dots
  anywhere and no longer swallows the start of the next read name. A root whose name holds
  another dash also matches a path written with `-`, so the hook and the git hooks refuse that
  spelling too. Generic names under a root (`sample_01`) now also mask text such as
  `sample 01`.

## [0.2.0b1] - 2026-11-18 (beta)

The first public release. phiward keeps protected data (for example patient data) out of what
an AI coding agent sends to its model provider. Read
[docs/threat-model.md](docs/threat-model.md) before you rely on it, and
[docs/release-notes/v0.2.0b1.md](docs/release-notes/v0.2.0b1.md) for what is tested.

### Added
- **Mode A**, a Claude Code session wired by `phiward install claude --user --write`: a hook
  on every tool, Claude Code's sandbox settings and permission rules for the protected roots
  and patterns, credentials and histories (the hidden list), and the files that run later
  (settings, skills, hooks, git's control files, editor settings).
- **Mode B**, `phiward launch`: the whole agent tool in a kernel profile (macOS Seatbelt,
  Linux bubblewrap), with stateless carry-over and quarantine (`phiward carryover`).
- **The gateway**: `phiward run -- CMD` and `phiward copy` run through a broker outside the
  agent, in a kernel profile, and print masked output (protected paths, entry names,
  identifiers). `[broker] commands` limits the programs; grants for write places and the
  network come from the user config only.
- **MCP servers**: `phiward mcp list|wrap|unwrap` runs a local server in the kernel profile; the
  hook trusts a wrapped server only while it runs so, with the profile the hook would build.
- **HPC** through your own shared SSH connection: `phiward run --remote HOST -- CMD`, and
  copies to and from approved remotes.
- **Setup and checks**: `phiward setup` (profiles, a results folder, a program list, the login
  service), `phiward init` for a project, `phiward doctor` (also `--headless` for unattended
  agents), the Claude Code plugin (`/phiward:setup`) and a start-of-session note.
- **Sanitizer packs** (`genomics`, `dates`, and an example institution pack) and your own
  names files and patterns.

### Upgrading from agent-guards (a private pre-release)
Uninstall agent-guards, install phiward, move `~/.config/agent-guards` to
`~/.config/phiward` (and a repo's `.agent-guards.toml` to `.phiward.toml`), then run
`phiward setup` (choice 1), `phiward mcp list` and `phiward doctor`. The `agent-guards` command
stays as an alias during the beta.

### Limits
What phiward does not protect, and every known gap, is in
[docs/threat-model.md](docs/threat-model.md).
- Out of the box, masking inside file contents covers only sequence and alignment file names,
  read names and loci (the `genomics` pack). Subject and sample identifiers inside files are
  masked only with a pack that has them (the `msk` example), your own `[sanitize] patterns` or
  `names_from`. The gateway masks entry names under the protected roots (4 characters or
  longer). Planned for 0.2.0b2: setup asks, doctor warns, and the output says what was masked
  ([#3](https://github.com/msk-access/phiward/issues/3),
  [#5](https://github.com/msk-access/phiward/issues/5)).
