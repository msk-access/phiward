# Changelog

All notable changes to phiward. Dates are UTC. Versions follow semantic versioning; until
1.0, a minor version may change behaviour.

## [0.2.0b2] - unreleased

### What changes for you (upgrading from 0.2.0b1)

The release notes have the same steps as a checklist:
[docs/release-notes/v0.2.0b2.md](docs/release-notes/v0.2.0b2.md).

**Do these once, in your own terminal, in this order.**

1. **Install the new version.** Use the install line in
   [docs/quickstart.md](docs/quickstart.md#1-install-phiward), with `--force`.
2. **Restart the broker.** A broker that runs keeps the old code until it restarts. Run
   `(cd ~ && phiward broker --service --write)`; it restarts the login service. Without the
   service, stop `phiward broker` and start it again. `phiward doctor` now warns while the
   running broker's version differs from its own, and `doctor --headless` is not ready.
3. **Re-run `(cd ~ && phiward install claude --user --write)`. It is required.**
   - It adds the prompt check (a `UserPromptSubmit` hook), the setting that turns `@` mentions
     off, and `~/.phiward/profiles` to the hidden list. It rewrites the hooks in the new form.
   - Until you run it, `doctor` warns, and `doctor --headless` is not ready (no prompt check).
   - On macOS, until you run it, the hook refuses every shell command but a gateway call once
     the broker has run: the sandbox does not hide the new `~/.phiward/profiles`.
   - **Hosts you added by hand.** With `[network] limit` on, `install` now sets
     `sandbox.network.allowedDomains` to exactly your `[network] allowed_domains`. It prints
     each host it removes. Move each host you added to the settings by hand into
     `[network] allowed_domains` first, or `git push` and `pip install` to it fail.
   - Run it again after any upgrade that moves phiward's Python. Until then every tool call is
     refused, and `doctor` names the cause.
4. **A project you wired with `phiward install claude --project --write`:** run that command
   again in the project. Its committed hooks have no prompt check, so `doctor --headless`
   reports the project as not ready. Projects set up with `phiward init` only are not affected.
5. **Plugin users:** add the marketplace again with this release's tag, as
   [docs/plugins.md](docs/plugins.md) says. The plugin stays at the tag you added, with that
   release's hooks.
6. Run `phiward doctor` and fix each WARNING. Each one names its step. `doctor` does not
   check the plugin's version: plugin users check step 5 by hand, in `/plugin` in Claude
   Code. The plugin's version must match `phiward --version`.

**Claude Code:** 2.1.295 or newer, as before. 2.1.299 or newer turns `@` mentions off;
`doctor` warns below it.

**Refusals you may meet now.** Each refusal names its fix.

- **A `[remote] roots` entry that is not absolute** (`~/data`, `data`) makes the config
  unusable. Then every guarded action refuses: the hook, the gateway and `launch`. Write the
  remote's absolute path.
- **A push with no `[remote] roots`.** `phiward copy` to a remote now writes only under
  `[remote] roots`; with none, every push is refused. Run `(cd ~ && phiward setup)`, which makes
  each copy remote's folder a remote root, or add each remote's folder to `[remote] roots`.
  `doctor` warns about a copy remote without one.
- **An empty or relative `PATH` entry** (a leading or trailing `:`, `::`, `.`, `bin`) stops
  `launch`, and every MCP server wrapped by `phiward mcp wrap`: such a server then "failed to
  connect". `phiward doctor` names the entry. Remove it from `PATH` (often a trailing `:` in
  your shell startup file).
- **A `[broker] commands` program the broker does not find.** `doctor` now warns about each
  one (setup's `@genomics` lists several, such as `samtools`). Start the broker from a terminal
  where the program works, list it by its full path, or remove the ones you do not use.
- **`launch --tool claude` and the program it runs.** On macOS and Linux it refuses a Claude
  Code older than 2.1.295, a tool that gives no Claude Code version, a shim or wrapper (`npx`,
  `env`, a script), and an npm build without its `package.json`. Run Claude Code's own
  binary, or use `--tool generic`.
- **`launch --tool claude` and your own `--settings`** (Linux below 7.1). launch passes its own
  `--settings`, and Claude Code keeps only one. Yours is dropped when its content is the same as
  the file `install` writes, from this release or the earlier one. Any other `--settings` stops
  the start. If it is phiward's file, run `(cd ~ && phiward install claude --user --write)`.
- **`hook claude` answers `PreToolUse` only.** A `hook claude` entry you wired by hand under
  another event (`PostToolUse`, ...) now exits 2 there, with a refusal that names
  `phiward doctor`. What Claude Code does with exit 2 depends on the event. Remove the entry;
  phiward's hooks go under `PreToolUse` and, for the prompt check, `UserPromptSubmit`.
- **The masking check.** `launch` refuses to start, and the broker refuses every request,
  when a root, a protected pattern, a `[remote] roots` entry or a `[sanitize] examples` value
  does not come out fully masked. Run `phiward doctor`: it names the entry, the rule or the
  root by number.
- **The project scan.** `launch` refuses a project whose files or file names hold subject or
  sample IDs. Run `phiward doctor --show-paths` to see the files. Move the data under a
  protected root, or list made-up files in `[sanitize] scan_allow`.
- **`launch` network.** The tool reaches the network only through phiward's proxy, which
  refuses this machine and private addresses. List the private ranges you need in
  `[launch] private_networks`. On Linux, `launch` needs network namespaces.
- **Linux:** `launch` refuses `/tmp` itself as the project or the spool. A folder below `/tmp`
  works.
- **Files that run later** are read-only under `launch`. In Mode A the hook now asks before a
  file tool writes `.cursor`, `.gemini`, `.codex`, `.Rprofile` or `.Renviron`, and refuses
  where it cannot ask.
- **Copies:** a local path with `..`, a quoted `~` or an empty one is refused. Give the full
  path.
- **Doctor** warns until your user config masks subject IDs (a pack, patterns or
  `names_from`) or records `[sanitize] subjects = "none"`. `phiward setup` asks.

**Changed defaults and new options** (user config only):

- `[launch] keep_transcripts` is **on by default**. `launch --tool claude` now keeps each
  project's transcripts in `~/.phiward/carryover/claude/transcripts/`, so `--resume` and `-c`
  work. To keep nothing, set it to `false`.
- `[no_phi] folders`: exact folders you are sure hold no PHI. There, in Mode A, a shell that
  only a sandbox opener such as `allowLocalBinding` (macOS) leaves unconfined gets the text
  check, not the refusal. Nothing to do unless you need it.
- `[launch] write_to`: more folders a `launch` session may write, besides the project. launch
  checks each one at its start. Nothing to do unless you need it.
- Also new: `[launch] private_networks`, `[sanitize] examples`, `scan_allow` and
  `id_columns`.

### Added

- `[launch] write_to` (user config only): folders a `phiward launch` session may write besides
  the project (a sibling repository, a shared output folder). launch checks each one when it
  starts and refuses, naming the entry, for a file, a link, or a folder that overlaps a
  protected path, a derived folder, a place where files run later (home, its dot-folders,
  `~/Library`, `PATH`), a phiward file, the spool, a credential or a `[broker] write_to` folder.
  A missing entry is skipped with a NOTE; one inside the project is dropped. Each folder gets
  the project's rules: files that run later and git control files read-only (on Linux what
  exists at the start; launch makes nothing there), the project scan in the same 2 s budget
  (the instruction files of every folder first), and the end report under the folder's name.
  launch names the folders at the start and in `--report` (`write_to`); `--tool claude` gets
  `--add-dir D` for each; `phiward doctor` counts them and gives the same refusals. The
  broker's `PATH` filter and `pseudonymize` treat them as agent-writable. SIGHUP and SIGTERM
  now end the wait, not the launcher, so the end report still comes (exit 128 + the signal;
  one ignored at the start, as under `nohup`, stays ignored); after such a signal, a SIGKILL
  or a crash the next launch names the folders of the session that did not finish.
- `[no_phi] folders` (user config only): exact folders you are sure hold no PHI. In Mode A, a
  session whose project is a listed folder gets the text check of `[shell] best_effort` for
  Bash and Monitor, in place of the refusal, when only the sandbox openers (on macOS,
  `allowLocalBinding` for a dev server; never `filesystem.disabled`, a unix socket or
  `allowMachLookup`) leave the shell
  unconfined. Any other cause, such as a root missing from `denyRead`, keeps the refusal. Protected roots, the prompt scan, the project scan and the asks for files
  that run later stay on. The hook checks the one entry that matches the session's project: a
  link on its path, a place `launch` refuses as a project, or a folder inside or above a
  protected path is not relaxed. A relative entry is a bad config; a missing one relaxes
  nothing. The session's start message says whether it is relaxed (and warns when the project
  scan finds identifiers there); `phiward doctor` lists the folders. `phiward launch` runs as
  usual in a listed folder, with a NOTE. The `allowLocalBinding` refusal names `[no_phi]
  folders` as a way out. The start message and doctor use the hook's own test, so where the
  hook keeps the refusal (a unix socket, a root missing from `denyRead`) they say "not
  relaxed", with the reason and its step.
- The masking check, and `[sanitize] examples` (user config only): made-up values in the form
  of your own rules (`FAKE-PT-0001` for `FAKE-PT-\d{4} => <SUBJECT>`), never real ones.
  `phiward doctor`, `phiward launch` and the broker at its start check that each value is fully
  masked (only placeholders left, in text and table mode) and blocked by the prompt scan, and
  that a made-up path below each root, protected pattern and `[remote] roots` entry comes out
  masked. It names index numbers only. Doctor warns (the exit status is unchanged) and notes
  each rule no example tests; `doctor --headless` lists a failure.
- The project scan: subject and sample IDs in the project's own files and file names, outside
  the protected roots. One walk of the project, with no git, following no link: every name
  first, then the content, the instruction files first and then the smallest files,
  git-ignored files too; the first 64 KiB of each text file (doctor: 1 MiB; gzip, BGZF and
  UTF-16 read too). A folder named after an ID is one finding. It uses the subject rules only (your patterns and pack files, and
  the built-in packs in force), never positions, numbers, dates or roots, and names kinds,
  counts and masked paths only. `phiward launch` refuses on a finding (2 s budget; over it, it
  starts with a NOTE); `phiward doctor` scans with no limit and warns (`--show-paths` lists the
  files, `--headless` lists a finding as a reason); in Mode A the SessionStart note warns within
  2 s (under launch it does not scan again). `[sanitize] scan_allow` (user config only, absolute paths) allows files of made-up IDs.
  The leak test's launch leg allows its own `notes.md`, and a new step expects the refusal.
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
- A command reference: [docs/cli.md](docs/cli.md). A test fails when it and a command's help
  disagree.
- The prompt scan: a `UserPromptSubmit` hook (`phiward prompt-scan claude`, `onFailure:
  block`) that `install` writes in the user and project wiring and the plugin, and `launch`
  writes beside the fast hook. A prompt that the sanitizer would change is not sent: a match of
  the user config's packs or `[sanitize] patterns`, or a path below a protected root or a
  `[remote] roots` entry (also as `~/...`, `$HOME/...` or a relative path). The message names
  the kind, never the value. Built-in packs label rules that are details (`detail`; genomics:
  file and read names), and the scan leaves those and the positions out; with the `dates`
  pack on, a date blocks. Entry names, `names_from` and derived roots do not count. It fails
  closed. `doctor` reports a missing or weak prompt entry, warns of other prompt hooks and of a
  user pack file inside a root. It is a tripwire for honest pasting, not a boundary: the limits
  are in [docs/threat-model.md](docs/threat-model.md#known-prompt-scan). `hook claude` and
  the fast hook now refuse a payload of any event but `PreToolUse`.

### Changed

- Mode A: a `sandbox.excludedCommands` entry no longer stops the whole shell. Claude Code
  matches entries against each call's text with its own matcher, which phiward does not copy;
  so while the list it reads is not empty, every Bash and Monitor call gets the text check of
  `[shell] best_effort`. A command that names protected data, or a path the guard cannot see
  (`$(...)`, an unknown variable), is refused, and the refusal names the file that holds the
  entry and the way out; `ls`, `pytest` and `git status` run. `phiward doctor` says so on its
  "sandbox confines the shell" line. Not seen: an entry from an MDM profile, server-managed
  settings or `--settings` (threat model: `known-excluded-commands`).
- Mode A on Linux: `sandbox.network.allowLocalBinding` no longer counts as opening the sandbox
  (Claude Code's docs: it has no effect there). On macOS it still does. The step says to run a
  dev server in your own terminal, or to list a folder with no PHI in `[no_phi] folders`.
- `phiward launch` routes the tool's network through a proxy that allows only public addresses.
  The tool has no direct outbound IP connection: on macOS its profile allows only the proxy's random port on
  loopback, TCP only (held on both 127.0.0.1 and [::1]); on Linux the session has a network namespace of
  its own, and a relay on the session's own 127.0.0.1 gets each connection to the proxy as one end
  of a socket pair from the launcher (no socket with a path leads to the proxy, so this works
  also where the tool cannot make unix sockets; a pair that cannot be passed is a refusal). The
  proxy runs in the launcher, outside the profile. It takes CONNECT tunnels only (to any port), needs a token
  for the session, looks a name up once, checks every address, and connects to the checked addresses in turn
  (a short timeout each, so broken IPv6 does not stop a connection). It refuses this
  machine, the local link and the private ranges; `[launch] private_networks` in the user config
  (never a project's) lists private ranges it may reach, connected to directly. A `HTTPS_PROXY`
  in the terminal is chained by checked address only, for public addresses. The tool's proxy variables all name the session's proxy and
  `NO_PROXY` is empty. What this breaks is in docs/launch.md (servers on this machine, also on
  macOS one the session starts; tools that ignore the proxy variables; UDP; on Linux, name
  lookups inside the session). `launch` refuses to start when the proxy cannot start, and on
  Linux where network namespaces are not available, which `doctor` reports. On macOS the
  profile no longer allows the `nsurlsessiond`, `networkd`, `ocspd` and system `trustd`
  services (the user's `trustd` agent stays: it reads the OS trust store). On macOS a session can still
  listen on any address (Seatbelt cannot limit binds to loopback): bind local servers to
  `127.0.0.1`. The launcher raises
  its own soft limit of open files, so carry-over and the report still run while 64 tunnels are
  held. On Linux the session's network namespace keeps abstract unix sockets apart, on every
  kernel.
- `phiward launch --tool claude` keeps this project's transcripts between sessions, so
  `--resume` and `-c` work. Before, nothing was shared between sessions. `launch` sets
  `CLAUDE_CODE_PROJECT_DIR_NAME` (16 hex digits of the project's path hash) and copies only that
  folder, whole and never read, to `~/.phiward/carryover/claude/transcripts/` at the end and
  back at the start: plain files and real folders only, never `memory/` or `mcp-tasks/`, merged
  under the carry-over lock, at most 500 MiB for each project. `[launch] keep_transcripts =
  false` (user config only) turns it off, and a resume flag then gets a NOTE. `carryover
  status` lists the store. A resumed session reads what an earlier one wrote as its history: a
  stated limit (threat model, `open-transcripts`).
- `phiward launch` with an activated `.venv` (a project folder on `PATH`) still refuses, but now
  names the entry and says to run `deactivate` (or take it off `PATH`), not "start the tool in a
  project folder".
- `launch`'s proxy says why in a refusal's status line (`403 phiward: <why>`), names `[launch]
  private_networks` for a private address, and lists the refused hosts at exit (also in
  `--report`). With `--tool claude`, an `ANTHROPIC_BASE_URL` the proxy would refuse (not
  `https://`, this machine, a private range not listed) stops the start.
- On Linux, a `launch` session's Claude Code settings set `sandbox.allowUnsandboxedCommands:
  false`: a Bash command is not retried outside Claude Code's own sandbox.
- `phiward launch` and the broker may now refuse a config they used to accept: when the masking
  check fails, launch refuses to start (`the masking check failed: ...; run phiward doctor`),
  and the broker refuses every request until the config is fixed and the broker restarted.
  With no `[sanitize] examples`, only the roots are checked. To fix any failure, run
  `phiward doctor`: it names the entry, the rule or the root by number.
- `phiward launch` may now refuse a project it used to start: when the project scan finds a
  subject or sample ID in a project file or a file name (`the project scan found <SUBJECT> in
  3 files: ...`). To fix it, run `phiward doctor --show-paths` in your own terminal (it lists the
  files, masked, with line numbers), then move the data under a protected root or pseudonymize
  it (`phiward pseudonymize`). For files of made-up IDs, add them to `[sanitize] scan_allow` in
  your user config. A project too large for the scan's 2 s starts with a NOTE.
- The hooks phiward writes run from files in its package, with no inline code. The user
  wiring's hooks are in Claude Code's exec form: the command is `data/clean-exec.sh` (it clears
  the Python and loader variables, listed in `data/clean-env.awk`), and phiward's own Python
  with `-I -m phiward ...` are its arguments. The plugin runs its own copy of the script, and
  its MCP server is `phiward mcp` with no shell. The hooks under `launch` run
  `<python> -I -S <package>/phiward/entry.py ...`, now with `onFailure: "block"` on the fast
  hook too. Each failure still blocks: a script that is not there cannot start, a Python or
  `phiward` that is not there, an awk list that cannot be read, or a start without the
  arguments exits 2, and `entry.py` exits 2 when phiward's code cannot be loaded.
  `launch --tool claude` refuses, on macOS and Linux, a Claude Code older than 2.1.295, or a
  tool that gives no Claude Code version (run Claude Code's own program directly, or use
  `--tool generic`). It starts only a native binary to ask the version (from `/`), never a
  program inside the project or the session's folders; for the npm build it reads the
  package's `package.json`, and a shim or a wrapper is refused.
  `install --project` keeps its one
  `/bin/sh` line. **Re-install (required):** run `(cd ~ && phiward install claude --user
  --write)` once; it replaces the old entries in place. Until then `doctor` warns that they
  are in the older form, and `doctor --headless` is not ready (no prompt check). After an
  upgrade that moves phiward's Python, every tool call is refused until you run it again;
  `doctor` names the cause.
- The `msk` example pack no longer has path rules: `<PATIENTPATH>` (a path holding
  `inputs/patient`) and `<CLINICALPATH>` (a path under `/clinical/`) are gone. They were
  examples of one folder layout, not facts about any institution. A user who relied on them
  must add those folders as protected roots (`[protected_paths] roots`), or add a
  `[sanitize] patterns` rule for a custom path shape.
- The `msk` example pack's `<DONOR>` and `<CMOID>` rules leave ordinary words of code and
  prompts as written, and keep masking the IDs they are for. `<DONOR>` needs a digit in the
  name (`DonorFake-7`, not `donor_id`, `donors` or `DonorSearch`). `<CMOID>` needs a digit in
  the ID or six capital letters (`C-FAKE01`, `C-ABCDEF`, not `C-string` or `c-header`). So with
  `msk` on, these words no longer block a prompt, and output keeps them.
- macOS: the gateway's kernel profile is a file, run with `/usr/bin/sandbox-exec -f FILE`,
  instead of the profile's text in the command line. The file is new for each request, in
  `~/.phiward/profiles` (made 0700; the file 0600, removed when the request ends; files older
  than a day are removed when the broker starts). A request is refused, with a message, when
  `~/.phiward` is a link, another account's or writable by other accounts, or when `profiles`
  is a link or another account's. `~/.phiward/profiles` is on the hidden list: Claude Code's
  sandbox, the permission rules and the hook keep sessions from reading or writing it, and
  gateway commands cannot read it. Under `phiward launch` the tool's profile denies reading
  it. An existing wiring needs `(cd ~ && phiward install claude --user --write)` again: until
  then, once the broker has made the folder, the sandbox does not hide it, so the hook refuses
  every shell command but a gateway call, and `doctor` warns.
- macOS: the login service runs `/bin/launchctl` by its full path, not from `PATH`.
- `phiward copy` puts no code in a command line. A pull unpacks with `phiward/tar_extract.py`,
  a file of the installed package, run as `<python> -I FILE DEST`; a missing file fails the
  pull, and nothing is written. A local copy makes its destination folder with `/bin/mkdir -p`
  as its own step, in the same profile and write place as the copy, and copies only when that
  step succeeded (its output adds a line `copy (make the folder) done: exit=0`). A dry run
  without rsync runs the system `true`. The remote side of a push and a pull is unchanged.
- macOS: `phiward launch` starts the tool as `/usr/bin/sandbox-exec -f FILE TOOL ARGS...`, with
  no Python helper in between. The tool's profile is a file in `~/.phiward/profiles`, under the
  same rules as the gateway's, removed when the tool ends. A program name is found on the
  session's `PATH` before the start; when there is none, launch says so and exits 127. The tool
  now starts with SIGPIPE at its default. Launch no longer checks at start whether it runs
  inside another sandbox: there `sandbox-exec` cannot apply the profile, and nothing runs. When
  the tool exits with an error within a few seconds of its start, launch adds a line that
  points to `phiward doctor`, which names a start inside another sandbox or a profile that
  does not compile.
- macOS: a launch inside a session no longer trusts `HOME` to find the session. With a `HOME`
  that is not the account's, a launch inside a session builds its own profile, and nothing
  runs.
- `@path` mentions are turned off in the user settings and the `--settings` file
  (`env.CLAUDE_CODE_DISABLE_FILE_MENTIONS=1`; Claude Code v2.1.299+; ignored in project
  settings, so none is written there). A mention would put a file's text into the prompt without
  a tool call the hook sees; now it is a Read. Cost: `@` completion no longer inserts file
  contents; the agent reads the file with Read. The IDE's open-file and selection context is not
  covered. `doctor` reports a missing value and a Claude Code older than v2.1.299 (a problem
  below 2.1.295). Re-run `(cd ~ && phiward install claude --user --write)`. On Linux below
  7.1, `launch --tool claude` passes the same value in its own `--settings`.
- Linux: `launch` no longer masks host unix sockets by name; the kernel limits them. From
  Landlock ABI 9 (Linux 7.1) the session reaches only the unix sockets it made itself (and the
  name-service ones), and a helper that cannot apply this stops the start. Below ABI 9,
  `--tool claude` relies on Claude Code's sandbox to block unix sockets for Bash: `launch`
  passes `--settings` that turn it on (`enabled`, `failIfUnavailable`, no unsandboxed
  retries) as the last arguments of whatever it runs, and refuses to start when that sandbox
  cannot apply its filter (the native binary's, run as Claude Code runs it, does not block
  unix sockets in the session; the session could replace it; another architecture than
  x86_64 or aarch64), when settings open it, or when a `--` is among the arguments. The
  filter judged is that of the program that runs, and only Claude Code's native build is
  accepted (a JavaScript program, `env`, `npx`, `node` or a wrapper that adds arguments is
  refused). launch's `--settings` holds what the file `install` writes holds, mentions off
  included. Your own `--settings` is dropped when its content is that file's, from this
  release or the earlier one; any other one (another key or value, an allow, a hook, a file
  that does not parse) stops the start, and the refusal says to rerun
  `phiward install claude --user --write`. A Claude Code command (`claude mcp`, `daemon`, `rc`)
  stops the start too, also after options and hidden ones:
  `launch` asks the program that runs (`claude WORD --help` has a Usage line of its own), and a
  help that cannot be read stops the start. Below
  ABI 9, `--tool generic` and a wrapped MCP server cannot make unix sockets at all (also their
  own; socketpairs and pipes work). The warnings about Landlock scopes are gone.
- `launch` makes files that other tools run later read-only, for the tool and a wrapped MCP
  server alike: the `.claude`, `.vscode`, `.idea`, `.cursor`, `.gemini` and `.codex` folders as
  a whole, `.mcp.json`, `.gitmodules`, `.ripgreprc`, `.Rprofile` and `.Renviron`, at any depth on
  macOS and, on Linux, those that exist at the start (it makes `.claude`, `.vscode` and `.idea`
  if there are none). What a link inside them leads to is read-only too; `launch` refuses to
  start where it cannot tell. So skills, hooks and editor settings are edited outside `launch`,
  `--worktree`, agent worktrees (`isolation: worktree`) and `/loop` durable tasks do not work
  inside it, a `git pull`, `checkout` or `switch` that changes a tracked file in those folders
  fails partway there (run it in your own terminal), and `renv::init()` runs once
  outside it. A wrapped server on Linux can no longer write `.idea`, `.gitmodules` or
  `.ripgreprc` (they were read-only only on macOS). The hook also asks before a file tool writes
  `.cursor`, `.gemini`, `.codex`, `.Rprofile` or `.Renviron` anywhere in a project (in the modes
  that do not prompt, it refuses), and the exit report lists them, and `.tool-versions`, at any
  depth. Files in `.cursor/rules/` are now listed as settings, not as instructions for models.
  Trees of installed code (`node_modules`, `.venv`, `venv`, `site-packages`, `renv/library`,
  `.tox`, `target`, `.git`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`;
  `SKIP_TREES` in `wholetool.py`) are left writable, and `.claude/worktrees` is not walked for
  links; where the walk stops at its bound, `launch` says so at the start and in the exit report.
- `[network] limit`: `install` replaces `sandbox.network.allowedDomains` in your user settings
  with exactly `allowed_domains` and prints each host it removes (it used to keep the hosts
  already there). `doctor` warns about each level (managed, user, project) whose
  `WebFetch(domain:...)` allow rules add hosts, and about listed hosts the config does not have.
- `phiward run --table` reads CSV/TSV output by column (issue #2): a cell under an identifier
  header (a built-in list, plus `[sanitize] id_columns` in the user config) is masked whole as
  `<IDCOL>`, whatever its shape; a plain number passes only in a parsed cell of another column.
  One table per output, its header the first line, which must name an identifier column (else
  the whole output is text: a table without one keeps no numbers); from the first line that is
  not a row of it, the rest is masked as text. Output without a header line, or with a line
  before it (a warning on stderr too), is masked as text, with a note that says so; before,
  every number in it was kept. `phiward sanitize --table` and the git hooks keep the per-line
  meaning.
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
  exist would; nothing is masked less than before.
- Entry names now match across dashes, digits and separators. The sanitizer reads every dash
  (U+2010, U+2013, U+2212, ...) as `-`, in lines and names alike, to find names in other
  spellings; pack rules written with `-` match those spellings too, also with no inventory. Other
  decimal digits (Arabic-Indic `٠١`, ...) are matched as ASCII digits, by entry names and by pack
  rules (Python 3.9 knows fewer of them than later versions). The masked line is printed as
  written. A name of 5 or more letters and digits, with a letter, is also masked with its
  separators (`-`, `_`, `.`, a space) changed or left out: `FAKE-PT-0001` masks `FAKE_PT_0001`,
  `FAKE PT 0001` and `FAKEPT0001`. Shorter names, digits-only names and names with a separator at
  either end are matched as written only; a name whose stem is matched that way
  (`FAKE-PT-0001.bam`) is matched whole as written only, so its extension stays for the file
  rules. The sanitizer masks a line as before, then masks the names in other spellings, and each
  rule's matches on the line read that way, in the text it left; its placeholders stay as they
  are, so a line is never masked less than before. Such a mask takes the whole of a number it
  starts or ends inside (`SAM_PLE12:00`; across a comma only a number of a million or more, and
  only in text mode), and overlapping ones become one placeholder: `<PROTECTED>` when a protected
  path is in it, else a rule's match that covers them all, else `<ENTRY>` when a name is in it,
  else that of the first. In a table read by column (`--table`), the row is masked as before, then
  these masks are made in each cell but an ID cell on its own; the table ends only where it ended
  before (a row that only these masks keep from its second pass is withheld). A root whose name
  holds another dash also matches a path written with `-`, so the hook and the git hooks refuse
  that spelling too. Generic names under a root (`sample_01`) now also mask text such as
  `sample 01`.

### Fixed

- **Mode A on Linux with bubblewrap before 0.5 (RHEL 8):** every Bash call failed where the
  Kerberos KCM socket exists ("bwrap: Can't create file at /run/.heim_org.h5l.kcm-socket"):
  Claude Code's sandbox cannot hide a socket by path there. On such a node only (Linux x86_64
  and aarch64), phiward now leaves the Docker and KCM sockets out of the sandbox's lists, and
  Claude Code's seccomp filter for new Unix sockets keeps a shell command from them; doctor
  says so in a NOTE. They leave the Read and Edit deny rules too, which Claude Code merges into
  its sandbox; phiward's hook still refuses a file tool that names them. Elsewhere nothing changes.
  The sandbox check has a new probe for that filter (`unix-socket`). Run
  `(cd ~ && phiward install claude --user --write)` again on the node.
- After an upgrade, `doctor` said "broker: running" for a broker that still ran the old code.
  The broker now writes its phiward version into its status file. `doctor` warns when it
  differs from its own or is missing (an older broker writes none; a status that cannot be
  read counts as missing), with the restart step, and
  `doctor --headless` gives it as a reason it is not ready. The request protocol is unchanged.
- Three refusals now name their next step: no confinement backend (install bubblewrap and have
  it on the PATH, on Linux), an upstream `HTTPS_PROXY` that is not `http://` (unset it for
  `launch`, or give an `http://` proxy), and Landlock ABI below 2 (Linux 5.19 or newer with
  Landlock on).
- A pull no longer needs `mkdir` and `tar` on this machine. phiward refused a pull without
  them, but it never ran them: the remote runs `tar`, and phiward's own extractor unpacks.
- The Mode A session note says when the project scan could not run, and names `phiward doctor`;
  in a `[no_phi] folders` folder the person's message says so too. It said nothing before.
- A pull counted any file it could not write as "kept", and a write that failed partway left a
  truncated file that the next pull kept. Only a file that exists is kept now. A file or folder
  it cannot make or write in full (no permission, no space) fails the pull; a partly written
  file is removed. A stream that ends early (a dropped connection, a killed remote tar) stops
  the pull with one line, not a traceback, and the file it was writing is removed too.
- `phiward doctor`'s launch section decides the project folder with launch's own checks, not a
  copy of them. It now also warns when the folder is inside or above a protected path, and,
  as launch does, names the first problem only.
- `launch` refuses an empty `PATH` entry (a leading or trailing `:`, or `::`), `.` and any
  other relative entry. It names the folder the shell is in: the project, where the tool runs,
  or a folder of it after the session. The check skipped such entries, so a program the session
  wrote there could run later. The step says to remove the entry. `phiward doctor` gives the
  same refusal, and the `[launch] write_to` check refuses such an entry too.
- Linux: the broker makes its cache folder (`~/.cache/phiward`) when it starts. While a
  command runs, Claude Code's own sandbox puts an empty read-only file at each denied path
  that does not exist, and the cache folder is denied: a first `phiward run` from a session
  (no `launch`) failed with `run failed (FileExistsError)`. A file left at that place (or
  above it) is never removed: the broker refuses to start, names it and says to remove it.
  The sandbox check's stand-in
  now leaves the same files, and an unclassified gateway failure notes its first line
  (words of letters only; any other word shown as `<x>`).
- Linux: under `phiward launch` the session's `TMPDIR`, `TMUX_TMPDIR` and
  `CLAUDE_CODE_TMPDIR` are `/tmp`, the name the session's view gives its own temp folder, not
  that folder's full path under `~/.phiward`. A unix socket's path holds at most 107 bytes, and
  under the full path Claude Code's sandbox could not make its bridge sockets
  (`Failed to create bridge sockets after 5 attempts`: Bash did not run under
  `launch --tool claude`), nor tmux its socket. So `launch` on Linux refuses a project or
  spool that is `/tmp` (it would cover the session's own `/tmp` with the shared one); a folder
  below `/tmp` works.
- A `[remote] roots` entry that is not absolute (`~/data`, `data`) makes the config unusable;
  the sanitizer never masked it as written. Until the entry is absolute, every guarded action
  refuses (the hook, the gateway, `launch`), as with any config that cannot be used. The
  message names the entry by number. Write the remote's absolute path (`/data1/me/data`).
- macOS: `doctor`'s gateway self-test runs `/usr/bin/true` by its full path, not `true`
  from `PATH`.
- macOS: the gateway's profile and `phiward launch`'s tool profile also deny mounting file
  systems and creating launchd jobs.
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
  to wrap itself again and fail on the read-only `~/.phiward`. A launch inside a session now
  runs its command directly, under the session's own profile, as on macOS. Anything else
  builds the full profile, and refuses where `~/.phiward` cannot be written. The sandbox
  check's stub run expects `PASS Mode B` on Linux.
- `date` is a placeholder word: a names file with a path part `date` no longer turns the dates
  pack's `<DATE>` into `<<NAME>>`.
- On Linux with an older C library (RHEL 8), carry-over no longer crashes when it gives a
  session's folder back its owner bits (a refused `phiward launch` ended with a traceback).
- Linux: before a `phiward run` or `phiward copy` command starts, the gateway confirms that each
  folder and file it binds (the write places, a `.claude` folder in one, the ssh config, the
  shared connection's socket) is, inside, the same file it found at that name before the start
  (a link not followed), mounted at that name. Anything it cannot confirm, an error included,
  stops the request (nothing runs). Some settings that ran before now stop the request: a
  hidden path at or above a write place or at its `.claude` (before, the command ran with it
  masked or without writes there), and a bind listed twice.

### Docs

- `docs/endpoint-security.md`, for IT and security teams: what phiward installs and writes,
  and every process it starts on macOS, with its parent, image, how often it runs, its exact
  command line and a command-line regex of at most 256 characters. A test records what phiward
  starts and checks the page's list both ways. setup.md, launch.md, the troubleshooting list and
  the threat model link to it.
- A "Small counts" section in `docs/daily-use.md`: masking hides identifiers, not small counts;
  suppress counts of 7 or fewer, round the rest to 5, and watch for differencing (after
  OpenSAFELY's rules). phiward does not enforce it. The rules that `phiward init` adds now say so.
- why.md and threat-model.md say whom phiward is built against: an honest user, and an
  agent that text it reads can mislead; not a determined attacker who already runs code on the
  machine.

### For maintainers

- A leak test for typical sessions (`tests/test_leak_typical.py`; no change to phiward itself):
  a scripted session is replayed through the session note, the prompt scan, the hook, the
  gateway and `phiward mcp`, in Mode A with a full and a default config, and under `phiward
  launch` on Linux. Made-up values planted under a root, in the project and in pasted prompts
  must come out refused, masked, blocked or sent as the threat model says; a pack file weakened,
  a pattern edited or a root removed in the config must be found. What it does not cover is in
  the threat model (`known-leak-test`).
- The release check with the real Claude Code (`scripts/sandbox-check`) runs on Linux too:
  `check.sh` on a real machine (`SBX_BASE`), or `linux.sh` in a container with Claude Code
  pinned by a lock file. One session per mode (`MODES`, A and B), new probes (the Read tool,
  `phiward run` from the session, the git hook, the parents' environment, doctor before and
  after, and with `REMOTE` push, run and pull through the shared connection), reason classes
  per platform, a facts file, and a verdict per mode. The token is replaced by `<TOKEN>` in
  every kept file. `--stub` checks the plumbing with a stand-in claude (issue #6).
  `SBX_BASE` may be a folder below your home folder (not the home folder itself), and is
  refused when it or a folder above it holds `CLAUDE.md`, `CLAUDE.local.md`, `.claude`,
  `.git`, `.mcp.json`, `.phiward.toml`, `.agent-guards.toml` or `AGENTS.md`, also right before
  each session. `SBX_TOOLS` puts a folder that holds only socat (a cluster has none) on the
  session's PATH, when it and its socat pass phiward's own rule for a PATH folder. The check
  starts itself again under an empty environment (only its own variables, HOME, TMPDIR, TERM
  and PATH cross), runs in its own folder with its own home, and takes the token only at its
  prompt, no longer from `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`. claude and uv, found
  through your PATH, must pass the same rule before the prompt. `SBX_WHEEL` with
  `SBX_WHEEL_SHA256` installs a wheel built beforehand, checked by its sha256, so the node needs
  no package index. `linux.sh` with
  `SBX_SH=bash` runs the stub with bash as `/bin/sh`.
  The parents' environment probe scans every process the session can see in `/proc` and
  records only counts and PIDs, never a name or a value; a credential variable's name from
  `token-names.txt` in any of them fails the mode. `CLAUDE_CODE_MESSAGING_TOKEN`, which Claude
  Code gives to Bash commands on purpose, is only counted and noted. An exported token is
  not used, but it is in the start environment of your shell and of the check's first start,
  so the check warns: paste the token when `check.sh` asks for it.
- Two tests of the output cap restart the broker after changing the config, so they test the
  cap; before, every run in them was refused and their bounds held trivially.

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
