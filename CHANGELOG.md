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

### Fixed

- Linux: under `phiward launch` the session's `TMPDIR`, `TMUX_TMPDIR` and
  `CLAUDE_CODE_TMPDIR` are `/tmp`, the name the session's view gives its own temp folder, not
  that folder's full path under `~/.phiward`. A unix socket's path holds at most 107 bytes, and
  under the full path Claude Code's sandbox could not make its bridge sockets
  (`Failed to create bridge sockets after 5 attempts`: Bash did not run under
  `launch --tool claude`), nor tmux its socket. So `launch` on Linux refuses a project or
  spool that is `/tmp` (it would cover the session's own `/tmp` with the shared one); a folder
  below `/tmp` works.
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

### Docs

- A "Small counts" section in `docs/daily-use.md`: masking hides identifiers, not small counts;
  suppress counts of 7 or fewer, round the rest to 5, and watch for differencing (after
  OpenSAFELY's rules). phiward does not enforce it. The rules that `phiward init` adds now say so.

### Changed

- `phiward launch` routes the tool's network through a proxy that allows only public addresses.
  The tool has no direct IP network: on macOS its profile allows only the proxy's random port on
  loopback, TCP only (held on both 127.0.0.1 and [::1]); on Linux the session has a network namespace of
  its own, and a relay on the session's own 127.0.0.1 gets each connection to the proxy as one end
  of a socket pair from the launcher (no socket with a path leads to the proxy, so this works
  also where the tool cannot make unix sockets; a pair that cannot be passed is a refusal). The
  proxy runs in the launcher, outside the profile. It takes HTTPS (CONNECT) only, needs a token
  for the session, looks a name up once, checks every address, and connects to the checked addresses in turn
  (a short timeout each, so broken IPv6 does not stop a connection). It refuses this
  machine, the local link and the private ranges; `[launch] private_networks` in the user config
  (never a project's) lists private ranges it may reach. A `HTTPS_PROXY` in the terminal is
  chained by checked address only. The tool's proxy variables all name the session's proxy and
  `NO_PROXY` is empty. What this breaks is in docs/launch.md (servers on this machine, also on
  macOS one the session starts; tools that ignore the proxy variables; UDP; on Linux, name
  lookups inside the session). `launch` refuses to start when the proxy cannot start, and on
  Linux where network namespaces are not available, which `doctor` reports. On macOS the
  profile no longer allows the `nsurlsessiond`, `networkd`, `ocspd` and system `trustd`
  services (the user's `trustd` agent stays: it reads the OS trust store). The launcher raises
  its own soft limit of open files, so carry-over and the report still run while 64 tunnels are
  held. On Linux the session's network namespace keeps abstract unix sockets apart, on every
  kernel.
- On Linux, a `launch` session's Claude Code settings set `sandbox.allowUnsandboxedCommands:
  false`: a Bash command is not retried outside Claude Code's own sandbox.
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
  `/bin/sh` line. **Re-install:** run `(cd ~ && phiward install claude --user --write)` once;
  it replaces the old entries in place, and until then `doctor` warns that they are in the
  older form. After an upgrade that moves phiward's Python, every tool call is refused until
  you run it again; `doctor` names the cause.
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
  it. Run `phiward install claude --user --write` again to add it to an existing wiring;
  `doctor` warns until then.
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
- macOS: a launch inside a session decides from the session's own run folder, which launch
  names in `PHIWARD_RUN`, and from the account's home folder, never `HOME`. With a `HOME` that
  is not the account's, a launch inside a session builds its own profile, and nothing runs.
- Docs: why.md and threat-model.md say whom phiward is built against: an honest user, and an
  agent that text it reads can mislead; not a determined attacker who already runs code on the
  machine.
- `@path` mentions are turned off in the user settings and the `--settings` file
  (`env.CLAUDE_CODE_DISABLE_FILE_MENTIONS=1`; Claude Code v2.1.299+; ignored in project
  settings, so none is written there). A mention would put a file's text into the prompt without
  a tool call the hook sees; now it is a Read. Cost: `@` completion no longer inserts file
  contents; the agent reads the file with Read. The IDE's open-file and selection context is not
  covered. `doctor` reports a missing value and a Claude Code older than v2.1.299 (a problem
  below 2.1.295). Re-run `(cd ~ && phiward install claude --user --write)`.
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
  refused). Your own `--settings` is refused unless it says just what launch passes, and so is
  a Claude Code command (`claude mcp`, `daemon`, `rc`), also after options and hidden ones:
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
  Trees of installed code (`node_modules`, `.venv`, `venv`, `site-packages`, `renv/library`, `.tox`, `target`, `.git`, `__pycache__`, `.mypy_cache`; `SKIP_TREES` in `wholetool.py`) are left writable, and `.claude/worktrees` is not walked for links; where the walk
  stops at its bound, `launch` says so at the start and in the exit report.
- `[network] limit`: `install` replaces `sandbox.network.allowedDomains` in your user settings
  with exactly `allowed_domains` and prints each host it removes (it used to keep the hosts
  already there). `doctor` warns about each level (managed, user, project) whose
  `WebFetch(domain:...)` allow rules add hosts, and about listed hosts the config does not have.
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
