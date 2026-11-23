# Commands

**For:** looking up a command or an option. The guides say when and why to use each one.

Each section follows the command's own help (`phiward COMMAND --help`): its usage lines, word
for word, and one line for each subcommand and option. The help is the long form. A test
(`tests/test_docs_cli.py`) fails when this page and the help disagree.

The parsers are written by hand. For `phiward mcp list`, `wrap` and `unwrap`, the test also
checks the options against the parser. For the other commands, nothing checks the help against
the parser.

Also: `phiward --version` (or `phiward version`, `-V`) prints the installed version, and
`phiward --help` lists the commands.

## The operator's commands

Run these in your own terminal, not through an agent.

### phiward setup

The first-time setup: it asks questions and writes the user config.
Guide: [Set up](quickstart.md#2-set-it-up). Detail: [setup.md](setup.md#3-the-user-config-phiward-setup).

```text
usage: phiward setup [--from TEAM.toml]
       phiward setup --first-run --root PATH [--root PATH]... [--remote HOST:/PATH]...
```

| Option | What it does |
|---|---|
| `--from FILE` | Start from a team template: its settings fill in what your config does not have. |
| `--first-run` | Write the first user config without questions. Only when none exists. |
| `--root PATH` | With `--first-run`: a protected root. |
| `--remote HOST:/PATH` | With `--first-run`: a copy remote. |
| `-h`, `--help` | Show the help. |

### phiward pin

Approve the programs of `[broker] commands`, and record the derived protected folders.
Guide: [Run a script the agent wrote](daily-use.md#run-a-script-the-agent-wrote).

```text
usage: phiward pin
```

| Option | What it does |
|---|---|
| `-h`, `--help` | Show the help. |

### phiward broker

Run the gateway commands outside the agent. Start it yourself.
Guide: [Start the broker](setup.md#5-start-the-broker).

```text
usage: phiward broker [--max-jobs N]
       phiward broker --service [--write]
```

| Option | What it does |
|---|---|
| `--max-jobs N` | Run at most N gateway commands at the same time (default 4). |
| `--service` | Print the login service for the broker, and the command that loads it. |
| `--write` | With `--service`: write the service file. |
| `-h`, `--help` | Show the help. |

At its start the broker runs the masking check once
([configuration.md](configuration.md#sanitize)). While it fails, the broker refuses every
request (`refused: the masking check failed when the broker started`); fix the config and
restart the broker.

### phiward carryover

Read and keep what `phiward launch` sessions put in quarantine.
Guide: [When a session ends](launch.md#when-a-session-ends).

```text
usage: phiward carryover status [--tool NAME]
       phiward carryover add PATH [--as NAME] [--tool NAME]
       phiward carryover show [--tool NAME]
       phiward carryover accept ID [ITEM...] [--tool NAME]
       phiward carryover reset [--tool NAME]
```

| Command or option | What it does |
|---|---|
| `status` | Show the size of each carry-over folder, and what it costs to delete it. |
| `add PATH` | Put an instruction file or folder of your own into the trusted copy. |
| `show` | List the changes in quarantine, each with its ID and items. |
| `accept ID [ITEM...]` | Keep a change from quarantine, all of it or the named items. |
| `reset` | Make the record again from the trusted copy, when it cannot be read. |
| `--as NAME` | With `add`: the name it gets in the trusted copy. |
| `--tool NAME` | The agent tool (default: `claude`). |
| `-h`, `--help` | Show the help. |

### phiward pseudonymize

Make a copy of one table in which the identifier columns you name hold codes (`S0042`).
Guide: [Give the agent pseudonymized data](daily-use.md#give-the-agent-pseudonymized-data-phiward-pseudonymize).
What it does not hide: [the threat model](threat-model.md#known-limits).

```text
usage: phiward pseudonymize (--new-key NAME [--prefix P] | --key NAME)
                            --columns H[=NEW],... [--drop H,...] [--keep H,...]
                            [--keep-order] IN OUT
       phiward pseudonymize (--new-key NAME [--prefix P] | --key NAME)
                            [--keep-samples N,...] [--keep-order] IN.vcf OUT.vcf
       phiward pseudonymize (--new-key NAME [--prefix P] | --key NAME)
                            --columns PATH,... [--drop PATH,...] [--keep PATH,...]
                            [--keep-order] IN.json OUT.json
```

| Option | What it does |
|---|---|
| `--new-key NAME` | Start a new key. |
| `--key NAME` | Extend an existing key: known IDs keep their codes. |
| `--prefix P` | With `--new-key`: 1 to 3 capital letters before the digits (default `S`). |
| `--columns H[=NEW],...` | The identifier columns to code (in JSON, key paths). |
| `--drop H,...` | Columns (in JSON, key paths) to leave out. |
| `--keep H,...` | Columns (in JSON, key paths) that look like identifiers, kept as they are on your word. |
| `--keep-samples N,...` | With a VCF: keep the names of these samples, on your word. |
| `--keep-order` | Keep the order of the rows, of a VCF's sample columns or of JSON arrays. |
| `--` | End the options. IN and OUT follow. |
| `-h`, `--help` | Show the help, with the rules for each kind of file. |

## Wire a project and a tool

### phiward init

Set up a project: the rules in `AGENTS.md`, the Claude Code settings, the git hooks.
It only adds.
Guide: [Set up each project](quickstart.md#3-set-up-each-project-and-check-it).

```text
usage: phiward init [--root DIR]...
```

| Option | What it does |
|---|---|
| `--root DIR` | Add DIR to the project's protected folders (`.phiward.toml`). |
| `-h`, `--help` | Show the help. |

### phiward install claude

Print the wiring for Claude Code, or write it after a diff and a yes.
Detail: [setup.md](setup.md#claude-code).

```text
usage: phiward install claude [--user|--project] [--no-hooks] [--block-outside-reads] [--write [--yes]]
       phiward install claude --json
```

| Option | What it does |
|---|---|
| `--user` | The user settings, `~/.claude/settings.json` (the default). |
| `--project` | The project settings, `.claude/settings.json` and `.claude/settings.local.json`. |
| `--no-hooks` | Write only the sandbox and permission settings, not the hooks. |
| `--block-outside-reads` | With `--user`: also set up to two Claude Code permission settings, as defence in depth around the project. Each is set only when the installed Claude Code takes it: which ones, and from which version, is in [setup.md](setup.md#claude-code). |
| `--write` | Merge the wiring into the settings file, show the difference, write it after a yes. |
| `--yes` | With `--write`: write without the question. |
| `--json` | Print the user wiring as one JSON object, for an unattended run. See [unattended.md](unattended.md). |
| `-h`, `--help` | Show the help. |

### phiward doctor

Show the config in force and what may turn the guards off (on Linux, also when `phiward launch`
cannot start because there are no network namespaces).
Guide: [Check with doctor](setup.md#7-check-with-doctor).

```text
usage: phiward doctor [--verbose] [--show-paths | --headless]
```

| Option | What it does |
|---|---|
| `--verbose`, `-v` | Every check on its own line, and the detail counts. |
| `--show-paths` | Also print the protected paths (by default only their counts), and the project files the project scan found (masked, with line numbers). |
| `--headless` | A short check before an unattended run: exit 0 when the session would be guarded. See [unattended.md](unattended.md). |
| `-h`, `--help` | Show the help. |

After the sanitizer line, doctor prints the masking check: `masking check: ok (...)`, or a
WARNING for each value of `[sanitize] examples` that is not fully masked and each root whose
made-up path came out unmasked, and a NOTE for each of your rules that no example tests
([configuration.md](configuration.md#sanitize)). It names index numbers only. A failure does
not change the exit status; `--headless` lists it as a reason.

Then doctor prints the project scan ([launch.md](launch.md#the-project-scan)), with no time
limit: `project scan: ok (N files)`, or `WARNING: project scan: found <SUBJECT> in 3 files,
<SAMPLEID> in 1 file name; ...`. With `--show-paths`, it lists each file as
`data/<SUBJECT>.csv: line 2: <SUBJECT>` (the path masked, at most 50 files). A NOTE counts
what it did not read. In `/`, the home folder or above it, it says `project scan: skipped (not
a project folder)`; with no rule for subject IDs, `project scan: off`. A finding does not
change the exit status; `--headless` lists it as a reason (it scans for 2 s at most).

### phiward mcp list, wrap and unwrap

Show your MCP servers, and run each one in phiward's kernel profile (wrap) or as it was (unwrap).
Guide: [Wrap an MCP server](modes.md#wrap-an-mcp-server-mode-a).

```text
usage: phiward mcp wrap NAME...|--all [--yes|-y]
       phiward mcp unwrap NAME... [--yes|-y]   (only in your own terminal, even with --yes)
       phiward mcp list
```

| Command or option | What it does |
|---|---|
| `list` | Say which servers are wrapped, and the command for each that is not. |
| `wrap NAME...` | Run these servers under `phiward launch`. It shows the change and asks first. |
| `unwrap NAME...` | Run these servers as they were. Only in your own terminal. |
| `--all` | With `wrap`: every server. One that cannot be wrapped is left as it is. |
| `--yes`, `-y` | Change the files without the question. |
| `-h`, `--help` | Show the help. |

## Work with protected data

### phiward run

Run a command with read access to protected data, and print its output masked.
Guide: [Work with protected data](daily-use.md#work-with-protected-data-phiward-run).
On HPC: [hpc.md](hpc.md).

```text
usage: phiward run [--write-to DIR]... [--net] [--names-from FILE]... [--table] -- CMD [ARG]...
       phiward run --remote HOST [--names-from FILE]... [--table] -- CMD [ARG]...
```

| Option | What it does |
|---|---|
| `--write-to DIR` | Let CMD write in DIR, a `[broker] write_to` folder or a folder inside one. |
| `--net` | Let CMD use the network (needs `[broker] net = true`). |
| `--names-from FILE` | Also mask the names listed in FILE. |
| `--table` | Read CSV or TSV output by column (needs `[sanitize] table = true`). |
| `--remote HOST` | Run CMD on an HPC host in `[remote] hosts`. |
| `--` | End the options. CMD and its arguments follow. |
| `-h`, `--help` | Show the help. |

### phiward copy

Copy into a protected folder or a configured remote. Nothing is printed.
Guide: [Copy protected data](daily-use.md#copy-protected-data-phiward-copy).
On HPC: [hpc.md](hpc.md#phiward-copy).

```text
usage: phiward copy [--dry-run] SRC... DST
```

| Option | What it does |
|---|---|
| `--dry-run` | Check the request and copy nothing. Only as the first word. |
| `-h`, `--help` | Show the help. |

### phiward launch

Run a whole agent tool, or one program, in phiward's kernel profile (Mode B).
Guide: [Mode B: phiward launch](launch.md).

```text
usage: phiward launch [--tool NAME] [--memory] [--report FILE] [--entry ID] [--] [PROGRAM [ARG]...]
```

| Option | What it does |
|---|---|
| `--tool NAME` | The agent tool: `claude`, or `generic` (the default). |
| `--memory` | Turn Claude Code's auto memory on. |
| `--report FILE` | Write a JSON report there when launch ends, for a run with nobody watching. |
| `--entry ID` | Written by `phiward mcp wrap` into a wrapped server's entry. Not for you to type. |
| `--` | End the options. PROGRAM and its arguments follow. |
| `-h`, `--help` | Show the help. |

Before the tool starts, launch runs the project scan for 2 s at most
([launch.md](launch.md#the-project-scan)). On a finding it refuses: `phiward launch: the
project scan found <SUBJECT> in 3 files: move the data under a protected root, pseudonymize it
(phiward pseudonymize), or allow the files ([sanitize] scan_allow); phiward doctor --show-paths
lists them; nothing runs`. When it stops at its limit, the tool starts after one line: `phiward
launch: NOTE: the project scan stopped at its 2 s limit after N files; run phiward doctor for
the full scan`. When it finished but left part unread: `phiward launch: NOTE: the project scan
did not read all of the project (3 files read only to their head); phiward doctor gives the
counts`.

### phiward check

Show what the guard decides for a shell command, and why. Nothing runs.
Guide: [Check a command](daily-use.md#check-a-command-phiward-check).

```text
usage: phiward check [--cwd DIR] -- COMMAND...
```

| Option | What it does |
|---|---|
| `--cwd DIR` | Decide as if the command ran in DIR. |
| `-h`, `--help` | Show the help. |

### phiward sanitize

Mask protected paths and identifiers in text: stdin in, the masked text out.
Guide: [Filter your own output](daily-use.md#filter-your-own-output-phiward-sanitize).

```text
usage: phiward sanitize [--table] [--names-from FILE]...
       phiward sanitize --selftest
       phiward sanitize [--names-from FILE]... --check FILE...
       phiward sanitize [--names-from FILE]... --check-table FILE...
```

| Option | What it does |
|---|---|
| `--names-from FILE` | Also mask the names in FILE, an index file. |
| `--table` | Mask each line as a table row (needs `[sanitize] table = true`). |
| `--check FILE...` | Report what the files would leak. Exit 1 when something would. |
| `--check-table FILE...` | The same, for files read as tables. |
| `--selftest` | Run the sanitizer's own made-up cases. |
| `-h`, `--help` | Show the help. |

## Called by tools

You rarely run these yourself. `phiward install claude` and `phiward init` write them into the
settings and the git hooks.

### phiward hook claude

Read a Claude Code hook payload on stdin, and reply as Claude Code expects.
Detail: [setup.md](setup.md#claude-code).

```text
usage: phiward hook claude
```

| Option | What it does |
|---|---|
| `-h`, `--help` | Show the help (`phiward hook --help`). |

### phiward session-note claude

The start-of-session note, run by Claude Code as a SessionStart hook.
Detail: [setup.md](setup.md#claude-code).

```text
usage: phiward session-note claude   (reads the hook payload on stdin)
```

| Option | What it does |
|---|---|
| `-h`, `--help` | Show the help (`phiward session-note --help`). |

### phiward prompt-scan claude

The check of each prompt before Claude Code sends it, run as a UserPromptSubmit hook. A prompt
that holds a match of the user config's packs or `[sanitize] patterns`, or a path below a
protected root, is not sent; the reply names the kind, never the value.
Detail: [threat-model.md](threat-model.md#known-prompt-scan).

```text
usage: phiward prompt-scan claude   (reads the hook payload on stdin)
```

| Option | What it does |
|---|---|
| `-h`, `--help` | Show the help (`phiward prompt-scan --help`). |

### phiward mcp

phiward's gateway as an MCP server on stdin and stdout, which Claude Code starts.
Detail: [configuration.md](configuration.md#mcp-servers).

```text
usage: phiward mcp   (an MCP server on stdin and stdout)
       phiward mcp list|wrap|unwrap ...   your own MCP servers: see `phiward mcp list --help`
```

| Option | What it does |
|---|---|
| `-h`, `--help` | Show the help, with the server's tools. |

### phiward git-hook

Run a git hook, or install the hooks.
Detail: [setup.md](setup.md#git-hooks).

```text
usage: phiward git-hook pre-commit | pre-push | install [--force]
```

| Command or option | What it does |
|---|---|
| `pre-commit` | Check the staged changes. git runs it before a commit. |
| `pre-push` | Check the branches to be pushed. git runs it before a push. |
| `install` | Write both hooks into this repository's hooks folder. |
| `--force` | With `install`: replace hooks that are there already. |
| `-h`, `--help` | Show the help (`phiward git-hook --help`). |
