# Setup reference

**For:** anyone who wants each setup step, option and limit explained; upgrades; removal.

The [quick start](quickstart.md) is the short way. This page explains each step, its options
and its limits, in the same order. Run the steps in your own Terminal. The guided setup
(`/phiward:setup`) lets the agent run the first-time steps for you, but only while no config
exists ([below](#the-guided-first-run)).

1. [Check the requirements](#1-requirements)
2. [Install](#2-install)
3. [Write the user config with `phiward setup`](#3-the-user-config-phiward-setup)
4. [Wire the agent tool](#4-wire-the-agent-tool)
5. [Start the broker](#5-start-the-broker)
6. [Pin the derived folders](#6-pin-the-derived-folders)
7. [Check everything with `phiward doctor`](#7-check-with-doctor)
8. [Try it on made-up data](#8-try-it-on-made-up-data)
9. [Per repository: `.phiward.toml` and the git hooks](#9-per-repository)

Later: [change the setup](#change-the-setup),
[upgrade from agent-guards](#upgrade-from-agent-guards-010), [remove phiward](#remove-phiward).

## 1. Requirements

- Python 3.9 or newer.
- macOS: `/usr/bin/sandbox-exec` (part of macOS; Apple marks it as deprecated, Claude Code uses
  it too).
- Linux:
  - bubblewrap (`bwrap`) on the `PATH`;
  - Landlock ABI 2 or newer in the kernel (Linux 5.19 or newer, with Landlock turned on). The
    gateway uses it as a second layer for its writes and refuses to run without it;
  - for `phiward launch --tool claude` before Linux 7.1: `socat`, and Claude Code's native
    build, which carries its seccomp filter; `launch` refuses to start without a filter that
    works ([launch.md](launch.md#limits-in-this-release));
  - on Ubuntu 24.04, AppArmor can block unprivileged user namespaces
    (`kernel.apparmor_restrict_unprivileged_userns`). Then bubblewrap cannot start. Change the
    setting, or add an AppArmor profile for `bwrap`. `doctor` says when this is the cause.
- Native Windows has no confinement. Use WSL 2, which is Linux.
- For Claude Code: version 2.1.295 or newer (it needs `onFailure` on hooks). On Linux, Claude
  Code's own sandbox (Mode A) also needs bubblewrap and `socat`; `install` sets
  `failIfUnavailable`, so without them Claude Code stops at start instead of running commands
  unsandboxed. `doctor` checks both.

Without a working confinement backend, the broker refuses to run anything. It fails closed.

## 2. Install

Install a release from PyPI with `uv` (to get `uv` itself:
`curl -LsSf https://astral.sh/uv/install.sh | sh`, or `brew install uv`):

```bash
uv tool install --python-preference only-managed phiward==0.2.0b1
```

Or with `pipx`:

```bash
pipx install phiward==0.2.0b1
```

Name the version: a beta is not chosen without it. The same release from its GitHub tag, without
PyPI: `uv tool install git+https://github.com/msk-access/phiward@v0.2.0b1`. Pin a version or a tag;
do not install a branch. Use `uv tool` or `pipx`: they give phiward a Python folder of its own.
phiward protects the folder of the Python that runs it (the agent may not write there, or it could
change what the broker runs), so an install into a shared environment (a conda base, a project's
`.venv`) would make that whole environment read-only for the agent. They also keep the launcher at
one path across upgrades (`~/.local/share/uv/tools/phiward/bin/phiward`,
pipx's folder, for example `~/.local/share/pipx/venvs/phiward/bin/phiward`), which `phiward mcp wrap` writes into each entry; an
install whose path holds the version (phiward in a Homebrew Python's own site folder) would need
`wrap` again after each upgrade. Check the install:

```bash
phiward --help
```

## 3. The user config: `phiward setup`

`setup` first asks how you will use phiward:

1. **Real patient data** (the default): you give your protected folders; it suggests a results
   folder inside the first one (the one write place, so no `--write-to` is needed), sets the
   program list to `@genomics` plus an optional folder of your own scripts, gives gateway
   commands no network, asks whether shell commands may reach only hosts you list (`[network]`;
   yes is suggested; with yes, `git push` and `pip install` fail until you list their hosts),
   and asks about HPC.
2. **Made-up data**: your folders and a results folder; any program may run.

Every profile also asks which rules mask subject and sample identifiers ([Question
8](#question-8-subject-and-sample-identifiers-sanitize)).
3. **Every setting**: the [questions below](#question-1-protected-roots), one by one.

`phiward setup --from team.toml` starts from a team template (a config file with shared
settings); its settings fill in what your config does not have, and lists are joined with
yours. A template may set only shared settings: the program list (by name or `@` list, not by
path), built-in packs, HPC host names and the programs allowed there, cluster folders to mask,
patterns, and limits (only lower than the defaults). It may never set a write place, the
network, a copy remote, an ssh config, names files, pack files or environment. One kept in a
project (a folder with `.git`, `.claude` or `.phiward.toml` above it) is refused. `setup`
shows every setting in it and asks before it uses them. At the end `setup` writes the
file after your yes, makes the results folder and phiward's ssh config, approves the programs,
wires Claude Code, and installs or restarts the broker service (each with a yes; see
[the end of the dialogue](#the-end-of-the-dialogue)).

The user config holds the facts of your machine: which folders are protected, and what gateway
commands may do. Once step 4 is done, the agent's shell cannot write it, and the hook refuses
the agent's file tools for its usual spelling (not for every spelling: [known gap
2](threat-model.md#gaps-of-the-hook-alone)). Write it with:

```bash
phiward setup
```

Each answer is checked as phiward checks the file later; a
refused answer is asked again, with the reason. Nothing is written until you say yes at the end.
It writes `~/.config/phiward/config.toml` (or the file that `$PHIWARD_CONFIG` names;
see [configuration.md](configuration.md#where-the-files-are)) with mode 0600, and keeps the old
file as `config.toml.bak` (each run replaces the `.bak` file, so copy it away if you want to
keep an older one).

Once a config exists, `setup` is yours only: it refuses to run without a terminal, and the hook
refuses it as an agent command. These two checks are a convenience, not a boundary: a program can
fake a terminal. What stops an agent is that Claude Code's sandbox (or `launch`) denies writes
to the config, `~/.phiward` and the service file. If an agent shows you `phiward setup` as a command to approve,
refuse it.

### The guided first run

**We recommend that you run `phiward setup` yourself**, as above. The guided setup
(`/phiward:setup`) recommends it too, and gives you the commands.

It can also let the agent write the first config: `phiward setup --first-run --root PATH
[--root PATH ...] [--remote host:/path ...]`, with the paths that you type in chat. This works
only while no config exists. It writes protected roots and copy remotes only (each remote's
folder also as a `[remote] root`, so a push can land there), never a grant (no write places, no
network). It refuses a `PHIWARD_CONFIG`, `PHIWARD_SPOOL` or `XDG_*` override
without a terminal.

**When to use it, and what you trust.** Before your config exists, nothing protects the agent's
choices: you trust the agent, in that session, to write exactly what you said, and to install
the broker service and the wiring as they should be. Use it only in a **new** session that has
not read web pages, other people's files or repositories you do not know. Then check what it
wrote: `phiward doctor --show-paths`, in your own Terminal, lists the roots. These limits hold on both
paths:
- a root that is your home folder or above it, in a dot-folder of your home folder, in
  `~/Library` or in a `PATH` folder stays protected, but gateway commands cannot write in it
  (your own tools load code from there);
- a copy remote must name a work folder: not `/`, a folder just below it, a home folder, or a
  dot-folder;
- the broker service skips `PATH` folders inside a project, and folders the agent's sandbox may write
  (a temp folder, also inside your home folder, the spool, an allowWrite folder of your own or
  the managed settings).

The agent-run setup takes `KRB5CCNAME` and the other Kerberos variables from its session, as
your own shell names them. If your ticket cache is in a place other than the default ones, run
the setup yourself.

### Question 1: protected roots

Folders that hold protected data. Give each one as an absolute path or with `~/`, one per line,
and an empty line to end the list.

- Give the folder that holds the data, not a folder above it. A root cannot be `/`, your home
  folder, or a folder above your home folder (the agent could not work at all). `setup` refuses
  these; the loader refuses only `/`, so take care when you edit the file by hand.
- A root cannot hold a phiward file or folder (for example `~/.config`, which holds the
  user config). `setup` refuses such a root.
- Each root must exist; `setup` refuses a missing one. Claude Code's sandbox hides a root only
  when it exists as a command starts.
- Prefer the real path. A root reached through a link is protected, but gateway commands cannot
  write to it (`doctor` says so).
- Keep protected data outside the git repositories that the agent works in. The `.git` folder of
  a work tree that holds a root is protected too, so the agent cannot use git there.

### Question 2: protected patterns (optional)

Glob patterns, such as `/data/runs/*/panel`, for protected places that are spread out. `*` is the
only wildcard, and only printable ASCII is accepted (see
[configuration.md](configuration.md#protected_paths)). Prefer roots: Claude Code's sandbox cannot take patterns, so
on Linux its shell does not count as confined while patterns are set, and the hook then refuses
shell commands other than gateway calls (see [configuration.md](configuration.md#shell)). The
gateway and `phiward launch` still enforce patterns.

### Question 3: write places (`[broker] write_to`)

Folders where `phiward run --write-to DIR` may write. DIR must be one of these folders or a
folder inside one. Use this for result folders, for example `~/projects/study-a/results`.

- Each folder must exist, and you must give its real path (no link on the way). It must not
  hold a `.claude` folder: choose a results folder, not a project folder. (A `.claude` folder
  made there later makes phiward skip the entry.) `setup` shows
  the real path when you give a link.
- A write place cannot be `/`, your home folder or above it, in a dot-folder of your home folder
  (`~/.ssh`, `~/.config`), in `~/Library` or a `PATH` folder, above a protected root, in a
  derived protected folder or a pattern match, hold a names or pack file of the config, or hold
  or be inside a phiward file or folder. It **may** sit inside a protected root: what is written
  there stays protected.
- Gateway commands write only in their own scratch folder and in these places: protected roots
  are read only for them. So a workflow that writes results next to protected data needs a write
  place inside that root, for example `~/data/patients/derived`.
- Each write place gives code that the agent chooses a place to put what it read. To keep the
  gateway as closed as possible, keep this list short.

### Question 4: programs (`[broker] commands`)

The programs gateway commands may run. Empty means any program: then code the agent writes can
run on protected data. For real data, list them: `@genomics` or `@counts` (built-in lists),
program names, your own scripts by full path, or a folder of your scripts as a path ending in
`/`. Interpreters and shells (`python3`, `bash`) run any code: list your scripts instead.
Choice 1 sets `@genomics` and asks for a folder of your own scripts; how a script gets there is
in [daily-use.md](daily-use.md#run-a-script-the-agent-wrote).

### Question 5: network for gateway commands (`[broker] net`)

With yes, `phiward run --net` gets the network. Code that reads protected data could then
send it anywhere. The default and the recommendation is no. `phiward copy` to a configured
remote gets the network for that copy without this setting.

### Question 6: copy remotes (`[copy] remotes`)

Places on other machines that `phiward copy` may copy to or from, as `host:/absolute/prefix`
(through your shared SSH connection: [hpc.md](hpc.md)). For example `cluster:/data/work/study-a`. Leave the list empty if you do not
copy to another machine. Each remote is a place where protected data may go.

A remote copy does not read `~/.ssh/config` (the agent may be able to write it). It reads
phiward's own ssh config (`[copy] ssh_config`), which the HPC questions below write for you; or
write a small one yourself and set `[copy] ssh_config` by hand
([configuration.md](configuration.md#copy)).

### Question 7: network for shell commands (`[network]`)

With yes, the shell commands an agent runs in Claude Code reach only the hosts you list (Claude
Code's own sandbox enforces it). Commands that need the network fail until their hosts are
listed: `git push` needs `github.com` (or your git server), `pip install` needs `*.pypi.org`
and `files.pythonhosted.org`. Claude Code itself, WebFetch and MCP servers are not limited by
it. Each listed host is a way out, so list few. Choice 1 asks this too, with yes suggested.

### Question 8: subject and sample identifiers (`[sanitize]`)

The gateway masks the names of files and folders under your protected roots, and the `genomics`
pack masks sequence file names, read names and loci. A patient, sample or donor ID inside a
file, or in a name outside the roots, is masked only by a rule for its form. Choose:

1. Your data holds no such IDs beyond the names under the roots: setup records
   `subjects = "none"`. This is never the default: type 1 each time.
2. The `msk` pack: one institution's forms. It is an example; copy it for another institution.
3. Your own rules, one per line (`[sanitize] patterns`), each checked as you type it.

Every profile asks this (in choice 3 it is numbered 8). Setup keeps `genomics` in any pack
list it writes, also on a re-run over a list you wrote without it. Until one of these is set,
`phiward doctor` warns.

### The HPC questions

Choices 1 and 3 then ask whether you work with an HPC cluster. With yes, they ask for its short
name, its login host, your user name and work folder there, and the cluster folders to mask.
`setup` adds the work folder to the copy remotes, writes phiward's ssh config and prints the
lines to add to your own `~/.ssh/config` ([hpc.md](hpc.md#one-time-setup)).

### The end of the dialogue

1. `setup` shows the whole new file and the difference from the old one, and asks whether to
   write it.
2. It pins the derived folders ([step 6](#6-pin-the-derived-folders)).
3. When a program is new or changed, it lists the programs of `[broker] commands` as they are
   now, each with its path, and the count ("N found, M not installed here"). Then it asks
   **"Approve these N program(s) as they are now?"** The broker runs only approved programs.
   - The default is **Yes** on a first run (nothing approved before) with nothing marked.
   - The default is **No** when you approved programs before, when a program is marked
     `(changed)`, or when a program in your home folder shadows a system program of the same
     name (marked `(shadows /usr/bin/NAME)`). Read those lines before you say yes.
   - With No, the broker refuses every gateway request while a listed program is not approved,
     until you run `phiward pin` and restart it.
   - A program not installed here is approved when you run `phiward pin` from a terminal where
     it is found.
4. It asks whether to wire Claude Code for every session (step 4). One yes is enough: it shows
   the change and writes it.
5. It asks whether to start the broker at every login, or restart it (step 5).
6. It prints the next steps: what you did not say yes to, then `phiward doctor` in a project
   folder.

`setup` keeps the other sections of an existing file (`[git]`, `unresolved`) and the other
`[sanitize]` keys; it writes `[sanitize] subjects`, `packs` or `patterns` from Question 8. It
does not keep comments; the `.bak` file of this run has them. To set those other keys, edit the file by hand; see
[configuration.md](configuration.md).

## 4. Wire the agent tool

There are two modes ([modes.md](modes.md)). **Mode A**, a normal Claude Code session (the
desktop app, an IDE, a terminal), is what this section wires; it is the usual way for day-to-day
work. **Mode B**, `phiward launch --tool claude`, runs the whole tool inside phiward's kernel
profile and needs no wiring ([launch.md](launch.md)).

Wire your **user** settings, so every session in every folder is protected. Project wiring alone
protects only sessions opened in that folder. The Claude Code plugin
([plugins.md](plugins.md)) can add the skill, the commands and a second check; keep these user
hooks with it. `--no-hooks` writes only the sandbox and permission
settings (for a project whose contributors have user wiring).

### Claude Code

`setup` offers to do this. To do it yourself, first look at what will change:

```bash
(cd ~ && phiward install claude --user)
```

This prints a few `//` comment lines and then the JSON block for `~/.claude/settings.json` (a
long one: it lists every protected path and credential twice, as sandbox entries and as
permission rules). It writes nothing. Then merge it:

```bash
(cd ~ && phiward install claude --user --write)
```

It shows a diff and asks for your yes. It keeps a backup (`settings.json.phiward.bak`).
`--project` writes the project's `.claude/settings.json` with only what is the same for every
contributor (it can be committed) and puts the personal part into `.claude/settings.local.json`
(do not commit it).

Notes:

- Run `setup` and `broker --service` from your home folder (`cd ~`). They take the folder they
  run in for a project, and leave its `PATH` folders (a `.venv/bin`) out of the broker's `PATH`.
  `install --user` reads only your user config, wherever it runs; `install --project` also reads
  the project's `.phiward.toml`.
- `install --user` writes `settings.json` where Claude Code reads it: in `$CLAUDE_CONFIG_DIR`
  when you set that variable, else in `~/.claude` (the file `doctor` reads too).
- `install` only adds entries. When you remove a root from the config, remove it from
  `denyRead` and `denyWrite` by hand.
- Without a terminal, `install --write` refuses unless `--yes` is given. The guided first run
  gives `--yes`, before your config exists. After that, do not give `--yes` to an agent: read
  the diff yourself.

The block has four parts.

1. One `PreToolUse` hook entry with the matcher `*` (every tool). It sets `"onFailure": "block"`: without it, Claude
   Code lets a tool call go on when the hook fails. The command is
   `/bin/sh -c 'V=$(/usr/bin/awk ...) || { ...; exit 2; }; IFS=" "; unset $V; exec /path/to/python -I -m phiward hook claude'`:
   every `PYTHON*`, `LD_*` and `DYLD_*` variable is unset (a project's settings could set them to
   load other code; if `/usr/bin/awk` cannot list them, the hook refuses every call), then
   phiward's own Python runs isolated (`-I`: no user site folder). Before it writes, `install`
   checks that this Python finds phiward with `-I` (an install in the user site folder is not
   seen there) and that `/usr/bin/awk` exists. The plugin's hooks and `install --project` run
   `phiward` by name after the same unset; a project's `env.PATH` would choose that `phiward`, so
   the hook refuses every call while a project sets it, and you should wire your user settings
   too. `install`
   replaces every earlier form of its own hook entries (`.../bin/phiward hook claude`,
   `... -I -m phiward ...`).
2. A `SessionStart` hook (`phiward session-note claude`): every session starts with a short note
   on the rules (the gateway is the intended route). It names no protected path.
3. `permissions.deny`: `Read(...)` and `Edit(...)` rules for every protected root and every entry
   of the hidden list (credentials, tickets, histories). They are a second check on the file
   tools, inside Claude Code.
4. The sandbox block (shortened here; the real one also lists the hidden list):

```json
{
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false,
    "filesystem": {
      "denyRead": ["/data/patients", "/Users/me/.cache/phiward"],
      "denyWrite": ["/data/patients", "/Users/me/.cache/phiward",
                    "/Users/me/.config/phiward/config.toml", "/Users/me/.config/phiward",
                    "/path/to/site-packages/phiward", "/Users/me/.phiward/broker.json",
                    "/Users/me/.local/share/uv/tools/phiward",
                    "/Users/me/.local/bin/phiward",
                    "/Users/me/.local/lib/python3.12/site-packages"],
      "allowWrite": ["/Users/me/.phiward-spool"]
    }
  }
}
```

| Setting | Why |
|---|---|
| `sandbox.enabled: true` | Claude Code runs shell commands in its sandbox. |
| `failIfUnavailable: true` | Claude Code does not start when its sandbox cannot (on Linux it needs bubblewrap and socat). Without it, commands would run unsandboxed. |
| `allowUnsandboxedCommands: false` | The model cannot retry a command outside the sandbox. |
| `denyRead` | Every protected root and the derived folders (the cache folder, the `.git` of a work tree that holds a root). |
| `denyWrite` | The same roots, the phiward config and code, the broker's status file, the Python folder that runs phiward, the `phiward` launcher, the user site folder, and `[copy] ssh_config` when set. An agent that can change these can turn the guard off or change what the broker runs. Run `install` again after you set `ssh_config`. |
| `allowWrite` | The broker's spool folder: a gateway call is a client in the sandbox that writes its request there. |

**Patterns** (`[protected_paths] patterns`): with Claude Code 2.1.236 or newer, `install --user`
also adds each pattern and `pattern/**` to `denyRead`, and on macOS to `denyWrite`. On macOS the
shell can then count as confined with patterns. On Linux the sandbox cannot deny writes to a
wildcard path, so the entries are an extra layer, the shell does not count as confined, and the
hook refuses shell commands other than gateway calls. Protect plain folders (roots) on Linux.

**The `--settings` file.** `install --user --write` also writes
`~/.config/phiward/claude-settings.json`, which sets `sandbox.enabled`, `failIfUnavailable` and
`allowUnsandboxedCommands: false`. Start Claude Code with `claude --settings
~/.config/phiward/claude-settings.json` (an alias in your shell startup file does it): a `false`
given with `--settings` makes the sandbox admin-required, as managed settings would, so a
repository's `.claude/settings.json` cannot turn the sandbox off, add excluded commands or
writable folders, or re-open a folder you deny (Claude Code's
[sandboxing page](https://code.claude.com/docs/en/sandboxing), "Repository settings under an
admin-required sandbox"). The file and its folder are guard files. `doctor` checks the file, but
cannot tell whether a session was started with it, and the hook does not rely on it: it keeps
checking the user and project settings itself.

**After an upgrade, run `(cd ~ && phiward install claude --user --write)` again.** A new phiward can add
guard files; until the sandbox's `denyWrite` covers them, the shell does not count as confined
and the hook refuses shell commands (`doctor` says so).

**The shell is pinned to bash.** `install --user` sets `env.CLAUDE_CODE_SHELL` to `/bin/bash`:
the hook reads commands as bash does. A project's settings that
set `CLAUDE_CODE_SHELL` or `CLAUDE_CODE_SHELL_PREFIX` make the hook refuse every call (a
project's value wins over yours in Claude Code).

An older phiward offered `--shell-prefix`, which ran every shell command through its own kernel
profile. It is gone: Claude Code's sandbox confines the shell. If you used it, run
`(cd ~ && phiward install claude --user --write)` again; it removes the prefix setting (`doctor` warns
while it is there, because every shell command would fail).

**`--block-outside-reads`** (optional, `--user`): sets
`permissions.blockReadsOutsideWorkingDirectories` (Claude Code 2.1.257 or newer: Read, Grep and
Glob refuse paths outside the working folders, in every permission mode) and
`permissions.denyInsteadOfPrompting` (2.1.319 or newer: a call that would wait on a prompt is
refused). Each is written only when `claude --version` is new enough. They are defence in depth
around the project, not a protected-path rule: phiward's own checks are the same with or
without them. `doctor` shows which are on.

**Bash stops asking.** With the sandbox on, Claude Code runs sandboxed Bash commands without a
permission prompt (its `sandbox.autoAllowBashIfSandboxed`, true by default): the sandbox takes
the place of the prompt. `deny` rules and narrow `ask` rules such as `Bash(git push *)` still
apply. To be asked for each command, set `"autoAllowBashIfSandboxed": false` in the `sandbox`
block of `~/.claude/settings.json`; phiward works the same either way.

The shell counts as confined only when all of these hold:

- the settings in the table above are in force;
- `excludedCommands` is empty;
- `network.allowAllUnixSockets` is not true, and `network.allowUnixSockets` is empty (a socket
  such as Docker's reaches a process outside the sandbox);
- no other project settings file that Claude Code may read turns part of the sandbox off;
- none of these is set, because each lets a command reach past the sandbox:
  `filesystem.disabled`, `enableWeakerNestedSandbox`, `allowAppleEvents`,
  `allowNestedUserNamespaces`, `network.allowLocalBinding`, `network.allowMachLookup`;
- no `allowRead` entry re-opens a root;
- no protected patterns are configured.

The hook reads the merged settings: managed settings and their `managed-settings.d` drop-ins,
the project settings, and the user settings in `$CLAUDE_CONFIG_DIR` (or `~/.claude`). The
project settings are `.claude/settings.json` in `$CLAUDE_PROJECT_DIR` and the
`.claude/settings.local.json` that Claude Code reads: at the git repository's root, or a
worktree's main checkout (the project folder when there is no repository, the root is your home
folder, or the root is not yours). A `.git` entry counts only as git counts it: an empty `.git`
folder is passed over, and a worktree's `.git` file must be named back by its worktree entry. Only these files can make the shell count as confined. Every
other `settings.local.json` Claude Code may read, and a project settings file that does not
parse as JSON, can only make it count as not confined. Settings passed with `--settings` cannot be seen. While the shell is confined, the
hook relaxes its text check for shell commands: the kernel guards them. The file tools stay
guarded by the hook only (see the
[gaps of the hook alone](threat-model.md#gaps-of-the-hook-alone)).

The hook also refuses file-tool writes (Write, Edit) to the phiward config, code and status
file, and to any `.claude/settings.json`, `.claude/settings.local.json` and the managed
settings. The shell sandbox's `denyWrite` covers the phiward files for shell commands.

**The strong form is managed settings.** A repository can put `"disableAllHooks": true` or
`excludedCommands` in its own `.claude/settings.json`. Managed settings (installed by an
administrator; a repository cannot change them) with the same block prevent that. The file is
`/Library/Application Support/ClaudeCode/managed-settings.json` on macOS and
`/etc/claude-code/managed-settings.json` on Linux.

### Other tools

Only the Claude Code hook exists (`phiward hook claude`). It also reads the payload that
GitHub Copilot sends when it runs hooks from `.claude/settings.json`.

For another tool, run the whole tool under `phiward launch` (Mode B, [launch.md](launch.md)):
its shell, file tools and MCP servers then run in phiward's kernel profile.

## 5. Start the broker

Open a terminal of its own, outside the agent tool, and run:

```bash
phiward broker
```

Keep it open while the agent works. For each request it prints three lines (its id with the
subcommand, the command's exit code with its line counts, then the code it reported), never
the output. Stop it with Ctrl-C. Only one broker runs at a time.

- It builds each command's environment from its own variables only: `PATH`, `HOME`, `USER`,
  `LOGNAME`, `LANG`, `LC_*`, `TZ` and `TERM`. The program is found on your `PATH`, not on the
  agent's.
- `--max-jobs N` sets how many commands run at the same time (default 4). At most 8 requests per
  job wait; past that, a request is refused as busy.
- It keeps its spool folder at `~/.phiward-spool` (or `$PHIWARD_SPOOL`), and its
  status file at `~/.phiward/broker.json`. When the broker stops, it removes the status
  file.
- It makes the spool folder with mode 0700. It refuses to start when the folder is a link, is
  not yours, or has another mode, and it stops when the folder is moved.

The broker must run in the same user account as the agent, with the same `HOME`,
`PHIWARD_CONFIG` and `XDG_*` variables. `doctor` warns when they differ.

**Or run it as a login service**, so you do not keep a terminal open. You still decide that it
runs; the agent cannot start, stop or change it (the service file is a guard file):

```bash
(cd ~ && phiward broker --service --write)
```

It writes a LaunchAgent (macOS) or a systemd user service (Linux) that starts the broker at
login and again if it stops, with the `PHIWARD_*` and `XDG_*` variables of the terminal you run
it in. Run in your own terminal, it then loads the service, or restarts it when it runs already
(`launchctl` or `systemctl --user`); without a terminal it only prints those commands. It also
prints the commands that remove it. Its log is in `~/Library/Logs/phiward` (macOS) or
`~/.local/state/phiward` (Linux), which no session can read; `phiward doctor` shows whether it
is running. The gateway is then available whenever
you are logged in; every request is still checked against your config.

## 6. Pin the derived folders

`phiward setup` does this each time it writes the config. After the
guided first run, or after you edit the config by hand, do it yourself (`phiward doctor` notes
when they are not pinned). In your own terminal:

```bash
phiward pin
```

It records, now, the folders phiward protects without being told (the `.git` of a work tree
that holds a root, snapshot folders next to a root, other mounts of the same data), so a file
the agent plants later cannot hide them. It also lists the programs of `[broker] commands` as
they are now, and approves them with the same yes. Then restart the broker, so it uses the new
pins; `pin` ends by printing the command: `(cd ~ && phiward broker --service --write)`.

## 7. Check with doctor

In the top folder of each project where the agent works (it reads `.claude/` there):

```bash
phiward doctor
```

It prints, among others:

- the config files in use, and the counts of roots, patterns and derived folders;
- whether the confinement backend works here;
- whether the sanitizer starts;
- the grants: the number of write places (and the ones skipped, with why), network yes or no,
  the number of copy remotes;
- whether the broker runs, and whether it uses the same config as this shell;
- keys that a repo config set but may not set (they are ignored);
- for Claude Code: each settings level, whether phiward is wired with `onFailure: "block"`,
  and whether the sandbox confines the shell (and if not, why not).

One WARNING says that your user config enables no pack that masks subject or sample
identifiers: add one with `phiward setup` (Question 8), or record `[sanitize] subjects = "none"`.
A repo's `.phiward.toml` cannot clear it.

Fix each line that starts with PROBLEM or WARNING (`doctor` exits with 0 even when there are
WARNING lines). It also warns when the current folder is inside or above a protected path.

`doctor` shows the protected paths only as counts; add `--show-paths` to list them. It always
names the files it reads, and a PROBLEM line can quote a path from the config. Run it in your
own terminal when the paths are sensitive: when an agent runs it, the output reaches the model.

## 8. Try it on made-up data

Do this once, with a made-up folder, before the agent sees real data. Make a folder with a fake
file, for example `~/phiward-trial/FAKE-PT-0001.txt` holding `FAKE-CONTENT`, and add `~/phiward-trial` as a
root (run `(cd ~ && phiward setup)` again, and let it wire Claude Code again, so that the sandbox
covers the new root). The broker must run (step 5). Then, in a project folder:

```bash
phiward run -- ls ~/phiward-trial
```

This must print `<ENTRY>` in place of the file name, a note that counts it, then
`run done: exit=0 ...`.

```bash
phiward run --net -- true
```

With `net` not set, this must print `run refused: --net is not granted`.

Then the real test, in the Claude Code desktop app: open a **new** session in a project folder,
and ask the agent (1) to read `~/phiward-trial/FAKE-PT-0001.txt` with its Read tool, (2) to run
`cat ~/phiward-trial/FAKE-PT-0001.txt`, (3) to run `phiward run -- wc -l ~/phiward-trial/FAKE-PT-0001.txt`.
The first two must be refused; the third must print a count with the name masked. Also ask it to
edit a file and run a script in the project: those must work. Remove the trial root
afterwards, from the config (with `setup`) and from `denyRead` and `denyWrite` in the Claude Code
settings (by hand).

## 9. Per repository

### `.phiward.toml`

A repository can commit `.phiward.toml`. It can only add protection: more roots and
patterns, built-in packs, protected branches, a stricter `unresolved`, a lower
`inventory_limit`. It cannot grant anything: `write_to`, `net`, `remotes`, sanitize rules and
pack files come from the user config only. A repo config or a template cannot set
`[sanitize] subjects`, and a pack a repo config adds masks but does not clear doctor's warning
about subject identifiers. A root that only a repo config adds is protected from
the agent, but gateway commands cannot write to it. See
[configuration.md](configuration.md#the-repo-config).

### Git hooks

```bash
phiward git-hook install
```

This writes `pre-commit` and `pre-push` hooks in the current repository (it refuses to replace a
hook that is not its own, unless you add `--force`).

- `pre-commit` refuses a staged file inside a protected path, and an added line or file name
  that holds an identifier.
- `pre-push` refuses a push to a protected branch. It does nothing until you list branches in
  `[git] protected_branches` (by hand; `setup` does not ask).

They print only sanitized names, line numbers and placeholder words. A human can bypass them with
`--no-verify`; an agent must not.

## Change the setup

Run `(cd ~ && phiward setup)` again. It starts from the current file: for each list it shows what is
there and asks whether to start that list again. Or edit the file by hand and run
`phiward doctor`. A bad file makes every guarded action refuse until you fix it.

After you add a root, wire the agent tool again
(`(cd ~ && phiward install claude --user --write)`), so that its sandbox lists it; `doctor` says when a root is not covered. After you
remove a root, remove it from `denyRead` and `denyWrite` by hand (`install` only adds).

**Restart the broker after every change.** The broker takes a fingerprint of the config, the
pins and the names and pack files the config names when it starts, and refuses requests when
their content changes, until you restart it. Saving the same text again changes nothing. So a
config that something else changes has no effect until you have read it. On macOS:
`launchctl kickstart -k gui/$(id -u)/org.phiward.broker`; on Linux:
`systemctl --user restart phiward-broker.service`; or stop `phiward broker` and start it
again.

## Upgrade from agent-guards 0.1.0

phiward was called agent-guards before 0.2.0b1.

1. Uninstall agent-guards first (`uv tool uninstall agent-guards`, or
   `pipx uninstall agent-guards`): phiward also installs an `agent-guards` command, so the
   installer refuses while the old one is there. Then install phiward (step 2).
2. Move your config: `mv ~/.config/agent-guards ~/.config/phiward`. In each repository, rename
   `.agent-guards.toml` to `.phiward.toml`. Until you do, phiward refuses, because the old files
   may protect paths.
3. Wire Claude Code again: `(cd ~ && phiward install claude --user --write)`. This replaces the
   old hook entries.
4. Delete `~/.agent-guards` (sessions cannot read it).

The command `agent-guards` stays as an alias of `phiward` during the beta.

## Remove phiward

1. Unwrap your MCP servers first: a wrapped entry names phiward's launcher, so it fails to start
   once phiward is gone. `phiward mcp list` names them; `phiward mcp unwrap NAME` for each.
2. Remove the phiward entries from the agent tool's settings (the backup from `install` has
   the old file), and the `alias claude='claude --settings ...'` line if you added one.
3. Stop the broker. If it runs as a login service: `launchctl bootout gui/$(id -u)
   ~/Library/LaunchAgents/org.phiward.broker.plist` and remove that file (macOS), or
   `systemctl --user disable --now phiward-broker.service` and remove the unit (Linux).
4. In each project where you ran `phiward init`: remove the git hooks from `.git/hooks`, the
   phiward section of `AGENTS.md`, and the phiward entries of `.claude/settings.json` and
   `.claude/settings.local.json`.
5. Uninstall: `uv tool uninstall phiward` (or `pipx uninstall phiward`), and the plugin if you
   added it (`/plugin uninstall phiward`).
6. Remove `~/.config/phiward`, `~/.phiward`, `~/.cache/phiward`, `~/.phiward-spool` and the
   broker's log (`~/Library/Logs/phiward` on macOS, `~/.local/state/phiward` on Linux).
