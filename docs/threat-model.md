# Threat model and limits

**For:** people who decide whether phiward is enough for their data.

This page says what is protected, against whom, and where the limits are.

## For reviewers: the summary

- **What leaves the machine:** what the agent tool sends to its model provider: your prompts, the
  files and output the agent reads, and the masked output of gateway commands. phiward keeps
  protected files, credentials and unmasked gateway output out of that.
- **The network is open by default in both modes.** phiward does not stop the agent from sending
  what it can read. It stops the agent from reading protected data. In Mode A, `[network] limit`
  lets the shell commands reach only listed hosts. Claude Code's own sandbox enforces it. The
  WebFetch tool, MCP servers, commands a project excludes from the sandbox, and Mode B stay open.
  Each listed host is itself a way out (a push, a gist, a host behind a shared CDN).
- **Trusted:** the operator, the operator's terminal, the user config, the broker, the operating
  system and its sandbox (Seatbelt on macOS; bubblewrap, seccomp and Landlock on Linux), and Claude
  Code's own sandbox and permission rules in Mode A.
- **Not trusted:** the agent, everything it writes, and the code it runs.
- **Who it is built against:** an honest user, and an agent that text it reads (prompt
  injection) can turn against the user. phiward is not built to stop a determined attacker who
  already runs code on the machine with the user's rights. Some routes such an attacker could
  use are stated as limits below.
- **Masking hides names and identifiers, not other content.** Gateway commands should print counts
  and summaries, not records, and hide small counts ([Small counts](daily-use.md#small-counts)).
- **What stops what.** The kernel is the strongest guard:

| What the agent tries | Mode A stops it with | Mode B stops it with | The main limit |
|---|---|---|---|
| A shell command reads protected data or the hidden list | the kernel: Claude Code's sandbox | the kernel: phiward's profile | other hard links and other mounts ([the shell sandbox](#the-shell-sandbox-the-strongest-layer)) |
| A file tool (Read, Grep, Glob, Edit) reads them | the hook and Claude Code's permission rules, not the kernel | the kernel | a spelling that both miss ([Mode A](#mode-a-a-claude-code-session)) |
| An MCP server or a hook of the tool reads them | nothing, unless the server is wrapped in `phiward launch --` | the kernel | not wrapped, they run with your rights ([gaps of the hook alone](#gaps-of-the-hook-alone)) |
| A gateway command prints protected data | masking of names and identifiers | the same | other content, and a command written to leak ([the gateway](#the-gateway-a-controlled-opening)) |
| It sends out what it can read | nothing by default; `[network] limit` for shell commands only | nothing: the network is open | each listed host is itself a way out |
| It uses credentials that are not files (the Keychain, tokens in the environment) | nothing: a file list does not hide them | Linux: the kernel keyrings are blocked; macOS: the Keychain stays reachable. Only a short list of environment variables is passed | [Mode A](#mode-a-a-claude-code-session), [Mode B](#mode-b-phiward-launch) |

- **What was tested**, on made-up data:

| What | Where | Result |
|---|---|---|
| Mode A: the real Claude Code desktop app, wired by `install claude` | macOS | reads of protected data and credentials refused (Read tool, `cat`, Monitor), `ssh` to HPC failed, normal work unaffected |
| Mode A with the plugin only | macOS, desktop app | session note given, reads refused by the hook; no sandbox or permission rules without `install` |
| Mode B: the real Claude Code under `phiward launch` | macOS | file tools and shell refused protected data; gateway output masked; skills and an MCP server carried over |
| An MCP server wrapped in `phiward launch`: a small stdio server driven the way Claude Code drives one, and on Linux the published `@modelcontextprotocol/server-filesystem` 2.3.0 | macOS, Linux | works; refused protected data and credentials. Wrapped, the published server read ordinary files and could neither read nor list a protected folder; unwrapped, it read both |
| HPC through the shared SSH connection | macOS to a real cluster | remote runs, push, pull, refused push of `~/.ssh`, refusal without the connection |
| The full test suite (over 1,000 tests) | macOS; Linux (bubblewrap) | passes |

- **Not tested:**
  - the real Claude Code on Linux (only the test suite);
  - `phiward launch` driven from the app with Remote Control;
  - a published MCP server under `launch` on macOS (on Linux it was);
  - a protected folder on a mounted HPC volume;
  - `[network] limit` in a live Claude Code session (the settings it writes are tested; Claude
    Code enforces them);
  - other agent tools than Claude Code.
- **Independent reviews:** each part had adversarial reviews before this release, and each finding
  was fixed or is listed on this page as a limit.

## What is protected

The asset is protected data (for example patient data, sample identifiers, file names under a
protected folder). The leak path is **tool output**: everything an agent's tools print goes to the
model provider. phiward keeps protected data out of that output. Its git hooks also keep protected
files and identifiers out of commits, and pushes off protected branches. They work against a
careless agent: a deliberate commit with `--no-verify` (or a changed `core.hooksPath`) skips them.

## Against whom: read this first

**This release has two modes** ([modes.md](modes.md)), and they protect against different
agents:

- **Mode B (`phiward launch`)** is meant as a boundary against a hijacked agent, for what is on this
  machine. A hijacked agent is one under prompt injection that tries on purpose to get the data out.
  The whole tool, its file tools, MCP servers and hooks included, cannot read protected data or the
  hidden list. Its limits are in [Mode B](#mode-b-phiward-launch) below.
- **Mode A (a Claude Code session wired by the hook)** confines Bash with Claude Code's own sandbox.
  It refuses protected data and the hidden list to the file tools inside Claude Code (the hook and
  permission rules, not the kernel). It stops a careless agent and makes a deliberate one work hard.
  It is not a kernel boundary for the file tools, and hooks and MCP servers that are not wrapped run
  with your rights. See [Mode A](#mode-a-a-claude-code-session).
- **The hook alone** (without Claude Code's sandbox or `launch`) guards against a careless agent
  only: [the gaps of the hook alone](#gaps-of-the-hook-alone).

In every mode, the agent works on protected data only through the gateway, and the gateway's masking
hides names and identifiers, not other content.

The operator, the operator's terminal and the user config are trusted. The agent can run any command
it likes in its own shell, write any file it can write, and choose what it asks the gateway to run.

## The boundaries

### The shell sandbox: the strongest layer

The kernel confines the agent's **shell**. In Mode A it is Claude Code's sandbox, with the entries
`(cd ~ && phiward install claude --user --write)` writes. In Mode B (`phiward launch`) it is
phiward's own profile, for the whole tool. An agent shell command cannot read or write anything in a
protected root (or, on macOS, a pattern match), the hidden list, or the phiward config, code or
status file. Claude Code's sandbox also keeps its own settings files, `.mcp.json`, the project's
`.git/config` and hooks, the working folder's own `.vscode` and `.idea`, and the shell startup
files from being written. A nested `.vscode` or `.idea` (`sub/.vscode/tasks.json`) is not in
that list: VS Code and JetBrains read one only when you open that subfolder as a workspace or
project, and a rule for every depth would deny `npm install` and `git pull` in every project.
The hook asks before a file tool writes one; a shell command can. Git's other control files are
a known limit (see "Git's control files" below). Links, letter case, nested shells and child
processes are covered for ASCII paths, because the kernel does the check. Exceptions (gaps 8, 9):
other hard links to a protected file, other mounts of the same file system, and a root spelled
`/System/Volumes/Data/...`. phiward does not confine the shell itself in Mode A. It checks that
Claude Code's settings confine it (`doctor`), and the hook refuses shell commands when they do not.

It does not cover everything: the agent tool's own file tools (Read, Grep, Glob, Edit), its MCP
servers and its hooks run **outside** the kernel profile, and a few path spellings and pattern forms
are not enforced by the kernel. See [the gaps of the hook alone](#gaps-of-the-hook-alone).

### The gateway: a controlled opening

The gateway (`phiward run`, `phiward copy`) runs the command the agent asks for, with read access to
the roots. What it can do besides is fixed by the user config:

| Channel | Default | Opened by |
|---|---|---|
| Output to the agent | always, sanitized | — |
| Writes | its private scratch folder only (protected roots are read only) | `[broker] write_to` + `--write-to` (may sit inside a root); a copy's own destination |
| Network | none | `[broker] net = true` + `--net`; a copy to a `[copy] remotes` entry |
| Other processes | none (see below) | macOS: `net = true` also allows name lookups; unix sockets stay blocked |
| Its environment | the broker's allow list only | — |

The program runs from the broker's `PATH`, which keeps only folders the agent cannot write. A folder
is dropped when it is relative, writable by others, inside a project, or a folder the agent's
sandbox may write. Those are a temp folder (inside your home folder too), the spool, and the
allowWrite and additionalDirectories folders of your own and the managed settings. The broker does
not know a project's own settings. So a project whose settings open a `PATH` folder of yours to
writes (allowWrite `~/bin`) lets the agent put a program there, and a gateway call may run it (still
confined, with its output sanitized). Keep tools out of folders a project opens.

On macOS the broker writes each request's profile to a new file in `~/.phiward/profiles` (a
random name, made only if no file has that name, mode 0600, read back before use) and runs
`/usr/bin/sandbox-exec -f` on it; the file is removed when the command ends. `phiward launch`
writes the tool's profile there the same way and runs `/usr/bin/sandbox-exec -f FILE TOOL`, with
no program in between; the file is removed when the tool ends. No session can write
that folder (Claude Code's sandbox denies `~/.phiward`; under `launch` it is not a write place),
and the hidden list keeps the session's shell, its file tools and every gateway command from
reading it; under `launch` the tool's own profile denies reading it. A request is refused when
`~/.phiward` is a link, another account's, or writable by other accounts, or when `profiles` is a
link or another account's; `profiles` is made 0700.

On macOS phiward puts no code in a local command line: no `python -c`, no `sh -c` of its own, no
awk program and no `sandbox-exec -p`. Its hooks run files of the package (exec form), and the
pull's extractor is a file too. Two exceptions: the command that ssh carries to the remote host,
which runs there (a push's is a fixed `sh -c` script), and the project hook's fixed line
(`install --project`). Words that the agent or the user chose (a gateway command, a wrapped
server's command) keep their own shape. [endpoint-security.md](endpoint-security.md) lists every
process and its command line; `tests/test_macos_processes.py` records them and checks the list.

"Other processes" means: no clipboard, notifications, unix sockets, signals or views of other
processes. macOS denies Mach services, and both macOS profiles also deny mounting file
systems and creating launchd jobs; Linux uses seccomp, Landlock and new IPC and PID namespaces.
For the agent tool under `launch` on Linux, unix sockets are limited as
[below](#open-unix-sockets) says.

The sanitizer masks protected paths, entry names under the roots, and identifiers from the packs.
Out of the box, only file names, read names and loci are masked inside file contents; `phiward
doctor` warns until a pack or rule for subject identifiers is on, or `subjects = "none"` is
recorded.
This stops **accidental** leaks from ordinary tools (`ls`, `find`, error messages, tracebacks). It
also covers a name that a tool writes with escapes: git's octal quoting (`\303\274`), JSON's and
Python's `\u00fc` and `\xfc`, and a URL's `%C3%BC`. A line whose decoded form holds a name is withheld.
It does not stop a command that is written to leak: `base64`, HTML entities, splitting a name into
parts, or printing content that is not an identifier all get past it.

### Grants and the safe setting

A grant gives code that the agent chooses that capability. With a write place, that code can put
what it read where something else may pick it up. With the network, it can send what it read
anywhere. A copy remote is a place where protected data may go.

**Protected roots are read only for the gateway.** It writes only in its scratch folder, in the
`write_to` folders you grant (which may sit inside a root), and at a copy's destination. A grant is
refused where your own tools load code later (the home folder or above it, its dot-folders,
`~/Library`, `PATH` folders) and where it would hold a names or pack file. A copy remote must name a
work folder. A copy never goes into a dot-folder. A push refuses a destination that is your home
folder on the cluster or above it (checked there, by real path). A push never sends files that run
at login (`.bashrc`, `.ssh`, `.gitconfig`, `.envrc`) or any dot-name at the top of its destination.

**The broker takes the config it started with.** It records a fingerprint of the user config, the
pins, and the names and pack files the config names at start, and refuses every request after their
content changes, until the operator restarts it. So a change that the agent manages to make does not
take effect unseen. The repository config (`.phiward.toml`) is not part of it: it can only add
protection. A request that starts just as the config changes may still use the new one.

**Terminal checks are a convenience.** `setup`, `pin`, `pseudonymize` and `carryover
add|accept|reset` refuse to run without a terminal, but a program can fake one. What stops an
agent from changing them is that Claude Code's sandbox (Mode A) or the kernel profile (Mode B)
denies writes to the config, `~/.phiward` and the service file, and hides
`~/.phiward/backups` (the pseudonymize keys) from every session and gateway command. A plugin-only session, with no sandbox, has only the hook.

**To make the gateway itself as tight as it can be, set `write_to` empty, `net` false, `remotes`
empty.** Then the only way out of the gateway is its sanitized output, and the only leak through it
is a command written to encode data on purpose. This does not make the hook alone safe against a
hijacked agent: the file tools, MCP servers and hooks run outside the kernel profile (gaps 1–6).

### Why nothing asks at run time

Earlier versions asked the operator to approve grants, first on the broker's terminal, then in a
native dialog. Reviews showed that both are in reach of the agent's code. It runs in the same user
session, so it can write to the terminal, draw a window over the dialog, or (on X11, or with
Accessibility permission on macOS) send it input. Approving a command's words does not approve the
code it loads (its scripts, `.git/config`), which the agent can write. So grants are now decided
ahead of time, in the user config. The agent's shell cannot write it; the agent's file tools are
refused by the hook for its usual spelling only (gap 2). `phiward setup` is a dialogue, but a
first-time one, in the operator's own terminal. Its result is a file the operator reads before it is
written.

### The hook: a first layer

The hook guards the file tools, which a shell sandbox does not cover, and checks shell command text.
Where the shell is kernel-confined, the text check is relaxed for shell commands; that relaxation
trusts Claude Code settings files that phiward does not itself deny (gap 17). For the file tools,
the hook is the only guard, and it checks paths as text: that is enough for a careless agent, not
for one that tries (see gaps 1 and 2 below).

**Without the kernel, shell commands are refused; the text check is best effort.** Where no kernel
confines the shell (Claude Code's sandbox off or not there), the hook refuses its commands by
default ([configuration.md](configuration.md#shell)). Only with `[shell] best_effort` on does it
check their text instead. Shell text cannot be read completely, so that check is a first layer: for
real data, use the sandbox or `phiward launch`, where the kernel decides. What the text check does:

- It refuses (by `unresolved`, deny by default) every word it cannot read whole:
  - a path built from `$(...)`, backticks, a special parameter (`$1`, `$_`, `${1:-x}`, `$((...))`,
    `$[...]`) or variables the command sets, joined to other text (`ph$(echo i)`, `X=../ph; Y=i/f;
    cat $X$Y`);
  - a variable whose value is made over several steps (`X+=`, `printf -v`, `read`, `mapfile`, two
    assignments);
  - any `$'...'`, and a `${NAME...}` with a modifier (`${HOME:-x}`);
  - `cd -`, `popd`, a `cd` to a folder built from variables, `find -execdir`, a `cd` word it does
    not read as a command, and `$PWD` after a `cd` in the line;
  - a `..` after a folder that does not exist yet and, in a line that runs `ln`, any path through a
    name that does not exist yet (the line may make it a link);
  - a zsh or extglob group outside quotes, comments and heredocs, and text it cannot parse.
- It follows the folder a command runs in: `cd` and `pushd` after a keyword or in a group or
  function (`then cd d`, `{ cd d; }`), `cd` with no folder (`~`), and the folder options of `git
  -C`, `make -C`/`--directory`, `tar -C` and `env -C`/`--chdir`. A line of plain steps (`;`, `&&`)
  reads each step from the folder the steps before it left (`cd build && cmake ..`); any other line
  reads every step from every folder it names.
- It reads shell code passed as text: the string after `sh -c` (and `bash`, `zsh`, `dash`, `ksh`),
  the words of `eval`, and the heredocs a shell reads.
- It counts a dot glob (`.*`, `.?`) as `..` too: bash before 5.2 expands it so.
- It lets through, as ordinary text: `$(...)` and variables in the words of an `echo` or `printf` at
  the top of a line that defines no function and does not pipe their output on, `$(pwd)` and `$PWD`
  when the line does not change folder, and a `cd` to exactly one `$(...)`. A `for` loop's variable
  is like any other variable the line sets.
- It accepts, and only the sandbox stops: a path printed by a command (`cat $(printf ...)`, `cd
  "$(cmd)"`) or built by an interpreter (`python -c`, `awk`); a word that is exactly one `$(...)` is
  judged by the command inside it.
- Not yet covered, so only the sandbox or `launch` stops them: commands run through another program
  (a wrapper in front of `sh -c` or `ln`), some ways of changing the folder a command runs in,
  recursive commands that follow links, names made by moving or copying, and shell code given on
  standard input. Closing them is planned.

In the sandbox all of these are the kernel's to stop. A path whose written form passes through a
protected folder (`../phi/x/../../repo`) is refused in every mode, whether or not the names on the
way exist.

**A wildcard gets one verdict, whatever a protected folder holds.** Who stops a read decides what
the hook does with a glob:

- **A shell in Claude Code's sandbox:** the kernel stops a read of a protected path or a credential,
  so the hook decides from the pattern alone, against your roots and patterns, and never lists the
  disk. `cat /data/p*/G*` and `cat /data/p*/F*` are both refused; `cat lea*` (a link the agent made
  to protected data) is allowed by the hook and refused by the kernel.
- **A shell without the sandbox, and the file tools:** the hook is the guard. It decides from the
  pattern against your roots, patterns and the hidden list (`*` names dot entries too), then walks
  where the glob can go and checks every link a glob part matches: its target, then the rest of the
  glob from there. A link to a folder is followed, as the shell follows it. A literal part is looked
  up by name (a folder that cannot be listed hides nothing); names are compared in every case and
  Unicode form; a file or folder that is a root under another name (a mount, a hard link) counts. No
  folder that is, or can lead the glob into, a protected path is listed. Under `**`, a link into a
  protected folder refuses the glob (the shell would walk into it only if it is a folder, and only
  the protected folder knows that). More than 200 000 names listed (each folder counted once) and
  entries looked at, or `..` after a wildcard, are refused with their own reason; nothing is cut
  short. In the sandbox, `..` after a wildcard is read as text over the whole path
  (`repo/*/../../phi` is `phi`). Bracket classes and `?` count as any text (a superset); `.` parts
  are dropped as the shell drops them. A file tool's glob is also read with its braces expanded,
  backslashes dropped and extglob groups (`@(a)`, `!(a)`, `(a|b)`, nested ones too) as `*`; a group
  that spans folders (`(a/b|c)`) is refused.

**A project's settings can run code before phiward starts.** Claude Code applies a project's `env`
to hooks, and starts a hook's command with `sh -c`. A project's settings can add hooks of their own,
and its `env` can make that shell run code (`SHELLOPTS=xtrace` with a `PS4` that holds `$(...)`),
before phiward runs. So phiward cannot guard against project settings it did not write. The guard
keeps the agent from writing them (`.claude/settings*.json` and `.mcp.json`, by the hook outside the
sandbox and by the sandbox inside it). You trust the project settings you bring in (gap 17).

**What Claude Code runs as code, and where the file tools write (Mode A).** The hook sees every tool
(its matcher is `*`; about 85 ms per call). Claude Code's built-in tools that only carry text
(Agent, Task, TodoWrite, AskUserQuestion, plan mode, SendMessage, ToolSearch) are not text-checked:
a subagent's own tool calls reach the hook. For a write, in this order:
1. Refused in every mode, by every writer the hook sees: phiward's own files, the shell's start-up
   files, every Claude Code settings file and `.mcp.json`, anything inside a `.git` folder and any
   file named `.git`, `~/.gitconfig` and `~/.config/git/`, and a `phiward` in any PATH folder. Why
   `.git`: git runs what its config, hooks and `commondir` name, and Claude Code runs git outside
   its sandbox. A writer the hook sees is a file tool, or an MCP server's tool that names the file
   itself. The hook does not see a bare server's tool that moves a whole folder above one. A bare
   server runs with your rights anyway: wrap it.
2. Asked or refused: what Claude Code runs as code, and what an editor or a tool runs. Claude Code's
   code is skills, subagents, commands, hooks, workflows, plugins, routines, `launch.json` and
   `scheduled_tasks.json`, under any `.claude` folder but its `worktrees`, and under the user config
   folder. An editor's or a tool's is any `.vscode`, `.idea`, `.cursor`, `.gemini` or `.codex`
   folder, `.gitmodules`, `.ripgreprc`, `.Rprofile`, `.Renviron`.
   The hook asks you in the modes known to prompt (`default`, `acceptEdits`, `plan`). It refuses in
   every other (`bypassPermissions`, `dontAsk`, `auto`, a missing mode). A skill or subagent may
   hold hooks that run with your rights: allow it only after reading it.
3. A file tool's write outside the folders the sandbox lets the shell write (the project, the temp
   folder, `allowWrite`, `additionalDirectories`) and Claude Code's memory and plans folders: asked
   or refused, as in 2. To stop the prompts for a folder, add it to
   `permissions.additionalDirectories` in your user settings.

The app's own tools that start the project's code are asked or refused as in 2. They are the
preview, the simulator's `build` and its `launch` action, and changing the session's folder. The
preview's `preview_start` runs the command `.claude/launch.json` names. In a check in the desktop
app it ran outside the sandbox, although the project turned the sandbox on. Tools that name a folder
by a path field and are not MCP tools (Copilot's `list_dir`, `file_search`), and the app's browsers
with a `file:` URL, are also judged as a search: a folder above protected data is refused. Not
covered: a script the browser runs in a page (`javascript_tool`, `execute_javascript`). It can open
a `file:` URL it builds itself; its text is checked only. The app's browser reads with your rights:
keep it out of protected work.

A shell command in the sandbox meets Claude Code's own rules: from version 2.1.318 its sandbox
denies writes to the working folder's settings, skills and hooks and the user folder's code folders.
Not covered: a `.claude` folder below the working folder, folders added with `/add-dir`, and older
versions. A script that a settings file names (a hook, `statusLine`, `apiKeyHelper`) runs too: keep
it in your user folder's `hooks/` (`~/.claude/hooks/`), which no session in a project writes;
`phiward doctor` names one that a session can write.

A Claude config folder is known by what it is. It is the `.claude` of every folder above the file
written and above the project, where it really leads (a link, also one whose target is not made
yet). Its settings and code places count where they really lead (`skills -> ../shared/skills`, a
stow-managed `~/.claude`). From those code folders one list of code roots is built for each call.
The file tools and MCP tools meet it, and `doctor`. The list holds:
- every link inside the code folders, followed until nothing new turns up (a skill, an agent or a
  command linked in one at a time, and links inside those);
- the plugin folders that `CLAUDE_CODE_PLUGIN_CACHE_DIR` and `CLAUDE_CODE_PLUGIN_SEED_DIR` name. In
  `plugins`, links are followed only to where an install is (`marketplaces/NAME`,
  `cache/MARKETPLACE/PLUGIN/VERSION`): a link deeper in a plugin is its own, in a folder the agent
  cannot write;
- a linked tree past 50,000 entries as a whole; its deep links are not followed (`doctor` names it);
- no link to `/` or to a folder that holds your home folder (it would hold every write). `doctor`
  names it too.

A write in a root or below it is asked or refused (as 2 above). **The shell is not held by this
list**: Claude Code's sandbox denies the real path of its own code folders only. So a skill linked
in from a folder a session can write (the project, the temp folder) can be changed by that session's
shell. `doctor` names each such link with its one step (replace the link with a copy). Not seen: a
`.claude` link below the working folder that is off the path to the file written, a folder added
with `--plugin-dir`, and a `directory` marketplace's own folder (Claude Code copies from it into its
cache). A file tool's write to a file with another name (a hard link, `nlink > 1`) is asked or
refused, since that name may be a code file. This check is for the built-in file tools only: an MCP
server's tool is not checked for it.

What phiward does with a project's `env`:

- Its hooks start a shell script from phiward's package (the user wiring and the plugin, in exec
  form: no inline code), or `/bin/sh` by absolute path (`install --project`). They unset the
  variables that make Python or a library
  load other code or read a file they name. These are: every `PYTHON*`, `LD_*`, `DYLD_*`,
  `OPENSSL_*`, `MALLOC_*` and macOS `Malloc*` variable; `__PYVENV_LAUNCHER__` (macOS framework,
  conda and Homebrew Pythons read it even with `-I`); `GCONV_PATH`, `LOCPATH`, `NLSPATH`,
  `GLIBC_TUNABLES`, `HOSTALIASES`, `LOCALDOMAIN`, `RES_OPTIONS`, `RESOLV_HOST_CONF`, `NIS_PATH`,
  `TZDIR` and `GETCONF_DIR`; and a `TZ` that names a file (`/...`, `:/...`; a zone name stays).
  `/bin/sh` and awk read the loader's and allocator's variables and `GCONV_PATH`/`LOCPATH` before
  they are unset; `doctor` notes a project that sets them. A phiward whose Python needs `PYTHONPATH`
  or `LD_LIBRARY_PATH` cannot start after the clean-up, so every call is refused; `doctor` says so.
  The variables are listed by `/usr/bin/awk` (by absolute path). When awk cannot run, the hook
  refuses every call (exit 2) instead of running with them. This is a list of known names, not an
  allow list: the hook itself reads `XDG_*`, `CLAUDE_CONFIG_DIR`, `KRB5*` and the variables an SSH
  setup uses. The user wiring then runs phiward's Python isolated (`-I`).
- The plugin's and `install --project`'s hooks run `phiward` by name. A project `env.PATH` could
  make them run another program called `phiward`, which may allow every call: the refusal of `PATH`
  below comes from phiward, which then never starts. For real data, wire your user settings (`(cd ~
  && phiward install claude --user --write)`: absolute paths, `-I`); `doctor --headless` requires
  that wiring.
- `LD_*` and `DYLD_*` reach the shell and awk before they are unset: a project that sets them can
  load code there. They are not refused (projects set `LD_LIBRARY_PATH` for their builds); `doctor`
  notes them.
- The hook refuses every tool call, and names the file, when a project's settings set one of the
  variables below, or when a project settings file does not parse (an empty one is `{}`). `doctor`
  names them too. The refusal comes after such a shell has run: it tells you, it does not undo.
  - `PHIWARD_*`, `KRB5*`, `USER`, `LOGNAME`, `CLAUDE_PROJECT_DIR`;
  - `PATH` (it chooses the `phiward` the plugin's and project hooks start);
  - `CLAUDE_CODE_SHELL_PREFIX` and `CLAUDE_CODE_SHELL` (a project's would win over yours);
  - a variable that makes the shell run code (`SHELLOPTS`, `BASHOPTS`, `PS4`, `BASH_ENV`, `ENV`,
    `PROMPT_COMMAND`, `IFS`, `CDPATH`, `GLOBIGNORE`, `BASH_FUNC_*`).
- The hook reads the settings of every project a call may belong to: `$CLAUDE_PROJECT_DIR`, and
  every folder at or above the call's own folder that holds `.claude` or `.git` (not the home
  folder). So a submodule or a folder with its own `.claude` cannot hide the project's settings. A
  redirect in any of them refuses every call. A project `env` that points `CLAUDE_PROJECT_DIR`
  elsewhere cannot hide its own settings that way. The shell counts as confined only when
  `$CLAUDE_PROJECT_DIR` is the call's folder or above it (letter case as the volume stores it), and
  the named project and every project folder in it above the call confine it. Folders above the
  named project do not decide it. A call in a folder added outside the project gets the best-effort
  check below.
- Claude Code itself ignores `HOME`, `TMPDIR`, the `XDG_*` family and `CLAUDE_CONFIG_DIR` in a
  project's `env`.
- The user wiring's and the plugin's hooks are in Claude Code's exec form (`args`, no shell
  between Claude Code and the script). Their command is the script itself: a Claude Code that
  ignores `args` runs it with no arguments, and it refuses (exit 2). It reads no input. That
  holds only when the script's path has no space or other character a shell splits on: an
  older Claude Code runs the command through `sh -c`, so such a path does not start, and with
  no `onFailure` (older than 2.1.295) a hook that does not start lets the call go on. phiward
  needs Claude Code 2.1.295 or newer for that reason. Under `phiward launch` the hooks run
  `<python> -I -S <package>/phiward/entry.py ...`, and `launch` refuses, on every platform, a
  Claude Code older than 2.1.295 or one that gives no version. It learns the version outside
  the profile, so it never starts a program inside the project or the session's folders, and
  it starts only a native binary (`TOOL --version`, from `/`). A script's interpreter is found
  on PATH and a shim reads the project's config, so either could be the session's: for a
  script (the npm build) it reads the npm package's `package.json` instead, and a shim or a
  wrapper is refused. The project hook stays one `/bin/sh` line, because a committed file names no path
  of this machine.

**Masking never trades a name for a count.** A folder a protected pattern matches now is masked as a
whole path, spaces and all. That includes `'`, `(` and `&`, which a pattern's wildcard at its end
stops at. A wildcard with more of the pattern after it, as in `runs/*/panel` or `phi_*_raw`, takes
them all. The longest such folder wins (`phi_Ann Zorroquux` over `phi_Ann`), compared as written
(letter case and Unicode form included: `Straße`). The text after it stays only where no name can go
on: a `/`, a tab, the line's end, or another path after a space. It also stays after `: ` and counts
with at most a plain unit each, to a tab or the end (`phi_A: 12 reads, 3 errors`). Otherwise the
mask runs to the end of the line. Numbers after a space are masked (`phi_Ann 4471` may be a longer
name). A match of a pattern whose wildcard is at its end, that no folder on disk covers and whose
wildcard meets one of `' " ` < > | ; & ( )`, also runs to the end of the line.

When a path goes on inside a root or a match (`<root>/x`) and no folder on disk covers it, the text
after it stays only where the name has clearly ended: the line's end, a tab, or spaces and another
path (`cp <root>/a /tmp/b`). Anything else masks to the next tab or the line's end. So no part of a
name that is not on disk (made during the run) leaks, whatever it holds: a word after a space
(`<root>/New Person 7`), quotes and brackets (`<root>/O'Brien`, `'<root>/O' Brien'`, `(<root>/Ann)
Zorro`), separators (`<root>/Doe; Jane`, `<root>/Doe, Jane`). Ordinary text after such a path is
lost with it (`cat '<root>/x' done` shows `cat '<PROTECTED>`). The rule makes no guess about quotes
or brackets, so it holds by construction; the test suite checks it on random names
(`tests/test_v2_properties.py`). One known gap: a folder whose name ends in a space (`<root>/Cat
/x`) reads as a path, then another path.

Other spellings of the same path are read plainly: a JSON-escaped slash (`\/`), `//`, `/./`, and, in
the hook, a backslash-newline (bash and Python join the two lines). Where that makes a protected
path, the sanitizer prints the line in the plain spelling.

The hook and the sanitizer find a protected path written in free text (code in `python -c`,
heredocs, `echo`) the same way, with no regex over the patterns. A root (and a pattern with no `*`)
is found as text, in its NFC, NFD and NFKC forms too, and every match counts. On macOS the text and
the roots are case-folded as names are (`İ`, `ß` included: `Straße` is `STRASSE`). A pattern is
found by its literal start (the parts before the first `*`), then compared part by part with its own
glob. A part before the last ends at the next `/`. The last part may end at any place before the
next `/`, tab or line end where it matches. The hook takes the first place that counts. A match
whose wildcards hold `;`, `&` or `|` counts only when that path exists on disk (`runs/R&D/panel`;
not `ls phi_a; echo x_raw`, which is two commands). After 256 such disk checks in one command the
command is refused. The sanitizer takes the longest place. Each step stays inside one part of the
text, so the time grows with the text's length, not faster. A hook that is slower than its timeout
refuses the call: phiward's hook entries set `onFailure: "block"`.

## What is not protected

- Data that a gateway command encodes on purpose, or content that is not an identifier, printed
  through `phiward run`. Write scripts that print aggregates, with small counts hidden ([Small counts](daily-use.md#small-counts)).
- Data a granted write place, the network or a copy remote carries away (see above).
- On a cluster, what a push puts there is protected only by phiward's masking of remote output
  (`[remote] roots`) and the cluster's own permissions; a link on the cluster can lead a push
  elsewhere. A push goes only under `[remote] roots`; with none, every push is refused.
- Code that the agent writes and the operator later runs outside the guards: shell startup files,
  git hooks, scripts. Read such code before you run it. (The broker itself runs only the phiward
  code and the system `rsync`/`ssh`; it reads the repo config, names files and pack files only as
  plain files, never through a link, and never blocks on them. The user config may be a link: it is
  yours.)
- Protection that comes only from a repo config. The agent can edit its repository.
- Copies outside the protected folders: shell history, Spotlight, backups, editors' caches.
- The name of a link's target: `ls -l` and `readlink` on a link in an open folder show it.
- A user who turns the guards off, and a repository that does so where the install is not managed
  (`disableAllHooks`, `excludedCommands`).
- Native Windows: there is no confinement.

## Known limits

- <a id="known-file-mentions"></a>**`@` mentions and the IDE's context.** With mentions on,
  Claude Code puts a mentioned file's text into the prompt without a tool call, so no hook sees
  it. `install --user` turns mentions off (`CLAUDE_CODE_DISABLE_FILE_MENTIONS=1`, Claude Code
  v2.1.299+, ignored in a project's settings); a mention is then a Read that the hook and the
  deny rules judge. `doctor` reports a missing value and an older Claude Code. Not covered: the
  IDE's open file and selection, which Claude Code adds to the prompt (only its best-effort
  `Read` deny rules apply; set `claudeCode.attachSelection` and `claudeCode.attachOpenFile` to
  false in VS Code); a session whose own launch environment sets the variable (the Desktop app,
  a runner); and any Claude Code older than v2.1.299. What a person types or pastes into Claude
  Code is checked by [the prompt scan](#known-prompt-scan); in another tool that runs the same
  hooks, it may not be.

- <a id="known-prompt-scan"></a>**The prompt scan is a tripwire for honest pasting, not a
  boundary.** phiward's `UserPromptSubmit` hook (`phiward prompt-scan claude`, in both modes)
  refuses a prompt that the sanitizer would change: a match of the user config's packs or
  `[sanitize] patterns` (built-in `detail` rules left out), or a path below a protected root or
  a `[remote] roots` entry ([configuration.md](configuration.md#sanitize)). The message names
  the kind, never the value. A config or pack file it cannot use, a prompt over 1 MiB, or an
  error refuses the prompt. What it does not stop:
  - It protects Claude Code only. Other tools that run the hooks of `.claude/settings.json` may
    ignore a prompt hook's answer (GitHub Copilot in VS Code does), so there the prompt is sent.
  - Other prompt hooks (`UserPromptSubmit`, `UserPromptExpansion`) run in parallel with
    phiward's, at any settings level or in a plugin, so phiward's block does not keep the prompt
    from them. `doctor` warns of each one; nothing removes them.
  - A session can add a prompt hook to settings it can write. Under `phiward launch` the entry
    is in the session's own `settings.json`, which the session can edit: it can remove phiward's
    prompt entry. A settings `env` that sets `PHIWARD_CONFIG` changes the config the scan reads
    (doctor names it in a project's settings; under launch, the session's own settings can set
    it).
  - It does not see pasted images, the clipboard or other programs, the IDE's selection and
    open file (only the best-effort `Read` deny rules apply), or what a skill, a custom command,
    a `!` command or an MCP prompt expands to: it sees the prompt as typed.
  - Entry names under the roots are not checked: `FAKE-PT-0001` typed alone is sent; a path
    below a root is not. Nor are relative paths with no `/`, paths with spaces and no quotes, or
    a link spelling of a root whose target does not exist. The derived protected folders (a
    work tree's `.git`, the cache folder) do not count.
  - What the packs do not catch is not caught: an ID glued to letters (`patientFAKE-PT-0001`;
    the rules start at a word edge), and free text that is not an identifier. With `genomics`
    alone, file names, read names, positions and numbers are details and are sent.
  - The hook also runs on automatic turns (`/loop`, scheduled tasks, a background subagent's
    report, a message from another session); a blocked one stalls the loop, and the user sees
    the reason.
  - A blocked prompt stays in the local transcript and the prompt history, which are not
    guarded paths in Mode A.
  - Under `phiward launch`, a user pack file inside a protected root cannot be read, so every
    prompt is refused (`doctor` warns). Below Claude Code 2.1.295 the hook fails open (no
    `onFailure`).

- <a id="known-masking-check"></a>**The masking check tests only what its examples show.**
  Doctor, launch and the broker's start check that each `[sanitize] examples` value is fully
  masked, and that a made-up path below each root is
  ([configuration.md](configuration.md#sanitize)). It covers the user config's rules, examples
  and roots. Built-in packs that a repo's `.phiward.toml` adds are covered by the self-check,
  which hashes the installed packs, not by the masking check. It builds the sanitizer with no
  inventory entries, so it errs toward failing: an entry name that would mask a value at run
  time does not help it pass. What it cannot see:
  - a rule too narrow for real forms that its examples do not show (an example of one form
    passes while another real form leaks);
  - a rule with no example (doctor's NOTE says which, by number);
  - entry names under the roots and `names_from` (the check reads neither);
  - the built-in packs, which the self-check covers as installed files, not the check.

- <a id="known-leftover-processes"></a>**A gateway command's leftover processes (macOS).** A request ends when its command ends, and the
  broker ends the command's process group; a stop of the broker ends every running request and
  removes its scratch folder. A process that leaves the group (`setsid`, a daemon) keeps running on
  macOS until it exits, in the gateway profile: it can read protected data, but has no network, no
  write place (its scratch is removed) and no way to send output back. On Linux the PID namespace
  ends it with the request.

- <a id="known-pseudonymized-tables"></a>**Pseudonymized tables (`phiward pseudonymize`).** The codes replace only the columns you name;
  what they do not hide:
  - You choose the identifier columns. An ID column under a header no glob matches (`kit`,
    `tube`) goes into the copy as it is, masked only by the rules.
  - Quasi-identifiers can re-identify a subject: dates of birth, zip codes, ages over 89, rare
    diagnoses, free text, names that no names file lists. Codes that link several tables (one
    key) add to that, on purpose. The number of subjects shows.
  - The scan of the copy finds only the IDs of the run and the key. Another subject's ID, a
    name or an ID glued to other digits (`19990001` for `9990001`) in a kept field goes into
    the copy, masked only by the rules. A MAF's dropped `#` lines may be provenance you need;
    its tumor and normal barcodes get unrelated codes; its other values stay as they are.
  - A VCF keeps its records whole: genotypes and every other value stay, and genotypes can
    re-identify a subject. Its dropped `##` lines (reference, command lines, contig lengths)
    may be provenance you need. The stop list of sample names that are words is short: a word
    with a digit (`TUMOR1`) gets a code like an ID. The agent reads VCF positions as `<LOCUS>`
    where the genomics pack is on.
  - A gzip or bgzip input is read up to 1 GiB expanded; the copy is checked by reading it back.
    A bug in the BGZF writer gives a file `tabix` rejects, never a leak (the scan and the
    check-back come first). Parquet is not read.
  - A Markdown copy keeps every cell of the columns you did not name. The scan reads each cell
    raw, with its entities decoded and its emphasis marks removed, and finds only the IDs of
    the run and the key. Prose, inline HTML, links, images, code spans and escapes are
    refused, not scanned. The other tables of the file keep their row
    order, which may pair them with a shuffled table.
  - A JSON copy keeps every value at a path you did not name. The ID-glob rule sees only the
    key that holds a value: an ID under a key no glob matches (`note`, `label`) goes into the
    copy, masked only by the rules, unless it is an ID of the run or the key. Only the array
    at the last `[]` of a coded path is shuffled: the order of the other arrays and of the
    keys stays, and it can follow the IDs. A shuffle is refused only when an array of the
    same length sits beside the shuffled one; arrays paired by position across objects or
    files are not seen. Keys that are IDs are refused, not coded.
  - A code that is also a file name under a root reads `<ENTRY>`, and a later `[sanitize]
    patterns` rule can mask old codes: both hide a code, never leak an ID. Wide tables with IDs
    as headers are refused, not covered.
  - A run on a file the agent made or asked for, or with a key the agent chose, confirms the IDs
    it guessed (they get old codes). The command refuses inputs in the places an agent writes
    (the working folder, a git work tree, the temp folders, the sandbox's write folders,
    `write_to`, the spool, `~/.phiward`). It cannot tell a file inside a protected root that
    `phiward copy` put there at the agent's request, nor one the agent got you to put elsewhere
    by hand: never run it on a file the agent made or asked for, wherever it is.
  - The command line you type (paths, headers, the key name) stays in the terminal's scrollback,
    which an app that reads the terminal can see. The command's own messages name none of it.
  - The key is hidden as a credential is (below `~/.phiward/backups`), so the same limits apply:
    with `[shell] best_effort`, scripts through `run_in_terminal` and bare local MCP servers, a
    key can be read as a credential can. The tty check alone is not a boundary (a pty passes it);
    the hidden key folder is.
  - The hook's refusal of operator commands (`setup`, `pin`, `carryover`, `broker`,
    `pseudonymize`) is a tripwire for honest mistakes, not a boundary: it reads the words of a
    command (with `phiward` in command position, after reserved words and the usual wrappers, a
    subcommand built at run time is refused), and
    a program can build them where the hook cannot see (`python -c`, an `sh -c` string). The
    boundary is the tty check together with the hidden key folder.
  - The places refused for the input come from the sandbox settings of the working folder's
    project and the user and managed settings, and from any `.git`, `.claude` or
    `.phiward.toml` above the input below the home folder (the home folder's own `~/.claude`
    does not count). Another project's settings can let its agent write a
    folder elsewhere: run the command from the folder of the project whose agent will read the
    copy.
  - A column that is not coded is refused when it holds an ID of a coded column or of the key:
    an ID of 5 or more characters anywhere in a cell (after NFKC, in any letter case), an ID of 5
    or more digits as a whole run of digits, a shorter ID with a letter as a whole word, a
    shorter ID of digits only as the whole cell. Not found: a short digit ID inside a cell
    (`12` in `12 mg`), an MRN glued to other digits (`19990001`, a position may look so), an
    MRN of digits only written with separators (`999 0001`), an ID split across cells, an ID
    with its leading zeros dropped or added. Unicode dashes read as `-`, and an ID with a letter
    is also matched with its separators removed (`FAKE PT 0001`).

- <a id="known-git-control-files"></a>**Git's control files.** Claude Code runs git outside its sandbox: about a hundred times in a
  short session (a check in the real app, 2026-11), at the start, for its status and diff views, and
  to make worktrees. Most of these calls turn hooks and `core.fsmonitor` off, but not all (`git diff
  --name-only HEAD` does not), and a fetch reads `credential.helper` and `core.sshCommand` from the
  repository's config. The shell sandbox keeps the project's `.git/config` and `.git/hooks` from
  being written, not git's other control files. So a confined shell can make git run a command with
  your rights when Claude Code next runs git in the project: through a `commondir` in `.git`, a
  submodule's own config under `.git/modules/`, or a nested repository staged into the index. What
  reduces it:
  - The file tools may not write inside any `.git` folder (rule 1 of "What Claude Code runs as code"
    above).
  - On macOS, with Claude Code 2.1.236 or newer, `install` also denies the shell writes to a `.git`
    folder's `config`, `config.worktree`, `commondir` and `hooks` (also those of its first-level
    submodules and worktrees), in every repository under your home folder. The cost: in the agent's
    shell there, `git init`, `git clone`, `git submodule`, `git worktree add`, `git remote add` and
    `git push -u` (which write the repository's config) fail, and so do tools that clone into your
    home folder (pre-commit, git dependencies of cargo, uv or npm). Claude Code's own worktrees are
    made outside it. Not covered by these rules: a `.git` folder renamed, changed and renamed back
    (a rule on `.git` itself would deny every write inside it).
  - A wrapped MCP server's profile is the session's (Mode B, "Files that run later"), and keeps
    every `.git` folder of the project read-only as a whole too: on macOS also one made while it
    runs; on Linux those that exist when it starts.
  - `doctor` names a `commondir` in the project's `.git`, and a `.git` file that leads to a folder
    the agent can write. It does not name a `commondir` that holds only `.` (git then uses that
    `.git` folder itself). Claude Code writes one at start on Linux when
    `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` is set.

  Not covered: Linux (its sandbox has no wildcard write rules), projects outside the home folder, a
  nested repository staged into the index, submodules below the first level, and older Claude Code.
  Do not run git yourself in a project the agent changed without looking at what `git status` lists,
  and read `phiward doctor`'s warnings.

- <a id="known-claude-code-path"></a>**Claude Code's own PATH.** Claude Code starts an MCP server whose entry names its program without
  a path (`npx`, `uvx`) by looking it up on its PATH, outside every sandbox. The agent chooses what
  runs with your rights when a folder of that PATH that it can write comes ahead of the real
  program. Such a folder is the project's `.venv/bin` of an activated environment, a relative entry,
  a folder the sandbox's `allowWrite` or `additionalDirectories` opens, or the temp folder. phiward
  cannot change the PATH Claude Code starts with; `doctor` names each such entry. Start Claude Code
  with those folders off PATH, or give the entry the program's full path. A wrapped entry names the
  launcher by its full path, so this does not reach it.
- <a id="known-only-output-masked"></a>**Only the output is masked.** A gateway command's arguments, environment and open files are
  visible to other processes of the same user: `ps`, `lsof`, `/proc`. Under `launch` (Mode B) the
  session cannot see other processes. In Mode A it depends on whether Claude Code's sandbox hides
  process information, which phiward does not check; in a plugin-only session, nothing hides them.
  Keep names and records out of command arguments: let the command read them from the protected
  files.
- <a id="known-repo-roots-listed"></a>**A repo config's roots are listed by the broker.** A repo config may add protected roots and
  patterns anywhere (it can only add protection), and the agent can edit it. The broker lists what
  they name to mask it, outside every sandbox. So an agent can learn whether a name exists in a
  folder it cannot read (a root over `~/.ssh` masks the names there). A wide pattern makes each
  request walk many folders before it starts.
- <a id="known-masking-confirms-guess"></a>**Masking can confirm a guess.** A name under a protected root that the agent prints itself comes
  back masked, so an agent can test whether a name it guessed or saw elsewhere exists there, for
  many names in one request. Where a file or identifier rule (a pack, `[sanitize] patterns`)
  matches the text around a name, the name reads as that rule's placeholder, as a name that does
  not exist would. Elsewhere it reads `<ENTRY>`: plain names, names with a plain part, names
  written where the rule does not match (inside a longer word, joined to a plain name, in
  another spelling, or overlapping the rule's match), and `names_from` names can be
  tested. Masking hides names; it does not keep a name the agent already holds a secret.
- <a id="known-encoded-output"></a>**Code the agent writes can print protected data encoded.** Masking hides names and identifiers,
  not other content. Without `[broker] commands`, a gateway command may be a script the agent wrote,
  which can read a record and print it in a form masking does not catch (base64, digits spelled
  out). With `[broker] commands` set to your own programs, the agent can only run those on protected
  data. You approve them as they are (`phiward pin`); the broker runs none whose content differs,
  and stops when one changes while it runs. Approval covers each listed file, and every file in a
  listed folder and its subfolders (up to 2000 files); it does not cover other files a listed
  program loads from elsewhere (a library, a helper script in another folder). Keep a script's
  helpers in its listed folder. A listed program that runs other code it is given (an interpreter, a
  shell, `git`, `find`, `make` and the like) undoes the list; `doctor` warns about them. The list
  does not limit what a listed program prints.
- <a id="known-listed-program-selects"></a>**A listed program can select or count records by a value the agent gives.** Many data tools
  pick records by a value or a pattern on their command line or in a file the agent wrote
  (`samtools view -d`, `-D`, `-r` or `-e`, `seqkit grep`). A count, or whether anything is
  printed, is not masked. So the agent can test whether a value it guessed, or a prefix of one,
  occurs in a protected file, for many values in one request. Masking hides identifiers in what
  a program prints; it does not hide whether a program found them. If that matters for your
  data, leave such programs out of `[broker] commands`.
- <a id="known-run-table"></a>**`phiward run --table` reads columns for honest programs.** It is off unless the operator sets
  `[sanitize] table = true`. A cell under an identifier header is masked whole; a plain number in
  any other column passes. The agent can print a header of its choice (with `[broker] commands`
  unset, or with a listed program that prints what it is told, such as `cut` or `printf`) and get
  numbers through, as with per-line table mode before. A column of identifiers under a header that
  no glob matches passes its numbers (`kit`, `tube` and a lab's own codes are not on the
  built-in list). The header must name an identifier column, but ordinary data can still make
  the first line a header that is really data or prose: a row printed without its header (`tail
  -n +2 x.tsv`) or a line of prose with commas (`sample, mrn and notes`), when one of its fields
  is an identifier word; the numbers in its other columns pass. A row that fits the header (same
  field count, a number cell) is read under it even when it starts another table (a second header
  with a number field, a headerless second file of the same width). Rules that mask positions
  across cells in text mode (`chr1` tab `1234567`) do not match cell by cell, so both cells are
  shown.
- <a id="known-exit-status"></a>**Exit status.** The agent sees only success or failure (`exit=0` or `exit=1`; 130 when
  cancelled); the real status goes to the broker's log, which no session can read. One output note
  carries a count (`[N more identical line(s)]`), which the command chooses. A failure is still one
  bit per call. The placeholder note at the end is counted from the lines shown, so it tells the
  agent nothing those lines do not: it counts placeholders shown (a program can print one), not
  substitutions, nothing past the cap, and only kinds, so an identifier partly masked by a number
  rule (`P-<NUM>-T01-IM6`) is flagged only when no identifier placeholder appears in the output.
- <a id="known-without-kernel-confinement"></a>**Without kernel confinement**, the hook checks command text only and can miss a spelling. A line
  that changes how bash finds commands or folders (`PATH`, `CDPATH`, `HOME`, `BASH_ENV`, `hash`,
  `shopt`, `alias`, set by any means) is unresolved there (deny by default).
- <a id="known-patterns"></a>**Patterns** in Claude Code's sandbox: on macOS (Claude Code 2.1.236 or newer, after `install
  claude --user --write`) a pattern is in denyRead and denyWrite, and the shell can count as
  confined. The hook cannot run `claude --version`: its step says to run install in a terminal where
  it prints 2.1.236 or newer (install reads the version there); `doctor` knows the version and gives
  the exact step. On Linux the sandbox cannot deny writes to a wildcard path, and it expands a
  pattern when a command starts. So a pattern is in denyRead only, as an extra layer, and the shell
  does not count as confined: the hook refuses shell commands (or, with `[shell] best_effort`,
  checks their text, best effort). For the hook alone (without `launch`) on Linux, a folder that
  matches a pattern after a command started is covered from the next command on. Under `launch` on
  Linux, a match made after the start is not in the session's view, except inside a folder that can
  be entered but not listed (docs/launch.md). The session's view is checked against what was
  checked before the tool starts: an entry the host replaces while the session starts stops it.
- <a id="known-sandbox-on-linux"></a>**Claude Code's sandbox on Linux** (bubblewrap): a denied path is hidden at its real place, so a
  link to it (`~/work -> /data/...`) is covered too. A path that does not exist when a command
  starts is not hidden in that command, only from the next one on. phiward's probe of the sandbox
  engine (`@anthropic-ai/sandbox-runtime` 0.0.81) passed on a RHEL 8 HPC login node with bubblewrap
  0.4.0, for one user without admin rights. It showed: a root under `/scratch` hidden by its real
  path, through a home link and by a wildcard; settings files and startup files not writable; no
  direct network. Claude Code needs `bwrap` and `socat` there (`doctor` checks them).
- <a id="known-unconfined-shell"></a>**A shell that no kernel confines** (Claude Code's sandbox off or not there): the hook refuses its
  commands, except a phiward command written whole (the gateway, `doctor`, `check`). This covers
  GitHub Copilot, which runs the hook without a sandbox. With `[shell] best_effort` (user config
  only), the hook checks the text instead, which is best effort (below): a spelling it misses is a
  known limit of that mode, not a defect of the refusal.
  - **Tools that run commands.** A tool whose name says it runs commands (`write_bash`,
    `run_in_terminal`, `run_command`, `executeCode`, `start_process`) is judged as such a shell,
    unless its MCP server is wrapped in `phiward launch --`: one whole gateway call in one exact
    form, nothing else. Only Claude Code's own Bash and Monitor can count as confined. A tool of a
    bare local MCP server whose name does not say so gets the text check only, which is not a
    boundary: the server runs with the operator's rights (gap 3). When a server counts as wrapped,
    and the limits of that:
    [How the hook trusts a wrapped MCP server](#how-the-hook-trusts-a-wrapped-mcp-server).
  - **The exempt commands** trust what the shell makes of the bare name `phiward`: the PATH (keep
    folders the agent can write off it) and what the shell runs before a command. No file tool may
    write the bash and zsh startup files, the files `$BASH_ENV` and `$ENV` name, or Claude Code's
    shell snapshots, so no `phiward` function or alias can be planted there. Not covered: a file
    they source in turn (a plugin framework's folder), which changes the next session's snapshot.
  - **Before the first setup** (no protected path yet) the refusal does not apply: the hidden list
    is then guarded by the text check only, which is best effort.
- <a id="known-hooks-fail-open"></a>**Hooks fail open** in most tools by default. Claude Code (`onFailure: "block"`) and Cursor
  (`failClosed`) have a switch. No tool documents whether a hook deny still applies in its bypass or
  auto-approve mode.
- <a id="known-managed-settings"></a>**Managed settings** are the only hook settings a repository cannot change.
- <a id="known-long-lived-shells"></a>**Long-lived shells** that started outside the confinement stay outside it.
- <a id="known-linux-landlock"></a>**Linux** needs Landlock ABI 2 or newer for the gateway, and bubblewrap must be able to start
  (AppArmor on Ubuntu 24.04 can block it).
  Before a gateway command starts, a helper inside checks that each folder and file bound into
  it is the same file found at that name before the start (a link not followed), mounted at its
  name; anything it cannot confirm stops the request. So a write place must not be at or below
  a hidden path (credentials, traces): such a request stops.
- <a id="known-sanitizer-short-names"></a>**The sanitizer** does not mask entry names shorter than 4 characters (6 when only digits) or
  names that are common words of its stop list (`patient`, `normal`, `bam`, ...), and it stops
  (fails closed) when the roots hold more entries than `inventory_limit`. A name with spaces (`Doe
  Jane 1970`) is masked whole, after a root, under a pattern (`phi_*` matches `phi_Doe Jane`) and in
  escaped output (`Doe\ Jane`, from `ls -b`); the masked output shows an escaped space as a plain
  space. Every dash is read as `-`, and other decimal digits as ASCII digits, to match names and
  rules; the masked output shows both as written (Python 3.9, with Unicode 13, knows fewer digits
  than later versions). A name of 5 or more letters and digits, with a letter, is also masked
  with its separators (`-`, `_`, `.`, a space) changed or left out; such a name may then mask
  ordinary text too (`sample_01` masks `sample 01`). A shorter or digits-only name, a name with
  a separator at either end, or one whose separator-free form is a stop word or part of a
  placeholder (`SAM_PLE`), is masked only as written; so is a whole name whose stem is masked
  in other spellings (`FAKE_PT_0001.bam` reads `<ENTRY>.bam`, which a file rule may then mask).
  Not matched: look-alike letters from other scripts (Cyrillic `А` for Latin `A`), an accent
  added or left off (`José`, `Jose`), base64, hex and other encodings, a name broken across
  lines, a tab and the separators `:` `+` `~` `,` `'` and `/`, and IDs that are not entry names
  (only rules catch those). The pack rules know only `-` as a separator: `P_9990002_T01_IM6` is
  not an `msk` ID.
- <a id="known-names-from-files"></a>**`names_from` files** are themselves protected data. Keep them inside a protected root.
- <a id="known-git-work-tree-root"></a>**A git work tree that holds a root** is closed to the agent's git.
- <a id="known-claude-settings-in-write-place"></a>**Claude Code settings in a write place.** The gateway may not write a `.claude` folder: on macOS
  by its profile, anywhere. On Linux only a `.claude` folder directly in a write place is read-only;
  one deeper down is writable, and gateway code can make a new one. Use write places that are not
  project folders. A `write_to` entry that holds a `.claude` folder is skipped (at every load;
  `doctor` counts it).
- <a id="known-remote-copies"></a>**Remote copies** run the system `ssh` through your shared connection (pushes and pulls are tar
  streams; [hpc.md](hpc.md)); local copies run the system `mkdir`, then `rsync` or `cp`. A pull
  unpacks with a file of the installed package, run by path. No part of a copy is code in a
  command line. The remote host itself is trusted with what is copied there.
- <a id="known-phiward-python"></a>**The Python that runs phiward** is guarded: the agent may not write its prefix, the `phiward`
  launcher found on `PATH` (the link itself and the file it points to) or the user site folder.
  Install phiward in a folder of its own (`uv tool`, `pipx`).
- <a id="known-group-account"></a>**Another account in your group** is not the agent, and the goals do not cover it, but phiward
  makes its own Python safe from it and says when it is not. One rule decides "another account can
  change it": a file and each folder above it are yours or root's and no group or other account can
  write them. Inside your home folder the folders are judged up to the home folder; outside it up to
  `/`, where a sticky folder (`/tmp`) is fine for your own entry. A link is judged by its folder,
  then its target. The one exception is Homebrew's own folders on macOS, which the `admin` group may
  write (its members can use sudo already). The walk follows the path as the kernel does, one link
  at a time. It knows the home folder by identity (a `/home` that is a link is fine). A folder above
  the home folder counts only off the way home. phiward does not try to tell your private group from
  a shared one: ACLs, accounts it cannot list (LDAP) and NFS made every such guess unreliable.
  - **What `install` fixes.** `install` (and so `setup`) compiles phiward's Python and makes what
    you own of it writable by you alone: the venv, the standard library, `lib-dynload`, the
    interpreter, `pyvenv.cfg`, the folders above them up to your home folder, and the `PATH` folder
    of the `phiward` link. It never changes your home folder or anything outside it (a Homebrew or
    system Python, a lab share). For those it gives the step. For your home folder it is `chmod go-w
    ~`. For what is yours outside it, it is `chmod go-w` on exactly the files and folders on the way
    that the check names, and one command per folder of phiward's Python, run from inside it. Or
    else install phiward on uv's own Python.
  - **That one command** works in this order. A `cd` that fails runs nothing.
    1. It fixes the modes of what the check judges there, with `find`: your own entries, no link,
       never `chmod -R`. For the standard library it leaves out its own packages folder (a folder or
       a link of that name: the base Python's site-packages, which a venv's Python does not read).
    2. It compiles the folder, as `install` does inside your home folder, so no later start writes a
       group-writable `__pycache__` there. Python runs with `-I -S` (no `.pth` runs), and runs from
       the folder only what phiward's Python runs anyway.
    3. It fixes the modes again: a default ACL can make a new `__pycache__` group-writable.

    Where a folder cannot be read or changed, Python compiles anyway and the check names what is
    left. If the same step fails again, the fault is not a mode (a flag, an ACL, a read-only file
    system). phiward's own package outside your home folder gets the same one command for its
    folder. So `launch` and the session note may give it too, and `doctor` may show the command for
    the whole venv beside it (which covers the package's). Where a Homebrew folder of yours is in
    such a folder, the `find` also clears its admin group's write bit, which the check allows.
  - **What `doctor` and each start check.** `doctor` checks all of that. Every start of `launch` and
    of a wrapped server checks phiward's own package (its hashes, its modes and the folders above
    it) and the venv's start-up files. It refuses:
    - a `.pth` that runs code, unless it is known (an install record listing it proves nothing);
    - a `.pth` that is not plain ASCII or is over 1 MiB (no Python version may read it differently);
    - a `.pth` path line that does not lead into the venv (or, for a pipx venv, pipx's own shared
      libraries), or that does not lead to a folder (a zip there could hold start-up code);
    - a `sitecustomize` or `usercustomize` in any form (a `.py`, a `.pyc`, a package, an extension
      module), in the venv or in a folder a `.pth` line adds. Python imports it at every start; the
      step removes it;
    - a venv whose `pyvenv.cfg` lets Python read the base Python's and your own site folders.
  - **How `pyvenv.cfg` is read:** as `site.py` reads it. The one next to the interpreter comes
    first, line by line. The last line wins, and a file without the line counts as reading them
    (Python's default). A `pyvenv.cfg` next to a system interpreter (`/usr/bin/pyvenv.cfg`) makes
    that Python a venv for phiward as it does for `site.py`. On macOS `site.py` takes the
    interpreter from `__PYVENV_LAUNCHER__` when it is set. Whoever sets phiward's environment is not
    the agent, so the check reads the one `sys.executable` names.
  - **The reinstall step** names the tool that installed phiward, read from the file that tool keeps
    in its venv (`uv-receipt.toml`, `pipx_metadata.json`), at the running version: `uv tool install
    --force --reinstall`, or `pipx reinstall`, then `pipx install --force`. Each restores a changed
    file and removes a planted one. Known limit: a file of the base Python that is missing (a link
    loop in its standard library) gets the reinstall step, which does not restore it.
  - **What a check reports.** The problems are kept by kind, in the order the step reads them, at
    most 50 of each. So a line the step needs first is never pushed out by many lines of a later
    kind, and the check stays linear on a tree of any size. Each problem names the fault itself and
    whether it is inside your home folder, as the walk found it. One round names every fault of
    yours outside your home folder, so one step fixes them. A refusal shows the lines its step fixes
    (a folder's one line first) and how many more there are. `doctor` shows a second WARNING for the
    rest of phiward's Python only when its step differs from the package's. A check that gives no
    answer (it did not finish in time, or could not run) says so, in the same words in `doctor`,
    `launch` and the session note. Its step is to start again, then to reinstall.
  - **What is read and walked.** The package check, like the full check, names every fault of yours
    outside your home folder in one round. It reads a file with a mode fault too, so a changed file
    is in its list in the same round. Inside your home folder its step is then the reinstall;
    `phiward install` then fixes the modes, which a reinstall with umask 002 leaves group-writable
    again. It reads a file only if it is a regular file, never waiting on one (the install record,
    `pyvenv.cfg` and the `.pth` files too). Every folder phiward's Python reads is walked, however a
    `.pth` line spells it (a link, `..`). One rule, by identity, decides what each folder of the
    walk covers. Only the standard library leaves out its own packages folder. A Python without a
    venv (pip into conda or a system Python) is judged for its interpreter, standard library and
    lib-dynload only, not its site-packages: install phiward with uv or pipx.
  - **Links.** A link inside phiward's Python is judged where it leads: the way there and the
    target. A link that leads nowhere yet is judged by the deepest folder on its way. Left out: the
    standard library's own packages link, with that folder. `install` fixes what the check names of
    a link inside your home folder (every folder of a chain, the target, that deepest folder), and
    judges it again after each change. The contents of a linked folder are not walked: anyone who
    could plant such a link could change the standard library itself, which is not hashed either.
  - A check that runs inside the code it checks cannot stop an account that changed that code first;
    that is why `install` makes the files safe and `doctor` checks them all.
  - Not checked: ACLs (mode bits do not show them, on macOS or NFSv4), and dynamic libraries loaded
    from elsewhere (for example Homebrew's OpenSSL).
- <a id="known-what-claude-code-protects"></a>**What Claude Code protects by itself:** its sandbox keeps commands from writing "most of"
  `~/.claude` (or `$CLAUDE_CONFIG_DIR`), `~/.claude.json` and the credentials file, even under an
  `allowWrite` that covers them. The docs give no exact list and no version for it. phiward refuses
  the settings that the docs say remove this protection (`filesystem.disabled`,
  `allowNestedUserNamespaces`), and adds nothing of its own there. On Linux a `denyWrite` path that
  does not exist yet becomes a read-only placeholder file, which could block a plugin install.
- <a id="known-scripts-settings-name"></a>**Scripts that Claude Code settings name** (a hook's command, `statusLine`, `apiKeyHelper`) run
  with your full rights. Keep them under a `hooks/` folder of `~/.claude` or of the project's
  `.claude` (the hook asks before a file tool writes there, and Claude Code's sandbox denies its
  shell), or in a folder no session writes; never elsewhere in a project.
- <a id="known-real-sandbox-not-tested"></a>**Not tested by phiward's own checks:** Claude Code's real sandbox. The test suite never runs
  the real `claude`. The release check (`scripts/sandbox-check`, [releasing.md](releasing.md))
  does, on macOS and Linux, run by the operator: one session per mode, judged from its files.
  Its probe lines are written inside the session, so a model could forge them; the checks made
  outside it (files on the host, the settings hash, the stream that `launch.py` writes after the
  session) are harder to forge, but a process the session leaves running could still reach
  them before the judge reads them.
  It does not cover MCP tools, WebFetch, IDEs on Linux, remote with
  `use_shared_connection = false`, RHEL 8, NFS home folders, sssd or Kerberos; and the first
  check after your own install is yours.
- <a id="known-spool-folder"></a>**The spool folder** is writable by the agent: it can fill it or move it, which stops the gateway
  (the broker stops when its folder is moved). It cannot make the broker write outside the folder or
  run a command through a shell.
- <a id="known-broker-status-file"></a>**The broker's status file** only adds protection to the agent's side. On Linux, if it does not
  exist when an agent shell starts, that shell can create it in its way; the agent's own config
  still applies, and `doctor` reports a mismatch.
- <a id="known-gateway-not-container"></a>**The gateway is not a container.** It sees the whole file system read-only, the roots included;
  it writes only to the places listed above.

## Gaps of the hook alone

These apply when only phiward's hook runs, without Claude Code's sandbox (Mode A) or `launch` (Mode
B). Each gap was found by a review. **Confirmed** means a probe on made-up data showed it; **not
verified** or **from reading the code** means it was not shown by a probe.

**The agent tool itself**
1. <a id="gap-1"></a>**File tools are checked by path, then used by path.** A link swapped in between can give a Read
   the content of a protected file (confirmed by a simulation, not through Claude Code). Spellings
   the hook does not resolve also pass it: `/.vol/<dev>/<inode>/...` and `/System/Volumes/Data/...`
   on macOS (confirmed), and accented names in the other Unicode form (confirmed).
2. <a id="gap-2"></a>**The hook's list of files the agent may not write is incomplete.** It refuses file-tool writes
   to phiward's own files (compared as the file system compares names, and by device and inode), and
   to Claude Code's `settings*.json`, `.mcp.json` and `~/.claude.json`. It asks before a file tool
   writes what Claude Code runs as code (hooks, skills, plugins: rule 2 above). It cannot know every
   file another tool runs later. In Mode A, Claude Code's own permission rules (`install` writes
   `Edit` deny rules for phiward's files) and its sandbox cover more.
3. <a id="gap-3"></a>**MCP servers and the tool's hooks run outside the kernel profile.** A local MCP server runs with
   your rights unless it is wrapped in `phiward launch --`. The hook sees only what a tool is asked
   to do, never what it returns. So a tool that returns your terminal text or a file can show
   protected data. A published server (`@modelcontextprotocol/server-filesystem` 2.3.0) wrapped this
   way read ordinary files and could neither read nor list a protected folder (Linux; confirmed).

**The agent's confined shell (Claude Code's sandbox)**
4. <a id="gap-4"></a>**It can write files the operator or a later unconfined tool runs**: shell startup files,
   `~/.ssh/config`, `~/.gitconfig`, `.git/config` and `.git/hooks`, LaunchAgents, programs in PATH
   folders, `~/.claude.json` (user-scope MCP servers), `~/.claude/hooks`, plugins, `.mcp.json`.
   Under Claude Code's sandbox, writes are limited to its allowed folders (the project, the
   temporary folder, the broker's spool). Claude Code's documentation says the sandbox also denies
   writes to `.claude` settings files and `.mcp.json` in the working folder and the folders above
   it, shell startup files, `.gitconfig` and `.git/hooks` and `.git/config` in the working folder,
   and most of `~/.claude`. phiward's HPC probe confirmed this for the sandbox engine with explicit
   entries, not for Claude Code's own list.
5. <a id="gap-5"></a>**Keystroke injection**: from a confined shell, a program can queue keystrokes into the terminal
   that started it (TIOCSTI; confirmed under a profile like phiward's old one, not tested under
   Claude Code's own sandbox).
6. <a id="gap-6"></a>**Unconfined programs it can reach**, unless the sandbox blocks them: unix sockets (tmux, ssh
   connection sharing, ssh-agent, systemd, job schedulers), IDE extensions, `open` / LaunchServices,
   Spotlight (`mdfind`), Claude in Chrome (from the reviews; a unix-socket server was confirmed, the
   others **not verified**).
7. <a id="gap-7"></a>**Pattern forms the kernel does not enforce**: a `?` or `[...]` that must match a non-ASCII
   character, and some class forms (`[!-x]`, ranges across `/`) (confirmed). Use roots, or patterns
   with `*` and ASCII names only.
8. <a id="gap-8"></a>**A root spelled `/System/Volumes/Data/...`** in the config is not denied by Seatbelt on its
   normal path (confirmed). Write roots in their normal form.
9. <a id="gap-9"></a>**Other names of a protected file**: an existing hard link outside a root is readable (confirmed
   on macOS). On macOS, other mounts of the same data are not detected: list each mount path as a
   root. On Linux, other mounts of the same file system are not covered by the hook alone, and a
   guard file that does not exist yet (for example a user site folder) is not protected (from
   reading the code).

**The trusted side (broker, hook, doctor, install, git hooks)**
10. <a id="gap-10"></a>**The base Python** that phiward runs on is not a guard folder (with uv, Homebrew, pyenv or
    conda it is user-writable) (confirmed).
11. <a id="gap-11"></a>**`doctor`'s self-test runs `true` found on PATH** without a restriction (confirmed).
12. <a id="gap-12"></a>**`install --project --write`** writes its backup and temporary file through links that may be
    planted in the project (confirmed).
13. <a id="gap-13"></a>**The git hook's fallback** (`python3 -m phiward`) can import a planted package from the
    repository (confirmed).
14. <a id="gap-14"></a>**Programs and their settings**: Linux finds `bwrap` on PATH (confirmed); a remote copy's
    `rsync` reads `~/.popt` on Linux (confirmed in Docker); an operator `ssh_config` may `Include`
    or `Match exec` files the agent can write, and ssh reads `~/.ssh/known_hosts` and `id_*` (from
    reading the code).
15. <a id="gap-15"></a>**The start environment** of the broker, `doctor` and `setup` comes from the operator's shell
    startup files (see gap 4) (from reading the code).

**On a cluster**
16. <a id="gap-16"></a>**Job submission** (`sbatch`, `srun`) from the agent's shell runs jobs outside any profile, on
    nodes that see the same data (from reading the design; not probed).
16b. <a id="gap-16b"></a>**Protection follows the path** (confirmed on Linux, by design on macOS): a protected folder
     that the operator moves outside its protected path, into a folder a session can see, is
     readable there, during a session or after it.

**Smaller path and trusted-side gaps**
17. <a id="gap-17"></a>Each smaller, all real:
    - grant checks compare paths as raw text, so a case twin of `~/.ssh` or of a root's parent
      passes the `write_to` check (confirmed);
    - a root written in NFD Unicode form is masked now, in that form and in NFC (tested:
      `test_phicheck.py`), so it is no longer a gap;
    - entry names that are not valid UTF-8 are not masked on Linux (confirmed);
    - a `.git` file (worktree, submodule) makes the gitfile, not the real object store, the derived
      root (from reading the code);
    - Claude Code settings are read following links and can block on a FIFO; the "confined"
      relaxation trusts project settings that phiward does not deny;
    - the plugin's and `install --project`'s hooks run the first `phiward` found on PATH (the user
      wiring names phiward's own Python by its full path);
    - git is found on PATH, and the pre-commit hook runs `git diff` without `--no-textconv`, with
      `core.fsmonitor` and `core.hooksPath` read from the repository;
    - with a `pip --user` install, the launcher folder is on `sys.path`;
    - user pack files and `names_from` files outside the roots are not guard files, so masking can
      be weakened.

## Reduce the risk (every mode)

1. **If the agent reads untrusted input** (web pages, issues, other people's repositories, MCP
   tools), **use Mode B** (`phiward launch`), or run it as a separate user, or on a machine, with no
   protected data.
2. Install phiward with `uv tool` or `pipx`, and keep its Python out of the agent's reach.
3. Prefer roots; in patterns use only `*` and ASCII names. Write roots in their normal form (not
   `/System/Volumes/Data/...`). Avoid hard links and second mounts of protected data.
4. Give no write places, no network and no copy remotes unless you need them; keep write places away
   from project folders.
5. Use only MCP servers, plugins and hooks you trust.
6. Run `install --project` only in a project you created.
7. Run the agent in a terminal that holds nothing else; do not leave tmux, ssh connection sharing,
   ssh-agent or other socket services open to it.
8. Do not run agents on a cluster login node that can submit jobs against protected data.
9. After agent sessions, review: shell startup files, `~/.ssh/config`, `~/.gitconfig`, `.git/config`
   and `.git/hooks`, LaunchAgents, programs in PATH folders, `~/.claude.json`, `~/.claude/hooks`,
   `~/.claude/plugins`, and the project's `.claude/` and `.mcp.json`.

## Mode A: a Claude Code session

`phiward install claude` wires the session. Bash (and Monitor) runs in Claude Code's own sandbox,
which denies protected roots and the hidden list. The file tools are refused them by phiward's hook
and by Claude Code's permission deny rules (both resolve links). A start-of-session note tells the
agent the rules. Tested in the desktop app: reads of protected data and of a made-up credential by
the Read tool and by `cat` were refused, `ssh` to HPC failed, a Keychain-backed GitHub token was not
reachable from the session's Bash, and ordinary work was unaffected. What it does not do:

- the file tools are refused inside Claude Code, not by the kernel: a spelling that both the
  permission rules and the hook miss reads the file;
- hooks and MCP servers that are not wrapped in `phiward launch --` run with your rights;
- credentials that are not files (the macOS Keychain in general, Kerberos caches kept by the macOS
  credential service or the Linux kernel keyring or KCM, tokens in your environment) are not hidden
  by a file list; `doctor` warns about ticket caches that are not files;
- **only sessions that load the wiring are protected:** project wiring applies only to a session
  opened in that folder; wire your user settings (`--user`) so every session is covered;
- a repository can turn the phiward plugin off unless managed settings force it on;
- a gateway command may write files that run later (`.git/hooks`, `.mcp.json`, `.envrc`) inside a
  `write_to` folder or a copy's destination; give `write_to` folders that are not projects, and read
  what lands there before you run anything from it. Protected roots themselves are read only for the
  gateway;
- on Linux, a `run --write-to` command can write a `.claude` folder below the top of its `write_to`
  folder (bubblewrap makes only the top one read only); do not open a Claude Code session inside a
  `write_to` folder;
- the hook reads the config that its environment names (`HOME`, `PHIWARD_CONFIG`, `XDG_CONFIG_HOME`,
  `CLAUDE_CONFIG_DIR` and the spool and cache variables). A project whose settings set a
  `PHIWARD_*` variable in `env` (a repository you clone can) makes the hook refuse every tool call,
  and `doctor` names it. Claude Code ignores `HOME`, `XDG_*` and `CLAUDE_CONFIG_DIR` there. Claude
  Code's sandbox and the hook refuse Bash and file-tool writes to those settings. The
  hook does not check its config against the broker's;
- another session's gateway replies in the spool can be changed by the agent (it is the same user):
  a forged reply leaks nothing, but it can mislead you or another agent;
- **the first setup:** before your config exists, nothing protects it. If the agent writes the first
  config (`/phiward:setup`, `setup --first-run`), you trust that session to write what you said; see
  [setup.md](setup.md#the-guided-first-run).

### How the hook trusts a wrapped MCP server

Claude Code starts a server when a session starts and keeps it running. So a server wrapped in the
config afterwards still runs bare. After `phiward mcp wrap`, start Claude Code again; `/resume`,
`/clear` and compaction change nothing.

**Which server a tool belongs to.** The hook learns it from Claude Code itself (`mcp_server.source`,
2.1.274 and newer; Claude Code's docs say to base trust on it, not on the name). It reads that one
scope's entry: `.claude.json` or `.mcp.json`, or a plugin's installed files. The agent cannot write
`.claude.json` or `.mcp.json`: the file tools refuse them, and the sandbox denies them to Bash. The
app's own servers (`sdk`) and every source phiward does not read count as bare. So a repository's
`.mcp.json` cannot speak for a server of the app's that has the same name. Without a source (an
older Claude Code, Copilot) only `~/.claude.json` counts and `.mcp.json` servers are bare. A config
file that cannot be read strictly makes its scope bare. A config entry phiward cannot read (`args`
that is not a list of strings) counts as bare, and does not change how the others are read.

**The record.** Each `phiward launch` keeps a record of its own process in `~/.phiward/launched`
while it runs: process id, start time, parent, a hash of what it runs (its command), and a hash of
what its profile hides (the hidden list, the roots and the patterns). It is a guard folder: the
agent cannot write it, its confined server can read it but not write it, and neither it nor
`~/.phiward` may be a link. The hook trusts a wrapped entry only while a live launcher of its
command is a child of the hook's own Claude Code. A launcher the agent starts from Bash has the
sandboxed shell as its parent, never an ancestor of the hook. The hook takes the nearest of its own
ancestors (up to four) with launcher children as its Claude Code. So a Claude Code started inside
another's Bash is best effort (its environment is the agent's). The hook also trusts a record only
when its profile hash is the one the hook would build itself. An entry counts as bare when its
`env` changes the hidden list (`KRB5CCNAME`, `KRB5_CONFIG`), or when the config or your credentials
changed since the server started. It stays bare until Claude Code starts it again.

**Inside `launch` (Mode B).** The record folder is a guard folder in Mode B too, so a wrapped
server's launcher inside the session cannot write its record (`record_launch` gives up quietly),
and the hook keeps that server bare. It is not made writable: a record the session can write, it
can forge. This matters only for an MCP tool with a shell-like name under a `*` matcher: the hook
that `launch` writes matches the file tools and Bash only, and the kernel profile confines the
server. A launch inside the session runs its command directly, under the session's profile (on
Linux it knows it is inside from the session's seccomp filter; on macOS from the session's own
run folder, found from the account's home folder, never `HOME`); that profile is wider than a
server's own (`SERVER_READ_ONLY`), as on macOS. Any launch inside a session runs so, also for
another project: that project's repo config (`.phiward.toml`) is not applied. Any process may install such a filter on itself and its children, so the fingerprint is not a secret: forging it needs code running in the launcher or one of its ancestors, and such code could skip `launch` anyway.

**Plugins and configured servers.** A launcher also notes a hash of its `CLAUDE_PLUGIN_ROOT`, which
Claude Code exports only to a plugin's stdio server.
- A configured server needs a launcher without one, started with its entry's own id (`phiward launch
  --entry ID`, which `wrap` writes). That id is its launch hash. So one launcher never vouches for
  two entries, and no entry is parsed for what else it might start. An id found twice, anywhere in
  the config files' strings, is trusted for nothing (decoded JSON: a copy of the entry, in any
  wrapper, makes both untrusted).
- A plugin's server needs a launcher of its own copy's folder (any copy that applies to this
  project). A plugin's launcher counts only for that plugin's copy, never for a configured server.
  So a plugin never vouches for your server, and a broken or disabled plugin does not affect it. A
  plugin's entries carry no ids (the plugin's author writes them). There the hook counts every entry
  of the copy that may start a launcher with the command, also through `nice`, `env` or a shell's
  `-c` text (every `launch` word, split at `;`, `&&` and `|`). Counting too many only asks for more
  launchers.
- A launcher with any `CLAUDE_PLUGIN_*` variable but no plugin folder is trusted for nothing. If
  Claude Code itself was started with a `CLAUDE_PLUGIN_*` variable set, its configured servers'
  launchers carry it and are not trusted. A configured entry whose `env` sets `CLAUDE_PLUGIN_ROOT`
  or `CLAUDE_PLUGIN_DATA` counts as bare.

**How an entry is compared.** Folders are compared as they really lead. A plugin's entry is filled
in exactly as Claude Code fills it (checked with Claude Code 2.1.318): the folder as the registry
has it, the data folder without a trailing `/`. Its `${CLAUDE_PLUGIN_DATA}` is filled in as
`~/.claude/plugins/data/<id>`. A launcher of another fill does not count. A configured entry's
placeholders are filled in without the hook's own plugin variables. An entry whose command holds
`${VAR}` is compared as the hook fills it in, and a mismatch counts as bare. The launcher itself
counts only when the entry's command is, by its full path, the launcher phiward's install record
lists (a guard file). `phiward` by name never counts, since Claude Code looks it up on its own
`PATH` when it starts the server. A source checkout has no record. There the launcher is the
`phiward` found in the `PATH` folders the agent cannot write (the broker's rule, and none inside
`$CLAUDE_PROJECT_DIR`).

**Why the records are safe.** Claude Code's sandbox denies all of `~/.phiward` to Bash, after
`phiward install claude --write` writes it into `denyWrite`. Until then `doctor` says the shell is
not confined, and the hook refuses shell commands other than gateway calls. The shell counts as
confined only with that entry, and with no `allowWrite` that re-opens part of it. `denyWrite` holds
inside writable folders. So neither a session opened in the home folder, nor `--add-dir ~`, nor an
`allowWrite` can write, rename or replace the records or wrap's backups. `phiward mcp wrap` keeps
its backups only in `~/.phiward/backups`, a guard folder: nothing beside a config file is ever shown
as the operator's original. The spool, the one folder the agent must write, lives outside it
(`~/.phiward-spool`). `install` makes the folders up front. So bubblewrap, which protects only paths
that exist, covers them from the first session on.

**A server reached by URL** counts as remote only when the URL surely names another machine. The URL
must be plain ASCII with no `\`, no user part and no `%` in the host. The host must not be this
machine: `127.0.0.1` in any spelling, `0177.1`, `[::1]`, `[::ffff:127.0.0.1]`, `localhost`,
`*.localhost`, a link-local address, this machine's host name, a name `/etc/hosts` maps to it.
Claude Code reads URLs with Node's parser, which accepts many more spellings; any URL phiward cannot
read this strictly counts as this machine. A server on this machine (an IDE's) runs outside Claude
Code: phiward cannot wrap it (`phiward mcp wrap` leaves it alone and says so), and its command tools
may make only gateway calls. Not recognised: a DNS name that points at this machine, and this
machine's own network address (`10.x`, `192.168.x`); such a "remote" server counts as remote.

## Mode B: `phiward launch`

`phiward launch --tool claude` runs the whole agent tool, and every child it starts, in the kernel
profile: its file tools, MCP servers and hooks are confined too, so the hook is no longer the guard
for them. What changes for the operator:

**Files that run later.** A coding agent must write in the project, and you later run what is there:
tests, builds, scripts, git with its hooks and config, editor tasks, git hook managers (`.husky/`,
lefthook). No sandbox can tell a planted hook from a real change. `launch` makes the common places
read-only: git control files of every repository it finds at start, and, for the tool and a
wrapped server alike, the `.claude`, `.vscode`, `.idea`, `.cursor`, `.gemini` and `.codex`
folders as a whole, `.mcp.json`, `.gitmodules`, `.ripgreprc`, `.Rprofile` and `.Renviron`, at
any depth (on Linux, those that exist at start; it makes `.claude`, `.vscode` and `.idea` if
there are none), and what a link inside them leads to (it refuses to start where it cannot
tell). So R's `renv::init()`, which writes `.Rprofile`, runs once outside `launch`. On Linux it
also reports git control files a session changed. But the class cannot be closed by a list. **The rule:** treat everything in the project as written by the agent.
Run project commands inside `launch` (`phiward launch -- git status`, `phiward launch -- make
test`), or read the change before you run it outside.

**Known open items in this phase:**
- <a id="open-network"></a>the network is open under `launch` (a proxy for listed hosts is planned; `[network] limit` covers
  Mode A's shell commands only). The agent cannot read protected data under `launch`, so this
  matters for credentials and for gateway output;
- <a id="open-environment"></a>the tool's environment is an allow-list (proxy, CA and locale variables, the tool's own
  `ANTHROPIC_`/`CLAUDE_` ones); add more with `[launch] pass_env` in the user config, knowing that
  whatever you pass is readable by the agent;
- <a id="open-keychain"></a>macOS: the Keychain stays reachable (Claude Code keeps its own login there); items whose access
  list trusts `security` or `git credential-osxkeychain` can be read; other apps' preferences are
  readable;
- <a id="open-terminals"></a>macOS: only the session's own terminal can be read or written. Tools that open new terminals
  (`script`, `tmux`, `expect`) do not work yet. When xcrun's cache is stale, the `/usr/bin` tools
  print a cache warning (the cache is never written under `launch`). The per-user temp folder is
  writable (the compiler uses it);
- <a id="open-git-control-files"></a>both systems: git control files are covered for the repositories found when `launch` starts (top,
  nested, submodules; up to 50,000 entries, skipping `node_modules`, `.venv` and similar).
  Repositories created during a session and git hook managers (`.husky/`) are not: see the rule
  above. `.claude` is read-only as a whole (its settings can hold hooks), so Claude Code's "don't
  ask again" answers, `--worktree` and `/loop` durable tasks do not stay in the project under
  `launch`;
- <a id="open-unix-sockets"></a>Linux: unix sockets are limited by the kernel, not by their names.
  From Landlock ABI 9 (Linux 7.1) the whole tool reaches only the sockets made in the session
  and the name-service folders (sssd, nscd, userdb); a helper that cannot apply this stops the
  start. Below ABI 9, `--tool generic` and a wrapped MCP server cannot make unix sockets at all
  (seccomp; io_uring too). Below ABI 9, `--tool claude` relies on Claude Code's own sandbox,
  whose seccomp filter blocks unix sockets for Bash: `launch` gives it `--settings` that keep
  it on and forbid unsandboxed retries, and refuses to start when the filter is missing, does
  not work in the session's view, could be replaced by the session, or when settings open the
  sandbox. What runs outside that sandbox can still reach unix sockets outside the session:
  Claude Code itself, command hooks, MCP servers, LSP servers, the status line,
  `apiKeyHelper` and `!` commands you type. You configure these; the session cannot change
  the project's `.claude`. `launch` accepts only Claude Code's native build (a JavaScript
  program is refused) and runs the filter of the program that will run as Claude Code does,
  the binary itself with `ARGV0=apply-seccomp`; then it runs that same file. If a Claude Code
  release runs its filter otherwise, `launch` may prove a filter Claude Code does not use. The tests use a made-up
  filter; that the real binary's filter works inside launch's bubblewrap is shown only by
  the sandbox check. `launch` passes `--settings` last and refuses another one, unless it
  says the same, since Claude Code keeps only the last. `launch` makes
  `.claude`, `.vscode` and `.idea` if they are missing, and `.mcp.json` as a read-only `{}`
  placeholder. After a session, `launch` reports git control files that changed;
- <a id="open-hpc"></a>HPC through Kerberos and mounts (the operator's setup): a session cannot read the operator's
  Kerberos ticket caches (the one `KRB5CCNAME` names, `krb5cc*` files in the shared temp folders,
  `/run/user/<uid>` on Linux), `~/.ssh`, the SSH agent, or the shared SSH connection's socket. So
  the agent cannot log in to HPC itself and read data there unmasked. HPC work goes through the
  gateway, which the operator's broker runs over the operator's shared SSH connection
  ([hpc.md](hpc.md)): `phiward run --remote` and `phiward copy` (tested against a real cluster).
  Protected data on HPC storage mounted on the Mac needs its mount path in the protected roots.
- <a id="open-carry-over"></a>carry-over: each session gets a fresh config folder, built from a trusted copy and thrown away at
  exit. Nothing is shared between sessions. Instruction changes go to quarantine (`phiward carryover
  show | accept ID`, `add PATH`). Every file the session changed in the project is listed,
  instructions for models first. Auto memory is off unless `--memory`. Nothing is ever killed: on
  macOS a process a session leaves behind keeps running, but what it writes does not reach a later
  session (tests/test_v2_s17.py, test_18);
- <a id="open-fresh-config"></a>a fresh config folder for the tool: your normal Claude Code memory, skills, plugins and MCP
  servers are not there until you add them (`phiward carryover add`), and a login token is needed
  ([launch.md](launch.md)).

**Recorded limits (beta).** These stay open in the beta. Each one belongs to the class "files that
run later" or to the macOS process model:

| | Limit | What reduces it |
|---|---|---|
| <a id="l1"></a>L1 | Files that run later and are not in launch's list (`.husky/`, `.envrc`, `.devcontainer/`, `.tool-versions`, a `Makefile`) can be made or changed in the project; the exit report lists them. | The rule above. |
| <a id="l2"></a>L2 | Linux: a name of the list that is missing at the start can be made and written in the session: `.cursor`, `.gemini`, `.codex`, `.gitmodules`, `.ripgreprc`, `.Rprofile` or `.Renviron` at the top, and any of them, `.claude`, `.vscode` and `.idea` too, in a subfolder; so can a nested one that is a link (where it leads is read-only, the link can be replaced) and one past the first 50,000 entries of the walk (launch says where it stopped, at the start and in the exit report). A bind needs a file that exists. The exit report lists them. On both systems, the trees of installed code (`node_modules`, `.venv`, `venv`, `site-packages`, `renv/library`, `.tox`, `target`, `.git`, `__pycache__`, `.mypy_cache`; `SKIP_TREES` in `wholetool.py`) are not walked, and the names of the list inside them stay writable; the links in `.claude/worktrees` are not followed. A `git pull`, `checkout` or `switch` that changes a tracked file in a `.claude`, `.vscode` or `.idea` folder fails partway inside `launch`: run it in your own terminal. | The rule above. |
| <a id="l3"></a>L3 | `.claude/settings.local.json` is read-only, but a plain run outside `launch` still reads whatever was in it before the session. | Read it once before the first `launch`. |
| <a id="l4"></a>L4 | macOS: the per-user temp folder is writable, and it is also your own TMPDIR. A file planted there can be used by a later plain run. A session can also **read** `/private/tmp` (except Kerberos caches) and the per-user temp folder, where your own tools leave files (R's `RtmpXXXX`, Python temp files, other Claude Code sessions' scratch). | Do not run tools that load code from TMPDIR; keep protected data out of temp folders. |
| <a id="l5"></a>L5 | macOS: a process that leaves the tool's process tree (a new session, a double fork) keeps running after the tool exits; `launch` never ends a process. Its session folder is moved to `trash/` and thrown away, and a later session's folder is new, so nothing it writes there reaches a later session. It can still write the project (after the report, not reported), the spool and the per-user temp folder, and can make a folder again at its old run path (never read). | Close the terminal after a session; a separate macOS user for the agent (not part of this release). |
| <a id="l6"></a>L6 | Carry-over (stateless): each session runs in a config folder built from a trusted copy that no session can read or write, and thrown away after it. Nothing in the tool folder is shared between sessions: no transcripts, no login, no caches, no history. On macOS two things outside it still are: the Keychain (Claude Code keeps its login there, so a session may add or change login items, including the one your plain `claude` uses) and the per-user temp folder, which your own tools also use. Instruction files a session changes, and the MCP and permission keys of `.claude.json`, go to quarantine; only what you accept (`phiward carryover accept`) or add yourself (`phiward carryover add PATH`) is trusted. A session cannot read another session's folder. Everything phiward keeps for this may be deleted at any time; you lose only what it costs to rebuild ([launch.md](launch.md)). Login: a fresh folder means a new login each time, unless you set `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`) or `ANTHROPIC_API_KEY`, which the agent can read. Project memory (`CLAUDE.md`, `AGENTS.md`, `.claude/rules/` in the project) is reported, not put back. | Read the quarantine and the project report before you accept or run anything. |
| <a id="l7"></a>L7 | Names that a gateway command makes while it runs are not in that run's inventory, so they are not masked in its own output. The next call sees them. | Print aggregates, not names (rule 3 of the agent rules in a project's `AGENTS.md`). |
| <a id="l9"></a>L9 | `claude --bare` and an Agent SDK app with `settingSources: []` load none of phiward's wiring (hook, sandbox block, deny rules), and nothing says so. | Do not use `--bare` on protected work; load the user settings in an SDK app or pass `phiward install claude --json` as its settings, or run it under `phiward launch` ([unattended.md](unattended.md)). |
| <a id="l10"></a>L10 | Linux: a folder of thousands of entries above a protected folder makes `launch` show that folder whole, with its protected entries masked (the view must fit in bwrap's 9000 arguments). There, a protected entry made or replaced after the start is not hidden. `launch` says how many folders it shows whole, and refuses when the folder that holds a protected root would have to be shown whole (it would list the root's name). | Protect large data folders as roots, not one entry each among many; keep new protected data in folders that exist before the session. |
| <a id="l8"></a>L8 | Two sessions in one project share its write places: one can plant files that the other runs. Not confirmed in a test. | Several sessions may run side by side; prefer one per project when one of them reads untrusted input. |

