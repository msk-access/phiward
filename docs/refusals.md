# What is refused, and the way around it

phiward refuses some things that typical work meets. This page lists them: what works, what is
refused and why, and the way around each one. Each refusal names its next step in one line, and
`phiward doctor` warns about the ones it can see before you start. The refusals that are the
product itself (a read of protected data, a credential, a guard file) are in
[daily-use.md](daily-use.md#when-a-command-is-refused).

Run `phiward doctor` in the project folder first. Its section "launch (Mode B)" runs the start
checks of `phiward launch` without starting anything, and its Claude Code section covers Mode A.

## What works

- Edits, builds and tests in the project: `pytest`, `npm run dev`, `git status`, `git commit`.
- Package installs into the project (`.venv`, `node_modules`), with the caches below.
- Work with protected data through the gateway: `phiward run -- CMD`, `phiward copy SRC DST`.
- Under `phiward launch`: HTTPS to public hosts through phiward's proxy, private ranges you list,
  and `--resume` and `-c` (this project's transcripts are kept).

## `phiward launch` (Mode B)

**No protected paths yet.** Launch says:
no protected paths are configured: there is nothing to confine; run `(cd ~ && phiward setup)` first

**The folder cannot be the project.** Launch refuses `/`, your home folder or a folder above it,
a dot folder in your home, `~/Library` on macOS, and a folder that holds a phiward folder. Each
of them is writable as a whole in a session, and other programs run what is there later. The
message ends: ); start the tool in a project folder

**A folder on PATH inside the project** (an activated `.venv`, direnv, `node_modules/.bin`). Your
own shell runs what is there after the session, and the session could write there. The message
names the entry and the step. For an activated `.venv`: run `deactivate` (or take the entry
off PATH), then start again; in the session, use `.venv/bin/python` or `uv run`. For any other
entry: take it off PATH (for direnv, `direnv deny`), then start again. Doctor names the entry
relative to the project (`--show-paths` names it in full).

**A settings file or folder that is a link** (`.claude` or `.vscode` linked to a dotfiles
repository). A session's writes would reach a file a later plain run reads. The message ends:
in the project is a link; replace it with a real file or folder

**A wrapper, a shim or an old Claude Code** (`module load` scripts, asdf, mise, volta, a site
`claude` script). Launch needs Claude Code's own program, at the version whose hooks it writes,
and never starts a script to ask. The step:
run Claude Code's own program directly (the native binary, or the npm package's cli.js), not a wrapper or a shim, or use --tool generic for another tool

Launch needs Claude Code 2.1.295 or newer. Doctor judges the build from its files and starts
nothing; for a native binary it uses the version it read, and when that is unknown it says only
launch can tell.

On Linux, the JavaScript (npm) build is refused too: it does not carry Claude Code's seccomp
filter. Update to the native build: `claude install`.

**Files that run later are read-only** (`.claude`, `.vscode`, `.idea`, `.Rprofile`,
`.Renviron`, `.mcp.json` and the like, at any depth). Other tools run them later, outside the
session. The operating system refuses the write with "Operation not permitted", which phiward
cannot change, so doctor says it before the start:
NOTE: in a launch session the files other tools run later are read-only, at any depth: .claude, .vscode, .idea, .Rprofile, .Renviron, .mcp.json and the like (a write gets 'Operation not permitted'). Edit them in a plain terminal, or `phiward carryover add` for Claude Code's own files; run renv::init() once outside launch.

So skills, agents, hooks, editor settings, Claude Code's `--worktree` and `/loop` tasks are not
written inside launch.

**The network.** A session reaches only HTTPS (CONNECT) to public addresses through phiward's
proxy. A private address (an internal GitLab, a package mirror) is refused until you list its
range in `[launch] private_networks` of the user config
([configuration.md](configuration.md)). A plain HTTP request gets:
only CONNECT (HTTPS) goes through phiward's proxy; use an https:// URL for the index or mirror

An `ANTHROPIC_BASE_URL` the proxy would refuse (`http://`, this machine, a private range not
listed) stops the start; doctor warns about it. Use Mode A for a model on this machine, or list
the range. Details: [launch.md](launch.md).

**Linux below Landlock ABI 9 (the inner mode).** There Claude Code's own sandbox blocks unix
sockets, and launch passes its own `--settings`, last. So launch refuses your own `--settings`
(put them in managed settings, or in launch's trusted copy with `phiward carryover add FILE --as
settings.json --tool claude`), Claude Code commands such as `claude mcp` and `claude doctor`
(run them outside launch), and a `--` among Claude Code's arguments:
launch passes --settings to Claude Code as the last arguments, so `--` cannot be among them: drop the `--` and put the prompt last

Doctor names the mode launch would use (Landlock or inner), and checks your settings for the
inner mode.

**The login.** Each session starts with a fresh config folder, so Claude Code asks you to log in
every time. To log in once, run `claude setup-token` and set `CLAUDE_CODE_OAUTH_TOKEN` (the agent
can read it).

**A source checkout.** Launch checks phiward's installed files first. A source checkout or an
editable install has no install record: install with `uv tool` or `pipx`, or set
`PHIWARD_DEV=1` (developers only).

## Mode A: Claude Code with the hook and its sandbox

**A sandbox opener stops the whole shell.** One of `network.allowLocalBinding` (macOS),
`allowUnixSockets`, `allowAllUnixSockets` or `allowMachLookup` in any settings level means the
shell is not confined, and the hook refuses every command but a gateway call. Doctor's line
"sandbox confines the shell" names the key and the file. Remove the key; run a dev server or
docker in your own terminal. A non-empty `sandbox.excludedCommands` does not stop the shell:
the hook checks the text of every command, and refuses a path it cannot see
([setup.md](setup.md)).

**Package caches are read-only.** Claude Code's sandbox writes only the project and the temp
folder. phiward adds no `allowWrite` for the caches, because a cache a session writes is code a
later run executes. Doctor says:
NOTE: Claude Code's sandbox keeps the package caches outside the project read-only (pip: ~/.cache/pip, or ~/Library/Caches/pip on macOS; uv: ~/.cache/uv; npm: ~/.npm), so an install that writes its cache fails with 'Operation not permitted'. Use `pip install --no-cache-dir`, or set PIP_CACHE_DIR, UV_CACHE_DIR and npm_config_cache to folders under $TMPDIR. phiward adds no allowWrite for them: a cache a session writes is code a later run executes.

Under `phiward launch` the caches are the session's own, so installs work there.

**git with credentials.** The SSH agent, SSH keys and the keychain are hidden from the session.
The session note tells the agent:
git push, pull and fetch that need the operator's SSH key or keychain run in the operator's own terminal

**`@file` mentions.** `phiward install` turns them off: a mention would put a file's text into
the prompt without a tool call the hook sees. Ask the agent to read the file with the Read tool.

**Grep and Glob above a protected root.** When a root sits inside the project (`./data`), a Grep
or Glob from the project folder would list it, so it is refused. Give it a subfolder that holds
no protected folder (`src/`). Doctor warns when the folder is above a root.

**Your own `--settings`.** Claude Code keeps one `--settings`. Put your own settings in your user
settings (`~/.claude/settings.json`) or in managed settings, and start Claude Code with the file
phiward writes (doctor names it).

**Files that run later.** A write to `.vscode/`, `.Rprofile`, a skill or a hook asks you first.
In `-p`, auto, `dontAsk` or `bypassPermissions` mode nobody can be asked, so it is refused: write
the file yourself.

## The gateway: `phiward run` and `phiward copy`

**A program not on the broker's PATH.** The broker keeps the PATH of the terminal that started
it. Doctor warns about each listed program it does not find there. Start the broker again from a
terminal where the program works (after `conda activate`), or list the program by its full path.

**The config changed.** The broker refuses requests after any change to the config, the pins or
the listed programs. Restart the broker. Doctor does not compare the config's content with the
broker's yet.

**A copy out of a root.** A copy may not take protected data out of the protected folders:
the destination is not inside a protected path of the user config; results leave a root only as `phiward run` output (counts and summaries)

More messages of `run` and `copy`: [daily-use.md](daily-use.md#when-a-command-is-refused).
