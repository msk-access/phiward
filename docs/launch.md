# Mode B: the agent tool under `phiward launch`

- **For:** people who run the agent in a terminal and want the whole tool confined.
- **Before:** the [quick start](quickstart.md), steps 1 and 2.
- **You will have:** sessions in phiward's kernel profile, with settings you approve.

`phiward launch --tool claude` runs **the whole agent tool**, and everything it starts,
inside the kernel profile: its file tools, shell, MCP servers and hooks. The tool cannot read your
protected data, whatever the model asks it to do. You work with protected data through the
gateway (`phiward run`, `phiward copy`), which masks what comes back. This is the
strongest mode (Mode B). A normal Claude Code session wired by the hook (Mode A) is the other;
[modes.md](modes.md) compares them.

Tested with the real Claude Code on macOS: reads of protected data by the file tools and the shell
were refused, and the gateway returned masked output. Mode B is for the terminal: driving a
`launch` session from the desktop app with Remote Control is not tested yet.

How a session's settings stay trusted:

```mermaid
flowchart TD
  A["The trusted copy (what you added with carryover add)"] --> B["A fresh folder for this session"]
  B --> C["The session runs in the kernel profile"]
  C --> D["What it changed goes to quarantine"]
  D --> E{"phiward carryover show: you read it"}
  E -->|"accept"| A
  E -->|"leave it"| F["Not used by later sessions"]
```

## Once

1. Install and set up: steps 1 and 2 of the [quick start](quickstart.md).
2. A login token, because each session starts in a fresh config folder: run `claude setup-token`
   in a plain terminal, open the URL, approve, and keep the token it prints. Then, in the terminal
   where you start sessions:

   ```bash
   export CLAUDE_CODE_OAUTH_TOKEN='<the token>'
   ```

   The agent can read this variable, like an API key. Revoke it in your Claude account settings
   when you no longer need it.
3. The broker must run (for `run` and `copy`): best as a login service
   ([setup.md](setup.md#5-start-the-broker)), or `phiward broker` in a terminal of its own.

## Every session

From the project folder:

```bash
phiward launch --tool claude
```

- `--memory`: turn Claude Code's auto memory on. It then lives in the session's folder, and its
  changes go to quarantine like any other instruction.
- `launch` refuses to start in `/`, your home, a folder above or inside protected data, a dot
  folder, `~/Library`, a folder on your `PATH`, or a phiward folder.
- Several `launch` sessions may run side by side, also in one project (see limit L8 of the
  threat model).

## What a session can and cannot do

| | Can | Cannot |
|---|---|---|
| Files | read and write the project; write its own session folder and the spool | read protected roots, patterns or derived folders (`.git`, snapshots, and on Linux other mounts of the same data); read credentials (`~/.ssh`, `~/.aws`, `~/.claude`, other agent tools' logins, browser profiles, Kerberos tickets and keytabs, SSH keys your SSH config names, research-data and registry logins), shell histories, the Trash, or the gateway's `write_to` folders; write anywhere else |
| Settings that run later | | change `.mcp.json`, `.claude/settings*.json`, `.vscode` settings, or git control files (hooks, config) in the project. On Linux a git control file that is missing at the start (`commondir`) can be made; the report at the end names it. A wrapped MCP server (`--entry`) cannot write the project's `.git` folders, `.claude` or `.vscode`; on macOS also `.idea`, `.gitmodules`, `.ripgreprc` or a new `.git` (on Linux a name missing at the start can be made) |
| Processes | run any program in the profile | read other terminals, signal processes outside, inject keystrokes, open or script other apps |
| Network | HTTPS to public addresses, through phiward's proxy ([below](#the-network)) | reach this machine's own services, its link or private ranges; use plain HTTP, UDP, or tools that ignore the proxy variables; reach outside unix sockets (the SSH agent, your shared SSH connection, docker) |
| Protected data | `phiward run -- CMD` (masked output), `phiward copy` (no names printed) | anything else |

## The network

The session has no direct network. `launch` runs a proxy outside the profile, and the tool's
`HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` (and their lowercase forms) name it, with a token for
this session only; `NO_PROXY` is empty. Claude Code, git, pip, npm and curl use it.

- **Only public addresses.** The proxy looks the name up once, checks every address it gets
  back, and connects to the address it checked. It refuses this machine (`localhost`,
  `127.0.0.1` in any spelling, `[::1]`, this machine's names and addresses, which it reads again
  for each connection), the local link (`169.254.x`, `fe80::`) and the private ranges (`10.x`,
  `172.16-31.x`, `192.168.x`, `100.64.x`, `fc00::/7`).
- **Private ranges you need** (an HPC web service, an internal Git server): list them in
  `[launch] private_networks` in your user config ([configuration.md](configuration.md#launch)).
  A project's `.phiward.toml` cannot.
- **HTTPS only** (CONNECT). Plain HTTP through the proxy is refused.
- **A proxy of your own:** when the terminal you start `launch` from sets `HTTPS_PROXY` (or
  `ALL_PROXY`) to an `http://` proxy, phiward's proxy goes through it, by the checked address
  only (`CONNECT <address>:443`). A name that does not resolve on this machine is refused, not
  sent on. Any other kind of proxy there (`https://`, `socks5://`) stops the start.
- **At most 64 connections at once.** One more is refused, not queued.
- `launch` refuses to start when the proxy cannot start.

What this breaks:
- MCP servers over HTTP on this machine, IDE integrations (the IDE's WebSocket on localhost),
  and `/login` with a localhost callback (use `CLAUDE_CODE_OAUTH_TOKEN`, above). Stdio MCP
  servers the session starts work.
- Tools that ignore the proxy variables (raw sockets, `ssh` to port 22, some Go and Java tools),
  and all UDP. They fail visibly.
- Docker over TCP (`DOCKER_HOST=tcp://localhost`); the Docker socket is blocked already.
- **macOS:** the session cannot reach a server on this machine, also one it started itself: test
  suites with local HTTP fixtures, dev servers, Jupyter kernels (ZMQ over TCP by default) and Dask
  local clusters. Use unix sockets in the project or the session's temp folder, or an IPC
  transport (`jupyter ... --transport ipc`). Name lookups still work.
- **Linux:** the session has a network of its own, with its own `localhost`: servers it starts
  itself work. Name lookups inside the session fail (`ping`, `dig`, `ssh` to a name); tools that
  use the proxy do not need them. `launch` refuses to start where network namespaces are not
  available: it says so when `user.max_net_namespaces` is 0, and bubblewrap stops the start
  when it cannot make one for another reason. Nothing runs then; `phiward doctor` checks both.

## When a session ends

- **The session's folder is thrown away.** Each session starts from a trusted copy in
  `~/.phiward/carryover/claude/`, which no session can read or write. Nothing is shared
  between sessions: no transcripts, no login, no caches.
- **Instruction changes go to quarantine.** These are files Claude Code reads as instructions
  or settings (`CLAUDE.md`, `rules/`, `skills/`, `agents/`, `commands/`, `plugins` you install,
  `settings.json`), and the MCP and permission keys of `.claude.json`. The exit message lists
  them:

  ```bash
  phiward carryover show --tool claude
  phiward carryover accept ID [ITEM...] --tool claude
  phiward carryover add PATH [--as NAME] --tool claude   # your own CLAUDE.md, a skill
  phiward carryover status --tool claude                 # sizes; what is safe to delete
  ```

  `accept ID settings.json` takes the whole `settings.json` as the session left it; `show` lists
  the keys that changed, and for `.claude.json` the value `accept` writes, so read it first.
  Items you do not name stay in quarantine. `add ~/.claude.json` takes only its MCP servers,
  trust and allowed-tools keys, never the login or the history; an MCP server's `env` and
  header values there are readable by the agent.
- **The project report.** It lists every file the session changed that is read as instructions
  for models (`CLAUDE.md`, `AGENTS.md`, `.claude/`), every file that runs later (git control
  files of any repository, hooks, build files, `.pth`, scripts, executables) and every settings
  file. Other changed files are named when there are 10 or fewer, and otherwise only counted;
  code under `.venv` or `node_modules` is in that count. In a very large project it says so, and
  past its limit checks only the first three kinds (dot folders such as `.claude` first); past
  2,000,000 entries it checks nothing more. **Treat everything in the project as written
  by the agent**, and read it before you run anything outside `launch`.
- **Anything under `~/.phiward` may be deleted at any time** (a disk quota, an HPC purge, or
  you). The next start rebuilds from what is left, and it never trusts a folder a session could
  write. `carryover status` says what each deletion costs.

## HPC

See [hpc.md](hpc.md): HPC through your Kerberos ticket and mounts, `copy` to approved remotes, and
`run --remote` for commands on HPC.

## Linux: the session's view

On Linux the session sees a snapshot of the file system. Every folder above a protected path or
a credential (for example `/`, `/home`, your home) is rebuilt for the session from the entries it
held at the start, without the protected ones. A protected folder replaced at its path, and a
pattern match, credential or ticket cache made after the start, are not in the view.

What this costs:
- An entry the host adds to one of those folders after the start (a new folder in your home) is
  seen only by the next session. A file the host replaces there (an editor saving `~/.gitconfig`)
  stays as it was for the session.
- The session's view is checked against what was checked before the tool starts. An entry the
  host removes from one of those folders while the session starts is left out of the view. An
  entry the host replaces while the session starts stops the start: nothing runs; start again.
  A short window stays: an entry removed between bubblewrap's own check and its mount stops the
  start with `bwrap: Can't bind mount ...`; start again.
- A folder that is missing from the view cannot be made: `mkdir ~/.ssh` fails (read-only).
- A folder that can be entered but not listed (mode 711, common on HPC) cannot be rebuilt. It is
  shown whole, with the protected roots and credentials in it masked; one made in it later is not
  hidden.
- On Linux the view must fit in bwrap's 9000 arguments, about three for each entry it rebuilds. A
  protected folder below a folder of thousands of entries (a large data folder) would need more,
  so `launch` shows such folders whole instead, those that save the most first, and says before
  the tool starts how many folders it shows whole. In those folders, as in a 711 folder, a
  protected entry made or replaced after the start is not hidden. A folder shown whole lists its
  masked entries by name, so the folder that holds a protected root, or where a pattern's `*`
  names the protected entries, is never shown whole: if the view cannot fit then, `launch`
  refuses, and you protect that folder as a root instead (`/data/study` rather than
  `/data/study/<name>`). `launch` also counts bwrap's whole command line before it starts and
  says so when it is too long. A pattern whose `*` falls on a folder that cannot be listed cannot
  cover it: `launch` refuses, and you protect that folder as a root instead.
- A pattern follows a linked folder only in its literal part (`/data/...` through `/data ->
  /gpfs/...`), not at a `*` level: a match reached through a link there is hidden at the link
  only. Protect the target as a root.

**Protection follows the path, on Linux and macOS.** A protected folder that you move into a
folder the session can see is readable there, during a session or after it.

## Self-check

It also reports start-up files next to phiward (`.pth`, `sitecustomize` in any form) that no install
record lists, or that changed since install. One it cannot check: `_virtualenv.py`, which uv's
and virtualenv's environments add and no record lists.

`launch` checks its own installed files against the installer's record first, in a separate
Python that reads no compiled files. A changed file, a compiled file that does not match its
source, or a file the record does not list makes it refuse: reinstall. Without a record (a source
checkout or an editable install) it refuses unless `PHIWARD_DEV=1` is set. It cannot find code
that changes the launcher itself so that the check is skipped, and it trusts the installer's
record: a process running as you that changes a file **and** its record line is not found. It
is meant to catch what a session without `launch` left behind by mistake or by a careless agent;
when in doubt, reinstall: the step names the command for the tool that installed phiward.

## Limits in this release

- **Not hidden:** shell start-up files (`~/.zshrc`, which may export tokens), `~/.gitconfig`
  (which may hold an `http.extraheader`), and, on macOS, Keychain items whose access list trusts
  the `security` tool (the session can reach the Keychain service). Keep tokens out of start-up
  files; prefer Mode A's test result for Keychain-backed tokens until Mode B is checked.
- **Git control files are read-only** for the repositories found at the start, so `git remote
  add`, `git config`, `git submodule update --init`, `git worktree add` and `git push -u` fail
  inside `launch` (and `git switch` to a remote branch, `git branch -u`, `-m` and `-d` cannot
  record their settings: `git switch` still prints "set up to track" but does not); run them in
  your own terminal. A repository the session makes is not
  read-only, but its control files are listed in the exit report as files that run later.
- **Linux: Claude Code's own sandbox runs inside launch.** phiward turns it off only on macOS.
  On Linux its bubblewrap starts inside phiward's, and where the host refuses a user namespace
  inside bubblewrap, Claude Code's Bash tool fails (visibly: the command is refused, nothing
  runs unconfined). Bash reaches the network through Claude Code's own proxy, which then goes
  through phiward's; that a given Claude Code version does this is for the real-tool check to
  confirm.
- **A launch inside a session** (a wrapped MCP server, or a launch for another project) runs its
  command directly, under the session's own profile: not the narrower profile of a server (which
  keeps more of the project read-only), and not another project's `.phiward.toml`. On macOS a file only that profile denies tells `launch` it is inside;
  on Linux the session's seccomp filter answers one unused system call with an error number
  nothing else gives. Anything else (no filter, another sandbox's filter) builds the full
  profile; where `~/.phiward` cannot be written, that launch refuses and nothing runs.

Read [threat-model.md](threat-model.md) (Mode B, [limits L1–L10](threat-model.md#l1)). In short:
- **The network goes only to public addresses, through phiward's proxy** ([above](#the-network)).
  A session cannot read protected data, so it cannot send it. But it can carry out what it can
  read, to any public host: gateway output (masked), the login token, the project.
- **macOS:** a process that leaves the tool's process tree keeps running after the session
  (L5). It can no longer change what a later session reads, but it can write the project, and
  it keeps its session's one allowed port after the proxy is gone. Close the terminal after a
  session.
- **macOS:** the Keychain and the per-user temp folder are shared with your own tools.
- **Masking covers names and identifiers, not content.** Through the gateway, print counts and
  summaries, not records (rule 3 of the agent rules that `phiward init` adds to `AGENTS.md`). Dates can be masked with the `dates` pack.
- `tmux`, `script` and other tools that open a new terminal do not work yet.
- Other tools than Claude Code run under `launch -- PROGRAM` with the boundary, but without a
  per-session config folder (no adapter yet).

Next: what Mode B does not cover is in [the threat model](threat-model.md#mode-b-phiward-launch).
