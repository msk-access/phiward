# For IT and security teams: what phiward runs on a Mac

- **For:** the people who run an endpoint tool on Macs where phiward is used.
- **You will have:** every process phiward starts, with its exact command line and a regex
  for it, so that you can recognise each one and, if your policy needs it, scope one exception.

## What phiward is

phiward keeps protected health information (PHI) out of what an AI coding agent sends to its
model provider. It runs the agent's commands in a kernel profile (`sandbox-exec`) and masks the
output. It is a Python package that runs as the user.

It needs no admin rights, no kernel extension and no network service. It opens no listening
port: the agent and the broker talk through files in a private folder.

## What it installs and writes

All of it is in the user's home folder, written by the user's own account:

- **The package**, installed by `uv tool` or `pipx`, with its own Python: for example
  `~/.local/share/uv/tools/phiward/` (uv) or `~/.local/pipx/venvs/phiward/` (pipx). Below it,
  `lib/python3.X/site-packages/phiward/` holds phiward's code and its two hook files
  (`data/clean-exec.sh`, `data/clean-env.awk`).
- **The launcher** `~/.local/bin/phiward`: a Python script that uv or pipx writes.
- **phiward's own state** in `~/.phiward/`: the sessions of `phiward launch`, the kernel profiles
  of running commands (`profiles/`, one file per command, removed when it ends), records of
  running launchers, the broker's status and backups.
- **The spool** `~/.phiward-spool/`: requests from the agent to the broker, and their output.
- **Scratch folders** in `~/.cache/phiward/`: one per gateway command, removed when it ends.
- **The user config** `~/.config/phiward/config.toml`, and `~/.config/phiward/claude-settings.json`.
- **Claude Code's settings** `~/.claude/settings.json`: the hook entries and the sandbox settings.
- **The login service** `~/Library/LaunchAgents/org.phiward.broker.plist`, if the user sets it up,
  and its log `~/Library/Logs/phiward/broker.log`.
- **In a repository, on request:** `.claude/settings.json` (`install --project`) and the git
  hooks `.git/hooks/pre-commit` and `pre-push` (`phiward init`).
- **The Claude Code plugin**, if the user installs it: Claude Code copies it into its own plugin
  folder (`~/.claude/plugins/...`).

## Every process phiward starts on macOS

Each row is one kind of process. The ID points to its command lines and its regex in the
[list below](#the-command-lines). phiward starts no process whose command line holds code:
no `python -c`, no `sh -c` of its own, no `awk` program, no `sandbox-exec -p`. The one
exception is the project hook's fixed line (R1, R2), which a repository commits.

| ID | Parent | Image | How often | What it does |
|---|---|---|---|---|
| G1 | the broker | `/usr/bin/sandbox-exec` | each `phiward run` request | runs the agent's command in the gateway's profile |
| G2 | `phiward doctor` | `/usr/bin/sandbox-exec` | each `doctor` | the gateway's self-test: `/usr/bin/true` in the profile |
| C1 | the broker | `/usr/bin/sandbox-exec` | each local `phiward copy` | makes the destination folder (`/bin/mkdir`) |
| C2 | the broker | `/usr/bin/sandbox-exec` | each local `phiward copy` | copies the files (`/usr/bin/rsync`) |
| C3 | the broker | `/usr/bin/sandbox-exec` | each copy from a remote host | runs `/usr/bin/ssh` through the user's shared connection |
| C4 | the broker | `/usr/bin/sandbox-exec` | each copy from a remote host | unpacks what ssh receives, with a file in the package |
| C5 | the broker | `/usr/bin/ssh` | each request to a remote host | reads the ssh config (no network) |
| C6 | the broker | `/usr/bin/ssh` | each request to a remote host | checks that the shared connection is up |
| H1 | Claude Code | `/bin/sh` | each tool call, prompt and session start | the hook's script: clears the Python and loader variables, then runs phiward |
| H2 | the H1 script | `/usr/bin/awk` | with each H1 | lists the variables to clear, from a file in the package |
| H3 | the H1 script (exec) | the Python | with each H1 | the hook itself: decides the tool call, checks the prompt, or writes the session note |
| P1 | Claude Code | `/bin/sh` | each tool call, prompt and session start, with the plugin | the plugin's copy of the H1 script |
| P2 | the P1 script | `/usr/bin/awk` | with each P1 | the plugin's copy of H2 |
| P3 | the P1 script or the R1 line (exec) | the Python | with each P1 or R1 | the hook, through the launcher |
| P4 | Claude Code | the Python | once per session, with the plugin | phiward's MCP server (the gateway's tools) |
| L1 | `phiward launch` | `/usr/bin/sandbox-exec` | once per launched session or wrapped MCP server | runs the agent tool, or the server, in the tool's profile |
| L2 | `phiward launch` | `/usr/bin/getconf` | each launch | asks for the per-user temp folder |
| L3 | Claude Code, under `launch` | the Python | each tool call and prompt | the hook in a launched session |
| L4 | `launch`, a wrapped server, `doctor`, the session note | the Python | each start | phiward checks its own installed files, in a separate Python |
| L5 | `launch --tool claude`, `install`, `doctor` | Claude Code | each start | asks Claude Code its version (`--version`, from `/`) |
| M1 | Claude Code | the Python | once per session, per wrapped MCP server | starts a wrapped MCP server under `phiward launch` |
| M2 | `phiward launch` (exec) | the server's | inside a launched session | a wrapped server inside a session: its own command line, unchanged |
| S1 | launchd | the Python | at login, kept running | the broker |
| S2 | `phiward setup`, `phiward broker --service --write` | `/bin/launchctl` | when the user sets up the login service | loads or restarts the broker's service |
| D1 | `phiward install` | the Python | each `install --write` | checks that the isolated Python finds phiward |
| D2 | `phiward doctor` | `/bin/sh` | each `doctor` | runs the H1 script once, with `phiward --help` |
| R1 | Claude Code | `/bin/sh` | each tool call, prompt and session start, in a repository with `install --project` | the project hook: one fixed line |
| R2 | the R1 line | `/usr/bin/awk` | with each R1 | lists the variables to clear (its program is in the fixed line) |
| R3 | git | `/bin/sh` | each commit and push, in a repository with `phiward init` | the git hooks phiward writes |
| R4 | the R3 hook (exec) | the Python | with each R3 | phiward's git checks |
| R5 | R4 | `git` from `PATH` | with each R4 | the git commands of those checks |

"The Python" is phiward's own Python: the `bin/python` of its uv or pipx environment, which
points to the Python that uv or the system installed. "The launcher" is `~/.local/bin/phiward`,
a Python script; the kernel shows it as `<python> <launcher>`.

The user also starts phiward in a terminal (`phiward launch -- claude`, `phiward doctor`,
`phiward setup`). Those command lines are the user's own words after `<python> <launcher>`.

Rarer forms, not in the list: a local copy without rsync runs `/bin/cp -R -n -- SOURCE...
DEST`; a dry run runs `/usr/bin/true`; a git hook without `phiward` on `PATH` runs `python3 -m
phiward git-hook NAME`; `phiward run --remote` runs `/usr/bin/ssh ... HOST -- WORDS`, where
WORDS are the agent's own.

### The command lines

Each entry gives the command line as the kernel shows it (`argv`), and a regex for it (`regex`;
`-` where none fits). The regexes are written for an install by uv or pipx. The placeholders:

- `<python>`: phiward's Python, such as `~/.local/share/uv/tools/phiward/bin/python`;
- `<PKG>`: its `site-packages` folder; `<plugin>`: the plugin's folder;
- `<launcher>`: `~/.local/bin/phiward`;
- `<profile>`: `~/.phiward/profiles/` and a random name of 32 hex digits, then `.sb`;
- `<home>`: the home folder; `<uid>`: the user's id; `<entry>`: 16 hex digits;
- `<path>`, `<source>`, `<dest>`: paths the request names;
- `<ssh-config>`, `<socket>`, `<host>`: the user's ssh config file, the shared connection's
  socket and the host; `<remote>`: the command for the remote host (`tar -c -f - -C DIR -- NAME`);
- `<record>`: the package's install record; `<claude>`: Claude Code's program;
- `<command> ...`, `<tool> ...`, `<server> ...`, `<arguments>`: the user's or the agent's own
  words;
- `<project-hook>`, `<project-prompt-hook>`, `<project-note>`: the project hook's fixed text
  (`PROJECT_HOOK`, `PROJECT_PROMPT_HOOK` and `PROJECT_NOTE` in `install.py`), which begins
  `command -v phiward >/dev/null 2>&1 || `; `<awk-program>`: the awk program in it, which begins
  `BEGIN{for(k in ENVIRON)`.

A path with a space in it shows as more than one word, so `[^ ]+` does not match it. Use `.+`
there if your users have such paths.

<!-- argv-shapes: tests/test_docs_endpoint_security.py and tests/test_macos_processes.py read this block -->
```text
G1 argv  /usr/bin/sandbox-exec -f <profile> <command> ...
G1 regex ^/usr/bin/sandbox-exec -f [^ ]+/\.phiward/profiles/[0-9a-f]{32}\.sb /?[^ ]+
G2 argv  /usr/bin/sandbox-exec -f <profile> /usr/bin/true
G2 regex ^/usr/bin/sandbox-exec -f [^ ]+/\.phiward/profiles/[0-9a-f]{32}\.sb /usr/bin/true$
C1 argv  /usr/bin/sandbox-exec -f <profile> /bin/mkdir -p -- <path>
C1 regex ^/usr/bin/sandbox-exec -f [^ ]+/\.phiward/profiles/[0-9a-f]{32}\.sb /bin/mkdir -p -- /
C2 argv  /usr/bin/sandbox-exec -f <profile> /usr/bin/rsync -rt --ignore-existing --exclude=.claude/ -- <source> ... <dest>
C2 regex ^/usr/bin/sandbox-exec -f [^ ]+/\.phiward/profiles/[0-9a-f]{32}\.sb /usr/bin/rsync -rt --ignore-existing --exclude=\.claude/ -- [^ ]
C3 argv  /usr/bin/sandbox-exec -f <profile> /usr/bin/ssh -F <ssh-config> -o BatchMode=yes -o ProxyCommand=none -o ProxyJump=none -o PermitLocalCommand=no -o ClearAllForwardings=yes -o ForwardAgent=no -o ForwardX11=no -o ForwardX11Trusted=no -o RequestTTY=no -T -o ControlMaster=no -S <socket> <host> -- <remote>
C3 regex ^/usr/bin/sandbox-exec -f [^ ]+/\.phiward/profiles/[0-9a-f]{32}\.sb /usr/bin/ssh -F [^ ]+ -o BatchMode=yes -o ProxyCommand=none .* -o ControlMaster=no -S [^ ]+ [^ ]+ -- tar -c -f - -C [^ ]
C4 argv  /usr/bin/sandbox-exec -f <profile> <python> -I <PKG>/phiward/tar_extract.py <path>
C4 regex ^/usr/bin/sandbox-exec -f [^ ]+/\.phiward/profiles/[0-9a-f]{32}\.sb [^ ]+/bin/python[0-9.]* -I [^ ]+/site-packages/phiward/tar_extract\.py /
C5 argv  /usr/bin/ssh -G -F <ssh-config> -- <host>
C5 regex ^/usr/bin/ssh -G -F [^ ]+ -- [^ ]+$
C6 argv  /usr/bin/ssh -F <ssh-config> -S <socket> -O check -- <host>
C6 regex ^/usr/bin/ssh -F [^ ]+ -S [^ ]+ -O check -- [^ ]+$
H1 argv  /bin/sh <PKG>/phiward/data/clean-exec.sh <python> -I -m phiward hook claude
H1 argv  /bin/sh <PKG>/phiward/data/clean-exec.sh <python> -I -m phiward prompt-scan claude
H1 argv  /bin/sh <PKG>/phiward/data/clean-exec.sh <python> -I -m phiward session-note claude
H1 regex ^/bin/sh [^ ]+/site-packages/phiward/data/clean-exec\.sh [^ ]+/bin/python[0-9.]* -I -m phiward (hook|prompt-scan|session-note) claude$
H2 argv  /usr/bin/awk -f <PKG>/phiward/data/clean-env.awk
H2 regex ^/usr/bin/awk -f [^ ]+/site-packages/phiward/data/clean-env\.awk$
H3 argv  <python> -I -m phiward hook claude
H3 argv  <python> -I -m phiward prompt-scan claude
H3 argv  <python> -I -m phiward session-note claude
H3 regex ^[^ ]+/bin/python[0-9.]* -I -m phiward (hook|prompt-scan|session-note) claude$
P1 argv  /bin/sh <plugin>/hooks/clean-exec.sh phiward hook claude
P1 argv  /bin/sh <plugin>/hooks/clean-exec.sh phiward prompt-scan claude
P1 argv  /bin/sh <plugin>/hooks/clean-exec.sh phiward session-note claude
P1 regex ^/bin/sh [^ ]+/hooks/clean-exec\.sh phiward (hook|prompt-scan|session-note) claude$
P2 argv  /usr/bin/awk -f <plugin>/hooks/clean-env.awk
P2 regex ^/usr/bin/awk -f [^ ]+/hooks/clean-env\.awk$
P3 argv  <python> <launcher> hook claude
P3 argv  <python> <launcher> prompt-scan claude
P3 argv  <python> <launcher> session-note claude
P3 regex ^[^ ]+/bin/python[0-9.]* [^ ]+/bin/phiward (hook|prompt-scan|session-note) claude$
P4 argv  <python> <launcher> mcp
P4 regex ^[^ ]+/bin/python[0-9.]* [^ ]+/bin/phiward mcp$
L1 argv  /usr/bin/sandbox-exec -f <profile> <tool> ...
L1 regex ^/usr/bin/sandbox-exec -f [^ ]+/\.phiward/profiles/[0-9a-f]{32}\.sb /[^ ]+
L2 argv  /usr/bin/getconf DARWIN_USER_TEMP_DIR
L2 regex ^/usr/bin/getconf DARWIN_USER_TEMP_DIR$
L3 argv  <python> -I -S <PKG>/phiward/entry.py hook claude --launched
L3 argv  <python> -I -S <PKG>/phiward/entry.py prompt-scan claude
L3 regex ^[^ ]+/bin/python[0-9.]* -I -S [^ ]+/site-packages/phiward/entry\.py (hook claude --launched|prompt-scan claude)$
L4 argv  <python> -I -S -B -X pycache_prefix=/dev/null/phiward <PKG>/phiward/selfcheck.py <record>
L4 argv  <python> -I -S -B -X pycache_prefix=/dev/null/phiward <PKG>/phiward/selfcheck.py --full <record> <python>
L4 regex ^[^ ]+/bin/python[0-9.]* -I -S -B -X pycache_prefix=/dev/null/phiward [^ ]+/site-packages/phiward/selfcheck\.py [^ ]
L5 argv  <claude> --version
L5 regex ^[^ ]+/claude --version$
M1 argv  <python> <launcher> launch --entry <entry> -- <server> ...
M1 regex ^[^ ]+/bin/python[0-9.]* [^ ]+/bin/phiward launch --entry [0-9a-f]{16} -- [^ ]
M2 argv  <server> ...
M2 regex -
S1 argv  <python> <launcher> broker
S1 regex ^[^ ]+/bin/python[0-9.]* [^ ]+/bin/phiward broker$
S2 argv  /bin/launchctl print gui/<uid>/org.phiward.broker
S2 argv  /bin/launchctl kickstart -k gui/<uid>/org.phiward.broker
S2 argv  /bin/launchctl bootstrap gui/<uid> <home>/Library/LaunchAgents/org.phiward.broker.plist
S2 regex ^/bin/launchctl (print|kickstart -k|bootstrap) gui/[0-9]+(/org\.phiward\.broker| [^ ]+/Library/LaunchAgents/org\.phiward\.broker\.plist)$
D1 argv  <python> -I -m phiward --version
D1 regex ^[^ ]+/bin/python[0-9.]* -I -m phiward --version$
D2 argv  /bin/sh <PKG>/phiward/data/clean-exec.sh phiward --help
D2 regex ^/bin/sh [^ ]+/site-packages/phiward/data/clean-exec\.sh phiward --help$
R1 argv  /bin/sh -c <project-hook>
R1 argv  /bin/sh -c <project-prompt-hook>
R1 argv  /bin/sh -c <project-note>
R1 regex ^/bin/sh -c command -v phiward >/dev/null 2>&1 \|\| [^ ]
R2 argv  /usr/bin/awk <awk-program>
R2 regex ^/usr/bin/awk BEGIN\{for\(k in ENVIRON\)
R3 argv  /bin/sh <repo>/.git/hooks/pre-commit
R3 argv  /bin/sh <repo>/.git/hooks/pre-push
R3 regex ^/bin/sh [^ ]+/\.git/hooks/pre-(commit|push)$
R4 argv  <python> <launcher> git-hook pre-commit
R4 argv  <python> <launcher> git-hook pre-push
R4 regex ^[^ ]+/bin/python[0-9.]* [^ ]+/bin/phiward git-hook pre-(commit|push)$
R5 argv  git <arguments>
R5 regex ^git [^ ]
```

A test records every process phiward starts on macOS and checks that this list holds the same
command lines, both ways (`tests/test_macos_processes.py`).

## Who signed what

`sandbox-exec`, `sh`, `awk`, `ssh`, `mkdir`, `rsync`, `getconf` and `launchctl` are Apple's
platform binaries. The Python is the one the user installed, signed by whoever built it (the
python.org installer's is signed with its Developer ID). `git` is Apple's, or the one the user
installed (Homebrew, for example). phiward itself is not signed code: it is Python
source that the Python reads.

## What the agent runs is not phiward's

The agent chooses the commands it runs through the gateway (G1) and inside a launched session
(L1). Their command lines are the agent's own, and they may use any shape: an agent may run
`python -c` or `sh -c` there. Their parent is `sandbox-exec`, and they run inside phiward's
profile. A wrapped MCP server (M1, M2) has the command line its user configured; many servers
are started as `sh -c "..."` or `npx ...`.

## What to put in an exception

If your policy needs an exception, scope it narrowly:

- by the image path and the regex of the row you see;
- to the users who run phiward;
- not for all of Python, and not for every program in phiward's Python folder.

The rows that phiward starts most often are H1 to H3 (each tool call in a Claude Code session),
L3 (each tool call under `launch`) and G1 (each gateway request).

## How to check a Mac

`phiward doctor`, in the user's terminal, checks the install, the hook wiring, the broker and the
gateway's profile, and says what is missing. It starts G2, D2, L4 and L5.

## Limits

- `sandbox-exec` is deprecated by Apple, with no date and no named replacement.
- The commands the agent runs (G1, L1) have their own shapes, and your tool may judge what they
  do. phiward cannot change that.
- The project hook (R1, R2) is one fixed line with code in it. A repository commits it, and the
  same line runs on Linux.
- This page lists macOS only.

## Linux

On Linux phiward confines with bubblewrap (`bwrap`), Landlock and seccomp instead of
`sandbox-exec`. Its processes have the same parents and the same jobs, with other command
lines: `bwrap` in place of `sandbox-exec`, a small Python helper with inline code inside the
`bwrap` profile, and `systemctl --user` for the login service. Those command lines are not
listed here.
