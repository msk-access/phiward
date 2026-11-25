# Quick start

- **For:** anyone who sets phiward up for the first time.
- **Before:** macOS or Linux, and Claude Code 2.1.295 or newer; 2.1.299 or newer for
  `@` mentions off (`phiward doctor` warns below it).
- **You will have:** phiward installed, your protected folders set, Claude Code wired, and a test
  that shows it works.

| Step | Where | What you type | You see |
|---|---|---|---|
| 1. Install | Terminal | `uv tool install ... phiward==0.2.0b1` | `phiward --version` prints the version |
| 2. Set up | Terminal (or the plugin) | `cd ~ && phiward setup` | its questions, then the config it wrote |
| 3. Check | the project folder | `phiward init`, then `phiward doctor` | no `PROBLEM` or `WARNING` line |

phiward keeps protected data (for example patient data) and your credentials out of what an AI
coding agent sends to its model provider. The agent works on protected data only through
phiward's **gateway** (`phiward run`, `phiward copy`). A **broker** runs those commands outside
the agent and masks their output. Words in bold are explained in the [glossary](glossary.md).

**What you get with the steps below:** **Mode A**. The wiring in your user settings covers every
Claude Code session, in every folder: phiward's hook checks each tool call, and Claude Code's
sandbox keeps shell commands out of your protected folders. In each project where you work with
protected data, you also run `phiward init` once (step 3): without it, a shell command in that
project could rewrite the project's Claude Code settings. This is the right start for most
people. The stronger **Mode B**
(`phiward launch`) is for the terminal only; see [modes.md](modes.md) when you need it.

## 1. Install phiward

**On Linux, first** install bubblewrap and socat (phiward's kernel profile and Claude Code's
sandbox need them), with your package manager, for example `sudo apt install bubblewrap socat`.
Without admin rights, see [hpc.md](hpc.md#claude-code-on-the-login-node). On Ubuntu 24.04,
AppArmor can block bubblewrap: see [setup.md](setup.md#1-requirements).

**On an HPC node with RHEL 8** (`uname -r` starts with `4.18`), the gateway cannot run: that
kernel has no Landlock. Choose before you start: run the agent on your laptop and reach the
cluster with `phiward run --remote` ([hpc.md](hpc.md#phiward-run---remote-host----cmd)), or run
Claude Code on the node with the hook and its sandbox only, no gateway
([hpc.md](hpc.md#claude-code-on-the-login-node)).

In Terminal:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

```bash
uv tool install --python-preference only-managed phiward==0.2.0b1
```

```bash
uv tool update-shell
```

The first command installs `uv`, a Python installer that needs no admin rights. If you have
Homebrew, `brew install uv` does the same. The second gives phiward a Python of its own, which
uv downloads once (not Xcode's, conda's or the system's, which another account or tool can
change). The last command puts `~/.local/bin`, where `phiward`
now is, on your `PATH`.

**On a cluster, or with conda**, make sure no other account can write the programs phiward
trusts, before step 2. On many clusters new folders are group-writable (umask 002), and phiward
refuses a program in such a folder. Run `chmod go-w ~/.local ~/.local/bin`. Use the `uv` from
the installer above, not a conda one: `command -v uv` shows which one runs.

Then **open a new Terminal**, and **quit and reopen the Claude Code desktop app** (Cmd-Q on
macOS), so that both find `phiward`. In the new Terminal, `phiward --version` prints the version.

Do not install phiward into conda or another shared Python environment: phiward protects its own
folder from the agent. Setup also makes phiward's own Python writable by you alone (it says
which folders it changed); it never changes your home folder. If an older phiward is in conda, remove it there first
(`pip uninstall phiward`).

## 2. Set it up

Choose one way. Both do the same steps.

### With Claude Code's help

In a Claude Code session, type these two commands:

```
/plugin marketplace add msk-access/phiward#v0.2.0b1
```

```
/plugin install phiward@phiward
```

Then open a **new** session and type:

```
/phiward:setup
```

The agent walks you through the steps, and Claude Code asks you before each command. It asks
**you** which folders hold protected data; it never looks into your folders to guess.

It recommends that you write the config yourself, with the two commands of "By hand" below, which
it gives you. It can also write the first config for you, while none exists. That is quicker,
but then you trust the agent, in that session, to write exactly what you say: do it only in a
new session that has not read web pages, other people's files or repositories you do not know.
After the first config, only you can change it, in your own Terminal (`phiward setup`).

**If the agent wrote the first config**, it holds your protected folders (and copy remotes)
only: no results folder, no list of programs, no network. The rest is yours, in your own
Terminal: `cd ~ && phiward setup`, and choose **1** (the steps below). It adds the results folder
and the program list, wires Claude Code and starts the broker at every login. More about the plugin: [plugins.md](plugins.md).

### By hand

In Terminal, in your home folder (not inside a project), from a Terminal where your tools (for
example `samtools` from conda) are found:

```bash
cd ~ && phiward setup
```

It asks how you will use phiward. Choose **1, real patient data** (the default), and it sets
safe defaults for you:
- your protected folders (you type them);
- a results folder inside the first one, where gateway commands write (Enter accepts it);
- a list of programs that gateway commands may run on the data (`@genomics`), plus a folder of
  your own scripts if you have one;
- no network for gateway commands;
- shell commands in Claude Code reach only the hosts you list (Enter says yes). `git push` and
  `pip install` from a session fail until you list their hosts, such as `github.com`;
- which rules mask subject and sample IDs inside your files: none (type 1; there is no
  default), the `msk` example pack, or your own patterns;
- if you use an HPC cluster: its short name, login host, your user name and work folder.
  `setup` writes phiward's ssh config and prints the lines to add to your `~/.ssh/config`.

At the end it shows the whole config. Nothing is written until you say yes; then it writes the
config and records the folders it protects with your roots (`phiward pin`). Then it asks three
more questions:

1. **"Approve these N program(s) as they are now?"** It first lists each program of your
   program list with its path. The broker runs only the programs you approve. On a first run,
   with nothing marked, Enter says yes. When a program is marked `(changed)`, or a program in
   your home folder hides a system program of the same name (`(shadows /usr/bin/NAME)`), the
   default is No: read those lines first.
2. **Wire Claude Code for every session?** One yes: it shows the change to your user settings
   (a long list: every protected path and credential, twice) and writes it (`(cd ~ && phiward install claude --user --write)`).
3. **Start the broker at every login?** (A system without a service manager for your login,
   such as a container or WSL without systemd, cannot: `setup` says so, and you run
   `phiward broker` yourself in a terminal that stays open.)

Say yes to each. The wiring ends with an `alias claude='claude --settings ...'` line. Add it to
your shell startup file (for example `~/.zshrc`) yourself, if you start `claude` in Terminal:
then a repository's settings cannot turn the sandbox off. Without it phiward still works; the
hook checks the project's settings itself ([setup.md](setup.md#claude-code)).
(Choose 2 to try phiward on made-up data with open defaults, or 3 to choose every setting.)

**When you change your config later**, run `(cd ~ && phiward setup)` again: it restarts the broker for
you. After a change by hand, restart it yourself: the broker refuses requests after the config
changes, and the refusal names the command.

A team can share its settings in a template: `phiward setup --from team.toml` fills in the
program list, packs and HPC hosts; each person adds their own folders.

## 3. Set up each project, and check it

In Terminal, in each project folder where you work with protected data, run once:

```bash
phiward init
```

It only adds; it changes nothing that is there. It adds the phiward rules for agents to
`AGENTS.md`, a `.gitignore` line, the project's Claude Code settings (`.claude/settings.json`
and `.claude/settings.local.json`) and git hooks. The project settings stop a shell command
from rewriting them. In a repository that is not yours, do not commit these files: list the
new ones in `.git/info/exclude` (for example `AGENTS.md` and `.claude/`). Then, in the same
folder:

```bash
phiward doctor
```

When all is well, you see lines such as:

```text
protected roots: 1, patterns: 0
  sandbox confines the shell: yes
broker: running
```

Fix each `WARNING`; each one says how. A `NOTE` is for your information. If you kept setup's
`@genomics` programs, doctor warns about each one the broker does not find (for example
`samtools`): remove the ones you do not use from `[broker] commands` in your config. Before Claude Code is
wired, one line gives the next step; `phiward doctor --verbose` lists every check. Then open a
**new** Claude Code session in that folder and ask the agent to read a file in a protected
folder: it must be refused. Then ask it to run `phiward run -- wc -l <that file>`: you get a
line count, with the file name masked. (If you said No to the login service, start the broker
first: `phiward broker` in a Terminal of its own.)

**If you chose 2 or 3 and now use real patient data**, list the programs that gateway commands
may run (`[broker] commands`, see [configuration.md](configuration.md)): run `(cd ~ && phiward setup)`
again and choose 1.

Next: [daily-use.md](daily-use.md) tells you how to work with the agent on protected data.

## A project where every contributor is protected

1. Each contributor does steps 1 to 3 above.
2. Someone runs, once, in the project folder:

   ```bash
   phiward init --root data/protected
   ```

   `--root` names the project's own protected folders, if it has any. `init` only adds; it
   changes nothing that is there. It adds:
   - the phiward rules for agents to `AGENTS.md`;
   - the protected folders to `.phiward.toml`;
   - the project's Claude Code settings: the shared part in `.claude/settings.json`, the
     personal part in `.claude/settings.local.json`;
   - a `.gitignore` line for the personal file;
   - git hooks that refuse commits holding protected names or identifiers.
3. Commit `AGENTS.md`, `.phiward.toml`, `.gitignore` and `.claude/settings.json`. **Never**
   commit `.claude/settings.local.json`.
4. Each other contributor runs `phiward init` once too (for the personal file and the git
   hooks), then `phiward doctor`.

## HPC

The agent never uses `ssh` itself. It runs approved programs on the cluster with
`phiward run --remote`, and moves files with `phiward copy`. Both go through **your own** shared
SSH connection, which you open in Terminal (for example `kinit`, then `ssh -fN hpc`). No agent
request can read your key or Kerberos ticket. The one-time setup is in [hpc.md](hpc.md).

## If something goes wrong

| What you see | What to do |
|---|---|
| Every tool call is refused with "phiward is not installed or not on PATH" | The app does not find `phiward`. Quit the app (Cmd-Q on macOS) and open it again. If that does not help, check in Terminal that `command -v phiward` prints `~/.local/bin/phiward`, and run `uv tool update-shell` again. |
| `phiward run` says no broker is running | Start it at every login: `(cd ~ && phiward broker --service --write)` in Terminal. Or run `phiward broker` in a Terminal and keep it open. |
| A command the agent needs is refused | The refusal says what to run instead. See [daily-use.md](daily-use.md). |
| `phiward doctor` shows a `PROBLEM` | Fix it before you use the agent; the line says how. |
| A wrapped MCP server "failed to connect", or `doctor` says phiward's own files fail its self-check | Usually after `uv tool upgrade` with umask 002: run `(cd ~ && phiward install claude --user --write)` again (it makes phiward's own Python writable by you alone), then start Claude Code again. The WARNING names any other step. |
