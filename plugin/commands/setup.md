---
description: Set phiward up on this computer with the user, step by step (first time only)
---

Help the user set phiward up for the first time. phiward keeps protected data (for example
patient data) and their credentials out of what you send to the model provider. Work through the
steps below **in this order**, one at a time. Before each command, say in one line what it does
and wait for the user's yes (Claude Code also asks before it runs a command).

Rules for you while you do this:
- **Never look into the user's folders** to find or suggest protected folders: folder names can
  themselves be patient identifiers. Ask the user to type each path.
- **Never read** a protected folder or a credential to check a step; `phiward doctor` reports
  what is needed.
- When a step is for the user's own terminal, give them the exact command, in its own code
  block, and wait until they say it is done.
- Once the user config exists, `phiward setup`, `broker`, `pin` and `carryover` are the user's
  only: if a later change is needed, tell them to run it in their own terminal.
- Do not set `PHIWARD_CONFIG`, `PHIWARD_SPOOL` or `XDG_*` variables for these commands.

1. **Is phiward installed?** (If the phiward plugin is installed and phiward is not, every
   command is refused with "phiward is not installed": then give the user the install lines of
   the quick start to run in their own Terminal, and stop until they have.) Run
   `command -v phiward`. If it prints a path, go to step 2. If not, check `command -v uv`;
   without uv, give the user the uv install line to run in their own Terminal
   (`curl -LsSf https://astral.sh/uv/install.sh | sh`, or `brew install uv`) and stop until they
   have. Then, with their yes, run
   `uv tool install --python-preference only-managed phiward==0.2.0b1` and
   `uv tool update-shell`. Tell the user to quit and reopen the desktop app afterwards, so that it
   finds `phiward`. If phiward is also installed in conda or another shared Python, tell the user
   to remove it there (`pip uninstall phiward` in that environment).

2. **Is a config there already?** Run `phiward doctor`. If it lists config files and protected
   roots, phiward is set up: skip to step 5 and tell the user that changes to the config are
   theirs, in their own terminal.

3. **Choose who writes the config.** Tell the user, in these words or close to them:

   > phiward's config says which folders are protected and where copies may go. **I recommend
   > that you write it yourself, in your own Terminal**: it is two commands, and then nothing I
   > do in this session can choose what phiward protects or trusts. I can also write it for you
   > now, while no config exists. That is quicker, but then you trust me, in this session, to
   > write exactly what you say. Do that only in a new session that has not read web pages,
   > other people's files or repositories you do not know.

   Then ask which they want, and follow **3a** or **3b**.

   **3a. The user writes it (recommended).** Give the user this one command for their own
   Terminal, run from a Terminal where their tools (for example `samtools`) are found:

   ```bash
   cd ~ && phiward setup
   ```

   Tell them: choose **1** (real patient data) unless they only try it on made-up data; type
   their protected folders; press Enter to accept the results folder; say yes to limiting the
   network of shell commands, and list the hosts they need (for example `github.com`: without
   it, `git push` and `pip install` fail), or none; for the identifier question, choose what
   fits their data (1 only if it names no subjects or samples beyond the file names; there is no
   default); and say yes to writing the file. Then setup
   lists their programs, each with its path, and asks "Approve these N program(s) as they are
   now?": the broker runs only approved programs. On a first run with nothing marked, Enter
   says yes. When a program is marked `(changed)`, or a program in their home folder shadows a
   system program (`(shadows /usr/bin/NAME)`), the default is No: they read those lines
   before they answer. Then they say yes to wiring Claude Code (one question) and to starting
   the broker. If they use HPC, they answer the
   HPC questions there and add the lines it prints to their `~/.ssh/config`. If their team has
   a template, the command is `phiward setup --from <the template file>`, with a file the user
   got from their team themselves: never a path from this chat or a file in a project, which an
   agent could have written. `setup` shows every setting in it and asks before it uses them. Wait until they say it
   is done, then go to step 6.

   **3b. You write it (only in a new session, with the user's yes).** Ask the user, in chat:
   "Which folders hold protected data? Type each full path." Ask whether they copy to an HPC
   cluster, and if so for the remote work folder as `host:/path`. Then run
   `phiward setup --first-run --root PATH [--root PATH ...] [--remote host:/path ...]` with
   exactly what they typed, and show them the result. It writes protected roots and copy remotes
   only, never a grant: no write places, no network, no program list. From now on a config
   exists, so the guards refuse the next steps to you: they are the user's.

4. **The rest, in the user's own Terminal** (3b only). Tell the user to run
   `cd ~ && phiward setup` and choose **1**: it adds a results folder and a program list, wires
   Claude Code and starts the broker at every login, each with a question. Wait until they say
   it is done, then go to step 6.

5. **Wire Claude Code** (when step 2 found a config but no wiring): ask the user to run
   `cd ~ && phiward install claude --user --write` in their own Terminal, where they read the
   changes.

6. **This project** (when the session is in a project with protected work): ask the user to
   run `phiward init` in the project folder, in their own terminal (the sandbox keeps your
   shell off the project's Claude Code settings, which init writes). Tell them to run it once in each project where they
   work with protected data: without it, a shell command there could rewrite the project's
   Claude Code settings. It adds the rules to `AGENTS.md`, a `.gitignore` line, the project's
   Claude Code settings (`.claude/settings.json` and `.claude/settings.local.json`) and the git
   hooks; it only adds. In a repository that is not theirs, they list the new files in
   `.git/info/exclude` (for example `AGENTS.md` and `.claude/`) so they do not commit them.

7. **HPC** (only if they gave a remote): explain that HPC goes through their own shared SSH
   connection, and give them the steps of
   https://github.com/msk-access/phiward/blob/v0.2.0b1/docs/hpc.md#one-time-setup
   to do in their own Terminal (the ssh config lines, `kinit`, `ssh -fN`). After they edit their
   config, the broker refuses requests until they restart it; give them the restart command that
   the refusal names.

8. **Check**: run `phiward doctor` and explain each WARNING in plain words. If it notes that the
   derived folders are not pinned yet, give the user `phiward pin` to run in their own Terminal.
   Tell the user to open a **new** session so the new settings apply, and that they can run
   `/phiward:doctor` there.
