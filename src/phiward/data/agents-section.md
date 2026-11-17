## Protected data (phiward)

This repository uses phiward. Some folders hold protected data, for example patient data.
Your tool output goes to a model provider. Protected data must not reach it.

Rules:

1. Never read a protected path directly. Do not use `cat`, `ls`, `grep`, `find`, `head`, `git`
   or your file tools (Read, Grep, Glob) on a protected path or on a folder above one.
2. To work with protected data, run `phiward run -- CMD [ARG]...`. Write it as the whole
   command, with the bare name `phiward`. Put nothing before or after it: no `cd`, no
   pipe, no redirect, no `$(...)`. The operator's broker runs the command. If `run` says no
   broker is running, stop and ask the operator to start the broker. The broker
   runs the program from the operator's PATH with its own environment, not yours.
3. Write analysis scripts that print aggregates: counts, summaries, tables. Do not print raw
   records, sample names or identifiers. The sanitizer masks identifiers. It does not mask
   other content. Draft a script in the project, then ask the operator to read it and move it
   into their scripts folder; after that, run it by its full path:
   `phiward run -- /full/path/NAME.py ARGS`.
4. To copy protected data, use `phiward copy SRC... DST`. The destination must be
   inside a protected folder or a configured remote.
5. `run` allows read access and no network. It writes only where the operator granted it:
   `--write-to DIR` and `--net` work only where the operator granted them in the user config
   (`[broker] write_to`, `[broker] net`). Nothing asks the operator at run time: a grant that is
   not in the config is refused. If you need one, stop and ask the operator. Once a config
   exists, never run `phiward setup`, `broker`, `pin` or `carryover`: they are for the operator,
   in their own terminal. The only exception is the guided first setup (`/phiward:setup`),
   before any config exists.
6. Use `phiward check -- CMD` to see if a command is allowed, before you run it.
7. For an HPC cluster, do not use `ssh` yourself: your session cannot use the operator's ticket,
   key or connection. Run `phiward run --remote HOST -- CMD [ARG]...`, and move files with
   `phiward copy` to or from the approved remotes. The gateway is the intended route, not a way
   around the guards. Only the hosts
   and programs the operator listed in the user config are allowed, and the output is masked.
   The command is not confined on the cluster: keep it to counts and states.

A refusal is a decision, not a fault. Read the reason. Do what it says. Do not try another
spelling, a link, a nested shell, an encoded command or another tool to read the same data.
Do not edit settings files, hooks or `.phiward.toml` to remove a guard. Do not use
`--no-verify`. If the work cannot continue, stop and tell the operator what you need.
Do not ask the operator to show you protected data either: no `! cat`, no paste, no copy into
the project, and no change that removes a guard. Offer a gateway command that prints a count or
a summary instead.
