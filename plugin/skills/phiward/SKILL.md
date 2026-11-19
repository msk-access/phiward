---
name: phiward
description: Use when a task touches protected or patient data (for example genomics, clinical or study folders), or when a command, file read or search was refused by phiward. Gives the rules for reading protected data through `phiward run`, copying with `phiward copy`, and the grants the operator configures.
---

# phiward

phiward keeps protected data out of tool output. Tool output goes to a model provider.
The operator lists protected folders (roots) in a config file. The kernel denies your shell
commands access to a root (with known gaps; never look for them). One gateway can read the roots: `phiward run` and
`phiward copy`. These are clients: the operator's broker (outside your tool: in a terminal, or
as a login service) runs the command and sends back its sanitized output.

## Rules

1. Never read a protected path directly. Do not use `cat`, `ls`, `grep`, `find`, `head`,
   `git` or your file tools (Read, Grep, Glob) on a protected path. Do not search from a folder
   above one.
2. To work with protected data, write `phiward run -- CMD [ARG]...` as the whole command,
   with the bare name `phiward` (not a path, not `python -m`). Put nothing before or after
   it: no `cd`, no pipe, no redirect, no `$(...)`, no `&&`. Globs, braces and `~` are allowed.
   The broker finds the program on the operator's PATH and uses its own environment, not
   yours: give a path (`./tools/x.py`, `.venv/bin/python`) for a program that only you have.
3. Write scripts that print aggregates (counts, summaries, tables). Do not print raw records.
   The sanitizer masks identifiers and the names of protected entries. It does not mask other
   content. Content that you print is content that the provider receives.
4. Copy with `phiward copy SRC... DST`. The destination must be inside a protected folder
   or under a configured remote. `copy` accepts no options, except `--dry-run` first.
5. `run` has these limits: it reads the roots; it writes only in a private scratch folder and
   in granted folders (protected roots are read only; a granted folder may sit inside one); it
   has no network. Its stdin is empty.
6. Grants are set ahead of time by the operator, in the user config; nothing asks at run time.
   `--write-to DIR` works only when DIR is a `[broker] write_to` folder or inside one. `--net`
   works only with `[broker] net = true`. A grant that is not configured is refused. If you need
   one, stop and ask the operator to add it. Once a config exists, never run `phiward setup`,
   `broker`, `pin` or `carryover` (they are for the operator, in their own terminal), and never
   edit the user config. The only exception is the guided first setup (`/phiward:setup`),
   before any config exists. The operator may also limit your shell commands to listed hosts
   (`[network]`): when one is refused a host, do not reach it another way; ask the operator.
7. The operator may list the programs gateway commands may run (`[broker] commands`). Then
   only those run on protected data: use them, and ask the operator for others; do not try an
   interpreter or a shell instead.
8. Use `phiward check -- CMD` to see the decision for a command (`allow`, `ask` or
   `deny`) before you run it.
9. For an HPC cluster, do not use `ssh` yourself: the session cannot use the operator's ticket,
   key or connection. Run `phiward run --remote HOST -- CMD [ARG]...`, and move files with
   `phiward copy`. The gateway is the intended route, not a way around the guards. Only the hosts and
   programs the operator listed are allowed, the output is masked, and the command is not
   confined on the cluster: keep it to counts and states.

## What a refusal means

A refusal is a decision. Read the reason in the message. It says what to run instead.

Do not work around a refusal. These actions are not allowed:

- another spelling of the path (`..`, a link, different letter case, `$VAR`);
- a nested shell (`bash -c`, `eval`), an encoded command or a here-document;
- another tool that reads the same file;
- a change to settings files, hooks, `.phiward.toml` or the user config;
- `git commit --no-verify` or `git push --no-verify` (only the human may use them).

Do not ask the operator to show you protected data either. Do not suggest:

- `! cat` or another command that prints it into the session;
- a paste, or a copy into the project;
- a change that removes a guard (permission rules, sandbox, config).

Offer a gateway command that prints a count or a summary instead.

If the work cannot continue, stop. Tell the operator what you need.

Other refusals you can meet:

- "The phiward config cannot be used": the config is bad. Every guarded action is refused.
  Tell the operator to run `phiward doctor`.
- "no confinement backend": the system has no `sandbox-exec` or `bwrap`. Tell the operator.
- "the destination is not inside a protected path": `copy` refused the destination.
- "no phiward broker is running": ask the operator to start the broker (in a terminal, or its
  login service), in a
  terminal outside your tool.
- "--write-to names a folder that is not granted" or "--net is not granted": the user config
  does not grant it. Do not try another folder or spelling. Ask the operator.
- "the broker is busy": too many requests wait. Try again later, one at a time.

## Worked examples

### Count records in a protected folder

Wrong. This lists protected names and is refused:

```bash
ls ~/data/patients | wc -l
```

Right. Write a script that prints one number:

```python
# count.py
import os, sys
root = sys.argv[1]
n = sum(len(files) for _, _, files in os.walk(root))
print("files:", n)
```

Then run it through the gateway:

```bash
phiward run -- python3 count.py ~/data/patients
```

The output has the count, a note with the placeholders in the lines shown, and one summary
line: `run done: exit=0`. When the note says no identifier placeholder was shown, tell the
operator in your reply: their rules may not match this data. A count of
5 or more digits shows as `<NUM>`. `--table` reads CSV/TSV output by column: cells under an
identifier header show `<IDCOL>`, numbers in other columns are kept, and lines before the header
are masked as text. It works only when the operator turned it on; otherwise it is refused. Do
not ask for it to be turned on to see identifiers.

These examples run `python3`, which works only where the operator set no program list. With
`[broker] commands` set (the recommended setup for real data), run the operator's listed
scripts instead, with full paths (`phiward run -- ~/pipelines/bin/count.py ~/data/patients`),
and never try an interpreter.

### Summarize a table without printing rows

Print aggregates only. Do not print a row that has an identifier:

```python
# summarize.py
import csv, sys, collections
counts = collections.Counter()
with open(sys.argv[1], newline="") as fh:
    for row in csv.DictReader(fh):
        counts[row["status"]] += 1
for key, value in sorted(counts.items()):
    print(key, value)
```

The operator reads it, makes it executable, moves it into their scripts folder and approves it
(`phiward pin`; docs/daily-use.md "Run a script the agent wrote"); then run it by its full path:

```bash
phiward run -- ~/pipelines/bin/summarize.py ~/data/patients/results.csv
```

### Write a result for later use

`run` writes only where the operator granted it (`[broker] write_to`); a granted folder may sit
inside a protected folder. Write the result there, and print only a summary:

```bash
phiward run --write-to ~/data/patients/derived -- python3 build_index.py ~/data/patients ~/data/patients/derived/index.json
```

If there is no granted folder, ask the operator to add one. A result outside the protected
folders goes to a granted folder there too:

```bash
phiward run --write-to ~/project/out -- python3 export_counts.py ~/data/patients ~/project/out/counts.tsv
```

Only share counts that are safe to leave the protected place.

### Copy protected data

```bash
phiward copy ~/data/patients/run1 ~/data/patients/run1-copy
```

To a configured remote (the operator lists it under `[copy] remotes`):

```bash
phiward copy ~/data/patients/run1 cluster:/data/work/project/run1
```

### Check a command first

```bash
phiward check -- grep -r finding ~/data/patients
```

The answer is `deny` with a reason. Use `phiward run` instead.

### A command is refused and you do not know why

Run `check` on the exact command. Read the reason. If the reason names a bad config, tell the
operator to run `phiward doctor`.

### Commit work

Do not stage files from a protected folder. The `pre-commit` hook refuses protected files and
identifiers. It prints a sanitized name and a line number. Remove the identifier from the
change. Do not use `--no-verify`.
