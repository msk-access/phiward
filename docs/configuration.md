# Configuration reference

This page lists every config key, file place and environment variable. For a first setup, use
`phiward setup` ([setup.md](setup.md)); it writes the keys that matter most.

## Where the files are

phiward reads two files and combines them.

| File | Place | Who writes it | Commit it? |
|---|---|---|---|
| User config | `$PHIWARD_CONFIG`, else `$XDG_CONFIG_HOME/phiward/config.toml`, else `~/.config/phiward/config.toml` | the operator (`phiward setup`, or by hand) | no |
| Repo config | `.phiward.toml`, the first one found from the working folder upward | the repository's maintainers (the agent can edit it too) | yes |

With no config and no protected paths, the guards do nothing. If `$PHIWARD_CONFIG` names a
file that does not exist, the config is bad (see [Fail closed](#fail-closed)).

phiward also uses these places. You do not configure them in a file.

| Place | What it is | The agent may |
|---|---|---|
| `~/.cache/phiward` (or `$XDG_CACHE_HOME/phiward`) | the gateway's scratch folders, while commands run | not read or write it |
| `~/.phiward-spool` (or `$PHIWARD_SPOOL`) | requests from clients to the broker | write requests (it must) |
| `~/.phiward/broker.json` | the broker's status: the config, cache folder, roots and patterns it uses | not write it |

## Who may set what

The agent can edit a repo config, and it chooses the folder that a gateway request comes from.
So a repo config may only **add protection**. Everything that **widens or changes** what a
gateway command can do comes from the user config only.

| Key | User config | Repo config |
|---|---|---|
| `[protected_paths] roots`, `patterns` | yes | yes, adds (the gateway cannot write a repo-only root) |
| `[protected_paths] unresolved` | yes | only stricter |
| `[protected_paths] snapshot_names` | yes | yes, adds |
| `[sanitize] packs` | yes (built-in names and pack files) | built-in names only; pack files are ignored |
| `[sanitize] names_from`, `patterns`, `subjects` | yes | ignored |
| `[sanitize] inventory_limit` | yes | only lower |
| `[copy] remotes`, `ssh_config`, `push_limit_gib` | yes | ignored |
| `[sanitize] table` | yes | ignored |
| `[remote] hosts`, `commands`, `roots`, `use_shared_connection` | yes | ignored |
| `[launch] pass_env` | yes | ignored |
| `[broker] write_to`, `net` | yes | ignored |
| `[network] limit`, `allowed_domains` | yes | ignored |
| `[broker] commands` | yes | narrows: a program must be in every list that is set |
| `[broker] max_output_lines` | yes | only lower |
| `[git] protected_branches` | yes | yes, adds |
| `[shell] best_effort` | yes | ignored |

A repo config that sets an ignored key is not an error. `phiward doctor` lists the ignored
keys.

## Every key

An example user config with every key:

```toml
[protected_paths]
# Folders that the agent must never read. Absolute, or starting with ~/ or $HOME.
# No "..", no "$" variable other than $HOME (or ${HOME}), no wildcard (* ? [).
# Each should exist.
roots = ["~/data/patients", "~/data/study-a"]

# Glob patterns for protected places. Absolute, or starting with ~/ or $HOME. "*" matches inside
# one path part ("?" and "[...]" are refused).
# Prefer roots: Claude Code's sandbox cannot take patterns.
patterns = ["~/projects/*/inputs/patient"]

# More folder names that hold snapshots of a root (protected too). The usual ones (.snapshot,
# .snapshots, .zfs, ~snapshot) are always found.
snapshot_names = [".backups"]

# What the hook's text check does with a variable it cannot see: "allow", "ask" or "deny".
# Default "deny". Used only where the shell is not kernel-confined.
unresolved = "deny"

[sanitize]
# Pattern packs. A name without "/" is a built-in pack ("genomics", "msk", "dates").
# A name with "/" is the path of your own pack file. Default ["genomics"].
packs = ["genomics"]

# Index files whose paths hold names to mask (<NAME>): lines of tab-separated fields; each
# field with a "/" is a path, and its parts (and their dash pieces) are masked. Keep the files
# inside a protected root: the list is protected data, and elsewhere the agent can read it.
names_from = ["~/data/patients/.names.txt"]

# Extra rules, each 'REGEX => <PLACEHOLDER>'.
patterns = ['\bPT-\d{6}\b => <SAMPLEID>']

# Or your record that the protected data holds no subject or sample IDs beyond the names
# under the roots (phiward doctor warns until a rule masks them or this is set):
# subjects = "none"

# The most entries the sanitizer lists under the roots. Default 200000.
inventory_limit = 200000

# Whether `--table` may be used (it lets bare numbers through). Default false.
table = false

[copy]
# Places on other machines that `phiward copy` may copy to or from: "host:/absolute/prefix".
remotes = ["cluster:/data/work/study-a"]
# The ssh config every HPC request uses (it names the host's ControlPath; see hpc.md).
ssh_config = "~/.config/phiward/ssh_config"
# A push larger than this many GiB is refused: copy it yourself. Default 5.
push_limit_gib = 5

[remote]
# Hosts `phiward run --remote` may name, programs it may run there, protected paths there.
hosts = ["cluster"]
commands = ["squeue", "sacct", "sinfo"]
roots = ["/data/protected"]
# Join your shared SSH connection (no request reads a key or ticket). Default true.
use_shared_connection = true

[launch]
# Extra environment variables passed to a `phiward launch` session (the agent can read them).
pass_env = []

[broker]
# Folders where `phiward run --write-to DIR` may write (DIR is one of them or inside one).
# Each must be a real, existing folder. Default: none.
write_to = ["~/projects/study-a/results"]

# Whether `phiward run --net` gets the network. Default false.
net = false

# The most lines of a gateway command's output that the agent sees. Default 2000.
max_output_lines = 2000
# The programs gateway commands may run (default: any). Set it for real patient data. A listed
# program starts in a private folder, not in the agent's: paths are given in full.
# commands = ["@genomics", "~/pipelines/bin/"]

[git]
# Branches that `git push` must not change (the pre-push hook).
protected_branches = ["main", "release"]

[network]
# Shell commands in Claude Code sessions reach only these hosts (Mode A). Default false.
limit = true
allowed_domains = ["github.com", "pypi.org"]

[shell]
# Take the hook's text check where Claude Code's sandbox does not confine the shell. Default
# false: then such a shell runs only gateway calls.
best_effort = false
```

### `[protected_paths]`

- **`roots`** (list of folders). Claude Code's sandbox (as `install` writes it) denies the
  agent's shell every read and write of each root, and the hook refuses the file tools. The
  gateway can read every root. It writes only in `[broker] write_to` folders, which may sit
  inside a root.
- **`patterns`** (list of globs). Like roots, for places that are spread out. `*` matches any run
  of characters in one path part, names that start with a dot included; it is the only wildcard.
  `?`, `[...]` and any character outside printable ASCII are refused (the config is then bad, and
  the message suggests a rewrite): give such names as roots. On macOS, letter case does not matter.
  Every part of phiward (hook, the gateway and `launch` profiles, sanitizer, settings check)
  uses this one meaning. On Linux, Claude Code's sandbox cannot hold patterns, so with patterns
  the hook refuses shell commands other than gateway calls; the gateway and `launch` cover the
  folders that match when they start. A match reached through a link
  is neither hidden on that path nor a gateway write place.
- **`snapshot_names`** (list of folder names). Snapshot folders next to a root or above it
  hold old copies of protected files. `.snapshot`, `.snapshots`, `.zfs` and `~snapshot` are found
  without this key; add your site's name here if it differs. Each one found becomes a protected
  folder. A repo config may add names too (it only adds protection). On Linux, other mounts of
  the same file system that show a root (bind mounts, a second mount of one share) are protected
  the same way.
- **`unresolved`** (`"allow"`, `"ask"` or `"deny"`; default `"deny"`). Where the shell is not
  kernel-confined, the hook checks command text only. This is what it does with a `$VARIABLE` or
  text it cannot parse. When the tool cannot ask (Claude Code in a bypass or "don't ask" mode),
  `"ask"` becomes a deny.

### `[sanitize]`

The sanitizer filters everything a gateway command prints, the output of
`phiward sanitize`, and what the git hooks check. It always masks protected paths
(`<PROTECTED>`). For `run` and `copy` it also masks the name of every entry under the roots
(`<ENTRY>`); `sanitize` and the git hooks do not list the roots, so they do not. These keys add
to that.

In text mode (without `--table`) the `genomics` pack masks positions and long numbers
(`<LOCUS>`, `<NUM>`, for example any run of 5 or more digits, also next to a comma). A run
joined to other digits by a dot keeps its digits, as in a decimal (`12345.678`, but also
`1234567.7654321`). Table mode (`--table`) keeps them,
so a record number in a table would pass: it is off unless you turn it on with `table = true`
(user config only). Turn it on only when identifiers in your data are caught by a pack or a
pattern, not by the number rule.

An entry name shorter than 4 characters (6 when it is only digits) is not masked, and neither is
one that is a common word of the built-in stop list (for example `patient`, `normal`, `tumour`,
`bam`, `runs`, `test`).

- **`packs`** (list). Built-in packs are `genomics` (the default) and `msk` (one institution's
  identifiers; an example, not a default). A pack file has the lists `paths`, `identifiers`,
  `positions` and `keep_files`; the format is at the top of
  `phiward/packs/genomics.toml` in the installed package. A pack file must be a regular
  file, not a link.
- **`names_from`** (list of files). Index files: each line is tab-separated fields; in each field
  that holds a `/`, every path part of 4 or more characters, the part before its first dot, and
  its `-`/`_`/`.` pieces are masked as `<NAME>` (never a stop word or a bare number). A file
  must be a regular file, not a link. Keep these files inside a protected root: elsewhere the
  agent can read the list. `--names-from FILE` on `run` follows the same rules, and its file
  must be inside a protected path of the user config: the broker reads it outside the sandbox,
  and a file elsewhere would let the agent test what it holds.
- **`table`** (true or false, default false; user config only). Whether `--table` may be used.
- **`patterns`** (list). Each entry is `REGEX => <PLACEHOLDER>`. Like every identifier rule of a
  pack, it matches in any letter case; write `(?-i:...)` around a part that must keep its case.
  So the `msk` pack also masks some ordinary words (`c-string`, `donor-derived`), the git
  hook refuses a commit that holds them as it would an identifier, and `phiward sanitize
  --check` counts them. To check that your rules match your data, run a command over it: the
  note at the end of `phiward run` counts the placeholders shown and says when no identifier
  placeholder was shown.
- **`subjects`** (user config only). Only `"none"`: your record that the protected data holds no
  subject or sample identifiers beyond the names under the roots. Without it, and without a
  rule that masks them (the `msk` pack, a pack file of your own with identifier rules,
  `patterns` or `names_from`), `phiward doctor` warns. `phiward setup` asks; `"none"` is never
  its default. A repo config or a team template cannot set it.
- **`inventory_limit`** (whole number, default 200000). The sanitizer lists every entry under the
  roots each time a gateway command starts. With more entries than this, it stops (fails
  closed). Raise it for a very large root, or narrow the root.

Built-in packs: `genomics` (the default), `msk`, and `dates` (v0.2, off by default: dates and
times become `<DATE>`, for example the dates `ls -l` prints).

### `[copy]`

- **`remotes`** (list of `host:/absolute/prefix`). `phiward copy` may use a place under one
  of these as a source or a destination. `..` is refused. How pushes and pulls work:
  [hpc.md](hpc.md#phiward-copy).
- **`push_limit_gib`** (whole number, default 5; user config only). A push larger than this is
  refused: copy it yourself.
- **`ssh_config`** (a file; default none). The ssh config that every HPC request uses
  (`ssh -F FILE`, never `~/.ssh/config` unless you name it), with the system `ssh` from
  `/usr/bin`, `/bin`, `/usr/sbin` or `/sbin`, never from your `PATH`, and `ProxyCommand`,
  `ProxyJump` and `LocalCommand` off, `BatchMode=yes`. It must name the host's `ControlPath`
  (the shared connection, [hpc.md](hpc.md)). Keep it outside `~/.ssh`; it becomes a guard file
  (the agent may not write it). An `Include` in it would read files the agent may write. The
  value must be absolute (or start with `~/`).

### `[remote]`

For `phiward run --remote HOST -- CMD` ([hpc.md](hpc.md)). User config only.
- **`hosts`** (list): the hosts a remote run may name.
- **`commands`** (list): the programs it may run there, as bare names. The default is empty,
  which refuses every remote run. Nothing confines a command on the remote side: this list is
  what limits its effects.
- **`roots`** (list of absolute paths on the remote): masked in the output as `<PROTECTED>`.
- **`use_shared_connection`** (`true` or `false`; default `true`). Every HPC request joins your
  shared SSH connection and reads no credential ([hpc.md](hpc.md)). `false`: ssh logs in itself,
  so requests can read your key or ticket and have the network.

### `[launch]`

- **`pass_env`** (list): environment variables passed to a launched tool besides the built-in
  allow-list. The agent can read whatever you pass.

### `[broker]`

The grants. Nothing asks the operator at run time: what is not written here is refused.

- **`write_to`** (list of folders; default none). With exactly one folder here, gateway commands
  may write in it without `--write-to` (the default results folder). `phiward run --write-to DIR` is allowed only
  when DIR resolves to one of these folders or a folder inside one. When the config loads, each
  entry is checked:
  - an entry that does not exist yet is skipped (`doctor` counts it);
  - an entry reached through a link is skipped (`doctor` counts it): whoever can change the link
    would choose the place. Name the real folder;
  - an entry that is `/`, the home folder or above it, in a dot-folder of the home folder, in
    `~/Library` or a `PATH` folder, above a protected root, in a derived protected folder or a
    pattern match, that holds a names or pack file of the config, that holds a `.claude`
    folder, or that holds or is inside a phiward file or folder (the config, the code, the
    spool, the status file, the interpreter folder) is a problem: the config is bad.
  - an entry **inside** a protected root is fine: gateway commands write only in `write_to`
    folders (protected roots are read only for them), and what they write there stays
    protected.
- **`net`** (`true` or `false`; default `false`). With `true`, `phiward run --net` gets the
  network. On macOS it may also look up DNS; local unix sockets stay blocked (an SSH agent's or
  a shared connection's socket would log in to HPC as you). On Linux it gets the host network
  (unix sockets stay blocked).
- **`commands`** (list; default: not set, so any program may run). The programs that
  `phiward run` may run on protected data. An entry is:
  - a bare name: a program found on the broker's `PATH` by that name, called by that name
    (`wc`, not `/usr/bin/wc`);
  - `@genomics` or `@counts`: a built-in list (`samtools`, `bedtools`, `tabix`, `bgzip`,
    `mosdepth`, `seqkit`, `wc`, `uniq`, `cut`, `du`, checksums, `ls`, `file`, `stat`, `head`,
    `tail`, `zcat`, `gzip`, `gunzip`; `@counts` is the counting part). None of them runs other
    code it is given. `fastqc`, `multiqc`, `bcftools` and `sort` are left out on purpose: each
    can be told to start another program or load a library;
  - a path: one file, for example your own script, written as its real path: a path with a
    link on it lists nothing (`phiward pin` and `doctor` say so), because what is checked and
    what starts must be the same file. List a link by its name instead (a multi-call program
    such as busybox then acts as that name), or list its folder. A script's `#!` interpreter
    is not part of what you approve: point it at an interpreter the agent cannot change;
  - a folder (ending in `/`): every program in it, for example `~/pipelines/bin/`, called by
    its path or its name in that folder (a link in the folder runs as that link, as in
    Homebrew's `bin`).

  What runs is always the entry of your user config that lists it, never a link of the
  agent's: a repo config's list can only narrow yours.

  When it is set, any other program is refused. You approve the listed programs as they are:
  `phiward setup` does it when it writes the config, and `phiward pin` does it again. The broker
  runs no listed program whose content differs from what you approved, and stops when one
  changes while it runs. After you update a listed program, check it and run `phiward pin`, then
  restart the broker. Approval covers every file of a listed folder and its subfolders, so keep
  a script's helpers there; a folder with more than 2000 files is never approved. Files and
  folders named by path, and listed programs you own, are protected from agent writes
  (`(cd ~ && phiward install claude --user --write)`). `pin` and `doctor` find the programs on the running
  broker's `PATH`, and name any that are new, changed or not installed. **Set it when you work with real patient data**: without it, code
  that the agent writes can run on protected data and print what it reads in a form masking
  does not catch (for example encoded). A program that runs other code it is given (an
  interpreter, a shell, `git`, `find`, `xargs`, `make`, `sort`, a workflow engine) undoes the
  list: list your own scripts, kept outside the projects the agent works in, instead.
  `phiward doctor` warns about such entries. A repo config may set its own list too; a program must then be in both.
  `run --remote` has its own list (`[remote] commands`).
- **`max_output_lines`** (whole number, default 2000). The most lines of a gateway command's
  output (`run`, `run --remote` and `copy`) that the agent sees. The lines after that are
  counted, not shown, and a last line says how many were withheld. A notice such as
  `[3 more identical line(s)]` counts as a line; the placeholder note after the output does
  not, and counts only the lines shown. A repo config may only lower this value. To
  see more, write the results to a file in a `write_to` folder inside a protected root, and
  print a summary.

A grant gives code that the agent chooses that capability. To keep the gateway as closed as
possible, leave `write_to` empty and `net` false (and `[copy] remotes` empty); this still is not
a defence against a hijacked agent. See [threat-model.md](threat-model.md).

### `[network]`

The network of the shell commands that an agent runs in a Claude Code session (Mode A). With
`limit = true`, `(cd ~ && phiward install claude --user --write)` writes Claude Code's own
`sandbox.network.strictAllowlist` and `allowedDomains` into your user settings: shell commands
then reach only the listed hosts, and are refused all others without a question. A repository's
settings cannot add hosts or proxy ports (Claude Code ignores them while the user settings set
`strictAllowlist`). They can still take a command out of the sandbox
(`sandbox.excludedCommands`), and an excluded command reaches any host: `phiward doctor` warns
then. Needs Claude Code 2.1.285 or newer.

**Each listed host is a way out.** Code the agent writes can send what it reads to any listed
host, for example in a gist, an issue or a push to `github.com`. Claude Code's proxy decides by
the host name the client gives, so a host behind a shared front (a CDN) can reach others behind
it. A shared host by its exact name (`raw.githubusercontent.com`, `s3.amazonaws.com`) serves
anyone's content, so it is a way out to every account behind it; phiward refuses only the
wildcard forms. List only the hosts you need, and as narrowly as you can.

- **`limit`** (true or false, default false). `setup` asks, and suggests yes for real data.
- **`allowed_domains`** (list): the hosts shell commands may reach, for example `github.com`,
  `*.pypi.org` (every subdomain) or `github.com:443` (one port). Not `*`, not a URL, and not a
  wildcard over a top-level or two-part public suffix (`*.com`, `*.co.uk`) or over, or below, a
  common shared hosting name where anyone can have a site (`*.github.io`, `*.amazonaws.com`,
  `*.s3.amazonaws.com`, `*.vercel.app`, ...). This is a short list, not the whole public suffix list: check a
  wildcard yourself. Empty: no host at all. Hosts of `WebFetch(domain:...)` allow rules in your user settings count too.

What it does not limit: Claude Code's own connection to the model provider, the WebFetch and
WebSearch tools, MCP servers, hooks, and Mode B (`phiward launch`). `install` only adds: to
remove a host, or to open the network again, edit `sandbox.network` in
`~/.claude/settings.json` yourself. `phiward doctor` shows how many hosts are open and names
hosts in the settings that the config no longer lists.

### `[git]`

- **`protected_branches`** (list). The pre-push hook refuses a push that changes or deletes one.

### Keys that are gone

| Key | Gone since | What to do |
|---|---|---|
| `[broker] confirm` | 0.0.x | Remove it. Grants are `write_to` and `net`. |
| `[broker] prompt` | 0.0.x | Remove it. Nothing asks at run time. |

A file that still sets one is a bad config, with a message that says this. `phiward setup`
drops them.

### `[shell]`

```toml
[shell]
best_effort = true     # default false; user config only
```

A shell is **confined** when the kernel decides what its commands can read: Claude Code's
sandbox, as `install claude --user --write` sets it. `phiward doctor` says whether it holds,
and why not.

By default, phiward's hook refuses every command of a shell that is not confined. Only a
phiward command written as the whole command runs there:

- the gateway: `phiward run -- CMD ...` and `phiward copy SRC... DST`;
- `phiward doctor` and `phiward check -- CMD` (`check` answers as if the command ran in the
  sandbox).

The refusal says how to fix it. This applies once protected paths are set; before the first
setup, only the hidden list is checked, by the text check (best effort).

**`best_effort = true`** keeps the old behaviour: a shell command that no kernel confines gets
the hook's text check instead of a refusal. That check cannot read shell text completely
([threat model](threat-model.md)), so use it only where Claude Code's sandbox cannot run
(GitHub Copilot, which runs phiward's hook without it; a Linux machine without a usable
bubblewrap). For real data there, prefer `phiward launch`. `doctor` warns while it is on. Only your user config can set it.

`[shell] strict` and `[shell] commands` (strict mode, removed before release) still load and
do nothing: the default refusal replaces strict mode. Remove them when you next edit the file.

## MCP servers

An MCP server is a program Claude Code starts, outside its sandbox, with your rights. phiward
judges a server's tools by what confines them, not by guessing from their fields. `phiward mcp
list` shows what each of your servers is and what to do about it; `phiward mcp wrap NAME` wraps
one ([modes.md](modes.md#wrap-an-mcp-server-mode-a)).

- A tool of a server **wrapped** in `phiward launch --` runs in phiward's kernel profile: it works
  as usual, with the text check of its input. The hook trusts it as wrapped only while it really
  runs so: each `phiward launch` keeps a record of its own process, and the hook looks for a live
  one started with the entry's own id under its own Claude Code. So after `phiward mcp wrap`, start
  Claude Code again; `/resume`, `/clear` and compaction change nothing. A wrapped entry whose `env`
  sets PATH, HOME, `PHIWARD_*`, `XDG_*`, `PYTHON*`, `LD_*` or `DYLD_*`, or that has a `cwd`, counts
  as not wrapped: those change what runs. How the hook tells:
  [threat-model.md](threat-model.md#how-the-hook-trusts-a-wrapped-mcp-server).
- A tool whose **name** says it runs commands on this machine (`run_in_terminal`, `write_bash`,
  `run_command`, `execute_command`, `executeCode`, `start_process`, `run_python`, `send_keys`,
  `interact_with_process`), from any other server or from Copilot, may make only one whole
  gateway call: one `command` (or `cmd`, `script`, `input`) string or one `argv` list, with no
  other options than a description, a title, a timeout (a number), a background flag (true or
  false) or this folder as `cwd`. Everything else is refused, and the refusal says what to do
  for that kind of server. JavaScript in a browser (a tool or server named for the browser:
  Chrome's `execute_javascript`) is not a shell, and neither is a name that only reads
  (`read_terminal`, `search_shell_history`) or a terminal tool given only a folder or a title
  (`open_terminal_tab`). A local query tool (`execute_sql`) is: a local database can run
  commands. Its remote server's tools work. Container exec (`docker_exec`) is a shell too. The
  desktop app's own `_consent` field (true or false) does not count as an option; any other
  field does.
- With `[shell] best_effort` on, such a tool gets the text check in place of the exact form,
  as Bash does (Copilot's `run_in_terminal` is its shell).
- **Every other tool** (a docs query, a coupon `code`, a Slack message) works, with every
  string of its input checked for protected paths, also percent-decoded (a `file://` URL), and
  a string that looks like a path (a `/`, `~`, or a file name with an extension) by where it
  really leads, from this folder and from the project folder (a link into a protected folder,
  or a new file in one). Such a string may not name the files that control the guards either
  (`.mcp.json`, Claude Code's settings, phiward's own files), since a local server could write
  them; a web address (`https://...`) and the input of a remote server may, since nothing here
  is written. A web address is still followed as a path (a local server may join it to its
  folder, where a link may be named `https:`). One that climbs above its host
  (`https://x/../../f`, `https://../f`, also percent-encoded), or one whose scheme names
  something in this folder or the project folder (a file or link `https:`), may not name those
  files either. A link made after the check (by a Bash call in the same turn), or in a folder
  the server joins paths to that is neither of these, is not seen. This check cannot be complete: the server may start from another
  folder, or a link may change after the check. Wrapping is the boundary.
  For a bare local server this text check is not a boundary: the server itself can read what
  you can. `doctor` names such servers; wrap
  the ones you use with protected data nearby.


### Which server a tool belongs to

Claude Code 2.1.274 and newer tells the hook each MCP
tool's server and where its definition came from (`mcp_server.source`). phiward reads that
scope's entry, by its exact name:

| source | phiward reads | its tools |
|---|---|---|
| `local`, `project`, `user` | `~/.claude.json` (this project's entry, or the top level) or the project's `.mcp.json` | wrapped or remote: as such; else bare |
| `plugin` | the plugin's installed `.mcp.json` or `plugin.json`, in the copies that apply to this project (one installed for another project does not; a local or project copy before a user one); an entry of this plugin phiward cannot read makes it bare, other plugins' entries are not read | wrapped (the plugin itself runs it under `phiward launch`) or remote: as such; else bare (`phiward mcp wrap` does not change a plugin's files: they are replaced on update) |
| `claudeai` (a claude.ai connector) | nothing | remote |
| `sdk` (the app's own servers, such as the desktop app's `terminal`) and any other source | nothing | bare |

A server reached by URL counts as remote only when its URL surely names another
machine; any URL phiward cannot read strictly counts as this machine. A server on this
machine (an IDE's) runs outside Claude Code, so phiward cannot wrap it, and its command tools
may make only gateway calls. A config entry phiward cannot read (`args` that is not a list
of strings) counts as not wrapped, and does not change how the others are read. The detail:
[threat-model.md](threat-model.md#how-the-hook-trusts-a-wrapped-mcp-server).

A config file of another scope cannot speak for the server, however it names it. With an
older Claude Code (and with Copilot) the hook knows only the tool's name: then only your own
config (`~/.claude.json`) can make a server wrapped or remote, and a server of `.mcp.json`
counts as bare. `doctor` warns when Claude Code is too old. To see what your Claude Code
sends, run `bash tools/check-claude-mcp-source.sh` from a phiward checkout (it runs `claude
-p` once, in a temporary project, and changes no settings of yours).


## The repo config

`.phiward.toml` uses the same sections and keys, with the limits in
[Who may set what](#who-may-set-what). An example:

```toml
[protected_paths]
roots = ["~/data/study-a"]

[sanitize]
packs = ["genomics"]

[git]
protected_branches = ["main"]
```

Do not rely on a repo config alone for protection: the agent can edit its repository. Put the
roots that matter in the user config.

## Fail closed

A config file that cannot be read, does not parse, has an unknown section or key, has a bad
value, sets a key that is gone, or has a `write_to` entry that may not be granted, is a **bad
config**. A repo config must also be a regular file, not a link, and not inside a protected
path. With a bad config, every guarded action is refused until you fix it: the hook,
`phiward run` and `copy` all refuse. `phiward doctor` prints the problem.
For a repo config, the message the agent sees quotes nothing from the file (it may be a link
into a protected folder); `phiward doctor --show-paths`, in your own terminal, shows why.

## Derived protected folders

When there is at least one protected path, two more folders are protected without being in the
config:

- the cache folder (it holds the gateway's scratch folders while commands run);
- the `.git` of a work tree that holds a root (git keeps copies of its files there). The agent
  then cannot use git in that work tree. Keep protected data outside the repositories that the
  agent works in.

## Environment variables

Set these in the shell where you start the agent tool **and** in the shell where you start the
broker, with the same values. **The Claude Code desktop app does not see variables you set in a
terminal:** for Mode A, keep the default places and do not set `PHIWARD_CONFIG` or
`PHIWARD_SPOOL` (or set them in the `env` block of the Claude Code settings and for the broker
service alike). `doctor` warns when the broker uses another config, cache folder
or set of roots.

| Variable | Effect |
|---|---|
| `PHIWARD_CONFIG` | The user config file. Must name an existing file. |
| `XDG_CONFIG_HOME` | The base of the default user config place. |
| `XDG_CACHE_HOME` | The base of the cache folder. |
| `PHIWARD_SPOOL` | The broker's spool folder (default `~/.phiward-spool`). |
| `PHIWARD_BROKER_WAIT` | Seconds a client waits for the broker to claim its request (default 10). |
| `PHIWARD_DEV` | `1`: `launch` and `install --user --write` work from a source checkout, without phiward's check of its own installed files. For development only. |
| `CLAUDE_PROJECT_DIR` | Set by Claude Code for hooks. Without it, the hook cannot find the project settings, so it does not treat the shell as confined. |
| `CLAUDE_CONFIG_DIR` | Claude Code's user settings folder (default `~/.claude`). When it is set, Claude Code reads `.claude.json` (its user and local MCP servers) from it in place of `~/.claude.json`, and so do `mcp list`, `wrap`, `doctor` and the hook. |

The broker does not pass the agent's environment to gateway commands. A command gets only
`PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_*`, `TZ` and `TERM` from the broker's own
environment, and `TMPDIR` set to its private scratch folder.
