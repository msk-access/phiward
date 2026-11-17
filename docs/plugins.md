# The Claude Code plugin, and other plugins

**For:** people who use phiward's Claude Code plugin, or other plugins beside it.

## phiward's plugin

phiward's repository is also a Claude Code plugin marketplace. The plugin gives a session:
- phiward's hooks: the guard on every tool call, and the start-of-session note with the rules;
- the skill: how to work through the gateway;
- three commands: `/phiward:setup` (the guided first setup), `/phiward:doctor` (checks the setup
  and explains each warning) and `/phiward:help` (how to work with protected data and HPC);
- an MCP server, `phiward`, whose tools are the gateway: `phiward_run`, `phiward_copy`,
  `phiward_remote`, `phiward_check` and `phiward_doctor`. They do the same checks and masking as
  the commands, with arguments as lists and no shell.

**Tested** in a desktop-app session on made-up data: the note, the refusals, the commands and
normal work.

The plugin **does not** install the phiward package, and it **cannot** set Claude Code's sandbox
or permission rules. Those come from the [quick start](quickstart.md) (`phiward install claude
--user`), and they are what stops the reads in a normal session. Keep that user wiring even when
you use the plugin: a project can turn a plugin off, but not your user wiring.

### Install it

In Claude Code, two commands:

```
/plugin marketplace add msk-access/phiward#v0.2.0b1
```

```
/plugin install phiward@phiward
```

`#v0.2.0b1` pins the plugin to the release you installed with `uv`, so their versions agree.
In a terminal, the same is `claude plugin marketplace add msk-access/phiward#v0.2.0b1`, then
`claude plugin install phiward@phiward`.

### Offer it to every contributor of a project

The project's committed `.claude/settings.json` can offer it:

```json
{
  "extraKnownMarketplaces": {
    "phiward": { "source": { "source": "github", "repo": "msk-access/phiward",
                             "ref": "v0.2.0b1" } }
  },
  "enabledPlugins": { "phiward@phiward": true }
}
```

Each contributor then trusts the folder and installs it (`/plugin install phiward@phiward`, or
`claude plugin install phiward@phiward --scope project`).

### Know this

- **The plugin runs `phiward` from the app's `PATH`.** If the desktop app does not find it,
  every tool call is refused, with a message that says phiward is not installed: quit the app
  and open it again ([quickstart.md](quickstart.md#if-something-goes-wrong)). A `PATH` folder the
  agent can write could put another program first ([modes.md](modes.md)). The user wiring uses
  the full path.
- **A project can turn a plugin off** (`"phiward@phiward": false` in its settings), unless your
  organization's managed settings force it on. Your user wiring cannot be turned off by a
  project that way. A project's `disableAllHooks` can still turn all hooks off; only managed
  settings stop that. `phiward doctor` warns when a project turns the plugin off or sets `PATH`.
- **For an organization, managed settings are the strong form.** They can force the plugin on,
  allow only managed and forced hooks, and set the sandbox and permission rules.
- **The plugin follows the tag you added.** With `#v0.2.0b1`, the marketplace takes the plugin
  from that release. Without a tag it follows the repository's `main` branch. The plugin's
  version must match the installed phiward package (`phiward --version`). To move to a new
  release, update both: `uv tool install --force phiward==<version>`, then add the marketplace
  again with the new tag.

## Other plugins (for example ECC)

You can use phiward together with other Claude Code plugins, for example
[ECC](https://github.com/affaan-m/ECC). You do not have to choose. Tested: the phiward plugin
and ECC 2.2.3 in one desktop-app session on made-up data. phiward's guard refused the reads of
the protected folder, and the normal work ran.

### How they work together

- **Claude Code runs every hook that matches a tool call.** phiward's guard runs on each call,
  whatever other plugins also run. If one hook refuses a call, the call does not run.
- **Other plugins' switches do not turn phiward off.** For example, ECC's
  `ECC_HOOKS_ENABLED`, `ECC_HOOK_PROFILE`, `ECC_DISABLED_HOOKS` and `ECC_GATEGUARD=off` change
  only ECC's own hooks.
- **Do not put phiward's guard into another plugin's hook list.** Keep phiward as its own
  plugin, or wire it with `phiward install claude --user`. The switches of the other
  plugin could then turn the guard off.
- **The hook is not the protection by itself.** In a normal session (Mode A), Claude Code's
  sandbox and permission rules stop the reads. `phiward install claude` writes them; no plugin can
  ([modes.md](modes.md)). Under `phiward launch` (Mode B), the kernel profile stops them.

### Set up

1. Do the [quick start](quickstart.md): install phiward, write your config, wire Claude Code
   and start the broker.
2. Optional: add the phiward plugin (above).
3. Install the other plugin as its own instructions tell you.
4. Run `phiward doctor` and open a new session.

### Know this

- **In a normal session, other plugins' hooks and MCP servers run as you, outside Claude Code's
  sandbox.** They are not confined by phiward. A hook can read any file that you can read,
  and it can add text to what Claude Code sends to the model. Install only plugins you trust,
  and check what their hooks read and keep. Under `phiward launch`, they run inside the kernel
  profile, the same as the tool.
- **A hook sees each tool call.** A hook that runs before a call sees its input, also when
  phiward refuses the call: for example a command that names a protected path. A hook that runs
  after a call also sees its output. Output from `phiward run` is masked before Claude Code
  receives it, so a hook sees the masked output.
- **Some plugins stop the agent's first command and ask it questions.** For example, ECC's
  GateGuard asks the agent to state facts before its first shell command, and its message tells
  the agent how to turn GateGuard off. That is ECC's decision about ECC's own hook.
  phiward's refusals tell the agent the approved route; they never tell it how to turn a guard
  off.
- **Under `phiward launch`, a plugin is not there until you carry it over.** Each session starts
  from a trusted copy of the tool's config (`phiward carryover add`, see [launch.md](launch.md)).
  A plugin that a session installs or turns on goes to quarantine. Carrying over a plugin such
  as ECC into `launch` is **not tested yet**.

Next: [daily use](daily-use.md).
