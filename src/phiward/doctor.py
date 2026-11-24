"""`phiward doctor`: what is configured, whether it loads, and what may turn the guards off.

It reads settings files and never writes them. Paths from the config are shown only as counts,
unless `--show-paths` is given (this output may reach the model).
"""

import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from phiward import claude_settings, config, confine, install, pathid


def _hook_words(h: Dict[str, Any]) -> List[str]:
    import shlex
    try:
        return shlex.split(str(h.get("command", ""))) + [str(a) for a in h.get("args", []) or []]
    except ValueError:
        return []


_PYTHON_NAME = re.compile(r"python(?:3(?:\.\d+)?t?)?")


def hook_form(h: Dict[str, Any]) -> str:
    """Which phiward hook an entry is, by its exact shape only: "isolated" (what
    `install --user` writes: `install.hook_entry`, or the one `/bin/sh` line an earlier phiward
    wrote, with this install's own Python), "launcher" (an older user form: an absolute
    `.../phiward hook claude`, a Python with `-I` and no clean-up of the loader variables, or
    another environment's Python), "project" (`install --project`: phiward by name), or "" (not
    phiward's guard, whatever it mentions; not a command hook; not run by sh)."""
    if h.get("type", "command") != "command" or h.get("shell") not in (None, "bash"):
        return ""
    py = install.hook_python(h)
    if py:
        if not _PYTHON_NAME.fullmatch(os.path.basename(py)):
            return ""
        return "isolated" if _same_folder(py, sys.executable) else "launcher"
    if h.get("args"):
        # the exec form an older phiward wrote with its shell prefix: the same isolated command
        py = install.shell_form_python(install._entry_text(h))
        return "isolated" if py and _PYTHON_NAME.fullmatch(os.path.basename(py)) else ""
    command = str(h.get("command", ""))
    if command == install.PROJECT_HOOK or command in install.OLD_PROJECT_HOOKS:
        return "project"
    py = install.shell_form_python(command)
    if py:
        if not _PYTHON_NAME.fullmatch(os.path.basename(py)):
            return ""
        # only this install's own Python: another environment's (an older phiward in a project
        # venv) runs its own phiward, whatever its interpreter is
        return "isolated" if _same_folder(py, sys.executable) else "launcher"
    words = _hook_words(h)
    if len(words) == 3 and words[0].startswith("/") and words[1:] == ["hook", "claude"] \
            and os.path.basename(words[0]) in config.PROGRAMS:
        return "launcher"
    if len(words) == 6 and words[0].startswith("/") and words[1:] == [
            "-I", "-m", "phiward", "hook", "claude"] \
            and _PYTHON_NAME.fullmatch(os.path.basename(words[0])):
        return "launcher"
    return ""


def _same_folder(a: str, b: str) -> bool:
    """Whether two programs sit in the same folder (by device and inode of the folder)."""
    try:
        x, y = os.stat(os.path.dirname(a)), os.stat(os.path.dirname(b))
    except OSError:
        return False
    return (x.st_dev, x.st_ino) == (y.st_dev, y.st_ino)


def _program_there(h: Dict[str, Any]) -> bool:
    import shutil
    py = install.hook_python(h)
    if py:  # the script and the Python it runs
        return all(os.path.isfile(p) and os.access(p, os.X_OK)
                   for p in (str(h["command"]), py))
    first = install.shell_form_python(str(h.get("command", ""))) or (_hook_words(h) or [""])[0]
    if h.get("command") in (install.PROJECT_HOOK, install.PROJECT_NOTE) + install.OLD_PROJECT_HOOKS:
        first = "phiward"  # the project hook: phiward by name
    if "/" in first:
        return os.path.isfile(first) and os.access(first, os.X_OK)
    return shutil.which(first) is not None


PROMPT_EVENTS = ("UserPromptSubmit", "UserPromptExpansion")
HOOK_TYPES = ("command", "prompt", "agent", "http", "mcp_tool")


def is_prompt_scan(h: Dict[str, Any]) -> bool:
    """Whether a hook entry is phiward's prompt check, by its exact shape: the user form
    (`install.hook_entry`, or the `/bin/sh` line an earlier phiward wrote), or the project form
    (PROJECT_PROMPT_HOOK). A program at any other path, whatever its name, is not."""
    if h.get("type", "command") != "command" or h.get("shell") not in (None, "bash"):
        return False
    if install.hook_python(h, "prompt-scan"):
        return True
    if h.get("args"):
        return False
    command = str(h.get("command", ""))
    return command == install.PROJECT_PROMPT_HOOK or \
        bool(install.shell_form_python(command, "prompt-scan"))


def prompt_hooks(data: Any) -> List[Tuple[str, Dict[str, Any]]]:
    """(event, entry) for each UserPromptSubmit and UserPromptExpansion hook in a settings
    object or a plugin's hooks.json."""
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return []
    return [(ev, h) for ev in PROMPT_EVENTS
            for g in (hooks.get(ev) if isinstance(hooks.get(ev), list) else [])
            if isinstance(g, dict) and isinstance(g.get("hooks"), list)
            for h in g["hooks"] if isinstance(h, dict)]


def _hook_type(h: Dict[str, Any]) -> str:
    t = h.get("type", "command")
    return t if t in HOOK_TYPES else "unknown"


def _other_prompt_hook(where: str, ev: str, h: Dict[str, Any]) -> str:
    return (f"  WARNING: {where} has a {ev} hook of type `{_hook_type(h)}`: it runs beside "
            "phiward's prompt check, and may send the prompt on (the check is a tripwire, not a "
            "boundary)")


def plugin_prompt_lines(project: str, home: str) -> List[str]:
    """The WARNINGs for the prompt hooks of each enabled plugin other than phiward's (its
    hooks/hooks.json in each installed copy that applies here)."""
    from phiward import claude_settings, mcp_config
    enabled: Dict[str, bool] = {}
    for _lvl, _p, data in claude_settings.levels(project, home):
        plugins = data.get("enabledPlugins") if isinstance(data, dict) else None
        if isinstance(plugins, dict):
            for k, v in plugins.items():
                if isinstance(k, str) and k not in enabled:
                    enabled[k] = v is True  # the highest level that names it wins
    out: List[str] = []
    for key in sorted(k for k, on in enabled.items() if on and k != "phiward@phiward"):
        roots = (mcp_config._plugin_roots(home, dict(os.environ), project,
                                          key.split("@", 1)[0]) or {}).get(key, [])
        for root in roots:
            data, _err = claude_settings.read_settings(os.path.join(root, "hooks", "hooks.json"))
            for ev, h in prompt_hooks(data):
                out.append(_other_prompt_hook(f"the enabled plugin {key}", ev, h))
    return out


@dataclass
class Wiring:
    """What Claude Code's settings files say about phiward's hook, for `doctor` and its
    `--headless` check. `problems` are the reasons a session here would not be guarded;
    `isolated` whether the user or managed settings run the isolated hook (`hook_form`)."""
    lines: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    wired: bool = False
    isolated: bool = False


def wiring_state(project: str, home: str) -> Wiring:
    w = Wiring()
    wired_levels: List[str] = []
    disable: Optional[Tuple[str, bool]] = None  # the highest level that sets it wins
    covered: set = set()
    isolated: set = set()  # matchers the user or managed settings run the isolated hook for
    bare_name = False
    managed_only = False
    lv = claude_settings.levels(project, home)
    for level, path, _ in lv:
        data, err = claude_settings.read_settings(path)
        if err:
            w.lines.append(f"  {level}: {path} cannot be read ({err})")
            w.problems.append(f"the {level} settings file {path} cannot be read as JSON, so "
                              "what it sets (hooks, the sandbox) cannot be checked")
            continue
        if data is None:
            continue
        mine = [(g, h, form) for g in (data.get("hooks", {}) or {}).get("PreToolUse", []) or []
                if isinstance(g, dict) for h in g.get("hooks", []) or [] if isinstance(h, dict)
                for form in [hook_form(h)] if form]
        prompts = prompt_hooks(data)
        scans = [h for ev, h in prompts if ev == "UserPromptSubmit" and is_prompt_scan(h)]
        w.lines += [_other_prompt_hook(f"the {level} settings", ev, h) for ev, h in prompts
                    if not (ev == "UserPromptSubmit" and is_prompt_scan(h))]
        if mine and not scans:
            w.problems.append(f"the {level} settings run phiward's hook but not its prompt "
                              "check (a UserPromptSubmit entry): run `(cd ~ && phiward install "
                              "claude --user --write)`")
        for h in scans:
            if h.get("onFailure") != "block" or h.get("async") or h.get("asyncRewake") \
                    or "if" in h:
                w.problems.append(f"phiward's prompt check in the {level} settings has no "
                                  "onFailure: block, or has `async` or `if`, so a prompt can be "
                                  "sent unchecked")
        if mine:
            wired_levels.append(level)
            blocks = all(h.get("onFailure") == "block" for _g, h, _f in mine)
            note = "phiward wired" + ("" if blocks else ", WITHOUT onFailure: block")
            if not blocks:
                w.problems.append(f"a phiward hook entry in the {level} settings has no "
                                  "onFailure: block (a hook that fails lets the tool run)")
            if any(install.is_old_form(h) for _g, h, _f in mine) or \
                    any(install.is_old_form(h) for h in scans):
                w.lines.append(f"  WARNING: the {level} settings run phiward's hooks in the form "
                               "an older phiward wrote (one inline shell line): run `(cd ~ && "
                               "phiward install claude --user --write)` again; it replaces them "
                               "with hooks that run from phiward's own files")
            for _g, h, form in mine:
                if not _program_there(h) and install.hook_python(h):
                    w.problems.append(f"the hook's file in the {level} settings is gone: "
                                      "phiward's Python moved (an upgrade, or another Python "
                                      "version); every tool call is refused until you run "
                                      "`(cd ~ && phiward install claude --user --write)` again")
                elif not _program_there(h):
                    w.problems.append(f"a phiward hook in the {level} settings names a program "
                                      "that is not there")
                if h.get("async") or h.get("asyncRewake") or "if" in h:
                    w.problems.append(f"a phiward hook entry in the {level} settings has "
                                      "`async` or `if`, so it does not decide every tool call")
                bare_name = bare_name or form == "project"
                if level in ("user", "managed") and form == "isolated":
                    isolated.add(str(_g.get("matcher", "")))
            covered |= {str(g.get("matcher", "")) for g, _h, _f in mine}
        elif level == "project local" and isinstance(data.get("sandbox"), dict):
            note = "this machine's entries for the sandbox and rules (personal, not committed)"
        elif level == "project" and isinstance(data.get("sandbox"), dict):
            note = "sandbox and permission rules (hooks come from your user wiring)"
        else:
            note = "phiward not wired"
        w.lines.append(f"  {level}: {path}: {note}")
        if disable is None and "disableAllHooks" in data:
            disable = (level, bool(data["disableAllHooks"]))
        if level == "managed" and data.get("allowManagedHooksOnly") is True:
            managed_only = True
    read = {p for _l, p, _d in lv}
    for f in claude_settings.project_files(project, home):
        data = claude_settings.read_settings(f)[0] if f not in read else None
        if data and data.get("disableAllHooks") is True:
            w.problems.append(f"disableAllHooks is true in {f}, a settings file Claude Code "
                              "may read")
    if disable and disable[1]:
        w.lines.append(f"  WARNING: disableAllHooks is true at the {disable[0]} level: user and "
                       "project hooks do not run (managed hooks still do).")
        if "managed" not in wired_levels:
            w.problems.append(f"disableAllHooks is true at the {disable[0]} level")
    if managed_only and "managed" not in wired_levels:
        w.problems.append("managed settings allow only managed hooks, and they do not run phiward")
    w.lines += plugin_prompt_lines(project, home)
    on, level, off, path = install.plugin_state(project, home)
    if on:
        w.lines.append(f"  the phiward plugin is enabled ({level} settings): it carries hooks")
        bare_name = True  # the plugin's hooks run `phiward` by name
        if level in ("user", "managed"):
            wired_levels.append(level)
    if off:
        w.lines.append("  WARNING: this project's settings turn the phiward plugin off: only "
                       "your user wiring's own hooks guard this project")
    if path:
        w.lines.append("  WARNING: this project's settings set env.PATH: the plugin's hooks run "
                       "`phiward` by name, so the project could choose the program")
        if bare_name:
            w.problems.append("the project's settings set env.PATH, and a hook runs `phiward` "
                              "by name")
    w.wired = bool(wired_levels) or on
    w.isolated = any(m in isolated for m in install.ALL_TOOLS)
    if not w.wired:
        w.lines.append("  WARNING: no Claude Code settings file runs phiward "
                       "(see `phiward install claude`).")
        w.problems.append("Claude Code is not wired: no settings file or plugin runs phiward's "
                          "hook (`(cd ~ && phiward install claude --user --write)`)")
    else:
        if not any(m in covered for m in install.ALL_TOOLS) and not on:
            w.problems.append("phiward's hook covers only some tools (an older install): run "
                              "`(cd ~ && phiward install claude --user --write)`")
        if not any(lv in ("user", "managed") for lv in wired_levels):
            # found in practice: a session opened on the folder above the project loaded none
            # of the project's settings, so nothing guarded it
            w.lines.append("  WARNING: only this project is wired: a session opened in any other "
                           "folder (a parent folder, another checkout) has no protection. Wire "
                           "your user settings too: `(cd ~ && phiward install claude --user --write)`.")
    return w


def pack_lines(cfg: config.Config) -> List[str]:
    """A WARNING for each user pack file inside a protected path: under `phiward launch` the
    prompt check cannot read it, so every prompt is refused."""
    from phiward import paths
    pset = paths.ProtectedSet(cfg.all_roots, cfg.patterns)
    return [f"WARNING: a pack file of the user config ({p}) is inside a protected path: under "
            "`phiward launch` the prompt check cannot read it, and refuses every prompt. Move it "
            "out of the root." for p in cfg.user_packs
            if "/" in p and pset.relation(os.path.expanduser(p)) == paths.INSIDE]


def claude_report(project: str, home: str) -> List[str]:
    return wiring_state(project, home).lines


def _merged_rules(project: str, home: str) -> List[str]:
    out: List[str] = []
    for _, path, _ in claude_settings.levels(project, home):
        data, _err = claude_settings.read_settings(path)
        if isinstance(data, dict):
            perms = data.get("permissions")
            if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
                out += [r for r in perms["deny"] if isinstance(r, str)]
    return out


def mcp_servers(project: str, home: str) -> List[Tuple[str, bool]]:
    """(name, wrapped) for every MCP server in the user's and the project's MCP config
    (mcp_config.servers)."""
    from phiward import mcp_config
    return [(s.name, s.wrapped) for s in mcp_config.servers(project, home).values()]


def bare_split(project: str, home: str) -> Tuple[List[str], List[Tuple[str, str]]]:
    """The servers that run with the operator's rights: (names `phiward mcp wrap` can change,
    [(name, why it cannot be wrapped)]), by `mcp_config.entry_state`, the answer `mcp list`,
    `wrap` and the hook's advice give too."""
    from phiward import mcp_config
    states = mcp_config.name_states(project, home)
    can, cannot = [], []
    for n, w in mcp_servers(project, home):
        if w or n.startswith("\0"):
            continue  # an unreadable file is named by mcp_config.problems
        why = mcp_config.cannot_wrap_why(states.get(n, set()))
        if why:
            cannot.append((n, why))
        else:
            can.append(n)
    return sorted(can), sorted(cannot)


def install_lines() -> List[str]:
    """doctor's lines for how phiward itself is installed: a shared environment, and the
    self-check. Setup does not change them, so they show before setup too."""
    out = []
    if os.path.isdir(os.path.join(sys.prefix, "conda-meta")) or \
            os.path.basename(sys.prefix).lower() in ("anaconda3", "miniconda3", "mambaforge",
                                                     "miniforge3"):
        # its folder is a guard file: the agent may not change it, so a shared environment
        # (conda base) becomes read-only for the agent's own package installs
        out.append("WARNING: phiward is installed in a shared Python environment ("
                   f"{os.path.basename(sys.prefix)}); its folder is protected from the agent, so "
                   "the agent cannot install packages there. Install phiward with `uv tool "
                   "install` or `pipx` instead (see docs/setup.md).")
    return out + selfcheck_lines()


# what the last self-check found: {"installed": bool}, for the launch section (no second check)
SELFCHECK: Dict[str, bool] = {}


def selfcheck_lines() -> List[str]:
    """doctor's lines for phiward's self-check and its full check of phiward's own Python: one
    WARNING for the package (what `launch` and every wrapped MCP server check before they start,
    and refuse), one for the rest of its Python (which another account could change), each with
    its own step."""
    from phiward import selfcheck
    try:
        installed, package, python = selfcheck.check_full_isolated()
    except Exception as exc:  # noqa: BLE001 - doctor reports; it does not stop
        return [f"WARNING: phiward's self-check could not run ({type(exc).__name__})"]
    SELFCHECK["installed"] = bool(installed)
    if not installed:
        return []
    out = []
    here = selfcheck._running_package()
    if package and selfcheck._kind(package[0]) == selfcheck.K_NO_ANSWER:
        # doctor ran the full check; `launch` runs a shorter one, which may answer
        return [f"WARNING: {selfcheck.refusal(package)}: " + selfcheck.fix_text(package, here)]
    if package:
        out.append(f"WARNING: {selfcheck.refusal(package)}, so `phiward launch` and every "
                   "wrapped MCP server refuse to start: " + selfcheck.fix_text(package, here))
    # each WARNING its own step, from its own whole list (the package's is what `launch` says);
    # the second only when its step differs, with the lines that step fixes
    step = selfcheck.fix_text(python, here)
    if any(p != selfcheck.MORE for p in python) and \
            (not package or step != selfcheck.fix_text(package, here)):
        out.append("WARNING: phiward's Python can be changed by another account (" +
                   selfcheck._listed(python) + "): " + step)
    return out


def path_risks(project: str, home: str, path: str) -> List[Tuple[str, str, int]]:
    """(entry name, program, how many folders) for each MCP entry that names its program without
    a path, when `path` (Claude Code's PATH) has folders the agent can write before the folder
    where the program is found: a relative or empty entry (Claude Code's own folder), or one
    inside `agent_writable`."""
    from phiward import mcp_config
    roots = claude_settings.agent_writable(project, home)
    out: List[Tuple[str, str, int]] = []
    for e in mcp_config.entries(project, home):
        if e.state in ("remote", "here", "no-command") or not isinstance(e.spec, dict):
            continue
        cmd = mcp_config._command(e.spec)
        if not cmd or not cmd[0] or "/" in cmd[0]:
            continue
        bad = 0
        for d in path.split(":"):
            if not d.startswith("/"):
                bad += 1  # relative to the folder Claude Code runs in, the project
                continue
            if claude_settings.inside(d, roots):
                bad += 1
                continue
            if os.access(os.path.join(d, cmd[0]), os.X_OK) and \
                    os.path.isfile(os.path.join(d, cmd[0])):
                break
        if bad:
            out.append((e.name, cmd[0], bad))
    return out


# the settings keys whose value is a command Claude Code runs with your rights
_COMMAND_KEYS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")


def _settings_commands(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(where, command) for each command a settings file makes Claude Code run."""
    out: List[Tuple[str, str]] = []
    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    for event, groups in hooks.items():
        for g in groups if isinstance(groups, list) else []:
            for h in (g.get("hooks") if isinstance(g, dict) else None) or []:
                if isinstance(h, dict) and isinstance(h.get("command"), str):
                    out.append((f"a {event} hook", h["command"]))
    for key in ("statusLine", "fileSuggestion"):
        v = data.get(key)
        if isinstance(v, dict) and isinstance(v.get("command"), str):
            out.append((key, v["command"]))
    for key in _COMMAND_KEYS:
        if isinstance(data.get(key), str):
            out.append((key, data[key]))
    return out


def _script_files(command: str, project: str, home: str) -> List[str]:
    """The files a command runs: its first word, and when that is a launcher (`sh`, `node`,
    `python3`...: config.LAUNCHERS) each later word that is an existing file. `~` and
    `$CLAUDE_PROJECT_DIR` expanded, a relative path taken in the project (where Claude Code
    runs hooks); a word with `${CLAUDE_PLUGIN_ROOT}` (a plugin's own folder) and a bare name (a
    PATH lookup, which differs per terminal) are left out."""
    import shlex
    try:
        words = shlex.split(command)
    except ValueError:
        return []
    out: List[str] = []
    # `env [VAR=x]... [-opts] PROGRAM ...`: the program is what runs; `-u VAR`, `-C DIR` and
    # `-P PATH` take a word, `-S STRING` is split into words
    while words and os.path.basename(words[0]) == "env":
        words = words[1:]
        while words and ("=" in words[0] or words[0].startswith("-")):
            w, words = words[0], words[1:]
            if w == "--":
                break
            if w in ("-S", "--split-string") and words:
                try:
                    words = shlex.split(words[0]) + words[1:]
                except ValueError:
                    return []
            elif w.startswith("-S") and not w.startswith("--"):
                try:
                    words = shlex.split(w[2:]) + words
                except ValueError:
                    return []
            elif w in ("-u", "-C", "-P", "--unset", "--chdir") and words:
                words = words[1:]

    def place(w: str) -> str:
        if "CLAUDE_PLUGIN_ROOT" in w:
            return ""
        for var in ("${CLAUDE_PROJECT_DIR}", "$CLAUDE_PROJECT_DIR"):
            w = w.replace(var, project)
        for var in ("${HOME}", "$HOME"):
            w = w.replace(var, home)
        if w == "~" or w.startswith("~/"):
            w = home + w[1:]
        if "/" not in w or "$" in w:
            return ""
        return w if w.startswith("/") else os.path.join(project, w)

    first = place(words[0]) if words else ""
    if first and os.path.isfile(first):
        out.append(first)
    if words and config.runs_other_code(words[0]):
        for w in words[1:]:
            # a launcher's argument names a file, also with no `/` (`python3 x.py`)
            p = place(w) or (os.path.join(project, w) if "/" not in w and "$" not in w
                             and not w.startswith("-") and "CLAUDE_PLUGIN_ROOT" not in w else "")
            if p and os.path.isfile(p) and p not in out:
                out.append(p)
    return out


def init_lines(project: str, home: str) -> List[str]:
    """A NOTE in a project (a git work tree other than the home folder) whose own settings do
    not deny the shell its Claude Code settings (`phiward init`, `install --project`)."""
    if os.path.realpath(project) == os.path.realpath(home) or \
            not os.path.exists(os.path.join(project, ".git")):
        return []
    data, _why = claude_settings.read_settings(os.path.join(project, ".claude", "settings.json"))
    deny = (((data or {}).get("sandbox") or {}).get("filesystem") or {}).get("denyWrite") or []
    if "./.claude/settings.json" in deny:
        return []
    return ["  NOTE: this project is not set up with `phiward init`: a shell command here could "
            "rewrite its Claude Code settings (your user wiring's hook still checks every tool "
            "call); run `phiward init` in it (it writes an AGENTS.md section, a .gitignore line, "
            ".claude/settings.json and git hooks)"]


def settings_script_lines(project: str, home: str) -> List[str]:
    """doctor's lines for what Claude Code's settings make it run: a script a session in
    `project` can write (its shell too), a WARNING with its step (into the user folder's
    `hooks/`, or, when a session here can write that too, a project folder to work in); a
    PermissionRequest hook, a NOTE (it can answer the prompts phiward's hook asks for code
    files and writes outside the sandbox's folders). phiward's own hooks are left out."""
    writable = [pathid.fold(w).rstrip("/") + "/" for w in
                claude_settings.agent_writable(project, home)]
    hooks_dir = os.path.join(claude_settings.user_dir(home), "hooks")
    shown_dir = "~" + hooks_dir[len(home):] if pathid.inside(hooks_dir, home) else hooks_dir
    if any((pathid.fold(os.path.realpath(hooks_dir)) + "/").startswith(w) for w in writable):
        step = (f"a session in {project} can write {shown_dir} too: start Claude Code in a "
                "project folder, not here")
    else:
        step = (f"move it into `{shown_dir}/` (your user folder, which no session in a project "
                "writes) and name it there")
    out: List[str] = []
    seen = set()
    for level, path, data in claude_settings.levels(project, home):
        if not isinstance(data, dict):
            continue
        hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
        if hooks.get("PermissionRequest"):
            out.append(f"  NOTE: the {level} settings ({path}) have a PermissionRequest hook: it "
                       "can answer the prompts phiward's hook asks (code files, writes outside "
                       "the sandbox's folders) without you; know what it allows")
        for where, command in _settings_commands(data):
            if hook_form({"type": "command", "command": command}):
                continue  # phiward's own
            for f in _script_files(command, project, home):
                real = os.path.realpath(f)
                key = pathid.fold(real)
                if key in seen:
                    continue
                seen.add(key)
                if not any((key + "/").startswith(w) for w in writable):
                    continue
                out.append(f"  WARNING: {where} in the {level} settings runs {real} with your "
                           "rights, and a session in this project can write it, its shell too: "
                           + step)
    return out


def code_root_lines(project: str, home: str) -> List[str]:
    """doctor's lines for the code Claude Code runs that a session in `project` can write, its
    shell too (`claude_settings.writable_code_roots`: a skill linked in from the project)."""
    out = []
    roots, notes = claude_settings.code_root_report(project, home)
    if len(roots) > 3:
        out.append(f"  WARNING: Claude Code runs {len(roots)} folders as code that a session in "
                   "this project can write, its shell too (linked in from "
                   + ", ".join(v for _r, v in roots[:3]) + ", ...): open sessions in a folder "
                   "that holds none of them")
    else:
        for real, via in roots:
            out.append(f"  WARNING: Claude Code runs {real} as code (through the link {via}), "
                       "and a session in this project can write it, its shell too: replace the "
                       f"link with a copy of {real} (then edit the copy outside such sessions)")
    said = {
        "tree": lambda r, v: (f"Claude Code runs {r} as code" + (f" (through {v})" if v else "")
                              + ", which holds too many entries: the links inside it are not "
                              "checked; " + ("replace the link with a copy without "
                                             "`node_modules` or `.git`" if v else
                                             "move `node_modules` and `.git` out of it")),
        "total": lambda r, v: (f"Claude Code runs {r} as code" + (f" (through {v})" if v else "")
                               + ", and its code folders hold too many entries in all for the "
                               "links in it to be checked: move the biggest linked skill out"),
        "wide": lambda r, v: (f"the link {v} leads to {r}, which holds your home folder or your "
                              "user config folder: Claude Code would run all of it as code; "
                              "remove the link"),
        "holds": lambda r, v: (f"the link {v} leads to {r}, which holds this project: Claude Code "
                               "may run anything in it as code, so every write here is asked "
                               "or refused; remove the link"),
    }
    for why in ("holds", "wide", "tree", "total"):
        group = [(r, v) for w, r, v in notes if w == why]
        if len(group) > 3:
            out.append(f"  WARNING: {len(group)} such links ({', '.join(v or r for r, v in group[:3])}"
                       f", ...): " + said[why](group[0][0], group[0][1]).split(": ", 1)[-1]
                       if why in ("wide", "holds") else
                       f"  WARNING: {len(group)} code folders hold too many entries for their "
                       "links to be checked (" + ", ".join(r for r, _v in group[:3])
                       + ", ...): move `node_modules` and `.git` out of them")
        else:
            out += [f"  WARNING: {said[why](r, v)}" for r, v in group]
    return out


def path_risk_lines(project: str, home: str) -> List[str]:
    """doctor's lines for `path_risks`, with this shell's PATH (Claude Code's, when it is started
    from here)."""
    from phiward import mcp_config
    lines = []
    for name, prog, n in path_risks(project, home, os.environ.get("PATH", "")):
        lines.append(f"  WARNING: MCP server {mcp_config.shown(name)} names "
                     f"`{mcp_config.shown(prog)}` without its path, and PATH has {n} folder(s) the "
                     "agent can write ahead of "
                     "the real one (a project's `.venv/bin`, a relative entry, a folder the "
                     "sandbox opens): Claude Code would start a file the agent put there with your "
                     "rights. Start Claude Code with those folders off PATH (deactivate the "
                     "project's environment), or give the entry the program's full path")
    return lines


def mode_report(project: str, home: str, cfg: "config.Config") -> List[str]:
    """Which mode this session is in and which layers are on."""
    from phiward import hidden
    if int(os.environ.get("PHIWARD_LAUNCH_DEPTH", "0") or 0) > 0:
        return ["  mode: B (launch): the whole tool runs in the kernel profile"]
    if wiring_state(project, home).wired:
        lines = ["  mode: A (a Claude Code session wired by the hook): Bash in Claude Code's "
                 "sandbox, file tools refused by the hook and permission rules (not the kernel)"]
    else:
        lines = ["  mode: none: no Claude Code settings file or plugin runs phiward here (run "
                 "`(cd ~ && phiward install claude --user --write)`); the layers below are what it would "
                 "have"]
    secret = [h for h in hidden.paths(None, cfg, session=True) if os.path.lexists(h)]
    # the same rule as the confinement check (`_covers`: both spellings, the path and where it
    # leads, as the sandbox resolves links: on macOS /tmp is /private/tmp)
    deny_read = claude_settings._paths(claude_settings.levels(project, home), project, home,
                                       None, "denyRead", deny=True)
    miss = [h for h in secret if not claude_settings._covers(deny_read, h)]
    lines.append(f"  hidden list in the sandbox: {len(secret) - len(miss)} of {len(secret)}"
                 + ("" if not miss else " (WARNING: run `(cd ~ && phiward install claude --user --write)` again)"))
    rules = set(_merged_rules(project, home))
    want = install.permission_rules(secret, home)
    have = sum(1 for r in want if r in rules)
    lines.append(f"  permission rules for the hidden list: {have} of {len(want)}"
                 + ("" if have == len(want) else " (WARNING: run `(cd ~ && phiward install claude --user --write)` again)"))
    kind = hidden.non_file_tickets()
    if kind:
        lines.append(f"  NOTE: your Kerberos tickets are kept by the system ({kind} cache, the "
                     "default on a Mac), not in a file, so a file list cannot hide them; a Bash "
                     "command in Claude Code's sandbox may reach them. Most people leave this. "
                     "To keep them in a file instead, run `export "
                     "KRB5CCNAME=FILE:/tmp/krb5cc_$(id -u)` before `kinit`, in each terminal")
    from phiward import mcp_config
    for why in mcp_config.problems(project, home):
        lines.append(f"  WARNING: an MCP config file cannot be read strictly, so its servers count "
                     f"as bare: {why}")
    lines += path_risk_lines(project, home)
    lines += code_root_lines(project, home)
    lines += settings_script_lines(project, home)
    lines += init_lines(project, home)
    servers = [(n, w) for n, w in mcp_servers(project, home) if not n.startswith("\0")]
    bare = [n for n, w in servers if not w]
    if servers:
        version = claude_settings.claude_version()
        if version is not None and version < mcp_config.MIN_SOURCE_VERSION:
            lines.append(
                f"  WARNING: Claude Code {claude_settings.version_text(version)} does not tell "
                "the hook which server a tool belongs to (from "
                f"{claude_settings.version_text(mcp_config.MIN_SOURCE_VERSION)} on): until you "
                "update it, a server of the project's `.mcp.json` counts as bare, and only your "
                "own config (`~/.claude.json`) can make a server wrapped")
    if servers and len(bare) < len(servers):
        lines.append("  NOTE: the hook trusts a server as wrapped only while it runs under a live "
                     "`phiward launch` (its record in ~/.phiward/launched): after `phiward mcp "
                     "wrap`, start Claude Code again")
        if os.path.isdir(os.path.join(home, ".phiward", "sessions")):
            lines.append("  NOTE: ~/.phiward/sessions is left from an older phiward and no longer "
                         "used; you may remove it: rm -r ~/.phiward/sessions")
    can, cannot = bare_split(project, home)
    if can:
        lines.append(f"  WARNING: {len(can)} MCP server(s) run with your full rights (not wrapped "
                     f"in `phiward launch --`): {', '.join(can)}. Wrap each in your own "
                     "terminal: " + "; ".join(f"`phiward mcp wrap {n}`" for n in can))
    if cannot:
        lines.append(f"  WARNING: {len(cannot)} MCP server(s) run with your full rights and cannot "
                     "be wrapped by phiward: " + "; ".join(f"{n} ({why})" for n, why in cannot)
                     + ". Their command tools may make only gateway calls.")
    if not bare and servers:
        lines.append(f"  MCP servers: {len(servers)}, all wrapped or remote")
    return lines


USAGE = "usage: phiward doctor [--verbose] [--show-paths | --headless]\n"
HELP = USAGE + """
Options:
  --verbose, -v  every check on its own line (by default, before Claude Code is wired, its
                 parts are one next step), and the detail counts
  --show-paths   also print the protected paths (by default only their counts), and the
                 project files the project scan found (masked, with line numbers)
  --headless     a short check before an unattended run (`claude -p`, an Agent SDK app, a
                 scheduled agent): exit 0 when the session would be guarded, 1 with the
                 reasons when not (docs/unattended.md); a NOTE (for example: no rule masks
                 subject identifiers) does not change the exit status
  -h, --help     show this help

Show the config in force and whether it loads, and what may turn the guards off: the
confinement backend, the sanitizer (and whether it masks subject identifiers), the broker, the pinned folders, Claude Code's settings and
MCP servers. On Linux it also says when `phiward launch` cannot start because the session
cannot have a network of its own (no network namespaces). Its section "launch (Mode B)" runs
the start checks of `phiward launch` in this folder, without starting anything, and names the
step for each (docs/refusals.md). It reads settings files and never writes them. Run it in the project folder.
The exit status is 1 when the config or the sanitizer cannot be used.

The project scan reads the project's files and file names for subject and sample IDs outside
the protected roots, with no time limit (`phiward launch` refuses such a project). It names
only the kinds and counts.

Its output may reach the model, so it shows paths only with --show-paths.
"""


_INSTALL = "(cd ~ && phiward install claude --user --write)"


def _pattern_version(cfg: config.Config) -> "Optional[tuple]":
    """The Claude Code version, asked for only where it changes a step: on macOS, with protected
    patterns (install writes their sandbox entries from 2.1.236 on)."""
    if sys.platform != "darwin" or not cfg.patterns:
        return None
    return claude_settings.claude_version()


def _after_install(project: str, home: str, cfg: config.Config,
                   hidden: list, version: "Optional[tuple]" = None) -> "Optional[claude_settings.Reason]":
    """Why the shell would still not be confined once `_INSTALL` has written the user wiring
    (with that reason's own step), or None: what stays is in a file install does not change (the
    project's or managed settings), in a setting install never removes, or in the config."""
    from phiward import install
    try:
        path = os.path.join(claude_settings.user_dir(home), "settings.json")
        want = install.merge(claude_settings._read(path) or {},
                             install.wiring(cfg, version=version))
        return claude_settings.confinement_reason(project, home, cfg.all_roots, cfg.patterns,
                                                  config.guard_files(), hidden=hidden,
                                                  user_data=want, version=version)
    except Exception as exc:  # noqa: BLE001 - doctor reports; a failure here only unfolds a line
        return claude_settings.Reason(f"cannot tell ({type(exc).__name__})",
                                      "run `phiward doctor --verbose`")


# the lines of doctor's Claude Code section whose only fix, before Claude Code is wired, is
# `_INSTALL`: one next step stands for them (`--verbose` prints them). A warning with news of
# its own (an older phiward's prefix, the network limit) is never folded.
_FOLDED = ("  WARNING: no Claude Code settings file runs phiward", "  mode: none:",
           "  hidden list in the sandbox:", "  permission rules for the hidden list:",
           "  WARNING: sandbox confines the shell: NO", "  NOTE: Claude Code's shell is not pinned",
           "  NOTE: no `--settings` file yet", "  WARNING: env.CLAUDE_CODE_DISABLE_FILE_MENTIONS is not")


def main(argv: List[str]) -> int:
    if argv[:1] in (["-h"], ["--help"]):
        sys.stdout.write(HELP)
        return 0
    unknown = [a for a in argv if a not in ("--headless", "--show-paths", "--verbose", "-v")]
    if unknown:
        sys.stderr.write(f"doctor: unknown option {unknown[0]}\n" + HELP)
        return 2
    if "--headless" in argv:
        return headless(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd(),
                        pathid.home())
    show = "--show-paths" in argv
    verbose = "--verbose" in argv or "-v" in argv
    if show and not sys.stdin.isatty():
        # the paths are the operator's to see: an agent tool has no terminal, and what it
        # runs reaches the model
        print("doctor: --show-paths prints the protected paths, so it runs only in your own "
              "terminal. Run `phiward doctor` without it here.", file=sys.stderr)
        return 2
    cwd = os.getcwd()
    home = pathid.home()
    cfg = config.load(cwd)
    from phiward import __version__
    print(f"phiward doctor (phiward {__version__})")
    print(f"config files: {', '.join(cfg.files) if cfg.files else 'none'}")
    if cfg.problem:
        print(f"PROBLEM: {cfg.problem}")
        if show and cfg.problem_detail:
            print(f"  detail: {cfg.problem_detail}")
        print("Every guarded action is refused until this is fixed.")
        return 1
    if cfg.ignored:
        print("NOTE: the repo config sets keys that only the user config may set; they are "
              f"ignored: {', '.join(cfg.ignored)}")
    print(f"protected roots: {len(cfg.roots)}, patterns: {len(cfg.patterns)}" + (
        f", derived (cache, .git around a root): {len(cfg.derived_roots)}, "
        f"unresolved: {cfg.unresolved}" if verbose else ""))
    if show:
        for p in cfg.roots + cfg.patterns + cfg.derived_roots:
            print(f"  {p}")
    if any(r.endswith(("/.git", ".git")) for r in cfg.derived_roots):
        print("NOTE: a protected root sits in a git work tree; its .git is protected too, so the "
              "agent cannot use git in that repository.")
    from phiward import confine
    why = confine.self_test()
    print(("" if why is None else "WARNING: ") + f"confinement: {confine.backend() or 'none'}: "
          + ("ok" if why is None else f"NOT WORKING: {why}"))
    if not cfg.has_protected_paths:
        # nothing is set up yet: the one step is setup (it writes the config, wires Claude Code
        # and starts the broker); the wiring and broker lines would point the other way
        print("No protected paths are configured yet, so phiward protects nothing. Next step: "
              "`(cd ~ && phiward setup)` (it writes the config, wires Claude Code and starts the "
              "broker); then run `phiward doctor` again.")
        from phiward import broker as _broker
        if not _broker.read_status(config.spool_dir()):
            # setup cannot fix phiward's own install: its WARNINGs still show
            for line in install_lines():
                print(line)
            return 1  # nothing else applies yet; a running broker is reported below
    from phiward.sanitize import Sanitizer, SanitizerError
    try:
        Sanitizer.from_config(cfg)
        print(f"sanitizer: ok (packs: {', '.join(cfg.packs) or 'default'})")
        for line in pack_lines(cfg):
            print(line)
    except SanitizerError as exc:
        print(f"PROBLEM: the sanitizer cannot start: {exc}")
        return 1
    if _subjects_unmasked(cfg):
        print(SUBJECTS_WARNING)
    for line in masking_lines(cfg, cwd):
        print(line)
    for line in project_scan_lines(cfg, cwd, show):
        print(line)
    rel = None
    if cfg.has_protected_paths:
        from phiward import paths
        rel = paths.ProtectedSet(cfg.all_roots, cfg.patterns).relation(cwd)
    if rel:
        print(relation_line(rel))
    from phiward import broker
    spool = config.spool_dir()
    where = broker.running(spool)
    print(("broker: running" + (f" ({where})" if where.startswith("on ") else "")) if where else
          ("WARNING: broker: NOT RUNNING: gateway calls (phiward run|copy) fail until the operator "
                        "starts `phiward broker` in a terminal outside the agent, or its login "
                        "service (`(cd ~ && phiward broker --service --write)`)"))
    elsewhere = None if broker._alive(spool) else broker.other_spool(spool)
    if elsewhere:
        print(f"WARNING: a broker is running with the spool {elsewhere}; this shell uses {spool} "
              "(check PHIWARD_SPOOL on both sides)")
    from phiward import service
    dropped = service.dropped_path_entries(os.environ.get("PATH", ""))
    if dropped:
        print(f"NOTE: the broker does not search {len(dropped)} folder(s) of this PATH (relative, "
              "writable by others, inside a project, or a folder the agent's sandbox may write: "
              "a temp folder, or one in allowWrite); programs there are 'not on the "
              "broker's PATH'" + (": " + ", ".join(dropped[:5]) if show else
                                  " (`--show-paths` lists them)"))
    sf = service.service_file()
    try:
        with open(sf, encoding="utf-8") as fh:
            unit = fh.read()
    except OSError:
        unit = ""
    if unit and service.log_folder() not in unit:
        print("WARNING: the broker's login service was written by an older phiward and keeps no "
              "log: run `(cd ~ && phiward broker --service --write)` again")
    st = broker.read_status(spool)
    if st and st.get("config") != config.user_config_path():
        print(f"WARNING: the broker uses the user config {st.get('config', '(none)')}; this shell "
              f"uses {config.user_config_path()} (check PHIWARD_CONFIG on both sides)")
    elif st and (st.get("cache") != cfg.cache_dir or set(st.get("roots", [])) != set(cfg.user_roots)):
        print("WARNING: the broker uses another cache folder or roots than this shell (check "
              "XDG_CACHE_HOME on both sides, and restart the broker after a config change)")
    for line in broker_path_lines(cfg, st):
        print(line)
    from phiward import fsinfo, pin
    if cfg.has_protected_paths:
        pinned = set(pin.read_pins())
        found = set(pin.pinnable(cfg))
        if not os.path.exists(pin.pins_path()):
            print("NOTE: no derived protected folders are pinned yet; run `phiward pin` in "
                  "your own terminal (it records the git folders, snapshots and other mounts "
                  "found now, so a file the agent plants later cannot hide them)")
        elif not pin.pins_readable():
            print("WARNING: pinned.toml cannot be read; nothing is pinned (run phiward pin)")
        else:
            if found - pinned:
                print(f"WARNING: {len(found - pinned)} derived protected folder(s) are found now "
                      "but not pinned; check them (doctor --show-paths) and run `phiward pin`")
            if pinned - found:
                print(f"WARNING: {len(pinned - found)} folder(s) are pinned but not found now; "
                      "check them (doctor --show-paths) and drop wrong ones with `phiward pin`")
            if show:
                for d in sorted(found - pinned):
                    print(f"  found, not pinned: {d}")
                for d in sorted(pinned - found):
                    print(f"  pinned but not found: {d}")
    respelled = [r for r in cfg.user_roots if os.path.exists(r) and
                 pathid.canon(r) != os.path.realpath(r)]
    if respelled:
        print(f"WARNING: {len(respelled)} root(s) are written in another spelling than the file "
              "system's own (letter case, Unicode form or /System/Volumes/Data); phiward "
              "covers both, but write the canonical spelling (doctor --show-paths)")
        if show:
            for r in respelled:
                print(f"  {r} -> {pathid.canon(r)}")
    hl = fsinfo.hardlinked_count(cfg.roots, cfg.inventory_limit) if cfg.roots else 0
    if hl:
        print(f"WARNING: {hl} protected file(s) have other hard links; path rules cannot cover "
              "those other names (docs/threat-model.md, known gap 9)")
    if any(os.path.basename(d) in fsinfo.SNAPSHOT_NAMES + tuple(cfg.snapshot_names)
           for d in cfg.derived_roots):
        print("NOTE: snapshot folders next to or above a root are protected too (derived roots)")
    print("NOTE: protected roots are read only for gateway commands; they write only in "
          "[broker] write_to folders (which may sit inside a root)")
    print(f"grants: write_to folders: {len(cfg.write_to)}"
          + (f" (skipped: {cfg.write_to_missing} that do not exist yet)" if cfg.write_to_missing else "")
          + (f" (skipped: {cfg.write_to_linked} reached through a link; name the real folder)"
             if cfg.write_to_linked else "")
          + (f" (skipped: {cfg.write_to_claude} that hold a .claude folder)"
             if cfg.write_to_claude else "")
          + f", network: {'yes' if cfg.net else 'no'}, copy remotes: {len(cfg.remotes)}")
    folders = [os.path.normpath(r.split(":", 1)[-1]) for r in cfg.remotes]
    bare = [f for f in folders if not any(
        f == x or f.startswith(x.rstrip("/") + "/") for x in cfg.remote_roots)]
    if bare:
        print(f"WARNING: {len(bare)} copy remote(s) are not entirely under [remote] roots: a push "
              "goes only under a remote root (what lands there is masked in remote output), so a "
              "push to the rest of such a remote is refused. Add the folder to [remote] roots of "
              "your user config (`(cd ~ && phiward setup)` does it for a new remote).")
    if show:
        for p in cfg.write_to:
            print(f"  write_to: {p}")
    if cfg.command_lists:
        n = min(len(x) for x in cfg.command_lists)
        print(f"programs gateway commands may run: only those in [broker] commands "
              f"({n} listed)")
        names = {os.path.basename(e.rstrip("/")) for lst in cfg.command_lists for e in lst
                 if not e.startswith("@")}
        runs_code = sorted(n for n in names if config.runs_other_code(n))
        if runs_code:
            print(f"WARNING: {len(runs_code)} listed program(s) can run other code (an "
                  "interpreter, a shell, git aliases, find -exec, make and the like): with "
                  "them, code the agent writes can run again. List your own scripts instead")
        home = pathid.home()
        from phiward import broker
        mine = [p for p in broker.listed_programs(cfg, broker.command_env().get("PATH", ""))
                if p.startswith(home.rstrip("/") + "/")]
        if mine:
            print(f"NOTE: {len(mine)} listed program(s) are in your home folder (conda, "
                  "~/.local/bin): `(cd ~ && phiward install claude --user --write)` protects them from "
                  "agent writes, and the broker runs them only as you approved them. After you "
                  "update one, check it and run `phiward pin`, then restart the broker")
    if cfg.command_lists:
        from phiward import pin
        bad = [line for line in pin.describe(cfg) if line.endswith(")")]
        if pin.unapproved(cfg):
            print(f"WARNING: {len(pin.unapproved(cfg))} listed program(s) are not approved as "
                  "the broker finds them: gateway commands are refused until you check them "
                  "and run `phiward pin` in your own terminal, then restart the broker:")
            for line in bad[:20]:
                print(f"  {line}")
    else:
        print("WARNING: programs gateway commands may run: any (no [broker] commands list). Code "
              "that the agent writes can run on protected data and print it encoded. Before real "
              "patient data, run `(cd ~ && phiward setup)` in your own terminal and choose 1, or list your "
              "programs (docs/configuration.md)")
    if cfg.ssh_config:
        print("copy: ssh config file " + ("set" if os.path.isfile(cfg.ssh_config) else
                                          "set, but WARNING: it does not exist"))
    if cfg.write_to or cfg.net or cfg.remotes:
        print("NOTE: a grant gives code the agent chooses that capability. Against an agent you "
              "do not trust, leave write_to and remotes empty and net false.")
    # the operator runs doctor in the project folder; a hook gets $CLAUDE_PROJECT_DIR
    project = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
    SELFCHECK.clear()  # filled by the self-check: the launch section asks no second time
    for line in install_lines():
        print(line)
    version = claude_settings.claude_version()  # read once, for mentions and launch
    print("Claude Code:")
    # before Claude Code is wired, each part's fix is the same command: one next step (each
    # part is behind --verbose)
    fold = not verbose and not wiring_state(project, home).wired
    if fold:
        print(f"  WARNING: Claude Code is not wired to phiward yet. Next step, in your own "
              f"terminal: `{_INSTALL}` (the hook, the sandbox and the permission rules), then "
              "run doctor again. `phiward doctor --verbose` lists each part.")

    def say(line="", *a, **k):
        if fold and line.startswith(_FOLDED):
            return
        print(line, *a, **k)

    for line in claude_report(project, home):
        say(line)
    redirect = claude_settings.project_redirects(project, home)
    if redirect:
        say(f"  WARNING: {claude_settings.redirect_text(redirect)}: the hook refuses every "
              "tool call until you fix that (it could change what the hook runs or reads).")
    for r in claude_settings.git_redirects(project, home):
        say("  WARNING: " + GIT_REDIRECT.format(r) + ".")
    loader = claude_settings.project_loader_keys(project, home)
    if loader:
        say("  NOTE: this project's Claude Code settings set " + ", ".join(
            "env." + k for k in loader) + ": the hooks clear them before phiward starts, but the "
              "shell that starts a hook loads them first (docs/threat-model.md).")
    clean = clean_start_problem()
    if clean:
        say(f"  WARNING: {clean}.")
    for line in sandbox_needs():
        say(line)
    for line in launch_network_lines():
        say(line)
    for line in launch_settings_report():
        say(line)
    for line in mentions_report(project, home, version):
        say(line)  # folded with the rest until Claude Code is wired: one next step
    if cfg.has_protected_paths and not cfg.problem:
        for line in mode_report(project, home, cfg):
            say(line)
    if cfg.has_protected_paths:
        from phiward import hidden as _hidden
        hidden_now = [h for h in _hidden.paths(None, cfg, session=True) if os.path.lexists(h)]
        version = _pattern_version(cfg)
        reason = claude_settings.confinement_reason(
            project, home, cfg.all_roots, cfg.patterns, config.guard_files(), hidden=hidden_now,
            version=version)
        ok, why_not = reason is None, reason.text if reason else ""
        # folded only when the next step fixes it: a cause install does not fix is shown even
        # before Claude Code is wired
        still = None if ok else _after_install(project, home, cfg, hidden_now, version)
        fixed = still is None
        # one fix, the right one: install when it would confine the shell; otherwise the step of
        # what would stay after it (the same step the hook's refusal gives)
        fix = ("" if ok else f". To fix it: {claude_settings.INSTALL_STEP}, or use `phiward "
               "launch`." if fixed else
               f". To fix it: {still.step}" + ("" if still.text == why_not else
                                                 f" ({still.text})") + ".")
        show = say if ok or not fold or fixed else print
        # not confined only by excludedCommands: the hook text-checks every call (b1), as its
        # own reading (`shell_reason`) says
        where = "" if ok or claude_settings.shell_reason(
            project, home, cfg.all_roots, cfg.patterns, config.guard_files(),
            hidden=hidden_now) is not None else claude_settings.excluded_step(project, home)[0]
        show("  sandbox confines the shell: yes" if ok else
             f"  WARNING: sandbox confines the shell: NO ({why_not})" +
             (f"; excludedCommands is not empty ({where}): the hook checks the text of every "
              "command (as with [shell] best_effort), and refuses a path it cannot see"
              if where else
              "; for shell commands only the hook's text check is left, which is best effort"
              if cfg.shell_best_effort else
              "; so the hook refuses shell commands except gateway calls") + fix)
        if claude_settings._env_value(project, home, None, "CLAUDE_CODE_SHELL_PREFIX")[0] == \
                config.shell_prefix_path():
            say("  WARNING: env.CLAUDE_CODE_SHELL_PREFIX names the shell prefix of an older "
                  "phiward, which is gone: every shell command fails. Run `phiward install claude "
                  "--user --write` again; it removes the setting.")
        say("  Claude Code's shell is /bin/bash: yes"
              if claude_settings.bash_pinned(project, home) else
              "  NOTE: Claude Code's shell is not pinned to /bin/bash (env.CLAUDE_CODE_SHELL); "
              "the hook reads commands as bash. `(cd ~ && phiward install claude --user --write)` pins it.")
        blocks = [k for k in ("blockReadsOutsideWorkingDirectories", "denyInsteadOfPrompting")
                  if claude_settings._first(claude_settings.levels(project, home),
                                            "permissions", k) is True]
        say("  read blocking outside the project: " + (", ".join(blocks) or
              "off (optional: `(cd ~ && phiward install claude --user --block-outside-reads --write)`)"))
        if cfg.shell_best_effort:
            say("  WARNING: [shell] best_effort is on: a shell call that Claude Code's sandbox "
                  "does not confine gets only the hook's text check, which is best effort "
                  "(docs/threat-model.md). Turn it off once the sandbox confines the shell.")
        else:
            say("  shell calls outside Claude Code's sandbox: refused (there only the gateway, "
                  "`doctor` and `check` run)")
        allow = claude_settings._merged_list(claude_settings.levels(project, home), "sandbox",
                                             "filesystem", "allowWrite")
        if ok and not any(os.path.normpath(a.replace("~", home, 1)) in (spool, os.path.dirname(spool))
                          for a in allow):
            say("  NOTE: sandbox.filesystem.allowWrite does not hold the spool folder; "
                  "gateway calls cannot reach the broker from the sandbox.")
        if ok:
            for line in package_cache_lines():
                say(line)
    for line in network_report(project, home, cfg):
        say(line)
    print("launch (Mode B), for a session started with `phiward launch` here:")
    for line in launch_report(cwd, home, cfg, version=version,
                              installed=SELFCHECK.get("installed"), show=show):
        print(line)
    return 0


def relation_line(rel: str) -> str:
    """The WARNING for a folder inside or above a protected path; above one, Grep and Glob from
    it are refused too (they would list the root), so it names the way: a subfolder."""
    from phiward import paths
    return (f"WARNING: this folder is {rel} a protected path: its commands are refused or denied, "
            "except gateway calls (phiward run|copy). Run the agent in a project folder." +
            (" Grep and Glob from this folder are refused too: give them a subfolder that holds "
             "no protected folder." if rel == paths.ABOVE else ""))


def broker_path_lines(cfg: config.Config, status: Dict[str, Any]) -> List[str]:
    """A WARNING for the bare names of `[broker] commands` that the running broker's PATH (its
    status file) does not find: `phiward run` refuses them as "not on the broker's PATH"."""
    if not status or not cfg.command_lists or not isinstance(status.get("path"), str):
        return []
    from phiward import broker
    missing = sorted({p[len("missing:"):] for p in broker.listed_programs(cfg, status["path"])
                      if p.startswith("missing:")})
    if not missing:
        return []
    return [f"WARNING: {len(missing)} program(s) of [broker] commands are not on the broker's "
            "PATH, so `phiward run` refuses them: " + ", ".join(f"`{n}`" for n in missing[:10])
            + ". The operator starts the broker again from a terminal where they work (for "
            "example after `conda activate`), or lists them by their full path."]


CACHE_NOTE = (
    "NOTE: Claude Code's sandbox keeps the package caches outside the project read-only (pip: "
    "~/.cache/pip, or ~/Library/Caches/pip on macOS; uv: ~/.cache/uv; npm: ~/.npm), so an "
    "install that writes its cache fails with 'Operation not permitted'. Use `pip install "
    "--no-cache-dir`, or set PIP_CACHE_DIR, UV_CACHE_DIR and npm_config_cache to folders under "
    "$TMPDIR. phiward adds no allowWrite for them: a cache a session writes is code a later run "
    "executes.")


def package_cache_lines() -> List[str]:
    """Mode A: the package caches the sandbox keeps read-only, and the way around (docs only:
    no allowWrite, decided)."""
    return ["  " + CACHE_NOTE]


RUNS_LATER_NOTE = (
    "NOTE: in a launch session the files other tools run later are read-only, at any depth: "
    ".claude, .vscode, .idea, .Rprofile, .Renviron, .mcp.json and the like (a write gets "
    "'Operation not permitted'). Edit them in a plain terminal, or `phiward carryover add` for "
    "Claude Code's own files; run renv::init() once outside launch.")


def launch_report(project: str, home: str, cfg: config.Config,
                  env: Optional[Dict[str, str]] = None, platform: str = sys.platform,
                  version: Optional[Tuple[int, int, int]] = None,
                  installed: Optional[bool] = None, show: bool = False) -> List[str]:
    """`phiward launch` started in `project`: what its start would refuse, from the checks launch
    itself runs (wholetool), and what a session there cannot do. It starts nothing and asks
    nothing again: Claude Code's build is judged from its files, a native binary's version is
    `version` (what doctor read; when None, a NOTE says only launch can tell), and whether
    phiward is installed is `installed` (doctor's self-check; None: not known, no line). A PATH
    entry is named relative to the project unless `show`."""
    import shutil
    from phiward import wholetool as wt
    env = dict(os.environ) if env is None else env
    real = os.path.realpath(project)
    out: List[str] = []

    def refused(why: str) -> None:
        out.append(f"  WARNING: launch would refuse to start here: {why}.")

    if not cfg.has_protected_paths:
        refused(wt.NO_PATHS)
    why = wt._project_problem(real, env)
    if why:
        refused(wt.PROJECT_STEP.format(why))
    entry = wt._path_entry_inside(real, env)
    if entry:
        shown = entry if show else os.path.relpath(os.path.realpath(entry), real)
        refused(wt._path_step(entry, env, shown))
    for rel in wt.LINK_REFUSED:
        if os.path.islink(os.path.join(real, rel)):
            refused(wt.LINK_STEP.format(rel))
    tool = shutil.which("claude", path=env.get("PATH") or os.defpath)
    if tool:
        asked: List[str] = []

        def known(real_tool: str, _env: Any) -> Optional[Tuple[int, int, int]]:
            asked.append(real_tool)  # a native binary: its version is the one doctor read
            return version or claude_settings.VERSION_HOOK_ARGS
        why = wt.claude_version_problem(tool, wt.write_places(real, env), env, ask=known)
        if why:
            refused(f"--tool claude: {why}")
        elif asked and version is None:
            out.append("  NOTE: launch --tool claude: the version of Claude Code is unknown "
                       "here: only launch can tell (it asks the native binary at the start).")
    if env.get("ANTHROPIC_BASE_URL"):
        why = wt.base_url_refusal(env["ANTHROPIC_BASE_URL"], cfg.launch_private_networks)
        if why:
            refused(why)
    if platform.startswith("linux"):
        abi = wt.landlock_abi()
        if abi >= wt.UNIX_ABI:
            out.append(f"  launch on Linux: Landlock ABI {abi}: a session reaches only the unix "
                       "sockets it makes itself")
        else:
            out.append(f"  NOTE: launch on Linux (Landlock ABI {abi}, below {wt.UNIX_ABI}): "
                       "--tool claude runs in the inner mode, where Claude Code's own sandbox "
                       "blocks unix sockets. There launch refuses your own --settings (put them "
                       "in managed settings or launch's trusted copy), a `--` among Claude Code's "
                       "arguments (put the prompt last), and Claude Code commands such as `claude "
                       "mcp` (run those outside launch).")
            why = wt.inner_sandbox_reason(real, env)
            if why:
                refused(f"--tool claude: {why}")
    if not any(env.get(k) for k in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY",
                                    "ANTHROPIC_AUTH_TOKEN")):
        out.append(f"  NOTE: {wt.LOGIN_NOTE}.")
    out.append("  " + RUNS_LATER_NOTE)
    if installed is False and env.get("PHIWARD_DEV") != "1":
        out.append("  NOTE: this phiward is a source checkout or an editable install, which "
                   "launch refuses: install it with uv tool or pipx, or set PHIWARD_DEV=1 to "
                   "start from a checkout.")
    return out


def clean_start_problem() -> Optional[str]:
    """Why `phiward`, started by name as the plugin and project hooks start it (after the
    variables are cleared: the package's `clean-exec.sh`), does not start, or None (also when it
    is not on PATH: that is reported on its own). A phiward whose Python needs PYTHONPATH or
    LD_LIBRARY_PATH (a module Python, a checkout) stops there, and every tool call is refused."""
    import shutil
    import subprocess
    if not shutil.which("phiward") or not os.access(install.CLEAN_EXEC, os.X_OK):
        return None
    try:
        r = subprocess.run([install.CLEAN_EXEC, "phiward", "--help"],
                           capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"phiward could not be started the way the hooks start it ({type(exc).__name__})"
    if r.returncode == 0:
        return None
    gone = sorted(k for k, v in os.environ.items() if install.cleared(k, v))
    return ("phiward does not start once the hooks clear " +
            (", ".join(gone) if gone else "the Python and loader variables") +
            f" (exit {r.returncode}), so the hooks refuse every tool call. Install phiward with "
            "`uv tool install` or `pipx`, whose Python needs none of them (docs/setup.md)")


GIT_REDIRECT = ("git takes this repository's config and hooks from a folder the agent can write "
                "({}): git, which Claude Code runs outside its sandbox, would run what the agent "
                "puts there. If you did not set this up, remove that file and the folder it "
                "names")


def headless_problems(project: str, home: str) -> List[str]:
    """Why an unattended Claude Code run in `project` would not be guarded, or []."""
    from phiward import broker, hidden
    cfg = config.load(project)
    if cfg.problem:
        return [f"the phiward config cannot be used: {cfg.problem}"]
    if not cfg.has_protected_paths:
        return ["no protected paths are configured: run `(cd ~ && phiward setup)` in your own "
                "terminal"]
    out: List[str] = [f"{t} is missing: the hooks need it to clear the Python and loader "
                      "variables, so they refuse every call" for t in install.CLEAN_TOOLS
                      if not os.access(t, os.X_OK)]
    clean = clean_start_problem()
    if clean:
        out.append(clean)
    redirect = claude_settings.project_redirects(project, home)
    if redirect:
        out.append(claude_settings.redirect_text(redirect) + " (the hook refuses every call)")
    out += [GIT_REDIRECT.format(r) for r in claude_settings.git_redirects(project, home)]
    wiring = wiring_state(project, home)
    out += wiring.problems
    out += [ln.strip()[len("WARNING: "):] for ln in code_root_lines(project, home)]
    out += [ln.strip()[len("WARNING: "):] for ln in settings_script_lines(project, home)
            if ln.strip().startswith("WARNING: ")]
    if wiring.wired and not wiring.isolated:
        out.append("the user settings do not run the isolated hook on every tool group; "
                   "the plugin's and project hooks run phiward by name, so a project's env.PATH "
                   "can replace them. Run `(cd ~ && phiward install claude --user --write)`")
    secret = [h for h in hidden.paths(None, cfg, session=True) if os.path.lexists(h)]
    rules = set(_merged_rules(project, home))
    missing = [r for r in install.permission_rules(list(cfg.all_roots) + secret, home)
               if r not in rules]
    if missing:
        out.append(f"{len(missing)} permission deny rule(s) for protected and hidden paths are "
                   "missing (the file tools' second check)")
    reason = claude_settings.confinement_reason(project, home, cfg.all_roots, cfg.patterns,
                                                config.guard_files(), hidden=secret,
                                                version=_pattern_version(cfg))
    if reason is not None:
        out.append(f"the shell is not confined by Claude Code's sandbox ({reason.text}); to fix "
                   f"it: {reason.step}")
    out += [x.strip().replace("WARNING: ", "") for x in sandbox_needs()]
    can, cannot = bare_split(project, home)
    if can:
        out.append(f"{len(can)} MCP server(s) run with your full rights, unwrapped: "
                   + ", ".join(can) + " (`phiward mcp wrap NAME` in your own terminal)")
    if cannot:
        out.append(f"{len(cannot)} MCP server(s) run with your full rights and cannot be wrapped: "
                   + "; ".join(f"{n} ({why})" for n, why in cannot)
                   + " (their command tools may make only gateway calls)")
    if not broker.running(config.spool_dir()):
        out.append("the broker is not running (gateway calls would fail)")
    from phiward import phicheck
    out += [f"masking check: {f}" for f in phicheck.check(cfg, project).failed]
    out += project_scan_problems(cfg, project)
    return out


SUBJECTS_WARNING = (
    "WARNING: your user config enables no pack that masks subject or sample identifiers. The "
    "gateway masks the names of entries under the protected roots, and the genomics pack masks "
    "sequence file names, read names and loci; a patient, sample or donor ID inside a file, or in "
    "a name outside the roots, reaches the model provider. In your user config, add a pack for "
    "your institution's forms ([sanitize] packs, for example \"msk\"), your own [sanitize] "
    "patterns or names_from, or record that your data has none: [sanitize] subjects = \"none\" "
    "(a repo's .phiward.toml cannot do this). `(cd ~ && phiward setup)` asks.")


def masking_lines(cfg: config.Config, cwd: str) -> List[str]:
    """The masking check (phicheck): the ok line, or a WARNING for each failure; a NOTE for each
    rule or pattern it does not test. A failure does not change doctor's exit status."""
    from phiward import phicheck
    r = phicheck.check(cfg, cwd)
    return ([r.summary] if not r.failed else []) + \
        [f"WARNING: masking check: {f}." for f in r.failed] + \
        [f"NOTE: masking check: {n}." for n in r.notes]


def project_scan_lines(cfg: config.Config, project: str, show: bool) -> List[str]:
    """The project scan (projectscan) with no time limit: counts and kinds; with `show`, the
    masked path, line number and kinds of each file found. A finding or an error is a WARNING,
    and does not change doctor's exit status."""
    from phiward import projectscan
    why = projectscan.place_problem(cfg, project)
    if why:
        return ["project scan: skipped (not a project folder)"]
    r = projectscan.scan(cfg, project)
    if r.error:
        return [f"WARNING: {r.error}."]
    if r.off:
        return ["project scan: off (no rule for subject or sample identifiers)"]
    out = [f"project scan: ok ({r.files} files)"] if not r.hits else [
        f"WARNING: project scan: found {projectscan.found_text(r)}; `phiward doctor "
        "--show-paths` in your own terminal lists them."]
    if r.hits and show:
        out += [f"  {path}: " + (f"line {n}" if n else "name") + f": {', '.join(kinds)}"
                for path, n, kinds in r.hits[:projectscan.SHOWN]]
        if len(r.hits) > projectscan.SHOWN:
            out.append(f"  ... and {len(r.hits) - projectscan.SHOWN} more")
    if r.skipped:
        out.append(f"NOTE: project scan: not read: {projectscan.skipped_text(r)}.")
    return out


def project_scan_problems(cfg: config.Config, project: str) -> List[str]:
    """`--headless`: the project scan within launch's time budget; a finding or an error is a
    problem (counts and kinds only), a scan that stops at the budget is not."""
    from phiward import projectscan
    if projectscan.place_problem(cfg, project):
        return []
    r = projectscan.scan(cfg, project, projectscan.deadline())
    if r.error:
        return [r.error + " (run phiward doctor)"]
    if r.hits:
        return [f"the project scan found {projectscan.found_text(r)} (`phiward doctor "
                "--show-paths` in your own terminal lists them)"]
    return []


def _subjects_unmasked(cfg: config.Config) -> bool:
    """Protected data, no record that it names no subjects, and nothing in the user config that
    masks subject identifiers. A pack file that cannot be read counts as not masking."""
    if not cfg.has_protected_paths or cfg.sanitize_subjects == "none":
        return False
    from phiward.sanitize import SanitizerError, masks_subjects
    try:
        return not masks_subjects(cfg)
    except SanitizerError:
        return True


def headless_notes(project: str) -> List[str]:
    """What an unattended run should know but that does not stop it."""
    cfg = config.load(project)
    if cfg.problem or not _subjects_unmasked(cfg):
        return []
    return ["NOTE: your user config enables no pack that masks subject or sample identifiers "
            "inside files; `phiward doctor` says how to add one, or record [sanitize] subjects = "
            "\"none\". It does not stop the run."]


def headless(project: str, home: str) -> int:
    problems = headless_problems(project, home)
    notes = headless_notes(project)
    if not problems:
        print("headless: ready (wired, sandboxed, broker running). Run `claude -p` "
              "without --bare; an Agent SDK app loads the user settings or passes "
              "`phiward install claude --json` as its settings.")
        for n in notes:
            print(f"  {n}")
        return 0
    print("headless: NOT READY")
    for p in problems:
        print(f"  - {p}")
    for n in notes:
        print(f"  {n}")
    return 1


def sandbox_needs(platform: str = sys.platform, run=None) -> List[str]:
    """What Claude Code's own sandbox needs on Linux (bubblewrap 0.4 or newer, and socat). With
    failIfUnavailable, a missing one stops Claude Code at start."""
    import re
    import shutil
    import subprocess
    if not platform.startswith("linux"):
        return []
    from phiward import service
    out = []
    # only on PATH folders the agent cannot write (as the broker's service looks): a planted
    # `bwrap` must not answer for the real one, nor run here
    safe = ":".join(service._safe_path_entries(os.environ.get("PATH", "")))
    found = {p: shutil.which(p, path=safe) for p in ("bwrap", "socat")}
    missing = [p for p, f in found.items() if f is None]
    if missing:
        out.append(f"  WARNING: Claude Code's sandbox needs {' and '.join(missing)} on the PATH: "
                   "with sandbox.failIfUnavailable (which install sets) Claude Code stops at "
                   "start without it. Install it with the system's package manager, or without "
                   "admin rights in a conda environment (`socat` from conda-forge), and put its "
                   "bin folder on the PATH before you start Claude Code (not a folder the "
                   "agent's sandbox may write, such as one in allowWrite; sandbox.socatPath "
                   "and bwrapPath are read only from managed settings).")
    if "bwrap" not in missing:
        run = run or (lambda cmd, **k: subprocess.run(cmd, **k))
        try:
            r = run([found["bwrap"], "--version"], capture_output=True, text=True, timeout=10)
            m = re.search(r"(\d+)\.(\d+)", r.stdout or "")
        except (OSError, subprocess.SubprocessError):
            m = None
        if not m or (int(m.group(1)), int(m.group(2))) < (0, 4):
            out.append("  WARNING: Claude Code's sandbox needs bubblewrap 0.4 or newer; `bwrap "
                       "--version` gave " + (m.group(0) if m else "nothing it could read") + ".")
    return out


def launch_network_lines(platform: str = sys.platform, problem: Optional[str] = None) -> List[str]:
    """Linux: a WARNING when `phiward launch` would refuse because bubblewrap cannot give the
    session a network namespace of its own (its network goes only through phiward's proxy)."""
    import shutil
    if not platform.startswith("linux"):
        return []
    if problem is None:
        bwrap = shutil.which("bwrap", path="/usr/bin:/bin")  # the one launch runs
        if not bwrap:
            return []  # sandbox_needs says bwrap is missing
        problem = confine.net_namespace_problem(bwrap)
    if not problem:
        return []
    return [f"  WARNING: `phiward launch` cannot start here: a session needs a network of its "
            f"own, and {problem}. Ask the admins to allow user network namespaces, or use "
            "Mode A (docs/launch.md)."]


def launch_settings_report() -> List[str]:
    """The `claude --settings` file that makes the sandbox admin-required (install writes it)."""
    path = config.launch_settings_path()
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return [f"  NOTE: no `--settings` file yet: `(cd ~ && phiward install claude --user --write)` writes "
                f"{path}; start Claude Code with `claude --settings {path}`, so a repository's "
                "settings cannot loosen the sandbox."]
    except (OSError, ValueError):
        data = None
    sb = data.get("sandbox") if isinstance(data, dict) else None
    want = install.LAUNCH_SETTINGS["sandbox"]
    env = data.get("env") if isinstance(data, dict) else None
    if not isinstance(sb, dict) or any(sb.get(k) != v for k, v in want.items()) or \
            not isinstance(env, dict) or env.get(install.MENTIONS_OFF) != "1":
        return [f"  WARNING: {path} does not set " + ", ".join(
            [f"sandbox.{k}: {json.dumps(v)}" for k, v in want.items()] +
            [f"env.{install.MENTIONS_OFF}: \"1\""]) +
            ". Run `(cd ~ && phiward install claude --user --write)` again."]
    return [f"  --settings file: {path}. Start Claude Code with `claude --settings {path}`; "
            "doctor cannot tell whether this session was started with it."]


# Claude Code knows the setting from 2.1.299; below 2.1.295 it also has no `onFailure` for hooks
MENTIONS_MIN_VERSION = (2, 1, 299)
MENTIONS_PROBLEM_BELOW = (2, 1, 295)


_UNREAD = object()


def mentions_report(project: Optional[str], home: str, version: Any = _UNREAD) -> List[str]:
    """`@path` mentions: with them on, a mention puts a file's text into the prompt without a
    tool call phiward's hook sees. The user (or managed) settings turn them off with
    `env.CLAUDE_CODE_DISABLE_FILE_MENTIONS` (Claude Code v2.1.299+, and ignored in a project's
    settings, so a project's value is not read). `version` is Claude Code's, when the caller has
    read it already."""
    trusted = [lv for lv in claude_settings.levels(project, home) if lv[0] in ("managed", "user")]
    value = claude_settings._first(trusted, "env", install.MENTIONS_OFF)
    out: List[str] = []
    if value != "1":
        out.append(f"  WARNING: env.{install.MENTIONS_OFF} is not \"1\" in your user settings: an "
                   "@-mention puts a file's text into the prompt without a tool call the hook "
                   "sees. Run `(cd ~ && phiward install claude --user --write)`.")
    if version is _UNREAD:
        version = claude_settings.claude_version()
    if version is not None and version < MENTIONS_MIN_VERSION:
        word = "PROBLEM" if version < MENTIONS_PROBLEM_BELOW else "WARNING"
        out.append(f"  {word}: Claude Code {claude_settings.version_text(version)} does not know "
                   f"env.{install.MENTIONS_OFF} (from "
                   f"{claude_settings.version_text(MENTIONS_MIN_VERSION)} on): an @-mention still "
                   "puts a file's text into the prompt without a tool call the hook sees. Update "
                   "Claude Code.")
    return out


def network_report(project: Optional[str], home: str, cfg: config.Config) -> List[str]:
    """The network of shell commands in Claude Code sessions. Claude Code honours
    `strictAllowlist` only from the user and managed settings, and then ignores a repository's
    allowed domains; the allowlist is `allowedDomains` plus `WebFetch(domain:...)` allow rules."""
    trusted = [lv for lv in claude_settings.levels(project, home) if lv[0] in ("managed", "user")]
    strict = claude_settings._first(trusted, "sandbox", "network", "strictAllowlist") is True
    if not strict:
        if cfg.network_limit:
            return ["  WARNING: [network] limit is set, but Claude Code's user settings do not set "
                    "sandbox.network.strictAllowlist: shell commands reach any host. Run "
                    "`(cd ~ && phiward install claude --user --write)`."]
        return ["  network for shell commands: open (any host; see [network] in "
                "docs/configuration.md)"]
    hosts = set(claude_settings._merged_list(trusted, "sandbox", "network", "allowedDomains"))
    # every level, the project's too: whether a project's rule extends a strict allowlist
    # depends on how Claude Code was started, so each one is counted as a way out
    every = claude_settings.levels(project, home)
    added: List[Tuple[str, str, List[str]]] = []
    for lvl, path, data in every:
        allow = ((data or {}).get("permissions") or {}).get("allow") or []
        rules = [r[len("WebFetch(domain:"):-1] for r in (allow if isinstance(allow, list) else [])
                 if isinstance(r, str) and r.startswith("WebFetch(domain:") and r.endswith(")")]
        if rules:
            added.append((lvl, path, rules))
            hosts.update(rules)
    n = len(hosts)
    out = [f"  network for shell commands: limited to {n} host{'' if n == 1 else 's'}"
           + (f" ({', '.join(sorted(hosts)[:5])}{', ...' if n > 5 else ''})" if hosts else
              " (none)")
           + "; WebFetch and MCP servers are not limited by it; each listed host is a way out"]
    for lvl, path, rules in added:
        out.append(f"  WARNING: {len(rules)} WebFetch(domain:...) allow rule(s) in the {lvl} "
                   f"settings ({path}) add hosts to the network limit: "
                   f"{', '.join(sorted(rules)[:5])}{', ...' if len(rules) > 5 else ''}. Remove "
                   "them if shell commands must not reach those hosts.")
    # every level, the project's too: a command outside the sandbox has no network limit
    if claude_settings._first(every, "sandbox", "enabled") is not True \
            or claude_settings._merged_list(every, "sandbox", "excludedCommands"):
        out.append("  WARNING: the network limit does not hold for every command: the sandbox is "
                   "off or sandbox.excludedCommands is set (a project's settings can do this); "
                   "excluded commands reach any host.")
    if cfg.network_limit:
        extra = sorted(set(claude_settings._merged_list(trusted, "sandbox", "network",
                                                        "allowedDomains"))
                       - set(cfg.allowed_domains))
        if extra:
            out.append(f"  WARNING: {len(extra)} host(s) in Claude Code's user settings are not "
                       "in [network] allowed_domains: run `(cd ~ && phiward install claude "
                       "--user --write)` again, which replaces sandbox.network.allowedDomains "
                       "with that list.")
    return out


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
