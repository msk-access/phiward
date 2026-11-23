"""The protected-paths guard: the text layer in front of the kernel boundary.

The boundary is the kernel: Claude Code's sandbox (as `install` writes it) keeps the agent's
shell commands from protected roots, and only the gateway (`phiward run|copy`, started by the
broker, confined by confine.py, output sanitized) can read them. This guard:
- allows a gateway call written as the whole command (a client of the broker; the broker checks
  the grants, `--write-to` and `--net`, against the user config);
- refuses a shell command that names a protected path (inside one), with a reason that says to
  use the gateway;
- when the tool's shell is NOT confined (no sandbox), refuses every command but a whole gateway
  call, `doctor` or `check`; with `[shell] best_effort` it instead also refuses a command that
  runs in, or names, a folder above a protected path, and applies `unresolved` to variables it
  cannot see (best effort, docs/threat-model.md). A shell that is not confined only because
  `sandbox.excludedCommands` is not empty (`Action.text_checked`) gets that same text check for
  every call: Claude Code decides which calls run outside the sandbox, and phiward does not
  guess;
- refuses file tools (read, search, write) on a protected path, and searches from above one.
  No shell sandbox covers the file tools, so this check always applies;
- refuses file-tool writes to the files that turn the guards off or widen the gateway: the
  phiward config, code and status file, and the agent tool's own settings files.

A command "names" a path when its working folder, a `cd` target, any word (after the guard
expands `~`, known variables, braces and globs, and resolves symlinks before it normalizes), the
text of an inner command, or the command text itself, reaches it.
"""

import os
import stat
import re
from dataclasses import replace
from typing import AbstractSet, Dict, List, Mapping, NamedTuple, Optional, Sequence, Set, Tuple

from phiward import gateway, paths, pathid, shell
from phiward.config import Config
from phiward.core import (ALLOW, ALLOWED, ASK, DENY, FILE_READ, FILE_SEARCH, FILE_WRITE,
                               SHELL, Action, Decision)

NAME = "protected-paths"
MAX_DEPTH = 8  # nesting of $( ) inside $( ) the guard follows before it gives up (fail closed)

# one short line: the rules themselves are in AGENTS.md and the skill, which
# the agent already has; a long reason on every refusal only costs context
RULE = ("Use `phiward run -- CMD` (the whole command) or `phiward copy`. Rules: AGENTS.md or "
        "the phiward skill.")


def deny(why: str, step: str = RULE) -> Decision:
    """A refusal: what is refused, then its one next step. RULE (the gateway) is the step only
    for a refusal that names protected data; any other refusal carries its own (`step=""`: the
    reason already says what to do)."""
    return Decision(DENY, f"{why} {step}".strip(), NAME)


class _Touch:
    """What one command (with its inner commands) does."""

    def __init__(self) -> None:
        self.relation: Optional[str] = None
        self.unresolved: List[str] = []  # names of unknown variables, or "syntax"

    def add(self, rel: Optional[str]) -> None:
        self.relation = paths.worst(self.relation, rel)


def check(action: Action, cfg: Config) -> Decision:
    from phiward import claude_settings
    home = pathid.home()
    for project in claude_settings.project_folders(action.cwd or "", home):
        redirect = claude_settings.project_redirects(project, home)
        if redirect:
            # the hook would read another config (or none): nothing it decides can be trusted
            text = claude_settings.redirect_text(redirect)
            return Decision(DENY, text[:1].upper() + text[1:]
                            + ", which can change what phiward's hook runs or reads. Every tool "
                            "call is refused until the operator fixes the project's "
                            ".claude/settings*.json.", NAME)
    if cfg.problem:
        return Decision(DENY, f"The phiward config cannot be used, so guarded actions are "
                        f"refused until it is fixed: {cfg.problem}", NAME)
    home0 = pathid.home()
    memo: dict = {}  # the Claude folders and each path's answer, once for this call
    if action.kind == FILE_WRITE and _writes_a_guard_file(action, home0, cfg, memo=memo):
        # also before any config exists: the first setup is when the config is written, and a
        # file tool must not write it then either
        return deny("This file tool writes a file that controls the guards (the phiward "
                    "config, code or status file, the agent tool's settings, `.mcp.json`, anything "
                    "inside a `.git` folder or a `.git` file, or a `phiward` on PATH). Only the operator changes these.",
                    step="")
    if action.starts:
        # the app starts the project's own code outside the sandbox, with the operator's rights;
        # first every other check (a starter that names protected data is refused, not asked)
        first = check(replace(action, starts=""), cfg)
        if first.verdict == DENY:
            return first
        return _ask_or_deny(
            action, f"phiward: this tool starts {action.starts}, outside Claude Code's sandbox "
            "and with your rights: code the agent wrote there runs unconfined. Allow it only if "
            "you have read what it runs.",
            f"This tool starts {action.starts}, outside the sandbox and with the operator's "
            "rights, and this session cannot ask the operator: the operator starts it "
            "themselves.")
    if action.kind == FILE_WRITE and _writes_code(action, home0, memo):
        return _ask_or_deny(action, ASK_CODE, DENY_CODE)
    if action.kind == FILE_WRITE and _another_name(action, home0):
        return _ask_or_deny(action, ASK_LINK, DENY_LINK)
    if "powershell" in (action.tool or "").lower() and cfg.has_protected_paths:
        # its commands are not parsed like a POSIX shell's, and phiward does not know how
        # Claude Code confines them: only Bash is checked as a shell
        return deny("phiward does not check PowerShell commands as a shell; use Bash.", step="")
    if not cfg.has_protected_paths:
        # no config yet (first setup): no protected data is known, but the
        # credentials are: a key or ticket the agent reads now reaches the model all the same.
        # Only direct reads are refused here, not searches above them.
        return _credentials_only(action, cfg)
    # the hidden list (credentials, tickets, histories) is refused like protected
    # data: a credential that reaches the model undoes every mask
    from phiward import hidden
    pset = paths.ProtectedSet(cfg.all_roots + hidden.paths(None, cfg, session=True),
                              list(cfg.patterns) + list(hidden.KRB5_NAME_PATTERNS))
    pset.secret = paths.ProtectedSet(cfg.all_roots, cfg.patterns)
    home = pathid.home()
    try:
        if action.searches:
            # the paths a tool names by its path fields, as a search: only adds a refusal
            mode = pset.mode
            pset.mode = "file"
            d = _check_file(replace(action, kind=FILE_SEARCH, paths=action.searches), pset, home)
            pset.mode = mode
            if d.verdict == DENY:
                return d
        if action.kind == SHELL:
            # a named tool other than Claude Code's shells (no name: a generic shell, `check`)
            other = bool(action.tool) and action.tool not in ("Bash", "bash", "Monitor")
            if action.text and other:
                # a shell under another name: every string of its input, not only the command
                d = _check_text(action.text, pset, home, cwd=action.cwd or "/", cfg=cfg,
                                ask=action.can_ask, tool=action.tool)
                if d.verdict == DENY:
                    return d
            if other and action.shape and not cfg.shell_best_effort:
                return deny(UNSANDBOXED_TOOL.format(why=action.shape, advice=action.advice),
                            step="")
            # text_checked: unconfined only by an excludedCommands entry; the text check below
            # stands in for the blanket refusal, as with best_effort
            if not action.confined and not cfg.shell_best_effort and not action.text_checked:
                kind = _kernel_route(action.command)
                if kind is None:
                    if other:
                        return deny(UNSANDBOXED_TOOL.format(
                            why="its command is not one whole gateway call",
                            advice=action.advice), step="")
                    # said once: the rule's tail would repeat the gateway call
                    return Decision(DENY, gateway.not_whole(action.command) or
                                    unconfined_text(action.unconfined_why,
                                                    action.unconfined_step), NAME)
                if kind == "kernel":  # `doctor`, `check`: no protected data read here
                    action = replace(action, confined=True)
            return _check_shell(action, cfg, pset, home)
        if action.kind in (FILE_READ, FILE_WRITE, FILE_SEARCH):
            pset.mode = "file"
            d = _check_file(action, pset, home)
            if d.verdict != ALLOW or action.kind != FILE_WRITE:
                return d
            # a file tool writes where the sandbox lets the shell write (Mode A; inside `launch`
            # the kernel confines the whole tool)
            if action.claude_code and not os.environ.get("PHIWARD_LAUNCH_DEPTH") and \
                    _writes_outside(action, home):
                return _ask_or_deny(action, ASK_OUT, DENY_OUT)
            return d
        if action.remote:
            # a remote server runs nothing here and writes no file here: only its text
            return _check_text(action.text + action.paths, pset, home)
        return _check_text(action.text + action.paths, pset, home, cwd=action.cwd or "/",
                           ask=action.can_ask, tool=action.tool, cfg=cfg)
    except paths.GlobUnchecked as exc:
        return deny(str(exc), step="")


# why an unconfined shell call is refused (`[shell] best_effort` off, the default)
UNCONFINED = ("This shell is not confined by Claude Code's sandbox, so every command is refused "
              "but a whole gateway call (`phiward run -- CMD`, `phiward copy SRC... DST`). The "
              "operator turns the sandbox on with `(cd ~ && phiward install claude --user --write)` "
              "(`phiward doctor` says what is missing).")


def unconfined_text(why: str, step: str = "") -> str:
    """UNCONFINED, with the confinement check's reason and its own step when there is one: the
    same answer as `doctor`."""
    if not why:
        return UNCONFINED
    return (f"This shell is not confined by Claude Code's sandbox ({why}), so every command is "
            "refused but a whole gateway call (`phiward run -- CMD`, `phiward copy SRC... DST`)."
            + (f" To fix it: {step}." if step else ""))


# why a shell tool other than Claude Code's Bash and Monitor is refused
UNSANDBOXED_TOOL = ("This tool runs commands outside Claude Code's sandbox, with the operator's "
                    "rights, and {why}, so phiward refuses it. Such a tool may make one whole "
                    "gateway call (`phiward run -- CMD`, `phiward copy SRC... DST`), in its one "
                    "command field, with no other options. {advice}")


def _kernel_route(command: str) -> Optional[str]:
    """For a shell that Claude Code's sandbox does not confine: "gateway" for a gateway call
    (the broker runs it), "kernel" for `doctor` or `check` (they read no protected data), each
    written whole; else None (refused)."""
    words = gateway.whole_command(command)
    if not words:
        return None
    if words[0] in ("run", "copy"):
        return "gateway"
    if words[0] in ("doctor", "check"):
        return "kernel"
    return None


def _credentials_only(action: Action, cfg: Config) -> Decision:
    try:
        return _credentials_check(action, cfg)
    except paths.GlobUnchecked as exc:
        return deny(str(exc), step="")


def _credentials_check(action: Action, cfg: Config) -> Decision:
    from phiward import hidden
    pset = paths.ProtectedSet(hidden.paths(None, cfg, session=True), list(hidden.KRB5_NAME_PATTERNS))
    pset.secret = paths.ProtectedSet([], [])  # no protected paths yet
    if action.kind != SHELL:
        pset.mode = "file"
    else:
        pset.mode = "confined" if action.confined else "shell"
    home = pathid.home()
    why = ("This names a credential or a trace that no agent may read (phiward's hidden list): "
           "leave it out of the call.")
    if action.kind == SHELL:
        cmd = action.command
        if pset.text_search(_expand_home_in_text(cmd, home)):
            return deny(why, step="")
        touch = _Touch()
        try:
            _walk(shell.parse(cmd), [action.cwd or "/"], pset, home, touch, depth=0)
        except (shell.ShellSyntaxError, ValueError, RecursionError):
            touch.unresolved.append("syntax")
        if touch.relation == paths.INSIDE:
            return deny(why, step="")
        for p in action.searches:  # a shell-named tool's path fields
            p = _expand_home(p, home)
            full = p if p.startswith("/") else os.path.join(action.cwd or "/", p)
            if any(paths.word_relation(v, [action.cwd or "/"], pset, glob=True) == paths.INSIDE
                   for v in paths.loose_variants(full)):
                return deny(why, step="")
        return ALLOWED if action.confined else _unresolved(touch, cfg)
    # a file tool's paths, and the paths any tool names by its path fields (`searches`)
    for p in tuple(action.paths) + tuple(action.searches):
        p = _expand_home(p, home)
        full = p if p.startswith("/") else os.path.join(action.cwd or "/", p)
        for variant in paths.loose_variants(full):
            if paths.word_relation(variant, [action.cwd or "/"], pset, glob=True) == paths.INSIDE:
                return deny(why, step="")
    return ALLOWED


# -- file tools ---------------------------------------------------------------------------------

_SETTINGS = ("settings.json", "settings.local.json")
_SETTINGS_FOLDED = tuple(n.casefold() for n in _SETTINGS)


def _guard_places(home: str, cfg: Optional[Config] = None) -> List[str]:
    from phiward import claude_settings, config
    places = config.guard_files() + [os.path.join(claude_settings.user_dir(home), n)
                                     for n in _SETTINGS]
    places += claude_settings.shell_code_paths(home)  # what the shell runs before a command
    if cfg is not None:
        places += config.command_paths(cfg)  # the operator's own scripts the gateway may run
    for m in claude_settings.MANAGED:
        places += [m, os.path.join(os.path.dirname(m), "managed-settings.d")]
    # git's own config, which names programs git runs (Claude Code runs git outside its sandbox)
    from phiward import config as _config
    xdg = _config.xdg_config_home(home)
    places += [os.path.join(home, ".gitconfig"), os.path.join(xdg, "git")]
    # a launcher by the name the hook and the gateway are started by, in any PATH folder
    for e in os.environ.get("PATH", "").split(":"):
        if e.startswith("/"):
            places += [os.path.join(e, "phiward"), os.path.join(e, "agent-guards")]
    out: List[str] = []
    for p in places:
        for v in (os.path.normpath(p), os.path.realpath(p)):
            if v not in out:
                out.append(v)
    return out




def _guard_index(home: str, cfg: Optional[Config] = None) -> "tuple":
    """The guard places as `_writes_a_guard_file` compares them: (folded names, identities).
    Built once for a tool call that names many paths."""
    from phiward.pathid import fold
    places = _guard_places(home, cfg)
    return ([fold(g.rstrip("/")) for g in places],
            {i for i in (pathid.identity(g) for g in places) if i is not None})


def _writes_a_guard_file(action: Action, home: str, cfg: Optional[Config] = None,
                         index: "Optional[tuple]" = None, memo: Optional[dict] = None) -> bool:
    """Does a file tool write one of the files that control the guards? Compared as the file
    system compares names (letter case and Unicode form on macOS), and by what the target is
    (device and inode of it or of its nearest existing folder), so another spelling or another
    name of the same file is caught too."""
    from phiward.pathid import fold
    folded, ids = index if index is not None else _guard_index(home, cfg)
    for p in action.paths:
        p = _expand_home(p, home)
        raw = os.path.join(action.cwd or "/", p)
        full = os.path.normpath(raw)
        # `realpath` of the raw path resolves a link before the `..` after it, as the kernel
        # does; `normpath` first would drop the link as text
        kernel = os.path.realpath(raw)
        from phiward import claude_settings
        if claude_settings.claude_place(raw, home, _bases(action), memo=memo) == "settings":
            return True  # a Claude Code settings file, under a `.claude` by what it is
        for v in (full, os.path.realpath(full), kernel, pathid.canon_new(kernel)):
            parts = fold(v).split("/")
            if len(parts) >= 2 and parts[-2] == ".claude" and parts[-1] in _SETTINGS_FOLDED:
                return True  # any project's Claude Code settings
            if parts[-1] == ".mcp.json":
                return True  # an MCP server added there runs later
            if ".git" in parts:
                # git runs what its control files name (config, hooks, commondir, a `.git`
                # file's gitdir): a file tool has no reason to write anything there
                return True
            fv = fold(v)
            if any(fv == g or fv.startswith(g + "/") for g in folded):
                return True
        # the target, or the nearest folder of it that exists, is a guard file or folder
        probe = kernel
        while True:
            i = pathid.identity(probe)
            if i is not None:
                if i in ids:
                    return True
                break
            parent = os.path.dirname(probe)
            if parent == probe:
                break
            probe = parent
        # and every folder above it: a new file inside a guarded folder
        up = os.path.dirname(probe)
        while up and up != "/":
            if pathid.identity(up) in ids:
                return True
            nxt = os.path.dirname(up)
            if nxt == up:
                break
            up = nxt
    return False


# a file tool's write that only a person may let through: the reason for "ask" is shown to the
# person, the reason for a refusal to the agent
ASK_CODE = ("phiward: this file is run as code with your rights, outside the sandbox (a skill, "
            "subagent, command, hook, plugin or workflow of Claude Code, or an editor's or git's "
            "settings that name commands). Allow it only if you have read what the agent "
            "writes.")
DENY_CODE = ("This file tool writes a file that is run as code (a skill, subagent, command, "
             "hook, plugin or workflow of Claude Code, or an editor's or git's settings that name "
             "commands), and this session cannot ask the operator: the operator "
             "writes it, in their own editor.")
ASK_OUT = ("phiward: the agent writes outside the folders its sandbox may write (the project, "
           "the temp folder, allowWrite). Allow it only if you expect it; to stop these prompts "
           "for a folder, add it to permissions.additionalDirectories in your user settings.")
DENY_OUT = ("This file tool writes outside the folders the sandbox lets this session write: "
            "write inside the project, or ask the operator to add the folder to "
            "`permissions.additionalDirectories` in their user settings (a folder added with "
            "`--add-dir` is not known to phiward).")
ASK_NAMED = ("phiward: an MCP server's tool names a file Claude Code runs as code with your "
             "rights (a skill, subagent, command, hook, plugin or workflow), and may write it. "
             "Allow it only if you know what this tool does with it.")
DENY_NAMED = ("This MCP tool names a file Claude Code runs as code (a skill, subagent, command, "
              "hook, plugin or workflow), and may write it, and this session cannot ask the "
              "operator: read the file with the Read tool instead.")
ASK_LINK = ("phiward: this file has another name (a hard link), which may be a file Claude "
            "Code runs as code. Allow it only if you know what the other name is.")
DENY_LINK = ("This file tool writes a file that has another name (a hard link), which may be a "
             "file Claude Code runs as code, and this session cannot ask the operator: give the "
             "file a name of its own first (`cp FILE FILE.new && mv FILE.new FILE` in the "
             "shell; the other name keeps its content), then write it.")


def _ask_or_deny(action: Action, ask: str, refuse: str) -> Decision:
    """A prompt to the person where the session shows one (`can_ask`: a Claude Code payload in
    a mode known to prompt), else a refusal."""
    return Decision(ASK, ask, NAME) if action.can_ask else deny(refuse, step="")


def _bases(action: Action) -> List[str]:
    return [b for b in (action.cwd, os.environ.get("CLAUDE_PROJECT_DIR")) if b]


def _writes_code(action: Action, home: str, memo: Optional[dict] = None) -> bool:
    from phiward import claude_settings
    for p in action.paths:
        p = _expand_home(p, home)
        full = os.path.join(action.cwd or "/", p)
        if claude_settings.claude_place(full, home, _bases(action), memo=memo) == "code":
            return True
        if claude_settings.workspace_code(full):
            return True
    return False


def _another_name(action: Action, home: str) -> bool:
    """Whether a file a file tool writes has another name (a hard link): that name may be a
    settings or code file anywhere, which no rule here can see."""
    for p in action.paths:
        p = _expand_home(p, home)
        try:
            st = os.stat(os.path.join(action.cwd or "/", p))  # through a symlink too
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
            return True
    return False


def _writes_outside(action: Action, home: str) -> bool:
    """Whether a file tool writes outside the folders the sandbox lets the shell write and the
    folders where Claude Code keeps its memory and plans (`claude_settings.memory_places`):
    compared as the file system compares names."""
    import fnmatch
    from phiward import claude_settings
    project = os.environ.get("CLAUDE_PROJECT_DIR") or action.cwd or "/"
    # a write place over start-up files (a session in the home folder) does not count: there a
    # file tool asks or is refused (claude_settings.startup_write_problem)
    roots = [pathid.fold(r).rstrip("/") for r in claude_settings.agent_writable(project, home)
             if not claude_settings.startup_write_problem(r, home)]
    mem = [pathid.fold(m).rstrip("/") for m in claude_settings.memory_places(home)]
    for p in action.paths:
        p = _expand_home(p, home)
        full = os.path.realpath(os.path.join(action.cwd or "/", p))
        v = pathid.fold(pathid.canon_new(full))
        w = pathid.fold(full)
        ok = any(x == r or x.startswith(r + "/") for x in (v, w) for r in roots if r)
        ok = ok or any(fnmatch.fnmatchcase(x, m) or fnmatch.fnmatchcase(x, m + "/*")
                       for x in (v, w) for m in mem)
        if not ok:
            return True
    return False


def _hidden_place(path: str) -> bool:
    """Whether `path` is on the hidden list (credentials, histories), not a protected root."""
    from phiward import hidden
    real = os.path.realpath(path)
    return any(pathid.inside(real, h) or pathid.inside(path, h)
               for h in hidden.paths(session=True))


def _check_file(action: Action, pset: paths.ProtectedSet, home: str) -> Decision:
    targets: Sequence[str] = action.paths or ((action.cwd,) if action.kind == FILE_SEARCH else ())
    for p in targets:
        p = _expand_home(p, home)
        base = [action.cwd or "/"]
        absolute = p if p.startswith("/") else os.path.join(base[0], p)
        rel = None
        for variant in paths.loose_variants(absolute):  # braces, escapes, groups
            rel = paths.worst(rel, paths.word_relation(variant, base, pset, glob=True))
        if rel == paths.INSIDE:
            if _hidden_place(absolute):
                # the gateway cannot read the hidden list either: no gateway step
                return deny("This file is a credential or a trace (a login, a key, a history) "
                            "that no session may read, and the gateway cannot read it either. "
                            "If the work needs it, stop and ask the operator.", step="")
            return deny("This file tool names a protected path.")
        if rel == paths.ABOVE and action.kind in (FILE_SEARCH, FILE_READ):
            return deny("This file tool starts above a folder that holds protected data, so it "
                        "would reach it: give `path` a folder that holds no protected folder "
                        "(or a pattern that stays out of it).", step="")
    return _check_text(action.text, pset, home)


_FILE_NAME = re.compile(r"[\w.-]+\.[A-Za-z0-9]{1,10}")


def _leads_inside(p: str, pset: paths.ProtectedSet, seen: Optional[dict] = None) -> bool:
    """Whether a path, or the nearest folder of it that exists (a file not made yet), leads
    inside a protected path once its links are followed. `seen`: the answers of this one tool
    call, by that nearest existing path (many new files in one folder)."""
    try:
        q = os.path.abspath(p)
        while not os.path.lexists(q) and os.path.dirname(q) != q:
            q = os.path.dirname(q)
        if seen is not None and q in seen:
            return seen[q]
        out = pset.relation(q) == paths.INSIDE
        if seen is not None:
            seen[q] = out
        return out
    except (OSError, ValueError):
        return False


def _check_text(texts: Sequence[str], pset: paths.ProtectedSet, home: str,
                cwd: Optional[str] = None, cfg: Optional[Config] = None,
                ask: bool = False, tool: str = "") -> Decision:
    """A protected path written in any of `texts`; also percent-decoded (a `file://` URL), and,
    with `cwd` (a tool phiward does not otherwise read: an MCP tool), a whole string that is an
    existing path, by where it really leads (`repo/leak.txt` linked into a root)."""
    from urllib.parse import unquote, urlsplit
    index = None  # the guard places, built once (a call may name thousands of paths)
    seen: dict = {}
    memo: dict = {}  # the Claude folders, found once per folder in this call
    for t in dict.fromkeys(texts):
        forms = [t]
        if "%" in t:
            forms.append(unquote(t))
        for f in forms:
            if pset.text_search(_expand_home_in_text(f, home)):
                return deny("This tool call names a protected path.")
        if cwd is None or len(t) > 4096 or not t.strip() or "\n" in t or "\0" in t:
            continue
        bases = list(dict.fromkeys(b for b in (cwd, os.environ.get("CLAUDE_PROJECT_DIR")) if b))
        for f in dict.fromkeys(forms + [x.strip() for x in forms]):
            web = False
            if f.startswith("file:"):
                f = unquote(urlsplit(f).path)
            elif _URL.match(f):
                # a web address may name `.mcp.json` (nothing here is written), unless it climbs
                # above its host (`https://x/../../f`) or something named like its scheme
                # (`https:`) is in the folder; it is always followed as a path, since a local
                # server may join it to its folder, where `https:` may be a link
                web = not _climbs(f) and not any(
                    os.path.lexists(os.path.join(b, f.split("/", 1)[0])) for b in bases)
            # only what looks like a path (a `/`, `~`, or a file name with an extension): a plain
            # word (`data`) is text, not a file
            if "/" not in f and not f.startswith("~") and not _FILE_NAME.fullmatch(f):
                continue
            f = _expand_home(f, home)
            for base in ([""] if f.startswith("/") else bases):
                if _leads_inside(os.path.join(base, f) if base else f, pset, seen):
                    return deny("This tool call names a protected path (through a link).")
                # a tool phiward cannot see into (an MCP server's) may write what it names: not
                # the files that control the guards
                if web:
                    continue
                if index is None:
                    index = _guard_index(home, cfg)
                probe = Action(FILE_WRITE, base or "/", paths=(f,))
                if _writes_a_guard_file(probe, home, cfg, index, memo):
                    return deny("This tool call names a file that controls the guards (the "
                                "phiward config, code, status or session files, or the agent "
                                "tool's settings). Only the operator changes these.", step="")
                if tool.startswith("mcp__") and _writes_code(probe, home, memo):
                    # an MCP server's tool may write what it names; Claude Code's own tools
                    # that are not file tools (Skill, LSP) read or run, and write nothing
                    return _ask_or_deny(replace(probe, can_ask=ask), ASK_NAMED, DENY_NAMED)
    return ALLOWED


_URL = re.compile(r"(?i)(?:https?|wss?)://")


def _climbs(url: str) -> bool:
    """Whether a web address climbs above its own host with `..` parts (`https://x/../../f`):
    joined to a folder by a local server, it leads out of `https:/x`. `https://x/a/../f` stays
    inside and is just a web address."""
    parts = re.split(r"[/\\]", url)
    if len(parts) > 2 and parts[2] in ("", ".", ".."):
        return True  # no host, or one that is itself a step (`https://../f`)
    depth = 0
    for part in parts[3:]:  # after `scheme:`, ``, the host
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        elif part not in ("", "."):
            depth += 1
    return False


def _expand_home(p: str, home: str) -> str:
    if p == "~" or p.startswith("~/"):
        p = home + p[1:]
    return p.replace("${HOME}", home).replace("$HOME", home)


def _expand_home_in_text(t: str, home: str) -> str:
    t = t.replace("${HOME}", home).replace("$HOME", home)
    return re.sub(r"(^|[\s=:'\"(])~(?=/|$|[\s'\"])", lambda m: m.group(1) + home, t)


# -- shell --------------------------------------------------------------------------------------

def _check_shell(action: Action, cfg: Config, pset: paths.ProtectedSet, home: str) -> Decision:
    cmd = action.command
    if gateway.is_operator_command(cmd):
        return deny("`phiward setup`, `pin`, `carryover`, `broker` and `pseudonymize` are the "
                    "operator's once phiward is set up: ask the operator to run it in their own "
                    "terminal.",
                    step="")
    call = gateway.parse_call(cmd)
    if call is not None:
        if not action.confined and _has_unquoted_glob(cmd):
            # the agent's own shell would expand it: the names would sit in the request, in the
            # spool, which the agent can read
            return deny("A gateway call may not hold an unquoted wildcard inside a protected "
                        "path: this shell would list the names. Let the gateway expand it: "
                        "`phiward run -- sh -c 'CMD /protected/*'`.", step="")
        return _check_gateway(call)
    if _writes_claude_settings(cmd):
        return deny("This command writes Claude Code settings (`.claude/settings*.json`) or the "
                    "MCP config (`.mcp.json`). Only the operator changes these.", step="")
    if action.confined:
        pset.fail_closed = False  # the kernel decides about paths the walk cannot resolve
    pset.mode = "confined" if action.confined else "shell"
    touch = _Touch()
    parsed: Optional[shell.Parsed]
    try:
        parsed = shell.parse(cmd)
    except (shell.ShellSyntaxError, ValueError, RecursionError):
        parsed = None
    if pset.text_search(_expand_home_in_text(cmd, home)):
        touch.add(paths.INSIDE)
    if parsed is None:
        touch.unresolved.append("syntax")
        touch.add(pset.relation(action.cwd or "/"))
    else:
        _walk(parsed, [action.cwd or "/"], pset, home, touch, depth=0)

    if touch.relation == paths.INSIDE:
        return deny("This command names a protected path.")
    if action.confined:
        return ALLOWED  # the kernel denies whatever the text missed
    if touch.relation == paths.ABOVE:
        d = deny("This command runs in, or names, a folder that holds protected data, so a "
                 "listing or a recursive search from there reaches it (this tool's shell is "
                 "not sandboxed, so the guard must refuse it).")
    else:
        d = _unresolved(touch, cfg)
    if action.text_checked and d.verdict != ALLOW:
        # the cause is the entry, not the command: say which file holds it and the way out
        d = Decision(d.verdict, f"{d.reason} This shell is text-checked because "
                     f"{action.unconfined_why}; to run it, {action.unconfined_step}.", NAME)
    return d


# what makes a command unresolved besides a variable's name (`_walk`)
_REASONS = {"syntax": "text the guard cannot parse",
            "group": "a zsh or extglob group (`(a|b)`, `@(a)`)",
            "built": "a path built from `$(...)`, backticks, `$'...'` or variables the command "
                     "sets",
            "dotdot": "`..` after a folder that does not exist yet",
            "moved": "`cd -`, `popd` or `~-` (a folder the guard does not know)",
            "fresh": "a path through a link or folder the command makes",
            "lookup": "a change to how bash finds commands or folders (`PATH`, `CDPATH`, "
                      "`HOME`, `hash`, `shopt`, ...)"}


def _unresolved(touch: "_Touch", cfg: Config) -> Decision:
    """The decision for what the guard could not see, by `cfg.unresolved` (deny by default)."""
    if not touch.unresolved or cfg.unresolved == ALLOW:
        return ALLOWED
    names = sorted({u for u in touch.unresolved if u not in _REASONS})
    what = [_REASONS[r] for r in _REASONS if r in touch.unresolved]
    if names:
        what.insert(0, "variables the guard cannot see (" + ", ".join("$" + n for n in names)
                    + ")")
    reason = (f"This command uses {' and '.join(what)}, so the guard cannot tell whether it "
              "reaches protected data. Write the paths out in full.")
    return Decision(ASK if cfg.unresolved == ASK else DENY, reason, NAME)


def _has_unquoted_glob(cmd: str) -> bool:
    try:
        parsed = shell.parse(cmd)
    except (shell.ShellSyntaxError, ValueError, RecursionError):
        return True
    # any unquoted wildcard or brace: the agent's own shell expands it before the request is
    # written, and a link in the project can lead the expansion into a protected root, whose
    # names would then sit in the request (a prefix check cannot see through the link)
    for w in parsed.items:
        if isinstance(w, shell.Word) and (w.has_glob or w.has_brace):
            return True
    return False


_SETTINGS_NAME = re.compile(r"(^|/)\.claude/settings(\.local)?\.json$|managed-settings|"
                            r"(^|/)\.mcp\.json$", re.I)
_SETTINGS_TEXT = re.compile(r"settings(\.local)?\.json|managed-settings|\.mcp\.json", re.I)
# programs that write the files their arguments name
_WRITERS = {"cp", "mv", "tee", "ln", "rm", "install", "truncate", "touch", "rsync", "dd", "chmod",
            "unlink", "patch"}
_INPLACE = {"sed": "-i", "perl": "-i", "gsed": "-i"}


def _writes_claude_settings(cmd: str) -> bool:
    """A shell command that writes a Claude Code settings file: a redirection into one, or a
    writing program (cp, mv, tee, dd of=, sed -i, git checkout/restore, an interpreter's code)
    that names one, after quotes are removed (`sett""ings.json` passed a text
    match, and `grep … 2>/dev/null` was refused). A name built from variables, or reached after
    `cd .claude`, is not seen: in a project wired with `install --project`, Claude Code's
    sandbox denies the write itself."""
    if not _SETTINGS_TEXT.search(cmd.replace('"', "").replace("'", "")):
        return False
    try:
        parsed = shell.parse(cmd)
    except (shell.ShellSyntaxError, ValueError, RecursionError):
        return True  # cannot tell: refuse
    words: List[str] = []

    def simple_command_writes(ws: List[str]) -> bool:
        if not ws:
            return False
        prog = ws[0].rsplit("/", 1)[-1]
        if prog.startswith(("python", "node", "ruby", "perl", "bash", "sh", "zsh")) and \
                not (prog in _INPLACE and any(w.startswith(_INPLACE[prog]) for w in ws[1:])):
            # code that names the file anywhere: it may write it
            return any(_SETTINGS_TEXT.search(w) and (".claude" in w or ".mcp.json" in w)
                       for w in ws[1:])
        names = [w for w in ws[1:] if _SETTINGS_NAME.search(w.split("=", 1)[-1])]
        if not names:
            return False
        if prog in _WRITERS:
            return prog != "dd" or any(w.startswith("of=") and _SETTINGS_NAME.search(w[3:])
                                       for w in ws)
        if prog in _INPLACE and any(w.startswith(_INPLACE[prog]) for w in ws[1:]):
            return True
        if prog == "git" and len(ws) > 1 and ws[1] in ("checkout", "restore", "apply", "stash"):
            return True
        return False

    for it in parsed.items:
        if isinstance(it, shell.Op):
            if it.target is not None and it.text.rstrip("&").endswith(">") and \
                    _SETTINGS_NAME.search(it.target.text()):
                return True
            if not it.is_redirect:
                if simple_command_writes(words):
                    return True
                words = []
        else:
            words.append(it.text())
    return simple_command_writes(words)


def _check_gateway(call: "gateway.Call") -> Decision:
    if call.name == "copy":
        if len([a for a in call.args if a != "--dry-run"]) < 2:
            return deny("`phiward copy` needs a source and a destination.", step="")
        return ALLOWED
    from phiward import run
    a = run.parse(call.args)
    if a is None:
        return deny("`phiward run` must be written as `phiward run [--write-to DIR]... "
                    "[--net] [--names-from FILE]... [--table] -- CMD [ARG]...`.", step="")
    return ALLOWED  # grants: the broker checks them against the user config


def _walk(parsed: shell.Parsed, cwds: List[str], pset: paths.ProtectedSet, home: str,
          touch: _Touch, depth: int) -> None:
    if depth > MAX_DEPTH:
        touch.unresolved.append("syntax")
        touch.add(paths.ABOVE)
        return
    env = dict(os.environ)
    env["HOME"] = home
    env["PWD"] = cwds[0]  # the command's own folder, not the hook's
    env.pop("OLDPWD", None)
    unconfined = pset.mode != "confined"
    bound = shell.bound_names(parsed)
    words = parsed.words()
    cmds = _commands(parsed)
    where = _folders(parsed, cmds, cwds, env, bound, home)
    if where.moved:
        touch.unresolved.append("moved")
    if unconfined and parsed.groups:
        touch.unresolved.append("group")
    for b in where.union:
        touch.add(paths.word_relation(b, [], pset, glob=isinstance(b, paths.GlobBase)))
    made = _made_names(cmds, words)
    if unconfined and _changes_lookup(cmds, words):
        touch.unresolved.append("lookup")
    makes_links = any(c.words and c.words[0].text().rsplit("/", 1)[-1] == "ln" for c in cmds)
    plain_text = depth == 0 and not _redefines_commands(parsed, cmds)
    for i, (cmd, in_folders, from_start) in enumerate(zip(cmds, where.per_command,
                                                           where.started)):
        # `echo` and `printf` print text, not paths: only at the top of a line that redefines
        # no command, and when their output does not go on to another command (a pipe)
        piped = cmd.sep in ("|", "|&") or (i + 1 < len(cmds) and cmds[i + 1].sep in ("|", "|&"))
        text_only = plain_text and not piped and bool(cmd.words) and \
            cmd.words[0].text() in ("echo", "printf")
        for w in cmd.all:
            bases = from_start if id(w) in where.option_values else in_folders
            if shell.ASSIGNMENT.match(w.text()) and w.text().startswith("IFS="):
                continue  # a field separator, not a path
            if not where.changed:
                w = _pwd_as_variable(w)
            values, unknown = shell.expand(w, env, bound, home)
            text = text_only and not w.redirect_target
            if unknown and not text:
                touch.unresolved.extend([n for k, n, _ in w.segs if (k == "varx" or k == "var" and
                                         n not in env and n not in bound)] or ["moved"])
            if unconfined and not text and _built(w, bound, made):
                # without the sandbox the text is all the guard sees: a word it cannot read
                # whole is unresolved (docs/threat-model.md, "The hook: a first layer")
                touch.unresolved.append("built")
            if unconfined and where.changed:
                # $PWD is the command's folder; after a `cd` in the line it may be another
                touch.unresolved.extend(n for k, n, _ in w.segs
                                        if k == "var" and n in ("PWD", "OLDPWD"))
            for v in _variants(values, w):
                if not v:
                    continue
                full = paths.candidates(v, bases)
                if unconfined and any(_dotdot_after_missing(f) for f in full):
                    touch.unresolved.append("dotdot")
                if unconfined and makes_links and any(_through_missing(f) for f in full):
                    touch.unresolved.append("fresh")
                touch.add(paths.word_relation(v, bases, pset, glob=w.has_glob))
        for inner in _shell_text(cmd, parsed, env, bound, home):
            _walk_text(inner, in_folders, pset, home, touch, depth)
    for name in parsed.vars - set(env) - bound:
        # variables used in heredocs and ${...} parts
        if not any(n == name for w in words for k, n, _ in w.segs if k in ("var", "varx")):
            touch.unresolved.append(name)
    for inner in parsed.subs:
        _walk_text(inner, where.union, pset, home, touch, depth)


def _walk_text(text: str, bases: List[str], pset: paths.ProtectedSet, home: str,
               touch: _Touch, depth: int) -> None:
    """Shell text inside the command (`$(...)`, `bash -c '...'`, `eval`), checked as a
    command run in `bases`."""
    try:
        inner = shell.parse(text)
    except (shell.ShellSyntaxError, ValueError, RecursionError):
        touch.unresolved.append("syntax")
        return
    _walk(inner, bases, pset, home, touch, depth + 1)


_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}


def _shell_text(cmd: "_Cmd", parsed: shell.Parsed, env: Mapping[str, str], bound: Set[str],
                home: str) -> List[str]:
    """Shell code a command runs from a string: the argument after `-c` of a shell, the words
    of `eval`, and the heredocs a shell without `-c` reads."""
    if not cmd.words:
        return []
    prog = cmd.words[0].text().rsplit("/", 1)[-1]
    args = cmd.words[1:]

    def value(w: shell.Word) -> str:
        return " ".join(shell.expand(w, env, bound, home)[0])
    if prog == "eval":
        return [" ".join(value(a) for a in args)] if args else []
    if prog not in _SHELLS:
        return []
    for i, a in enumerate(args):
        t = a.text()
        if t.startswith("-") and not t.startswith("--") and "c" in t[1:]:
            return [value(args[i + 1])] if i + 1 < len(args) else []
    return list(parsed.heredocs)


def _pwd_as_variable(w: shell.Word) -> shell.Word:
    """`$(pwd)` as `$PWD`: the command's folder, when the line does not change folder."""
    if not any(k == "sub" and t.strip() in _PWD_COMMANDS for k, t, _ in w.segs):
        return w
    segs = [("var", "PWD", q) if k == "sub" and t.strip() in _PWD_COMMANDS else (k, t, q)
            for k, t, q in w.segs]
    return shell.Word(w.raw, segs, w.has_glob, w.has_brace, w.has_sub, w.has_dollar,
                      w.redirect_target)


_PWD_COMMANDS = {"pwd", "pwd -P", "pwd -L", "/bin/pwd"}


def _redefines_commands(parsed: shell.Parsed, cmds: List["_Cmd"]) -> bool:
    """Whether the line defines a function (`name()`, `function name`), or uses `alias` or
    `enable`: then `echo` may not be the shell's own."""
    items = parsed.items
    if any(isinstance(a, shell.Op) and a.text == "(" and isinstance(b, shell.Op) and
           b.text == ")" for a, b in zip(items, items[1:])):
        return True
    return any(w.text() in ("function", "alias", "enable", "unalias") for c in cmds
               for w in c.words[:1])


# what bash reads to find a command or a folder: a line that sets one (by any means), or runs a
# builtin that changes the lookup, makes every later name in it mean something the text does not
# say (`printf -v CDPATH ..; cd phi`, `printf -v PATH ...; cat x`, `shopt -s cdable_vars`)
LOOKUP_NAMES = frozenset({"PATH", "CDPATH", "HOME", "BASH_ENV", "ENV", "GLOBIGNORE", "BASHOPTS",
                          "SHELLOPTS", "PWD", "OLDPWD", "BASH_CMDS", "BASH_ALIASES", "FIGNORE"})
LOOKUP_BUILTINS = frozenset({"hash", "enable", "shopt", "alias"})
_SETTERS = frozenset({"export", "declare", "typeset", "local", "readonly", "read", "mapfile",
                      "readarray", "printf"})


def _changes_lookup(cmds: List["_Cmd"], words: List[shell.Word]) -> bool:
    """Whether the line sets a LOOKUP_NAMES variable or runs a LOOKUP_BUILTINS builtin."""
    for w in words:
        m = shell.ASSIGNMENT.match(w.text())
        if m and m.group(1) in LOOKUP_NAMES:
            return True
    for c in cmds:
        ws = [w.text() for w in c.words]
        if not ws:
            continue
        if ws[0] in LOOKUP_BUILTINS:
            return True
        if ws[0] in _SETTERS:
            # a name as its own word (`read PATH`, `export CDPATH`), or after a `-v` cluster
            # (`printf -vPATH`)
            for t in ws[1:]:
                name = t[2:] if t.startswith("-v") and len(t) > 2 else t
                if name in LOOKUP_NAMES:
                    return True
    return False


def _made_names(cmds: List["_Cmd"], words: List[shell.Word]) -> Set[str]:
    """Variables whose value is put together over several steps: more than one assignment,
    `+=`, `printf -v`, `read`, `mapfile`."""
    count: Dict[str, int] = {}
    made: Set[str] = set()
    for w in words:
        m = shell.ASSIGNMENT.match(w.text())
        if m:
            count[m.group(1)] = count.get(m.group(1), 0) + 1
            if w.text()[:m.end()].endswith("+="):
                made.add(m.group(1))
    made |= {n for n, c in count.items() if c > 1}
    for c in cmds:
        ws = [w.text() for w in c.words]
        if not ws:
            continue
        if ws[0] == "printf" and "-v" in ws[1:-1]:
            made.add(ws[ws.index("-v", 1) + 1])
        elif ws[0] in ("read", "mapfile", "readarray"):
            made |= {t for t in ws[1:] if shell.NAME.fullmatch(t)}
    return made


def _built(w: shell.Word, bound: AbstractSet[str], made: AbstractSet[str]) -> bool:
    """Whether a word's path is put together at run time from parts the guard does not see:
    `$'...'` (escapes); a variable whose value is made over several steps (`made`); or text
    from `$(...)`, backticks, a special parameter (`$1`, `$_`, `${1:-x}`, `$((...))`) or a
    variable the command sets, joined to anything else. A word that is exactly one `$(...)`
    is not: its command is checked, and a command that prints a path is the interpreter case
    the threat model accepts."""
    segs: List[Tuple[str, str]] = []
    for k, n, _ in w.segs:  # literal text joined (the lexer keeps it in pieces)
        if k == "lit" and segs and segs[-1][0] == "lit":
            segs[-1] = ("lit", segs[-1][1] + n)
        elif k != "lit" or n:
            segs.append((k, n))
    if segs and segs[0][0] == "lit":  # `X=$(...)`: the value after `=` counts, not the name
        m = shell.ASSIGNMENT.match(segs[0][1])
        if m:
            rest = segs[0][1][m.end():]
            segs = ([("lit", rest)] if rest else []) + segs[1:]
    if any(k == "ansi" or (k == "var" and n in made) for k, n in segs):
        return True
    mixed = [k for k, n in segs if k in ("sub", "special") or (k == "var" and n in bound)]
    return bool(mixed) and len(segs) > 1


def _dotdot_after_missing(path: str) -> bool:
    """Whether a `..` in `path` follows a folder that does not exist now: the command may make
    it (a link, as in `ln -s x s && cat s/../..`), and the kernel would then resolve the `..`
    from where that link points."""
    prefix = "/"
    for c in path.split("/"):
        if not c:
            continue
        if c == ".." and not os.path.lexists(prefix):
            return True
        prefix = os.path.join(prefix, c)
    return False


def _variants(values: List[str], w: shell.Word) -> List[str]:
    """Every spelling of a word to check: the word, its brace expansions, and the parts after
    `=` and `:` (as in `--file=PATH` and `host:PATH`)."""
    out: List[str] = []
    for v in values:
        forms = [v]
        if w.has_brace:
            try:
                forms += paths.expand_braces(v)
            except ValueError:
                forms.append("/")  # too many: count it as touching everything
        for f in forms:
            out.append(f)
            if f.startswith("-") and not f.startswith("--") and len(f) > 2:
                out.append(f[2:])  # a glued option value, as in -C../x or -o/path
            for sep in ("=", ":"):
                if sep in f:
                    out.extend(part for part in f.split(sep)[1:] if part)
    return out


_SEPARATORS = {";", "&&", "||", "|", "|&", "&", "\n", "(", ")", ";;"}
_SEQUENCE = {"", ";", "&&", "\n"}  # each step runs after the one before, in its folder
# words before a command that are not the command: reserved words, groups and prefixes
_KEYWORDS = {"{", "}", "!", "if", "then", "elif", "else", "fi", "do", "done", "while", "until",
             "time", "command", "builtin", "exec", "nohup"}
_FOLDER_CHANGE = ("cd", "pushd", "popd")
# programs that run in a folder an option names
_FOLDER_OPTIONS = {"git": ("-C",), "make": ("-C", "--directory"), "tar": ("-C", "--directory"),
                   "env": ("-C", "--chdir")}


class _Cmd(NamedTuple):
    words: List[shell.Word]  # from the command word on (keywords, assignments left out)
    all: List[shell.Word]  # every word, redirection targets too
    sep: str  # the operator before it
    keyword: bool  # it started with a keyword or a group


def _commands(parsed: shell.Parsed) -> List[_Cmd]:
    """The simple commands of a parsed line, in order."""
    out: List[_Cmd] = []
    words: List[shell.Word] = []
    every: List[shell.Word] = []
    sep, keyword = "", False
    for it in parsed.items:
        if isinstance(it, shell.Op):
            if it.text in _SEPARATORS:
                if every:
                    out.append(_Cmd(words, every, sep, keyword))
                words, every, sep, keyword = [], [], it.text, it.text in ("(", ")")
            elif it.target is not None:
                every.append(it.target)
            continue
        every.append(it)
        t = it.text()
        if not words and not it.has_dollar and t in _KEYWORDS:
            keyword = True
        elif words or not shell.ASSIGNMENT.match(t):
            words.append(it)
    if every:
        out.append(_Cmd(words, every, sep, keyword))
    return out


class _Folders(NamedTuple):
    per_command: List[List[str]]  # the folders each command may run in
    started: List[List[str]]  # the same before its own `-C` options: where their values are read
    option_values: Set[int]  # the words that are such values (by id)
    union: List[str]  # every folder the line may run in
    moved: bool  # it may run in a folder the guard cannot know
    changed: bool  # it changes folder at all


def _folders(parsed: shell.Parsed, cmds: List[_Cmd], cwds: List[str], env: Mapping[str, str],
             bound: Set[str], home: str) -> _Folders:
    """The folders each command may run in. A line of plain steps (`;`, `&&`, new lines, no
    group or keyword) follows its `cd`s in order; any other line may run every command in
    every folder it names. `cd` with no folder, or only `--`, is the home folder; `cd -`,
    `popd`, `pushd` without a folder, a folder built from variables, `find -execdir` and a
    `cd` word the guard does not read as a command mean a folder the guard cannot know."""
    linear = all(c.sep in _SEQUENCE and not c.keyword for c in cmds) and \
        not any(isinstance(it, shell.Op) and it.text in ("(", ")") for it in parsed.items)
    current, union = list(cwds), list(cwds)
    per: List[List[str]] = []
    started: List[List[str]] = []
    values: Set[int] = set()
    moved = changed = False
    command_words = {id(c.words[0]) for c in cmds if c.words}
    for w in parsed.words():
        if w.text() in _FOLDER_CHANGE and not w.has_dollar and id(w) not in command_words:
            moved = True  # `cd` where the guard does not see a command
    for c in cmds:
        here = list(current)
        new: Optional[List[str]] = None
        prog = c.words[0] if c.words else None
        name = prog.text().rsplit("/", 1)[-1] if prog else ""
        args = c.words[1:]
        if prog is not None and not prog.has_dollar and name in _FOLDER_CHANGE:
            changed = True
            targets = [a for a in args if a.text() == "-" or not a.text().startswith("-")]
            if name == "popd" or (name == "pushd" and not targets) or \
                    (targets and targets[0].text() == "-"):
                moved = True
            elif not targets:
                new = [home]
            else:
                new, unknown = _targets(targets[0], here, env, bound, home)
                moved = moved or unknown
        elif name in _FOLDER_OPTIONS:
            for i, a in enumerate(args):
                t = a.text()
                for opt in _FOLDER_OPTIONS[name]:
                    target = args[i + 1] if t == opt and i + 1 < len(args) else None
                    if target is None and t.startswith(opt + "=") and opt.startswith("--"):
                        target = shell.Word(a.raw, [("lit", t[len(opt) + 1:], False)])
                    if target is not None:
                        changed = True
                        values.add(id(target) if t == opt else id(a))  # `-C dir`, `--directory=dir`
                        dirs, unknown = _targets(target, here, env, bound, home)
                        moved = moved or unknown
                        here += [d for d in dirs or [] if d not in here]
                        union += [d for d in dirs or [] if d not in union]
        elif name == "find" and any(a.text() in ("-execdir", "-okdir") for a in args):
            moved = True  # it runs in the folder of every file it finds
        per.append(here)
        started.append(list(current))
        if new is not None:
            current = new if linear else current + [b for b in new if b not in current]
            union += [b for b in new if b not in union]
    if not linear:
        per = started = [union] * len(cmds)
    return _Folders(per, started, values, union, moved, changed)


def _targets(target: shell.Word, bases: List[str], env: Mapping[str, str], bound: Set[str],
             home: str) -> Tuple[Optional[List[str]], bool]:
    """The folders a `cd` (or `-C`) target names, and whether it is unknown. A target that is
    exactly one `$(...)` leaves the folders as they are (its command is checked); one built
    from variables or special parameters is unknown."""
    segs = [(k, n) for k, n, _ in target.segs if k != "lit" or n]
    if [k for k, _ in segs] == ["sub"]:
        return None, False
    values, unknown = shell.expand(target, env, bound, home)
    if unknown or any(k in ("sub", "special", "varx", "ansi") or (k == "var" and n in bound)
                      for k, n in segs):
        return None, True
    out: List[str] = []
    for v in _variants(values, target):
        found = paths.candidates(v or home, bases)
        # a glob target stays a pattern: the folders it names are not listed
        out += [paths.GlobBase(f) for f in found] if target.has_glob else found
    return out, False


def _through_missing(path: str) -> bool:
    """Whether a path goes through a name that does not exist now (a link or folder the line
    may make, which the kernel would then follow)."""
    prefix = "/"
    for c in [c for c in path.split("/") if c][:-1]:
        prefix = os.path.join(prefix, c)
        if c not in (".", "..") and not os.path.lexists(prefix):
            return True
    return False


