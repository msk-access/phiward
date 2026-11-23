"""Read Claude Code's settings files (never write them) and decide whether its sandbox confines
the agent's shell commands as phiward needs.

Confined means all of these hold, from the merged settings:
- `sandbox.enabled` is true;
- `sandbox.allowUnsandboxedCommands` is false (so the model cannot retry outside the sandbox);
- `sandbox.failIfUnavailable` is true (else commands run unsandboxed when the sandbox cannot
  start), and none of the settings in OPENERS is true (on macOS, `network.allowLocalBinding`
  too), and `network.allowMachLookup` is empty;
- `sandbox.filesystem.denyRead` and `denyWrite` cover every protected root (the root or a
  folder above it);
- `sandbox.filesystem.denyWrite` covers the phiward config and code (config.guard_files);
- `sandbox.excludedCommands` is empty (gateway calls are clients of the broker; they run in the
  sandbox like any command). `shell_reason`, the hook's reading, leaves this one out: while the
  list is non-empty (`excluded_entries`), the hook checks the text of every shell call instead;
- `sandbox.network.allowAllUnixSockets` is not true and `allowUnixSockets` is empty (a socket
  such as Docker's reaches a process outside the sandbox);
- no `sandbox.filesystem.allowRead` entry re-opens any part of a root. Claude Code applies the
  narrower of two overlapping read rules, so an allow inside the deny that covers a root, or at
  the same depth, re-opens it; an allow wider than that deny does not.

Paths use Claude Code's sandbox prefixes: `/` or `//` absolute, `~/` the home folder, `./` or no
prefix relative to the project folder (project files) or the user folder (user file). A relative
entry in a managed file has no known base: as a deny it covers nothing, as an allow it is taken
against both bases. A deny with a wildcard covers nothing; an allow with a wildcard counts from
its fixed part.
A protected pattern counts as denied by a wildcard entry: its literal start in the file
system's own spelling, then the pattern (or with `/**`), in denyRead and denyWrite; only on
macOS (`_patterns_unconfined`): elsewhere the sandbox cannot deny writes to a wildcard path.

Where the files are: managed settings and their `managed-settings.d`
drop-ins; project settings in `$CLAUDE_PROJECT_DIR` (Claude Code sets it for hooks; the shell's
working folder can be anywhere below it); user settings in `$CLAUDE_CONFIG_DIR`, else
`~/.claude`. Without `CLAUDE_PROJECT_DIR` the project files cannot be found, so the shell is not
treated as confined. Settings passed with `--settings` cannot be seen at all (a stated limit).
"""

import glob
import json
import os
import sys
from typing import Any, Callable, Dict, List, Mapping, NamedTuple, Optional, Sequence, Tuple

from phiward import config, pathmatch

MANAGED = ["/Library/Application Support/ClaudeCode/managed-settings.json",
           "/etc/claude-code/managed-settings.json"]


JSON_LIMIT = 64 * 1024 * 1024  # ~/.claude.json holds every project's history: it grows large


def read_json(path: str) -> Tuple[Optional[Dict[str, Any]], str, List[str]]:
    """The one reader of Claude Code's JSON files (settings, ~/.claude.json, .mcp.json):
    (the object, why it cannot be read, the keys given twice). As JSON.parse reads it: the last
    of two equal keys wins, no NaN, no byte-order mark. Through a link (a dotfiles setup), but
    only a regular file, never waiting on a FIFO, at most JSON_LIMIT bytes. An empty file is
    `{}`; a missing one is (None, "", [])."""
    from phiward import safeio
    try:
        text = safeio.read_text(path, limit=JSON_LIMIT, follow=True)
    except FileNotFoundError:
        return None, "", []
    except (OSError, ValueError) as exc:
        return None, type(exc).__name__, []
    if not text.strip():
        return {}, "", []
    twice: List[str] = []

    def pairs(items: List[Tuple[str, Any]]) -> Dict[str, Any]:
        seen = set()
        for k, _v in items:
            if k in seen and k not in twice:
                twice.append(k)
            seen.add(k)
        return dict(items)
    try:
        data = json.loads(text, object_pairs_hook=pairs, parse_constant=_no_constant)
    except ValueError as exc:
        return None, type(exc).__name__, []
    return (data, "", twice) if isinstance(data, dict) else (None, "not a JSON object", [])


def read_settings(path: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """(a settings file as a dict, why it cannot be read), as Claude Code reads it (`read_json`:
    a key given twice, the last one)."""
    data, why, _twice = read_json(path)
    return data, why


def _read(path: str) -> Optional[Dict[str, Any]]:
    """A settings file's JSON object, or None when it is missing or cannot be read."""
    return read_settings(path)[0]


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def user_dir(home: str, env: Optional[Mapping[str, str]] = None) -> str:
    env = os.environ if env is None else env
    return env.get("CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude")


# what bash and zsh read when they start (Claude Code makes its shell snapshot from them)
SHELL_STARTUP = (".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_aliases",
                 ".bash_logout", ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout")
_ZSH_STARTUP = (".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout")


def shell_code_paths(home: str, env: Optional[Mapping[str, str]] = None) -> List[str]:
    """What a shell runs before an agent's command: the bash and zsh startup files (also under
    `$ZDOTDIR`), the files `$BASH_ENV` and `$ENV` name, and Claude Code's shell snapshots (it
    sources one before each Bash command). A `phiward` function or alias planted there would
    stand in for phiward in a shell no kernel confines, so no file tool and no `exec` command
    may write them."""
    env = os.environ if env is None else env
    out = [os.path.join(home, n) for n in SHELL_STARTUP]
    zdot = env.get("ZDOTDIR", "")
    if zdot.startswith("/"):
        out += [os.path.join(zdot, n) for n in _ZSH_STARTUP]
    for name in ("BASH_ENV", "ENV"):
        v = env.get(name, "")
        if v.startswith("/"):
            out.append(v)
    out.append(os.path.join(user_dir(home, env), "shell-snapshots"))
    return list(dict.fromkeys(os.path.normpath(p) for p in out))


# variables a project's `env` must not set: they choose what the hook reads (where phiward's
# config and spool are, the ticket and user names its hidden list uses), make the shell that
# starts a hook run code (SHELLOPTS=xtrace with a PS4 that holds `$(...)`, exported functions,
# BASH_ENV, ENV), choose the `phiward` the plugin's and project hooks start by name (PATH), or
# the project whose settings the hook reads (CLAUDE_PROJECT_DIR). The hook refuses every call while
# one is set; it cannot undo what such a shell already ran, which is why the agent may not write
# these files (docs/threat-model.md, "A project's settings can run code before phiward starts").
# Not here: PYTHON*, __PYVENV_LAUNCHER__, LD_* and DYLD_* (the hooks unset them before phiward
# starts; projects set PYTHONPATH and LD_LIBRARY_PATH for their own builds; the loader ones
# reach the shell and awk first, which `doctor` reports and the threat model states), and HOME,
# TMPDIR, XDG_* and CLAUDE_CONFIG_DIR (Claude Code itself ignores them in a project's `env`).
REDIRECT_PREFIXES = ("PHIWARD_", "KRB5", "BASH_FUNC_")
REDIRECT_NAMES = ("USER", "LOGNAME", "PATH", "SHELLOPTS", "BASHOPTS", "PS4", "BASH_ENV", "ENV",
                  "PROMPT_COMMAND", "IFS", "CDPATH", "GLOBIGNORE", "CLAUDE_PROJECT_DIR",
                  # a project's prefix or shell wins over the user's (part 1 of the plan)
                  "CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_CODE_SHELL")


def project_files(project: str, home: str) -> List[str]:
    """The project's settings files Claude Code may read for a session in `project`: its
    `settings.json`, and every `settings.local.json` it may read (`local_candidates`). In a
    session opened in the home folder the project's `settings.json` is the user settings file,
    the operator's own (where `install` pins the shell): it is not a project's."""
    shared = os.path.join(project, ".claude", "settings.json")
    user = os.path.join(user_dir(home), "settings.json")
    own = os.path.realpath(shared) == os.path.realpath(user)
    return ([] if own else [shared]) + local_candidates(project, home)


def redirect_text(found: List[str]) -> str:
    """`project_redirects` in words, for the hook's refusal and `doctor`."""
    keys = ", ".join("env." + k for k in found if not k.startswith("unreadable:"))
    bad = [k.split(":", 1)[1] for k in found if k.startswith("unreadable:")]
    parts = ([f"set {keys}"] if keys else []) + (
        ["have a settings file that cannot be read as JSON (" + ", ".join(bad) + ")"]
        if bad else [])
    return "this project's Claude Code settings " + " and ".join(parts)


def project_folders(cwd: str, home: str) -> List[str]:
    """The project folders a call may belong to: `$CLAUDE_PROJECT_DIR`, and every folder at or
    above `cwd` that holds `.claude` or `.git` (not the home folder, whose `.claude` is the
    user's). Not only the nearest one: a submodule or a folder with its own `.claude` inside the
    project must not hide the project's own settings. A project's `env` could point
    `$CLAUDE_PROJECT_DIR` elsewhere: the call's own folders are read too."""
    out: List[str] = []
    named = os.environ.get("CLAUDE_PROJECT_DIR")
    if named:
        out.append(named)
    d = os.path.abspath(cwd) if cwd else ""
    top = os.path.realpath(home)
    while d:
        if os.path.realpath(d) != top and \
                any(os.path.lexists(os.path.join(d, x)) for x in (".claude", ".git")) and \
                not any(os.path.realpath(o) == os.path.realpath(d) for o in out):
            out.append(d)
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return out


def _holds(top: str, path: str) -> bool:
    """Whether `path` is `top` or below it, compared in canonical spelling (letter case and
    Unicode form as the volume stores them)."""
    from phiward import pathid
    a, b = pathid.canon(os.path.abspath(top)), pathid.canon(os.path.abspath(path))
    return b == a or b.startswith(a.rstrip("/") + "/")


def named_project_holds(cwd: str) -> bool:
    """Whether `$CLAUDE_PROJECT_DIR` is set and is `cwd` or a folder above it. When it is not,
    the settings Claude Code reads may be in a folder phiward cannot find from the call."""
    named = os.environ.get("CLAUDE_PROJECT_DIR")
    return bool(named and cwd and _holds(named, cwd))


def confining_folders(cwd: str, home: str) -> List[str]:
    """The project folders whose settings must confine the shell for a call in `cwd`: the
    named project and the folders in it at or above `cwd` (a nested repository or `.claude`).
    A folder above the named project is not one Claude Code reads for this session (its
    `env` is still read for redirects: `project_folders`)."""
    named = os.environ.get("CLAUDE_PROJECT_DIR")
    if not named:
        return []
    return [f for f in project_folders(cwd, home) if f == named or _holds(named, f)]


def project_redirects(project: str, home: str) -> List[str]:
    """The `env` keys of the project's settings that are REDIRECTs, and "unreadable:<file>"
    for a settings file that exists but does not parse (its `env` cannot be seen)."""
    return _project_env(project, home,
                        lambda k: k.startswith(REDIRECT_PREFIXES) or k in REDIRECT_NAMES,
                        unreadable=True)


# cleared by the hooks, but read by sh and awk before they are cleared: the dynamic loader's and
# glibc's own (character set modules, locale files), and the memory allocator's (macOS
# `MallocLogFile` writes a file)
LOADER_PREFIXES = ("LD_", "DYLD_", "MALLOC_", "Malloc")
LOADER_NAMES = ("GCONV_PATH", "LOCPATH")


def project_loader_keys(project: str, home: str) -> List[str]:
    """The `env` keys of the project's settings that the hook's shell reads before they are
    cleared."""
    return _project_env(project, home,
                        lambda k: k.startswith(LOADER_PREFIXES) or k in LOADER_NAMES,
                        unreadable=False)


def _project_env(project: str, home: str, wanted: Callable[[str], bool], *,
                 unreadable: bool) -> List[str]:
    found: List[str] = []
    for f in project_files(project, home):
        data = _read(f)
        if data is None:
            if unreadable and os.path.lexists(f):
                found.append(f"unreadable:{f}")
            continue
        env = data.get("env")
        if isinstance(env, dict):
            found += [k for k in env if wanted(k) and k not in found]
    return found


def _owned(path: str) -> bool:
    try:
        return os.stat(path, follow_symlinks=False).st_uid == os.getuid()
    except FileNotFoundError:
        return True  # missing: nothing to own
    except OSError:
        return False  # cannot be checked: not counted as this user's


def _repo_root(dot: str, home: str) -> Optional[str]:
    """The folder git takes as the repository's root for the `.git` entry `dot` (for a linked
    worktree, the main checkout), or None when git would not accept it. A `.git` file counts
    only as git counts it: a worktree's `gitdir` names a folder directly under
    `<common>/worktrees/`, whose own `gitdir` file points back to `dot`, in a common git folder
    that is a real one (`config._sane_git_dir`); a submodule's names a real git folder."""
    if os.path.isdir(dot):  # a folder, or a link to one (git follows it)
        return os.path.dirname(dot) if _is_repository(dot) else None
    if not os.path.isfile(dot):
        return None
    dirs = config.git_dirs(dot)
    if len(dirs) < 2 or not config._sane_git_dir(dirs[1], home):
        return None
    entry = os.path.realpath(dirs[1])
    if os.path.basename(os.path.dirname(entry)) != "worktrees":
        return os.path.dirname(dot)  # a submodule: its own work tree is the root
    common = os.path.dirname(os.path.dirname(entry))
    back = _read_line(os.path.join(entry, "gitdir"))
    # git 2.48+ may write it relative to its own folder (`worktree.useRelativePaths`)
    if not back or os.path.realpath(os.path.join(entry, back)) != os.path.realpath(dot) \
            or not config._sane_git_dir(common, home) or os.path.basename(common) != ".git":
        return None
    return os.path.dirname(common)


def git_redirects(project: str, home: str) -> List[str]:
    """Where git would take its config and hooks from for `project` when that is a folder the
    session can write and not inside a repository's own `.git` folder: a `commondir` in the
    project's `.git`, or a `.git` file whose git folder (or the common folder it leads to) lies
    there. Each as "FILE -> FOLDER", for doctor and the session note. A report, not a guard: the
    shell writes these before any hook sees them (docs/threat-model.md, git's control files)."""
    writable = [w.rstrip("/") + "/" for w in agent_writable(project, home)]

    def open_to_agent(d: str) -> bool:
        r = os.path.realpath(d)
        if ".git" in r.split("/"):
            return False  # inside a repository's own git folder: git made it there
        return any((r.rstrip("/") + "/").startswith(w) for w in writable)

    out: List[str] = []
    for dot in config.enclosing_git_dirs(project):
        if os.path.isdir(dot):
            common = os.path.join(dot, "commondir")
            # `.` (Claude Code's env scrub writes it on Linux): git's common folder is then this
            # folder itself, as with no commondir. Only the exact forms with trailing newlines
            # pass; anything else is reported, also forms git reads the same way (`.\r\n`)
            if os.path.lexists(common) and _read_raw(common).rstrip("\n") not in (".", "./", "./."):
                text = _read_line(common)
                out.append(f"{common} -> {os.path.realpath(os.path.join(dot, text)) if text else '?'}")
            continue
        for d in config.git_dirs(dot)[1:]:
            if open_to_agent(d):
                out.append(f"{dot} -> {os.path.realpath(d)}")
                break
    return out


def _is_repository(d: str) -> bool:
    """A `.git` folder git itself takes as a repository: HEAD, objects/ and refs/."""
    return (os.path.isfile(os.path.join(d, "HEAD")) and os.path.isdir(os.path.join(d, "objects"))
            and os.path.isdir(os.path.join(d, "refs")))


def _read_line(path: str) -> str:
    try:
        return _read_raw(path).strip().splitlines()[0]
    except IndexError:
        return ""


def _read_raw(path: str) -> str:
    """The file's text as it is, or "" when it cannot be read."""
    from phiward import safeio
    try:
        return safeio.read_text(path, limit=4096)
    except (OSError, UnicodeDecodeError, ValueError):
        return ""


def local_file(project: str, home: str) -> str:
    """The `settings.local.json` Claude Code reads for a session in `project`: at the git
    repository's root (`_repo_root`), or in the project folder when there is no repository
    (an invalid `.git` file: git refuses it), the root is the home folder, or the root, its
    `.git` or `.claude` is not owned by this user. An invalid `.git` folder is passed over, as
    git passes over it."""
    fallback = os.path.join(project, ".claude", "settings.local.json")
    for dot in config.enclosing_git_dirs(project):
        if os.path.isdir(dot) and not _is_repository(dot):
            continue
        root = _repo_root(dot, home)
        if root is None or os.path.realpath(root) == os.path.realpath(home) or not all(
                _owned(p) for p in (root, os.path.join(root, ".git"),
                                    os.path.join(root, ".claude"))):
            return fallback
        return os.path.join(root, ".claude", "settings.local.json")
    return fallback


def local_candidates(project: str, home: str) -> List[str]:
    """Every `settings.local.json` that Claude Code may read for `project`, the one it reads
    (`local_file`) first: the project folder's, and that of each enclosing work tree whose
    root and `.git` are this user's (another user's folder above cannot change the verdict).
    The others may only make the confinement check stricter."""
    out = [local_file(project, home), os.path.join(project, ".claude", "settings.local.json")]
    for dot in config.enclosing_git_dirs(project):
        root = os.path.dirname(dot)
        if _owned(root) and _owned(dot):
            out.append(os.path.join(root, ".claude", "settings.local.json"))
    return list(dict.fromkeys(out))


INSTALL_STEP = "the operator runs `(cd ~ && phiward install claude --user --write)`"
# the excludedCommands entries an older phiward wrote; install removes them (`install.merge`),
# so a list of only these is one install fixes
OLD_EXCLUDES = ["phiward run *", "phiward copy *",
                "python3 -m phiward run *", "python3 -m phiward copy *"]


def install_removes(entry: Any) -> bool:
    """Whether `install claude --user --write` removes this excludedCommands entry."""
    return entry in OLD_EXCLUDES


def _only_old_excludes(node: Any) -> bool:
    return isinstance(node, list) and all(install_removes(c) for c in node)


class Reason(NamedTuple):
    """Why the shell is not confined, and the one step that fixes it (the same in the hook's
    refusal and in doctor)."""
    text: str
    step: str


def levels(project: Optional[str], home: str, env: Optional[Mapping[str, str]] = None,
           local: str = "") -> List[Tuple[str, str, Optional[Dict[str, Any]]]]:
    """(level, path, data) from the highest precedence down. `project` is the project folder
    ($CLAUDE_PROJECT_DIR), or None when it is not known; `local`, the `settings.local.json` to
    take as the one read (default: `local_file`)."""
    files = []
    for m in MANAGED:
        # the drop-ins merge on top of the base file in name order, so the last one wins: listed
        # first here (highest precedence first)
        files += [("managed", p) for p in sorted(
            glob.glob(os.path.join(os.path.dirname(m), "managed-settings.d", "*.json")),
            reverse=True)]
        files.append(("managed", m))
    if project:
        files += [("project local", local or local_file(project, home)),
                  ("project", os.path.join(project, ".claude", "settings.json"))]
    files.append(("user", os.path.join(user_dir(home, env), "settings.json")))
    return [(lvl, p, _read(p)) for lvl, p in files]


def _at(data: Any, keys: Sequence[str]) -> Any:
    """`data[k1][k2]...`, or None where a step is not an object."""
    for k in keys:
        data = data.get(k) if isinstance(data, dict) else None
    return data


def _first(levels_: Sequence[Tuple[str, str, Optional[Dict[str, Any]]]], *keys: str) -> Any:
    for _, _, data in levels_:
        node = _at(data, keys)
        if node is not None:
            return node
    return None


def _merged_list(levels_, *keys: str) -> List[str]:
    out: List[str] = []
    for _, _, data in levels_:
        node = _at(data, keys)
        if isinstance(node, list):
            out += [str(v) for v in node if str(v) not in out]
    return out


def _shown_file(path: str, project: str, home: str) -> str:
    """A settings file or folder as the operator knows it: relative to the project, or `~/...`
    (always `~/...` in a session started from the home folder)."""
    if project and home and os.path.normpath(project) == os.path.normpath(home):
        project = ""
    for base, lead in ((project, ""), (home, "~/")):
        if base and path.startswith(base.rstrip("/") + "/"):
            return lead + os.path.relpath(path, base)
    return path


def _bases(level: str, project: str, home: str, env: Optional[Mapping[str, str]]) -> List[str]:
    if level.startswith("project"):
        return [project]
    if level == "user":
        return [user_dir(home, env)]
    return [project, user_dir(home, env)]  # managed: unknown


def _resolve(entry: str, bases: Sequence[str], home: str) -> List[str]:
    if entry.startswith("//"):
        entry = entry[1:]
    if entry.startswith("/"):
        return [entry]
    if entry == "~" or entry.startswith("~/"):
        return [home + entry[1:]]
    return [os.path.join(b, entry) for b in bases]


def _fixed_dir(p: str) -> str:
    """The deepest folder of a glob pattern with no wildcard in it."""
    cut = min([i for i in (p.find("*"), p.find("?"), p.find("[")) if i >= 0] or [len(p)])
    return p[:cut].rsplit("/", 1)[0] or "/"


def _paths(levels_, project: str, home: str, env, key: str, deny: bool) -> List[str]:
    """Every entry of sandbox.filesystem.<key> as absolute paths, in both spellings."""
    out: List[str] = []
    for level, _, data in levels_:
        node = _at(data, ("sandbox", "filesystem", key))
        if not isinstance(node, list):
            continue
        for v in node:
            v = str(v)
            wild = any(c in v for c in "*?[")
            if deny and wild:
                continue
            bases = _bases(level, project, home, env)
            if deny and level == "managed" and not v.startswith(("/", "~")):
                continue
            if wild:  # an allow pattern stays a pattern; _reopened matches it
                for p in _resolve(v, bases, home):
                    fixed = _fixed_dir(p)
                    for sp in {os.path.normpath(fixed), os.path.realpath(fixed)}:
                        pat = sp.rstrip("/") + "/" + p[len(fixed):].lstrip("/")
                        if pat not in out:
                            out.append(pat)
                continue
            for p in _resolve(v, bases, home):
                for sp in (os.path.normpath(p), os.path.realpath(p)):
                    if sp not in out:
                        out.append(sp)
    return out


def _inside(p: str, folder: str) -> bool:
    """Whether the deny entry `folder` covers `p`. "Covered" relaxes the hook, so this is
    strict: the entry counts only when it is written in the file system's own spelling (the one
    the kernel compares), and `p`, in that spelling, is it or inside it."""
    from phiward import pathid
    if pathid.canon(folder) != folder:
        return False
    p = pathid.canon(p)
    return p == folder or p.startswith(folder.rstrip("/") + "/")


def _spell(p: str) -> List[str]:
    return list({os.path.normpath(p), os.path.realpath(p)})


def _covers(deny: Sequence[str], root: str) -> bool:
    return any(_inside(s, d) for s in _spell(root) for d in deny)


def _reopened(root: str, deny: Sequence[str], allow: Sequence[str]) -> bool:
    """Whether an allowRead entry re-opens part of `root`: the allow overlaps the root and is
    not wider than the narrowest deny that covers the root. A glob entry re-opens it when it can
    match the root or a path inside it."""
    for s in _spell(root):
        covering = [d for d in deny if _inside(s, d)]
        if not covering:
            continue
        narrowest = max(covering, key=len)
        for a in allow:
            if _wild(a):
                if _reaches_into(pathmatch.fold(a), pathmatch.fold(s)):
                    return True
                continue
            overlaps = _inside(a, s) or _inside(s, a)
            if overlaps and _inside(a, narrowest):  # as narrow as the deny, or narrower
                return True
    return False


# sandbox settings that let a sandboxed command reach past the sandbox: with any of them true,
# the shell does not count as confined
OPENERS = (("filesystem", "disabled"), ("enableWeakerNestedSandbox",), ("allowAppleEvents",),
           ("allowNestedUserNamespaces",))
# macOS only (read when the check runs): there it lets a sandboxed command reach every service
# on localhost; on Linux a sandboxed command's localhost is its own and the key has no effect
# (Claude Code's docs, sandboxing)
LOCAL_BINDING = ("network", "allowLocalBinding")
LOCAL_BINDING_STEP = ("a dev server runs in your own terminal, or in a folder with no PHI that "
                      "the operator lists in [no_phi] folders (user config), not in the "
                      "session's shell (on macOS this key lets a sandboxed command reach every "
                      "local service): ")


def _opened(lv, excluded_opens: bool = True) -> Optional[Tuple[str, Tuple[str, ...], bool]]:
    """Why these settings let a sandboxed command reach past the sandbox: (the reason, the keys
    under `sandbox`, whether it is a list), or None. `excluded_opens`: whether a non-empty
    `excludedCommands` counts (`shell_reason` leaves it to the hook's text check)."""
    for keys in OPENERS + ((LOCAL_BINDING,) if sys.platform == "darwin" else ()):
        if _first(lv, "sandbox", *keys) is True:
            return f"sandbox.{'.'.join(keys)} is true (it opens the sandbox)", tuple(keys), False
    if excluded_opens and _merged_list(lv, "sandbox", "excludedCommands"):
        return "sandbox.excludedCommands is not empty", ("excludedCommands",), True
    if _first(lv, "sandbox", "network", "allowAllUnixSockets") is True:
        return ("sandbox.network.allowAllUnixSockets is true",
                ("network", "allowAllUnixSockets"), False)
    if _merged_list(lv, "sandbox", "network", "allowUnixSockets"):
        return ("sandbox.network.allowUnixSockets is not empty",
                ("network", "allowUnixSockets"), True)
    if _merged_list(lv, "sandbox", "network", "allowMachLookup"):
        return ("sandbox.network.allowMachLookup is not empty (a listed service acts outside "
                "the sandbox)", ("network", "allowMachLookup"), True)
    return None


def _globs(levels_, project: str, home: str, env, key: str) -> List[str]:
    """The wildcard entries of sandbox.filesystem.<key>, as absolute paths."""
    out: List[str] = []
    for level, _, data in levels_:
        node = _at(data, ("sandbox", "filesystem", key))
        for v in node if isinstance(node, list) else []:
            v = str(v)
            # not `_wild`: a deny entry counts only as written (a brace is an ordinary character
            # to the sandbox), while an allow entry with a brace is read widely (`_reaches_into`)
            if any(c in v for c in "*?[") and not (level == "managed" and v[:1] not in "/~"):
                out += [p for p in _resolve(v, _bases(level, project, home, env), home)
                        if p not in out]
    return out


def pattern_entries(pattern: str) -> List[str]:
    """The sandbox entries that deny a protected pattern: its literal start in the file system's
    own spelling, then the pattern, and the same with `/**` (what is inside a match)."""
    from phiward import paths
    form = paths.canon_prefix(pattern).rstrip("/")
    return [form, form + "/**"]


def _wild(entry: str) -> bool:
    """Whether a sandbox entry may be a wildcard: `*`, `?`, `[`, or `{` (taken as one, in case
    the sandbox expands braces)."""
    return any(c in entry for c in "*?[{")


def _parts_meet(a: str, p: str) -> bool:
    """Whether one name can match both parts (taken widely when both may hold a wildcard)."""
    if not _wild(a):
        return pathmatch.match_part(p, a)
    if not _wild(p) and "{" not in a:
        return pathmatch.match_part(a, p)
    return True


def _reaches_into(allow: str, pattern: str) -> bool:
    """Whether an allowRead entry can name a match of `pattern` or a path inside one: its parts
    meet the pattern's one by one (a `**` meets whatever follows) and it goes as deep as a match
    or deeper. A wildcard entry whose literal start is at or below the pattern's literal start
    counts too (taken widely). An entry that ends above every match is wider than the deny, which
    holds under it (docs: a wildcard deny holds under a wider allowRead)."""
    p = pathmatch.parts(pattern)
    a = pathmatch.parts(allow)
    if _wild(allow) and ".." in a:
        return True  # where a `..` after a wildcard lands is not known here
    if _wild(allow):
        head = p[:next((i for i, c in enumerate(p) if "*" in c), len(p))]
        if pathmatch.parts(_fixed_dir(allow))[:len(head)] == head:
            return True
    for i, part in enumerate(a):
        if "**" in part or (i < len(p) and "**" in p[i]):
            return True
        if i >= len(p):
            return True  # inside a match
        if not _parts_meet(part, p[i]):
            return False
    return len(a) >= len(p)


def _pattern_step(version: Optional[Tuple[int, int, int]]) -> str:
    """The step for pattern entries the sandbox lacks: install writes them only for Claude Code
    VERSION_PATTERNS or newer, as `claude --version` tells it in the operator's terminal."""
    need = version_text(VERSION_PATTERNS)
    if version is None:
        return (f"{INSTALL_STEP} in a terminal where `claude --version` prints {need} or newer "
                "(update Claude Code first if it is older)")
    if version < VERSION_PATTERNS:
        return (f"the operator updates Claude Code to {need} or newer, then runs `phiward "
                "install claude --user --write` (or protects folders instead of patterns)")
    return INSTALL_STEP


def _patterns_unconfined(lv, project: str, home: str, env, patterns: Sequence[str],
                         version: Optional[Tuple[int, int, int]] = None) -> Optional[Reason]:
    """Why the sandbox settings leave a protected pattern open, or None. Only macOS's sandbox can
    deny writes to a wildcard path (on Linux only a trailing `/**` works, and a match made while
    a command runs is readable in it: docs/threat-model.md)."""
    if not patterns:
        return None
    if sys.platform != "darwin":
        return Reason("Claude Code's sandbox cannot deny writes to a protected pattern on this "
                      "system (only a trailing /** works here)",
                      "the operator protects the folders instead of patterns ([protected_paths] "
                      "roots), or runs the agent under `phiward launch`")
    for key in ("denyRead", "denyWrite"):
        have = set(_globs(lv, project, home, env, key))
        # both: the pattern (a match itself) and `pattern/**` (what is inside one)
        miss = [p for p in patterns if not set(pattern_entries(p)) <= have]
        if miss:
            return Reason(f"sandbox.filesystem.{key} does not cover {len(miss)} protected "
                          "pattern(s)", _pattern_step(version))
    for level in lv:
        allow = _paths([level], project, home, env, "allowRead", deny=False)
        if any(_reaches_into(a, pathmatch.fold(pattern_entries(p)[0]))
               for a in map(pathmatch.fold, allow) for p in patterns):
            return Reason("sandbox.filesystem.allowRead re-opens part of a protected pattern's "
                          "matches", _step_in(level[0], level[1], project, home, env,
                                              "that allowRead entry", False))
    return None


def _env_value(project: str, home: str, env: Optional[Mapping[str, str]], name: str) -> Tuple[Optional[str], str]:
    """(the value Claude Code takes for `env.<name>`, why it cannot tell): it must be the same
    whichever `settings.local.json` Claude Code reads, and every settings file must parse."""
    found: List[Optional[str]] = []
    for local in local_candidates(project, home):
        lv = levels(project, home, env, local)
        for _l, f, data in lv:
            if data is None and os.path.lexists(f):
                return None, f"{f} cannot be read as JSON"
        value = _first(lv, "env", name)
        found.append(value if isinstance(value, str) else None)
    if len(set(found)) != 1:
        return None, f"env.{name} differs between the settings.local.json files Claude Code may read"
    return found[0], ""


# the files of a project folder that change what Claude Code runs (hooks, sandbox, MCP servers)
PROJECT_FILES = (".claude/settings.json", ".claude/settings.local.json", ".mcp.json")


def bash_pinned(project: Optional[str], home: str,
                env: Optional[Mapping[str, str]] = None) -> bool:
    """Whether the settings Claude Code reads set its shell to /bin/bash (part 4 of the plan)."""
    return bool(project) and _env_value(project or "", home, env, "CLAUDE_CODE_SHELL")[0] == BASH


BASH = "/bin/bash"
# the Claude Code versions a setting needs (docs: settings reference; part 1 of the plan)
VERSION_PATTERNS = (2, 1, 236)  # macOS: a wildcard denyRead holds under a wider allowRead
VERSION_BLOCK_READS = (2, 1, 257)  # permissions.blockReadsOutsideWorkingDirectories
VERSION_DENY_PROMPTS = (2, 1, 319)  # permissions.denyInsteadOfPrompting
# a hook's `onFailure` (2.1.295), and `args` (exec form, older than that): `launch` refuses an
# older Claude Code, on every platform
VERSION_HOOK_ARGS = (2, 1, 295)


def version_text(version: Tuple[int, int, int]) -> str:
    return ".".join(map(str, version))


def claude_version() -> Optional[Tuple[int, int, int]]:
    """The installed Claude Code's version (`claude --version`), or None when it cannot tell."""
    import re
    import shutil
    import subprocess
    from phiward import service
    # never a `claude` the agent could have planted: the PATH folders the broker searches, but
    # a tool's own clone in the home folder (nvm, asdf) counts (the agent's sandbox does not
    # write it); found only elsewhere, the version is unknown and nothing runs
    path = os.environ.get("PATH", "")
    exe = shutil.which("claude", path=":".join(
        service.path_entries(path, service.path_inputs(), work_trees=False)))
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=20,
                             stdin=subprocess.DEVNULL).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.match(r"\s*(\d+)\.(\d+)\.(\d+)", out)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _user_file(home: str, env: Optional[Mapping[str, str]]) -> str:
    return os.path.join(user_dir(home, env), "settings.json")


def _step_in(level: str, f: str, project: str, home: str, env: Optional[Mapping[str, str]],
             what: str, install_fixes: bool) -> str:
    """The step for `what` (a setting, or "that ... entry") set in the settings file `f`."""
    if level == "managed":
        return f"an admin changes the managed settings ({f})"
    if install_fixes and os.path.normpath(f) == os.path.normpath(_user_file(home, env)):
        return INSTALL_STEP
    return (f"the operator removes {what} from {_shown_file(f, project, home)} (install never "
            "removes it)" if not install_fixes else
            f"the operator removes {what} from {_shown_file(f, project, home)}")


def _step_for(lv, project: str, home: str, env: Optional[Mapping[str, str]], keys: Sequence[str],
              install_fixes: Any, merged: bool = False) -> str:
    """The step for a setting by the file whose value Claude Code uses (`merged`: the first file
    with a non-empty list); none at all: install, which writes the user file. `install_fixes`:
    whether install sets or removes it, or a function of the value that says so."""
    for level, f, data in lv:
        node = _at(data, keys)
        if node is None or (merged and not node):
            continue
        fixes = install_fixes(node) if callable(install_fixes) else install_fixes
        return _step_in(level, f, project, home, env, ".".join(keys), bool(fixes))
    return INSTALL_STEP


def confinement_reason(project: Optional[str], home: str, roots: Sequence[str],
                       patterns: Sequence[str],
                guard: Sequence[str] = (), env: Optional[Mapping[str, str]] = None,
                hidden: Sequence[str] = (),
                user_data: Optional[Dict[str, Any]] = None,
                version: Optional[Tuple[int, int, int]] = None,
                excluded_opens: bool = True) -> Optional[Reason]:
    """Why the shell is not confined, with its step, or None. `excluded_opens`: whether a
    non-empty `excludedCommands` counts (`shell_reason`). `user_data`: the user settings to take in place of the file (what
    `install claude --user --write` would write, for doctor), in every level whose file is the user
    file (a session started from the home folder reads it as its project file too). `version`:
    the Claude Code version when it is known (doctor; the hook cannot run `claude --version`),
    for the step of a pattern the sandbox does not cover. `hidden`: the hidden list's paths that exist; the sandbox must deny
    reading every one, or the shell does not count as confined and the hook checks its text
    (an older install left credentials readable to Bash). It must hold whichever of the
    `settings.local.json` files Claude Code may read is the one it reads (`local_candidates`):
    a file the agent can choose (with a planted `.git`) cannot make the shell count as
    confined. A settings file that exists but does not parse means not confined."""
    if sys.platform.startswith("win"):
        return Reason("Claude Code runs commands unsandboxed on native Windows",
                      "run Claude Code in WSL")
    if not project:
        return Reason("$CLAUDE_PROJECT_DIR is not set, so the project's Claude Code settings "
                      "cannot be read", NO_PROJECT_STEP)
    for w in session_write_places(project, home):
        why = startup_write_problem(w, home)
        if why:
            where = "the session's folder" if os.path.realpath(w) == os.path.realpath(project) \
                else f"the write place {_shown_file(w, project, home)}"
            return Reason(f"Claude Code's sandbox may write {where}, and {why}: a shell command "
                          "could set up a program that runs later with your rights",
                          "open Claude Code in a project folder, and keep your home folder, "
                          "~/.config, ~/.local/bin and ~/Library/LaunchAgents out of "
                          "allowWrite and additionalDirectories")
    candidates = local_candidates(project, home)
    for local in candidates:
        lv = levels(project, home, env, local)
        if user_data is not None:
            mine = os.path.normpath(_user_file(home, env))  # install replaces the file there
            lv = [(lvl, f, user_data if os.path.normpath(f) == mine else d) for lvl, f, d in lv]
        r = _confined_with(lv, project, home, roots, patterns, guard, env, hidden, version,
                           excluded_opens)
        if r is not None:
            if local != candidates[0]:  # not the file Claude Code is thought to read
                r = Reason(f"{r.text}, with {local} as the settings.local.json Claude Code may "
                           "read", r.step)
            return r
    return None


def shell_reason(project: Optional[str], home: str, roots: Sequence[str],
                 patterns: Sequence[str], guard: Sequence[str] = (),
                 env: Optional[Mapping[str, str]] = None,
                 hidden: Sequence[str] = ()) -> Optional[Reason]:
    """For the hook only: `confinement_reason` without `excludedCommands`. Claude Code matches
    an entry against each call's text with its own parser, which phiward does not copy; while
    the list is non-empty (`excluded_entries`), the hook checks the text of every shell call
    instead of refusing the whole shell. Every other cause still means not confined."""
    return confinement_reason(project, home, roots, patterns, guard, env, hidden,
                              excluded_opens=False)


def excluded_entries(project: Optional[str], home: str,
                     env: Optional[Mapping[str, str]] = None) -> List[str]:
    """The merged `sandbox.excludedCommands` of every level phiward reads, with each
    `settings.local.json` Claude Code may read (`local_candidates`). Only "non-empty" is used.
    An MDM profile, server-managed settings and `--settings` are not read here
    (docs/threat-model.md)."""
    out: List[str] = []
    for local in (local_candidates(project, home) if project else [""]):
        out += [e for e in _merged_list(levels(project, home, env, local), "sandbox",
                                        "excludedCommands") if e not in out]
    return out


def excluded_step(project: Optional[str], home: str,
                  env: Optional[Mapping[str, str]] = None) -> Tuple[str, str]:
    """(the file that holds an `excludedCommands` entry, as the operator knows it; the step that
    empties it), from the first level with a non-empty list, or ("", "")."""
    for local in (local_candidates(project, home) if project else [""]):
        lv = levels(project, home, env, local)
        for level in lv:
            if _merged_list([level], "sandbox", "excludedCommands"):
                return (_shown_file(level[1], project or "", home),
                        _step_for(lv, project or "", home, env, ("sandbox", "excludedCommands"),
                                  _only_old_excludes, True))
    return "", ""


def launch_sandbox_reason(project: str, home: str, env: Optional[Mapping[str, str]],
                          flag: Dict[str, Any]) -> Optional[str]:
    """`phiward launch` below Landlock ABI 9: why Claude Code's sandbox, with `flag` given by
    `--settings` (below managed settings, above every file), would not keep Bash from unix
    sockets, or None. Every `settings.local.json` Claude Code may read counts. A file that
    does not parse counts as opening it."""
    for local in local_candidates(project, home):
        lv = levels(project, home, env, local)
        managed = [x for x in lv if x[0] == "managed"]
        lv = managed + [("command line", "--settings", flag)] + lv[len(managed):]
        for _l, f, data in lv:
            if data is None and os.path.lexists(f):
                return f"{_shown_file(f, project, home)} cannot be read as JSON"
        for key, want in (("enabled", True), ("allowUnsandboxedCommands", False),
                          ("failIfUnavailable", True)):
            if _first(lv, "sandbox", key) is not want:
                return f"the managed settings set sandbox.{key}"
        opened = _opened(lv)
        if opened:
            return (f"Claude Code's settings open its sandbox ({opened[0]}), so Bash could reach "
                    "unix sockets outside the session; remove that setting")
    return None


NO_PROJECT_STEP = "update Claude Code (it gives hooks $CLAUDE_PROJECT_DIR)"
OUTSIDE_PROJECT_STEP = "run the command inside the project folder ($CLAUDE_PROJECT_DIR)"


def _confined_with(lv, project: str, home: str, roots: Sequence[str], patterns: Sequence[str],
                   guard: Sequence[str], env: Optional[Mapping[str, str]],
                   hidden: Sequence[str],
                   version: Optional[Tuple[int, int, int]] = None,
                   excluded_opens: bool = True) -> Optional[Reason]:
    """`confinement_reason` for one set of settings files (`levels`)."""
    for _l, f, data in lv:
        if data is None and os.path.lexists(f):
            return Reason(f"{f} cannot be read as JSON",
                          f"the operator fixes or removes {_shown_file(f, project, home)}")
    for key, want, text in (("enabled", True, "sandbox.enabled is not true"),
                            ("allowUnsandboxedCommands", False,
                             "sandbox.allowUnsandboxedCommands is not false"),
                            ("failIfUnavailable", True,
                             "sandbox.failIfUnavailable is not true (without it, commands run "
                             "unsandboxed when the sandbox cannot start)")):
        if _first(lv, "sandbox", key) is not want:
            # install sets these three in the user file
            return Reason(text, _step_for(lv, project, home, env, ("sandbox", key), True))
    opened = _opened(lv, excluded_opens)
    if opened:
        text, keys, merged = opened
        fixes = _only_old_excludes if keys == ("excludedCommands",) else False
        step = _step_for(lv, project, home, env, ("sandbox",) + keys, fixes, merged)
        return Reason(text, LOCAL_BINDING_STEP + step if keys == LOCAL_BINDING else step)
    r = _patterns_unconfined(lv, project, home, env, patterns, version)
    if r is not None:
        return r
    deny_read = _paths(lv, project, home, env, "denyRead", deny=True)
    deny_write = _paths(lv, project, home, env, "denyWrite", deny=True)
    for key, deny in (("denyRead", deny_read), ("denyWrite", deny_write)):
        missing = [r for r in roots if not _covers(deny, r)]
        if missing:
            return Reason(f"sandbox.filesystem.{key} does not cover {len(missing)} protected "
                          "root(s)", INSTALL_STEP)
    for level in lv:
        # one file at a time, so the step names the file that holds the entry
        allow_read = _paths([level], project, home, env, "allowRead", deny=False)
        if any(_reopened(r, deny_read, allow_read) for r in roots):
            return Reason("sandbox.filesystem.allowRead re-opens part of a protected root",
                          _step_in(level[0], level[1], project, home, env,
                                   "that allowRead entry", False))
        if any(_reopened(h, deny_read, allow_read) for h in hidden):
            return Reason("sandbox.filesystem.allowRead re-opens a credential path",
                          _step_in(level[0], level[1], project, home, env,
                                   "that allowRead entry", False))
    miss = [h for h in hidden if not _covers(deny_read, h)]
    if miss:
        return Reason(f"sandbox.filesystem.denyRead does not cover {len(miss)} credential "
                      "path(s)", INSTALL_STEP)
    denied = config.sandbox_denied(dict(env) if env is not None else None)
    for level in lv:
        # one settings file at a time, so the refusal names the file that holds the entry (an
        # older phiward's `allowWrite ~/.phiward/spool` may be in a project's file too)
        allow_write = _paths([level], project, home, env, "allowWrite", deny=False)
        for d in denied:
            if any(a == d or a.startswith(d.rstrip("/") + "/") for a in allow_write):
                f = _shown_file(level[1], project, home)
                return Reason(f"sandbox.filesystem.allowWrite in {f} re-opens part of "
                              f"{_shown_file(d, project, home)}, phiward's own folder",
                              _step_in(level[0], level[1], project, home, env,
                                       "that entry", False))
    if any(not _covers(deny_write, g) for g in list(guard) + denied):
        return Reason("sandbox.filesystem.denyWrite does not cover the phiward config and code "
                      "(an upgrade)", INSTALL_STEP)
    return None


# --- the folders Claude Code lets the agent write ----------------------------------------------

# what Claude Code runs as code, beside its settings files: under any `.claude` folder (not its
# `worktrees`) and under the user config folder (CLAUDE_CONFIG_DIR may have another name). A skill
# or subagent may hold hooks in its frontmatter, a skill or command `!` lines, a plugin hooks and
# MCP servers; `launch.json` names what the app's preview starts. The one list: the hook asks
# before a file tool writes one (`code_place`), and carryover quarantines them.
SETTINGS_NAMES = ("settings.json", "settings.local.json")
CODE_DIRS = ("skills", "agents", "commands", "hooks", "workflows", "plugins", "routines")
CODE_FILES = ("launch.json", "scheduled_tasks.json")
# the one list of what an agent tool, an editor, R or git runs from a project later, outside
# every sandbox, wherever it is in the tree: Claude Code's, Cursor's, Gemini CLI's and Codex's
# folders, an editor's workspace settings (tasks, an interpreter path, MCP servers), the files git
# and ripgrep read for commands, and what R runs at start. Under `launch` (the tool and a wrapped
# server) each is read-only as a whole (wholetool)
RUNS_LATER_DIRS = (".claude", ".vscode", ".idea", ".cursor", ".gemini", ".codex")
RUNS_LATER_FILES = (".mcp.json", ".gitmodules", ".ripgreprc", ".Rprofile", ".Renviron")
# the hook asks before a file tool writes one of these: the list without `.claude` (judged by
# `claude_place`, so `.claude/worktrees` stays writable) and `.mcp.json` (asked as Claude's own)
WORKSPACE_CODE_DIRS = tuple(d for d in RUNS_LATER_DIRS if d != ".claude")
WORKSPACE_CODE_FILES = tuple(f for f in RUNS_LATER_FILES if f != ".mcp.json")
# the editors' folders. Claude Code's sandbox denies the working folder's own to the shell, not a
# nested one (`sub/.vscode/tasks.json`); VS Code and JetBrains read them only at a workspace or
# project root, and a wildcard rule for them would deny `npm install` and `git pull` in every
# project, so a nested one is left to the hook's question (`workspace_code`)
EDITOR_DIRS = (".vscode", ".idea")
# git's control files below any `.git` folder under the home folder (a submodule's config, a
# worktree's commondir, hooks): git runs what they name, and Claude Code runs git outside its
# sandbox. Anchored to the control files themselves, so a branch named `config` or `hooks/x`
# (under refs/ and logs/) stays writable; the hooks folder itself too, so it cannot be renamed
# and replaced. Wildcards: written for macOS and Claude Code VERSION_PATTERNS or newer only
GIT_CONTROL_GLOBS = ("~/**/.git/config", "~/**/.git/config.worktree", "~/**/.git/commondir",
                     "~/**/.git/hooks", "~/**/.git/hooks/**",
                     "~/**/.git/modules/*/config", "~/**/.git/modules/*/config.worktree",
                     "~/**/.git/modules/*/hooks", "~/**/.git/modules/*/hooks/**",
                     "~/**/.git/worktrees/*/commondir", "~/**/.git/worktrees/*/config.worktree")


def workspace_code(path: str) -> bool:
    """Whether `path` is a file an editor or a tool runs commands from (WORKSPACE_CODE_DIRS,
    WORKSPACE_CODE_FILES), as the file system compares names."""
    from phiward import pathid
    dirs = {pathid.fold(n) for n in WORKSPACE_CODE_DIRS}
    files = {pathid.fold(n) for n in WORKSPACE_CODE_FILES}
    for v in (os.path.normpath(path), os.path.realpath(path)):
        parts = pathid.fold(v).split("/")
        if any(p in dirs for p in parts[:-1]) or parts[-1] in files:
            return True
    return False


def _spellings(path: str) -> List[str]:
    """`path` as the file system may compare it: as written, where it really leads, and in the
    file system's own spelling (case and Unicode form folded on macOS)."""
    from phiward import pathid
    out = []
    real = os.path.realpath(path)
    for v in (os.path.normpath(path), real, pathid.canon_new(real)):
        f = pathid.fold(v)
        if f not in out:
            out.append(f)
    return out


def _code_rel(parts: Sequence[str]) -> bool:
    """Whether a path below a Claude Code config folder (its parts below it) is a code place."""
    return bool(parts) and (parts[0] in CODE_DIRS or (len(parts) == 1 and parts[0] in CODE_FILES))


# the code folders are walked for their links, followed until nothing new turns up: each linked
# tree up to TREE_WALK entries, all of them up to LINK_WALK; a tree past its bound still counts as
# code as a whole (only the links deep inside it are not followed), and `doctor` names it.
# `plugins` only to the level where an install is (marketplaces/NAME,
# cache/MARKETPLACE/PLUGIN/VERSION): deeper, a link is the plugin's own, written by its installer
TREE_WALK = 50_000
LINK_WALK = 200_000
_PLUGIN_DEPTH = 3


def _too_wide(real: str, keep: Sequence[str]) -> bool:
    """A link target no code folder can mean: `/`, or a folder that is or holds one of `keep`
    (the home folder, the user config folder: taken as code it would hold every write there),
    as the file system compares names; `doctor` names the link."""
    from phiward import pathid
    if real == "/":
        return True
    r = pathid.fold(real).rstrip("/") + "/"
    return any((pathid.fold(k).rstrip("/") + "/").startswith(r) for k in keep if k)


def _skipped(path: str, trees: Sequence[str]) -> bool:
    """Whether the folder `path` is one of `trees` (folder names, or `a/b` for a name below
    another: `renv/library`)."""
    parts = path.rstrip("/").split("/")
    return any(parts[-len(t.split("/")):] == t.split("/") for t in trees)


def _code_walk(starts: Sequence[Tuple[str, Optional[int], str]], home: str = "",
               skip: Sequence[str] = ()
               ) -> "Tuple[List[Tuple[str, str]], List[Tuple[str, str, str]]]":
    """The code roots below `starts` ([(a real code folder, how deep to walk or None, how it is
    named)]): each start, and where every link inside one leads, a linked folder walked in turn
    (a cycle guard), with `os.scandir` (no stat per entry). ([(real path, the link that led
    there)], [(why, real path, link)] for `doctor`: "tree" a tree past TREE_WALK, "total" one not
    walked once LINK_WALK was passed (both still code as a whole; links deep in them not
    followed), "wide" a target that is or holds the home or user config folder, not taken as
    code). Folders named in `skip` (`_skipped`) are not walked."""
    roots: List[Tuple[str, str]] = []
    notes: List[Tuple[str, str, str]] = []
    keep = [os.path.realpath(home)] + ([os.path.realpath(user_dir(home))] if home else [])
    todo = list(starts)
    done = set()
    total = 0
    while todo:
        top, limit, via = todo.pop(0)
        if top in done:
            continue
        done.add(top)
        if via and _too_wide(top, keep):
            notes.append(("wide", top, via))
            continue
        roots.append((top, via))
        if total > LINK_WALK:
            notes.append(("total", top, via))
            continue
        seen = 0
        stack = [(top, 0)]
        while stack:
            here, depth = stack.pop()
            try:
                entries = list(os.scandir(here))
            except OSError:
                continue
            for e in entries:
                seen += 1
                total += 1
                if seen > TREE_WALK:
                    notes.append(("tree", top, via))
                    stack = []
                    break
                try:
                    if e.is_symlink():
                        real = os.path.realpath(e.path)
                        if os.path.isdir(real):
                            todo.append((real, None, e.path))
                        elif real not in done:
                            done.add(real)
                            if not _too_wide(real, keep):
                                roots.append((real, e.path))  # a file, or nothing yet
                    elif (limit is None or depth < limit) and e.is_dir(follow_symlinks=False) \
                            and not (skip and _skipped(e.path, skip)):
                        stack.append((e.path, depth + 1))
                except OSError:
                    continue  # an entry that vanished, or cannot be read (/dev/fd)
    return roots, notes


def _spellings_memo(path: str, memo: Dict[Any, Any]) -> List[str]:
    key = ("sp", path)
    if key not in memo:
        memo[key] = _spellings(path)
    return memo[key]


def _claude_places(path: str, home: str, bases: Sequence[str],
                   env: Optional[Mapping[str, str]] = None,
                   memo: Optional[Dict[Any, Any]] = None) -> "Tuple[List[str], List[Tuple[str, str, bool]]]":
    """The Claude Code config folders that may hold `path`, and their settings and code
    places, by what they are, not their names: (the folders, [(place, kind, is a folder)]).
    The folders: the user config folder, and the `.claude` of every folder above `path` (as
    written and as it really leads) and above each of `bases` (the project, the working
    folder), each where it really leads (a `.claude` that is a link to `cfg` makes `cfg` one,
    also before `cfg` exists). The places: each child named in SETTINGS_NAMES, CODE_DIRS and
    CODE_FILES of such a folder, where it really leads (`skills -> ../.agents/skills`). All
    folded real paths; `memo` holds one tool call's (a call may name thousands)."""
    memo = {} if memo is None else memo
    real_folders: List[str] = []

    def dot_claude(d: str) -> str:
        key = ("dc", d)
        if key not in memo:
            c = os.path.join(d, ".claude")
            # a link counts even when it leads nowhere yet: the write may make its target
            memo[key] = os.path.realpath(c) if os.path.lexists(c) else ""
        return memo[key]

    def add(real: str) -> None:
        if real and real not in real_folders:
            real_folders.append(real)

    add(os.path.realpath(user_dir(home, env)))
    starts = [os.path.dirname(os.path.normpath(path)), os.path.dirname(os.path.realpath(path))]
    starts += [b for b in bases if b]
    for s in starts:
        d = s
        while True:
            add(dot_claude(d))
            up = os.path.dirname(d)
            if up == d:
                break
            d = up
    folders: List[str] = []
    places: List[Tuple[str, str, bool]] = []
    for real in real_folders:
        key = ("pl", real)
        if key not in memo:
            fs = [f.rstrip("/") for f in _spellings(real)]
            ps: List[Tuple[str, str, bool]] = []
            for n in SETTINGS_NAMES + CODE_FILES + CODE_DIRS:
                c = os.path.join(real, n)
                if os.path.lexists(c):  # a link: where it leads (`skills -> ../shared/skills`)
                    kind = "settings" if n in SETTINGS_NAMES else "code"
                    for f in _spellings(os.path.realpath(c)):
                        ps.append((f.rstrip("/"), kind, n in CODE_DIRS))
            memo[key] = (fs, ps)
        fs, ps = memo[key]
        folders += [f for f in fs if f and f not in folders]
        places += [p for p in ps if p not in places]
    memo[("rf", path, tuple(bases))] = real_folders
    return folders, places


def _code_starts(real_folders: Sequence[str],
                 env: Optional[Mapping[str, str]] = None) -> List[Tuple[str, Optional[int], str]]:
    """Where the walk of code roots starts: each code folder of each Claude folder, where it
    really leads, and the plugin folders Claude Code may keep elsewhere
    (CLAUDE_CODE_PLUGIN_CACHE_DIR, CLAUDE_CODE_PLUGIN_SEED_DIR)."""
    env = os.environ if env is None else env
    out: List[Tuple[str, Optional[int], str]] = []
    for real in real_folders:
        for n in CODE_DIRS:
            c = os.path.join(real, n)
            if os.path.isdir(c):
                out.append((os.path.realpath(c), _PLUGIN_DEPTH if n == "plugins" else None,
                            c if os.path.islink(c) else ""))
    for k in ("CLAUDE_CODE_PLUGIN_CACHE_DIR", "CLAUDE_CODE_PLUGIN_SEED_DIR"):
        v = env.get(k) or ""
        if v.startswith("/") and os.path.isdir(v):
            # the like of plugins/cache: MARKETPLACE/PLUGIN/VERSION
            out.append((os.path.realpath(v), _PLUGIN_DEPTH - 1, f"${k}"))
    return out


def code_roots(real_folders: Sequence[str], env: Optional[Mapping[str, str]] = None,
               memo: Optional[Dict[Any, Any]] = None, home: str = ""
               ) -> "Tuple[List[Tuple[str, str]], List[Tuple[str, str, str]]]":
    """The one list of what Claude Code runs as code, below the given Claude folders
    (`_code_walk`: the roots, and the notes `doctor` gives), kept in `memo` for one call. Read
    by the hook and by `doctor`."""
    memo = {} if memo is None else memo
    key = ("roots", tuple(real_folders))
    if key not in memo:
        memo[key] = _code_walk(_code_starts(real_folders, env), home)
    return memo[key]


def code_root_report(project: str, home: str, env: Optional[Mapping[str, str]] = None
                     ) -> "Tuple[List[Tuple[str, str]], List[Tuple[str, str, str]]]":
    """For `doctor`: (the code roots a session in `project` can write, its shell too, with the
    link that leads there: those inside `agent_writable(project)` and outside the user config
    folder, as the file system compares names), and the walk's notes (`_code_walk`)."""
    from phiward import pathid
    memo: Dict[Any, Any] = {}
    _claude_places(os.path.join(project, "x"), home, [project], env, memo)
    real_folders = memo[("rf", os.path.join(project, "x"), (project,))]
    roots, notes = code_roots(real_folders, env, memo, home)
    user = pathid.fold(os.path.realpath(user_dir(home, env))).rstrip("/") + "/"
    writable = [pathid.fold(w).rstrip("/") + "/" for w in agent_writable(project, home)]
    out = []
    for real, via in roots:
        r = pathid.fold(real).rstrip("/") + "/"
        if not via or r.startswith(user):
            continue
        if any(r.startswith(w) for w in writable):
            out.append((real, via))
        elif any(w.startswith(r) for w in writable):
            # it holds this project: Claude Code may run anything in it, so every write here
            # is asked or refused as code
            notes.append(("holds", real, via))
    return out, notes


def writable_code_roots(project: str, home: str,
                        env: Optional[Mapping[str, str]] = None) -> List[Tuple[str, str]]:
    """The code roots a session in `project` can write (`code_root_report`)."""
    return code_root_report(project, home, env)[0]


def claude_place(path: str, home: str, bases: Sequence[str] = (),
                 env: Optional[Mapping[str, str]] = None,
                 memo: Optional[Dict[Any, Any]] = None) -> str:
    """What `path` (absolute) is to Claude Code: "settings" (a settings file), "code" (one it
    runs as code: `CODE_DIRS`, `CODE_FILES`) or "". Below a `.claude` folder by name (any, but
    its `worktrees`), below a Claude config folder by what it is, or at one of its settings and
    code places where they really lead (`_claude_places`)."""
    def kind(rel: List[str]) -> str:
        if not rel or rel[0] == "worktrees":
            return ""
        if len(rel) == 1 and rel[0] in SETTINGS_NAMES:
            return "settings"
        return "code" if _code_rel(rel) else ""
    memo = {} if memo is None else memo
    key = ("cp", path, tuple(bases))
    if key in memo:
        return memo[key]
    memo[key] = _claude_place(path, home, bases, env, memo, kind)
    return memo[key]


def _claude_place(path: str, home: str, bases: Sequence[str],
                  env: Optional[Mapping[str, str]], memo: Dict[Any, Any], kind: Any) -> str:
    found = ""
    folders, places = _claude_places(path, home, bases, env, memo)
    roots, _notes = code_roots(memo[("rf", path, tuple(bases))], env, memo, home)
    rkey = ("rootset", tuple(r for r, _v in roots))
    if rkey not in memo:
        memo[rkey] = {f.rstrip("/") for r, _v in roots for f in _spellings_memo(r, memo)}
    rootset = memo[rkey]
    for v in _spellings_memo(path, memo):
        # the path, or a folder above it, is a code root: O(depth)
        d = v
        while d and d != "/":
            if d in rootset:
                found = found or "code"
                break
            d = d.rsplit("/", 1)[0]
        parts = v.split("/")
        for i, c in enumerate(parts[:-1]):
            if c == ".claude":
                found = found or kind(parts[i + 1:])
        for f in folders:
            if v.startswith(f + "/"):
                found = found or kind(v[len(f) + 1:].split("/"))
        for place, k, is_dir in places:
            if v == place or (is_dir and v.startswith(place + "/")):
                if k == "settings":
                    return k
                found = found or k
        if found == "settings":
            return found
    return found


def code_place(path: str, home: str, env: Optional[Mapping[str, str]] = None) -> bool:
    """Whether `path` (absolute) is one Claude Code runs as code (`claude_place`)."""
    return claude_place(path, home, (), env) == "code"


def memory_places(home: str, env: Optional[Mapping[str, str]] = None) -> List[str]:
    """Where Claude Code itself writes its memory and plans (the file tools may write there in
    any mode): `projects/*/memory`, `agent-memory` and `plans` under the user config folder, and
    `autoMemoryDirectory` and `plansDirectory` of the user and managed settings (never a
    project's, which the agent can write) unless one is the home folder or above it. Real paths;
    a `*` stands for one name."""
    base = user_dir(home, env)
    out = [os.path.join(base, "projects", "*", "memory"), os.path.join(base, "agent-memory"),
           os.path.join(base, "plans")]
    lv = levels(None, home, env)
    for key in ("autoMemoryDirectory", "plansDirectory"):
        v = _first(lv, key)
        if not isinstance(v, str) or not v.strip():
            continue
        v = home + v[1:] if v == "~" or v.startswith("~/") else v
        if not v.startswith("/"):
            continue
        real = os.path.realpath(v)
        h = os.path.realpath(home)
        if real == h or h.startswith(real.rstrip("/") + "/") or real == "/":
            continue
        out.append(real)
    return [os.path.realpath(o) if "*" not in o else o for o in out]


def _temp_roots() -> List[str]:
    """The temp folders Claude Code's sandbox lets the agent write."""
    import tempfile
    return [tempfile.gettempdir(), "/tmp"]


def agent_writable(project: str, home: str) -> List[str]:
    """The folders Claude Code lets the agent write, from its own settings (as its sandbox reads
    them): the project, the temp folders, phiward's spool, `sandbox.filesystem.allowWrite` (a
    pattern: its fixed part) and `permissions.additionalDirectories`. Real paths."""
    lv = levels(project, home)
    roots = [project, config.spool_dir()] + _temp_roots()
    for p in _paths(lv, project, home, None, "allowWrite", deny=False):
        cut = min([p.index(c) for c in "*?[" if c in p] or [len(p)])
        roots.append(p if cut == len(p) else os.path.dirname(p[:cut]))
    for d in _merged_list(lv, "permissions", "additionalDirectories"):
        d = str(d)
        roots.append(os.path.join(project, d) if not d.startswith(("/", "~")) else
                     os.path.expanduser(d.replace("~", home, 1) if d.startswith("~/") else d))
    out: List[str] = []
    for r in roots:
        real = os.path.realpath(r)
        if r and real not in out:
            out.append(real)
    return out


# the folders under the home folder from which your own tools start programs later (login items,
# user services, shell and editor settings, a PATH folder): a session whose sandbox may write one
# of them is not confined, and a file tool asks before it writes there
STARTUP_PLACES = (".config", ".local/bin", "Library/LaunchAgents")


def startup_write_problem(root: str, home: str) -> str:
    """Why the write place `root` reaches files that start programs later, or "": the home folder
    or a folder above it, or a STARTUP_PLACES folder, a folder inside one, or one above it under
    the home folder (`~/.local`, `~/Library`)."""
    from phiward import pathid
    r = pathid.fold(os.path.realpath(root)).rstrip("/") or "/"
    h = pathid.fold(os.path.realpath(home)).rstrip("/")
    if h == r or h.startswith(r + "/") or r == "/":
        return "it is your home folder or above it"
    for s in STARTUP_PLACES:
        place = pathid.fold(os.path.join(h, s))
        if r == place or r.startswith(place + "/") or (
                place.startswith(r + "/") and r.startswith(h + "/")):
            return f"it holds ~/{s}, where programs that start later are set up"
    return ""


def session_write_places(project: str, home: str) -> List[str]:
    """The write places a session's own settings give: the project, `allowWrite` and
    `additionalDirectories` (not phiward's spool or the temp folders). Real paths."""
    skip = {os.path.realpath(p) for p in [config.spool_dir()] + _temp_roots()}
    return [w for w in agent_writable(project, home)
            if w not in skip or os.path.realpath(w) == os.path.realpath(project)]


def agent_writable_anywhere(home: str) -> List[str]:
    """The folders the agent's sandbox may write in every project, as far as they are known
    without one (the broker's PATH): the spool, and the allowWrite and additionalDirectories
    entries of the managed and user settings that are absolute paths (a relative one would be
    resolved against a project, which is not known here). Real paths. The temp folders are
    `_temp_roots`."""
    lv = levels(None, home)
    roots = [config.spool_dir()]
    for p in _paths(lv, "", home, None, "allowWrite", deny=False):
        cut = min([p.index(c) for c in "*?[" if c in p] or [len(p)])
        roots.append(p if cut == len(p) else os.path.dirname(p[:cut]))
    for d in _merged_list(lv, "permissions", "additionalDirectories"):
        d = str(d)
        roots.append(home + d[1:] if d == "~" or d.startswith("~/") else d)
    out: List[str] = []
    for r in roots:
        if r.startswith("/"):
            real = os.path.realpath(r)
            if real not in out:
                out.append(real)
    return out


def inside(path: str, roots: List[str]) -> bool:
    """Whether `path` (as it really leads) is one of `roots` or inside one."""
    real = os.path.realpath(path)
    return any(real == r or real.startswith(r.rstrip("/") + "/") for r in roots)
