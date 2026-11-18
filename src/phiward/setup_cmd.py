"""`phiward setup`: first-time setup. It asks the operator questions and writes the user
config. The text users see is HELP below.

A prompt is safe here, unlike at run time, because nothing it answers is an approval of what
the agent asks for: the operator starts it in their own terminal, it writes only the user config
(which the agent cannot write once the guards are wired), and the result is a file the operator
reads before it is written and that `doctor` checks afterwards.
"""

import difflib
import os
import re
import sys
import tempfile
from typing import Tuple, Any, Callable, Dict, List, Optional, TextIO

from phiward import _toml, config, pathid, safeio

USAGE = ("usage: phiward setup [--from TEAM.toml]\n"
         "       phiward setup --first-run --root PATH [--root PATH]... [--remote HOST:/PATH]...\n")
HELP = USAGE + """
Options:
  --from FILE       start from a team template: a config file with shared settings (the
                    program list, packs, HPC hosts). Its settings fill in what your config does
                    not have; you see the whole file before anything is written
  --first-run       write the first user config without questions (see below)
  --root PATH       with --first-run: a protected root (a folder with protected data)
  --remote HOST:/PATH  with --first-run: a copy remote (a host and an absolute path prefix)
  -h, --help        show this help

`phiward setup` asks you questions and writes the user config. Run it in your own terminal,
never through an agent tool. It refuses to run without a terminal on stdin and stdout, and
the hook refuses it as an agent command.

It first asks how you will use phiward: real patient data (a results folder inside your first
protected folder, the @genomics program list plus your own scripts folder, no network), made-up
data (open defaults), or every setting (the protected roots, patterns, write places, programs,
network and copy remotes, one by one). For real data and every setting, it also asks whether
the shell commands of Claude Code sessions may reach only hosts you list ([network]). Then, if
you like, the HPC questions. Each answer is
checked as the config loader checks it; a refused answer is asked again. Then it shows the whole file and the difference from the old
one. It writes the file only after a yes (mode 0600; the old file is kept as `.bak`). Other
sections of an existing file are kept. Its comments are not kept (the backup has them).

`phiward setup --first-run` writes the first config without questions. An agent may run it
to set phiward up with you:
- It works only when no user config exists yet. To change a config later, run
  `phiward setup` in your own terminal.
- It writes protected roots and copy remotes only. It never writes write places or network
  grants: those stay yours.
- Give at least one --root. Each root must be an absolute path (or start with ~/), exist,
  have no wildcard, and not be your home or a folder above it.
- Without a terminal, it refuses when PHIWARD_CONFIG, PHIWARD_SPOOL, XDG_CONFIG_HOME or
  XDG_CACHE_HOME is set. The first config must go to the default place.
"""
_REMOTE = re.compile(r"[A-Za-z0-9_.@-]+:/[^\s]*")


# ---- writing TOML (the config uses strings, lists of strings, whole numbers and true/false) ----

def _quote(v: str) -> str:
    """A TOML basic string: backslash and quote escaped, and every control character written as
    \\uXXXX, so a value can neither break the file nor move the cursor on the screen."""
    out = []
    for ch in v:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return _quote(v)
    if isinstance(v, list):
        if not v:
            return "[]"
        return "[\n" + "".join(f"  {_value(x)},\n" for x in v) + "]"
    raise ValueError(f"cannot write a {type(v).__name__}")


def dump(data: Dict[str, Dict[str, Any]]) -> str:
    out = ["# phiward user config, written by `phiward setup`.",
           "# The agent cannot write this file. See docs/configuration.md for every key.", ""]
    for section in config.SCHEMA:
        body = data.get(section)
        if not body:
            continue
        out.append(f"[{section}]")
        for key, v in body.items():
            out.append(f"{key} = {_value(v)}")
        out.append("")
    return "\n".join(out)


# ---- checking one answer --------------------------------------------------------------------

def _expand(answer: str, home: str) -> str:
    return os.path.normpath(home + answer[1:]) if answer == "~" or answer.startswith("~/") \
        else os.path.normpath(answer) if answer.startswith("/") else answer


def check_root(answer: str, home: str) -> str:
    """Why `answer` cannot be a protected root, or ""."""
    p = _expand(answer, home)
    if not p.startswith("/"):
        return "it must be absolute (or start with ~/)"
    if any(c in p for c in "*?["):
        return "it has a wildcard; give it as a pattern instead"
    if p == "/" or ".." in answer.split("/"):
        return "it must be below / and have no '..'"
    if not os.path.lexists(p):
        return "it does not exist (create it first: on Linux the agent shell refuses to run " \
               "while a root is missing)"
    real_home = os.path.realpath(home)
    if config.inside(real_home, os.path.realpath(p)):
        return "it is the home folder or above it (the agent could not work at all)"
    for g in config.guard_files():
        if config.inside(os.path.realpath(g), os.path.realpath(p)):
            return "it holds a phiward file or folder"
    return ""


def check_pattern(answer: str, home: str) -> str:
    p = _expand(answer, home)
    if not p.startswith("/"):
        return "it must be absolute (or start with ~/)"
    if not any(c in p for c in "*?["):
        return "it has no wildcard; give it as a root instead"
    if ".." in answer.split("/") or "$" in p:
        return "it may not hold '..' or a variable"
    from phiward import pathmatch
    return pathmatch.problem(p) or ""


def check_remote(answer: str) -> str:
    if not _REMOTE.fullmatch(answer) or ".." in answer.split(":", 1)[1].split("/"):
        return "it must look like host:/absolute/prefix, with no '..'"
    from phiward.copying import remote_prefix_problem
    return remote_prefix_problem(answer.split(":", 1)[1])


# ---- the dialogue ---------------------------------------------------------------------------

class Ask:
    def __init__(self, fin: TextIO, fout: TextIO):
        self.fin, self.fout = fin, fout

    def say(self, msg: str = "") -> None:
        self.fout.write(msg + "\n")
        self.fout.flush()

    def line(self, prompt: str) -> str:
        self.fout.write(prompt)
        self.fout.flush()
        got = self.fin.readline()
        if not got:
            raise EOFError
        return got.strip()

    def yes(self, question: str, default: bool = False) -> bool:
        hint = "[Y/n]" if default else "[y/N]"
        while True:
            a = self.line(f"{question} {hint} ").lower()
            if not a:
                return default
            if a in ("y", "yes", "n", "no"):
                return a.startswith("y")
            self.say("  Type y or n.")

    def many(self, title: str, help_: str, have: List[str],
             check: Callable[[str], str]) -> List[str]:
        """A list, one answer per line; an empty line ends it. Each answer is checked."""
        self.say("")
        self.say(title)
        self.say(help_)
        out = list(have)
        if out:
            self.say(f"  Now: {len(out)} entr{'y' if len(out) == 1 else 'ies'}:")
            for v in out:
                self.say(f"    {v}")
            if self.yes("  Remove all of these and start again? (No keeps them)"):
                out = []
        while True:
            a = self.line("  Add one (an empty line, or `none`, ends the list) > ")
            if not a or a.strip().lower() in ("n", "no", "none", "skip", "done"):
                return out
            why = check(a)
            if why:
                self.say(f"  Refused: {why}. Try again.")
                continue
            if a in out:
                self.say("  Already in the list.")
                continue
            out.append(a)


_SYSTEM_BIN = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")


def home_of(env: Dict[str, str]) -> str:
    return pathid.home(env)


def approval(lines: List[str], home: str, before: bool) -> "Tuple[List[str], bool, int, int]":
    """How setup shows the programs to approve: (the lines, each program in the home folder that
    shadows a system program of the same name marked; the question's default; how many are
    found; how many are not installed). The default is Yes only on a first approval with nothing
    changed and nothing shadowing a system program: a changed or shadowing program is what the
    question is there to catch."""
    shown: List[str] = []
    shadows = False
    found = missing = 0
    h = os.path.realpath(home).rstrip("/") + "/"
    for x in lines:
        path = x.split("  ", 1)[0]
        if x.endswith("(not installed)"):
            missing += 1
            continue
        found += 1
        name = os.path.basename(path)
        hit = next((os.path.join(b, name) for b in _SYSTEM_BIN
                    if os.path.realpath(path).startswith(h) and os.path.isfile(os.path.join(b, name))),
                   "")
        if hit:
            shadows = True
            x += f"  (shadows {hit})"
        shown.append(x)
    changed = any(x.endswith("(changed)") for x in lines)
    return shown, not before and not changed and not shadows, found, missing


def _read_existing(path: str) -> Dict[str, Dict[str, Any]]:
    if not os.path.isfile(path):
        return {}
    raw, _ = _toml.load_file(path)
    return {s: dict(b) for s, b in raw.items() if isinstance(b, dict)}


def _write(path: str, text: str) -> None:
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    if os.path.exists(path):
        safeio.write_new(path + ".bak", safeio.read_text(path))
    safeio.write_new(path, text)


# what a team template may set: shared, non-grant settings. Never a write place, the network,
# a copy remote, an ssh config, names files, pack files by path, environment to pass on
TEAM_KEYS = {("broker", "commands"), ("sanitize", "packs"), ("remote", "hosts"),
             ("remote", "commands"), ("remote", "roots"), ("protected_paths", "patterns"),
             ("protected_paths", "snapshot_names"), ("copy", "push_limit_gib"),
             ("sanitize", "inventory_limit"), ("broker", "max_output_lines")}


def _ssh_entry(path: str, host: str) -> Dict[str, str]:
    """The HostName and User of `Host host` in an ssh config file, or {} (read only)."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read(1 << 20)
    except OSError:
        return {}
    out: Dict[str, str] = {}
    inside = False
    for line in text.splitlines():
        words = line.split()
        if not words:
            continue
        key = words[0].lower()
        if key in ("host", "match"):
            inside = key == "host" and host in words[1:]
            if inside:
                out["found"] = "yes"
        elif inside and key in ("hostname", "user") and len(words) > 1:
            out[key] = words[1]
    return out


def _in_project(path: str) -> bool:
    """Whether a file sits where an agent may have written it: in the current folder, or in a
    folder with `.git`, `.claude` or `.phiward.toml` above it."""
    here = os.path.realpath(os.getcwd())
    if path == here or path.startswith(here.rstrip("/") + "/"):
        return True
    # a folder the agent's sandbox may write in every project (its allowWrite, the spool)
    from phiward import claude_settings, pathid
    for w in claude_settings.agent_writable_anywhere(pathid.home()):
        r = os.path.realpath(w)
        if path == r or path.startswith(r.rstrip("/") + "/"):
            return True
    d = os.path.dirname(path)
    while d and d != "/":
        if any(os.path.lexists(os.path.join(d, n)) for n in (".git", ".claude", ".phiward.toml")):
            return True
        d = os.path.dirname(d)
    return False


def _team_problem(raw: Dict[str, Any]) -> str:
    """Why a team template cannot be used, or "": every value of the type the config expects,
    no control characters, limits only lower than the defaults, no paths in the program list."""
    limits = {("broker", "max_output_lines"): config.Config().max_output_lines,
              ("copy", "push_limit_gib"): config.Config().push_limit_gib,
              ("sanitize", "inventory_limit"): config.Config().inventory_limit}
    for sec, keys in raw.items():
        for k, v in keys.items():
            want = config.SCHEMA[sec][k]
            ok = {"list": isinstance(v, list) and all(isinstance(x, str) for x in v),
                  "bool": isinstance(v, bool), "str": isinstance(v, str),
                  "int": isinstance(v, int) and not isinstance(v, bool)}.get(want, False)
            if not ok:
                return f"{sec}.{k} must be a {want}" + (" of strings" if want == "list" else "")
            for x in (v if isinstance(v, list) else [v]):
                if isinstance(x, str) and any(not c.isprintable() for c in x):
                    # a control character, or one that turns text around (U+202E)
                    return (f"{sec}.{k} holds a control character or another character "
                            "that is not printable")
            if (sec, k) in limits and v > limits[(sec, k)]:
                return f"{sec}.{k} may only be lower than the default ({limits[(sec, k)]})"
            if (sec, k) == ("broker", "commands") and any("/" in x for x in v):
                return ("broker.commands names a place (a path); your own scripts are yours to "
                        "add")
    return ""


PROFILES = ("Real patient data (recommended): a results folder, a list of programs, no network",
            "Made-up data, to try phiward: any program may run, no network",
            "Choose every setting yourself")


def _merge_team(data: Dict[str, Dict[str, Any]], team: Dict[str, Dict[str, Any]]) -> int:
    """A team template's settings, added where the operator's own config has none (lists are
    joined). Returns how many keys it set."""
    n = 0
    for sec, keys in team.items():
        if not isinstance(keys, dict):
            continue
        mine = data.setdefault(sec, {})
        for k, v in keys.items():
            if k not in mine:
                mine[k] = v
                n += 1
            elif isinstance(v, list) and isinstance(mine[k], list):
                extra = [x for x in v if x not in mine[k]]
                if extra:
                    mine[k] = list(mine[k]) + extra
                    n += 1
    return n


def dialogue(ask: Ask, path: str, home: str, env: Dict[str, str],
             team: Optional[Dict[str, Dict[str, Any]]] = None, team_name: str = "") -> int:
    try:
        data = _read_existing(path)
    except (OSError, UnicodeDecodeError, _toml.TomlError) as exc:
        ask.say(f"setup: the config at {path} cannot be read ({type(exc).__name__}); fix or move "
                "it first.")
        return 3
    for sec, key in sorted(config.REMOVED):  # iteration-4 keys: dropped, said so
        if key in data.get(sec, {}):
            del data[sec][key]
            ask.say(f"Note: '{sec}.{key}' is no longer used (nothing asks at run time); it is "
                    "dropped from the new file.")
    pp, br, cp = (data.setdefault(s, {}) for s in ("protected_paths", "broker", "copy"))

    ask.say("phiward setup")
    ask.say(f"User config: {path}")
    ask.say("Answer each question. Nothing is written until you say yes at the end.")
    ask.say("This terminal is yours: what you type here does not reach the agent.")
    if team:
        ask.say("")
        ask.say(f"Team template {team_name} sets:")
        for sec, keys in team.items():
            for k, v in keys.items():
                ask.say(f"  [{sec}] {k} = {_value(v)}")
                if (sec, k) in (("broker", "commands"), ("remote", "commands")):
                    launch = sorted({os.path.basename(str(x)) for x in v
                                     if config.runs_other_code(str(x))})
                    if launch:
                        where_ = "on your data" if sec == "broker" else "on the cluster"
                        ask.say(f"    WARNING: {', '.join(launch)} can run other code: with "
                                f"it, code the agent writes can run {where_}")
                if isinstance(v, list) and (data.get(sec) or {}).get(k):
                    ask.say("    (added to your own list)")
        if not ask.yes("Use these team settings?", False):
            ask.say("Nothing was written.")
            return 1
        n = _merge_team(data, team)
        pp, br, cp = (data.setdefault(s, {}) for s in ("protected_paths", "broker", "copy"))
        ask.say(f"{n} team setting(s) used: added where you had none, lists joined with yours.")
    ask.say("")
    ask.say("How will you use phiward?")
    for i, t in enumerate(PROFILES, 1):
        ask.say(f"  {i}. {t}")
    while True:
        a = ask.line("Choose 1, 2 or 3 [1] > ") or "1"
        if a in ("1", "2", "3"):
            profile = int(a)
            break
        ask.say("  Type 1, 2 or 3.")
    created: List[str] = []
    ssh_file: Optional[Tuple[str, str]] = None
    hpc_lines: List[str] = []

    pp["roots"] = ask.many(
        "1. Protected roots",
        "  Folders that hold protected data. The agent cannot read them; only gateway commands\n"
        "  (phiward run|copy) can, and their output is masked. Use absolute paths or ~/.",
        list(pp.get("roots", [])), lambda a: check_root(a, home))
    if profile == 3:
        pp["patterns"] = ask.many(
            "2. Protected patterns (optional; prefer roots)",
            "  Glob patterns such as /data/runs/*/panel. On macOS, Claude Code's sandbox denies\n"
            "  them too (Claude Code 2.1.236 or newer); on Linux it cannot deny writes to them,\n"
            "  so there the hook refuses shell commands (use roots, or `phiward run`).",
            list(pp.get("patterns", [])), lambda a: check_pattern(a, home))
    else:
        pp.setdefault("patterns", [])
    probe = config.Config(roots=[_expand(r, home) for r in pp["roots"]],
                          patterns=[_expand(p, home) for p in pp["patterns"]],
                          derived_roots=[config.cache_dir(env)])

    def check_write(a: str, may_create: bool = False) -> str:
        p = _expand(a, home)
        if not p.startswith("/"):
            return "it must be absolute (or start with ~/)"
        if may_create and not os.path.exists(p):
            parent = os.path.realpath(os.path.dirname(p))
            if not os.path.isdir(parent):
                return "its folder does not exist"
            full = os.path.join(parent, os.path.basename(p))
        else:
            full = os.path.realpath(p)
            if not os.path.isdir(full):
                return "it is not an existing folder (create it first)"
        if full != p:
            return f"a link is on its path; give the real folder instead: {full}"
        if os.path.isdir(os.path.join(full, ".claude")):
            return "it holds a .claude folder (choose a results folder, not a project folder)"
        return config.grant_problem(full, probe, env)

    if profile == 3:
        br["write_to"] = ask.many(
            "3. Write places for gateway commands ([broker] write_to)",
            "  Folders where gateway commands may write results; with one, it is the default\n"
            "  (no --write-to needed). Gateway commands write nowhere else: protected folders\n"
            "  are read only for them. What lands here is not masked, so the agent cannot read\n"
            "  these folders directly either. The simplest choice is a results folder inside a\n"
            "  protected folder, for example ~/data/patients/results.",
            list(br.get("write_to", [])), check_write)
    elif not br.get("write_to") and pp["roots"]:
        # a results folder inside the first protected folder: the default write place
        first = os.path.realpath(_expand(pp["roots"][0], home))  # the real folder, not a link
        suggest = os.path.join(first.rstrip("/"), "phiward-results")
        ask.say("")
        ask.say("Results folder. Gateway commands write results only here (protected folders are")
        ask.say("read only for them); what lands here stays protected, so the agent sees its name")
        ask.say("masked and reads results through the gateway (`phiward run -- head`). Enter")
        ask.say("accepts it, `none` skips it.")
        while True:
            a = ask.line(f"  Results folder [{suggest}] > ") or suggest
            if a.lower() in ("none", "n", "no", "skip"):
                break
            why = check_write(a, may_create=True)
            if why:
                ask.say(f"  Refused: {why}. Try again.")
                continue
            br["write_to"] = [a]
            if not os.path.exists(_expand(a, home)):
                created.append(_expand(a, home))
            break

    def check_command(a: str) -> str:
        if a.startswith("@"):
            return "" if a[1:] in config.COMMAND_PRESETS else (
                f"there is no list {a}; the lists are "
                + ", ".join("@" + k for k in config.COMMAND_PRESETS))
        if "/" in a:
            q = _expand(a, home)
            if not q.startswith("/") or not os.path.exists(q):
                return "a path must be absolute (or start with ~/) and exist"
            return ""
        return "" if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", a) else "it must be a program name"

    if profile == 1:
        cmds = list(br.get("commands", [])) or ["@genomics"]
        ask.say("")
        ask.say("Programs. Gateway commands may run only listed programs, so code the agent")
        ask.say("writes cannot run on your data. @genomics is samtools, bedtools, tabix, mosdepth,")
        ask.say("seqkit, wc and other tools that run no other code.")
        ask.say(f"  Now: {', '.join(cmds)}")
        ask.say("Add a folder of your own scripts, kept outside the projects the agent works in;")
        ask.say("phiward protects it from agent writes. They run by full path, for example")
        ask.say("`phiward run -- ~/pipelines/bin/count_reads.sh`. Enter skips.")
        while True:
            a = ask.line("  Your scripts folder (Enter for none) > ")
            if not a or a.lower() in ("none", "n", "no", "skip"):
                break
            q = _expand(a, home)
            if not os.path.isdir(q):
                ask.say("  Refused: it is not an existing folder. Try again.")
                continue
            entry = a.rstrip("/") + "/"
            if entry not in cmds:
                cmds.append(entry)
            break
        br["commands"] = cmds
    elif profile == 3:
        br["commands"] = ask.many(
            "4. Programs gateway commands may run ([broker] commands)",
            "  Empty: any program (code the agent writes can run on protected data). For real\n"
            "  data, list them: @genomics or @counts (built-in lists), program names, your own\n"
            "  scripts by path, or a folder of them ending in /. Interpreters and shells run any\n"
            "  code: list your scripts instead.",
            list(br.get("commands", [])), check_command)

    if profile == 3:
        ask.say("")
        ask.say("5. Network for gateway commands ([broker] net)")
        ask.say("  With yes, `phiward run --net` gets the network. Code that reads protected\n"
                "  data could then send it anywhere. Against an agent you do not trust, say no.")
        br["net"] = ask.yes("  Allow --net?", bool(br.get("net", False)))
        cp["remotes"] = ask.many(
            "6. Copy remotes ([copy] remotes)",
            "  host:/absolute/work/folder places that `phiward copy` may copy to or from. The\n"
            "  HPC questions below can fill this in. Leave empty if you do not use one.",
            list(cp.get("remotes", [])), check_remote)
    else:
        br.setdefault("net", False)

    if profile != 2:
        nw = data.setdefault("network", {})
        ask.say("")
        ask.say(("7. " if profile == 3 else "") + "Network for shell commands in Claude Code "
                "sessions ([network])")
        ask.say("  With yes, the shell commands an agent runs reach only the hosts you list (Claude")
        ask.say("  Code's own sandbox enforces it). Claude Code itself, WebFetch and MCP servers are")
        ask.say("  not limited by it. Commands that need the network (git push, pip install) need")
        ask.say("  their hosts listed, for example github.com or *.pypi.org. Each listed host is a")
        ask.say("  way out: code the agent writes can send what it reads there. List few.")
        if ask.yes("  Limit the network of shell commands?",
                   bool(nw.get("limit", profile == 1))):
            nw["limit"] = True

            def check_domain(a: str) -> str:
                return config.domain_problem(a)

            nw["allowed_domains"] = ask.many(
                "  Hosts shell commands may reach",
                "  One per line, for example github.com. None: no host at all.",
                list(nw.get("allowed_domains", [])), check_domain)
        else:
            if nw.get("limit"):
                ask.say("  Note: Claude Code keeps sandbox.network.strictAllowlist in "
                        "~/.claude/settings.json until you remove it there yourself.")
            data.pop("network", None)

    if profile != 2 and ask.yes("\nDo you work with an HPC cluster (copies, jobs)?", False):
        ask.say("  phiward reaches it only through your own shared SSH connection (you log in;")
        ask.say("  no request can read your key or ticket).")
        rm0 = data.get("remote", {}) or {}
        old_alias = (rm0.get("hosts") or ["hpc"])[0]
        old_ssh = _expand(cp["ssh_config"], home) if cp.get("ssh_config") else ""
        known = _ssh_entry(old_ssh, old_alias) if old_ssh else {}
        old_work = next((r.split(":", 1)[1] for r in cp.get("remotes", [])
                         if r.startswith(old_alias + ":")), "")
        while True:
            alias = ask.line(f"  Short name for the cluster, as you use it with ssh [{old_alias}] > ") \
                or old_alias
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", alias):
                break
            ask.say("  Refused: letters, digits, . _ - only. Try again.")
        ask.say("  HostName and User must be the same as in your own ~/.ssh/config entry for")
        ask.say(f"  {alias}, or phiward cannot find your shared connection.")
        while True:
            dflt = known.get("hostname", "") if alias == old_alias else ""
            login = ask.line("  Its login host, exactly as HostName in that entry"
                             + (f" [{dflt}]" if dflt else "") + " > ") or dflt
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", login or ""):
                break
            ask.say("  Refused: give the host name (letters, digits, . _ -). Try again.")
        udflt = (known.get("user") if alias == old_alias else "") or os.environ.get("USER", "")
        user = ask.line(f"  Your user name there, as User in that entry [{udflt}] > ") or udflt
        while True:
            wdflt = old_work if alias == old_alias else ""
            work = ask.line("  Your work folder there (absolute)"
                            + (f" [{wdflt}]" if wdflt else "") + " > ") or wdflt
            why = check_remote(f"{alias}:{work}") if work else "it is needed"
            if not why:
                break
            ask.say(f"  Refused: {why}. Try again.")
        remotes = list(cp.get("remotes", []))
        if f"{alias}:{work}" not in remotes:
            remotes.append(f"{alias}:{work}")
        cp["remotes"] = remotes
        rm = data.setdefault("remote", {})
        rm["hosts"] = sorted(set(rm.get("hosts", [])) | {alias})
        rm.setdefault("commands", ["squeue", "sacct", "sinfo"])
        masked = ask.line(f"  Protected folders on the cluster, masked in remote output [{work}] > ")
        rroots = list(rm.get("roots", []))
        for r in ([masked] if masked else [work]):
            if r.startswith("/") and r not in rroots:
                rroots.append(r)
        rm["roots"] = rroots
        if cp.get("ssh_config") and _ssh_entry(_expand(cp["ssh_config"], home), alias):
            ask.say(f"  phiward's ssh config already has `Host {alias}`; nothing to add there.")
        elif cp.get("ssh_config"):
            ask.say(f"  Kept your ssh config for phiward: {cp['ssh_config']}; add a `Host "
                    f"{alias}` entry to it with HostName, User and the ControlPath below.")
        else:
            ssh_path = os.path.join(os.path.dirname(path), "ssh_config")
            cp["ssh_config"] = ssh_path.replace(home, "~", 1) if ssh_path.startswith(home + "/") \
                else ssh_path
            ssh_file = (ssh_path, f"Host {alias}\n  HostName {login}\n  User {user}\n"
                                  f"  ControlPath ~/.ssh/cm-%C\n  ControlMaster no\n")
        hpc_lines = [f"Host {alias}", f"  HostName {login}", f"  User {user}",
                     "  ControlMaster auto", "  ControlPath ~/.ssh/cm-%C", "  ControlPersist 8h"]
        ask.say("")
        ask.say(f"  In ~/.ssh/config (phiward does not edit it): if you have a `Host {alias}` entry,")
        ask.say("  add only the three Control lines to it; otherwise add the whole block:")
        for line in hpc_lines:
            ask.say("    " + line)

    for sec in ("protected_paths", "broker", "copy"):
        for key in [k for k, v in data[sec].items() if v in ([], False)]:
            del data[sec][key]
    if data.get("network", {}).get("allowed_domains") == []:
        del data["network"]["allowed_domains"]  # limit = true with no host: none at all
    text = dump(data)
    old = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            old = fh.read()
    # the same checks as every later load: a file that would not load is not written. The trial
    # file is in a new private folder, never next to the config
    trial = tempfile.mkdtemp(prefix="phiward-setup-")
    tmp = os.path.join(trial, "config.toml")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        cfg = config.load("/", env=dict(env, PHIWARD_CONFIG=tmp))
    finally:
        safeio.remove_tree(trial)
    ask.say("")
    ask.say("The new user config:")
    ask.say("-" * 60)
    ask.say(text.rstrip())
    ask.say("-" * 60)
    if old:
        diff = list(difflib.unified_diff(old.splitlines(), text.splitlines(), "now", "new",
                                         lineterm=""))
        ask.say("Changes:" if diff else "No changes.")
        for line in diff:
            ask.say("  " + line)
    if cfg.problem:
        ask.say(f"This file cannot be used: {cfg.problem}")
        ask.say("Nothing was written. Run setup again.")
        return 3
    if not cfg.roots and not cfg.patterns:
        ask.say("Note: no protected paths. The guards will do nothing until you add some.")
    if not ask.yes(f"Write it to {path}?"):
        ask.say("Nothing was written.")
        return 1
    for folder in created:  # the results folder, made only after the yes
        os.makedirs(folder, mode=0o700, exist_ok=True)
        ask.say(f"Made the results folder: {folder}")
    _write(path, text)
    ask.say(f"Written: {path} (mode 0600" + (", the old file is in .bak)" if old else ")"))
    if ssh_file:
        if os.path.lexists(ssh_file[0]):
            ask.say(f"Kept phiward's ssh config as it is: {ssh_file[0]}")
        else:
            fd = os.open(ssh_file[0], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(ssh_file[1])
            ask.say(f"Written phiward's ssh config: {ssh_file[0]}")
    from phiward import pin
    pinned_cfg = config.load(os.getcwd(), env=dict(env, PHIWARD_CONFIG=path))
    if pinned_cfg.problem:
        ask.say(f"Not pinned: the new config cannot be used: {pinned_cfg.problem}")
    else:
        approve = True
        if pinned_cfg.command_lists:
            pe = dict(env, PHIWARD_CONFIG=path)
            lines = pin.describe(pinned_cfg, pe)
            fresh = [x for x in lines if x.endswith(("(new)", "(changed)"))]
            if fresh:
                before = bool(pin.read_approved(pe))
                shown, default, found, missing = approval(lines, home_of(env), before)
                ask.say("")
                ask.say(f"Programs of [broker] commands, as they are now ({found} found, "
                        f"{missing} not installed here); the broker runs only what you approve:")
                for x in shown:
                    ask.say(f"  {x}")
                if missing:
                    ask.say("  (A program not installed here is added when you run `phiward pin` "
                            "from a terminal where it is found.)")
                approve = ask.yes(f"Approve these {found} program(s) as they are now?", default)
                if not approve:
                    ask.say("Kept your earlier approvals. While a listed program is not approved, "
                            "the broker refuses every gateway command: run `phiward pin`." if before
                            else
                            "Nothing is approved yet: gateway commands refuse every program "
                            "until you run `phiward pin`.")
        try:
            pin.write_pins(pinned_cfg, env=dict(env, PHIWARD_CONFIG=path), approve=approve)
        except OSError as exc:
            ask.say(f"Not pinned ({type(exc).__name__}); run `phiward pin` later")
        else:
            n = len(pin.pinnable(pinned_cfg))
            if n:
                ask.say(f"Recorded {n} folder(s) that phiward protects with your roots (git "
                        "folders, snapshots, other mounts), so a file planted later cannot hide "
                        "them.")

    ask.say("")
    wired = ask.yes("Wire Claude Code for every session (your user settings) now? It shows the "
                    "change it makes.", True)
    if wired:
        from phiward import install
        if path != config.user_config_path(dict(env, PHIWARD_CONFIG="")):
            os.environ["PHIWARD_CONFIG"] = path  # only a non-default place
        # the yes above is the one answer; wired only when install wrote it
        wired = install.main(["claude", "--user", "--write", "--yes"]) == 0
    ask.say("")
    started = ask.yes("Start the broker at every login now, or restart it so it uses this "
                      "config? (This runs " + ("launchctl" if sys.platform == "darwin" else
                                               "systemctl --user") + " now.)", True)
    if started:
        from phiward import service
        service.main(["--write"])
    ask.say("")
    ask.say("Next steps:")
    step = 1
    if not wired:
        ask.say(f"  {step}. Wire Claude Code:  (cd ~ && phiward install claude --user --write)")
        step += 1
    if not started:
        ask.say(f"  {step}. Start the broker:  (cd ~ && phiward broker --service --write)  (or "
                "`phiward broker` in a terminal of its own); restart it after every config change")
        step += 1
    if hpc_lines:
        ask.say(f"  {step}. HPC: add the lines above to ~/.ssh/config; before each session that "
                f"uses it, run kinit, then ssh -fN {hpc_lines[0].split()[1]}")
        step += 1
    from phiward import mcp_config
    home = pathid.home()
    bare = sorted(s.name for s in mcp_config.servers(os.getcwd(), home).values() if not s.wrapped)
    if bare:
        ask.say(f"  {step}. Your MCP server(s) {', '.join(bare)} run with your full rights, outside "
                "Claude Code's sandbox. Wrap them in phiward's kernel profile:  "
                "phiward mcp wrap --all")
        step += 1
    ask.say(f"  {step}. In a project folder:  phiward doctor; then open a new Claude Code session")
    ask.say(f"  {step + 1}. In each project with protected work:  phiward init (docs/quickstart.md)")
    return 0


def first_run(argv: List[str], fout: TextIO) -> int:
    """`setup --first-run`: the first config, without questions, for an agent that sets phiward
    up with the operator. Only when no user config exists yet; after it the agent may not change
    it. It writes protected roots and copy remotes only: no write places, no network (those are
    grants, and stay the operator's). A root where your tools load code later stays read only
    for the gateway, and a copy remote must name a work folder. The agent chooses what is
    written here, so the docs recommend that the operator runs `phiward setup` instead."""
    env = dict(os.environ)
    home = pathid.home(env)
    from phiward import install
    why = install.agent_override_problem()
    if why:
        # the first config goes to the default place: one at a path the agent names would not
        # be the config the operator's tools read
        sys.stderr.write(f"setup --first-run: {why}. Nothing was written.\n")
        return 2
    path = config.user_config_path(env)
    if os.path.lexists(path) or (not env.get("PHIWARD_CONFIG") and
                                 os.path.lexists(config.legacy_user_config_path(env))):
        sys.stderr.write("setup --first-run: a user config exists already; change it in your own "
                         "terminal with `(cd ~ && phiward setup)`. Nothing was written.\n")
        return 2
    roots: List[str] = []
    remotes: List[str] = []
    it = iter(argv)
    for w in it:
        if w in ("--root", "--remote"):
            v = next(it, "")
            why = check_root(v, home) if w == "--root" else check_remote(v)
            if not v or why:
                sys.stderr.write(f"setup --first-run: {w} {v!r}: {why or 'a value is needed'}. "
                                 "Nothing was written.\n")
                return 2
            (roots if w == "--root" else remotes).append(v)
        else:
            sys.stderr.write(USAGE)
            return 2
    if not roots:
        sys.stderr.write("setup --first-run: give at least one --root (a folder with protected "
                         "data). Nothing was written.\n")
        return 2
    data: Dict[str, Dict[str, Any]] = {"protected_paths": {"roots": roots}}
    if remotes:
        data["copy"] = {"remotes": remotes}
    _write(path, dump(data))
    fout.write(f"setup --first-run: wrote {path} with {len(roots)} protected root(s) and "
               f"{len(remotes)} copy remote(s); no write places, no network. From now on only "
               "you change it, with `(cd ~ && phiward setup)` in your own terminal.\n"
               "Next, before real patient data: run `(cd ~ && phiward setup)` in your own terminal and "
               "choose 1, which adds the list of programs gateway commands may run.\n")
    return 0


def main(argv: List[str], fin: Optional[TextIO] = None, fout: Optional[TextIO] = None) -> int:
    fin = sys.stdin if fin is None else fin
    fout = sys.stdout if fout is None else fout
    if argv[:1] in (["-h"], ["--help"]):
        fout.write(HELP)
        return 0
    if argv[:1] == ["--first-run"]:
        return first_run(argv[1:], fout)
    team: Optional[Dict[str, Dict[str, Any]]] = None
    team_name = ""
    if argv[:1] == ["--from"] and len(argv) == 2:
        team_name = argv[1]
        try:
            raw, _ = _toml.load_file(os.path.expanduser(argv[1]))
        except (OSError, UnicodeDecodeError, _toml.TomlError) as exc:
            sys.stderr.write(f"phiward setup: the team template cannot be read "
                             f"({type(exc).__name__}). Nothing was written.\n")
            return 2
        unknown = [f"{sec}.{k}" for sec, keys in raw.items() if isinstance(keys, dict)
                   for k in keys if sec not in config.SCHEMA or k not in config.SCHEMA[sec]]
        if unknown or any(not isinstance(v, dict) for v in raw.values()):
            sys.stderr.write("phiward setup: the team template has keys phiward does not know ("
                             + ", ".join(unknown[:5]) + "). Nothing was written.\n")
            return 2
        mine = [f"{sec}.{k}" for sec, keys in raw.items() for k in keys
                if (sec, k) not in TEAM_KEYS]
        paths = [str(v) for v in raw.get("sanitize", {}).get("packs", []) if "/" in str(v)]
        if mine or paths:
            sys.stderr.write("phiward setup: a team template may set only shared settings ("
                             + ", ".join(f"{a}.{b}" for a, b in sorted(TEAM_KEYS))
                             + ", packs by built-in name). It sets "
                             + ", ".join((mine + paths)[:5]) + ", which is yours to choose: "
                             "grants, files and places are never taken from a template. "
                             "Nothing was written.\n")
            return 2
        why = _team_problem(raw)
        if why:
            sys.stderr.write(f"phiward setup: the team template cannot be used: {why}. Nothing "
                             "was written.\n")
            return 2
        where = os.path.realpath(os.path.expanduser(argv[1]))
        if _in_project(where):
            sys.stderr.write("phiward setup: the team template is inside a project (a git work "
                             "tree), where an agent can change it. Read it, copy it to a folder "
                             "of your own, and give that copy. Nothing was written.\n")
            return 2
        team = raw
    elif argv:
        sys.stderr.write(USAGE)
        return 2
    try:
        tty = fin.isatty() and fout.isatty()
    except (AttributeError, ValueError):
        tty = False
    if not tty:
        sys.stderr.write("phiward setup asks questions: run it in your own terminal, not "
                         "through an agent tool. Nothing was written.\n")
        return 2
    env = dict(os.environ)
    home = pathid.home(env)
    try:
        return dialogue(Ask(fin, fout), config.user_config_path(env), home, env, team, team_name)
    except (EOFError, KeyboardInterrupt):
        fout.write("\nsetup stopped; nothing more was written.\n")
        return 1
