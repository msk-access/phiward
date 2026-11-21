"""`phiward pin`: approve the listed programs, and record the derived protected folders, as the
operator sees them now.

Derived roots (the git folders around a root, snapshot folders, other mounts of the same data)
are worked out from paths the agent may be able to write: a `.git` file planted closer to a root
would otherwise make the real git folder stop being protected on the next load. `pin` writes the
derived roots found from the operator's view to `pinned.toml` next to the user config (a guard
file: the agent cannot write it). Every later load uses the pinned folders and the folders it
finds, so a planted file can add protection but never remove a pinned folder. `doctor` warns
when the two differ.

It also approves the programs of `[broker] commands`: it lists each one with its path and a mark
(new, changed, not installed, a link that never runs, cannot be read), and after a yes records
the content of each. The broker runs only programs whose content is approved, and refuses every
request while one differs.

It runs only on a terminal (the operator's), shows the list, and writes after a yes. `setup`
pins after it writes the config.
"""

import os
import sys
from typing import List, Optional, Sequence, TextIO

from phiward import config

USAGE = ("Approve the programs of [broker] commands as they are now (the broker runs only "
         "approved ones),\nand pin the folders phiward found that hold copies of protected data; "
         "then restart the broker.\nRun it in your own terminal after you change a listed "
         "program or add a script to your scripts folder.\nusage: phiward pin\n\n"
         "Options:\n  -h, --help   show this help\n")


def pins_path(env: Optional[dict] = None) -> str:
    return os.path.join(os.path.dirname(config.user_config_path(env)), "pinned.toml")


def pinnable(cfg: config.Config) -> List[str]:
    """The derived roots worth pinning: all but the cache folder (always derived)."""
    return [d for d in (cfg.found_derived or cfg.derived_roots) if d != cfg.cache_dir]


def read_pins(env: Optional[dict] = None) -> List[str]:
    from phiward import _toml
    path = pins_path(env)
    if not os.path.isfile(path):
        return []
    try:
        raw, _ = _toml.load_file(path)
    except Exception:  # noqa: BLE001 - a bad file pins nothing; doctor reports it
        return []
    v = raw.get("pinned", {}).get("derived", []) if isinstance(raw, dict) else []
    return [x for x in v if isinstance(x, str) and x.startswith("/")]


def program_record(cfg: config.Config, path: Optional[str] = None) -> List[str]:
    """The programs `[broker] commands` allows, as the broker finds them now, each as
    "sha256  path" (content, not just the name): what the operator approves with `pin`. `path`:
    the PATH to find bare names on (the broker passes its own); else the running broker's."""
    import hashlib
    from phiward import broker
    out: List[str] = []
    for prog in broker.listed_programs(cfg, broker.program_path() if path is None else path):
        if prog.startswith(("too-many:", "missing:", "linked:")):
            out.append(f"{prog.split(':', 1)[0]}  {prog.split(':', 1)[1]}")
            continue
        try:
            with open(prog, "rb") as fh:
                h = hashlib.sha256()
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            out.append(f"{h.hexdigest()}  {prog}")
        except OSError:
            # there but not readable (mode 0111): its content cannot be approved, so it never
            # is (a "missing" line would equal itself whatever the file holds)
            out.append(f"{'unreadable' if os.path.lexists(prog) else 'missing'}  {prog}")
    return sorted(set(out))


def read_approved(env: Optional[dict] = None) -> List[str]:
    from phiward import _toml
    try:
        raw, _ = _toml.load_file(pins_path(env))
    except Exception:  # noqa: BLE001 - nothing approved
        return []
    v = raw.get("programs", {}).get("approved", []) if isinstance(raw, dict) else []
    return [x for x in v if isinstance(x, str)]


def unapproved(cfg: config.Config, env: Optional[dict] = None,
               path: Optional[str] = None) -> List[str]:
    """The listed programs that differ from what the operator approved (empty without a list).
    A program too large to check, or one that cannot be read, is never approved."""
    if not cfg.command_lists:
        return []
    have = set(read_approved(env))
    return [r.split("  ", 1)[1] for r in program_record(cfg, path)
            if r not in have or r.startswith(("too-many  ", "unreadable  ", "linked  "))]


def describe(cfg: config.Config, env: Optional[dict] = None) -> List[str]:
    """The listed programs as `pin` and `doctor` show them: each marked (new), (changed),
    (not installed) or (folder too large to check)."""
    have = read_approved(env)
    by_path = {r.split("  ", 1)[1]: r for r in have}
    out = []
    for r in program_record(cfg):
        kind, path = r.split("  ", 1)
        if kind == "too-many":
            mark = "  (folder too large to check: list fewer files)"
        elif kind == "missing":
            mark = "  (not installed)"
        elif kind == "linked":
            mark = "  (a link: never runs; list it by its name, or list its folder)"
        elif kind == "unreadable":
            mark = "  (cannot be read: never approved)"
        elif r in have:
            mark = ""
        elif path in by_path:
            mark = "  (changed)"
        else:
            mark = "  (new)"
        out.append(_shown_path(path) + mark)
    return out


def _shown_path(path: str) -> str:
    """A path as `pin`, `setup` and `doctor` print it: control characters written as `\\xNN`, so
    a file name cannot steer the terminal or look like another path."""
    import re
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", lambda m: "\\x%02x" % ord(m.group()), path)


def pins_readable(env: Optional[dict] = None) -> bool:
    from phiward import _toml
    try:
        _toml.load_file(pins_path(env))
        return True
    except Exception:  # noqa: BLE001
        return False


def write_pins(cfg: config.Config, env: Optional[dict] = None, add: Sequence[str] = (),
               drop: Sequence[str] = (), approve: bool = True) -> int:
    """Pin what is found now, keep what was pinned, plus `add`, minus `drop`."""
    from phiward.setup_cmd import _value
    path = pins_path(env)
    items = sorted((set(pinnable(cfg)) | set(read_pins(env)) | set(add)) - set(drop))
    text = ("# Derived protected folders pinned by `phiward pin` (the agent cannot write\n"
            "# this file). Every load protects these, as well as what it finds itself.\n\n"
            f"[pinned]\nderived = {_value(items)}\n")
    # the listed programs as they are now, or (approve=False) the approvals made before
    progs = program_record(cfg) if approve else read_approved(env)
    if progs:
        text += ("\n# The programs [broker] commands allows, as approved: the broker runs no "
                 "listed\n# program whose content differs.\n"
                 f"[programs]\napproved = {_value(progs)}\n")
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    from phiward import safeio
    safeio.write_new(path, text)
    return 0


def main(argv: List[str], fin: Optional[TextIO] = None, fout: Optional[TextIO] = None) -> int:
    fin = sys.stdin if fin is None else fin
    fout = sys.stdout if fout is None else fout
    if argv[:1] in (["-h"], ["--help"]):
        fout.write(USAGE + "\n" + (__doc__ or ""))
        return 0
    if argv:
        sys.stderr.write(USAGE)
        return 2
    try:
        tty = fin.isatty() and fout.isatty()
    except (AttributeError, ValueError):
        tty = False
    if not tty:
        sys.stderr.write("phiward pin asks for a yes: run it in your own terminal, not "
                         "through an agent tool. Nothing was written.\n")
        return 2
    cfg = config.load(os.getcwd())
    if cfg.problem:
        fout.write(f"pin refused: the config cannot be used: {cfg.problem}\n")
        return 3
    found = set(pinnable(cfg))
    items = sorted(found | set(read_pins()))
    fout.write(f"Derived protected folders to pin ({len(items)}):\n")
    for k, d in enumerate(items, 1):
        mark = "" if d in found else "   (pinned before, not found now)"
        fout.write(f"  {k}. {d}{mark}\n")
    fout.write("Numbers to drop (for example 2 5), or an empty line to keep all: ")
    fout.flush()
    drop: List[str] = []
    for w in fin.readline().split():
        if w.isdigit() and 1 <= int(w) <= len(items):
            drop.append(items[int(w) - 1])
    progs = program_record(cfg)
    if progs:
        lines = describe(cfg)
        missing = sum(1 for x in lines if x.endswith("(not installed)"))
        fout.write("Programs of [broker] commands to approve as they are now "
                   f"({len(lines) - missing} found, {missing} not installed here):\n")
        for line in lines:
            if not line.endswith("(not installed)"):
                fout.write(f"  {line}\n")
    fout.write(f"Write {len(items) - len(drop)} pin(s)" + (" and the programs" if progs else "")
               + f" to {pins_path()}? [y/N] ")
    fout.flush()
    if fin.readline().strip().lower() not in ("y", "yes"):
        fout.write("Nothing was written.\n")
        return 1
    write_pins(cfg, drop=drop)
    from phiward import broker
    fout.write(f"Pinned. Restart the broker so it uses them: {broker.restart_hint()}.\n")
    return 0
