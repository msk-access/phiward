"""`phiward sanitize`: stdin to stdout, every line masked. The one trusted printer.

The gateway (`phiward run`, `phiward copy`) sends every line its command prints through
this masking, in process. The `sanitize` command applies the same masking to stdin, for the git
hooks and for manual use; the hook does not allow a `| phiward sanitize` pipe as a way to
touch protected data. The filter fails closed and never echoes a line that was not masked.

A line is masked in this order (a placeholder is written in angle brackets):
1. protected paths of the config (roots, patterns, and the symlink-resolved spellings): <PROTECTED>;
   then, when the inventory is on, the name of every entry under the roots, wherever it
   appears in the line (inventory.py): <ENTRY>, or the placeholder of a file or identifier
   rule whose match holds it (so it reads as a name that does not exist would);
   (before step 1, escape sequences and control characters are removed and the line is put in
   Unicode NFKC form, so a name cannot hide behind color codes or look-alike letters);
2. the `paths` rules of the packs, then the `identifiers` rules of the packs, then the rules of
   `[sanitize] patterns` in the config;
3. name tokens from the `names_from` files and `--names-from` files: <NAME>;
4. text mode only: the `positions` rules of the packs.
Then, when the line holds another dash or digit, a root or pattern holds another dash, or
(with the inventory on) the line may hold a name in another spelling (`_more`): every protected
path with every dash of its root or pattern as `-`, every entry hit with every dash as `-`,
other decimal digits as ASCII and a long name with its separators changed or left out
(inventory.py), and each rule's own matches on the line read so (also with no inventory), each
widened to the whole of a number it starts or ends inside, are masked too, in the text the steps above left as it was;
their placeholders are not changed. So a line is never masked less than by the steps alone.
Table mode skips step 4 (a table's numeric cells are program-made numbers). This command and the
git hook use it per line. `phiward run --table` reads columns instead (`Columns`): a cell under an
identifier header is masked whole, and step 4 is skipped only for a plain number in another
column.

Packs: `[sanitize] packs` in the config (default `["genomics"]`). A name without "/" is a built-in
file `packs/<name>.toml`; a name with "/" is the path of a pack file. The pack format is described
at the top of `packs/genomics.toml`. A `keep_files` regex keeps whole file names that a <BAMFILE>
rule would mask.

Fail closed: a bad config, names file, pack or pattern stops the filter (exit 3) before it reads
a line. A line that cannot be processed, or whose masked form a second pass would change again, is
replaced by a fixed notice.

usage:
  producer 2>&1 | phiward sanitize [--names-from FILE ...] [--table]
  phiward sanitize --selftest
  phiward sanitize [--names-from FILE ...] [--table] --check FILE ...
  phiward sanitize [--names-from FILE ...] --check-table FILE ...
"""

import bisect
import fnmatch
import os
import re
import sys
from typing import (Any, BinaryIO, Dict, Iterable, List, Optional, Pattern, Sequence,
                    Set, TextIO, Tuple)

from phiward import _toml, config, inventory, paths, pathmatch

WITHHELD = "[line withheld by the sanitizer]"
KEEP_PLACEHOLDER = "<BAMFILE>"  # the placeholder whose matches `keep_files` can spare
DEFAULT_PACKS = ["genomics"]
PROBLEM_MESSAGE = ("sanitizer: the config, a names file or a pack could not be used; "
                   "stopping before any line is read (run 'phiward doctor')")
USAGE = ("Mask protected paths and identifiers in text: stdin in, the masked text out. It does "
         "not\nmask entry names under the roots; `phiward run` does. --check reports what a file "
         "would leak.\n"
         "usage: phiward sanitize [--table] [--names-from FILE]...\n"
         "       phiward sanitize --selftest\n"
         "       phiward sanitize [--names-from FILE]... --check FILE...\n"
         "       phiward sanitize [--names-from FILE]... --check-table FILE...\n")

HELP = USAGE + """
Options:
  --names-from FILE  also mask the names in FILE, an index file (tab-separated fields, as
                     `[sanitize] names_from` in docs/configuration.md); may be given again
  --table            mask each line as a table row: identifiers only, numbers and positions
                     are kept (no columns: `phiward run --table` reads columns). Only when the
                     operator turned it on ([sanitize] table = true in the user config)
  --check FILE...    read the files and report what would leak (exit 1 when something would);
                     prints no protected text
  --check-table FILE...  the same, for files read as tables
  --selftest         run the sanitizer's own made-up cases (exit 1 when one fails)
  -h, --help         show this help

The protected paths, names and identifier packs come from the config in force (`phiward
doctor` shows it). The first line says how many name tokens and rules are in force; the last
line counts the lines read and changed.
"""

PLACEHOLDER_WORDS = {"protected", "entry", "name", "sampleid", "cmoid", "bamid", "read", "locus", "num",
                     "donor", "patientpath", "clinicalpath", "bamfile", "date",
                     "idcol"}
# Words that carry no identity and appear in many paths: never a name token.
STOP_WORDS = {"data1", "share", "analysis", "star", "aligned", "sortedbycoord", "bam", "bams",
              "tumour", "normal", "inputs", "patient", "runs", "test", "scratch", "home",
              "none", "true", "false"} | PLACEHOLDER_WORDS

_PACK_KEYS = ("paths", "identifiers", "positions", "keep_files")
_PLACEHOLDER = re.compile(r"<[A-Z][A-Z0-9_]*>")
_PACK_NAME = re.compile(r"[A-Za-z0-9_-]+")

Rule = Tuple["Pattern[str]", str]


class SanitizerError(Exception):
    """The sanitizer cannot be built (fail closed)."""


def fmt_n(n: int) -> str:
    """A count for a log line without a run of five digits: 1234, 12.3k, 1.2M."""
    if n < 10000:
        return str(n)
    if n < 1_000_000:
        return f"{n / 1000:.1f}k"
    return f"{n / 1_000_000:.1f}M"


# identifier placeholders of the built-in packs that name no subject or sample (files, reads,
# dates)
NOT_SUBJECTS = frozenset({"<BAMFILE>", "<READ>", "<DATE>"})
IDENTIFIER_NOTE_LINES = 20  # shown lines from which a run with no identifier placeholder says so


def placeholder_note(counts: Dict[str, int], held: int, lines: int, identifiers: "Set[str]") -> str:
    """The note at the end of a run, from the lines the agent was shown: how many placeholders
    of each kind they hold and how many were withheld lines; and, from IDENTIFIER_NOTE_LINES
    shown lines on, that none holds an identifier placeholder. "" when there is nothing to say.
    Only fixed words, counts and the config's own placeholder names."""
    kinds = [f"{fmt_n(n)} {p}" for p, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    if held:
        kinds.append(f"{fmt_n(held)} lines withheld by the sanitizer")
    warn = ""
    if lines >= IDENTIFIER_NOTE_LINES and not (set(counts) & identifiers):
        warn = (f"in the {fmt_n(lines)} lines shown: if this data names subjects or samples, tell "
                "the operator to check [sanitize] packs and patterns (phiward doctor)")
    if kinds:
        return "[placeholders in the lines shown: " + ", ".join(kinds) + \
            (f"; no identifier placeholder {warn}" if warn else "") + "]"
    return f"[no placeholder {warn}]" if warn else ""


# ---- rules and packs ---------------------------------------------------------------------------

def parse_rule(text: str, where: str) -> Rule:
    """'REGEX => <PLACEHOLDER>' as a compiled regex and its placeholder."""
    regex, sep, repl = text.rpartition(" => ")
    repl = repl.strip()
    if not sep or not regex or not _PLACEHOLDER.fullmatch(repl):
        raise SanitizerError(f"{where}: a rule must read 'REGEX => <PLACEHOLDER>'")
    rx = _compile(regex, where)
    if rx.search("") is not None:
        raise SanitizerError(f"{where}: a rule must not match the empty string")
    return rx, repl


def _compile(regex: str, where: str) -> "Pattern[str]":
    try:
        return re.compile(regex)
    except (re.error, RecursionError, OverflowError) as exc:
        raise SanitizerError(f"{where}: a regex does not compile ({type(exc).__name__})")


class Pack:
    def __init__(self, name: str):
        self.name = name
        self.paths: List[Rule] = []
        self.identifiers: List[Rule] = []
        self.positions: List[Rule] = []
        self.keep_files: List[Pattern[str]] = []
        # placeholders of this pack's paths and identifiers rules that are details, not
        # identifiers: the prompt scan leaves them out. Kept for a built-in pack only (the label
        # is trusted from the package, never from a pack file)
        self.detail: Set[str] = set()


def pack_path(name: str) -> str:
    if "/" in name:
        return os.path.expanduser(name)
    if not _PACK_NAME.fullmatch(name):
        raise SanitizerError(f"pack '{name}': not a valid built-in pack name")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "packs", name + ".toml")


def load_pack(name: str) -> Pack:
    where = f"pack '{name}'"
    path = pack_path(name)
    try:
        data, _ = _toml.load_file(path, follow=False)  # never through a link
    except (OSError, UnicodeDecodeError) as exc:
        raise SanitizerError(f"{where}: cannot be read ({type(exc).__name__})")
    except _toml.TomlError as exc:
        raise SanitizerError(f"{where}: does not parse: {exc}")
    if set(data) != {"pack"} or not isinstance(data["pack"], dict):
        raise SanitizerError(f"{where}: must hold one [pack] table")
    body: Dict[str, Any] = data["pack"]
    pack = Pack(name)
    for key, value in body.items():
        if key == "name":
            if not isinstance(value, str):
                raise SanitizerError(f"{where}: 'name' must be a string")
        elif key in _PACK_KEYS:
            if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
                raise SanitizerError(f"{where}: '{key}' must be a list of non-empty strings")
        elif key == "detail":
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise SanitizerError(f"{where}: 'detail' must be a list of placeholders")
        else:
            raise SanitizerError(f"{where}: unknown key '{key}'")
    for key in ("paths", "identifiers", "positions"):
        getattr(pack, key).extend(parse_rule(v, f"{where} {key}") for v in body.get(key, []))
    pack.keep_files = [_compile(v, f"{where} keep_files") for v in body.get("keep_files", [])]
    written = {r for _rx, r in pack.paths + pack.identifiers}
    detail = set(body.get("detail", []))
    if not detail <= written:
        raise SanitizerError(f"{where}: 'detail' names a placeholder that none of its paths or "
                             "identifiers rules writes")
    if "/" not in name:
        pack.detail = detail
    return pack


# built-in packs whose rules mask subject or sample identifiers (an example institution's forms)
SUBJECT_PACKS = ("msk",)


def masks_subjects(cfg: "config.Config") -> bool:
    """Whether the operator's own config masks subject or sample identifiers inside files: its own
    [sanitize] patterns or names_from, a built-in subject pack, or a pack file with an identifier
    rule for something other than files, reads or dates. Only the user config counts (a repo
    file, which the agent can write, may add packs too). Raises SanitizerError when a pack file
    cannot be read."""
    if cfg.sanitize_patterns or cfg.names_from:
        return True
    for name in cfg.user_packs:
        if name in SUBJECT_PACKS:
            return True
        if "/" in name and any(r not in NOT_SUBJECTS for _rx, r in load_pack(name).identifiers):
            return True
    return False


def subject_sanitizer(cfg: "config.Config") -> "Sanitizer":
    """The project scan's sanitizer: the path and identifier rules of the effective packs (a
    repo file's built-in packs too: it can only add) and of `[sanitize] patterns`, less details
    and the placeholders that name no subject (NOT_SUBJECTS); no positions, names, entries or
    protected paths. Raises SanitizerError."""
    import dataclasses
    base = Sanitizer.from_config(dataclasses.replace(cfg, names_from=[]), identifiers_only=True)
    return Sanitizer(None, [r for r in base.path_rules if r[1] not in NOT_SUBJECTS],
                     [r for r in base.id_rules if r[1] not in NOT_SUBJECTS],
                     keep_files=base.keep_files)


# ---- name tokens -------------------------------------------------------------------------------

def name_tokens(lines: Iterable[str], stop: Optional[Iterable[str]] = None) -> "set[str]":
    """The name tokens of index-TAB-path lines: each path part, its sample part (before the first
    dot), and the dash/underscore pieces of the sample part, of 4 or more characters, never a
    stop word and never a bare number. Case does not matter."""
    stops = {s.lower() for s in (STOP_WORDS if stop is None else stop)}
    toks: set[str] = set()

    def add(t: str) -> None:
        if len(t) >= 4 and not t.isdigit() and t.lower() not in stops and t.isascii():
            toks.add(t)

    for line in lines:
        for field in line.rstrip("\r\n").split("\t"):
            if "/" not in field:
                continue
            for part in (p for p in field.split("/") if p):
                for cand in {part, part.split(".")[0]}:
                    add(cand)
                    for piece in (p for p in re.split(r"[-_.]", cand) if p):
                        add(piece)
                    if cand.count("-") >= 1:
                        add("-".join(cand.split("-")[:2]))
    return toks


def _read_names_file(path: str, stop: Iterable[str]) -> "set[str]":
    from phiward import safeio
    try:
        # never through a link, never blocking: a `--names-from` file comes from the agent
        text = safeio.read_text(os.path.expanduser(path))
        got = name_tokens(text.splitlines(), stop)
    except (OSError, UnicodeDecodeError) as exc:
        raise SanitizerError(f"a names file cannot be read ({type(exc).__name__})")
    if not got:
        raise SanitizerError("a names file yields no token")
    return got


# ---- the sanitizer -----------------------------------------------------------------------------

class Sanitizer:
    def __init__(self, protected: Optional["paths.ProtectedSet"] = None,
                 path_rules: Sequence[Rule] = (), id_rules: Sequence[Rule] = (),
                 pos_rules: Sequence[Rule] = (), keep_files: Sequence["Pattern[str]"] = (),
                 tokens: Iterable[str] = (), entries: Iterable[str] = (),
                 known: Iterable[str] = (), roots: Iterable[str] = ()):
        # the protected roots and patterns: their matches in a line (`text_spans`)
        self.protected = protected if protected else None
        # a root or pattern with another dash: the overlay looks for it written with `-` in
        # every line (`_paths`)
        self.dashed_roots = self.protected is not None and any(
            inventory.normalize(p) != p
            for p in list(self.protected.roots) + list(self.protected.patterns))
        # the folders a protected pattern matches now, as `_key`s, and their lengths as written
        # (folding can change a length: `ß`), longest first: a protected match that starts with
        # one is marked to its end (`_marked`)
        known = list(known)
        self.known = {_key(k) for k in known}
        self.known_lengths = sorted({len(k) for k in known}, reverse=True)
        self.root_keys = {_key(r) for r in roots}  # the roots' own spellings
        # rules applied before every other step: the remote roots of `run --remote`, so a local
        # entry name inside a remote path cannot break its match
        self.first_rules: List[Rule] = []
        self.path_rules = list(path_rules)
        self.id_rules = list(id_rules)
        self.pos_rules = list(pos_rules)
        self.keep_files = list(keep_files)
        # a long name is also matched with its separators left out, but not when that form is a
        # stop word or lies inside a placeholder's word (the second pass would withhold the line)
        words = PLACEHOLDER_WORDS | {p.strip("<>").replace("_", "") for p in self.placeholders()}
        self.entries = inventory.matcher(entries, STOP_WORDS, words)
        # the placeholders the steps write, longest first (remote roots, added later, write
        # <PROTECTED>, already one of them)
        self.holes = re.compile("|".join(re.escape(p) for p in sorted(self.placeholders(),
                                                                       key=len, reverse=True)))
        self.tokens = sorted(set(tokens), key=len, reverse=True)
        self.re_names: Optional[Pattern[str]] = None
        if self.tokens:
            alt = "|".join(re.escape(t) for t in self.tokens)
            self.re_names = re.compile(rf"(?<![A-Za-z0-9])(?:{alt})(?![A-Za-z0-9])", re.I)

    @classmethod
    def from_config(cls, cfg: "config.Config", extra_names_from: Sequence[str] = (),
                    entries: bool = False, names_lines: Sequence[str] = (),
                    identifiers_only: bool = False) -> "Sanitizer":
        """Build from a loaded config (and extra names files). With `entries`, it also lists the
        protected roots and masks every entry name (the caller must be able to read the roots).
        With `identifiers_only` (the prompt scan): no detail rules of a built-in pack, no
        positions, no names, no entries, and only the configured roots and patterns.
        Raises SanitizerError."""
        return cls._build(cfg, list(extra_names_from), list(names_lines), entries,
                          identifiers_only)

    @classmethod
    def _build(cls, cfg: "config.Config", names_files: Sequence[str],
               name_lines: Iterable[str], entries: bool = False,
               identifiers_only: bool = False) -> "Sanitizer":
        try:
            if identifiers_only:
                names_files, name_lines, entries = [], [], False
            if cfg.problem:
                raise SanitizerError("the config has a problem")
            names: List[str] = []
            for pack_name in (cfg.packs or DEFAULT_PACKS):
                if pack_name not in names:
                    names.append(pack_name)
            packs = [load_pack(n) for n in names]
            drop = (lambda p, r: r[1] in p.detail) if identifiers_only else (lambda p, r: False)
            path_rules = [r for p in packs for r in p.paths if not drop(p, r)]
            id_rules = [r for p in packs for r in p.identifiers if not drop(p, r)]
            id_rules += [parse_rule(v, "[sanitize] patterns") for v in cfg.sanitize_patterns]
            # identifiers in any letter case: entry names are matched in any case too
            id_rules = [(re.compile(rx.pattern, rx.flags | re.IGNORECASE), r) for rx, r in id_rules]
            pos_rules = [] if identifiers_only else [r for p in packs for r in p.positions]
            keep = [k for p in packs for k in p.keep_files]
            # Stop words come from the built-in list only: a rule's placeholder must never
            # exempt an entry name or a name token from masking.
            stop = set(STOP_WORDS)
            tokens = name_tokens(name_lines, stop) if name_lines else set()
            for f in ([] if identifiers_only else list(cfg.names_from)) + list(names_files):
                tokens |= _read_names_file(f, stop)
            # with the inventory (a gateway run): every folder a pattern matches now, looked up
            # in a set (a regex of tens of thousands of paths takes minutes to build)
            known = {f for p in cfg.patterns for m in pathmatch.matches(p)
                     for r in (m, os.path.realpath(m)) for f in (r, normalize(r))
                     } if entries else set()
            pset = paths.ProtectedSet(cfg.roots if identifiers_only else cfg.all_roots,
                                      cfg.patterns)
            roots = {f for r in pset.roots for f in (r, normalize(r))}
            ents: set[str] = set()
            if entries:
                try:
                    ents = inventory.build(cfg.roots, cfg.patterns, cfg.inventory_limit,
                                           {w.casefold() for w in stop})
                except inventory.InventoryError as exc:
                    raise SanitizerError(str(exc))
            return cls(pset, path_rules, id_rules, pos_rules, keep, tokens, ents, known, roots)
        except SanitizerError:
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed on anything
            raise SanitizerError(f"cannot build the sanitizer ({type(exc).__name__})")

    def placeholders(self) -> "Set[str]":
        """Every placeholder this sanitizer writes (computed when asked: remote roots are added
        after the build)."""
        rules = self.first_rules + self.path_rules + self.id_rules + self.pos_rules
        return {r for _rx, r in rules} | {"<PROTECTED>", "<ENTRY>", "<NAME>"}

    def identifier_placeholders(self) -> "Set[str]":
        """The placeholders that stand for a subject, a sample or a protected name: identifier
        and path rules (a patient's folder), names, entries and protected paths (not files,
        reads, dates, positions or numbers)."""
        return {r for _rx, r in self.path_rules + self.id_rules if r not in NOT_SUBJECTS} | \
            {"<PROTECTED>", "<ENTRY>", "<NAME>"}

    def _apply(self, rules: Sequence[Rule], line: str) -> str:
        for rx, repl in rules:
            if repl == KEEP_PLACEHOLDER and self.keep_files:
                line = rx.sub(lambda m, r=repl: m.group(0) if self._kept(m.group(0)) else r, line)
            else:
                line = rx.sub(lambda _m, r=repl: r, line)
        return line

    def _kept(self, token: str) -> bool:
        base = token.rsplit("/", 1)[-1]
        return any(k.fullmatch(base) for k in self.keep_files)

    def _mask(self, line: str, table: bool) -> str:
        return self._more(line, self._steps(line, table), table)

    def _more(self, line: str, out: str, table: bool) -> str:
        """`out`, the steps' output for `line`, with the protected paths and names in other
        spellings masked too (`_paths`, `inventory.matcher`), and each rule's own matches on the line read as `inventory.fold` writes it; each widened to
        the whole of a number it starts or ends inside. Only where `out` still shows the line's
        own characters (`_shown`): what the steps masked stays as they wrote it."""
        folded = inventory.fold(line)
        found = self._paths(folded) if self.protected is not None and (
            folded != line or self.dashed_roots) else []
        if folded == line and not found and (self.entries is None
                                             or not self.entries.other(folded)):
            return out
        found += [] if self.entries is None else [(s, e, "<ENTRY>", -1)
                                                  for s, e in self.entries.spans(line)]
        rules = self.path_rules + self.id_rules + ([] if table else self.pos_rules)
        for k, (rx, repl) in enumerate(rules):
            found += [(m.start(), m.end(), repl, k) for m in rx.finditer(folded)
                      if m.end() > m.start() and not (repl == KEEP_PLACEHOLDER and self.keep_files
                                                      and self._kept(m.group(0)))]
        if self.re_names is not None:
            found += [(m.start(), m.end(), "<NAME>", len(rules))
                      for m in self.re_names.finditer(folded) if m.end() > m.start()]
        if not found:
            return out
        places = _shown(line, out, self.holes)
        # spans and pieces are both in line order and do not overlap among themselves: one walk
        cuts: List[Tuple[int, int, str]] = []
        j = 0
        for s, e, r in _whole_numbers(line, found, table):
            while j < len(places) and places[j][1] + places[j][2] <= s:
                j += 1
            k = j
            while k < len(places) and places[k][1] < e:
                o, a, n = places[k]
                lo, hi = max(s, a), min(e, a + n)
                if lo < hi:
                    cuts.append((o + lo - a, o + hi - a, r))
                k += 1
        parts, pos = [], 0
        for s, e, r in cuts:
            parts += [out[pos:s], r]
            pos = e
        parts.append(out[pos:])
        return "".join(parts)

    def _steps(self, line: str, table: bool) -> str:
        line = self._apply(self.first_rules, line)
        if self.protected is not None:
            # another spelling of a path (`<root>\/Zorro` from JSON, `<root>//x`, `<root>/./x`):
            # the line is read plain where that makes a protected path, so the name after it
            # is masked too
            plain = paths.plain_spelling(line)
            spans = self.protected.text_spans(plain) if plain != line else []
            if spans:
                # plain from the first protected path on; the text before it stays as written
                plain, pos = paths.plain_spelling_map(line)
                cut = spans[0][0]
                line = line[:pos[cut]] + plain[cut:]
        if self.protected is not None:
            # the root (or pattern) part first, as a mark; then the entry names, which may hold
            # spaces; then the mark with the rest of the path (names, now placeholders, and
            # path characters) becomes one placeholder: no part of `Doe Jane/x` is left
            line = self._marked(line)
        line = self._entries(line)
        if self.protected is not None:
            # a mark and the rest of its path; one whose path goes on past the root or the
            # pattern (`<root>/New Person 7`) is followed by `_GOES_ON` for `_tail`
            line = _AFTER_MARK.sub(
                lambda m: "<PROTECTED>" + (_GOES_ON if len(m.group(0)) > 1 else ""), line)
            line = _tail(line)
        line = self._apply(self.path_rules, line)
        line = self._apply(self.id_rules, line)
        if self.re_names is not None:
            line = self.re_names.sub("<NAME>", line)
        if not table:
            line = self._apply(self.pos_rules, line)
        return line

    def _entries(self, line: str) -> str:
        """Entry names as `<ENTRY>`; but where an entry name lies inside what a file or
        identifier rule matches, that whole match becomes the rule's placeholder, as it would for
        a name that does not exist. The same text is masked as before (or more): only which
        placeholder it reads as changes."""
        rx = self.entries
        if rx is None:
            return line
        hits = [(m.start(), m.end()) for m in rx.finditer(line)]
        if not hits:
            return line
        spans: List[Tuple[int, int, str]] = []
        for rule, repl in self.path_rules + self.id_rules:
            spans += [(m.start(), m.end(), repl) for m in rule.finditer(line)
                      if m.end() > m.start() and _MARK not in m.group(0)
                      and not (repl == KEEP_PLACEHOLDER and self.keep_files
                               and self._kept(m.group(0)))]
        parts: List[Tuple[int, int, str]] = []
        for a, b in hits:
            cover = next(((s, e, r) for s, e, r in spans if s <= a and b <= e), None)
            parts.append(cover or (a, b, "<ENTRY>"))
        parts.sort()
        merged: List[List] = []
        for a, b, r in parts:  # overlapping parts are joined; <ENTRY> wins a tie (more masked)
            if merged and a < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
                if r == "<ENTRY>" or merged[-1][2] != r:
                    merged[-1][2] = "<ENTRY>"
            else:
                merged.append([a, b, r])
        out, pos = [], 0
        for a, b, r in merged:
            out += [line[pos:a], r]
            pos = b
        out.append(line[pos:])
        return "".join(out)

    def _marked(self, line: str) -> str:
        """Every protected root or pattern match as the mark. A pattern's wildcard may hold
        spaces, so its match runs to the end of the name, or past it. When the longest folder
        the pattern matches now starts at the match, that folder is marked whole (also when it
        holds characters the wildcard stops at: `phi_O'Brien Pat`), and the text after it is
        kept only when no name can go on there (`/`, a tab, the line's end, a count as in
        `: 12 reads`); otherwise the mark runs to the end of the line, so a longer name that is
        not on disk never leaks. An open match (its last wildcard met a quote or a shell
        character: `phi_New;Quux`) that no such folder covers runs to the end of the line too.
        Every match counts, also one inside or across another: overlapping matches are joined."""
        if self.protected is None:
            return line
        out: List[str] = []
        pos = 0
        for start, end in self._marks(line, self.protected.text_spans(line)):
            out += [line[pos:start], _MARK]
            pos = end
        out.append(line[pos:])
        return "".join(out)

    def _marks(self, line: str, spans: Sequence[Tuple[int, int, bool]]
               ) -> List[Tuple[int, int]]:
        """Where `_marked` puts its marks, for the protected matches `spans` in `line`."""
        marks: List[Tuple[int, int]] = []
        for start, end, open_ in spans:
            for size in self.known_lengths:
                stop = start + size
                if stop <= len(line) and _key(line[start:stop]) in self.known and \
                        (stop == len(line) or not _NAME_CHAR.match(line[stop])):
                    end = stop if _KEEP_AFTER.match(line, stop) else _line_end(line, stop)
                    break
            else:
                if open_ and _key(line[start:end]) not in self.root_keys:
                    end = _line_end(line, end)
            end = max(end, start + 1)
            if marks and start <= marks[-1][1]:
                marks[-1] = (marks[-1][0], max(marks[-1][1], end))
            else:
                marks.append((start, end))
        return marks

    def _paths(self, folded: str) -> List[Tuple[int, int, str, int]]:
        """The protected paths in `folded` (a line as `inventory.fold` writes it) where a root or
        pattern is read with every dash as `-`, as the steps would mask them: each mark with
        the rest of its path, to the next tab or the line's end when the name goes on."""
        found = []
        for start, end in self._marks(folded, self.protected.text_spans(folded, dashes=True)):
            stop = _REST_OF_PATH.match(folded, end).end()
            if stop > end and not _ENDED.match(folded, stop):
                stop = _line_end(folded, stop)
            found.append((start, stop, "<PROTECTED>", -2))
        return found

    def clean(self, line: str, table: bool = False) -> str:
        """The line with its identifiers masked (table mode: identifiers only). Never raises:
        a line it cannot process comes back as the fixed notice."""
        try:
            line = normalize(line)
            out = self._mask(line, table)
            # the masks must not leave what they mask: a second pass changes nothing (a line
            # the masks left as it was is that second pass already)
            if out != line and self._mask(out, table) != out:
                return WITHHELD
            # nor a name written with escapes, as ordinary tools print one (git's octal quoting,
            # JSON's \u, Python's \x, a URL's %XX): the masked line, decoded, holds nothing
            # more to mask (the line is not rewritten: its escapes may be what its reader needs)
            if "\\" in out or "%" in out:
                plain = normalize(unescape(out))
                if plain != out and self._mask(plain, table) != plain:
                    return WITHHELD
            return out
        except Exception:  # noqa: BLE001 - fail closed on anything
            return WITHHELD


# ---- column mode (`phiward run --table` only) ---------------------------------------------------

IDCOL = "<IDCOL>"
# column headers that name an identifier, as `col_key` globs; `[sanitize] id_columns` (user config
# only) adds to them. Broad on purpose: a numeric column such as `n_samples` shows <IDCOL>
BUILTIN_ID_COLUMNS = (
    "id", "id*", "*id", "*_ids", "*_id_*", "pt", "pt_*", "*_pt", "subj*", "*sample*", "*patient*",
    "*subject*", "*donor*", "*mrn*", "*barcode*", "*accession*", "*specimen*", "*record*",
    "*chart*", "*encounter*", "*visit*", "*ssn*", "*phone*", "*zip*", "*_no", "*number*", "case",
    "case_*", "*_case", "*birth*", "*dob*", "*num", "*nbr", "*rec*", "acc*", "caseno", "ptno",
    "patno", "labno", "empi", "fin", "csn", "participant*", "individual*", "proband*", "person*",
    "*date*")
# an `[sanitize] id_columns` entry as written: a header or a glob
ID_COLUMN_ENTRY = re.compile(r"[A-Za-z0-9 _.#*?\[\]!-]{1,64}")
_HEADER_FIELD = re.compile(r"#?[A-Za-z_][A-Za-z0-9_ .()/%+\-]{0,63}")
_NUMBER = re.compile(r"[-+]?(?:(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?|\.\d+)(?:[eE][-+]?\d+)?%?")
_PCT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
NO_HEADER_NOTE = "[--table: no header line was found; the output was masked as text]"


def col_key(name: str) -> str:
    """A column header (or an `id_columns` entry) in the form globs are matched against: spaces
    stripped, one leading `#` dropped, case folded, each run of spaces, `-` and `.` as `_`
    (`Patient ID`, `sample-id`, `#Sample.ID` become `patient_id`, `sample_id`)."""
    name = name.strip()
    if name.startswith("#"):
        name = name[1:].strip()
    return re.sub(r"[ .\-]+", "_", name.casefold())


def _words(norm: str, delim: str) -> bool:
    """Whether the line has 2 or more fields and each looks like a column name: a letter or `_`
    first (after an optional `#`), no quote, no run of 3 digits."""
    fields = norm.split(delim)
    return len(fields) >= 2 and all(
        _HEADER_FIELD.fullmatch(f.strip()) and not re.search(r"\d{3}", f) for f in fields)


class _Misfit(Exception):
    """A row that cannot be read by column (it is masked as text)."""


class Columns:
    """Masks the lines of one `phiward run --table` output by column. One table per output:
    its header is the first non-empty line, when it looks like one and names an identifier
    column (`_header`). Each row under
    it is masked as in table mode on the whole line; then each cell under an identifier header
    becomes <IDCOL>, and the positions rules run on each other cell that is not a plain number.
    The first line that is not such a row (an empty line, another field count, a quote or an
    escape, a mask that eats a delimiter, no plain-number cell, as in another header) ends
    column mode: it and every later line are masked as text (`Sanitizer.clean`). Made fresh for
    each run."""

    def __init__(self, san: Sanitizer, extra_globs: Iterable[str] = ()):
        self.san = san
        self.globs = list(BUILTIN_ID_COLUMNS) + [col_key(g) for g in extra_globs]
        # an ID cell that is exactly one of these is kept (the masks of the line already
        # replaced it)
        self.known = san.placeholders() | {IDCOL}
        self.state = "start"  # "start": no non-empty line yet; "table"; "none": text to the end
        self.delim = "\t"
        self.width = 0
        self.is_id: List[bool] = []
        self.headers = 0  # header lines found (0 or 1)
        self.rows = 0  # rows read by column
        self._plain = ""  # the last row as the steps alone show it (`_row`)

    def reset(self) -> None:
        """Text mode to the end (after a line too long to read)."""
        self.state = "none"

    def line(self, text: str) -> str:
        """The line as shown. Never raises."""
        try:
            norm = normalize(text)
            if self.state == "start":
                shown = self.san.clean(text)
                if norm != "":
                    self.state = "none"
                    if self._header(norm, shown):
                        self.state = "table"
                        self.headers += 1
                return shown
            if self.state == "table":
                try:
                    out = self._row(norm)
                except _Misfit:
                    self.state = "none"
                    return self.san.clean(text)
                # the second pass: the shown row read again gives itself, else it is withheld.
                # The table ends where it ended before: when the row as the steps alone show it
                # (`_plain`) fails its own second pass. A row that fails only by a mask in
                # another spelling (it can leave a root right before a placeholder) is
                # withheld, and the table goes on
                plain = self._plain
                why = self._check(out)
                if plain != out:
                    before = self._check(plain, plain=True)
                else:
                    before = None if why in (None, "more") else why
                if before is not None:
                    self.state = "none"
                    return WITHHELD
                if why is not None:
                    return WITHHELD
                self.rows += 1
                return out
            return self.san.clean(text)
        except Exception:  # noqa: BLE001 - fail closed on anything
            self.state = "none"
            return WITHHELD

    def _header(self, norm: str, shown: str) -> bool:
        if shown != norm:  # a field holds an identifier, a protected path or a name
            return False
        delim = "\t" if "\t" in norm else "," if "," in norm else ""
        # every field looks like a column name, and nothing a path or identifier rule matches
        # is in it: a first line of data is not a header
        if not delim or not _words(norm, delim):
            return False
        fields = norm.split(delim)
        rules = self.san.first_rules + self.san.path_rules + self.san.id_rules
        if any(rx.search(f) for f in fields for rx, _r in rules):
            return False
        is_id = [any(fnmatch.fnmatchcase(col_key(f), g) for g in self.globs) for f in fields]
        # a header names an identifier column: a first line of prose with commas (`Results,
        # see below`) or a table without one is text
        if not any(is_id):
            return False
        self.delim, self.width, self.is_id = delim, len(fields), is_id
        return True

    def _mask(self, line: str) -> str:
        """The line as the steps mask it in table mode (`_row` reads the columns in it)."""
        return self.san._steps(line, True)

    def _check(self, out: str, plain: bool = False) -> Optional[str]:
        """None when the shown row `out`, read again, gives itself; else "more" when only a mask
        in another spelling changed it, or "steps"."""
        try:
            if normalize(out) == out and self._row(out, again=True, plain=plain) == out:
                return None
            return "steps"
        except _Misfit as exc:
            return exc.args[0] if exc.args else "steps"

    def _row(self, norm: str, again: bool = False, plain: bool = False) -> str:
        """The row masked by column; `_Misfit` when it cannot be read so. `again`: the second
        pass, where the masks of the whole line must change nothing. `plain`: the row as it was
        read before the masks in other spellings. The first pass also keeps that row in
        `_plain`."""
        d, n = self.delim, self.width - 1
        # a quoted CSV row is not parsed; and an escape has no form by column
        if '"' in norm or "\\" in norm or _PCT_ESCAPE.search(norm) or norm.count(d) != n:
            raise _Misfit()
        # the masks of today's table mode, on the whole line (an entry name may hold the
        # delimiter); a mask that ate a delimiter makes a misfit
        m = self._mask(norm)
        if m.count(d) != n or (again and m != norm):
            raise _Misfit()
        cells = m.split(d)
        # a row with no plain-number cell (another header, as from `cat a.csv b.csv`, or a row
        # of words) is not read: it may start other columns (on the second pass, an ID cell
        # that was a number is <IDCOL>)
        if not again and not any(_NUMBER.fullmatch(c.strip()) for c in cells):
            raise _Misfit()
        for i, c in enumerate(cells):
            core = c.strip()
            if self.is_id[i]:
                if core and core not in self.known:
                    cells[i] = IDCOL
            elif not _NUMBER.fullmatch(core):
                cells[i] = self.san._apply(self.san.pos_rules, c)
        if not plain:
            # then the masks in other spellings, in each cell but an ID cell on its own (`_more`,
            # on the cell as just masked): they never cross a delimiter, nor change a mask
            if not again:
                self._plain = d.join(cells)
            more = [c if self.is_id[i] else self.san._more(a, c, True)
                    for i, (a, c) in enumerate(zip(norm.split(d), cells))]
            if again and more != cells:
                raise _Misfit("more")
            cells = more
        return d.join(cells)


_MARK = "\x00"  # never in a line: normalize removes control characters
# a number: digits joined by `:` (`12:00`, `1:2345`); in text mode also a number of a million or
# more in groups of thousands (`1,234,567`), as the `genomics` number rule reads one. Otherwise a
# comma is a separator (a CSV row: `0001,123` is two cells), so a mask never takes one in
_NUMBER_RUN = re.compile(r"\d+(?::\d+)*")
_NUMBER_RUN_TEXT = re.compile(r"(?<![\d,])\d{1,3}(?:,\d{3}){2,}(?![\d,])|\d+(?::\d+)*")


def _whole_numbers(line: str, found: Sequence[Tuple[int, int, str, int]], table: bool
                   ) -> List[Tuple[int, int, str]]:
    """Each (start, end, placeholder, rank) of `found` widened to the whole of a number
    (`_NUMBER_RUN`; in text mode `_NUMBER_RUN_TEXT`) it starts or ends inside, so no part of a
    number is left bare; overlapping ones joined, with one placeholder: `<PROTECTED>` when a protected path (rank -2) is in it,
    else a rule's match that covers the joined span (the first rule), else `<ENTRY>` when a
    name (rank -1) is in it, else that of the span that starts first."""
    runs = [(n.start(), n.end())
            for n in (_NUMBER_RUN if table else _NUMBER_RUN_TEXT).finditer(line)]
    starts = [ns for ns, _ne in runs]

    def run_at(i: int) -> Optional[Tuple[int, int]]:
        k = bisect.bisect_right(starts, i) - 1
        return runs[k] if k >= 0 and runs[k][0] < i < runs[k][1] else None
    wide = sorted(((run_at(s) or (s, s))[0], (run_at(e) or (e, e))[1], r, k)
                  for s, e, r, k in found)
    groups: List[List[Tuple[int, int, str, int]]] = []
    end = -1  # the furthest end in the last group
    for f in wide:
        if groups and f[0] < end:
            groups[-1].append(f)
            end = max(end, f[1])
        else:
            groups.append([f])
            end = f[1]
    out: List[Tuple[int, int, str]] = []
    for g in groups:
        s, e = g[0][0], max(f[1] for f in g)
        whole = [f for f in g if f[0] == s and f[1] == e and f[3] >= 0]
        names = [f for f in g if f[3] == -1]
        r = "<PROTECTED>" if any(f[3] == -2 for f in g) else \
            min(whole, key=lambda f: f[3])[2] if whole else "<ENTRY>" if names else g[0][2]
        out.append((s, e, r))
    return out


def _shown(line: str, out: str, holes: "Pattern[str]") -> List[Tuple[int, int, int]]:
    """Where `out` (the steps' output for `line`) still shows `line`'s own text: (place in
    `out`, place in `line`, length) of each piece between two placeholders, found in `line`
    in order (the first at the start, the last at the end when it fits; after a placeholder, at
    least one character on). A piece not found is left out: nothing is masked in it, and the
    second pass withholds the line if it still shows a name."""
    places: List[Tuple[int, int, int]] = []
    pieces = []
    pos = 0
    for m in holes.finditer(out):
        pieces.append((pos, out[pos:m.start()]))
        pos = m.end()
    pieces.append((pos, out[pos:]))
    at = 0
    for k, (o, text) in enumerate(pieces):
        if not text:
            at += k > 0
            continue
        if k == 0:
            a = 0 if line.startswith(text) else -1
        elif k == len(pieces) - 1 and line.endswith(text) and len(line) - len(text) >= at + 1:
            a = len(line) - len(text)
        else:
            a = line.find(text, at + 1)
        if a >= 0:
            places.append((o, a, len(text)))
            at = a + len(text)
    return places


_NAME_CHAR = re.compile(r"[\w.\-]")  # a character that would go on with a name
# after a folder on disk: text that cannot be more of a name (a path goes on, a tab, the end,
# or after `: ` counts, each with at most one plain unit, to a tab or the end: `: 12 reads, 3
# errors`). Numbers after a space are not kept: `phi_Ann 4471` may be a longer name
_COUNT = r"\d[\d.,]*(?: (?:" + "|".join([
    "reads?", "lines?", "files?", "folders?", "bytes?", "matches?", "errors?", "warnings?",
    "entries", "entry", "records?", "rows?", "items?", "samples?", "variants?", "calls?",
    "[KMGT]i?B", "kB", "%"]) + "))?"
_KEEP_AFTER = re.compile(r"$|/|\t|:$|[^\S\t]+(?=/)|: " + _COUNT + r"(?:, " + _COUNT +
                         r")*(?=\t|$)")
_GOES_ON = "\x01"  # after a mask whose path went on inside a root or a match (never in a line)
# where a name inside a protected path has clearly ended: the line's end, a tab, or spaces and
# another path (`cp <root>/a /tmp/b`). Anything else may be more of a name that is not on disk
# (`<root>/New Person 7`, `<root>/O'Brien`, `'<root>/O' Brien'`, `<root>/Doe; Jane`), so the
# mask runs to the next tab or the line's end: P5 holds by construction, and ordinary text
# after such a path (`cat '<root>/x' done`) is lost
_ENDED = re.compile(r"[^\S\t]*(?:$|(?=\t)|(?<=[^\S\t])(?=/)|(?=<PROTECTED>))")


def _tail(line: str) -> str:
    """The line with the text after each mask whose name has not clearly ended (`_ENDED`)
    masked to the next tab or the line's end."""
    out: List[str] = []
    pos = 0
    while True:
        i = line.find(_GOES_ON, pos)
        if i < 0:
            out.append(line[pos:])
            return "".join(out)
        out.append(line[pos:i])
        pos = i + 1 if _ENDED.match(line, i + 1) else _line_end(line, i + 1)


def _line_end(line: str, start: int) -> int:
    """Where the text from `start` ends: the next tab or the line's end."""
    tab = line.find("\t", start)
    return len(line) if tab < 0 else tab


def _key(path: str) -> str:
    """A path as the known-folder set holds it: case folded where the volume ignores case."""
    return path.casefold() if paths.FOLD_CASE else path
_REST_OF_PATH = re.compile(rf"(?:/{paths._PATH_CHAR}*)*")
_AFTER_MARK = re.compile("\x00" + rf"(?:/(?:<[A-Z][A-Z0-9_]*>|{paths._PATH_CHAR})*)*")
normalize = inventory.unfolded  # the form masking sees (escapes removed, NFKC)

# the escapes ordinary tools write a name with: a run of bytes (git's `\303\274`, Python's
# `\xc3\xbc`, a URL's `%C3%BC`), read as UTF-8 (else one character each: Python's `'\xfc'`),
# and JSON's or Python's `\u00fc` / `\U0001F600` (a surrogate pair joined)
_BYTES = re.compile(r"(?:\\[0-3][0-7]{2}|\\x[0-9A-Fa-f]{2}|%[0-9A-Fa-f]{2})+")
_UNI = re.compile(r"\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}")


def _bytes_of(run: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(run):
        if run[i] == "%":
            out.append(int(run[i + 1:i + 3], 16))
            i += 3
        elif run[i + 1] == "x":
            out.append(int(run[i + 2:i + 4], 16))
            i += 4
        else:
            out.append(int(run[i + 1:i + 4], 8))
            i += 4
    return bytes(out)


def _decode_run(m: "re.Match[str]") -> str:
    raw = _bytes_of(m.group(0))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def unescape(text: str) -> str:
    """`text` with the escapes above decoded, for a second look only (never printed)."""
    text = _BYTES.sub(_decode_run, text)
    text = _UNI.sub(lambda m: chr(int(m.group(0)[2:], 16)) if int(m.group(0)[2:], 16) <= 0x10FFFF
                    else m.group(0), text)
    # a surrogate pair from JSON (`\ud83d\ude00`) is one character
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


def filter_stream(san: Sanitizer, fin: BinaryIO, fout: TextIO, table: bool = False) -> Tuple[int, int]:
    """Mask every line of `fin` onto `fout`. Returns (lines, changed)."""
    lines = changed = 0
    for raw in fin:
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        parts = text.split("\n")
        if text.endswith("\n"):
            parts.pop()
        for part in parts:
            out = san.clean(part, table=table)
            lines += 1
            changed += out != part
            fout.write(out + "\n")
        fout.flush()
    return lines, changed


def check_files(san: Sanitizer, files: Sequence[str], table: bool, fout: TextIO) -> bool:
    """Count the lines of each file that the sanitizer changes. False if a file cannot be read."""
    ok = True
    for k, p in enumerate(files, 1):
        n = ch = 0
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\r\n")
                    n += 1
                    ch += san.clean(line, table=table) != line
        except OSError:
            fout.write(f"check file {k}: cannot be read\n")
            ok = False
            continue
        fout.write(f"check file {k}: lines={fmt_n(n)} changed={fmt_n(ch)}\n")
    return ok


# ---- the self-test: made-up lines and the masked lines they must become ------------------------

SELFTEST_ROOT = "/tmp/phiward-selftest/protected"
MADE_UP_RUNS = [  # index TAB path, all made up
    "1\t/tmp/ZedStudy9/analysis/ZedRun_77/STAR/P-9990001-T01-IM6.Aligned.sortedByCoord.out.bam",
    "2\t/tmp/Quux_Case_B/STAR/QQSAMP-ALPHA-12.Aligned.sortedByCoord.out.bam",
]
PROTECTED_CASES = [  # with SELFTEST_ROOT protected; any pack
    (f"see {SELFTEST_ROOT}/a/FAKE-PT-0001.txt", "see <PROTECTED>"),
    (f"see {SELFTEST_ROOT}/a/New Person 7", "see <PROTECTED>"),
    (f"at {SELFTEST_ROOT}, then", "at <PROTECTED>, then"),
    ("elsewhere /tmp/phiward-selftest/other/x stays", "elsewhere /tmp/phiward-selftest/other/x stays"),
]
GENOMICS_CASES = [  # pack "genomics" alone, no names: (made-up input, masked output in text mode)
    ("file Sample7.sorted.bam and Sample7.sorted.bam.bai", "file <BAMFILE> and <BAMFILE>"),
    ("path /tmp/x/ZedRun_77/y.Aligned.bam ok", "path <BAMFILE> ok"),
    ("neutral slice.bam and b01.bam and rows.vcf stay", "neutral slice.bam and b01.bam and rows.vcf stay"),
    ("reads fq lane_1.fastq.gz here", "reads fq <BAMFILE> here"),
    ("calls CALLS.VCF.GZ and idx x.csi", "calls <BAMFILE> and idx <BAMFILE>"),
    ("read A00123:45:HABCDEFXX:1:1101:12345:6789 and the mate", "read <READ> and the mate"),
    ("read A00123:45:HABCDEFXX:1:1101:12345:6789/1 x", "read <READ> x"),
    ("umi A00123:45:HABCDEFXX:2:2201:100:200_ACGTACGT.", "umi <READ>."),
    ("old HWUSI-EAS100R:6:73:941:1973#0/1 x", "old <READ> x"),
    ("pacbio m54012_190101_000000/12345/ccs z", "pacbio <READ> z"),
    ("pos chr1:1234567 and 12:5678901 and chrX:123", "pos <LOCUS> and <LOCUS> and <LOCUS>"),
    ("range 7:100-200 and chr2:1,234,567-1,300,000", "range <LOCUS> and <LOCUS>"),
    ("1\t1234567\t.\tA\tC", "<LOCUS>\t.\tA\tC"),
    ("row x\t12\t7654321\t.\tG", "row x\t<LOCUS>\t.\tG"),
    ("space chrX 12345 end", "space <LOCUS> end"),
    ("id 1_1234_A_C and chr7-55249071-C-T", "id <LOCUS> and <LOCUS>"),
    ("bare 1234567 and 98765. and (4567890)", "bare <NUM> and <NUM>. and (<NUM>)"),
    ("grouped 12,345,678 reads", "grouped <NUM> reads"),
    ("csv 1234567,7654321,12", "csv <NUM>,<NUM>,12"),
    ("tail position:48999 here", "tail position:<NUM> here"),
    # genomics alone does not know institution IDs; only the digit run goes
    ("sample P-9990001-T01-IM6 failed", "sample P-<NUM>-T01-IM6 failed"),
    # lines that must pass unchanged
    ("task 12 q20 state=complete runs=18", "task 12 q20 state=complete runs=18"),
    ("rows=1234 ad=56 rdad=9876 total=12.3k", "rows=1234 ad=56 rdad=9876 total=12.3k"),
    ("mean=12345.678 and v6.7.0 and 0.0123 and 1e-05", "mean=12345.678 and v6.7.0 and 0.0123 and 1e-05"),
]
GENOMICS_TABLE_CASES = [  # pack "genomics" alone: identifiers masked, numbers kept
    ("q20\tpenalty\ton\tclean\t0-4\t12345\t6\t1234567", "q20\tpenalty\ton\tclean\t0-4\t12345\t6\t1234567"),
    ("x\tlane_1.fastq.gz\t77777", "x\t<BAMFILE>\t77777"),
    ("1\t1234567\tA00123:45:HABCDEFXX:1:1101:12345:6789", "1\t1234567\t<READ>"),
]
MSK_CASES = [  # packs "genomics" + "msk" with the names of MADE_UP_RUNS
    ("sample P-9990001-T01-IM6 failed", "sample <SAMPLEID> failed"),
    ("normal P-9990001-N01-IM6_extra and P-9990002", "normal <SAMPLEID> and <SAMPLEID>"),
    ("cmo C-ABC123-L001-d seen; also s_C_XYZ789_P001_d", "cmo <CMOID> seen; also <CMOID>"),
    ("stem AB123456-T opened", "stem <BAMID> opened"),
    ("donor DonorFake-7 and DONOR_X1", "donor <DONOR> and <DONOR>"),
    ("file Sample7.sorted.bam and neutral slice.bam", "file <BAMFILE> and neutral slice.bam"),
    ("pos chr1:1234567 and bare 7654321", "pos <LOCUS> and bare <NUM>"),
    ("sample tokens ZedRun_77 and zedstudy9 and QQSAMP-ALPHA-12 and Quux_Case_B",
     "sample tokens <NAME> and <NAME> and <NAME> and <NAME>"),
    ("pieces QQSAMP and alpha mask; the number 12 and out and bam stay",
     "pieces <NAME> and <NAME> mask; the number 12 and out and bam stay"),
    ("task 12 q20 state=complete runs=18", "task 12 q20 state=complete runs=18"),
    ("rows=1234 ad=56 rdad=9876 total=12.3k", "rows=1234 ad=56 rdad=9876 total=12.3k"),
]
MSK_TABLE_CASES = [  # packs "genomics" + "msk" with the names of MADE_UP_RUNS
    ("q20\tpenalty\tgtf\ton\tclean\t0-4\t12345\t6\t1234567", "q20\tpenalty\tgtf\ton\tclean\t0-4\t12345\t6\t1234567"),
    ("q20\tP-9990001-T01-IM6\t3\t1234567", "q20\t<SAMPLEID>\t3\t1234567"),
    ("12\t3456\tZedRun_77\t7", "12\t3456\t<NAME>\t7"),
]


def selftest(fout: Optional[TextIO] = None) -> bool:
    """Run the built-in made-up cases for the built-in packs. True if all pass."""
    out = fout or sys.stdout
    bad = total_text = total_table = 0
    groups = [
        (["genomics"], False, GENOMICS_CASES, GENOMICS_TABLE_CASES),
        (["genomics", "msk"], True, MSK_CASES, MSK_TABLE_CASES),
    ]
    ntokens = 0
    try:
        for packs, with_names, cases, table_cases in groups:
            cfg = config.Config(roots=[SELFTEST_ROOT], packs=packs)
            san = Sanitizer._build(cfg, (), MADE_UP_RUNS if with_names else ())
            ntokens = max(ntokens, len(san.tokens))
            for src, want in cases + PROTECTED_CASES:
                total_text += 1
                got = san.clean(src)
                if got != want or san.clean(got) != got:
                    bad += 1
                    out.write("SELFTEST FAIL: a made-up case gave another output\n")
            for src, want in table_cases:
                total_table += 1
                if san.clean(src, table=True) != want:
                    bad += 1
                    out.write("SELFTEST FAIL: a made-up table case gave another output\n")
    except SanitizerError:
        out.write("SELFTEST FAIL: the built-in packs could not be loaded\n")
        return False
    out.write(f"selftest: {total_text} text cases and {total_table} table cases, {bad} failed; "
              f"up to {ntokens} name tokens from {len(MADE_UP_RUNS)} made-up run lines\n")
    return bad == 0


# ---- the command -------------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> Optional[Dict[str, Any]]:
    opts: Dict[str, Any] = {"names": [], "files": [], "table": False, "mode": "filter"}
    it = iter(argv)
    for a in it:
        if a == "--names-from":
            value = next(it, "")
            if not value:
                return None
            opts["names"].append(value)
        elif a == "--table":
            opts["table"] = True
        elif a == "--selftest":
            opts["mode"] = "selftest"
        elif a in ("--check", "--check-table"):
            opts["mode"] = "check"
            opts["table"] = a == "--check-table"
        elif opts["mode"] == "check" and not a.startswith("-"):
            opts["files"].append(a)
        else:
            return None
    if opts["mode"] == "check" and not opts["files"]:
        return None
    if opts["mode"] == "selftest" and (opts["names"] or opts["table"]):
        return None
    return opts


def main(argv: List[str]) -> int:
    if any(a in ("-h", "--help") for a in argv):
        print(HELP, end="")
        return 0
    opts = _parse_args(argv)
    if opts is None:
        print(USAGE, end="", file=sys.stderr)
        return 2
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    if opts["mode"] == "selftest":
        return 0 if selftest() else 1
    try:
        cfg = config.load(os.getcwd())
        if cfg.problem:
            raise SanitizerError("the config has a problem")
        if opts["table"] and not cfg.sanitize_table:
            from phiward.run import TABLE_OFF
            print(TABLE_OFF, file=sys.stderr)
            return 2
        san = Sanitizer.from_config(cfg, [os.path.expanduser(n) for n in opts["names"]])
    except Exception:  # noqa: BLE001 - fail closed on anything
        print(PROBLEM_MESSAGE)
        return 3
    if opts["mode"] == "check":
        return 0 if check_files(san, opts["files"], opts["table"], sys.stdout) else 1
    mode = "table" if opts["table"] else "text"
    try:
        sys.stdout.write(f"sanitizer on: name tokens={fmt_n(len(san.tokens))} "
                         f"rules={fmt_n(len(san.path_rules) + len(san.id_rules) + len(san.pos_rules))} "
                         f"mode={mode}\n")
        sys.stdout.flush()
        lines, changed = filter_stream(san, sys.stdin.buffer, sys.stdout, table=opts["table"])
        sys.stdout.write(f"sanitizer done: lines={fmt_n(lines)} changed={fmt_n(changed)}\n")
        sys.stdout.flush()
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")  # no error message from the flush at exit
        except OSError:
            pass
        return 0
    except Exception:  # noqa: BLE001 - never leave a half-masked state; stop
        print("sanitizer: stopped on an error")
        return 1
    return 0
