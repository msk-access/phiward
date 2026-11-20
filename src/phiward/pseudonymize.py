"""`phiward pseudonymize`: the operator's own command that makes a pseudonymized copy of one
table (TSV, CSV, a tab-separated .txt or a MAF, each plain or gzip-compressed) for the agent.

The identifier columns the operator names get codes (`S0042`): a prefix fixed in the key, then 4
digits drawn with `secrets` from the codes not used yet, so neither an ID nor its place in the
file decides its code. The key (ID -> code) is kept in `~/.phiward/backups/keys/NAME.tsv`, below
a folder that every session, launch and gateway command has hidden from install on; it is only
ever appended to. The output is a new file inside a protected root of the user config: the agent
reads it through `phiward run`, masked, and every code passes the sanitizer in force unchanged.

Only the operator runs it, in a terminal: it refuses without one, and the hook refuses it as an
agent command. Its messages never name a cell, a key line, a header or a path, and on success
give the row count only (the agent may read the operator's terminal, and counts of new or known
IDs would confirm guessed IDs).
"""

import csv
import fnmatch
import gzip
import io
import os
import pwd
import random
import re
import secrets
import stat
import unicodedata
import sys
from typing import Dict, List, Optional, Sequence, TextIO, Tuple

from phiward import config, copying, inventory
from phiward.sanitize import BUILTIN_ID_COLUMNS, Sanitizer, SanitizerError, col_key, unescape

USAGE = ("usage: phiward pseudonymize (--new-key NAME [--prefix P] | --key NAME)\n"
         "                            --columns H[=NEW],... [--drop H,...] [--keep H,...]\n"
         "                            [--keep-order] IN OUT\n")
HELP = USAGE + """
Make a copy of one table (IN) in which the identifier columns you name hold codes (S0042) in
place of the IDs. The agent then reads the copy through `phiward run`.
Type the command yourself, in your own terminal: never run it on a file the agent made or asked
for, and never on a key name the agent chose.

Options:
  --new-key NAME   start a new key (refused when NAME exists)
  --key NAME       extend an existing key: known IDs keep their codes (refused when missing)
  --prefix P       with --new-key: 1 to 3 capital letters before the digits (default S)
  --columns H[=NEW],...
                   the identifier columns to code; each one's header becomes NEW (default
                   pseudonym, then pseudonym_2, ...; in a MAF the header stays)
  --drop H,...     columns to leave out
  --keep H,...     columns that look like identifiers, kept as they are on your word
  --keep-order     keep the order of the rows (by default they are shuffled, so the order of
                   a sorted file does not give away the order of the IDs)
  -h, --help       show this help

The key: ~/.phiward/backups/keys/NAME.tsv (ID, a tab, the code). No agent session, launch or
gateway command can read or write it. Keep a backup of it where no agent can reach it: a lost
key cannot be rebuilt, and new runs give new codes. A code is `PREFIX` and 4 digits, so a key
holds at most 9999 IDs. The same ID gets the same code in every table coded with one key.

The kinds (the extensions decide; the content must fit them):
- .tsv, .csv; .txt, read as a TSV, with 2 or more columns (free text is refused);
- .maf: a TSV after its # lines. Of those only an exact `#version 2.4` is kept; the others
  are dropped, and a # line after the header is refused. Name the barcode columns in
  --columns (Tumor_Sample_Barcode,Matched_Norm_Sample_Barcode, one key) and the columns that
  look like IDs but are not (Entrez_Gene_Id, Exon_Number) in --keep;
- each of them compressed with gzip (.tsv.gz): every member is read, no more than 1 GiB
  expanded; the copy is gzip again, with no name and no time, and must read back as the
  coded table. bgzip (BGZF) files, .vcf, .json and .md are not covered yet; Parquet is not:
  convert it to TSV with your own tools first.
Any failure to read or write the kind gives one fixed refusal.

The rules:
- IN is a regular file reached with no link, outside every place an agent can write: the
  working folder (and its git work tree), any project (a folder with .git, .claude or
  .phiward.toml above IN), the temp folders, the sandbox's
  allowWrite and additionalDirectories, a [broker] write_to folder, the spool and ~/.phiward.
  A file inside a protected root may still be the agent's (`phiward copy` puts files there):
  never run this on a file the agent made or asked for, wherever it is.
  Every row has the header's number of fields (UTF-8).
- Every column whose header looks like an identifier (the built-in list and [sanitize]
  id_columns) is named in --columns, --drop or --keep. A header the sanitizer would mask is
  refused. A cell's ID is the cell without outer spaces; an empty cell stays empty; a cell
  with an invisible format character is refused. No field of the output (a cell, a header,
  the kept # line, the codes too) may hold an ID of a coded column or of the key, also in
  another letter case, Unicode form or escaped (%2D, \u002D): one of 5 or more characters
  anywhere in a field; one of 5 or more digits as a whole run of digits; a shorter one with
  a letter as a whole word; a shorter one of digits only as the whole field. Drop such a
  column or clean it first. Run it from the folder of the
  project whose agent will read the copy (its sandbox settings name the places refused).
- OUT is a new file of the same kind as IN (the same extensions), inside a protected root of your user config and
  outside every write_to folder (never replaced, mode 0600).
- Messages never name a cell, a header, a path or a key line; a run reports the row count only.
"""

PREFIX = re.compile(r"[A-Z]{1,3}")
KEY_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
KEY_MAGIC = "#phiward-key"
DIGITS = 4
LIMIT = 1 << 30  # the largest table read, compressed or expanded (it is held in memory)
# the kinds, by the last extension before an optional `.gz`: (delimiter, name in messages)
KINDS = {".tsv": ("\t", "TSV"), ".csv": (",", "CSV"), ".txt": ("\t", "tab-separated text"),
         ".maf": ("\t", "MAF")}
LATER = (".vcf", ".json", ".md")  # kinds of a later version: refused for now
GZIP_MAGIC = b"\x1f\x8b"
MAF_VERSION = re.compile(r"#version \d{1,3}(?:\.\d{1,3})?")  # the one `#` line a MAF keeps


class Refused(Exception):
    """A fixed message, never a value from the table, the key or a path."""


class Removed(Refused):
    """A failure after the key was appended: the output was removed."""


def _account_home() -> str:
    """The home folder of the password entry: a `$HOME` the agent planted would move the key
    folder."""
    return pwd.getpwuid(os.getuid()).pw_dir


def _shuffle(rows: List[List[str]]) -> None:
    random.SystemRandom().shuffle(rows)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]
    os.fsync(fd)


def _write_out(fd: int, data: bytes) -> None:
    """Write the output (its own name, so a test can make it fail after the key append)."""
    _write_all(fd, data)


# --- arguments ----------------------------------------------------------------------------------

def _names(value: str) -> List[str]:
    out = [v for v in value.split(",")]
    if not value or any(not v.strip() for v in out):
        raise Refused("a list of column names has an empty name.")
    return out


def _parse(argv: Sequence[str]) -> Dict[str, object]:
    opts: Dict[str, object] = {"keep_order": False, "drop": [], "keep": [], "prefix": None}
    files: List[str] = []
    takes = {"--key", "--new-key", "--prefix", "--columns", "--drop", "--keep"}
    i = 0
    while i < len(argv):
        a = argv[i]
        name, eq, val = a.partition("=")
        if a == "--keep-order":
            opts["keep_order"] = True
        elif name in takes:
            if not eq:
                i += 1
                if i >= len(argv):
                    raise Refused(f"{name} needs a value.")
                val = argv[i]
            key = name[2:].replace("-", "_")
            if key in opts and opts[key] not in (None, []) or \
                    key in ("key", "new_key") and ("key" in opts or "new_key" in opts):
                raise Refused(f"{name} is given twice, or with another key option.")
            if key in ("columns", "drop", "keep"):
                opts[key] = _names(val)
            else:
                opts[key] = val
        elif a == "--" and not files:
            files += list(argv[i + 1:])
            break
        elif a.startswith("-") and a != "-":
            raise Refused("an option is not known (see --help).")
        else:
            files.append(a)
        i += 1
    if "key" not in opts and "new_key" not in opts:
        raise Refused("give --new-key NAME or --key NAME.")
    if "columns" not in opts:
        raise Refused("give the identifier columns with --columns.")
    if len(files) != 2:
        raise Refused("give one input table and one output file.")
    name = str(opts.get("key", opts.get("new_key")))
    if not KEY_NAME.fullmatch(name):
        raise Refused("a key name is 1 to 64 letters, digits, `_` or `-` (never a path).")
    if opts["prefix"] is not None and "new_key" not in opts:
        raise Refused("--prefix goes with --new-key only (a key keeps its prefix).")
    prefix = "S" if opts["prefix"] is None else str(opts["prefix"])
    if not PREFIX.fullmatch(prefix):
        raise Refused("a prefix is 1 to 3 capital letters.")
    opts.update(name=name, new="new_key" in opts, prefix=prefix, inp=files[0], out=files[1])
    return opts


# --- places -------------------------------------------------------------------------------------

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_part(parent: int, name: str, what: str, mode: Optional[int]) -> int:
    """`name` in the folder `parent`, opened without following a link, as a real folder of
    ours (with `mode` when given). FileNotFoundError when it is missing."""
    try:
        fd = os.open(name, _DIR, dir_fd=parent)
    except FileNotFoundError:
        raise
    except OSError:
        raise Refused(f"{what} is not a real folder of yours (a link, a file, or another "
                      "account's).")
    try:
        _check_dir(fd, what, mode)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _check_dir(fd: int, what: str, mode: Optional[int] = 0o700) -> None:
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise Refused(f"{what} is not a real folder of yours (a link, a file, or another "
                      "account's).")
    if mode is not None and stat.S_IMODE(st.st_mode) != mode:
        raise Refused(f"{what} is not private (mode 0700).")


def _open_state(home: str) -> Tuple[int, int]:
    """(the backups folder, the keys folder or -1 when it is missing), each opened from the
    home folder one part at a time, never through a link."""
    try:
        hfd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        raise Refused("the home folder cannot be opened.")
    pfd = bfd = -1
    try:
        try:
            pfd = _open_part(hfd, ".phiward", "~/.phiward", None)
            bfd = _open_part(pfd, "backups", "~/.phiward/backups", 0o700)
        except FileNotFoundError:
            raise Refused("~/.phiward/backups is missing: run `phiward install claude` first "
                          "(it makes it).")
        try:
            kfd = _open_part(bfd, "keys", "~/.phiward/backups/keys", 0o700)
        except FileNotFoundError:
            kfd = -1
        return bfd, kfd
    except BaseException:
        if bfd >= 0:
            os.close(bfd)
        raise
    finally:
        os.close(hfd)
        if pfd >= 0:
            os.close(pfd)


def _home() -> str:
    home = _account_home()
    named = os.environ.get("HOME")
    if named and os.path.realpath(named) != os.path.realpath(home):
        raise Refused("$HOME names another folder than your account's home folder.")
    return home


def _git_top(start: str) -> Optional[str]:
    d = start
    while True:
        if os.path.lexists(os.path.join(d, ".git")):
            return d
        up = os.path.dirname(d)
        if up == d:
            return None
        d = up


def _project_top(start: str, home: str) -> Optional[str]:
    """The nearest folder at or above `start` that marks a project an agent may work in (its
    `.claude` settings can let the agent write anywhere in it). The home folder is never one:
    `~/.claude` is the user's own Claude Code folder, and the walk stops below it."""
    d = start
    homes = {os.path.normpath(home), os.path.realpath(home)}
    while True:
        if d in homes:
            return None
        if any(os.path.lexists(os.path.join(d, n)) for n in (".git", ".claude", ".phiward.toml")):
            return d
        up = os.path.dirname(d)
        if up == d:
            return None
        d = up


def _kind(path: str) -> Tuple[str, bool]:
    """(the kind, compressed): the extension chain of the name decides the parser. One `.gz`
    may follow the kind; anything else is refused."""
    stem, last = os.path.splitext(os.path.basename(path).lower())
    gz = last == ".gz"
    if gz:
        stem, last = os.path.splitext(stem)
    if last == ".parquet":
        raise Refused("Parquet is not covered: convert it to TSV with your own tools first.")
    if last in LATER:
        raise Refused("VCF, JSON and Markdown files are not covered yet.")
    if last not in KINDS or not stem:
        raise Refused("the input must be a .tsv, .csv, .txt or .maf file, or one of them "
                      "compressed with gzip (.tsv.gz).")
    return last, gz


def _label(kind: str, gz: bool) -> str:
    return ("gzip-compressed " if gz else "") + KINDS[kind][1]


def _input_place(path: str, cfg: config.Config, home: str) -> str:
    full = os.path.normpath(os.path.join(os.getcwd(), path))
    _kind(full)
    # no link anywhere on the way: each part as it is on disk
    d = "/"
    for part in full.split("/")[1:]:
        d = os.path.join(d, part)
        try:
            if stat.S_ISLNK(os.lstat(d).st_mode):
                raise Refused("the input is reached through a link; name its real path.")
        except FileNotFoundError:
            raise Refused("the input does not exist.")
        except OSError as exc:
            if isinstance(exc, Refused):
                raise
            raise Refused("the input cannot be checked.")
    # places an agent can write: a file there may be planted (a guess list confirmed by codes)
    from phiward import claude_settings
    cwd = os.path.realpath(os.getcwd())
    project = _git_top(cwd) or cwd  # the working folder's tree, a git repository or not
    places = list(cfg.write_to) + [config.spool_dir(), os.path.join(home, ".phiward")]
    places += claude_settings._temp_roots() + claude_settings.agent_writable_anywhere(home)
    places += claude_settings.agent_writable(project, home)
    if any(config._deny_inside(full, os.path.realpath(p)) or config._deny_inside(full, p)
           for p in places if p):
        raise Refused("the input is in a place an agent can write (the working folder, a "
                      "temp folder, the sandbox's write folders, a write_to folder, the spool "
                      "or ~/.phiward): copy it to a folder of your own first.")
    top = _project_top(os.path.dirname(full), home)
    if top and config._deny_inside(full, top):
        raise Refused("the input is in a project (a folder with .git, .claude or "
                      ".phiward.toml above it), where an agent can write: copy it to a "
                      "folder of your own first.")
    return full


def _read_input(full: str) -> bytes:
    try:
        fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise Refused("the input cannot be opened as a plain file.")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused("the input is not a regular file.")
        if st.st_size > LIMIT:
            raise Refused("the input is too large.")
        chunks, size = [], 0
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            size += len(b)
            if size > LIMIT:
                raise Refused("the input is too large.")
            chunks.append(b)
    finally:
        os.close(fd)
    return b"".join(chunks)


# --- the key ------------------------------------------------------------------------------------

class Key:
    def __init__(self, prefix: str, codes: Dict[str, str], ident: Optional[Tuple[int, int, int]]):
        self.prefix = prefix
        self.codes = codes  # ID -> code
        self.ident = ident  # (dev, inode, size) when read


def _read_key(kfd: int, file: str) -> Key:
    try:
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=kfd)
    except FileNotFoundError:
        raise Refused("the key does not exist (start one with --new-key).")
    except OSError:
        raise Refused("the key cannot be opened as a plain file.")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or \
                stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1:
            raise Refused("the key is not a plain file of yours with mode 0600 and one name.")
        chunks = []
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            chunks.append(b)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("the key is damaged (not UTF-8).")
    if not text.endswith("\n"):
        raise Refused("the key is damaged (its last line does not end).")
    lines = text[:-1].split("\n")
    head = lines[0].split("\t")
    if len(head) != 3 or head[0] != KEY_MAGIC or head[1] != "1" or not PREFIX.fullmatch(head[2]):
        raise Refused("the key is damaged (its first line).")
    prefix = head[2]
    code_rx = re.compile(re.escape(prefix) + r"\d{%d}" % DIGITS)
    codes: Dict[str, str] = {}
    seen = set()
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) != 2 or not parts[0] or parts[0] != parts[0].strip() or \
                "\r" in line or not code_rx.fullmatch(parts[1]):
            raise Refused("the key is damaged (a line is not an ID and a code).")
        if parts[0] in codes or parts[1] in seen:
            raise Refused("the key is damaged (an ID or a code twice).")
        codes[parts[0]] = parts[1]
        seen.add(parts[1])
    return Key(prefix, codes, (st.st_dev, st.st_ino, st.st_size))


# --- the table ----------------------------------------------------------------------------------

def _decompress(data: bytes) -> bytes:
    """The text of a plain gzip file (every member, each checked; zero padding after the last
    is allowed), read in chunks: no more than LIMIT bytes are expanded. No header field of the
    input (name, comment, extra, time) is kept."""
    if data[:2] != GZIP_MAGIC:
        raise Refused("the input is named .gz but is not gzip data.")
    if len(data) > 3 and data[3] & 4:
        raise Refused("the input has gzip extra fields (bgzip, BGZF): not covered yet; "
                      "decompress it first.")
    chunks, size = [], 0
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            size += len(b)
            if size > LIMIT:
                raise Refused("the input is too large.")
            chunks.append(b)
    return b"".join(chunks)


def _decode(data: bytes) -> str:
    """The text of the input; the content must fit the kind its name gives."""
    if not data:
        raise Refused("the input is empty.")
    if data[:2] == GZIP_MAGIC:
        raise Refused("the input holds gzip data where text belongs (a compressed file with a "
                      "plain name, or gzip inside gzip).")
    if b"\0" in data:
        raise Refused("the input holds a NUL byte.")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise Refused("the input is not UTF-8.")
    if text.startswith("##fileformat=VCF"):
        raise Refused("the input is a VCF file: VCF is not covered yet.")
    return text


def _read_table(text: str, kind: str) -> Tuple[List[str], List[List[str]]]:
    """(the `#` lines kept, the rows, header first). A MAF's `#` lines before the header are
    dropped, but for an exact `#version N.N`; a `#` line after its header is refused."""
    kept: List[str] = []
    if kind == ".maf":
        pos = 0
        while text.startswith("#", pos):
            end = text.find("\n", pos)
            end = len(text) if end < 0 else end
            line = text[pos:end]
            pos = end + 1
            if MAF_VERSION.fullmatch(line.rstrip("\r")) and not kept:
                kept.append(line.rstrip("\r"))
        text = text[pos:]
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=KINDS[kind][0],
                               strict=True))
    except csv.Error:
        raise Refused("the input cannot be read as a table (its quoting).")
    if not rows or not rows[0]:
        raise Refused("the input has no header line.")
    width = len(rows[0])
    for r in rows[1:]:
        if len(r) != width:
            raise Refused("a row has another number of fields than the header.")
    if kind == ".txt" and width < 2:
        raise Refused("a .txt file is read as a table with tabs: one with fewer than 2 columns "
                      "is free text, which is not covered.")
    if kind == ".maf" and any(r[0].startswith("#") for r in rows[1:]):
        raise Refused("a line after the header of the MAF starts with #.")
    return kept, rows


def _write_table(kept: List[str], table: List[List[str]], kind: str) -> str:
    buf = io.StringIO()
    for line in kept:
        buf.write(line + "\n")
    csv.writer(buf, delimiter=KINDS[kind][0], lineterminator="\n").writerows(table)
    return buf.getvalue()


def _encode(text: str, gz: bool) -> bytes:
    """The bytes of OUT: the text, or its gzip form with no name and time 0, which must read
    back as the text (what is written is what was scanned)."""
    data = text.encode("utf-8")
    if not gz:
        return data
    out = gzip.compress(data, mtime=0)
    if gzip.decompress(out) != data:
        raise Refused("the compressed copy does not read back as the table.")
    return out


def _find(header_keys: List[str], name: str) -> int:
    hits = [i for i, k in enumerate(header_keys) if k == col_key(name)]
    if len(hits) != 1:
        raise Refused("a column named in --columns, --drop or --keep is not found exactly once "
                      "in the header.")
    return hits[0]


def _clean_both(san: Sanitizer, text: str) -> bool:
    return san.clean(text) == text and san.clean(text, table=True) == text


def _norm(text: str) -> str:
    """As masking sees text (NFKC, format characters removed), in any letter case."""
    return inventory.normalize(text).casefold()


def _long(norm_id: str) -> bool:
    """An ID of 5 or more characters, not digits only: matched anywhere in a cell."""
    return len(norm_id) >= 5 and not norm_id.isdigit()


class _Matcher:
    """Whether a field holds an ID of the run or of the key, in the form masking sees (NFKC,
    format characters removed, any letter case) and with `\\u`, `\\x` and `%XX` escapes decoded:
    a long ID (`_long`) anywhere in the field; an ID of 5 or more digits as a whole run of
    digits (`see 9990002`, `x/9990002.bam`; not inside `19990001`, a position); a shorter ID
    with a letter as a whole word (`see ab12`); a shorter ID of digits only as the whole field
    (`12` is not in `0.12`)."""

    def __init__(self, ids: "set[str]"):
        norm_ids = {_norm(v) for v in ids} - {""}
        long_ids = sorted((v for v in norm_ids if _long(v)), key=len, reverse=True)
        self.numbers = {v for v in norm_ids if v.isdigit() and len(v) >= 5}
        self.whole = {v for v in norm_ids if v.isdigit() and len(v) < 5}
        words = sorted((v for v in norm_ids if len(v) < 5 and not v.isdigit()), key=len,
                       reverse=True)
        self.rx = re.compile("|".join(re.escape(v) for v in long_ids)) if long_ids else None
        self.wx = re.compile(r"(?<![0-9a-z])(?:" + "|".join(re.escape(v) for v in words) +
                             r")(?![0-9a-z])") if words else None

    def hit(self, field: str) -> bool:
        forms = {_norm(field)}
        decoded = unescape(field)
        if decoded != field:
            forms.add(_norm(decoded))
        for norm in forms:
            if norm.strip() in self.whole or (self.rx is not None and self.rx.search(norm)) or \
                    (self.wx is not None and self.wx.search(norm)) or \
                    (self.numbers and any(d in self.numbers
                                          for d in re.findall(r"[0-9]+", norm))):
                return True
        return False


def _has_cf(text: str) -> bool:
    return any(unicodedata.category(ch) == "Cf" for ch in text)


def _scan(kept: List[str], table: List[List[str]], cols: List[int], coded: "set[int]",
          m: _Matcher) -> None:
    """The scan of the whole output as it was read back, codes included: no field may hold an
    invisible format character or an ID (`_Matcher`). A place is named by the input's column
    number, never by a value."""
    for line in kept:
        if _has_cf(line) or m.hit(line):
            raise Refused("the kept # line holds an ID of a coded column or of the key.")
    for j, i in enumerate(cols):
        h = table[0][j]
        if _has_cf(h) or m.hit(h):
            raise Refused(f"the header of column {i + 1} in the output holds an ID or an "
                          "invisible format character.")
        for r in table[1:]:
            cell = r[j]
            if _has_cf(cell):
                raise Refused(f"a cell of column {i + 1} holds an invisible format character.")
            if m.hit(cell):
                if i in coded:
                    raise Refused(f"a code in column {i + 1} matches an ID of this table or of "
                                  "the key.")
                raise Refused(f"column {i + 1} holds an ID of a coded column or of the key: "
                              "drop it, or clean it first.")


def build(opts: Dict[str, object], cfg: config.Config, san: Sanitizer, rows: List[List[str]],
          key: Key, keep_headers: bool = False
          ) -> Tuple[List[List[str]], List[Tuple[str, str]], List[int], "set[int]", _Matcher]:
    """(the output rows, header first; the new key lines; the input column of each output
    column; the coded columns; the matcher of the run's and the key's IDs). Refuses on any
    rule. With `keep_headers` (MAF) a coded column keeps its header unless one is given."""
    header = rows[0]
    keys = [col_key(h) for h in header]
    if len(set(keys)) != len(keys):
        raise Refused("the header names a column twice.")
    for n, h in enumerate(header, 1):
        if not h.strip() or not _clean_both(san, h):
            raise Refused(f"the header of column {n} is empty or holds what the sanitizer masks "
                          "(tables with IDs as headers are not covered).")
    coded: Dict[int, Optional[str]] = {}  # None: the default header
    for spec in opts["columns"]:  # type: ignore[union-attr]
        name, eq, new = str(spec).partition("=")
        i = _find(keys, name)
        if i in coded:
            raise Refused(f"column {i + 1} is named twice.")
        coded[i] = new if eq else None
    drop = {_find(keys, str(h)) for h in opts["drop"]}  # type: ignore[union-attr]
    keep = {_find(keys, str(h)) for h in opts["keep"]}  # type: ignore[union-attr]
    if (drop & keep) or (drop & set(coded)) or (keep & set(coded)):
        raise Refused("a column is named in more than one of --columns, --drop and --keep.")
    globs = list(BUILTIN_ID_COLUMNS) + [col_key(g) for g in cfg.sanitize_id_columns]

    def is_id(k: str) -> bool:
        return any(fnmatch.fnmatchcase(k, g) for g in globs)

    for i, k in enumerate(keys):
        if is_id(k) and i not in coded and i not in drop and i not in keep:
            raise Refused(f"column {i + 1} looks like an identifier: name it in --columns, "
                          "--drop or --keep.")
    # the new headers
    auto = 0
    for i in sorted(coded):
        if coded[i] is None and keep_headers:
            coded[i] = header[i]  # checked above as every header is
            continue
        if coded[i] is None:
            auto += 1
            coded[i] = "pseudonym" if auto == 1 else f"pseudonym_{auto}"
        new = str(coded[i])
        if not new.strip() or "\t" in new or "," in new or "\n" in new or \
                is_id(col_key(new)) or not _clean_both(san, new):
            raise Refused(f"the new header of column {i + 1} is empty, looks like an identifier "
                          "or holds what the sanitizer masks.")
    cols = [i for i in range(len(header)) if i not in drop]
    out_header = [str(coded[i]) if i in coded else header[i] for i in cols]
    out_keys = [col_key(h) for h in out_header]
    if len(set(out_keys)) != len(out_keys):
        raise Refused("two columns of the output would have the same header.")
    # the IDs, in order of first appearance
    ids: List[str] = []
    seen = set()
    for r in rows[1:]:
        for i in coded:
            v = r[i].strip()
            if not v:
                continue
            if "\t" in v or "\n" in v or "\r" in v or \
                    any(unicodedata.category(ch) == "Cf" for ch in v):
                raise Refused(f"a cell of column {i + 1} holds a tab, a line break or an "
                              "invisible format character.")
            if v not in seen:
                seen.add(v)
                ids.append(v)
    new_ids = [v for v in ids if v not in key.codes]
    # an ID of the key or of a coded column left anywhere in the output would link its code to
    # it: the scan of the output (`_scan`) refuses it
    m = _Matcher(set(ids) | set(key.codes))
    # the draw: from every code not used yet, skipping one the sanitizer would touch, one the
    # scan would flag, or one that is a value of the input or the key
    used = {c.casefold() for c in key.codes.values()} | {v.casefold() for v in key.codes}
    used |= {c.strip().casefold() for r in rows for c in r}
    free = [n for n in range(1, 10 ** DIGITS)
            if f"{key.prefix}{n:0{DIGITS}d}".casefold() not in used]
    added: List[Tuple[str, str]] = []
    codes = dict(key.codes)
    for v in new_ids:
        while True:
            if not free:
                raise Refused(f"the key has no code left (at most {10 ** DIGITS - 1} IDs).")
            j = secrets.randbelow(len(free))
            free[j], free[-1] = free[-1], free[j]
            code = f"{key.prefix}{free.pop():0{DIGITS}d}"
            if _clean_both(san, code) and not m.hit(code):
                break
        codes[v] = code
        added.append((v, code))
    body = []
    for r in rows[1:]:
        body.append([codes[r[i].strip()] if i in coded and r[i].strip() else
                     ("" if i in coded else r[i]) for i in cols])
    if not opts["keep_order"]:
        _shuffle(body)
    return [out_header] + body, added, cols, set(coded), m


# --- the run ------------------------------------------------------------------------------------

def _out_place(path: str, kind: Tuple[str, bool], cfg: config.Config) -> Tuple[str, str]:
    """(the real folder of OUT, its file name)."""
    full = os.path.normpath(os.path.join(os.getcwd(), path))
    try:
        same = _kind(full) == kind
    except Refused:
        same = False
    if not same:
        raise Refused("the output must be a file of the same kind as the input, with the same "
                      "extensions (.tsv.gz for a .tsv.gz).")
    if os.path.lexists(full):
        raise Refused("the output exists; it is never replaced: name a new file.")
    real, why = copying.dest_place(full, os.getcwd(), cfg)
    if why:
        raise Refused(f"the output cannot go there: {why}.")
    if any(config._deny_inside(real, w) for w in cfg.write_to):
        raise Refused("the output cannot go in a write_to folder (gateway commands write "
                      "there).")
    parent = os.path.dirname(full)
    try:
        if not os.path.samefile(real, parent) or os.path.islink(parent):
            raise Refused("the folder of the output does not exist.")
    except OSError:
        raise Refused("the folder of the output does not exist.")
    return real, os.path.basename(full)


def _open_walk(folder: str) -> int:
    """The folder, opened from `/` one part at a time without following a link: the folder
    checked is the folder written, whatever is renamed on the way meanwhile."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in [p for p in folder.split("/") if p]:
            nxt = os.open(part, _DIR, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except OSError:
        os.close(fd)
        raise Refused("the folder of the output is reached through a link or cannot be opened.")
    return fd


def run(argv: Sequence[str]) -> int:
    opts = _parse(argv)
    home = _home()
    bfd, kfd = _open_state(home)
    try:
        return _run(opts, home, bfd, kfd)
    finally:
        os.close(bfd)
        if kfd >= 0:
            os.close(kfd)


def _run(opts: Dict[str, object], home: str, bfd: int, kfd: int) -> int:
    if kfd < 0 and not opts["new"]:
        raise Refused("the key does not exist (start one with --new-key).")
    cfg = config.load(os.getcwd())
    if cfg.problem:
        raise Refused("the config cannot be used (see `phiward doctor`).")
    if not cfg.user_roots:
        raise Refused("the user config has no protected root to put the output in.")
    full_in = _input_place(str(opts["inp"]), cfg, home)
    kind, gz = _kind(full_in)
    out_dir, out_name = _out_place(str(opts["out"]), (kind, gz), cfg)
    file = f"{opts['name']}.tsv"
    if opts["new"]:
        if kfd >= 0:
            try:
                os.stat(file, dir_fd=kfd, follow_symlinks=False)
                raise Refused("a key of that name exists; extend it with --key.")
            except FileNotFoundError:
                pass
        key = Key(str(opts["prefix"]), {}, None)
    else:
        key = _read_key(kfd, file)
    raw = _read_input(full_in)
    try:
        san = Sanitizer.from_config(cfg, entries=True)
    except SanitizerError:
        raise Refused("the sanitizer cannot be built from the config.")
    try:
        table, added, data = _code(opts, cfg, san, raw, kind, gz, key)
    except Refused:
        raise
    except Exception:
        # any failure of a reader, a writer or the check-back (deep nesting, a damaged gzip
        # member, a decode error, memory): one fixed text, never the exception's own
        raise Refused(f"the input cannot be read as a {_label(kind, gz)} file.")
    return _commit(opts, key, bfd, kfd, file, added, out_dir, out_name, data,
                   len(table) - 1)


def _code(opts: Dict[str, object], cfg: config.Config, san: Sanitizer, raw: bytes, kind: str,
          gz: bool, key: Key) -> Tuple[List[List[str]], List[Tuple[str, str]], bytes]:
    """(the output rows, the new key lines, the bytes of OUT): read, code, write, then read the
    written text back and scan it whole."""
    kept, rows = _read_table(_decode(_decompress(raw) if gz else raw), kind)
    for line in kept:
        if not _clean_both(san, line):
            raise Refused("the #version line holds what the sanitizer masks.")
    table, added, cols, coded, m = build(opts, cfg, san, rows, key, keep_headers=kind == ".maf")
    text = _write_table(kept, table, kind)
    back = _read_table(text, kind)
    if back != (kept, table):
        raise Refused("the copy does not read back as the coded table.")
    _scan(back[0], back[1], cols, coded, m)
    return table, added, _encode(text, gz)


def _commit(opts: Dict[str, object], key: Key, bfd: int, kfd: int, file: str,
            added: List[Tuple[str, str]], out_dir: str, out_name: str, data: bytes,
            count: int) -> int:
    """Create OUT, append the key, write OUT; OUT is removed on any failure after it exists."""
    dfd = _open_walk(out_dir)
    try:
        try:
            ofd = os.open(out_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                          dir_fd=dfd)
        except OSError:
            raise Refused("the output cannot be made (it exists, or the folder is not "
                          "writable).")
        try:
            try:
                _append_key(opts, key, bfd, kfd, file, added)
            except OSError:
                raise Refused("the key cannot be written.")
            os.fchmod(ofd, 0o600)
            try:
                _write_out(ofd, data)
            except OSError:
                raise Removed("the output cannot be written; it was removed. The key keeps "
                              "the codes it was given.")
        except BaseException:
            os.close(ofd)
            ofd = -1
            try:
                os.unlink(out_name, dir_fd=dfd)
            except OSError:
                pass
            raise
        finally:
            if ofd >= 0:
                os.close(ofd)
    finally:
        os.close(dfd)
    return count


def _append_key(opts: Dict[str, object], key: Key, bfd: int, kfd: int, file: str,
                added: List[Tuple[str, str]]) -> None:
    text = "".join(f"{v}\t{c}\n" for v, c in added)
    own = -1
    if kfd < 0:
        # made now, in the backups folder opened before (never by its path again)
        os.mkdir("keys", 0o700, dir_fd=bfd)
        own = os.open("keys", _DIR, dir_fd=bfd)
        kfd = own
    try:
        if own >= 0:
            os.fchmod(kfd, 0o700)  # the umask may have taken bits away
        _check_dir(kfd, "~/.phiward/backups/keys")
        if opts["new"]:
            fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                         dir_fd=kfd)
            text = f"{KEY_MAGIC}\t1\t{key.prefix}\n" + text
        else:
            if not added:
                return
            fd = os.open(file, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=kfd)
        try:
            st = os.fstat(fd)
            if opts["new"]:
                os.fchmod(fd, 0o600)
            elif (st.st_dev, st.st_ino, st.st_size) != key.ident or st.st_nlink != 1:
                raise Refused("the key changed while it was read.")
            _write_all(fd, text.encode("utf-8"))
        finally:
            os.close(fd)
    finally:
        if own >= 0:
            os.close(own)


def main(argv: List[str], fin: Optional[TextIO] = None, fout: Optional[TextIO] = None,
         ferr: Optional[TextIO] = None) -> int:
    fin = sys.stdin if fin is None else fin
    fout = sys.stdout if fout is None else fout
    ferr = sys.stderr if ferr is None else ferr
    if argv[:1] in (["-h"], ["--help"]):
        fout.write(HELP)
        return 0
    try:
        tty = fin.isatty() and fout.isatty()
    except (AttributeError, ValueError):
        tty = False
    if not tty:
        ferr.write("phiward pseudonymize is the operator's: type it yourself in your own "
                   "terminal, not through an agent tool. Nothing was written.\n")
        return 2
    try:
        n = run(argv)
    except Refused as exc:
        done = "" if isinstance(exc, Removed) else " Nothing was written."
        ferr.write(f"phiward pseudonymize: {exc}{done}\n")
        return 2
    except OSError as exc:
        ferr.write(f"phiward pseudonymize: a file operation failed ({type(exc).__name__}). "
                   "Nothing was written.\n")
        return 1
    fout.write(f"phiward pseudonymize: wrote the coded table, {n} row(s). Read it with "
               "`phiward run`.\n")
    return 0
