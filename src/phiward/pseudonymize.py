"""`phiward pseudonymize`: the operator's own command that makes a pseudonymized copy of one
table (TSV, CSV, a tab-separated .txt, a MAF, a VCF, a JSON file or the pipe tables of a
Markdown file, each plain, gzip- or bgzip-compressed) for the agent.

The identifier columns the operator names get codes (`S0042`): a prefix fixed in the key, then 4
digits drawn with `secrets` from the codes not used yet, so neither an ID nor its place in the
file decides its code. The key (ID -> code) is kept in `~/.phiward/backups/keys/NAME.tsv`, below
a folder that every session, launch and gateway command has hidden from install on; it is only
ever appended to. The output is a new file inside a protected root of the user config: the agent
reads it through `phiward run`, masked, and every code passes the sanitizer in force unchanged.

Only the operator runs it, in a terminal: it refuses without one, and the hook refuses it as an
agent command. Its messages never name a cell, a key line, a header or a path, and on success
give the row count only (a JSON run gives none; the agent may read the operator's terminal, and
counts of new or known IDs would confirm guessed IDs).
"""

import csv
import decimal
import fnmatch
import gzip
import html
import io
import json
import math
import os
import pwd
import random
import re
import secrets
import stat
import struct
import unicodedata
import zlib
import sys
from typing import Dict, Iterator, List, Optional, Sequence, TextIO, Tuple

from phiward import config, copying, inventory, sanitize
from phiward.sanitize import BUILTIN_ID_COLUMNS, Sanitizer, SanitizerError, col_key

USAGE = ("usage: phiward pseudonymize (--new-key NAME [--prefix P] | --key NAME)\n"
         "                            --columns H[=NEW],... [--drop H,...] [--keep H,...]\n"
         "                            [--keep-order] IN OUT\n"
         "       phiward pseudonymize (--new-key NAME [--prefix P] | --key NAME)\n"
         "                            [--keep-samples N,...] [--keep-order] IN.vcf OUT.vcf\n"
         "       phiward pseudonymize (--new-key NAME [--prefix P] | --key NAME)\n"
         "                            --columns PATH,... [--drop PATH,...] [--keep PATH,...]\n"
         "                            [--keep-order] IN.json OUT.json\n")
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
                   pseudonym, then pseudonym_2, ...; in a MAF the header stays); in JSON,
                   key paths (below)
  --drop H,...     columns (in JSON, key paths) to leave out
  --keep H,...     columns (in JSON, key paths) that look like identifiers, kept as they are
                   on your word
  --keep-samples N,...
                   with a VCF: keep the names of these samples (1 is the first sample) as they
                   are, out of the key (TUMOR, NORMAL), on your word
  --keep-order     keep the order of the rows, of a VCF's sample columns or of the JSON
                   arrays of objects (by default they are shuffled, so the order of a sorted
                   file does not give away the order of the IDs); for the whole run, never
                   for one array alone
  -h, --help       show this help

The key: ~/.phiward/backups/keys/NAME.tsv (ID, a tab, the code). No agent session, launch or
gateway command can read or write it. Keep a backup of it where no agent can reach it: a lost
key cannot be rebuilt, and new runs give new codes. A code is `PREFIX` and 4 digits, so a key
holds at most 9999 IDs. The same ID gets the same code in every table coded with one key.

The kinds (the extensions decide; the content must fit them):
- .tsv, .csv; .txt, read as a TSV, with 2 or more columns (free text is refused);
- .maf: a TSV after its # lines. Only the first `#version` line with a number
  (`#version 2.4`) is kept; the others are dropped, and a # line after the header is
  refused. Name the barcode columns in --columns (Tumor_Sample_Barcode,
  Matched_Norm_Sample_Barcode, one key) and the columns that look like IDs but are not
  (Entrez_Gene_Id, Exon_Number) in --keep;
- .vcf: its first line is ##fileformat=VCFv4.N. The IDs are the sample names after FORMAT,
  all coded (no --columns, --drop or --keep). Of the ## lines only fileformat, INFO, FORMAT,
  FILTER and ALT are kept, and contig with its ID only; the others (reference, source,
  command lines, SAMPLE, PEDIGREE) are dropped. A sample name that is a word (tumor,
  normal, sample, sample1, control, germline, blood, unknown, na, none, in any case), has no
  digit or is under 3 characters is refused: rename it first (bcftools reheader), or keep
  it by number with --keep-samples, on your word (the only check: the sanitizer must leave
  the name unchanged; a name it would mask is refused). The records keep their order (tabix
  needs it) and their values; the sample columns are shuffled instead. A record that holds a
  sample's ID is refused: clean it first (bcftools annotate). A short sample name of digits
  only (123) refuses every record that holds that number: rename it first;
- .json: the IDs are the values at the key paths in --columns: keys joined by `.`, `[]` for
  every element of an array (--columns 'samples[].id,samples[].mrn'; `[].mrn` for a
  top-level array). A key is matched exactly; one with `.`, `[` or `]` cannot be named. A
  path that matches nothing, or meets a value of another kind (a key where there is no
  object), is refused. A coded value is a string or an integer (it becomes a string code);
  null stays null; any other value is refused. Every key that looks like an identifier and
  holds values (a string, a number, true, false or null, also in an array: samples[] for
  strings under samples, samples[].id) is named by that path in --columns, --drop or --keep;
  a key that holds only objects or arrays needs no name. --keep names such a path; --drop a
  key, a container whole. A key the sanitizer would mask is refused (keys that are IDs are
  not coded). The array at the last [] of a coded path (an array of objects, samples[] for
  samples[].id) is shuffled, unless --keep-order; it is refused when an array of the same
  length sits beside it in the same object (arrays side by side may be paired by position,
  and a shuffle would break the pairing): give --keep-order, or drop the other array. A path
  that ends in [] (ids[], the elements themselves) needs --keep-order: an array of IDs may be
  paired by position with arrays phiward cannot see. Other arrays and the order of keys are
  kept. Refused as unreadable: a key twice in one object, NaN, Infinity, a number out of
  range, an integer of more than 4300 digits, nesting deeper than 100, a lone surrogate
  (\\ud800). For the scan, a number that is whole is also read as its integer (1234.0,
  "9.990001e6"). The copy is written with an indent of 2 and read back. A key is named in
  messages by its number in the order of the file. The run reports no count;
- .md: only pipe tables (| a | b |, each line starting and ending with |, the alignment row
  | --- | second) and blank lines. Any other line (prose, a heading, a list, code, front
  matter, an HTML comment) is free text, refused. A line with a backslash or a backtick (an
  escaped pipe, a code span), with <, [ or ] (inline HTML, a link, an image), or a second
  alignment row (two tables need a blank line between them) is refused, and so is a header
  with emphasis or an entity (**id**, _mrn_, &#95;). Each table follows the table rules
  with the names of --columns, --drop and --keep that its header holds; each name is in
  some table, and one ID gets one code in all of them. The body rows of a table with a
  coded column are shuffled; the header and the alignment row are kept. For the scan, each
  cell is also read with its HTML entities (&#45;, &amp;#45;, &hyphen;) decoded and its
  emphasis marks (**, _, ~~) removed. Messages name a table by its number;
- each of them compressed with gzip (.tsv.gz): every member is read, no more than 1 GiB
  expanded; the copy is gzip again, with no name and no time, and must read back as the
  coded table. A bgzip (BGZF) input, every block of it and its EOF block, gives a BGZF
  copy; for a VCF, run `tabix -p vcf` on it to index it (an index is never read or copied).
  Parquet is not covered: convert it to TSV with your own tools first.
Any failure to read or write the kind gives one fixed refusal.

The rules:
- IN is a regular file reached with no link, outside every place an agent can write: the
  working folder (and its git work tree), any project (a folder with .git, .claude or
  .phiward.toml above IN), the temp folders, the sandbox's
  allowWrite and additionalDirectories, a [broker] write_to folder, the spool and ~/.phiward.
  A file inside a protected root may still be the agent's (`phiward copy` puts files there):
  never run this on a file the agent made or asked for, wherever it is.
  Every row has the header's number of fields (UTF-8).
  In JSON, a key is a header and a scalar a cell in the rules below.
- Every column whose header looks like an identifier (the built-in list and [sanitize]
  id_columns) is named in --columns, --drop or --keep. A header the sanitizer would mask is
  refused. A cell's ID is the cell without outer spaces; an empty cell stays empty; a cell
  with an invisible format character is refused. Two IDs that are the same once normalized
  as the scan below reads them (P-1, p-1, a full-width P, an en dash; FAKE%2DPT-0001,
  FAKE PT 0001 for FAKE-PT-0001; not FAKE-PT-00011), in IN or in IN and the key, are
  refused: make them one first. A key that already holds two such IDs cannot code either
  again: start a new key. No field of the output (a
  cell, a header, the kept # line, the codes too) may hold an ID of a coded column or of
  the key, also in another letter case, Unicode form, dash (U+2010, U+2013, U+2212, every
  Unicode dash) or digits, or escaped (%2D, \\u002D, also twice): one of 5 or more
  characters anywhere in a field, or across the fields of a line as written, and one with a
  letter also with every character but letters and digits removed (FAKE PT 0001,
  FAKE.PT.0001 for FAKE-PT-0001); one of 5 or more digits as a whole run of digits; a
  shorter one with a letter as a whole word; a shorter one of digits only as the whole
  field. Drop such a column or clean it first. Run it from the folder of the
  project whose agent will read the copy (its sandbox settings name the places refused).
- OUT is a new file of the same kind as IN (the same extensions), inside a protected root of
  your user config and outside every write_to folder (never replaced, mode 0600).
- Messages never name a cell, a header, a key path, a path or a key line; a run reports the
  row (or VCF record) count only, and a JSON run no count.
"""

PREFIX = re.compile(r"[A-Z]{1,3}")
KEY_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
KEY_MAGIC = "#phiward-key"
DIGITS = 4
LIMIT = 1 << 30  # the largest table read, compressed or expanded (it is held in memory)
# the kinds, by the last extension before an optional `.gz`: (delimiter, name in messages)
KINDS = {".tsv": ("\t", "TSV"), ".csv": (",", "CSV"), ".txt": ("\t", "tab-separated text"),
         ".maf": ("\t", "MAF"), ".vcf": ("\t", "VCF"), ".json": ("", "JSON"),
         ".md": ("|", "Markdown")}
GZIP_MAGIC = b"\x1f\x8b"
# BGZF (the SAM spec, 4.1): a gzip member with the extra subfield `BC` (BSIZE, the block size
# - 1); a block holds at most 64 KiB, so bgzip puts 0xff00 input bytes in each; the EOF block
BGZF_BLOCK = 0xff00
BGZF_EOF = bytes.fromhex("1f8b08040000000000ff0600424302001b0003000000000000000000")
VCF_FORMAT = re.compile(r"##fileformat=VCFv4\.\d{1,2}")
VCF_FIXED = ["#CHROM", "POS", "ID", "REF", "ALT", "QUAL", "FILTER", "INFO", "FORMAT"]
VCF_META_KEPT = ("INFO", "FORMAT", "FILTER", "ALT")  # kept whole; `contig` keeps its ID only
VCF_META = re.compile(r"##([A-Za-z0-9_.-]+)=(.*)")
# a contig ID (VCF 4.3, 1.4.7), and one `key=value` of a structured `##` line
CONTIG_ID = re.compile(r"[0-9A-Za-z!#$%&+./:;?@^_|~-][0-9A-Za-z!#$%&*+./:;=?@^_|~-]*")
VCF_SPLIT = re.compile(r"[;,=|:]")  # the parts of an INFO, FORMAT or sample value
META_ITEM = re.compile(r'([A-Za-z0-9_.-]+)=("(?:[^"\\]|\\.)*"|[^,"<>]*)')
# sample names that are words, not IDs: coded, they would link unrelated subjects in the key
SAMPLE_WORDS = {"tumor", "normal", "sample", "sample1", "control", "germline", "blood",
                "unknown", "na", "none"}
_ZEROS = re.compile(rb"\0*")
MAF_VERSION = re.compile(r"#version \d{1,3}(?:\.\d{1,3})?")  # the one `#` line a MAF keeps
JSON_DEPTH = 100  # objects and arrays nested deeper are refused
JSON_DIGITS = 4300  # an integer of more digits is refused (Python 3.11's own limit, on 3.9 too)
JSON_STEP = re.compile(r"([^.\[\]]*)((?:\[\])*)")  # one part of a key path: a key, then []s
JSON_NUMBER = re.compile(r"-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
SURROGATE = re.compile("[\ud800-\udfff]")  # a lone surrogate: no UTF-8 form
MD_ALIGN = re.compile(r":?-+:?")  # a cell of a pipe table's alignment row
MD_MARKS = re.compile(r"[*_~]")  # the marks of emphasis and strike-through
# every dash (Unicode category Pd) and the look-alikes outside it, as `-`: for the scan and the
# twin rule only
DASHES = {c: "-" for c in range(sys.maxunicode + 1)
          if unicodedata.category(chr(c)) == "Pd" or c in (0x2212, 0x2043, 0x02D7, 0x30FC)}
ROUNDS = 4  # rounds of normalizing and decoding escapes, at most
MD_MARKUP = re.compile(r"[*~]|(?<![0-9A-Za-z])_|_(?![0-9A-Za-z])")  # emphasis: not in a header


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


def _numbers(value: str) -> List[int]:
    out = value.split(",")
    if not all(re.fullmatch(r"[1-9][0-9]{0,5}", v) for v in out) or len(set(out)) != len(out):
        raise Refused("--keep-samples takes sample numbers (1 for the first sample), each "
                      "once, separated by commas.")
    return [int(v) for v in out]


def _is_vcf(path: str) -> bool:
    try:
        return _kind(path)[0] == ".vcf"
    except Refused:
        return False


def _parse(argv: Sequence[str]) -> Dict[str, object]:
    opts: Dict[str, object] = {"keep_order": False, "drop": [], "keep": [], "prefix": None,
                               "keep_samples": []}
    files: List[str] = []
    takes = {"--key", "--new-key", "--prefix", "--columns", "--drop", "--keep", "--keep-samples"}
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
            elif key == "keep_samples":
                opts[key] = _numbers(val)
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
    if len(files) != 2:
        raise Refused("give one input table and one output file.")
    vcf = _is_vcf(files[0])
    if vcf and ("columns" in opts or opts["drop"] or opts["keep"]):
        raise Refused("a VCF's IDs are its sample names: --columns, --drop and --keep do not "
                      "apply to it (see --keep-samples).")
    if not vcf and "columns" not in opts:
        raise Refused("give the identifier columns with --columns.")
    if opts["keep_samples"] and not vcf:
        raise Refused("--keep-samples goes with a VCF input only.")
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
                      "account's).") from None
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
        raise Refused("the home folder cannot be opened.") from None
    pfd = bfd = -1
    try:
        try:
            pfd = _open_part(hfd, ".phiward", "~/.phiward", None)
            bfd = _open_part(pfd, "backups", "~/.phiward/backups", 0o700)
        except FileNotFoundError:
            raise Refused("~/.phiward/backups is missing: run `phiward install claude` first "
                          "(it makes it).") from None
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
    if last not in KINDS or not stem:
        raise Refused("the input must be a .tsv, .csv, .txt, .maf, .vcf, .json or .md file, or "
                      "one of them compressed with gzip or bgzip (.tsv.gz, .vcf.gz).")
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
            raise Refused("the input does not exist.") from None
        except OSError:
            raise Refused("the input cannot be checked.") from None
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
        raise Refused("the input cannot be opened as a plain file.") from None
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
        raise Refused("the key does not exist (start one with --new-key).") from None
    except OSError:
        raise Refused("the key cannot be opened as a plain file.") from None
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
        raise Refused("the key is damaged (not UTF-8).") from None
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

def _member_start(data: bytes, pos: int) -> Tuple[int, Optional[int]]:
    """(where the deflate data of the gzip member at `pos` starts, its BSIZE when it is a BGZF
    block). Its header is checked: the magic, deflate, no reserved flag bit (RFC 1952). An extra
    field is taken only as bgzip writes it: FEXTRA alone, XLEN 6, the one subfield `BC` with
    SLEN 2 (the SAM spec, 4.1)."""
    if data[pos:pos + 2] != GZIP_MAGIC or len(data) < pos + 10 or data[pos + 2] != 8:
        raise ValueError("not a gzip member")
    flg = data[pos + 3]
    if flg & 0xE0:
        raise ValueError("reserved flag bits")
    if flg & 4:
        if flg != 4 or data[pos + 10:pos + 16] != b"\x06\x00BC\x02\x00" or len(data) < pos + 18:
            raise ValueError("an extra field that is not BGZF")
        return pos + 18, struct.unpack("<H", data[pos + 16:pos + 18])[0]
    p = pos + 10
    for bit in (8, 16):  # FNAME, FCOMMENT: skipped, never kept
        if flg & bit:
            p = data.index(b"\0", p) + 1
    if flg & 2:  # FHCRC
        p += 2
    if p > len(data):
        raise EOFError("a member header ends early")
    return p, None


def _decompress(data: bytes) -> Tuple[bytes, bool]:
    """(the text of a gzip file, whether it is BGZF): every member, each header checked
    (`_member_start`) and each CRC and length, and a BGZF block's BSIZE; every member is BGZF or
    none is, and a BGZF file ends with the EOF block. Zero padding after a member is allowed,
    other trailing bytes are not. Expanded in 1 MiB steps: no more than LIMIT bytes. No header
    field of the input (name, comment, time) is kept."""
    if data[:2] != GZIP_MAGIC:
        raise Refused("the input is named .gz but is not gzip data.")
    chunks: List[bytes] = []
    size = pos = 0
    step = 1 << 20
    kinds = set()
    while pos < len(data):
        start = pos
        pos, bsize = _member_start(data, pos)
        kinds.add(bsize is not None)
        if len(kinds) > 1:
            raise Refused("the input mixes bgzip (BGZF) blocks and plain gzip members.")
        d = zlib.decompressobj(-zlib.MAX_WBITS)
        crc = length = 0
        while not d.eof:
            if pos >= len(data):
                raise EOFError("a member ends early")
            end = min(pos + step, len(data))
            tail = data[pos:end]
            while tail and not d.eof:
                b = d.decompress(tail, step)
                tail = d.unconsumed_tail
                size += len(b)
                if size > LIMIT:
                    raise Refused("the input is too large.")
                crc = zlib.crc32(b, crc)
                length += len(b)
                chunks.append(b)
            pos = end - len(d.unused_data) if d.eof else end
        if len(data) < pos + 8:
            raise EOFError("a member ends early")
        if data[pos:pos + 8] != struct.pack("<II", crc, length & 0xFFFFFFFF):
            raise ValueError("a member's CRC or length")
        pos += 8
        if bsize is not None and pos - start != bsize + 1:
            raise ValueError("a BGZF block's BSIZE")
        pos = _ZEROS.match(data, pos).end()  # padding
    if kinds == {True} and not data.endswith(BGZF_EOF):
        # cut at a block boundary, a BGZF file reads as a shorter one: its EOF block says it ends
        raise ValueError("a BGZF file without its EOF block")
    return b"".join(chunks), kinds == {True}


def _bgzf(data: bytes) -> bytes:
    """BGZF (the SAM spec, 4.1): blocks of at most BGZF_BLOCK input bytes, each a gzip member
    with time 0, the subfield `BC` and its BSIZE, raw deflate, CRC32 and ISIZE; then the EOF
    block."""
    out = []
    for i in range(0, len(data), BGZF_BLOCK):
        raw = data[i:i + BGZF_BLOCK]
        c = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
        body = c.compress(raw) + c.flush()
        size = 18 + len(body) + 8
        if size > 1 << 16:
            raise ValueError("a BGZF block over 64 KiB")
        out.append(b"\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\xff\x06\x00BC\x02\x00" +
                   struct.pack("<H", size - 1) + body +
                   struct.pack("<II", zlib.crc32(raw), len(raw)))
    out.append(BGZF_EOF)
    return b"".join(out)


def _decode(data: bytes, kind: str) -> str:
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
        raise Refused("the input is not UTF-8.") from None
    if kind != ".vcf" and text.startswith("##fileformat=VCF"):
        raise Refused("the input is a VCF file: name it .vcf.")
    return text  # a VCF's first line is checked by its reader (`_read_vcf`)


def _read_table(text: str, kind: str) -> Tuple[List[str], List[List[str]]]:
    """(the `#` lines kept, the rows, header first). A MAF's `#` lines before the header are
    dropped, but for the first `#version` and a number (`#version 2.4`); a `#` line after its
    header is refused."""
    meta: List[str] = []
    if kind == ".maf":
        pos = 0
        while text.startswith("#", pos):
            end = text.find("\n", pos)
            end = len(text) if end < 0 else end
            line = text[pos:end]
            pos = end + 1
            if MAF_VERSION.fullmatch(line.rstrip("\r")) and not meta:
                meta.append(line.rstrip("\r"))
        text = text[pos:]
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=KINDS[kind][0],
                               strict=True))
    except csv.Error:
        raise Refused("the input cannot be read as a table (its quoting).") from None
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
    return meta, rows


def _write_table(meta: List[str], table: List[List[str]], kind: str) -> str:
    buf = io.StringIO()
    for line in meta:
        buf.write(line + "\n")
    csv.writer(buf, delimiter=KINDS[kind][0], lineterminator="\n").writerows(table)
    return buf.getvalue()


def _encode(text: str, gz: bool, bgzf: bool) -> bytes:
    """The bytes of OUT: the text, or its gzip form (BGZF for a BGZF input) with no name and
    time 0, which must read back as the text (what is written is what was scanned)."""
    data = text.encode("utf-8")
    if not gz:
        return data
    if bgzf:
        out = _bgzf(data)
        if _decompress(out) != (data, True):
            raise Refused("the compressed copy does not read back as the table.")
        return out
    out = gzip.compress(data, mtime=0)
    if _decompress(out) != (data, False):
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


def _long(norm_id: str) -> bool:
    """An ID of 5 or more characters, not digits only: matched anywhere in a cell."""
    return len(norm_id) >= 5 and not norm_id.isdigit()


def _ascii_digits(text: str) -> str:
    """Every Unicode decimal digit as its ASCII digit (`٩` -> `9`): for the scan only."""
    return "".join(str(unicodedata.decimal(ch)) if ch > "\x7f" and
                   unicodedata.category(ch) == "Nd" else ch for ch in text)


def _plain(text: str) -> str:
    """NFKC with format characters removed (`inventory.normalize`), decimal digits as ASCII and
    every dash as `-` (`DASHES`: `FAKE‐PT`, `FAKE–PT`, `FAKE−PT` read `FAKE-PT`)."""
    return _ascii_digits(inventory.normalize(text)).translate(DASHES)


def _forms(text: str) -> "set[str]":
    """Every form a text takes on the way to its fixed point, in any letter case: one round is
    `_plain`, then `\\u`, `\\x` and `%XX` escapes decoded; the rounds stop when the text no
    longer changes, or after ROUNDS. So an escape that NFKC makes (`％２Ｄ`), one escaped twice
    (`%252D`) or a dash escaped (`%E2%80%90`) is decoded too."""
    forms = {text.casefold(), text.translate(DASHES).casefold()}
    for _ in range(ROUNDS):
        nxt = sanitize.unescape(_plain(text))
        forms.add(_plain(nxt).casefold())
        if nxt == text:
            break
        text = nxt
    return forms


class _Matcher:
    """Whether a field holds an ID of the run or of the key, in any of its forms (`_forms`):
    a long ID (`_long`) anywhere in the field, also with every character that is not a letter or
    a digit removed from both when the ID has a letter (`FAKE PT 0001`, `FAKE.PT.0001` for
    `FAKE-PT-0001`; never digits joined: `999 0001` is not `9990001`); an ID of 5 or more digits
    as a whole run of digits (`see 9990002`, `x/9990002.bam`; not inside `19990001`, a
    position); a shorter ID with a letter as a whole word (`see ab12`); a shorter ID of digits
    only as the whole field (`12` is not in `0.12`)."""

    def __init__(self, ids: "set[str]"):
        norm_ids = {f for v in ids for f in _forms(v)} - {""}
        long_ids = sorted((v for v in norm_ids if _long(v)), key=len, reverse=True)
        self.numbers = {v for v in norm_ids if v.isdigit() and len(v) >= 5}
        self.whole = {v for v in norm_ids if v.isdigit() and len(v) < 5}
        words = sorted((v for v in norm_ids if len(v) < 5 and not v.isdigit()), key=len,
                       reverse=True)
        self.rx = re.compile("|".join(re.escape(v) for v in long_ids)) if long_ids else None
        bare = sorted({b for v in long_ids for b in [_letters_digits(v)] if b}, key=len,
                      reverse=True)
        self.sx = re.compile("|".join(re.escape(v) for v in bare)) if bare else None
        self.wx = re.compile(r"(?<![0-9a-z])(?:" + "|".join(re.escape(v) for v in words) +
                             r")(?![0-9a-z])") if words else None

    def hit(self, field: str, whole: bool = True) -> bool:
        """`whole`: also the rule of a short digit ID as the whole text (a field; not a line,
        where it would be every field's rule at once)."""
        for norm in _forms(field):
            if (whole and norm.strip() in self.whole) or \
                    (self.rx is not None and self.rx.search(norm)) or \
                    (self.sx is not None and self.sx.search(_alnum(norm))) or \
                    (self.wx is not None and self.wx.search(norm)) or \
                    (self.numbers and any(d in self.numbers
                                          for d in re.findall(r"[0-9]+", norm))):
                return True
        return False


def _alnum(text: str) -> str:
    """The letters and digits of a text, every other character removed."""
    return "".join(ch for ch in text if ch.isalnum())


def _letters_digits(norm: str) -> str:
    """For a form (`_forms`) of 5 or more characters with a letter, its letters and digits if
    there are 5 or more (`FAKE PT 0001` and `FAKE.PT.0001` read `fakept0001`); else "". Digits
    alone are never joined."""
    if not (_long(norm) and re.search(r"[^\W\d_]", norm)):
        return ""
    b = _alnum(norm)
    return b if len(b) >= 5 else ""


def _has_cf(text: str) -> bool:
    return any(unicodedata.category(ch) == "Cf" for ch in text)


def _bad_id_text(text: str) -> bool:
    """Whether a value to code holds a tab, a line break or an invisible format character."""
    return "\t" in text or "\n" in text or "\r" in text or _has_cf(text)


def _is_id_header(name: str, globs: List[str]) -> bool:
    """Whether a header or a JSON key, as written, looks like an identifier: its `col_key`
    form matches a glob. It takes the name as written: `col_key` drops one `#` each time."""
    return any(fnmatch.fnmatchcase(col_key(name), g) for g in globs)


def _coded_cells(rows: List[List[str]], cols: List[int]) -> Iterator[Tuple[int, str]]:
    """(column, value) of each coded cell that is not empty, its outer spaces removed, row by
    row and in each row in the order of `cols`: the order of first appearance of the IDs."""
    for r in rows:
        for i in cols:
            v = r[i].strip()
            if v:
                yield i, v


def _scan(meta: List[str], table: List[List[str]], cols: List[int], coded: "set[int]",
          m: _Matcher) -> None:
    """The scan of the whole output as it was read back, codes included: no field may hold an
    invisible format character or an ID (`_Matcher`). A place is named by the input's column
    number, never by a value."""
    for line in meta:
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


def _fold(text: str) -> str:
    """NFKC with format characters removed, every dash as `-`, then a case fold: for the rule
    of sample names that are words (`ｓａｍｐｌｅ1`)."""
    return inventory.normalize(text).translate(DASHES).casefold()


def _twin_forms(text: str) -> "set[str]":
    """The forms in which the scan reads an ID: each of `_forms` (letter case, Unicode form,
    digits, dashes, escapes) and its letters and digits only (`_letters_digits`). Two IDs that
    share one are twins: the scan matches one with the other (`P-1`, `p-1`, `Ｐ-1`, `P–1`;
    `FAKE-PT-0001`, `FAKE-PT-٠٠٠١`, `FAKE%2DPT-0001`, `FAKE PT 0001`, `FAKE.PT.0001`)."""
    forms = _forms(text) - {""}
    return forms | {b for f in forms for b in [_letters_digits(f)] if b}


def _draw(ids: List[str], key: Key, san: Sanitizer, m: _Matcher, values: "set[str]"
          ) -> Tuple[Dict[str, str], List[Tuple[str, str]]]:
    """(every ID's code, the new key lines). Two IDs of the input, or of the input and the key,
    that share a form the scan reads (`_twin_forms`) but differ in text are refused: they would
    get two codes for what may be one subject. A code for each ID the key does not hold, drawn
    from every code not used yet, skipping one the sanitizer would touch, one the scan would
    flag (`m`), or one that is a value of the input (`values`) or the key."""
    forms: Dict[str, "set[str]"] = {}
    for v in key.codes:
        for f in _twin_forms(v):
            forms.setdefault(f, set()).add(v)
    for v in ids:
        for f in _twin_forms(v):
            twins = forms.setdefault(f, set())
            twins.add(v)
            if len(twins) > 1:
                raise Refused("two IDs of the input, or of the input and the key, differ only "
                              "in letter case, Unicode form, digits, escapes or separators (the "
                              "scan reads them as one): make them one first.")
    used = {c.casefold() for c in key.codes.values()} | {v.casefold() for v in key.codes}
    used |= {v.casefold() for v in values}
    free = [n for n in range(1, 10 ** DIGITS)
            if f"{key.prefix}{n:0{DIGITS}d}".casefold() not in used]
    added: List[Tuple[str, str]] = []
    codes = dict(key.codes)
    for v in ids:
        if v in codes:
            continue
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
    return codes, added


def build(opts: Dict[str, object], cfg: config.Config, san: Sanitizer, rows: List[List[str]],
          key: Key, keep_headers: bool = False, m: Optional[_Matcher] = None,
          values: "Optional[set[str]]" = None
          ) -> Tuple[List[List[str]], List[Tuple[str, str]], List[int], "set[int]", _Matcher]:
    """(the output rows, header first; the new key lines; the input column of each output
    column; the coded columns; the matcher of the run's and the key's IDs). Refuses on any
    rule. With `keep_headers` (MAF) a coded column keeps its header unless one is given. `m`
    and `values`, when given, are the matcher and the input values of the whole file (several
    Markdown tables) for the draw, in place of this table's own."""
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
    for i, h in enumerate(header):
        if _is_id_header(h, globs) and i not in coded and i not in drop and i not in keep:
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
                _is_id_header(new, globs) or not _clean_both(san, new):
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
    for i, v in _coded_cells(rows[1:], list(coded)):
        if _bad_id_text(v):
            raise Refused(f"a cell of column {i + 1} holds a tab, a line break or an "
                          "invisible format character.")
        if v not in seen:
            seen.add(v)
            ids.append(v)
    # an ID of the key or of a coded column left anywhere in the output would link its code to
    # it: the scan of the output (`_scan`) refuses it
    if m is None:
        m = _Matcher(set(ids) | set(key.codes))
    if values is None:
        values = {c.strip() for r in rows for c in r}
    codes, added = _draw(ids, key, san, m, values)
    body = []
    for r in rows[1:]:
        body.append([codes[r[i].strip()] if i in coded and r[i].strip() else
                     ("" if i in coded else r[i]) for i in cols])
    if not opts["keep_order"]:
        _shuffle(body)
    return [out_header] + body, added, cols, set(coded), m


# --- VCF ----------------------------------------------------------------------------------------

def _contig_id(value: str) -> str:
    """The ID of a `##contig=<...>` line, its only part kept (its length is a long number the
    packs mask, and its other parts may name a file)."""
    if not (value.startswith("<") and value.endswith(">")):
        raise Refused("a ##contig line is not of the form <ID=...>.")
    body, pos, ids = value[1:-1], 0, []
    while True:
        item = META_ITEM.match(body, pos)
        if not item:
            raise Refused("a ##contig line cannot be read.")
        if item.group(1) == "ID":
            ids.append(item.group(2))
        pos = item.end()
        if pos == len(body):
            break
        if body[pos] != ",":
            raise Refused("a ##contig line cannot be read.")
        pos += 1
    if len(ids) != 1 or not CONTIG_ID.fullmatch(ids[0]):
        raise Refused("a ##contig line has no ID, or one that is not a plain name.")
    return ids[0]


def _read_vcf(text: str) -> Tuple[List[str], List[str], List[List[str]]]:
    """(the `##` lines kept, the `#CHROM` line's fields, the records). Kept: the first
    `##fileformat` line, the INFO, FORMAT, FILTER and ALT lines, and each contig line's ID; every
    other `##` line is dropped. Every record is as wide as the `#CHROM` line, which has the 9
    fixed fields and one sample or more."""
    if "\r" in text:
        raise Refused("the VCF has a carriage return: give it Unix line ends.")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if not lines or not VCF_FORMAT.fullmatch(lines[0]):
        raise Refused("the first line of a VCF must be ##fileformat=VCFv4.N.")
    meta, i = [lines[0]], 1
    while i < len(lines) and lines[i].startswith("##"):
        hit = VCF_META.fullmatch(lines[i])
        if not hit:
            raise Refused(f"line {i + 1} of the VCF is not a ##KEY=VALUE line.")
        if hit.group(1) in VCF_META_KEPT:
            meta.append(lines[i])
        elif hit.group(1) == "contig":
            meta.append(f"##contig=<ID={_contig_id(hit.group(2))}>")
        i += 1
    if i >= len(lines) or lines[i].split("\t")[:9] != VCF_FIXED:
        raise Refused(f"line {i + 1} of the VCF is not its #CHROM header line with the 9 fixed "
                      "fields.")
    header = lines[i].split("\t")
    if len(header) == len(VCF_FIXED):
        raise Refused("the VCF has no sample column.")
    recs = [ln.split("\t") for ln in lines[i + 1:]]
    for n, r in enumerate(recs, i + 2):
        if len(r) != len(header):
            raise Refused(f"line {n} of the VCF has another number of fields than its header.")
        if r[0].startswith("#"):
            raise Refused(f"line {n} of the VCF, after its header, starts with #.")
    return meta, header, recs


def _write_vcf(meta: List[str], header: List[str], recs: List[List[str]]) -> str:
    return "".join(ln + "\n" for ln in meta + ["\t".join(r) for r in [header] + recs])


def _vcf_hit(field: str, m: _Matcher) -> bool:
    """The whole field (an ID with a colon is not cut), then each part of it split on
    `; , = | :` (INFO, FORMAT and sample values; a short ID as a whole part)."""
    return m.hit(field) or any(m.hit(p) for p in VCF_SPLIT.split(field) if p != field)


def _sample_check(samples: List[str], keep: "set[int]", san: Sanitizer) -> None:
    """Every sample name is an ID to code, or kept by number (`--keep-samples`). A name that is
    a word (TUMOR), has no digit or is under 3 characters is refused: coded, it would link
    unrelated subjects in the key, and as a known ID it would refuse every later file that says
    it."""
    if len(set(samples)) != len(samples):
        raise Refused("the VCF names a sample twice.")
    if any(n > len(samples) for n in keep):
        raise Refused("--keep-samples names a sample number the VCF does not have.")
    for n, s in enumerate(samples, 1):
        if not s.strip() or s != s.strip() or \
                any(unicodedata.category(ch).startswith("C") for ch in s):
            raise Refused(f"the name of sample {n} (column {n + 9}) is empty, has outer spaces "
                          "or holds an invisible or control character.")
        if n in keep:
            if not _clean_both(san, s):
                raise Refused(f"the kept name of sample {n} (column {n + 9}) holds what the "
                              "sanitizer masks.")
        elif _fold(s) in SAMPLE_WORDS or not re.search(r"[0-9]", _fold(s)) or len(_fold(s)) < 3:
            raise Refused(f"the name of sample {n} (column {n + 9}) is not an ID: a word of "
                          "the list in --help, a name with no digit, or one under 3 characters. "
                          f"Rename it first, or keep its name with --keep-samples {n}.")


def _scan_vcf(meta: List[str], header: List[str], recs: List[List[str]], coded: "set[int]",
              m: _Matcher) -> None:
    """The scan of the whole VCF as it was read back, codes included (`_vcf_hit`). A place is
    named by its number, never by a value."""
    for n, line in enumerate(meta, 1):
        if _has_cf(line) or _vcf_hit(line, m):
            raise Refused(f"the kept ## line {n} of the output holds an ID of a sample or of the "
                          "key, or an invisible format character.")
    for j, name in enumerate(header[9:]):
        if _has_cf(name) or _vcf_hit(name, m):
            if j in coded:
                raise Refused(f"the code of sample column {j + 10} matches an ID of this VCF or "
                              "of the key.")
            raise Refused(f"the kept name of sample column {j + 10} holds an ID of a sample or "
                          "of the key.")
    for n, r in enumerate(recs, 1):
        for f in r:
            if _has_cf(f) or _vcf_hit(f, m):
                raise Refused(f"record {n} holds an ID of a sample or of the key, or an "
                              "invisible format character: clean it first (bcftools "
                              "annotate).")


def _code_vcf(opts: Dict[str, object], san: Sanitizer, text: str, key: Key
              ) -> Tuple[str, List[Tuple[str, str]], int, _Matcher]:
    """(the written VCF, the new key lines, the record count, the matcher): the sample names
    coded, the sample columns shuffled (one permutation for the header and every record) unless
    --keep-order; the records keep their order (tabix needs it)."""
    meta, header, recs = _read_vcf(text)
    for n, line in enumerate(meta, 1):
        if not _clean_both(san, line):
            raise Refused(f"the kept ## line {n} of the output holds what the sanitizer masks: "
                          "clean it first.")
    samples = header[9:]
    keep = set(opts["keep_samples"])  # type: ignore[call-overload]
    _sample_check(samples, keep, san)
    ids = [s for n, s in enumerate(samples, 1) if n not in keep]
    m = _Matcher(set(ids) | set(key.codes))
    # a code is never a value of the input: a whole field or a part the scan splits (`X=S0042`)
    values = set(samples) | {v for r in recs for f in r for v in [f] + VCF_SPLIT.split(f)
                             if len(v) <= len(key.prefix) + DIGITS}
    codes, added = _draw(ids, key, san, m, values)
    perm = list(range(len(samples)))
    if not opts["keep_order"]:
        _shuffle(perm)
    out_head = VCF_FIXED + [samples[j] if j + 1 in keep else codes[samples[j]] for j in perm]
    out_recs = [r[:9] + [r[9 + j] for j in perm] for r in recs]
    coded = {k for k, j in enumerate(perm) if j + 1 not in keep}
    written = _write_vcf(meta, out_head, out_recs)
    back = _read_vcf(written)
    if back != (meta, out_head, out_recs):
        raise Refused("the copy does not read back as the coded VCF.")
    _scan_vcf(back[0], back[1], back[2], coded, m)
    return written, added, len(recs), m


# --- JSON ---------------------------------------------------------------------------------------

def _no_twins(pairs: List[Tuple[str, object]]) -> Dict[str, object]:
    out: Dict[str, object] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("a key twice in one object")
        out[k] = v
    return out


def _no_constant(name: str) -> object:
    raise ValueError("NaN or Infinity")


def _finite(text: str) -> float:
    f = float(text)
    if not math.isfinite(f):  # 1e400 reads as inf, which JSON cannot write
        raise ValueError("a number out of range")
    return f


def _integer(text: str) -> int:
    if len(text.lstrip("-")) > JSON_DIGITS:
        raise ValueError("an integer too long")
    return int(text)


def _read_json(text: str) -> object:
    """The document: a key twice in one object, NaN, Infinity, a number out of range, an
    integer of more than JSON_DIGITS digits, objects or arrays nested deeper than JSON_DEPTH and
    a lone surrogate (`\\ud800`, which has no UTF-8 form) in a key or a string are refused (as
    any error: the one fixed refusal)."""
    doc = json.loads(text, object_pairs_hook=_no_twins, parse_constant=_no_constant,
                     parse_float=_finite, parse_int=_integer)
    stack = [(doc, 1)]
    while stack:
        v, depth = stack.pop()
        if isinstance(v, str) and SURROGATE.search(v):
            raise ValueError("a lone surrogate")
        if isinstance(v, (dict, list)):
            if depth > JSON_DEPTH:
                raise ValueError("nested too deep")
            if isinstance(v, dict) and any(SURROGATE.search(k) for k in v):
                raise ValueError("a lone surrogate")
            stack += [(c, depth + 1) for c in (v.values() if isinstance(v, dict) else v)]
    return doc


def _write_json(doc: object) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


Steps = Tuple[Optional[str], ...]  # a key path: a key, or None for every element of an array


def _json_path(spec: str, n: int, opt: str) -> Steps:
    """`samples[].id` as ("samples", None, "id"); `[].mrn` names the elements of a top-level
    array. A key is matched exactly; one with `.`, `[` or `]` cannot be named."""
    steps: List[Optional[str]] = []
    for k, part in enumerate(spec.split(".")):
        hit = JSON_STEP.fullmatch(part)
        if not hit or not hit.group(1) and (k > 0 or not hit.group(2)):
            raise Refused(f"path {n} of {opt} is not a key path (see --help).")
        if hit.group(1):
            steps.append(hit.group(1))
        steps += [None] * (len(hit.group(2)) // 2)
    return tuple(steps)


def _json_at(box: List[object], steps: Steps, n: int, opt: str, last: int = -1
             ) -> Tuple[List[Tuple[object, object]], List[Tuple[object, object]]]:
    """(the places the path reaches, each a (container, key or index); the places of the arrays
    met at step `last`). A missing key or a null on the way reaches nothing there; any other
    value where the path needs an object or an array is refused."""
    places: List[Tuple[object, object]] = [(box, 0)]
    arrays: List[Tuple[object, object]] = []
    for i, step in enumerate(steps):
        nxt: List[Tuple[object, object]] = []
        for parent, slot in places:
            v = parent[slot]  # type: ignore[index]
            if v is None:
                continue
            if step is None and isinstance(v, list):
                nxt += [(v, j) for j in range(len(v))]
                if i == last:
                    arrays.append((parent, slot))
            elif step is not None and isinstance(v, dict):
                if step in v:
                    nxt.append((v, step))
            else:
                raise Refused(f"path {n} of {opt} meets a value of another kind (a key where "
                              "there is no object, or brackets where there is no array).")
        places = nxt
    return places, arrays


def _json_items(doc: object):
    """Every value of `doc` in the order of the file: (its path, the object or array it is in
    or None, the key it is under or None, the value, the nearest (object, key) above it or
    None)."""
    stack: List[Tuple[Steps, object, Optional[str], object, object]] = [
        ((), None, None, doc, None)]
    while stack:
        path, parent, k, v, owner = stack.pop()
        yield path, parent, k, v, owner
        if isinstance(v, dict):
            stack += [(path + (c,), v, c, x, (v, c)) for c, x in reversed(list(v.items()))]
        elif isinstance(v, list):
            stack += [(path + (None,), v, None, x, owner) for x in reversed(v)]


def _bare(steps: Steps) -> Steps:
    """The path without the `[]`s at its end: `samples[]` and `samples` name one key."""
    while steps and steps[-1] is None:
        steps = steps[:-1]
    return steps


def _json_readings(text: str) -> List[str]:
    """The text, and its integer form when it is a number that is whole (`1234.0`,
    `9.990001e6` -> `9990001`): for the scan only."""
    t = text.strip()
    if JSON_NUMBER.fullmatch(t):
        d = decimal.Decimal(t)
        if abs(d.adjusted()) <= 40 and d == d.to_integral_value():
            return [text, str(int(d))]
    return [text]


def _json_text(v: object) -> Optional[str]:
    """The text of a scalar for the scan: a string, or a number as written."""
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return json.dumps(v)
    return None


def _scan_json(doc: object, m: _Matcher) -> None:
    """The scan of the whole document as it was read back, codes included: no key and no
    scalar may hold an invisible format character or an ID (`_Matcher`)."""
    for _, _, k, v, _ in _json_items(doc):
        if k is not None and (_has_cf(k) or any(m.hit(f) for f in _json_readings(k))):
            raise Refused("a key of the output holds an ID of a coded path or of the key, or an "
                          "invisible format character.")
        text = _json_text(v)
        if text is not None and (_has_cf(text) or any(m.hit(f) for f in _json_readings(text))):
            raise Refused("a value of the output holds an ID of a coded path or of the key, or "
                          "an invisible format character: drop it, or clean it first.")


def _code_json(opts: Dict[str, object], cfg: config.Config, san: Sanitizer, text: str, key: Key
               ) -> Tuple[str, List[Tuple[str, str]], _Matcher]:
    """(the written JSON, the new key lines, the matcher). The values at the paths of --columns
    (a string or an integer; null stays) get codes; the keys at the paths of --drop are
    removed, a container whole; every scalar path an ID glob matches (`samples[]`,
    `samples[].id`) is named. The array at the last [] of a coded path that goes on to a key
    (an array of objects) is shuffled unless --keep-order, and refused when an array of the
    same length sits beside it (their pairing by position would break); a coded path that
    ends in [] (the elements themselves) needs --keep-order."""
    doc = _read_json(text)
    box: List[object] = [doc]
    # a key is named in messages by its number in the input, never by its text or its path
    keys = (x for x in _json_items(doc) if x[2] is not None)
    number = {(id(p), k): n for n, (_, p, k, _, _) in enumerate(keys, 1)}
    specs: Dict[str, List[Tuple[int, Steps]]] = {}
    named = set()
    for opt in ("columns", "drop", "keep"):
        flag = f"--{opt}"
        specs[opt] = []
        for n, spec in enumerate(opts.get(opt, []), 1):  # type: ignore[union-attr]
            spec = str(spec).strip()  # `a, b` as in a table's list of columns
            if opt == "columns" and "=" in spec:
                raise Refused("a key path takes no new name (=NEW): a coded value keeps its key.")
            steps = _json_path(spec, n, flag)
            if opt == "drop" and (not steps or steps[-1] is None):
                raise Refused(f"path {n} of --drop does not end in a key.")
            if _bare(steps) in named:
                raise Refused("a key path is named twice in --columns, --drop and --keep.")
            named.add(_bare(steps))
            specs[opt].append((n, steps))
    for n, steps in specs["drop"]:
        places, _ = _json_at(box, steps, n, "--drop")
        if not places:
            raise Refused(f"path {n} of --drop matches nothing.")
        for parent, slot in places:
            del parent[slot]  # type: ignore[attr-defined]
    # the scalar paths of the document (strings, numbers, true, false, null), without their
    # last []s, each with the key it is under
    scalars: Dict[Steps, Tuple[object, str]] = {}
    for path, _, _, v, owner in _json_items(box[0]):
        if not isinstance(v, (dict, list)) and owner is not None:
            scalars.setdefault(_bare(path), owner)  # type: ignore[arg-type]
    for n, steps in specs["keep"]:
        _json_at(box, steps, n, "--keep")
        if _bare(steps) not in scalars:
            raise Refused(f"path {n} of --keep names no value (a string, a number, true, "
                          "false or null).")
    fills: List[Tuple[object, object, str]] = []
    shuffled: Dict[int, Tuple[int, object, object]] = {}
    for n, steps in specs["columns"]:
        if steps[-1] is None and not opts["keep_order"]:
            raise Refused(f"path {n} of --columns codes the elements of an array, whose order "
                          "may follow the IDs and cannot be shuffled alone: give --keep-order.")
        last = max([i for i, s in enumerate(steps) if s is None], default=-1)
        places, arrays = _json_at(box, steps, n, "--columns", last)
        if not places:
            raise Refused(f"path {n} of --columns matches nothing.")
        for parent, slot in places:
            v = parent[slot]  # type: ignore[index]
            if v is None:
                continue
            if isinstance(v, bool) or not isinstance(v, (str, int)):
                raise Refused(f"a value at path {n} of --columns is not a string, an integer "
                              "or null.")
            s = (v if isinstance(v, str) else str(v)).strip()
            if _bad_id_text(s):
                raise Refused(f"a value at path {n} of --columns holds a tab, a line break or "
                              "an invisible format character.")
            fills.append((parent, slot, s))
        for parent, slot in arrays:
            shuffled[id(parent[slot])] = (n, parent, slot)  # type: ignore[index]
    if not opts["keep_order"]:
        for n, parent, slot in shuffled.values():
            a = parent[slot]  # type: ignore[index]
            beside = parent.values() if isinstance(parent, dict) else parent  # type: ignore
            if any(isinstance(b, list) and b is not a and len(b) == len(a) for b in beside):
                raise Refused(f"an array that path {n} of --columns would shuffle has an array "
                              "of the same length beside it: they may be paired by position, "
                              "and a shuffle would break the pairing. Give --keep-order (for "
                              "the whole run), or drop the other array.")
    globs = list(BUILTIN_ID_COLUMNS) + [col_key(g) for g in cfg.sanitize_id_columns]
    for path, (p, k) in scalars.items():
        if _is_id_header(k, globs) and path not in named:
            raise Refused(f"key {number[(id(p), k)]} (in the order of the file) looks like an "
                          "identifier: name its path in --columns, --drop or --keep.")
    for _, p, k, _, _ in _json_items(box[0]):
        if k is not None and not _clean_both(san, k):
            raise Refused(f"key {number[(id(p), k)]} (in the order of the file) holds what the "
                          "sanitizer masks (a key that is an ID is refused).")
    ids = list(dict.fromkeys(s for _, _, s in fills if s))  # in order of first appearance
    m = _Matcher(set(ids) | set(key.codes))
    for _, p, k, _, _ in _json_items(box[0]):
        if k is not None and (_has_cf(k) or any(m.hit(f) for f in _json_readings(k))):
            raise Refused(f"key {number[(id(p), k)]} (in the order of the file) holds an ID of "
                          "a coded path or of the key, or an invisible format character.")
    values = {c for _, _, k, v, _ in _json_items(box[0])
              for c in (k, _json_text(v)) if c is not None}
    codes, added = _draw(ids, key, san, m, {v.strip() for v in values})
    for parent, slot, s in fills:
        parent[slot] = codes[s] if s else ""  # type: ignore[index]
    if not opts["keep_order"]:
        for _, parent, slot in shuffled.values():
            _shuffle(parent[slot])  # type: ignore[index]
    written = _write_json(box[0])
    back = _read_json(written)
    # `==` takes 1 for true and 1.0: the compact text also compares the kinds and the order
    if back != box[0] or json.dumps(back) != json.dumps(box[0]):
        raise Refused("the copy does not read back as the coded JSON.")
    _scan_json(back, m)
    return written, added, m


# --- Markdown -----------------------------------------------------------------------------------

def _read_md(text: str) -> List[List[List[str]]]:
    """The pipe tables of a Markdown file, each its rows of cells (outer spaces removed): the
    header, the alignment row, the body rows. Only tables and blank lines are taken: any other
    line (prose, a heading, a list, code, a row without its outer pipes) is free text, refused.
    A line with a backslash or a backtick is refused: an escaped pipe or a code span has no
    safe split; so is a line with `<`, `[` or `]` (inline HTML, a link, an image). Every row of
    a table is as wide as its header; a second alignment row inside a table is refused."""
    if "\r" in text:
        raise Refused("the Markdown file has a carriage return: give it Unix line ends.")
    tables: List[List[List[str]]] = []
    cur: List[List[str]] = []
    lines = text.split("\n")
    for n, line in enumerate(lines + [""], 1):
        row = line.rstrip(" \t")
        if not row:
            if cur:
                if len(cur) < 2:
                    raise Refused(f"line {n - 1} of the Markdown file is not in a table (a "
                                  "table has a header and an alignment row): free text is not "
                                  "covered.")
                tables.append(cur)
            cur = []
            continue
        if len(row) < 2 or row[0] != "|" or row[-1] != "|":
            raise Refused(f"line {n} of the Markdown file is not a table row (| a | b |): free "
                          "text (prose, headings, lists, code) is not covered.")
        if "\\" in row or "`" in row:
            raise Refused(f"line {n} of the Markdown file holds a backslash or a backtick (an "
                          "escape or a code span): its cells cannot be split safely.")
        if "<" in row or "[" in row or "]" in row:
            raise Refused(f"line {n} of the Markdown file holds <, [ or ] (inline HTML, a link, "
                          "an image or an autolink), which is not covered: write &lt; or "
                          "remove it.")
        cells = [c.strip(" \t") for c in row[1:-1].split("|")]
        if cur and len(cells) != len(cur[0]):
            raise Refused(f"line {n} of the Markdown file has another number of cells than the "
                          "header of its table.")
        if len(cur) == 1 and not all(MD_ALIGN.fullmatch(c) for c in cells):
            raise Refused(f"line {n} of the Markdown file is not the alignment row of its table "
                          "(| --- |): free text is not covered.")
        if len(cur) > 1 and all(MD_ALIGN.fullmatch(c) for c in cells):
            raise Refused(f"line {n} of the Markdown file is an alignment row inside a table: "
                          "put a blank line between two tables.")
        cur.append(cells)
    if not tables:
        raise Refused("the Markdown file holds no table.")
    return tables


def _write_md(tables: List[List[List[str]]]) -> str:
    return "\n".join("".join("| " + " | ".join(r) + " |\n" for r in t) for t in tables)


def _md_render(text: str) -> str:
    """A cell with the marks of emphasis and strike-through removed (`999**0001**`), for the
    scan only. A cell has no HTML, link or image: `_read_md` refuses `<`, `[` and `]`."""
    return MD_MARKS.sub("", text)


def _md_readings(text: str) -> List[str]:
    """The forms of a Markdown cell for the scan: the text, then each round of NFKC, the
    escapes of `sanitize.unescape` and HTML entities decoded (`&#45;`, `&amp;#45;`, `%26%2345%3B`,
    `&hyphen;`), each also rendered (`_md_render`). A text still changing after ROUNDS rounds
    cannot be decided: ValueError (the one fixed refusal)."""
    forms: List[str] = []
    cur = text
    for _ in range(ROUNDS + 1):
        forms += [cur, _md_render(cur)]
        nxt = html.unescape(sanitize.unescape(inventory.normalize(cur)))
        if nxt == cur:
            return forms
        cur = nxt
    raise ValueError("entities nested too deep")


def _md_header_markup(header: str) -> bool:
    """Whether a Markdown header holds emphasis markup (`MD_MARKUP`) or an HTML entity."""
    return bool(MD_MARKUP.search(header)) or html.unescape(header) != header


def _scan_md(tables: List[List[List[str]]], cols: List[List[int]], m: _Matcher) -> None:
    """The scan of every cell of the output as it was read back, codes, headers and alignment
    rows included, in each of its forms (`_md_readings`). A place is named by the table and the
    input's column number, never by a value."""
    for t, rows in enumerate(tables, 1):
        for row in rows:
            for c, cell in enumerate(row):
                if any(_has_cf(f) or m.hit(f) for f in _md_readings(cell)):
                    raise Refused(f"table {t}: column {cols[t - 1][c] + 1} of the output holds "
                                  "an ID of a coded column or of the key, or an invisible "
                                  "format character (also behind an entity or markup): drop "
                                  "it, or clean it first.")


def _code_md(opts: Dict[str, object], cfg: config.Config, san: Sanitizer, text: str, key: Key
             ) -> Tuple[str, List[Tuple[str, str]], int, _Matcher]:
    """(the written Markdown, the new key lines, the body row count, the matcher). Each table
    follows the table rules (`build`) with the names of --columns, --drop and --keep its header
    holds; each name is found in some table. One draw knows the IDs and the values of every
    table, and one ID gets one code in all of them. The body rows of a table with a coded
    column are shuffled unless --keep-order; the header and the alignment row are kept."""
    tables = _read_md(text)
    names = {opt: [str(s) for s in opts.get(opt, [])]  # type: ignore[union-attr]
             for opt in ("columns", "drop", "keep")}
    subs: List[Dict[str, object]] = []
    found = set()
    ids = set()
    for t, rows in enumerate(tables, 1):
        for c, h in enumerate(rows[0], 1):
            if _md_header_markup(h):
                raise Refused(f"table {t}: the header of column {c} holds Markdown or HTML "
                              "markup or an entity: write it plain.")
        keys = [col_key(h) for h in rows[0]]
        sub: Dict[str, object] = {}
        for opt, specs in names.items():
            sub[opt] = [s for s in specs
                        if col_key(s.partition("=")[0] if opt == "columns" else s) in keys]
            found |= {(opt, s) for s in sub[opt]}  # type: ignore[attr-defined]
        coded = [keys.index(col_key(s.partition("=")[0]))
                 for s in sub["columns"]]  # type: ignore[attr-defined]
        ids |= {v for _, v in _coded_cells(rows[2:], coded)}
        sub["keep_order"] = opts["keep_order"] or not sub["columns"]
        subs.append(sub)
    if any((opt, s) not in found for opt, specs in names.items() for s in specs):
        raise Refused("a column named in --columns, --drop or --keep is not found in any table.")
    m = _Matcher(ids | set(key.codes))
    values = {f.strip() for rows in tables for r in rows for c in r for f in _md_readings(c)}
    work = Key(key.prefix, dict(key.codes), key.ident)
    out: List[List[List[str]]] = []
    cols_of: List[List[int]] = []
    added: List[Tuple[str, str]] = []
    for t, (rows, sub) in enumerate(zip(tables, subs), 1):
        try:
            table, new, cols, _, _ = build(sub, cfg, san, [rows[0]] + rows[2:], work, m=m,
                                           values=values)
        except Refused as exc:
            raise Refused(f"table {t}: {exc}") from None
        for h in table[0]:
            if "|" in h or "\\" in h or "`" in h or _md_header_markup(h):
                raise Refused(f"table {t}: a new header holds a pipe, a backslash, a backtick, "
                              "markup or an entity.")
        work.codes.update(new)
        added += new
        out.append([table[0], [rows[1][i] for i in cols]] + table[1:])
        cols_of.append(cols)
    written = _write_md(out)
    back = _read_md(written)
    if back != out:
        raise Refused("the copy does not read back as the coded tables.")
    m = _Matcher(set(work.codes))  # every ID of the key and of this run
    _scan_md(back, cols_of, m)
    return written, added, sum(len(t) - 2 for t in out), m


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
        raise Refused("the folder of the output does not exist.") from None
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
        raise Refused("the folder of the output is reached through a link or cannot be opened.") from None
    return fd


def run(argv: Sequence[str]) -> Tuple[int, str]:
    opts = _parse(argv)
    home = _home()
    bfd, kfd = _open_state(home)
    try:
        return _run(opts, home, bfd, kfd)
    finally:
        os.close(bfd)
        if kfd >= 0:
            os.close(kfd)


def _run(opts: Dict[str, object], home: str, bfd: int, kfd: int) -> Tuple[int, str]:
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
        raise Refused("the sanitizer cannot be built from the config.") from None
    try:
        count, added, data = _code(opts, cfg, san, raw, kind, gz, key)
    except Refused:
        raise
    except Exception:
        # any failure of a reader, a writer or the check-back (deep nesting, a damaged gzip
        # member, a decode error, memory): one fixed text, never the exception's own
        raise Refused(f"the input cannot be read as a {_label(kind, gz)} file.") from None
    _commit(opts, key, bfd, kfd, file, added, out_dir, out_name, data)
    return count, {".vcf": "VCF, {} record(s)", ".json": "JSON file",
                   ".md": "Markdown tables, {} row(s)"}.get(kind, "table, {} row(s)")


def _code(opts: Dict[str, object], cfg: config.Config, san: Sanitizer, raw: bytes, kind: str,
          gz: bool, key: Key) -> Tuple[int, List[Tuple[str, str]], bytes]:
    """(the row or record count, the new key lines, the bytes of OUT): read, code, write, then
    read the written text back and scan it whole."""
    plain, bgzf = _decompress(raw) if gz else (raw, False)
    if kind == ".vcf":
        text, added, count, m = _code_vcf(opts, san, _decode(plain, kind), key)
    elif kind == ".json":
        text, added, m = _code_json(opts, cfg, san, _decode(plain, kind), key)
        count = 0  # a JSON file reports no count (decision G)
    elif kind == ".md":
        text, added, count, m = _code_md(opts, cfg, san, _decode(plain, kind), key)
    else:
        meta, rows = _read_table(_decode(plain, kind), kind)
        for line in meta:
            if not _clean_both(san, line):
                raise Refused("the #version line holds what the sanitizer masks.")
        table, added, cols, coded, m = build(opts, cfg, san, rows, key,
                                             keep_headers=kind == ".maf")
        text = _write_table(meta, table, kind)
        back = _read_table(text, kind)
        if back != (meta, table):
            raise Refused("the copy does not read back as the coded table.")
        _scan(back[0], back[1], cols, coded, m)
        count = len(table) - 1
    data = _encode(text, gz, bgzf)
    # the lines as written (`_encode` has shown that the bytes read back as `text`): an ID can
    # span two fields (`Doe, John` as the CSV fields `Doe` and ` John`); a Markdown line in its
    # decoded forms too
    for n, line in enumerate(text.split("\n"), 1):
        if any(m.hit(f, whole=False) for f in (_md_readings(line) if kind == ".md" else [line])):
            raise Refused(f"line {n} of the output holds an ID of a coded column or of the key "
                          "across its fields: drop or clean those columns first.")
    return count, added, data


def _commit(opts: Dict[str, object], key: Key, bfd: int, kfd: int, file: str,
            added: List[Tuple[str, str]], out_dir: str, out_name: str, data: bytes) -> None:
    """Create OUT, append the key, write OUT. On any failure OUT is removed, and so is a new key
    this run made (its codes were never given out); an existing key keeps what was appended."""
    text = "".join(f"{v}\t{c}\n" for v, c in added)
    if opts["new"]:
        text = f"{KEY_MAGIC}\t1\t{key.prefix}\n" + text
    line_bytes = text.encode("utf-8")  # before any file is made: an error here leaves none
    dfd = _open_walk(out_dir)
    own = made = -1
    try:
        try:
            ofd = os.open(out_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                          dir_fd=dfd)
        except OSError:
            raise Refused("the output cannot be made (it exists, or the folder is not "
                          "writable).") from None
        try:
            try:
                if kfd < 0:
                    # made now, in the backups folder opened before (never by its path again)
                    os.mkdir("keys", 0o700, dir_fd=bfd)
                    own = kfd = os.open("keys", _DIR, dir_fd=bfd)
                    os.fchmod(kfd, 0o700)  # the umask may have taken bits away
                made = _append_key(opts, key, kfd, file, line_bytes, bool(added))
            except OSError:
                raise Refused("the key cannot be written.") from None
            os.fchmod(ofd, 0o600)
            try:
                _write_out(ofd, data)
            except OSError:
                raise Removed("the output cannot be written; it was removed. " +
                              ("The new key was removed." if opts["new"] else
                               "The key keeps the codes it was given.")) from None
        except BaseException:
            os.close(ofd)
            ofd = -1
            for name, fd in ((out_name, dfd), (file, kfd if made >= 0 else -1)):
                if fd >= 0:
                    try:
                        os.unlink(name, dir_fd=fd)
                    except OSError:
                        pass
            raise
        finally:
            if ofd >= 0:
                os.close(ofd)
    finally:
        os.close(dfd)
        if own >= 0:
            os.close(own)


def _append_key(opts: Dict[str, object], key: Key, kfd: int, file: str, data: bytes,
                any_added: bool) -> int:
    """Write the key lines; 1 when this run made the key file (it is removed on a failure, also
    one of its own write), -1 when it only appended or wrote nothing."""
    _check_dir(kfd, "~/.phiward/backups/keys")
    if opts["new"]:
        fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                     dir_fd=kfd)
    else:
        if not any_added:
            return -1
        fd = os.open(file, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=kfd)
    try:
        if opts["new"]:
            os.fchmod(fd, 0o600)
        else:
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino, st.st_size) != key.ident or st.st_nlink != 1:
                raise Refused("the key changed while it was read.")
        _write_all(fd, data)
    except BaseException:
        if opts["new"]:
            try:
                os.unlink(file, dir_fd=kfd)
            except OSError:
                pass
        raise
    finally:
        os.close(fd)
    return 1 if opts["new"] else -1


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
        n, what = run(argv)
    except Refused as exc:
        done = "" if isinstance(exc, Removed) else " Nothing was written."
        ferr.write(f"phiward pseudonymize: {exc}{done}\n")
        return 2
    except OSError as exc:
        ferr.write(f"phiward pseudonymize: a file operation failed ({type(exc).__name__}). "
                   "Nothing was written.\n")
        return 1
    except Exception:
        # never the exception's own text or a traceback: either may hold a value of the table
        ferr.write("phiward pseudonymize: the run stopped on an unexpected error. No output "
                   "was kept, and no new key; an existing key may keep codes appended to it.\n")
        return 1
    fout.write(f"phiward pseudonymize: wrote the coded {what.format(n)}. Read it with "
               "`phiward run`.\n")
    return 0
