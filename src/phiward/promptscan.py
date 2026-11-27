"""The prompt scan: would the sanitizer change this prompt? If so, the prompt is not sent.

Agent-neutral: text and a config in, a verdict out (the adapters are in adapters/). It is a
tripwire for honest pasting, not a boundary (docs/threat-model.md).

The sanitizer is built as the gateway builds it, less what is not an identifier
(`Sanitizer.from_config(identifiers_only=True)`): no detail rules of a built-in pack (genomics:
file and read names), no positions or numbers, no inventory names, no `names_from`, no derived
roots. Packs come from the user config only (`[sanitize] patterns` is the user's already); the
roots and patterns, and the remote roots, from the full config. Each line is compared in the
sanitizer's own form; the absolute forms of path-like words (`~/`, `$HOME/`, relative words with
a `/`, their link targets) are checked too, as extra lines nobody sees.

It fails closed: a config or pack that cannot be used, a prompt over MAX_BYTES, or any error
blocks, with a reason. The kinds and the reason are phiward's own words and placeholders, never
prompt text.
"""

import dataclasses
import json
import os
import re
import sys
from collections import Counter
from typing import List, NamedTuple, Tuple

from phiward import config, pathid, sanitize

MAX_BYTES = 1 << 20
PROTECTED = "<PROTECTED>"
WITHHELD_KIND = "text the sanitizer withholds"
DOCTOR = config.DOCTOR_STEP + "."
_WORD = re.compile(r"\"[^\"\n]*\"|'[^'\n]*'|\S+")
_HOME = re.compile(r"(?:~|\$HOME|\$\{HOME\})(?=/)")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:")


class Verdict(NamedTuple):
    blocked: bool
    kinds: Tuple[str, ...]  # placeholders ("<SAMPLEID>", "<PROTECTED>"), or WITHHELD_KIND
    why: str  # a sentence written by phiward; "" when clear


def reason(kinds: Tuple[str, ...]) -> str:
    """The message for a prompt that holds `kinds`."""
    parts = []
    if PROTECTED in kinds:
        parts.append("a path below a protected root (ask for it through the gateway: "
                     "`phiward run -- CMD`)")
    ids = [k for k in kinds if k not in (PROTECTED, WITHHELD_KIND)]
    if ids:
        parts.append(", ".join(ids) + " (masked by your packs or [sanitize] patterns)")
    if WITHHELD_KIND in kinds or not parts:
        parts.append(WITHHELD_KIND)
    return ("phiward: this prompt was not sent: it holds " + "; ".join(parts) + ". Remove it, "
            "or use its masked form or a pseudonymized ID (`phiward pseudonymize`), then send "
            "it again.")


def _fail(what: str) -> Verdict:
    return Verdict(True, (), f"phiward: this prompt was not sent: {what}; {DOCTOR}")


def path_forms(text: str, cwd: str) -> List[str]:
    """The absolute forms of the path-like words in `text`: a word that starts with `~/`,
    `$HOME/` or `${HOME}/`, a relative word with a `/` joined to `cwd`, and the link target of
    each (and of an absolute word). A leading `@`, quotes, brackets, a trailing `.,:;)` and a
    `#L…` suffix are taken off first. Only adds forms to check, never removes one."""
    home = pathid.home()
    out: List[str] = []
    for m in _WORD.finditer(text):
        w = m.group(0).lstrip("@").strip("\"'`()[]{}<>")
        w = re.sub(r"#L[\d\-:,L]*$", "", w).rstrip(".,:;)")
        if "/" not in w or len(w) > 4096 or "\0" in w:
            continue
        h = _HOME.match(w)
        if h:
            p = home + w[h.end():]
        elif w.startswith("/"):
            p = w
        elif _URL.match(w) or w.startswith("//"):
            continue
        else:
            p = os.path.join(cwd, w)
        p = os.path.normpath(p)
        for f in (p, os.path.realpath(p)):
            if f not in out:
                out.append(f)
    return out


def _kinds(clean: str, plain: str) -> List[str]:
    if clean == sanitize.WITHHELD:
        return [WITHHELD_KIND]
    before = Counter(sanitize._PLACEHOLDER.findall(plain))
    after = Counter(sanitize._PLACEHOLDER.findall(clean))
    return [k for k in after if after[k] > before[k]]


def prompt_sanitizer(cfg: config.Config) -> sanitize.Sanitizer:
    """The sanitizer the prompt scan uses under `cfg` (built once; `verdict_with` checks text
    with it). Raises SanitizerError."""
    scan_cfg = dataclasses.replace(cfg, names_from=[], packs=list(cfg.user_packs),
                                   sanitize_patterns=list(cfg.sanitize_patterns))
    san = sanitize.Sanitizer.from_config(scan_cfg, identifiers_only=True)
    if cfg.remote_roots:
        from phiward.run import add_remote_roots
        add_remote_roots(san, cfg)
    return san


def verdict_with(san: sanitize.Sanitizer, cfg: config.Config, text: str, cwd: str) -> Verdict:
    """Block or clear `text` with `san`, the prompt sanitizer of `cfg` (`prompt_sanitizer`)."""
    try:
        found: List[str] = []
        changed = False
        for line in text.splitlines() + path_forms(text, cwd):
            plain = sanitize.normalize(line)
            out = san.clean(line)
            if out != plain:
                changed = True
                found += [k for k in _kinds(out, plain) if k not in found]
        if not changed:
            return Verdict(False, (), "")
        kinds = tuple(sorted(found))
        return Verdict(True, kinds, reason(kinds))
    except Exception:  # noqa: BLE001 - fail closed on anything
        return _UNCHECKED


def prompt_verdict(text: str, cfg: config.Config, cwd: str) -> Verdict:
    """Block or clear `text` (a prompt), under the config `cfg`, from the folder `cwd`."""
    try:
        if len(text.encode("utf-8", "surrogatepass")) > MAX_BYTES:
            return Verdict(True, (), "phiward: this prompt was not sent: it is too long to "
                           f"check (over {MAX_BYTES // (1 << 20)} MiB); send it in parts.")
        if cfg.problem:
            return _fail("the repo config (.phiward.toml) has a problem" if cfg.problem_detail
                         else "the phiward config has a problem")
        try:
            san = prompt_sanitizer(cfg)
        except sanitize.SanitizerError as exc:
            return _fail(f"the prompt check cannot be built: {exc}")
        return verdict_with(san, cfg, text, cwd)
    except Exception:  # noqa: BLE001 - fail closed on anything
        return _UNCHECKED


_UNCHECKED = Verdict(True, (), "phiward: this prompt was not sent: the check could not run; "
                     + DOCTOR)


# ---- the Claude Code adapter: `phiward prompt-scan claude` -------------------------------------

HELP = """usage: phiward prompt-scan claude   (reads the hook payload on stdin)

Options:
  -h, --help   show this help

Claude Code runs it as a UserPromptSubmit hook, before each prompt is sent; `phiward install
claude` writes the wiring. A prompt the sanitizer would change (a pack or [sanitize] patterns
match of the user config, or a path below a protected root) is not sent: the reply names the
kind, never the value. A clear prompt gets no output. Anything it cannot read is blocked.
"""
_UNREAD = ("phiward: this prompt was not sent: the hook payload could not be read; " + DOCTOR)


def _claude_verdict(raw: str) -> Verdict:
    payload = json.loads(raw)
    if not isinstance(payload, dict) or payload.get("hook_event_name") != "UserPromptSubmit" \
            or not isinstance(payload.get("prompt"), str) \
            or not isinstance(payload.get("cwd"), str) or not payload["cwd"].startswith("/"):
        return Verdict(True, (), _UNREAD)
    cwd = payload["cwd"]
    return prompt_verdict(payload["prompt"], config.load(cwd), cwd)


def main(argv: List[str]) -> int:
    if argv[:1] in (["-h"], ["--help"]):
        sys.stdout.write(HELP)
        return 0
    try:
        if argv != ["claude"]:
            v = Verdict(True, (), "phiward: usage: phiward prompt-scan claude; every prompt is "
                        "refused until the wiring is fixed (`phiward install claude`).")
        else:
            v = _claude_verdict(sys.stdin.read())
    except Exception:  # noqa: BLE001 - fail closed on anything
        v = Verdict(True, (), _UNREAD)
    if not v.blocked:
        return 0
    # stdout is never empty on a block: an exit 2 with an empty stdout from a plugin is no block
    sys.stdout.write(json.dumps({"decision": "block", "reason": v.why, "hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}}) + "\n")
    sys.stderr.write(v.why + "\n")
    return 2
