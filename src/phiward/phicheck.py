"""The masking check: the user's own rules still mask their made-up examples, and a made-up path
below each root still comes out masked.

What fails closed already (a pack file that does not load, a regex that does not compile) needs
no check. This one finds rules and roots that load but no longer mask: a pattern edited so that
it misses its IDs, a pack file whose rules were weakened, a root the sanitizer does not match as
written. Doctor warns, launch refuses, and the broker refuses every request while it fails.

The examples come from `[sanitize] examples` in the user config, never from the regex (such an
example only proves that the regex matches itself). The built-in packs are not tested here: the
self-check covers phiward's installed files. What the check says names indexes, counts and
placeholders only, never an example, a pattern, a pack path, a root or matched text.
"""

import dataclasses
import re
from typing import List, NamedTuple, Tuple

from phiward import config, pathmatch, promptscan, sanitize

CANARY = "FAKE-CANARY-0001.txt"
WILD = "fakecanary"


class Result(NamedTuple):
    failed: List[str]  # each a reason in phiward's own words; empty when the check passes
    notes: List[str]  # rules and patterns that are not tested
    summary: str  # the ok line, or a count of the failures


def fully_masked(out: str) -> bool:
    """Whether `out`, the cleaned form of `x VALUE y`, keeps nothing of the value: it is withheld,
    or once its placeholders are taken out, no letter or digit is left between `x ` and ` y`
    (a path mask may run to the end of the line, taking ` y` with it)."""
    if out == sanitize.WITHHELD:
        return True
    rest = sanitize._PLACEHOLDER.sub("", out)
    if not rest.startswith("x "):
        return False
    rest = rest[2:]
    if rest.endswith(" y"):
        rest = rest[:-2]
    return not any(ch.isalnum() for ch in rest)


def value_masked(san: sanitize.Sanitizer, value: str, table: bool = True) -> bool:
    """Whether `san` fully masks `value` in a line of text, and also in table mode."""
    line = f"x {value} y"
    modes = (False, True) if table else (False,)
    return all(fully_masked(san.clean(line, table=t)) for t in modes)


def _user_rules(cfg: config.Config) -> List[Tuple[str, "re.Pattern[str]"]]:
    """The user's own rules, each with its label: `[sanitize] patterns`, then the paths and
    identifiers rules of each pack file, in order."""
    rules = [(f"[sanitize] patterns entry {i}",
              re.compile(sanitize.parse_rule(v, "[sanitize] patterns")[0].pattern, re.I))
             for i, v in enumerate(cfg.sanitize_patterns, 1)]
    files = [p for p in cfg.user_packs if "/" in p]
    for j, name in enumerate(files, 1):
        pack = sanitize.load_pack(name)
        rules += [(f"pack file {j}, rule {k}", rx)
                  for k, (rx, _r) in enumerate(pack.paths + pack.identifiers, 1)]
    return rules


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _check(cfg: config.Config, cwd: str) -> Result:
    from phiward.run import add_remote_roots
    try:
        # the gateway's form, less the names files (they would hide a rule that misses)
        gate = sanitize.Sanitizer.from_config(dataclasses.replace(cfg, names_from=[]))
        add_remote_roots(gate, cfg)
        prompt = promptscan.prompt_sanitizer(cfg)
        rules = _user_rules(cfg)
    except sanitize.SanitizerError:
        return Result(["the check could not run (the sanitizer cannot be built)"], [],
                      "masking check: 1 problem")
    failed: List[str] = []
    notes: List[str] = []

    def blocked(text: str) -> bool:
        return promptscan.verdict_with(prompt, cfg, text, cwd).blocked

    for i, v in enumerate(cfg.sanitize_examples, 1):
        if not value_masked(gate, v):
            hits = [label for label, rx in rules if rx.search(v)]
            failed.append(f"[sanitize] examples entry {i} is not fully masked " + (
                f"(it is matched by {', '.join(hits)}: widen that rule)" if hits else
                "(no rule of yours matches it: an edit may have broken a [sanitize] patterns "
                "rule or a pack file)"))
        elif not blocked(f"x {v} y"):
            failed.append(f"[sanitize] examples entry {i} is not blocked by the prompt scan")
    tested = 0
    for label, rx in rules:
        if any(rx.search(v) for v in cfg.sanitize_examples):
            tested += 1
        else:
            notes.append(f"{label} matches no entry of [sanitize] examples, so it is not tested")
    places: List[Tuple[str, str]] = [(f"protected root {i}", r)
                                     for i, r in enumerate(cfg.roots, 1)]
    for i, p in enumerate(cfg.patterns, 1):
        folder = p.replace("*", WILD)
        if pathmatch.match_path(p, folder):
            places.append((f"protected pattern {i}", folder))
        else:
            notes.append(f"protected pattern {i} is not tested")
    places += [(f"remote root {i}", r) for i, r in enumerate(cfg.remote_roots, 1)]
    for label, folder in places:
        path = f"{folder}/{CANARY}"
        # positions are text mode only, so a path is checked in text mode only
        if not value_masked(gate, path, table=False) or not blocked(path):
            hint = (" (write the remote's absolute path)"
                    if label.startswith("remote") and not folder.startswith("/") else "")
            failed.append(f"a made-up path below {label} came out unmasked{hint}")
    if failed:
        return Result(failed, notes, f"masking check: {_plural(len(failed), 'problem')}")
    what = ([_plural(len(cfg.sanitize_examples), "example")] if cfg.sanitize_examples else []) \
        + [_plural(len(places), "root")]
    mine = f"{tested} of {len(rules)} rules tested" if rules else "no rules of your own"
    return Result([], notes, f"masking check: ok ({', '.join(what)}; {mine})")


def check(cfg: config.Config, cwd: str) -> Result:
    """The masking check of `cfg` (the effective config), from the folder `cwd`. Never raises:
    anything it cannot decide is a failure."""
    try:
        return _check(cfg, cwd)
    except Exception:  # noqa: BLE001 - fail closed on anything
        return Result(["the check could not run"], [], "masking check: 1 problem")
