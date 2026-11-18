---
name: qa-check
description: "For work on phiward's own code: the checks before a commit or a release (ruff, the suite with the skip check, the Linux suites, build and twine, and for a release the quickstart and install checks), every exit code read."
---

# qa-check

Run them in this order. Read each exit code; never judge a check by a pipe (`pytest | tail`
exits with `tail`'s code). Redirect to a log, then test `$?`.

## Every commit

```bash
uvx ruff check --select F src tests;                 echo "ruff rc=$?"
uv run --quiet --with pytest --with pytest-timeout python -m pytest --timeout=300 -q \
  -p no:cacheprovider > /tmp/phiward-suite.log 2>&1; echo "suite rc=$?"; tail -3 /tmp/phiward-suite.log
```

- A test that skips must be listed in `tests/expected_skips_<platform>.txt`; CI fails on any
  other (`PHIWARD_CHECK_SKIPS=1`).
- A new test file goes into the index in `tests/README.md` (a test checks it).
- After an edit, run the checks again: they cover the tree they ran on.

## Before a merge (a maintainer's machine; CI covers Linux and macOS for others)

```bash
sh scripts/linux-check/check.sh                     # Python 3.12 and 3.9, two layouts, in Docker
```

## Before a release (a maintainer's machine)

```bash
uv build -o /tmp/phiward-dist . && uvx twine check --strict /tmp/phiward-dist/*
sh scripts/quickstart-check/check.sh                # 14 runs of a new user's setup, in Docker
sh scripts/quickstart-check/mac.sh WHEEL PYTHON     # macOS; PYTHON: uv's own python3
```

`sh scripts/sandbox-check/check.sh` runs the real Claude Code against phiward's settings, in a
home folder of its own. The maintainer runs it in their own terminal (it asks for their token);
an agent never runs it.

The release steps are in [docs/releasing.md](../../../docs/releasing.md).
