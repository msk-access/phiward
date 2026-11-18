# Releasing phiward

For maintainers. A release is a git tag; the `release` workflow builds the package, checks it,
and publishes it to PyPI. No PyPI token is stored anywhere: PyPI trusts the workflow through
trusted publishing (OpenID Connect).

## Once: connect PyPI to the repository

As an owner of the msk-access PyPI account, in a browser:
on PyPI, open **Your account → Publishing → Add a new pending publisher** (for the first
release; after that, the project's own **Settings → Publishing**), and enter:
- PyPI project name: `phiward`
- Owner: `msk-access`
- Repository name: `phiward`
- Workflow name: `release.yml`
- Environment name: leave it empty. The publish job runs in no GitHub environment, as in gbcms
  and krewlyzer: a pushed tag publishes once the tests and checks pass.

A pending publisher does not reserve the name: the first publish creates the project. So
**publish the first release before the repository is public**: until then, anyone could take
the name, and the install line in these docs would install their package. Trusted publishing
works from a private repository.

## The first release

1. Create `msk-access/phiward` as a **private** repository and push `main` and `develop`.
2. Add the pending publisher (above).
3. Push the tag (below). The workflow tests, builds and publishes.
4. Check https://pypi.org/project/phiward/ and the install line.
5. Only then make the repository public.

## Each release

The repository uses git-flow (`gitflow.prefix.versiontag` is `v`): start with
`git flow release start 0.2.0b2` from `develop`, make the changes below on that branch, and
`git flow release finish 0.2.0b2` merges it into `main` and `develop` and makes the tag `v0.2.0b2`.
Then push `main`, `develop` and the tag.

1. Set the version: `__version__` in `src/phiward/__init__.py` (the package and
   `phiward --version` take it from there), and the same in `plugin/.claude-plugin/plugin.json`
   and `.claude-plugin/marketplace.json`. A test fails when they disagree, and the workflow
   refuses a tag that names another version. PyPI's form has no `v`: `0.2.0b1`; the tag has
   it: `v0.2.0b1`. Change the install lines in the docs (`phiward==0.2.0b1`) too.
2. In `CHANGELOG.md`, replace "unreleased" with the date (UTC), and write the release notes in
   `docs/release-notes/`.
3. Run the full test suite on macOS ([tests/README.md](https://github.com/msk-access/phiward/blob/v0.2.0b1/tests/README.md) says how) and on
   Linux (`sh scripts/linux-check/check.sh`, needs Docker: Python 3.12 and 3.9, two layouts,
   on a `git archive` of HEAD), and the quickstart in clean Linux containers
   (`sh scripts/quickstart-check/check.sh`, needs Docker; its image is built fresh, and
   `--quick` runs four plain runs on the cached one while you work): a new user's steps, with
   umask 022 and 002, must end with no doctor WARNING and a wrapped MCP server. On macOS, run
   `sh scripts/quickstart-check/mac.sh WHEEL PYTHON` with uv's or Homebrew's `python3` (a home
   folder of its own, no login service).
   Then check that the real Claude Code obeys the settings phiward writes, which the scripts above
   cannot show: `sh scripts/sandbox-check/check.sh` (macOS; it asks only for a token from
   `claude setup-token` and builds the rest in a home folder of its own, with made-up data). In a
   `claude -p` session there, a Bash command that reads a protected file, writes `~/.phiward` or
   writes `~/.claude/settings.json` must fail, and a wrapped MCP server must start. Run it when
   phiward's Claude Code wiring (`install.py`, `claude_settings.py`, `fasthook.py`, `mcp.py`) or
   the lowest Claude Code version it supports changed since the last release; otherwise skip it.
4. Commit and tag: `git flow release finish` does both; the first release is tagged by hand on
   `main`. Then push the tag:

   ```bash
   git tag -a v0.2.0b1 -m "phiward v0.2.0b1"
   ```

   ```bash
   git push origin v0.2.0b1
   ```

5. The `release` workflow runs the whole test suite (macOS and Linux, Python 3.9 to 3.14),
   checks that the tag names the version everywhere, builds the wheel and the source archive,
   checks them (`twine check --strict`), installs the wheel and runs it. Only then does the
   publish job start; nothing waits for an approval, so push the tag only when the release is
   ready. Its actions are pinned by commit; update a pin by its release's commit, not a tag.
6. After it is published, check the install line from a clean shell:

   ```bash
   uv tool install --python-preference only-managed phiward==0.2.0b1
   ```

7. Make the GitHub release from the tag, with the release notes.

A version on PyPI can be yanked but never replaced: a fix is a new version.
