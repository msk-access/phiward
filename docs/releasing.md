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
5. Only then make the repository public, and turn on GitHub Pages: Settings, Pages, **Deploy from
   a branch**, `gh-pages`, `/ (root)`. The `docs` workflow publishes there with mike: `develop` as
   `dev`, each release tag as its version with the alias `stable`, which the site opens on.

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
   cannot show. You run it yourself, in a terminal: it asks only for a token from
   `claude setup-token`, pasted at its prompt (or `ANTHROPIC_API_KEY=KEY`), and builds the rest
   in a home folder of its own, with made-up data. It takes no token from the environment. An
   agent never runs it (it refuses without a terminal); an agent runs only
   `sh scripts/sandbox-check/linux.sh --stub`.
   It starts itself again under an empty environment first: only HOME, TMPDIR, TERM, your PATH
   (to find uv and claude; then it uses the system folders) and its own variables (SBX_*, MODES,
   KEEP, REMOTE*, CLAUDE_BIN) cross. The second start is clean: no variable, option or function
   of your shell acts on it. The first start is your shell's, and what it was given acts before
   the first line: under bash-as-sh, an exported `SHELLOPTS=xtrace` with a `PS4` that holds
   `$(...)` runs that command. Run it with `sh`, not `bash` (`bash check.sh` reads `BASH_ENV`).
   claude and uv, found through your PATH, must pass phiward's rule (`selfcheck.safe_path`)
   before the token prompt. Its programs run with its own home as HOME, in its own folder.
   `SBX_WHEEL` with `SBX_WHEEL_SHA256` installs a wheel you built beforehand instead of a build
   (see docs/hpc.md). uv's Python is found in
   `~/.local/share/uv/python`; give its path as an argument if yours is elsewhere.
   - `sh scripts/sandbox-check/check.sh` on macOS, and on a real Linux machine with
     `SBX_BASE` set (Landlock ABI 2 or newer for the gateway). SBX_BASE holds the check's
     folders; it may not be under /tmp or the temp folder, nor your home folder itself, nor
     anywhere the settings phiward installs let the session write (the check refuses). A
     folder below your home folder is fine. The check refuses SBX_BASE when it or any folder
     above it, your home folder too, holds `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`,
     `.claude`, `.git`, `.mcp.json`, `.phiward.toml` or `.agent-guards.toml`: Claude Code reads
     CLAUDE.md, CLAUDE.local.md and `.claude/rules` from every folder above the session's, and
     phiward the settings of every `.claude` or `.git` above it and its repository config, so
     your own would be read into the test. It looks again right before each session. Get the
     token first (`claude setup-token` may make `~/.claude` again), then move them away while
     the check runs, or choose another folder. On macOS it is `/Users/Shared` by default;
     without that folder, set SBX_BASE to another folder outside those (for example one you
     make for it on a second volume).
   - `SBX_TOOLS` names a folder for socat, when the system has none (a cluster). It may hold
     socat and nothing else, so it cannot stand in for `bwrap`, `git` or `sh`. The check puts
     it on the session's PATH after its own bin folders, before the system folders. It must be
     an absolute folder outside SBX_BASE and outside what the session may write, and pass
     phiward's own rule for a PATH folder: it, its socat (and what a link leads to) and every
     folder above them (up to your home folder, when they are inside it) are yours or root's,
     and no group or other account can write them. Else the check refuses, before the build.
   - On a cluster, the check's folders go below your home folder, the one place no other
     account can write a folder above it (scratch and group folders are writable by others, so
     phiward's self-check refuses phiward installed there). The steps are in
     [hpc.md](hpc.md#claude-code-on-the-login-node), at its end.
   - `sh scripts/sandbox-check/linux.sh` on a machine with Docker: the same check in a Linux
     container, with the Claude Code version that `scripts/sandbox-check/docker/package-lock.json`
     pins (`CLAUDE_VERSION=2.1.295` builds the lowest version phiward supports instead, unlocked).
   - Re-read "Permission mode on resume" in Claude Code's sessions docs. `launch` keeps
     transcripts on its word that a resumed bypass session starts in the mode a new one starts
     in. If a release restores bypass, `launch` must add `--permission-mode default` to a resume.

   Each runs one `claude -p` session per mode (`MODES`, default `A B`; Mode B runs under
   `phiward launch`), and with Mode A one more short session, the bypass probe: started with
   `--permission-mode bypassPermissions`, it Reads the protected file and runs `cat` on it.
   phiward must refuse both (the Read also by the deny rules `install` writes); the judge says
   `ok`, or `BAD` with one word (`leaked`, `hook-skipped`: FAIL; `no-session`, `no-read`,
   `no-cat`: INCONCLUSIVE). If it fails, the threat model must say that bypass skips the hook.
   Each session runs Haiku (or `SBX_MODEL=sonnet`, when Haiku declines the request) with a
   spending cap of $1 and a time limit. The session must be
   refused when it reads the protected file with the Read tool, and when a Bash command reads
   it, writes the data folder, `~/.phiward` or `~/.claude/settings.json`; `phiward run` from the
   session must mask its output, a commit of a made-up identifier must be refused by the git
   hook without showing it, the wrapped MCP server must start, and `doctor` must stay clean.
   For a write that worked, the report says whether the file reached the host (recorded right
   after each session). On Linux, in either mode, the sandbox may put an empty, writable view
   over a target it hides: a write that reaches nothing on the host is a note, not a failure,
   when the same session shows the target hidden: for the data folder, the read of the
   protected file found no such file, or not its content (an empty view); for `~/.phiward`, a
   sentinel there is missing; for the settings, they read as empty. Without that, it fails.
   That evidence shows the target hidden; what stops a real write is the record, right after
   each session, of whether the probe file is on the host (for the settings, their hash before
   and after). When `phiward run` fails in the session for another reason, the report notes one
   word for why (for example `no-broker` or `refused`), its exit code and an error class (for
   example `permission-denied` or `traceback`). When no word fits (`other`), it also notes the
   first line of the output, with each word that holds anything but letters (a digit, a path,
   an ID, a sign) shown as `<x>`; no other text of the output is kept. In Mode A, Claude
   Code's own refusal of the Read ("denied by your permission settings": the deny rules
   `install` writes) counts as a refusal. The session also reads the environment of every
   process it can see in `/proc`, and records only counts and PIDs: a credential variable's
   name in any of them fails the mode, and the report says how many of those processes are the
   session's own ancestors. The names are the list in `scripts/sandbox-check/token-names.txt`,
   taken from Claude Code's docs (code.claude.com/docs/en/env-vars and the authentication
   page). `CLAUDE_CODE_MESSAGING_TOKEN` is not on it: Claude Code gives it to Bash commands on
   purpose, so the report only notes how many processes hold it. No value passes through the
   probe's shell or reaches a file, also under `sh -x`: each environment is read once. A list with a CRLF line or a line that is not a name is
   refused whole (`scan-error`). A scan that read no non-empty environment, whose read failed
   (`scan-error`), or whose `/proc` is not the session's own (`foreign-proc`) is INCONCLUSIVE.
   So is a probe line that appears twice in the results, and a session that made anything
   other than exactly one Bash call, `sh ./probes.sh`.
   It ends with a verdict per mode and an overall `PASS`, `FAIL` or `INCONCLUSIVE`.
   With `REMOTE=HOST REMOTE_DIR=/abs/new/empty/folder` (on a real machine), it also pushes,
   runs, and pulls through your shared connection, which you start when it asks; it writes only
   under REMOTE_DIR and deletes nothing there: remove that folder yourself afterwards.
   `--stub` (a stand-in claude, no token) checks the plumbing only, and runs only in the
   container (`linux.sh --stub`): elsewhere `check.sh --stub` refuses, as it would plant a git
   hook and a home folder on your machine. (That refusal looks for the container's marks,
   `/.dockerenv` or SBX_IMAGE: a tripwire, not a gate.)
   Paste the token when the check asks; do not export it. A token exported in your shell is
   not used (the check starts again without it), and only the claude process gets the pasted
   one. `/proc` still keeps the start environment of your shell and of the check's first start,
   which the session's scan can see: such a run may FAIL for them, and the check warns. The check's home folder and its judge's folder are removed at the end, also
   after Ctrl-C, SIGTERM or a closed terminal; if one cannot be removed, the check names it and
   exits non-zero. A `kill -9` of `check.sh` or `launch.py` skips that: the session may keep
   running, and the folders stay (remove them yourself). Only the report and, per mode, the
   stream and the facts are kept, redacted in memory: with `KEEP=1` in a folder of their own
   (`phiward-sbx-kept-*` next to it), and with `linux.sh` in its output folder. If the token's
   value is still in any of them, nothing is kept ("redaction failed: nothing kept").
   A process the session starts in a session of its own (`setsid`) can outlive the check; its
   folders are removed all the same, so nothing it writes is kept.
   The stream reaches `launch.py` through a pipe, and `launch.py` writes it, after the session
   is stopped, into the judge's folder: next to the home folder, outside the folders the check
   gives the session. The check does not prove that the sandbox cannot write there; a process
   left running in a session of its own could, before the judge reads it.
   On Linux too the wrapped MCP server must start in Mode B: its launch inside the session runs
   it directly (the session's seccomp fingerprint). A server that does not start leaves the mode
   INCONCLUSIVE, as on macOS.
   What the session writes in its project folder (`results.txt`, `server.out`) a model could
   forge, line by line. The checks made outside the session are harder to forge: a probe's file
   on the host, the settings file's hash, the marker or the token in the stream, and the
   transcript's tool calls (with the limit above). Read a PASS with that in mind.
   Run the real check when phiward's Claude Code wiring (`install.py`, `claude_settings.py`,
   `fasthook.py`, `mcp.py`, `wholetool.py`) or the lowest Claude Code version it supports
   changed since the last release; otherwise skip it.
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
