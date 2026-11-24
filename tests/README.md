# The tests

Every test uses made-up folder trees with obviously fake identifiers (`FAKE-PT-0001`,
`SECRET-CONTENT-0001`); nothing reads a real config or real data. `conftest.py` makes the trees
and the fixtures (`tree`, `broker`, `launchers`, `home`); `helpers.py` holds the shared helpers
(`CONFINE_WHY`, `needs_confine`, `protect`, `gone`, `ready_line`, `write_file`...).

## Running them

```bash
uv run --with pytest --with pytest-timeout python -m pytest --timeout=300 \
  --basetemp=/tmp/phiward-pt
```

- `--basetemp` (macOS): the made-up trees go outside the per-user temp folder, as in CI. That
  folder is a session's write place, so launch would refuse the made-up Claude Code there. Not
  under your home folder either: a `.claude` there makes every tree a project. pytest empties
  the folder on each run. (On Linux a session replaces `/tmp`; CI uses `$RUNNER_TEMP`.)

- `-m "not slow"`: the quick loop; it leaves out the cost and property tests over many entries
  (marked `slow`). Every full run and CI run them.
- A test that needs the kernel sandbox (macOS `sandbox-exec`, Linux `bwrap`) skips without one;
  with `PHIWARD_REQUIRE_CONFINE=1` (CI) a missing backend fails the run instead.
- `PHIWARD_CHECK_SKIPS=1` (CI) fails the run on a skip not listed in
  `expected_skips_<platform>.txt`; `PHIWARD_WRITE_SKIPS=FILE` writes this run's skips.
- Linux in Docker, two Python versions and two layouts: `docs/releasing.md`.
- The renv test of test_v2_runs_later needs `Rscript`, renv and bubblewrap, so it skips in CI
  and in `scripts/linux-check`. Run it in a Linux container that
  has them (Ubuntu 24.04: `apt-get install python3-venv bubblewrap r-base-core r-cran-renv`),
  with `PHIWARD_REQUIRE_CONFINE=1`, before a change to launch's list ships.

## Where a feature is tested

Many files are named after the review round that found what they test; a file's docstring
says what it holds. By feature:

| Feature | Files |
|---|---|
| The config | test_config, test_v2_rename |
| The hook: protected paths in shell and file tools | test_protected_paths, test_v2_p0a, test_v2_p0a2, test_v2_p0a3, test_v2_p0a4, test_v2_round8, test_v2_round9, test_v2_round10, test_v2_round11, test_v2_round12, test_v2_round13, test_v2_round14, test_v2_round15, test_v2_round16, test_v2_round17, test_v2_properties, test_v2_fuzz, test_v2_usability, test_v2_final_review, test_v2_release18, test_v2_release18d, test_v2_release18f |
| Globs | test_v2_glob_cases |
| Credentials and other hidden places | test_v2_hidden, test_v2_modes |
| Claude Code's sandbox settings and confinement | test_install_and_sandbox, test_v2_part2, test_v2_part3, test_v2_part6, test_v2_sandbox_boundary, test_v2_reason_steps, test_v2_steps_match_install, test_v2_excluded_per_call, test_v2_no_phi, test_v2_records_place, test_v2_launch_settings, test_v2_old_settings, test_v2_network, test_v2_file_mentions |
| The hooks phiward writes, run from files in the package (the script, its variable list, `entry.py`, the plugin's copies, old entries replaced, doctor's notes, launch's Claude Code floor on macOS) | test_hooks_from_files |
| Tools other than Bash (MCP tools, Copilot) | test_v2_tool_rule, test_v2_shell_names, test_v2_refusal_words, test_v2_mcp_source |
| MCP: wrap, list, launch records, launcher | test_v2_mcp_wrap, test_v2_mcp_wrap_cmd, test_v2_wrap_shared, test_v2_backups, test_v2_entry_id, test_v2_one_answer, test_v2_one_wrapped, test_v2_twin_count, test_v2_launch_records, test_v2_launcher_identity, test_v2_launcher_owner, test_v2_launcher_path, test_v2_path_risk, test_v2_attacks, test_v2_review_round3, test_v2_review_round4 |
| The gateway and the broker | test_confinement, test_round2, test_round3, test_round4, test_round5, test_v2_broker_path_writable, test_v2_speed, test_v2_probe_bugs, test_v2_release_review, test_v2_placeholder_counts, test_v2_gateway_places, test_macos_gateway_profile_file, test_macos_inline_code |
| HPC: remote runs and pushes; copy run from files | test_v2_remote, test_v2_push, test_macos_copy_from_files |
| `phiward copy`: local paths resolved once | test_v2_copy_paths |
| `phiward pseudonymize` (codes, the key folder hidden also when made later, the places, the messages; the kinds, gzip and BGZF, MAF, VCF, JSON, Markdown, the scan of the output) | test_pseudonymize, test_pseudonymize_formats |
| The prompt scan (the core, `prompt-scan claude`, the wiring in both modes, doctor, the corpus of ordinary prompts, speed) | test_promptscan |
| The masking check (`[sanitize] examples` and the roots, at doctor, launch and the broker's start; the prompt scan's build and check) | test_phicheck |
| The leak test for typical sessions: a scripted session (`data/leak_session.jsonl`, stream-json shape) replayed through the session note, the prompt scan, the hook, the gateway and `phiward mcp`, in Mode A with two configs and under launch (Linux; `notes.md` allowed by `[sanitize] scan_allow`); planted values (`leak_values.py`) checked by kind and place; a control session; faults made through the config; launch refused by the project scan for the `notes.md` plant. The driver is `leak_session.py`. Not covered (the test's docstring, and the threat model's `known-leak-test`): `CLAUDE.md` and other instruction files, the git status in the system prompt, `!` commands, MCP servers that are not wrapped, compaction, Claude Code's own sandbox in Mode A, IDs in project files outside the roots in Mode A (sent; the note warns), and Claude Code's own file tools (the replay's Read, Grep and Glob are models of them) | test_leak_typical |
| The project scan (subject rules only, the walk without git, what is read and skipped, `[sanitize] scan_allow`, launch, doctor and `--headless`, the SessionStart note, never the matched text, speed on a large made-up project) | test_projectscan |
| The sanitizer | test_sanitize, test_columns, test_v2_dates, test_v2_id_names, test_v2_subjects, test_entry_spellings |
| `launch` (the whole tool in the kernel profile) | test_v2_w1, test_v2_w1b, test_v2_r1, test_v2_r1b, test_v2_view, test_v2_launch_races, test_v2_beta, test_macos_profile_mount_jobs, test_macos_launch_no_helper |
| `launch`'s `[launch] write_to` folders (the key, the start checks and refusals, a missing entry, the read-only rules per folder on macOS and Linux, the shared scan budget, the start line, the end report, doctor, SIGHUP and SIGTERM, the record of an unfinished session, the broker's PATH filter and pseudonymize, `--add-dir`) | test_launch_write_to |
| `launch --tool claude` and the operator's `--settings`: the file `install` writes is accepted by its content; one that says more or other, or does not parse, is refused | test_launch_install_settings |
| `launch`'s network: the proxy (token, the address check, an upstream proxy, limits, refusals that name `[launch] private_networks` and the list at exit), the macOS profile's one port, Linux's network namespace and relay, the `ANTHROPIC_BASE_URL` check at start | test_v2_launch_network |
| `launch`'s start step for a project folder on `PATH` (an activated `.venv`) | test_v2_launch_path_step |
| `launch`'s refusal of an empty or relative `PATH` entry (`::`, a leading or trailing `:`, `.`, `bin`), in doctor and for `[launch] write_to` | test_launch_path_relative |
| The one-line step of each typical refusal, doctor's launch section, the session note's limits, doctor's Mode A notes (package caches, Grep above a root, programs not on the broker's PATH) | test_v2_refusal_next_steps |
| Kept transcripts under `launch` (`--resume`, `-c`, `[launch] keep_transcripts`: the folder name, out at the end and in at the start, the merge, the cap, links and left-out names) | test_v2_launch_resume |
| Unix sockets under `launch` on Linux (Landlock ABI 9; below it Claude Code's seccomp filter for `--tool claude`, and no unix sockets for other tools). `conftest.py` plants a made-up native Claude Code that runs as Python (`helpers.tool_py`) | test_v2_launch_sockets, test_v2_nested_launch |
| Files that other tools run later (read-only under `launch` for the tool and a wrapped server, at any depth, with link targets; Mode A's nested `.vscode` and `.idea` on macOS; the network limit's exact host list; renv under `launch`, Linux with R) | test_v2_runs_later |
| A launch inside a session (a wrapped MCP server in Mode B; the Linux seccomp fingerprint) | test_v2_nested_launch, test_v2_w1 |
| Carry-over | test_v2_carryover, test_v2_s17, test_v2_old_glibc |
| phiward's own Python (the self-check) | test_v2_selfcheck, test_v2_full_check, test_v2_fault_place, test_v2_one_rule, test_v2_python_reads, test_v2_round7, test_v2_release8, test_v2_release9, test_v2_release10, test_v2_release11, test_v2_release12, test_v2_release13, test_v2_release14, test_v2_release16 |
| `doctor`, `setup`, `init`, onboarding | test_v2_doctor_first, test_v2_onboard, test_copy_and_adapter, test_v2_note_service, test_v2_review_final |
| Unattended agents (headless, the SDK) | test_v2_unattended |
| Git hooks | test_githooks |
| The docs' links and anchors, and the docs the code names | test_docs_links |
| The command reference (docs/cli.md) against each command's help | test_docs_cli |
| The refusals page (docs/refusals.md) against the messages it quotes | test_docs_refusals |
| The configuration table (docs/configuration.md) against the loader's keys | test_docs_config |
| The threat model's limit anchors against tests/limit_ids.txt | test_docs_limits |
| The page for security teams (docs/endpoint-security.md): its command lines and regexes, and on macOS every process phiward starts, recorded and checked against the rule and the page | test_docs_endpoint_security, test_macos_processes |
| The agent harness (AGENTS.md, .agents, .claude) | test_harness |
| The judge of the real Claude Code check (scripts/sandbox-check: per platform and mode, the facts, the token redaction) | test_sandbox_check_judge |
| Fixes from the first CI runs on GitHub (bubblewrap mounts, two launches at once, deep scratch folders) | test_v2_github_ci |
