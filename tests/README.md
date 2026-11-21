# The tests

Every test uses made-up folder trees with obviously fake identifiers (`FAKE-PT-0001`,
`SECRET-CONTENT-0001`); nothing reads a real config or real data. `conftest.py` makes the trees
and the fixtures (`tree`, `broker`, `launchers`, `home`); `helpers.py` holds the shared helpers
(`CONFINE_WHY`, `needs_confine`, `protect`, `gone`, `ready_line`, `write_file`...).

## Running them

```bash
uv run --with pytest --with pytest-timeout python -m pytest --timeout=300
```

- `-m "not slow"`: the quick loop; it leaves out the cost and property tests over many entries
  (marked `slow`). Every full run and CI run them.
- A test that needs the kernel sandbox (macOS `sandbox-exec`, Linux `bwrap`) skips without one;
  with `PHIWARD_REQUIRE_CONFINE=1` (CI) a missing backend fails the run instead.
- `PHIWARD_CHECK_SKIPS=1` (CI) fails the run on a skip not listed in
  `expected_skips_<platform>.txt`; `PHIWARD_WRITE_SKIPS=FILE` writes this run's skips.
- Linux in Docker, two Python versions and two layouts: `docs/releasing.md`.

## Where a feature is tested

Many files are named after the review round that found what they test; a file's docstring
says what it holds. By feature:

| Feature | Files |
|---|---|
| The config | test_config, test_v2_rename |
| The hook: protected paths in shell and file tools | test_protected_paths, test_v2_p0a, test_v2_p0a2, test_v2_p0a3, test_v2_p0a4, test_v2_round8, test_v2_round9, test_v2_round10, test_v2_round11, test_v2_round12, test_v2_round13, test_v2_round14, test_v2_round15, test_v2_round16, test_v2_round17, test_v2_properties, test_v2_fuzz, test_v2_usability, test_v2_final_review, test_v2_release18, test_v2_release18d, test_v2_release18f |
| Globs | test_v2_glob_cases |
| Credentials and other hidden places | test_v2_hidden, test_v2_modes |
| Claude Code's sandbox settings and confinement | test_install_and_sandbox, test_v2_part2, test_v2_part3, test_v2_part6, test_v2_sandbox_boundary, test_v2_reason_steps, test_v2_steps_match_install, test_v2_records_place, test_v2_launch_settings, test_v2_old_settings, test_v2_network |
| Tools other than Bash (MCP tools, Copilot) | test_v2_tool_rule, test_v2_shell_names, test_v2_refusal_words, test_v2_mcp_source |
| MCP: wrap, list, launch records, launcher | test_v2_mcp_wrap, test_v2_mcp_wrap_cmd, test_v2_wrap_shared, test_v2_backups, test_v2_entry_id, test_v2_one_answer, test_v2_one_wrapped, test_v2_twin_count, test_v2_launch_records, test_v2_launcher_identity, test_v2_launcher_owner, test_v2_launcher_path, test_v2_path_risk, test_v2_attacks, test_v2_review_round3, test_v2_review_round4 |
| The gateway and the broker | test_confinement, test_round2, test_round3, test_round4, test_round5, test_v2_broker_path_writable, test_v2_speed, test_v2_probe_bugs, test_v2_release_review, test_v2_placeholder_counts, test_v2_gateway_places |
| HPC: remote runs and pushes | test_v2_remote, test_v2_push |
| `phiward copy`: local paths resolved once | test_v2_copy_paths |
| `phiward pseudonymize` (codes, the key folder hidden also when made later, the places, the messages; the kinds, gzip and BGZF, MAF, VCF, JSON, Markdown, the scan of the output) | test_pseudonymize, test_pseudonymize_formats |
| The sanitizer | test_sanitize, test_columns, test_v2_dates, test_v2_id_names, test_v2_subjects |
| `launch` (the whole tool in the kernel profile) | test_v2_w1, test_v2_w1b, test_v2_r1, test_v2_r1b, test_v2_view, test_v2_launch_races, test_v2_beta |
| A launch inside a session (a wrapped MCP server in Mode B; the Linux seccomp fingerprint) | test_v2_nested_launch, test_v2_w1 |
| Carry-over | test_v2_carryover, test_v2_s17, test_v2_old_glibc |
| phiward's own Python (the self-check) | test_v2_selfcheck, test_v2_full_check, test_v2_fault_place, test_v2_one_rule, test_v2_python_reads, test_v2_round7, test_v2_release8, test_v2_release9, test_v2_release10, test_v2_release11, test_v2_release12, test_v2_release13, test_v2_release14, test_v2_release16 |
| `doctor`, `setup`, `init`, onboarding | test_v2_doctor_first, test_v2_onboard, test_copy_and_adapter, test_v2_note_service, test_v2_review_final |
| Unattended agents (headless, the SDK) | test_v2_unattended |
| Git hooks | test_githooks |
| The docs' links and anchors, and the docs the code names | test_docs_links |
| The command reference (docs/cli.md) against each command's help | test_docs_cli |
| The threat model's limit anchors against tests/limit_ids.txt | test_docs_limits |
| The agent harness (AGENTS.md, .agents, .claude) | test_harness |
| The judge of the real Claude Code check (scripts/sandbox-check: per platform and mode, the facts, the token redaction) | test_sandbox_check_judge |
| Fixes from the first CI runs on GitHub (bubblewrap mounts, two launches at once, deep scratch folders) | test_v2_github_ci |
