# Security boundary inventory

This inventory separates implemented controls, executable evidence and unfinished promises.
It covers the threat model in `ref/Hamster-Ball-Design.md`, sections 2 and 5 through 12.
An allowed destination can receive any data the agent can read; domain filtering is not content inspection.

## Evidence rules

- `paired`: named rejection and permissive-control tests exist; this is not a claim that every platform or attack variant was tested.
- `partial`: a relevant test exists but its control, mutation sensitivity or breadth remains pending under the named owner.
- `pending`: the guarantee is not established; the named bead owns the missing work.
- `unsupported`: outside the current contract, not a disguised passing result.

Test function names below identify source locations; intermediate private module names may be omitted.
A `paired` label describes source evidence, not a completed independent audit of that control.
`hb-8en` must verify each pair's sensitivity before the release assurance claim.
File paths are relative to the repository root.
Run commands and actual pass/fail/skip counts belong in bead notes, not this table.
For new regressions, a removed-control mutation must compile and reach the intended assertion before it counts as caught.
Timeouts, compiler errors, missing helpers and unavailable sandbox facilities are harness failures, not successful denials.
`HB_REQUIRE_SANDBOX=1` makes unavailable Seatbelt a failure instead of an early-return skip.

## Approval and configuration

| ID / design | Attack and control | Rejection evidence | Permissive control | Status / owner |
| --- | --- | --- | --- | --- |
| A01 / §5 | Run changed config under old approval; hash loaded closure bytes | `tests/approval_cli.rs::a_config_changed_after_approval_is_exit_78_again_and_the_message_names_the_file` | `an_approved_config_runs_without_a_question_and_the_childs_exit_code_comes_back` in same file | paired |
| A02 / §5 | Approve through piped input; require interactive terminal | `tests/approval_cli.rs::a_yes_piped_into_hb_approve_is_not_an_approval_even_with_a_terminal_for_the_output` | `a_yes_at_the_terminal_approves_and_the_next_run_needs_no_terminal` | paired |
| A03 / §5 | Read/list/modify approval store; overwrite or rename project config; floor rules | `tests/approval_cli.rs::the_agent_cannot_read_list_or_change_the_approval_store_or_its_own_config` | Outside-ball cat/ls of store plus in-ball project write/rename/read/delete | paired for tested operations; independent release audit hb-8en |
| A04 / §5 | Replace approved closure path with identical bytes elsewhere; path-bound fingerprint | `tests/security_boundaries.rs::identical_closure_bytes_do_not_allow_a_symlink_replacement` | Approved regular closure executes before replacement | paired: no-follow removal caught in hb-dvf |
| A05 / §5 | Race changed bytes between approval and execution; use same loaded snapshot | `tests/security_boundaries.rs::loaded_policy_and_approval_keep_the_same_snapshot_after_disk_replacement` | Newly approved policy reads exact canary | paired at library load/approval/run seam; disk-reread mutation caught in hb-dvf |
| A06 / §5 | Hostile approval record symlink, size or owner; bounded no-follow store | `src/approval/store.rs` unit suite | Valid approval record roundtrip in same suite | partial: full adversarial store review, hb-8en |
| A07 / §5 | Replace built-in preset or owner base outside sandbox | Owner installation and unsandboxed owner files are trusted, not approval-hashed project inputs | Not applicable | unsupported: trusted owner boundary |
| A08 / §5 | File diff hides semantic expansion; byte approval is not permission diff | Current format-1 approval | No semantic snapshot contract yet | pending: hb-wlm |
| A09 / §4, §6 | Project loosens base deny/floor or selects stronger mode | Existing merge/floor unit suites; `tests/secrets_guard.rs::a_template_name_does_not_reopen_the_projects_own_denies` | Allowed sibling file | partial: generated-capability ceilings, hb-0af |

## Filesystem and executable state

| ID / design | Attack and control | Rejection evidence | Permissive control | Status / owner |
| --- | --- | --- | --- | --- |
| F01 / §2, §6 | Read credential/personal directories; floor denies override broad grants | `tests/probe_matrix.rs::credential_and_personal_directories_cannot_be_read_by_any_tool_while_the_project_can` | Project reads in same test | paired |
| F02 / §6 | Plant shell/PATH startup code; write-deny floor | `tests/probe_matrix.rs::the_floor_keeps_the_path_directories_and_shell_startup_unwritable_beside_writable_siblings` | Writable siblings in same test | paired |
| F03 / §4, §6 | Bypass path rules through case, Unicode or symlink spelling | `tests/probe_matrix.rs::a_case_variant_of_a_floor_path_is_denied_and_one_of_an_allowed_path_is_not`; `an_nfd_spelling_of_a_name_is_the_same_directory_for_a_grant_and_for_a_deny` | Allowed path variants in the same tests | paired |
| F04 / §8 | Read or rename secret files into readable locations; secret patterns and parent pins | `tests/secrets_guard.rs::rename_copy_link_symlink_delete_overwrite_and_create_are_all_refused`; `a_secret_cannot_be_given_a_template_name_or_read_under_one` | `templates_and_source_files_stay_readable_and_editable` | paired |
| F05 / §8 | Force-add secrets to change tracked-file exemption; Git metadata protection | `tests/secrets_guard.rs::git_add_force_of_a_secret_is_refused` | `git_tracked_files_are_left_readable_and_untracked_ones_are_not` | paired for covered project Git metadata, not arbitrary Git configurations |
| F06 / §8 | Project enables secret exceptions; owner-only parsing | `tests/secrets_guard.rs::an_exception_in_a_project_file_is_refused` | `an_exception_in_the_user_base_reopens_exactly_what_it_names` | paired |
| F07 / §8 | Move secret directory into exempt dependency tree | `tests/secrets_guard.rs::a_secret_directory_cannot_be_moved_into_a_dependency_directory_to_be_read` | `key_and_certificate_files_in_dependency_directories_are_usable` | paired |
| F08 / §2, §8 | Plant nested/worktree/global/include-based Git hooks for host execution | Existing local survey is advisory and incomplete | No complete effective-config guarantee | pending: hb-9ox; do not run host Git as a remediation |
| F09 / §10 | Poison persistent hb cache for another run or warm operation | Cache is separate from user npm/uv cache but is run-writable; `tests/executable_state.rs::a_run_that_is_not_granted_hbs_cache_cannot_plant_in_it` shows a run with no declared server cannot plant | `tests/executable_state.rs::a_planted_tool_in_hbs_cache_runs_in_another_projects_ball` (poisoning proven across projects; the consumer is a fake `uvx`, so real uv/npm reuse of a tampered entry is unmeasured) | partial: poisoning proven, isolation pending hb-dai |
| F10 / §10, §13 | Modify agent plugins/hooks/settings later executed outside confinement | `tests/executable_state.rs::a_deny_write_on_claude_settings_stops_the_plant_and_the_hook`; `a_deny_write_on_kiros_run_directory_keeps_the_linked_program` (both use an owner `deny_write` added to the preset; the shipped presets do not have it) | `a_hook_planted_in_claude_settings_runs_in_a_later_outside_loader` (stand-in loader, not real claude); versioned inventory and drift gates in the same file | partial: poisoning proven for claude settings; the fix is hb-82i; unmeasured triggers listed in hb-tx4 notes |
| F14 / §10 | Write through a hard link that a PATH program shares with a path in a write grant (kiro `run/chat-cli-<v>`) | `a_deny_write_on_kiros_run_directory_keeps_the_linked_program` | `a_write_through_kiros_hard_linked_run_copy_changes_the_program` (a shell script replaces the Mach-O; the exec of the fixture program path is real) | partial: shipped kiro preset does not deny `run/`; owner hb-82i |
| F11 / §10 | Bypass offline launcher with absolute tool path | `tests/offline_launchers.rs::a_call_by_absolute_path_and_a_run_without_a_server_are_unchanged` | Absolute invocation intentionally untouched | unsupported: wrapper is not network enforcement; proxy policy still applies |
| F12 / §10 | Declared uvx/npx launch omits offline/cache options | `tests/offline_launchers.rs::with_a_declared_server_uvx_and_npx_run_offline_from_hbs_cache_for_that_call_only` | Absolute/no-server invocation above | paired for argv wiring, not package integrity |
| F13 / §10 | Unpinned package resolves differently or initialize executes malicious code | MCP initialize success proves protocol readiness only | Real MCP suite is opt-in and version-dependent | unsupported: no package integrity/benign-code guarantee; diagnostics owned by hb-pdz |

## Processes, environment and terminal

| ID / design | Attack and control | Rejection evidence | Permissive control | Status / owner |
| --- | --- | --- | --- | --- |
| P01 / §7.2 | Read secret through inherited launcher FD; CLI closes descriptors above 2 | `tests/session_run.rs::a_descriptor_the_launcher_left_open_reaches_the_child_unless_hb_closes_it_at_start` | Same test deliberately keeps FD 3 and reads canary | paired |
| P02 / §7.2 | Descriptors leak into privileged broker subprocesses | `tests/ctl_broker.rs::inherited_secret_descriptor_does_not_reach_the_host_broker_command` | Same fake tool reads FD 3 outside hb | paired for launcher FD 3/testdrive; broker-internal descriptors remain partial, hb-8en |
| P03 / §7.2 | Parent token/env/PATH leaks; allowlisted rebuilt environment | `tests/session_run.rs::the_child_environment_is_exactly_the_allowed_set_and_no_parent_token_reaches_it` | Explicit passed variables in same test | paired |
| P04 / §7.4 | Hidden helper or nested run expands Seatbelt rights | `tests/ctl_broker.rs::the_hidden_child_helper_cannot_replace_the_outer_sandbox` | Same hidden helper outside hb reads exact canary | paired for __child; __guard signal isolation remains pending hb-8en |
| P05 / §7 | Parent dies before guardian watch is active | Spawn precedes unacknowledged watch | Existing guardian SIGKILL tests only cover registered/running processes | pending: hb-ime, hb-9lu and hb-6wk |
| P06 / §7 | Leader exits or descendant changes process group and escapes cleanup | Process-group signaling is not durable descendant containment | Existing group cleanup tests do not establish this | pending: hb-caj; no complete tree-cleanup promise |
| P07 / §7.3 | TIOCSTI terminal input injection | `tests/pty.rs::an_agent_under_hb_cannot_inject_keystrokes_through_any_route_to_its_terminal` | `the_probe_injects_on_a_pty_when_nothing_stops_it`; `a_profile_without_hid_control_still_allows_injection_and_one_that_denies_it_does_not` | paired |
| P08 / §7.3 | Terminal response reaches owner's shell after run | `tests/pty.rs::a_reply_the_terminal_sends_after_the_agent_ended_is_never_typed_into_the_shell` | `the_emulator_does_type_a_late_reply_into_a_shell_that_nothing_protects` | paired |
| P09 / §7.3 | OSC clipboard write despite owner denial | `tests/pty.rs::with_clipboard_writes_denied_a_run_on_a_pty_removes_them_and_says_so` | `a_run_on_a_pty_says_how_many_times_the_agent_set_the_clipboard` | paired; clipboard write is allowed by default, not universally blocked |
| P10 / §11 | Project declares host hook; owner-only config and argv execution | `tests/hooks.rs::a_hook_in_the_project_file_never_runs_and_the_run_does_not_start` | `a_hook_in_the_users_base_runs_before_the_agent_and_its_file_is_given_by_path` | paired |
| P11 / §11 | Hook output leaks or failed hook still starts agent | `tests/hooks.rs::a_failing_hook_ends_the_run_before_the_agent_starts_and_says_which_hook`; `a_hook_that_runs_past_its_timeout_aborts_the_run` | Successful hook above | partial: detached-descendant lifetime is not proved, hb-caj/hb-8en |
| P12 / §7.2 | Library caller expects CLI descriptor/process hardening | `src/session/fds.rs` explicitly assigns descriptor closure to binary caller | Library may retain caller-owned descriptors | unsupported: embedder must establish its own outer process boundary |

## Network and host brokers

| ID / design | Attack and control | Rejection evidence | Permissive control | Status / owner |
| --- | --- | --- | --- | --- |
| N01 / §12 | Bypass proxy with direct TCP or unlisted loopback port | `tests/session_run.rs::proxy::an_allowed_host_is_reached_through_the_proxy_and_not_around_it`; loopback tests in same module | Allowed proxied request/listed loopback | paired |
| N02 / §12 | DNS exfiltration through system resolver | `tests/probe_matrix.rs::name_resolution_through_the_system_resolver_fails_while_the_hosts_file_still_answers` | Host resolver probe and hosts-file result in same test | paired; macOS/version-specific |
| N03 / §12 | Wrong token, unlisted hostname, port or address literal | `tests/proxy_hardening.rs::wrong_credentials_in_any_form_get_a_407`; `only_the_listed_ports_are_reachable_and_the_refusal_says_what_to_write`; `tests/proxy_core.rs::address_literals_are_refused_even_when_the_allowlist_is_not_consulted` | Valid credential/allowlisted host tests in same suites | paired |
| N04 / §12 | DNS rebinding or encoded private/loopback target | `tests/proxy_hardening.rs::the_name_is_looked_up_once_and_the_address_dialled_is_the_one_that_came_back`; address classification tests in same file | Global address and explicit internal-host cases | paired through injected resolver/dialer, not live hostile DNS |
| N05 / §12 | Oversized/slow heads or connection flood | `tests/proxy_core.rs::an_oversized_head_is_a_431_and_a_slow_one_is_a_408`; `connections_beyond_the_limit_get_a_503_and_a_closed_slot_is_reused` | Valid request/reused slot in same tests | paired |
| N06 / §12 | Proxy logs disclose tokens/headers | `tests/proxy_hardening.rs::no_event_and_no_reply_ever_contains_the_token_or_the_credentials_header` | Served/refused audit-event tests in same suite | partial: broader secret-bearing diagnostics, hb-co1 and hb-8en |
| N07 / §12 | Domain suffix overreach or ambiguous request framing | `tests/proxy_core.rs::the_allowlist_is_exact_or_wildcard_case_blind_and_label_safe`; parser/public-suffix unit suites | Exact and subdomain valid requests | partial: exhaustive parser mutation evidence, hb-8en |
| N08 / §12 | Readable information exfiltrated to allowed destination | Proxy permits traffic to approved hosts, including shared endpoints | No content-filtering claim | unsupported: owner chooses destinations and readable data |
| B01 / §9 | Agent directly controls Podman or names an unlisted container | `tests/ctl_broker.rs::the_agent_cannot_run_podman_itself_and_only_listed_names_work` | `inside_the_ball_hb_ctl_restarts_a_listed_container_through_the_broker` | paired |
| B02 / §9 | Raw malformed, oversized, unknown-field or unsupported-op broker request | `tests/ctl_broker.rs::raw_broker_requests_are_validated_before_any_host_mutation` | Same raw client performs listed restart before/after attacks | paired: unknown-field, size and UTF-8 mutations caught in hb-dvf |
| B03 / §9 | Container ID prefix or mismatched inspected name bypasses scope | `src/ctl/preflight.rs::tests::test_name_must_equal_the_request_and_scope_must_match` | Valid exact-name case in same module | paired unit evidence; end-to-end expansion owned by hb-dvf |
| B04 / §9 | Privileged container, dangerous namespace or volume option accesses host | `src/ctl/preflight.rs::tests::test_host_and_joined_namespaces_privilege_and_extras_are_refused`; `test_only_plain_local_volumes_are_accepted` | Plain container/local volume tests | paired unit evidence |
| B05 / §9 | Swap mount source or ancestor after preflight | `tests/mount_pins.rs::the_swap_attempts_are_blocked`; `a_hard_link_made_from_a_mounted_file_is_blocked` | Same operations without pins in same fixture | paired |
| B06 / §9 | Container code exploits broad VM host shares | `tests/podman_e2e.rs` opt-in broad-share refusal and narrow-share operation | Real VM exposure control required; not run by default | partial: exact runtime matrix and independent review, hb-8en |
| B07 / §9 | Read VM keys/container state despite broad filesystem grant | `tests/ctl_broker.rs::the_podman_machine_key_and_container_directories_are_unreadable_inside_the_ball` | Unconfined denied-fixture reads plus readable file beneath the covering `.local/share` grant | paired |
| B08 / §9 | Broker leaks launchd environment or controls unlisted job | `tests/launchd_e2e.rs` opt-in and launchd projection unit tests | Listed disposable job status/restart | partial: live suite must actually run, hb-8en |
| B09 / §9 | Container logs reveal secrets or container networking bypasses host proxy | Broker projects logs; container code does not run under host Seatbelt | No container data-content or egress guarantee | unsupported |
| B10 / §9 | Flood/slow request stalls host broker | `tests/ctl_broker.rs::raw_broker_admission_and_incomplete_requests_are_bounded` | Valid request after busy/partial-line timeout replies | paired for admission and incomplete input; admission mutation caught in hb-dvf; continuous trickle remains partial hb-8en |

| S01 / §2, §4.6 | Run or enable launchctl from agent/project config | `tests/probe_matrix.rs::launchctl_cannot_run_unless_the_users_own_config_turns_it_on`; `a_project_file_cannot_turn_launchctl_on` | Outside launchctl version and owner-base-enabled case | paired |
| S02 / §11 | Hook output permissions or leftover session credentials | `tests/hooks.rs::hook_files_are_private_and_gone_after_the_run_ends_normally_or_by_sigterm` | Fixture reads hook-produced files before cleanup | partial: full mode/lifetime review, hb-8en |
| S03 / §11 | Agent sends its allowed login token to an allowed service | Agent presets deliberately expose required login state | No content-filtering guarantee | unsupported: owner-accepted provider credential access |
| S04 / §7.1 | Clipboard read, LaunchServices, AppleEvents or privilege escalation | `tests/probe_matrix.rs::the_pasteboard_cannot_be_read_or_written_by_the_command_line_tools`; `launchservices_shows_no_applications_and_open_cannot_start_one`; `an_apple_event_cannot_be_delivered_to_a_running_application`; `sudo_cannot_start_while_an_ordinary_program_can` | Outside probes in suite; full environment-dependent controls need review | partial: hb-8en |
| S05 / §4.5, §12.1 | TLS trust or system proxy metadata exposure | `tests/seatbelt_tls.rs`, `tests/tls_handshake.rs` and `tests/tls_inspection.rs` | System-trust on/off cases | partial: platform trust evidence, hb-8en; proxy reporting failures, hb-co1 |

## Residual trust and release gates

Unsandboxed same-user processes can modify owner files, approval records and project state.
The proxy token is not protection from an owner process that can inspect another process's environment.
The OS/kernel, installed hb binary, built-in presets, owner-selected tools and host hooks remain trusted.
Host-mode kernel exploits are outside the contract.
Linux, WSL2, native Windows and managed VM guarantees are pending their platform epics, not implied by macOS tests.

Doctor findings are advisory, and today some failed inspections appear empty: pending `hb-szd`, `hb-9ox`, `hb-co1`.
Full assurance remains pending `hb-8en`, blocked by lifecycle, diagnostics, cache and ceiling integration.
This inventory can be complete while its pending guarantees are not.
