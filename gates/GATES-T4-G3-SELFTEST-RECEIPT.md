# GATES-T4 · G3 squad selftest receipt

- receipt_id: `GATES-T4-G3-SELFTEST-RECEIPT`
- task_id: `GATES-BUILD-2026-11-01`
- subtask: `GATES-T4-G3-SELFTEST`
- status: `G3_SQUAD_SELFTEST_SUCCEEDED`
- label: `STACK_OK_BUILDER_EVIDENCE`
- independent_acceptance: false
- reviewer_pass: false
- runtime_pass: false
- merge: false
- path_b: false
- gates_pin_sha: `UNSET_FAIL_CLOSED`
- PRD_fields_changed: false
- product_pr_11_touched: false

This file is squad selftest evidence only. It is not an independent Reviewer PASS and not a dual-Chief acceptance.

## Checkout under test

Explicit detach/checkout of the full tip, not a merge ref.

| field | value |
|---|---|
| branch | `test/gates-v6-isolated` |
| tip | `6f90851a8ef92a2a76afe57a6ba3acacf9835d1e` |
| tree | `66fe123e2b8082a21fe25a7d501bee1d3461e0a0` |
| parent | `5443c9b4dde7fc208a0a72457c87904650829f77` |
| draft PR | https://github.com/l3ol/octo/pull/12 |
| CI | https://github.com/l3ol/octo/actions/runs/41321778391 |
| CI head_sha | `6f90851a8ef92a2a76afe57a6ba3acacf9835d1e` (equals tip) |
| CI conclusion | success |

No gate logic changed in this G3 pass. There was no failing case to repair.

## Command

```
PYTHONPATH=. python -m gates.selftest
```

| field | value |
|---|---|
| exit | 0 |
| passed | 50 |
| failed | 0 |
| stdout | `STACK_OK_BUILDER_EVIDENCE command='PYTHONPATH=. python -m gates.selftest' exit=0 passed=50 failed=0 independent_acceptance=false runtime_pass=false` |

The 50 passed items are the 43-scene suite in `tests/gates/test_scenes.py` (42 collected items; scene 35 is inside `test_scene_34_and_35_recovery_verification`), plus canonical-byte checks, the 42-path map import check, and the existing `tests/test_models.py` and `tests/test_backup.py` cases. None failed.

## Scene index (1–43)

Each row is an assertion that passed on the checkout above. `squad_selftest=PASS` means the test passed. It does not mean an independent acceptance PASS.

| # | squad_selftest | asserted outcome | test |
|---|---|---|---|
| 1 | PASS | `SCOPE_MISSING_TASK_ID`; no merge | `test_scene_01_missing_task_id` |
| 2 | PASS | `POLICY_SECRET_PATTERN` plus `ACTIVATION_KILL_LINE` category `secret`; later package stays stopped | `test_scene_02_secret_trips_kill_line` |
| 3 | PASS | `VERIFICATION_CANDIDATE_DRIFT` | `test_scene_03_candidate_drift` |
| 4 | PASS | `VERIFICATION_BASE_STALE` | `test_scene_04_base_stale` |
| 5 | PASS | `POLICY_DOWNSTREAM_SIDE_EFFECT`; repo Path B fail-closed | `test_scene_05_downstream_side_effect` |
| 6 | PASS | landing `PASS` with merge and board record; reverse `VERIFICATION_NO_PASS` | `test_scene_06_positive_and_reverse_without_pass` |
| 7 | PASS | `ACTIVATION_EMERGENCY_STOP` on the stopped package and the next one | `test_scene_07_emergency_stop_freezes_later_packages` |
| 8 | PASS | injected fault → `GATE_INTERNAL_ERROR` and self-close; non-founder `ACTIVATION_NON_FOUNDER`; each missing reopen condition `ACTIVATION_REOPEN_INCOMPLETE` | `test_scene_08_fault_self_close_and_incomplete_reopen` |
| 9 | PASS | unknown id and closed id → `SCOPE_UNKNOWN_OR_CLOSED_TASK` | `test_scene_09_unknown_or_closed_task` |
| 10 | PASS | `SCOPE_OUT_OF_RANGE` | `test_scene_10_path_outside_task_range` |
| 11 | PASS | brain signature and backup signature → `POLICY_BRAIN_OR_BACKUP` | `test_scene_11_brain_or_backup_content` |
| 12 | PASS | `10485761` → `POLICY_SIZE_EXCEEDED`; `10485760` does not trip P-3 and the rest of the landing passes | `test_scene_12_size_threshold_boundary` |
| 13 | PASS | `tools/wallet/readme.txt` and `x/agent-data/a.txt` → `POLICY_FORBIDDEN_PATH`; `release/secret-manifest.json` exception does not path-reject; secret bytes inside that file still `POLICY_SECRET_PATTERN` | `test_scene_13_forbidden_paths_and_manifest_exception` |
| 14 | PASS | `ACTIVATION_IRREVERSIBLE_REQUIRES_HUMAN` | `test_scene_14_irreversible_requires_human` |
| 15 | PASS | untrusted issuer `VERIFICATION_UNTRUSTED_ISSUER`; one-byte signature change `VERIFICATION_RECEIPT_TAMPERED` | `test_scene_15_untrusted_issuer_and_tampered_receipt` |
| 16 | PASS | `VERIFICATION_REPLAY_BINDING` | `test_scene_16_replay_other_task` |
| 17 | PASS | gate file edit and registry inject → `TAMPER_GATES_PATH_TOUCHED`; deleted pattern → `POLICY_RULE_DOWNGRADE` with tamper also recorded; pinned patterns still reject `**/wallet/**`; three policy decision records plus a rule-change trace | `test_scene_17_gate_tamper_downgrade_and_audit` |
| 18 | PASS | `ATOMIC_MERGE_HEAD_MISMATCH`; receipt not consumed; swapped merge candidate also mismatches | `test_scene_18_head_moved_before_merge` |
| 19 | PASS | only `VERIFICATION_RECEIPT_ALREADY_CONSUMED`; other verification checks PASS; head observation PASS; not merged | `test_scene_19_already_consumed_is_the_only_failure` |
| 20 | PASS | exactly one merge `PASS` and one `VERIFICATION_RECEIPT_CONFLICT` | `test_scene_20_concurrent_receipt_one_winner` |
| 21 | PASS | `VERIFICATION_SHA_MISMATCH` | `test_scene_21_sha_mismatch_substitution` |
| 22 | PASS | `BINDING_INCONSISTENT` on candidate SHA | `test_scene_22_binding_inconsistent` |
| 23 | PASS | artifact mismatch → `ISOMORPHISM_DIGEST_MISMATCH` field `artifact_digest` | `test_scene_23_30_31_32_isomorphism` |
| 24 | PASS | default and production → `ACTIVATION_PATH_B_DISABLED` with message `Path B disabled`; no merge | `test_scene_24_path_b_disabled_by_default_and_on_production` |
| 25 | PASS | separated identities → decision PASS, reason_code null; overlap or shared write → decision REJECT | `test_scene_25_builder_acceptance_separation` |
| 26 | PASS | `UNSET_FAIL_CLOSED`, bad format, missing object, non-commit, and digest mismatch → `TAMPER_PIN_UNSET_OR_INVALID` with `fallback_used=false`; `gates/**` edit → `TAMPER_GATES_PATH_TOUCHED` | `test_scene_26_pin_fail_closed_and_path_filter` |
| 27 | PASS | `gates/atomic_merge/**` and `.git/hooks/pre-receive` → `TAMPER_GATES_PATH_TOUCHED`; runtime unaffected | `test_scene_27_compare_and_merge_bypass_rejected` |
| 28 | PASS | `INTEGRITY_RECOVERY_MISSING` | `test_scene_28_recovery_missing` |
| 29 | PASS | `INTEGRITY_BOARD_INVISIBLE`; no merge | `test_scene_29_board_invisible` |
| 30 | PASS | config mismatch → `ISOMORPHISM_DIGEST_MISMATCH` field `config_digest` | `test_scene_23_30_31_32_isomorphism` |
| 31 | PASS | altered sealed digest → `ISOMORPHISM_SEAL_TAMPERED` | `test_scene_23_30_31_32_isomorphism` |
| 32 | PASS | artifact and config digests match → decision PASS | `test_scene_23_30_31_32_isomorphism` |
| 33 | PASS | four reopen conditions → decision PASS in `isolated`; production reopen stays `ACTIVATION_PATH_B_DISABLED` | `test_scene_33_reopen_when_four_conditions_hold` |
| 34 | PASS | missing rollback, failed drill, or wrong binding → `INTEGRITY_RECOVERY_UNVERIFIED` | `test_scene_34_and_35_recovery_verification` |
| 35 | PASS | bound rollback exists and drill passed → decision PASS (same test as 34) | `test_scene_34_and_35_recovery_verification` |
| 36 | PASS | `ACTIVATION_KILL_LINE` category `funds` | `test_scenes_36_to_39_kill_lines` |
| 37 | PASS | `ACTIVATION_KILL_LINE` category `publish` | `test_scenes_36_to_39_kill_lines` |
| 38 | PASS | `ACTIVATION_KILL_LINE` category `send` | `test_scenes_36_to_39_kill_lines` |
| 39 | PASS | `ACTIVATION_KILL_LINE` category `delete` for `DROP TABLE` and full-table `DELETE FROM` | `test_scenes_36_to_39_kill_lines` |
| 40 | PASS | `ACTIVATION_NON_FOUNDER`; Path B stays off | `test_scenes_40_to_43_initial_activation` |
| 41 | PASS | `ACTIVATION_MISSING_RECEIPT` | `test_scenes_40_to_43_initial_activation` |
| 42 | PASS | `ACTIVATION_RECEIPT_MISMATCH` | `test_scenes_40_to_43_initial_activation` |
| 43 | PASS | isolated enable decision PASS; production twin `ACTIVATION_PATH_B_DISABLED` and flag stays false | `test_scenes_40_to_43_initial_activation` |

Count: 43. Positive scenes 6, 32, 33, 35, and 43 passed inside the isolated fixture only. Production Path B was not enabled.

## Map 42

Source: `gates/acceptance_item_map.md`. All 42 IDs checked against a passing squad selftest. `[x]` means the mapped test passed. It is not an acceptance signature.

| ID | check | scene test |
|---|---|---|
| R-1 | [x] | 6 |
| R-2 | [x] | 1 |
| R-3 | [x] | 9 |
| R-4 | [x] | 10 |
| R-5 | [x] | 1–43 |
| V-1 | [x] | 6 |
| V-2 | [x] | 3 |
| V-3 | [x] | 6 reverse |
| V-4 | [x] | 21 |
| V-5 | [x] | 4 |
| V-6 | [x] | 15 |
| V-7 | [x] | 16 |
| V-8 | [x] | 15 |
| V-9 | [x] | 19 |
| V-10 | [x] | 20 |
| P-1 | [x] | 2 |
| P-2 | [x] | 11 |
| P-3 | [x] | 12 |
| P-4 | [x] | 13 |
| P-5 | [x] | 5 |
| P-6 | [x] | 17 |
| J-1 | [x] | 6, 18 |
| J-2 | [x] | 22 |
| A-1 | [x] | 24 |
| A-2 | [x] | 25 |
| A-3 | [x] | 2, 36, 37, 38, 39 |
| A-4 | [x] | 7 |
| A-5 | [x] | 8, 33 |
| A-6 | [x] | 14 |
| A-7 | [x] | 40 |
| A-8 | [x] | 41 |
| A-9 | [x] | 42 |
| A-10 | [x] | 43 |
| G-1 | [x] | 26 |
| G-2 | [x] | 17 |
| G-3 | [x] | 17 |
| M-1 | [x] | 18 |
| M-2 | [x] | 27 |
| I-1 | [x] | 23, 30, 31, 32 |
| I-2 | [x] | 23, 30, 32 |
| L-1 | [x] | 6, 28, 34, 35 |
| L-2 | [x] | 29 |

Count: 42/42 checked. No blank row.

## Stop

G3 squad selftest is recorded. No merge. No production Path B. No product-tip or PR #11 edit. G4 was not started.
