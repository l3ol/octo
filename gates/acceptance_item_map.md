# acceptance_item_map (42 rows, G2 implementation)

- task_id: GATES-BUILD-2026-11-01
- subtask: GATES-T3-DEV
- status: G2_IMPLEMENTED
- runtime_pass: false
- independent_acceptance: false
- self_test_label: STACK_OK_BUILDER_EVIDENCE
- gates_pin_sha: UNSET_FAIL_CLOSED
- PRD_fields_changed: false
- code_written: true

Filled from the T2 skeleton. Implementation paths are the functions that enforce each item. Self-test evidence is builder scaffolding only and is not a Reviewer PASS.

| ID | Spec section | implement path | self-test scenes | self-test evidence |
|---|---|---|---|---|
| R-1 | §1 scope / §3 | `gates/scope/decide.py::decide` | 6 | `tests/gates/test_scenes.py::test_scene_06_positive_and_reverse_without_pass` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| R-2 | §1 scope / §3 | `gates/scope/decide.py::check_task_id_present` | 1 | `tests/gates/test_scenes.py::test_scene_01_missing_task_id` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| R-3 | §1 scope / §3 | `gates/scope/decide.py::check_task_active` | 9 | `tests/gates/test_scenes.py::test_scene_09_unknown_or_closed_task` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| R-4 | §1 scope / §3 | `gates/scope/decide.py::check_paths_in_range` | 10 | `tests/gates/test_scenes.py::test_scene_10_path_outside_task_range` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| R-5 | §1 scope / §3 | `gates/types.py::make_result` | 1–43 | `tests/gates/support.py::assert_machine_readable` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| V-1 | §1 verification / §3 | `gates/verification/decide.py::check_pass_present` | 6 | `tests/gates/test_scenes.py::test_scene_06_positive_and_reverse_without_pass` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| V-2 | §1 verification / §3 | `gates/verification/decide.py::check_candidate_binding` | 3 | `tests/gates/test_scenes.py::test_scene_03_candidate_drift` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| V-3 | §1 verification / §3 | `gates/verification/decide.py::check_pass_present` | 6 (reverse) | `tests/gates/test_scenes.py::test_scene_06_positive_and_reverse_without_pass` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| V-4 | §1 verification / §3 | `gates/verification/decide.py::check_candidate_binding` | 21 | `tests/gates/test_scenes.py::test_scene_21_sha_mismatch_substitution` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| V-5 | §1 verification / §3 | `gates/verification/decide.py::check_base_binding` | 4 | `tests/gates/test_scenes.py::test_scene_04_base_stale` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| V-6 | §1 verification / §3 | `gates/verification/decide.py::check_trusted_issuer` | 15 | `tests/gates/test_scenes.py::test_scene_15_untrusted_issuer_and_tampered_receipt` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| V-7 | §1 verification / §3 | `gates/verification/decide.py::check_replay_binding` | 16 | `tests/gates/test_scenes.py::test_scene_16_replay_other_task` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| V-8 | §1 verification / §3 | `gates/verification/receipt.py::signature_valid` | 15 | `tests/gates/test_scenes.py::test_scene_15_untrusted_issuer_and_tampered_receipt` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| V-9 | §1 verification / §3 | `gates/verification/decide.py::check_unconsumed` | 19 | `tests/gates/test_scenes.py::test_scene_19_already_consumed_is_the_only_failure` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| V-10 | §1 verification / §3 | `gates/atomic_merge/compare.py::compare_and_merge` | 20 | `tests/gates/test_scenes.py::test_scene_20_concurrent_receipt_one_winner` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| P-1 | §1 policy / §5.1–5.2 | `gates/policy/content.py::scan_secrets` | 2 | `tests/gates/test_scenes.py::test_scene_02_secret_trips_kill_line` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| P-2 | §1 policy / §5.1–5.2 | `gates/policy/content.py::scan_brain_or_backup` | 11 | `tests/gates/test_scenes.py::test_scene_11_brain_or_backup_content` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| P-3 | §1 policy / §5.1–5.2 | `gates/policy/size.py::measure_tree` | 12 | `tests/gates/test_scenes.py::test_scene_12_size_threshold_boundary` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| P-4 | §1 policy / §5.1–5.2 | `gates/policy/forbidden.py::evaluate_paths` | 13 | `tests/gates/test_scenes.py::test_scene_13_forbidden_paths_and_manifest_exception` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| P-5 | §1 policy / §5.1–5.2 | `gates/policy/decide.py::check_downstream` | 5 | `tests/gates/test_scenes.py::test_scene_05_downstream_side_effect` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| P-6 | §1 policy / §5.1–5.2 | `gates/policy/audit.py::record_rule_change` | 17 | `tests/gates/test_scenes.py::test_scene_17_gate_tamper_downgrade_and_audit` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| J-1 | §1 binding | `gates/binding/decide.py::decide` | 6, 18 | `tests/gates/test_scenes.py::test_scene_06_positive_and_reverse_without_pass` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| J-2 | §1 binding | `gates/binding/decide.py::decide` | 22 | `tests/gates/test_scenes.py::test_scene_22_binding_inconsistent` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| A-1 | §1 activation | `gates/activation/request.py::evaluate_for_landing` | 24 | `tests/gates/test_scenes.py::test_scene_24_path_b_disabled_by_default_and_on_production` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| A-2 | §1 activation | `gates/activation/request.py::check_separation` | 25 | `tests/gates/test_scenes.py::test_scene_25_builder_acceptance_separation` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| A-3 | §1 activation | `gates/activation/request.py::evaluate_for_landing` | 2, 36, 37, 38, 39 | `tests/gates/test_scenes.py::test_scenes_36_to_39_kill_lines` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| A-4 | §1 activation | `gates/activation/request.py::signal_emergency_stop` | 7 | `tests/gates/test_scenes.py::test_scene_07_emergency_stop_freezes_later_packages` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| A-5 | §1 activation | `gates/activation/request.py::reopen` | 8, 33 | `tests/gates/test_scenes.py::test_scene_33_reopen_when_four_conditions_hold` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| A-6 | §1 activation | `gates/activation/request.py::evaluate_for_landing` | 14 | `tests/gates/test_scenes.py::test_scene_14_irreversible_requires_human` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| A-7 | §1 activation | `gates/activation/request.py::enable_path_b` | 40 | `tests/gates/test_scenes.py::test_scenes_40_to_43_initial_activation` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| A-8 | §1 activation | `gates/activation/request.py::enable_path_b` | 41 | `tests/gates/test_scenes.py::test_scenes_40_to_43_initial_activation` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| A-9 | §1 activation | `gates/activation/request.py::enable_path_b` | 42 | `tests/gates/test_scenes.py::test_scenes_40_to_43_initial_activation` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| A-10 | §1 activation | `gates/activation/request.py::enable_path_b` | 43 | `tests/gates/test_scenes.py::test_scenes_40_to_43_initial_activation` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| G-1 | §1 tamper / §5.3 | `gates/tamper/loader.py::load_pin` | 26 | `tests/gates/test_scenes.py::test_scene_26_pin_fail_closed_and_path_filter` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| G-2 | §1 tamper / §5.3 | `gates/tamper/path_filter.py::path_filter` | 17 | `tests/gates/test_scenes.py::test_scene_17_gate_tamper_downgrade_and_audit` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| G-3 | §1 tamper / §5.3 | `gates/tamper/downgrade.py::detect_downgrade` | 17 | `tests/gates/test_scenes.py::test_scene_17_gate_tamper_downgrade_and_audit` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| M-1 | §1 atomic_merge / §5.3 | `gates/atomic_merge/compare.py::compare_and_merge` | 18 | `tests/gates/test_scenes.py::test_scene_18_head_moved_before_merge` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| M-2 | §1 atomic_merge / §5.3 | `gates/tamper/path_filter.py::path_filter` | 27 | `tests/gates/test_scenes.py::test_scene_27_compare_and_merge_bypass_rejected` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| I-1 | §1 isomorphism | `gates/isomorphism/seal.py::seal` | 23, 30, 31, 32 | `tests/gates/test_scenes.py::test_scene_23_30_31_32_isomorphism` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| I-2 | §1 isomorphism | `gates/isomorphism/seal.py::verify` | 23, 30, 32 | `tests/gates/test_scenes.py::test_scene_23_30_31_32_isomorphism` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| L-1 | §1 integrity | `gates/integrity/recovery.py::verify_recovery` | 6, 28, 34, 35 | `tests/gates/test_scenes.py::test_scene_34_and_35_recovery_verification` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |
| L-2 | §1 integrity | `gates/integrity/board.py::publish_board` | 29 | `tests/gates/test_scenes.py::test_scene_29_board_invisible` STACK_OK_BUILDER_EVIDENCE; not independent acceptance |

Count: R5+V10+P6+J2+A10+G3+M2+I2+L2=42.
