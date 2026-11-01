# GATES-T3-DEV Receipt

- task_id: GATES-BUILD-2026-11-01
- subtask: GATES-T3-DEV
- status: G2_IMPLEMENTED
- hard_stop: before G3 independent acceptance
- runtime_pass: false
- independent_acceptance: false
- merge: false
- path_b: false
- gates_pin_sha: UNSET_FAIL_CLOSED
- PRD_fields_changed: false
- product_pr_11_untouched: true
- product_tip_untouched: 2507563a917525d9b2d1f49613082cff97a5afc9

## Base

- branch: `test/gates-v6-isolated`
- base: `5443c9b4dde7fc208a0a72457c87904650829f77` (`main` at implementation start)
- isolated from product track PR #11 (`cursor/g2-s1-t04-router-6581`)

## Builder selftest

Label only: `STACK_OK_BUILDER_EVIDENCE`. This is not a Reviewer PASS and not a G3 acceptance run.

- command: `PYTHONPATH=. python -m gates.selftest`
- exit: 0
- passed: 50
- failed: 0

The same tests are what CI runs via `PYTHONPATH=. pytest tests/ -q`.

## What landed

Three gates (scope, verification, policy), binding, final-slot compare-and-merge, pin loader, path filter, isomorphism seal, recovery check, and board publish. Shipped pin manifest is `UNSET_FAIL_CLOSED`. `load_pin` rejects that value and does not fall back to tag, HEAD, worktree, or a candidate-supplied pin.

Pinned parameters:

- P-3: `total_bytes > 10485760` rejects with `POLICY_SIZE_EXCEEDED`; equality does not.
- P-4: the 21 canonical patterns, read from the byte-exact parameter file, plus the `manifest` + `.json`/`.sha256` exception.
- G-1: `gates/**` is protected. No invented pin SHA.
- Scene 19: `VERIFICATION_RECEIPT_ALREADY_CONSUMED`, with the other verification checks recorded as PASS.
- Canonical line 55: the three U+FFFD bytes are unchanged. M-1 compares the candidate SHA and base SHA the three gates already verified.

## Map

`gates/acceptance_item_map.md` — 42 rows, each implementation path is an importable function.

Production Path B stays hard-disabled (`environment != "isolated"` cannot enable it). The in-memory isolated flag used by builder tests is not a production grant.
