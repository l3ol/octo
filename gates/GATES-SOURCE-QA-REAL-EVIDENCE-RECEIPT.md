# GATES source QA real-evidence receipt

- task_id: GATES-BUILD-2026-11-01
- subtask: GATES-SOURCE-QA-DEV
- status: REAL_EVIDENCE_IMPLEMENTED
- runtime_pass: false
- independent_acceptance: false
- reviewer_pass: false
- merge: false
- path_b: false
- gates_pin_sha default: UNSET_FAIL_CLOSED
- parent tip: `d50148d9d84e42ac6cd3359d598f0ec7c600e834`
- parent tree: `03b23bf69839c1eb059b553ca027c13e0b342096`
- draft PR: https://github.com/l3ol/octo/pull/12
- authoritative Ops root: `/home/box/ops-isolation/gates/source-qa-isolation-bed-2026-11-01`
- ops root visible on this VM: false
- twin: isomorphic disposable bed built by `gates.isolation_bed.build_twin_bed`. It checks out `d50148d9…` when that object is in the clone. A shallow CI checkout deepens `origin` first and, if the object is still absent, detaches the twin at `HEAD` instead of inventing a SHA. Push URL stays `DISABLED-DO-NOT-PUSH`.

This is not a G4 seal and not an independent Reviewer PASS. Chief re-freezes G4.

## Three code changes

1. `gates/tamper/loader.py::load_pin` imports `gates/**` from `pin_loadpath` with importlib. Success evidence includes `gates_pin_sha`, `gate_tree_sha`, `pin_loadpath`, `module_origin`, `sys_path_gates_entry`, `candidate_code_used` derived from those paths, `manifest_path`, and `manifest_sha256`. A symlink that leaves the loadpath is `TAMPER_PIN_UNSET_OR_INVALID` with `module_origin_violation=true`. MemoryObjectStore matches stay `STACK_OK_BUILDER_EVIDENCE` and do not claim a real module load.
2. `gates/atomic_merge/compare.py::compare_and_merge` rejects `publish is None` with `ATOMIC_MERGE_PUBLISHER_MISSING`, `details.publisher="missing"`, `merged=false`, and does not record a ledger merge or move a ref. A real landing uses `GitCasPublisher` (`git update-ref <ref> <new> <old>`) in an isolated repo. Scene 18 advances that ref between the read and the CAS. Scene 20 is two processes on one ref.
3. `gates/integrity/recovery.py::verify_recovery` sets `drill_passed` only when the on-disk drill receipt `result==PASS`. A hand-filled bool, a missing receipt, a bad rollback SHA, a binding mismatch, or a missing board entry is `INTEGRITY_RECOVERY_UNVERIFIED`. The drill runner checks out the rollback commit and records ref readback.

`gates/loader/default_manifest.json` is unchanged (`UNSET_FAIL_CLOSED`). No pin SHA is hardcoded.

## Selftest (STACK_OK_BUILDER_EVIDENCE, not acceptance)

Command: `PYTHONPATH=. python -m gates.selftest`

```
54 passed
STACK_OK_BUILDER_EVIDENCE command='PYTHONPATH=. python -m gates.selftest' exit=0 passed=54 failed=0 independent_acceptance=false runtime_pass=false
```

exit=0 passed=54 failed=0

The 54 includes the previous builder scenes plus REAL cases. Builder scenes that still use `support.PIN=0123…` or MemoryObjectStore are STACK_OK only.

## REAL_ISOLATION_EVIDENCE

| check | result | label |
|---|---|---|
| RE-G1-PIN twin at `d50148d9` / tree `03b23bf6`, external manifest mode 0444, digests recomputed, default still UNSET | PASS | REAL |
| RE-G1-26a UNSET does not fall back to HEAD or the candidate pin | PASS | REAL |
| RE-G1-26b missing object and tree digest mismatch | PASS | REAL |
| RE-ORIGIN module `__file__` under `pin_loadpath`, `candidate_code_used=false` derived | PASS | REAL |
| RE-ORIGIN-NEG symlink escape `module_origin_violation=true` | PASS | REAL |
| RE-G1-26c candidate edit of `compare.py` does not change the loaded pin bytes | PASS | REAL |
| RE-PUB-NONE ref unchanged, ledger not merged, Path B not tripped | PASS | REAL |
| RE-M1-18 ref ends on the racer commit, candidate not consumed | PASS | REAL |
| RE-V10-20 one PASS, one `VERIFICATION_RECEIPT_CONFLICT`, ref advanced once, one ledger row | PASS | REAL |
| RE-L1-35 drill receipt `result=PASS`, `ref_after==rollback`, board readback | PASS | REAL |
| RE-L1-34 fake SHA, hand-filled bool, failed receipt, bad binding, missing board | PASS (all UNVERIFIED) | REAL |
| RE-L1-28 missing plan | PASS (`INTEGRITY_RECOVERY_MISSING`) | builder scene, real verifier |
| RE-L2-29 hidden board | PASS (`INTEGRITY_BOARD_INVISIBLE`) | builder scene |

Affected set re-run inside the 54: G-1 / 26, M-1 / 18, M-2 / 27, V-10 / 20, L-1 / 28 / 34 / 35, L-2 / 29, publisher-missing, plus the rest of `tests/`.

## Stop

No merge. No production Path B. PR #11 was not touched. Waiting for Chief to re-freeze G4.
