# GATES tip24 deviations dev receipt

- task_id: GATES-BUILD-2026-11-01
- receipt_id: GATES-TIP24-DEVIATIONS-DEV-2026-11-02
- status: DEVIATIONS_PATCHED_NOT_SEALED
- evidence_class: STACK_OK_BUILDER_EVIDENCE
- runtime_pass: false
- independent_acceptance: false
- reviewer_pass: false
- g4_refrozen: false
- merge: false
- path_b: false
- gates_pin_sha default: UNSET_FAIL_CLOSED
- parent tip: `24d558e193be6225aa2bb71bde3a75a2f7851b78`
- parent tree: `443f3a3bd72f92172f4f5e243fdaebfa429d90ac`
- parent of parent: `ba70231c3438a22eb6cd27e63776c23f4541fc47`
- draft PR: https://github.com/l3ol/octo/pull/12
- historical CI: 41325626443 is not G4 re-freeze evidence
- product PR #11 / tip97 / N11: not touched

This commit is the dev tip under test. It does not re-freeze G4. Ops rebinds REAL_ISO on this commit. STACK_OK_BUILDER is not an independent PASS.

## Citations (MATCH)

| document | sha256 |
|---|---|
| Intake `TB-t176-GATES-TIP24-SOURCE-DEVIATIONS-INTAKE` | `6db30101469af462949ebf7217d9cca84c4586391354687dbaa7d3c671dbe405` |
| Dev dispatch `DISPATCH-DEV-GATES-TIP24-DEVIATIONS-t176` | `2839c4f778a6bdc10f712ecff34ab82e8749b868c96be059e084278c91c3c32e` |
| Spec v1 `SPEC-GATES-TIP24-DEVIATIONS-v1` | `7028b79b0db613f84502bc8b82a29b4f186f4cc68119211a88038354a5d8f695` |
| Negative cases `TIP24-DEVIATIONS-NEGATIVE-CASES` | `bf94feb7efd71498ff7713200484c3bc5d12590e7df06f5d61bcd88782b62092` |
| Spec receipt | `e35c96a6f852e5703b1a60cd0d1c52412ae61d2f84e23adf01de22491ae20163` |
| Tester receipt MD | `09c94646a811acdb8751dbc15dc69efa1736da4659bed28c53f17c01d260a5fc` |
| Tester receipt JSON | `de37ab9b7ad6a5bb34a5534710f66aad00cd7cc002e2d867b4afadb5dda0a2cf` |
| Tester matrix | `67384584b7a727801bf0051fe9077f5645b4baf98c72cc3d422859ce4b464c36` |
| OPEN items | `6d1062a4a97f1686aff54f62444f920f390dea59c248677e116bf49c9caae56b` |

The spec records a separate dispatch sha256 `b6d0e7c49b5f95236426f4ccb4c0f94a46cd5002a44022ba406a002bb80eb464`. This receipt cites the dev dispatch file that was hashed locally.

D3 is plan B. There is no full config seal. `parameters_canonical_sha256` is the read-only citation `cff01a57e38b16af6bc5545789949575b1cbcc3078cdf5bf3158cee4b56fd884` (4332 bytes). `config_digest` is sha256 of the canonical four-field manifest, not that file alone.

Recomputed from the parent tip's policy and protection blobs (those blobs are unchanged in this commit):

```text
{"parameters_canonical_sha256":"cff01a57e38b16af6bc5545789949575b1cbcc3078cdf5bf3158cee4b56fd884","policy_config_digest":"68eb1f1844aa24947f9e23a9f21fb1365c50ca85f9012f981c98aed8fbbdfcda","protection_settings_digest":"ab4096de1a460ec7696df488e8d92cf5623b116c190fdf84153bf9037fc0d99e","rule_version":"6.0.0"}
config_digest=2feb73d01b2a717b0219253967770ad2da094dd137b918c4a3a35e1dd27ff59a
```

`rule_version` is the existing `6.0.0`. Policy and protection digests hash the existing module blobs. No new parameter value was introduced.

## Fixes

1. `ensure_commit` returns the named 40-hex object or `{status: FAIL, reason_code}`. A missing object is `PIN_OBJECT_MISSING`. A non-40-hex input is `TAMPER_PIN_UNSET_OR_INVALID`. There is no HEAD, tag, branch, worktree, or candidate-pin fallback.
2. `snapshot_pin_commit` builds the runtime pin with `git archive` and `commit-tree` of the build candidate's tree. Blob path, oid, and sha256 must match `gates/**`. Uncommitted tracked edits fail `PIN_SNAPSHOT_TREE_MISMATCH`. Untracked files are not in the pin. Build candidate, landing candidate, test base, and runtime pin are different fields.
3. `config_digest` is the plan-B manifest digest. A digest equal to the canonical file sha, or a manifest missing a required field, is `CONFIG_DIGEST_INCOMPLETE`.
4. `.github/workflows/ci.yml` checks out `pull_request.head.sha` (or `github.sha` off a pull request) with `fetch-depth: 0`, then `python -m gates.workflow_proof` logs and asserts HEAD, tree, and base. A mismatch is `WORKFLOW_HEAD_UNPROVEN`. The workflow does not run apt, sudo, sysctl, git merge, or git rebase.

## Selftest (STACK_OK_BUILDER_EVIDENCE)

Command: `PYTHONPATH=. python3 -m gates.selftest`

```text
........................................................................ [ 97%]
..                                                                       [100%]
74 passed in 300.97s (0:05:00)
STACK_OK_BUILDER_EVIDENCE command='PYTHONPATH=. python -m gates.selftest' exit=0 passed=74 failed=0 independent_acceptance=false runtime_pass=false
```

exit=0 passed=74 failed=0

This run covered the 17 negative cases TD-D1-01..04, TD-D2-01..04, TD-D3-01..04, TD-D4-01..05 plus the existing builder scenes and the real-evidence bed. It is not acceptance.
