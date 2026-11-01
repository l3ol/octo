# Isolation bed binding

Authoritative Ops root (shared box; this Dev VM may not have the path):

`/home/box/ops-isolation/gates/source-qa-isolation-bed-2026-11-01`

| env | authoritative default |
|---|---|
| `GATES_ISOLATION_BED_ROOT` | the root above |
| `GATES_DISPOSABLE_GIT` | `<root>/git/octo-gates-DISPOSABLE.git` |
| `GATES_PIN_LOADPATH` | `<root>/pin-loadpath-readonly` |
| `GATES_CAS_SLOT` | `<root>/cas-slot` |
| `GATES_L1_DRILL_ROOT` | `<root>/l1-recovery-drill` |

`gates/loader/default_manifest.json` stays `gates_pin_sha=UNSET_FAIL_CLOSED`. A real 40-hex pin is written only into an external manifest under the pin loadpath, outside the candidate worktree.

`ensure_commit` returns the named 40-hex commit or fails closed (`PIN_OBJECT_MISSING`, or `TAMPER_PIN_UNSET_OR_INVALID` when the input is not a full SHA). It does not substitute HEAD, a tag, a branch, the worktree, or a candidate-supplied pin. `GATES_TIP_BINDING` may name the authoritative tip. The historical `d50148d9…` commit is not that tip.

`snapshot_pin_commit` materializes the runtime pin from the build candidate's git objects (`git archive` and blob identity). The runtime pin, the build candidate, a landing candidate, and the test base are separate fields. Uncommitted tracked `gates/**` changes fail `PIN_SNAPSHOT_TREE_MISMATCH`. Untracked files are not pin content.

`config_digest` is sha256 of the plan-B config manifest (rule version, policy digest, protection digest, and the read-only canonical sha256 `cff01a57…`). It is not the hash of `GATES-PARAMETERS-CANONICAL.txt` alone.

VM and CI tests build an isomorphic disposable twin when the Ops root is not visible. Evidence must say so. Do not claim the box path was used unless that directory exists. The twin has push URL `DISABLED-DO-NOT-PUSH`. It is not product main, not PR #11, and not a Path B channel.
