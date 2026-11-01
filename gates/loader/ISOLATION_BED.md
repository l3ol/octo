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

VM and CI tests build an isomorphic disposable twin when the Ops root is not visible. Evidence must say so. Do not claim the box path was used unless that directory exists. The twin has push URL `DISABLED-DO-NOT-PUSH`. It is not product main, not PR #11, and not a Path B channel.
