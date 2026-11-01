# TC-MATRIX TD-D1..D4

Candidate tip `998784b3e6cc0e6e6597cde76ce018331d924a72`
Tree `62fd51cb0b31eeed130007201cfd36bbca081c44`
Parent `24d558e193be6225aa2bb71bde3a75a2f7851b78`

`case_result` records whether that negative case met the spec expectation.
It is not `runtime_pass`, not acceptance, not `verification_pass`, and not a G4 re-freeze.
STACK_OK is not PASS. CI success is not PASS.

Counts: PASS 17, FAIL 0, OPEN 0.

| ID | Spec expectation | case_result | Observed |
|---|---|---|---|
| TD-D1-01 | Missing 40hex → FAIL `PIN_OBJECT_MISSING`; return value is not HEAD | PASS | `{"status":"FAIL","reason_code":"PIN_OBJECT_MISSING"}`. No `sha`. HEAD unchanged. |
| TD-D1-02 | Shallow clone, still missing after deepen/fetch → FAIL `PIN_OBJECT_MISSING`; do not return HEAD/tag/branch | PASS | `--is-shallow-repository=true`. Parent object still absent. Same FAIL object. HEAD stayed on the shallow tip. |
| TD-D1-03 | Shallow clone that contains the full tip → OK; returned sha equals the input | PASS | Shallow tip present, parent absent. Result `{"status":"OK","sha":"<input>"}`. |
| TD-D1-04 | Short sha / empty / branch name → FAIL `TAMPER_PIN_UNSET_OR_INVALID` | PASS | `""`, `abc`, `998784b3`, `main`, `HEAD`, `24d558e` all failed closed with that reason and no `sha`. |
| TD-D2-01 | Untracked gates file stays out of the pin tree, or FAIL `PIN_SNAPSHOT_TREE_MISMATCH` | PASS | Snapshot OK via `git-archive`. `gates/untracked.txt` absent from blob paths and from the pin tree. Pin tree equals the source tree. |
| TD-D2-02 | Uncommitted tracked gates edit → FAIL `PIN_SNAPSHOT_TREE_MISMATCH` | PASS | FAIL with that reason. `refs/disposable/gates-qa/pin-snapshot` was not created. |
| TD-D2-03 | `git archive` of `build_candidate_sha` matches `gate_tree_sha` and every blob oid+sha256; sets equal | PASS | Method `git-archive`. Tester recomputed `ls-tree` oid/sha256 and archive bytes. Sets equal. Pin sha distinct from build, land, and test base. |
| TD-D2-04 | `method=workspace-copytree` → spec check FAIL | PASS | `reject_snapshot_method` → FAIL `PIN_SNAPSHOT_TREE_MISMATCH`. `gates/isolation_bed.py` has no `copytree(` call. |
| TD-D3-01 | `config_digest` equal to the cff hash → FAIL `CONFIG_DIGEST_INCOMPLETE` | PASS | Judge of `cff01a57…` against the four-field manifest returned that FAIL. Recomputed manifest digest `2feb73d0…` is not the cff hash. |
| TD-D3-02 | Changing `protection_settings_digest` changes `config_digest` | PASS | `2feb73d0…` → `adda8257…` (hashlib recompute matched). |
| TD-D3-03 | cff bytes stay `cff01a57…`, 4332 bytes | PASS | Worktree file and `HEAD:gates/policy/GATES-PARAMETERS-CANONICAL.txt` both 4332 bytes and that sha256. |
| TD-D3-04 | Manifest without `rule_version` → FAIL `CONFIG_DIGEST_INCOMPLETE` | PASS | `digest_config_manifest` and `judge_config_digest` both returned that reason. |
| TD-D4-01 | Merge-ref workspace must not be proven from metadata `head_sha`; `WORKFLOW_HEAD_UNPROVEN` | PASS | Metadata trigger set to the candidate while HEAD was the merge commit: exit 1, `WORKFLOW_HEAD_UNPROVEN`. `prove_checkout` with `checkout_ref=refs/pull/12/merge` failed the same way. Pull-request event whose workspace was the trigger object also failed closed. |
| TD-D4-02 | Explicit SHA checkout; HEAD and tree match; `base_sha` recorded | PASS | Detached checkout of tip998. HEAD and tree matched. `workflow_proof` printed `base_sha=24d558e193be6225aa2bb71bde3a75a2f7851b78` and `WORKFLOW_HEAD_PROVEN`. |
| TD-D4-03 | CI `41325626443` is not a re-freeze basis | PASS | Helper returned false for `41325626443` and for context run `41329214806`. Module flags `G4_REFROZEN` and `RUNTIME_PASS` are false. This tester does not adopt either run. |
| TD-D4-04 | `HEAD^{tree}` mismatch → FAIL `WORKFLOW_HEAD_UNPROVEN` | PASS | HEAD was tip998, actual tree `62fd51cb…`, expected tree was the parent tree `443f3a3b…`. FAIL, `proven=false`. |
| TD-D4-05 | A workflow that adds apt/sudo/sysctl or git merge/rebase fails the spec check | PASS | Candidate `ci.yml` hits empty (product scanner and tester scanner). Injected apt/sudo/sysctl/`git merge`/`git rebase` text: spec check FAIL. Candidate still has explicit `ref` and `fetch-depth: 0`. |

Probe: `python3 artifacts/t176-tip998/probe/run_td_d1_d4.py` (exit 0). `python -m gates.selftest` was not run. pytest is not installed in this environment. The Dev STACK_OK count was not reused as evidence.
