# TESTER-RECEIPT t176 tip998 negatives

## 状态
T176_TIP998_NEGATIVES_EVIDENCED

runtime_pass=false
verification_pass: not signed
g4_refrozen=false
merge=false
independent_acceptance=false
reviewer_pass=false
STACK_OK ≠ PASS
CI success ≠ PASS
tip51 product track: not touched
product code: not patched

REAL_ISO formal seal: not executed. Box is the authority. This cloud runner cannot see `/home/box`. No cloud twin was run. A cloud run, had one been started, would be labeled `TWIN_SUPPLEMENTARY` only.

## 结果
- Tip `998784b3e6cc0e6e6597cde76ce018331d924a72` MATCH `git rev-parse HEAD`
- Tree `62fd51cb0b31eeed130007201cfd36bbca081c44` MATCH `git rev-parse HEAD^{tree}`
- Parent `24d558e193be6225aa2bb71bde3a75a2f7851b78` MATCH `git rev-parse HEAD^`
- Parent tree observed `443f3a3bd72f92172f4f5e243fdaebfa429d90ac`
- TD-D1..D4 matrix: PASS 17, FAIL 0, OPEN 0
- `case_result=PASS` means the spec expectation for that negative held. It does not sign the tip.
- D3 plan B observed on this tip, recomputed here with hashlib, same bytes as the dev receipt figure: `config_digest=2feb73d01b2a717b0219253967770ad2da094dd137b918c4a3a35e1dd27ff59a`. That match is not acceptance.
- cff file unchanged: 4332 bytes, `cff01a57e38b16af6bc5545789949575b1cbcc3078cdf5bf3158cee4b56fd884`
- `python -m gates.selftest` was not run. pytest is not installed here. The Dev `passed=74` line was not reused.
- CI `41329214806` was read for context: `conclusion=success`, `headSha` equals the tip. Not acceptance.
- CI `41325626443` was not adopted. It is not G4 re-freeze evidence.
- Ops bed state cited by dispatch: `BED_READY_TIP998_FOR_TESTER_REAL_ISO`. `WAITING_OPS_TIP998` is lifted for the box. This runner still has `ops_root_visible=false`.

### OPEN
TD-D1..D4: none.

Not closed, and not a negative-case FAIL:
- Box REAL_ISO. Capability gap `OPS_BED_BOX_LOCAL_ONLY` and `PIN_NOT_PREMATERIALIZED`.
- Ops READY / CONFIRM / CURRENT files were not in this workspace, so those sha256 values were not recomputed here.
- Launch file `287cfe82…` was not in this workspace, so that sha256 was not recomputed here.

## 证据
Probe `artifacts/t176-tip998/probe/run_td_d1_d4.py` against the tip998 checkout. Disposable git beds under `/tmp/tip998-td-bed`. The product worktree was only read, plus one explicit `git clone --shared` into `/tmp` for TD-D4-02. After the probe, `git status` showed no tracked product diff. HEAD and tree were unchanged.

Bindings recomputed in this run:

| document | sha256 | result |
|---|---|---|
| Intake authority (upload `T176-TIP998-INTAKE-2026-11-02_7c03.md`) | `210efeddc4b5e32305a973dfac7a421c6cdb33d8fd67ebdcee652de1d7376dd9` | MATCH |
| Intake correction note | `663349c1390792091288dfa95311c1cd70337a73e48114727daa634035391199` | MATCH |
| Spec v1 | `7028b79b0db613f84502bc8b82a29b4f186f4cc68119211a88038354a5d8f695` | MATCH |
| Negative cases | `bf94feb7efd71498ff7713200484c3bc5d12590e7df06f5d61bcd88782b62092` | MATCH |
| Dev receipt | `c8662bbdc3b64ab643cc5ef3557190acace3538d42127548f323de3f4ff9ab21` | MATCH |
| Dispatch | `549d43be853c3868e3598b7c5b5a0e04e752309f261f7715039fc63d565561dc` | MATCH |
| Prior intake `3e5c4734…` | void | not authority |
| Prior intake `cead9014…` | void | not authority |
| Launch `287cfe82a06a9d92ec5fb025b79a3877125a133c7575cc33f0a2ab12c9e04e23` | cited | file absent, not recomputed |
| READY MD `4203567ff7fecbaa1d773b3994d1b0ff1f6af896685533cd32e07527ae8bee87` | cited | file absent, not recomputed |
| READY JSON `186a3481da1c375950aa761e3cbc49c998861e4551013a207c33ad917bfa5341` | cited | file absent, not recomputed |
| CONFIRM MD `ffe9fddcf4c2bb2960add4ce8b24a6c94a457656e9a9ddcc1efcd0fdcff7be4e` | cited | file absent, not recomputed |
| CONFIRM JSON `f94e73fe8f8ca858d362cb039a60d1d50268637e85590d0e1535adf7a9833d18` | cited | file absent, not recomputed |
| CURRENT.json `94199445d88a4de21484f4f613433532f1f762ea87d410d3c37c5ed1340988b6` | cited | file absent, not recomputed |

Evidence file sha256 (full file, frozen before this receipt):

| file | sha256 |
|---|---|
| `TC-MATRIX.md` | `70ea00ae21c2772c48263e513213d620371d0b4bb44d028913e3a6165a3c01a4` |
| `logs/td-d1-d4-observations.json` | `71ba828ca1bf1d02be95b79d845a4e8de7f76b996533fa35bfdbc22a8e08aa98` |
| `logs/probe-transcript.txt` | `11349df54cf1e191cf8eaf350d937e6a8f298098ddf930543ffefaa775b1e3db` |
| `probe/run_td_d1_d4.py` | `c732055e0f2fb40271dc6e86d7bb4758d1e435f93356a88635bf04eac1daf2c9` |
| `decisions/TD-D1-01.json` | `ac0f81e53f5a76051791d891e0ce8b74183140067216b76b3cc15b0294eca5b8` |
| `decisions/TD-D1-02.json` | `08286c86c92ad6c142207bc4494df11756cdba40995713dd96bbd4bc04dfdd30` |
| `decisions/TD-D1-03.json` | `4fb8dd39b9a1f9484963943bd9a7478d4c8e64eefd38e1c72715885b51306b4b` |
| `decisions/TD-D1-04.json` | `fe2662f91cb5f07211a0c0f62b1cbcda3d6b7bbee125968e5400c8d011d86e9c` |
| `decisions/TD-D2-01.json` | `c4e7e7107053c6cbf60ba245843d80b33259928e02bfee1af618f953562511ab` |
| `decisions/TD-D2-02.json` | `d0f272d93775faea2ccc75b3f837204ae9b59951df40e76a6869be190b190094` |
| `decisions/TD-D2-03.json` | `2c7259ac0095c7f11434a476aab93c1023f9286522076890f23b53923c5669b0` |
| `decisions/TD-D2-04.json` | `216ea510047ee843ab1c4a01c7768c4c2059bbc423aa0d8815b8d2a2014e34cb` |
| `decisions/TD-D3-01.json` | `3dfebdceaba2a2c0d7b2c73948215505374dcad60663e7fb9f3218977163ed09` |
| `decisions/TD-D3-02.json` | `ac82f7f5736665bf7464422be7bdf15577501da31eaad408c8093a9861c9b474` |
| `decisions/TD-D3-03.json` | `b6530f71e60c7758707a3bf85cd2a2e93da92a9e3a04e0d6a49ffef2ce09212b` |
| `decisions/TD-D3-04.json` | `f78dd0716b50b044214de36ca495c1f7e1897d0ed2c6cf93249f3d6960a48812` |
| `decisions/TD-D4-01.json` | `4a6718f72db791ecd3757f3ac26ba82e421faa810d902001c11d16cc4ca79f17` |
| `decisions/TD-D4-02.json` | `91fbb598955d653227b56f5657feeef651c542f3220666187e525f3f52ffb591` |
| `decisions/TD-D4-03.json` | `ac0fe4b339d6fd2968b73d3e4f46170aa51ac764146ddbdd9a64ade2e798d143` |
| `decisions/TD-D4-04.json` | `1ee98d5bb29759ba0f147a620efa33ab0a2eff4b094df510581dba5b5514e2d1` |
| `decisions/TD-D4-05.json` | `08df8de4cb7f5ef6681109d87565ceded36eab0ba68a1cef8ba5fde606ea5736` |

## Receipt
This file. `runtime_pass=false`. No G4 re-freeze. No merge. CI is not PASS. STACK_OK is not PASS. tip51 was not modified. Box REAL_ISO remains the authority and was not observed from this runner.
