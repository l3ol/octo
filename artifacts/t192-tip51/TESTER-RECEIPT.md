# TESTER-RECEIPT · TB t192 tip51

- receipt_id: `T192-TIP51-TESTER-2026-11-01`
- role: evidence-only Octo Tester
- at: `2026-11-01T16:55:21Z`
- candidate tip: `51a23ccd4f9efe7bafc759703997b01eccb04e13`
- tree: `babde0c3ac257f5d8ec1a2ec046e316f8a04ac5c`
- parent: `875836d57cf1f557bb71fc094025f72a084f44dc`
- tip047: `047923c15755e381697af699c7859b5df5d23eeb` (grandparent). Formal seal is stopped. This receipt does not seal tip047.

## 状态

`T192_TIP51_EVIDENCED_PARTIAL`

- `runtime_pass=false`
- `verification_pass` is not signed
- product PASS is not signed
- `merge=false`
- N11 is not complete
- GAP-01, GAP-02, GAP-03, GAP-04 stay OPEN
- STACK_OK is not PASS
- CI green is not PASS
- pytest green is not PASS
- pytest xfail is not PASS
- `PASS_EVIDENCE` and A2 mechanism `PASS` are row labels only
- tip047 is not sealed
- no product file was modified

## 结果

Independent probe on the pinned tip. 91 rows. No contract FAIL in the final probe.

| Verdict | Count | Meaning |
|---|---|---|
| MATCH | 71 | Observed value met that row's expectation |
| PASS | 6 | A2 mechanism checks held on a tester-made external store |
| PASS_EVIDENCE | 2 | NA-RO-03 and NA-RO-04 from the tip51 Ops bed |
| CLEARED | 1 | WAITING_OPS_TIP51 cleared by that tip51 bed |
| OPEN | 9 | Gaps and unbound A2 artifacts |
| CAPABILITY_GAP | 1 | This VM has no `bwrap` |
| CONTEXT | 1 | pytest, not acceptance |

DoD v1.1.1 A–E and the D4 hardcode contrasts held on this tip: N12 failure makes writeback `FAILED`; N12 success makes writeback `OK` while N11 stays `BLOCKED` and `run_standard` body stays `BLOCKED`; handoff follows the N11 envelope (`READY` / `NOT_READY` / `NOT_READY`) and the live run stays `NOT_READY` because no verified original exists. Same-store dedup suppresses the second call and a second process; a changed blocker notifies again; a different intent is not suppressed.

t187 negatives held: `ISSUER_SESSION_COLLISION`, wrong session/issuer `ISSUER_MISMATCH`, registry symlink and `..` / absolute path `PATH_ESCAPE` with no leaked bytes, `open_registry` reads `registry.json` through `_read_confined`. Empty registry is `EMPTY_REGISTRY` → N11 `BLOCKED`. A TEST_FIXTURE hit is `Found(test_only=true)` and N11 `BLOCKED` / `TEST_FIXTURE_ONLY`. A nonempty `source_evidence` on a `REVIEW_RECEIPT` is `EVIDENCE_UNVERIFIED`.

N10 held: fixed bytes keep one summary (`023ec624a31bb54fb5018eabfb1e72d2583177e19de5e8287809d7ee5b4188f6`); changed bytes change the summary (`96ff299e658dcedeaf95f703d5493ef534cfaa5e1bc4db43d4cd74a47cf8787d`); no grant is `AUTHORIZATION_REQUIRED`, dispatch 0, not `SUCCEEDED`.

NA-RO-03 and NA-RO-04 are PASS evidence from the tip51 Ops bed only. tip047's bed was not used. This VM did not re-execute that mount.

Local process isolation is `CAPABILITY_GAP`. `command -v bwrap` is empty. `apply_hardened_runner` returned `BWRAP_MISSING` with `runtime_pass=false`. The product test `test_hardened_runner_applies_proc_and_dev_contract` is xfailed. That xfail is not a pass. pytest finished `129 passed, 1 xfailed`, exit 0. That exit is not acceptance.

A2 mechanism checks on a tester-made store held (three-component digest recomputed independently, one-byte change moves runtime and fixture digests only, fail-closed rejects, `handoff_binding` returns `RECEIVED` with `runtime_pass=false` and writes no snapshot, `review_entry` refuses PASS). No Ops Grant/request/Receipt/log inventory is pinned to tip51 on this VM. No sealed `handoff_snapshot` is in the tree. Those two stay OPEN.

## 证据

Pin, read on this checkout:

- `git rev-parse HEAD` = `51a23ccd4f9efe7bafc759703997b01eccb04e13`
- `git rev-parse HEAD^{tree}` = `babde0c3ac257f5d8ec1a2ec046e316f8a04ac5c`
- `git rev-parse HEAD^` = `875836d57cf1f557bb71fc094025f72a084f44dc`

Spec bytes hashed before the run:

| Spec | sha256 |
|---|---|
| ALIGN-v1 | `61519a26ea70457e6e3ed396f262e33bd02a0a66cb9a8c84026d79071f55c1e5` |
| NEGATIVE-CASES (15) | `68be301daa3bb76f016b0fb1ebf3d15b9926aa01ac625f60caee870ac1b46322` |
| N11 INTERFACE | `c9341bf7b3c149655de865953d03f46c19377e4a796e606590ae590adfc9bebf` |
| N11 CASES | `cf651b3610580247ae70367fa54d5f123647b79cde1f0905ba3ca4e228342ad3` |
| DoD v1.1 | `eec603b74e032873facc0b7f02eb0a195c2578167c880867f10e6881eed18ada` |
| DoD v1.1.1 | `f921792c76b2f4f0d28ce41559212b0c51d7e7ca46c8f4c3069fa92c62362358` |
| TB Intake | `b98f5a5cc726b46542e4d49e2d5f6f34a63ea9ff2184177ce348a8ea0ed5bc78` |

Ops tip51 bed, hashed on this VM and matched to the stated digests:

| File | sha256 |
|---|---|
| ro_bind_proof.json | `21700f5fa8851659654b740976043b13023eea836569a2dd5f1a550337cf305f` |
| Ops Receipt MD | `0c33e6ced12fb9bb380091266994f571d11a6d984123ddf59395dda054743721` |
| Ops Receipt JSON | `dbb67fb8213f6c217bef6dec1e8cf012d7ab16ede305095974e10707735e8607` |

The proof pins this tip, tree, parent, and intake `b98f5a5c…`. Status in the proof is `RO_BIND_PROVEN`. The Ops receipt status is `RO_BIND_PROVEN_GAP04_STILL_OPEN`. Mechanism claim is `bwrap --ro-bind`, not chmod and not `os.access`. Guest mount is `--ro-bind` of `/home/box/ops-isolation/product/n11-trusted-original-root` onto `/trusted`. `statvfs_ST_RDONLY=true`. sha256 before and after match for `registry.json` (`d019f9c5cf72905427dac4571bd71052a1c6ac1c52c8fd1fb163243cdaec7c89`) and `originals/fixture-sample.txt` (`8ed407dc826fc62b23cbfce83d5c1839c2a69e20a322d3d294fcd96efaca73f8`). Production `registry.json` is `{"records":[]}`. `open_registry` under that mount reports `records_len=0`. The fixture file is not a registry record.

NA-RO-03 index and NA-RO-04 fixture original, four operations each, all `OSError`, all `ok=false`:

| op | errno | name |
|---|---|---|
| open_w | 30 | EROFS |
| os.replace | 18 | EXDEV |
| os.unlink | 30 | EROFS |
| os.rename | 30 | EROFS |

`os.replace` failed with `EXDEV` (cross-device link from `/iso/tmp` onto `/trusted`), not with `EROFS`. The replace did not land, and the sha256 values did not change. open, unlink, and rename failed with `EROFS`. This VM has no `/home/box` mount and no `bwrap`, so the bed was incorporated from the hash-matched proof. It was not re-executed here.

`ro_bind_assessment({"method":"bwrap"})` still returns `RO_BIND_UNPROVEN`. chmod without a read-only mount is `RO_BIND_UNPROVEN` even when `os.access(..., W_OK)` is false; that directory's `ST_RDONLY` flag was false. GAP-04 stays OPEN.

Local empty registry (outside the candidate tree, not the Ops mount): `Empty EMPTY_REGISTRY`, N11 `status=BLOCKED`, `verdict=BLOCKED`, note `EMPTY_REGISTRY no trusted reviewer registration`, evidence `runtime_pass=false`. Unset root and a writable root are `ROOT_UNAVAILABLE` and still `BLOCKED`.

CI context only, re-queried: run `41327702969` completed/success, `headSha` equals this tip. That match is not acceptance. Log: `logs/ci-41327702969.json`.

Probe command: `PYTHONDONTWRITEBYTECODE=1 python3 probe/t192_tip51_probe.py`. Probe exit 0 means the evidence write finished. It does not mean product PASS. Raw logs: `logs/`.

`git status --short` was empty after the probe and before these artifact files.

## Receipt

This file is the tester receipt for tip `51a23ccd4f9efe7bafc759703997b01eccb04e13`.

- It records evidence.
- It does not grant trust.
- It does not close GAP-01..04.
- It does not register a TEST_FIXTURE as a formal original.
- It does not seal tip047.
- It does not authorize merge.
- `runtime_pass` remains false.
- Full-file sha256 values for this directory are in `SHA256SUMS.txt` and in the tester report. This receipt does not embed its own digest.

Companion JSON: `TESTER-RECEIPT.json`.
