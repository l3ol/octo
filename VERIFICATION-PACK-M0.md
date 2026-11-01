# VERIFICATION-PACK-M0

**Status: FINAL (not draft). Unfinished items cleared.**

## Reviewer VERIFICATION_PASS (itemized evidence)

Verdict 栏引用 Reviewer Receipt `M0-T5b-REVIEWER-RERUN-2026-11-01`（total **VERIFICATION_PASS**；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`）。Dev 不自签 PASS。

### 1. R1 私有仓库（M0-S01）
- Evidence: Reviewer 本轮 `get_repository` → `private=false`，`visibility=public`（2026-11-01T11:45 Asia/Shanghai）。与 Spec「private=true」冲突。Founder 清除令 `M0-FOUNDER-R6-CLEARANCE-2026-11-01` sha256 `7bd34fe014a46fc61c3aad036d2424615dcba46327a7b5d240f29076e7500755` §3：**偏差已批**（不改冻结 PRD）。Repo URL: https://github.com/l3ol/octo
- uri_or_hash: 7bd34fe014a46fc61c3aad036d2424615dcba46327a7b5d240f29076e7500755
- Verdict: VERIFICATION_PASS（偏差已批）. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### 2. R2 main 保护（M0-S02）
- Evidence: Reviewer `get_branch(main)` → `protected=true`，`protection.enabled=true`，contexts=`["test"]`。ruleset `M0-main-protection` id `26235818` `enforcement=active`。rules: deletion；pull_request `required_approving_review_count=0`；required_status_checks context=`test` strict=true；non_fast_forward。API: https://api.github.com/repos/l3ol/octo/rulesets/26235818 ；HTML: https://github.com/l3ol/octo/rules/26235818 。对照 `M0-R2-RECHECK-2026-11-01`。

| 项 | 目标 | 实测 |
| --- | --- | --- |
| require PR | on | on |
| status check `test` + strict | on | on |
| block force push | on | on（`non_fast_forward`） |
| 禁止删 main | on | on（`deletion`） |
| Required approvals | 0 | 0 |

- uri_or_hash: https://api.github.com/repos/l3ol/octo/rulesets/26235818
- Verdict: VERIFICATION_PASS. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### 3. R3 CI 工作流（M0-S03）
- Evidence: `.github/workflows/ci.yml` 存在且含 job `test`（blob `e24ab09230ddb7f0308566b0b623dc49d94f8bf9` on main `18dfdfe2a2a198aa5902a59a971073f9d5a7ea9b`）。raw: https://github.com/l3ol/octo/blob/main/.github/workflows/ci.yml
- uri_or_hash: e24ab09230ddb7f0308566b0b623dc49d94f8bf9
- Verdict: VERIFICATION_PASS. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### 4. R4 PR 模板（M0-S04）
- Evidence: `.github/pull_request_template.md` 存在（blob `d1a85988edcd01a4f221c0a8b3c5933b32e0c99b` on main `18dfdfe2a2a198aa5902a59a971073f9d5a7ea9b`）。raw: https://github.com/l3ol/octo/blob/main/.github/pull_request_template.md
- uri_or_hash: d1a85988edcd01a4f221c0a8b3c5933b32e0c99b
- Verdict: VERIFICATION_PASS. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### 5. R5 CI 全绿本候选（M0-S05）
- Evidence: check name `test` conclusion=`success` on Candidate.HEAD `5e6e37cdd3375b29c16768b218ad8d90635ca964`. job: https://github.com/l3ol/octo/actions/runs/41233847282/job/124633368136 ; run: 41233847282. log anchor excerpt: `5 passed in 0.02s`. 不以无关历史绿勾冒充本候选。
- note: Tester independent verification M0-S05=CI_GREEN_BOUND_TIP. Dev 只回填 uri，不自签 PASS。
- uri_or_hash: https://github.com/l3ol/octo/actions/runs/41233847282/job/124633368136
- Verdict: VERIFICATION_PASS. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### 6. R6 Dev 不能自合另采证（M0-S06）
- Evidence: **主拒证（直推 `refs/heads/main`，无 PR）判过。** actor=`cursor[bot]`。对象 `refs/heads/main` ← probe tip `a0ad899f4007fb4d2442d88883aeb5a0e0aca7a9`。时间 2026-11-01T04:12:26+0800 Asia/Shanghai（git，exit 1）；同对象 `PATCH /repos/l3ol/octo/git/refs/heads/main`（`force=false`）于 2026-11-01T04:12:40+0800 Asia/Shanghai 返回 HTTP 422。拒绝原文含 `GH013: Repository rule violations found for refs/heads/main`，以及「Changes must be made through a pull request」与「Required status check "test" is expected」。记录评论: https://github.com/l3ol/octo/pull/5#issuecomment-6548596626
- **局限性（须写入本项）**：单身份下技术保护拦不住 Bot API merge。实证：PR#5 `merged=true`，`merged_by=cursor[bot]`，merge `18e3e58bdc7b1b4e131705b70b5f3c0e2f907ae8`，`merged_at=2026-10-31T20:13:22Z`。该次 HTTP 200 **不是** R6 通过证据，也不是拒证。流程禁合仍有效：Dev／Reviewer／Chief 永不调用 merge API；§7.2 合并只由 Founder 手点。
- 事故清除：PR#6 `merged=true`，`merged_by=l3ol`（Founder 手合），merge commit `18dfdfe2a2a198aa5902a59a971073f9d5a7ea9b`。main 干净：根路径 `m0-r6-probe.txt` 不存在。https://github.com/l3ol/octo/pull/6
- 不以合并 PR#1 或合并 PR#5 作为 R6 通过证据。
- uri_or_hash: https://github.com/l3ol/octo/pull/5#issuecomment-6548596626
- Verdict: VERIFICATION_PASS. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01（直推 GH013+HTTP 422 判过；局限性已记入）；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### 7. R7 本包路径（M0-S07）
- Evidence: 仓库根 `VERIFICATION-PACK-M0.md`（本文件）。Status=`FINAL (not draft). Unfinished items cleared.` 章节含 Candidate／Commits／Unfinished／Shared computer risk declaration。
- uri_or_hash: VERIFICATION-PACK-M0.md
- Verdict: VERIFICATION_PASS. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### 8. R9 共享电脑风险声明（M0-S08）
- Evidence: 见下方 `### Shared computer risk declaration`。含：同账号 Bot 共享一台云电脑；Bot 身份隔离 ≠ 凭证／文件隔离；本里程碑靠 GitHub＋CI＋Founder 合并权＋流程 Reviewer。禁止宣称「Bot 各自独立电脑、天然隔离」。
- uri_or_hash: null
- Verdict: VERIFICATION_PASS. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### 9. PR#1 关闭（M0-S09）
- Evidence: https://github.com/l3ol/octo/pull/1 → `state=closed`；`merged_at=null`；关闭评论含 Spec §2.1 五点：https://github.com/l3ol/octo/pull/1#issuecomment-6547922388 ；`closed_at=2026-10-31T19:12:10Z`。head 备查 `db50d4f5111e481a68b99e9ce91c555d1d7c9c18`。不以合并 PR#1 作为 M0／R6 证据。
- uri_or_hash: https://github.com/l3ol/octo/pull/1
- Verdict: VERIFICATION_PASS. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### 10. 无敏感数据
- Evidence: 本 PR 文件列表仅 `VERIFICATION-PACK-M0.md`；无密钥／Mac／MEGA／客户数据。
- uri_or_hash: null
- Verdict: VERIFICATION_PASS. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### 11. 范围一致（M0-S10）
- Evidence: 相对 main 的文件列表仅 `VERIFICATION-PACK-M0.md`。无 M1/M2 逻辑改动、无新产品功能、无 PRD 改写。
- uri_or_hash: null
- Verdict: VERIFICATION_PASS. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### 12. 证据可复核（M0-S11）
- Evidence: 上列各项含 uri_or_hash 或可重开链接（R5 job 124633368136；ruleset 26235818；PR#5 comment 6548596626）。Candidate.HEAD 钉死 `5e6e37cdd3375b29c16768b218ad8d90635ca964`，Tree SHA 钉死 `0fd133ec7c471be4c95add62a26c7d7676ea5a79`。其后仅改本 Markdown 的 PACK-align tip 不是第二 Candidate。
- uri_or_hash: 5e6e37cdd3375b29c16768b218ad8d90635ca964
- Verdict: VERIFICATION_PASS. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### 13. 无越界（M0-S12）
- Evidence: 本回写只改根目录 `VERIFICATION-PACK-M0.md`，并将 main `18dfdfe2a2a198aa5902a59a971073f9d5a7ea9b` 合并进 PR 分支以便不再 behind。未改产品代码、CI、M1/M2、PRD。未调用 merge API，未把 PR#4 合入 main。Receipt.scope_check=PASS。
- uri_or_hash: null
- Verdict: VERIFICATION_PASS. Reviewer Receipt M0-T5b-REVIEWER-RERUN-2026-11-01；verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai；receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`。Dev 不自签。

### Shared computer risk declaration
同账号 Bot 共享一台云电脑。Bot 身份隔离 ≠ 凭证／文件隔离。本里程碑靠 GitHub＋CI＋Founder 合并权＋流程 Reviewer（PRD v1.1 §7.7）。**禁止**宣称「Bot 各自独立电脑、天然隔离」。

## Candidate
- Branch: dev/m0-verification-pack
- HEAD: 5e6e37cdd3375b29c16768b218ad8d90635ca964
- Tree SHA: 0fd133ec7c471be4c95add62a26c7d7676ea5a79
- 验包／合并候选 tip = Candidate.HEAD（上列 SHA）。
- PR branch tip may be newer PACK-align commits that only edit this Markdown; those later tips are NOT a second Candidate.
- R5 remains bound to Candidate.HEAD via job 124633368136 / `5 passed in 0.02s`.

## Commits
- 3bda21e87a1c7496c9fc059359c53981b669564e
- 5e6e37cdd3375b29c16768b218ad8d90635ca964
- cda505dac7c2732a4b6315bbf1ee9012054a3591
- fee96e2d068bb0ecde2bacf5e31eefe1faa0c743
- 85d329e82290ab54a3ea8d9ac4a39a231a5d003a
- ece96a5073565bbc1e8c7d4ee4e8211b7e51cb0a
- b41d306d8beb649474ae674738afdf1d5de77cf0
- 3291d53cb66e5de049b84c7ef086b5c673a9c38c
- main update merged into this branch: 18dfdfe2a2a198aa5902a59a971073f9d5a7ea9b（不是第二 Candidate）

## Unfinished items
None. Cleared.

## Independent verification note
Reviewer T5b rerun: total **VERIFICATION_PASS**. receipt sha256 `5cac7c261004f734e13a970c08181c745b586a9b26674647c322906136b961b5`. verified_at 2026-11-01T11:46:02+0800 Asia/Shanghai. H2 NOT_HIT. next = H3 Founder hand-merge PR#4（https://github.com/l3ol/octo/pull/4）。Bot 不代合、不调用 merge API。Dev 不自签 VERIFICATION_PASS。
