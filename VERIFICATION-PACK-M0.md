# VERIFICATION-PACK-M0

**Status: DRAFT**

## Reviewer VERIFICATION_PASS (itemized evidence)

Dev 起草；**禁止自签 PASS**。下列条目 Evidence 供 Reviewer 逐项核验；Verdict 栏保持 PENDING／留空直至小队 Reviewer 填写。

### 1. R1 私有仓库（M0-S01）
- Evidence: `GET /repos/l3ol/octo` → `private=true`，`visibility=private`（采样时间 2026-11-01 ~03:11 Asia/Shanghai，Dev 旁证）。Repo URL: https://github.com/l3ol/octo
- Verdict: PENDING

### 2. R2 main 保护（M0-S02）
- Evidence: `GET /repos/l3ol/octo/branches/main` → `protected=false`；`protection.enabled=false`；`required_status_checks.enforcement_level=off`；contexts=[]。连接器侧无 ruleset／branch-protection **写入**工具；ruleset 名 `M0-main-protection`＝null（未建／不可由 Bot 启用）。
- 配置勾选表（目标态，当前均未满足）:

| 项 | 目标 | 实测 |
| --- | --- | --- |
| require PR | on | off（无保护） |
| status check `test` + strict | on | off |
| block force push | on | off／不可查 |
| 禁止删 main | on | off／不可查 |
| Required approvals | 0 | N/A（保护未启用） |

- **状态：BLOCKED_待 Founder** 在 GitHub Settings 启用 ruleset／classic protection（不得宣称 R2 已过）。
- Verdict: PENDING（Blocked until Founder）

### 3. R3 CI 工作流（M0-S03）
- Evidence: 路径 `.github/workflows/ci.yml` 存在于 `main`；含 job 名 `test`；raw: https://github.com/l3ol/octo/blob/main/.github/workflows/ci.yml ；main HEAD at旁证时 `44c9821d94f666e506e0f541cdd5cdbee504da89`
- Verdict: PENDING

### 4. R4 PR 模板（M0-S04）
- Evidence: 路径 `.github/pull_request_template.md` 存在于 `main`；raw: https://github.com/l3ol/octo/blob/main/.github/pull_request_template.md
- Verdict: PENDING

### 5. R5 CI 全绿本候选（M0-S05）
- Evidence: check name `test` conclusion success on tip `5e6e37cdd3375b29c16768b218ad8d90635ca964`. job: https://github.com/l3ol/octo/actions/runs/41233847282/job/124633368136 ; run: 41233847282. log anchor excerpt: `5 passed in 0.02s`.
- note: Tester independent verification M0-S05=CI_GREEN_BOUND_TIP (Dev only backfills uri; does not self-claim PASS).
- uri_or_hash: https://github.com/l3ol/octo/actions/runs/41233847282/job/124633368136
- Verdict: PENDING

### 6. R6 Dev 不能自合另采证（M0-S06）
- Evidence: **未执行**。前置 R2 未启用；按 Spec §2.2／§5：R2 未 on 时不得宣称 R6 已过；不以合并／关闭 PR#1 作为 R6 证据。
- uri_or_hash: null（待 R2=on 后另开探针采拒证）
- Verdict: PENDING

### 7. R7 本包路径（M0-S07）
- Evidence: 仓库根 `VERIFICATION-PACK-M0.md`（本文件）；Status=DRAFT；Independent verification=NOT_RUN。
- Verdict: PENDING

### 8. R9 共享电脑风险声明（M0-S08）
- Evidence: 见下方 `### Shared computer risk declaration`。
- Verdict: PENDING

### 9. PR#1 关闭（M0-S09）
- Evidence: https://github.com/l3ol/octo/pull/1 → `state=closed`；`merged_at=null`；关闭评论含 Spec §2.1 五点：https://github.com/l3ol/octo/pull/1#issuecomment-6547922388 ；关闭时间 API `closed_at=2026-10-31T19:12:10Z`（≈ 2026-11-01 03:12 Asia/Shanghai）。head 备查 `db50d4f5111e481a68b99e9ce91c555d1d7c9c18`。
- Verdict: PENDING

### 10. 无敏感数据
- Evidence: 本 PR 仅新增本 Markdown；无密钥／Mac／MEGA／客户数据。
- Verdict: PENDING

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

## Unfinished items
1. R2 main 保护：待 Founder 启用 ruleset `M0-main-protection` 或等价 classic protection（当前 `protection.enabled=false`）。
2. R6 另采证：待 R2=on 后执行 Spec §2.2（探针 merge/push 拒证；探针关闭不合并）。
3. Reviewer 逐项 VERIFICATION_PASS／BLOCKED；本包不得自签 PASS。Reviewer bus already returned BLOCKED (H2).
4. Founder 手合本 PR（H3）及后续铁律接口位（M0-IF07～IF10）— 非本 Dev 任务。

## Independent verification note
Independent verification = **NOT_RUN** in-repo until squad Reviewer. Dev／Spec 不得填写 VERIFICATION_PASS。
Reviewer bus already returned BLOCKED (H2). 本包不得自签 VERIFICATION_PASS。
