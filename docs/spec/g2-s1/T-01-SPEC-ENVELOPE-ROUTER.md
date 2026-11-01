# T-01 Spec — Common Node Envelope + Action-Type Router (G2-S1 TB-01)

Status: SPEC (paper). Implementation target branch: `dev/product-s1-standard-loop` (base 5443c9b4). This spec does NOT change any PRD field.

Basis (frozen, sha256-verified; physical location `/home/box/sand-data/agents/cee5d02e-69bc-4878-8d08-a232d986184d/prd/product-v1.0/`):
- io13 `Octo-产品PRD-v1.0-13节点IO.md` 27f3378e… §0 通用约定, 降级矩阵
- P0 Lite `continuum-p0-lite-design.md` 5a714511… §6.1 三档定义, §6.2 路由与升级规则 (cited by io13 §0)
- A2-FINAL-BINDING f08338f9…, CCI 958fa84d…

## 1. Common envelope
io13 §0: "每个节点输出必须带 `node_id`、`at`、`inputs_hash`（输入摘要），可追溯、可重算。"

Fields: `node_id` (N1..N13), `at` (ISO-8601 with offset; excluded from hash), `inputs` (actual input object), `inputs_hash` = sha256(canonical_json(inputs)) — canonical: UTF-8, recursive sort_keys, separators (",",":"), ensure_ascii=False, no trailing newline (A2-2), `status`, `output` (node-frozen schema per io13; null when status is a degrade/stop state).

Allowed `status`: OK, and only io13 §0 / 降级矩阵 states: PARTIAL, NEEDS_CLARIFICATION, BLOCKED, AUTHORIZATION_REQUIRED, SOURCE_UNAVAILABLE. Plus stage marker NOT_RUN_THIS_STAGE (N6/N7 only, output null, never fabricated). Forbidden: DEGRADED_SKIP_N6N7, DEGRADED_SKIP_*, any other invented state.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "octo/node-envelope.schema.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["node_id","at","inputs","inputs_hash","status","output"],
  "properties": {
    "node_id": {"enum": ["N1","N2","N3","N4","N5","N6","N7","N8","N9","N10","N11","N12","N13"]},
    "at": {"type": "string", "format": "date-time"},
    "inputs": {"type": "object"},
    "inputs_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "status": {"enum": ["OK","PARTIAL","NEEDS_CLARIFICATION","BLOCKED","AUTHORIZATION_REQUIRED","SOURCE_UNAVAILABLE","NOT_RUN_THIS_STAGE"]},
    "output": {"type": ["object","null"]}
  },
  "allOf": [
    {"if": {"properties": {"status": {"const": "NOT_RUN_THIS_STAGE"}}},
     "then": {"properties": {"node_id": {"enum": ["N6","N7"]}, "output": {"type": "null"}}}}
  ]
}
```
Validators must also recompute inputs_hash and reject mismatch.

## 2. Action types and tiers (quoted, not modified)
P0 Lite §6.1:
| 档位 | 适用 | 必跑节点 |
|---|---|---|
| Fast | 只读查询、解释、草稿、无外部副作用 | 1,2,10,12 |
| Standard | 可回滚的写操作、项目内交付、常规开发 | Fast + 3,4,5,8,11,13 |
| Full | 删除、发布、付款、改生产、改 Eval、跨账号数据、不可逆动作 | 全部 13 节点 |

io13 §0: "Router 按**动作类型**定档，不按语气定档；升档补节点，降档只能 Founder 批。"
io13 N9: "Full 档必跑；Standard/ Fast 涉及有后果动作时强制升档。"
P0 Lite §6.2: "Worker 自报低风险不构成降档理由" / "执行中发现动作实际涉及更高风险面…立即升档，补齐缺失节点后才能继续；降档只能由 Founder 在批准入口确认。"

Upgrade rules: (U1) tier = f(action_type) only. (U2) discovered higher risk → upgrade, fill missing nodes before continuing. (U3) downgrade only via Founder approval entry; Worker self-report ignored. (U4) S1 scope (CCI): Standard internal_readonly + N9_MINIMAL_SAFETY_PRECHECK before N10.

## 3. Router contract (S1)
- Input: `{action_type, grant_ref?}`. No `complexity` field, no complexity compatibility mapping; unknown extra routing fields rejected.
- action_type ∈ Standard set implemented in S1 → route N1,N2,N3,N4,N5,N8,N9_MIN,N10,N11,N12,N13.
- action_type maps to Full (needs N6/N7/full N9) or unknown action_type → `BLOCKED` (io13 降级矩阵 "关键前置缺失 → BLOCKED，通知一次"); Standard run stops; no partial skip.
- Upgrade triggered mid-run → BLOCKED in S1 (Full not implemented).
- N9 precheck lacks valid grant/authorization → `AUTHORIZATION_REQUIRED` with grant scope draft (io13 N9 降级), no execution.
- Forbidden: DEGRADED_SKIP_N6N7 or any invented state; using N6 output as N8.options (N8.options = CCI.execution_options).

## 4. scope_check
- No production/main changes; no Path B; no merge/deploy; no PRD change. Spec + schema only.
