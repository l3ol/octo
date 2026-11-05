"""t270 scope/handoff metadata. Builder selftest only. runtime_pass stays false."""
import json

from octo.g3_review import product_scope
from octo.scope_metadata import (
    A2_INVALIDATION_FIELDS,
    FORMAL_REVIEWER_ID,
    HISTORICAL_AGENT_ID,
    TIP_F95,
    TIP_F95_TREE,
    assess_freeze_order,
    assess_pass_after_rule_change,
    assess_product_scope,
    assess_scope_reviewer,
    assess_tip_seal,
    refuse_candidate_rewrite,
    register_external_inputs,
)


def _scope() -> dict:
    return json.loads(json.dumps(product_scope()))


def _pass_pair(**changes) -> tuple[dict, dict]:
    current = {
        "base_sha": "5443c9b4dde7fc208a0a72457c87904650829f77",
        "candidate_sha": "a" * 40,
        "scope_digest": "b" * 64,
        "fixture_digest": "c" * 64,
    }
    stored = {
        "decision": "PASS",
        "base_sha": current["base_sha"],
        "candidate_sha": current["candidate_sha"],
        "scope_digest": current["scope_digest"],
        "fixture_digest": current["fixture_digest"],
    }
    current.update(changes)
    return stored, current


def test_ac_t270_01_formal_reviewer_and_independence():
    scope = product_scope()
    result = assess_product_scope()
    assert result["ok"] is True
    assert result["reasons"] == []
    separation = scope["reviewer_separation"]
    assert separation["formal_reviewer_id"] == FORMAL_REVIEWER_ID
    assert separation["g3_reviewer_agent_id"] == FORMAL_REVIEWER_ID
    assert separation["g3_reviewer_agent_id"] != HISTORICAL_AGENT_ID
    assert separation["builder_may_sign_pass"] is False
    assert separation["g3_requires_reviewer_qualification_after_candidate_freeze"] is True
    assert separation["review_entry_issues_pass"] is False
    assert separation["squad_reviewer_prepares_entry_only"] is True
    assert separation["signature_migration_claimed"] is False
    note = separation["historical_reviewer_note"]
    assert note["prior_agent_id"] == HISTORICAL_AGENT_ID
    assert note["current_formal_reviewer"] is False
    assert note["signature_migration_claimed"] is False
    assert scope["handoff"]["formal_reviewer_id"] == FORMAL_REVIEWER_ID
    assert scope["handoff"]["signature_migration_claimed"] is False


def test_ac_t270_02_tip_f95_is_not_final():
    evidence = {
        "sha": TIP_F95,
        "tree": TIP_F95_TREE,
        "role": "mechanism_retest_evidence_only",
        "final_sha": False,
        "freeze_status": "NONFINAL_HOLD_AE",
    }
    assert assess_tip_seal(evidence)["reasons"] == []
    sealed = dict(evidence, final_sha=True, freeze_status="FINAL")
    assert "NONFINAL_FALSE_SEAL" in assess_tip_seal(sealed)["reasons"]
    scope = product_scope()
    assert scope["isolation_strategy"]["final_sha"] is False
    assert scope["isolation_strategy"]["freeze_status"] == "NONFINAL_HOLD_AE"
    assert scope["handoff"]["tip_f95_final"] is False
    assert scope["handoff"]["final_sha"] is False


def test_ac_t270_03_tuple_binds_after_static_bytes():
    ordered = assess_freeze_order([
        {"op": "commit_static", "includes_scope_reviewer": True, "includes_handoff": True},
        {"op": "bind_tuple", "static_bytes_committed": True, "tip": "successor"},
    ])
    assert ordered["ok"] is True
    assert ordered["reasons"] == []
    early = assess_freeze_order([
        {"op": "bind_tuple", "static_bytes_committed": False, "tip": "successor"},
    ])
    assert early["reasons"] == ["FREEZE_ORDER_VIOLATION"]


def test_ac_t270_04_rule_change_uses_a2_quadruple_only():
    stored, current = _pass_pair(scope_digest="d" * 64)
    result = assess_pass_after_rule_change(stored, current, still_accepted=False)
    assert result["reasons"] == []
    assert result["invalidation"]["status"] == "INVALID"
    assert result["invalidation"]["reasons"] == ["scope_digest"]
    assert result["invalidate_fields"] == list(A2_INVALIDATION_FIELDS)
    assert set(result["invalidation"]["reasons"]) <= set(A2_INVALIDATION_FIELDS)
    fixture_stored, fixture_current = _pass_pair(fixture_digest="e" * 64)
    fixture = assess_pass_after_rule_change(fixture_stored, fixture_current, still_accepted=False)
    assert fixture["invalidation"]["reasons"] == ["fixture_digest"]
    assert "rule_config" not in fixture["invalidation"]


def test_ac_t270_05_rule_config_and_custody_are_separate():
    registered = register_external_inputs([
        {
            "input_class": "rule_config",
            "issuer_allowlist": [FORMAL_REVIEWER_ID],
            "source_allowlist": ["6ae6216e-bbec-83e8-87dc-c3edd9027bcc"],
            "sha256": "a" * 64,
        },
        {
            "input_class": "reviewer_original_custody",
            "bytes_sha256": "b" * 64,
            "custody_ref": "custody/raw.json",
            "outside_candidate": True,
        },
    ])
    assert registered["ok"] is True
    assert registered["reasons"] == []
    assert registered["rule_config_log"] == [{
        "class": "rule_config",
        "sha256": "a" * 64,
        "issuer_allowlist": True,
        "source_allowlist": True,
    }]
    assert registered["custody_log"] == [{
        "class": "reviewer_original_custody",
        "bytes_sha256": "b" * 64,
        "outside_candidate": True,
        "not_issuer": True,
    }]
    assert registered["rule_config_log"][0]["class"] != registered["custody_log"][0]["class"]


def test_ac_t270_06_historical_agent_is_not_the_current_binding():
    stale = _scope()
    stale["reviewer_separation"]["formal_reviewer_id"] = HISTORICAL_AGENT_ID
    stale["reviewer_separation"]["g3_reviewer_agent_id"] = HISTORICAL_AGENT_ID
    stale["handoff"]["formal_reviewer_id"] = HISTORICAL_AGENT_ID
    stale["reviewer_separation"]["historical_reviewer_note"]["current_formal_reviewer"] = True
    result = assess_scope_reviewer(stale)
    assert result["ok"] is False
    assert "SCOPE_REVIEWER_STALE" in result["reasons"]
    sidenote = _scope()
    assert assess_scope_reviewer(sidenote)["reasons"] == []
    assert sidenote["reviewer_separation"]["historical_reviewer_note"]["prior_agent_id"] == HISTORICAL_AGENT_ID


def test_nc_t270_01_scope_reviewer_stale():
    scope = _scope()
    scope["reviewer_separation"].pop("formal_reviewer_id")
    scope["reviewer_separation"]["g3_reviewer_agent_id"] = HISTORICAL_AGENT_ID
    scope.pop("handoff")
    result = assess_scope_reviewer(scope)
    assert "SCOPE_REVIEWER_STALE" in result["reasons"]
    assert result["ok"] is False


def test_nc_t270_02_freeze_order_violation():
    result = assess_freeze_order([
        {"op": "mark_final", "tip": TIP_F95},
        {"op": "patch_scope", "tip": TIP_F95},
    ])
    assert "FREEZE_ORDER_VIOLATION" in result["reasons"]
    assert "NONFINAL_FALSE_SEAL" in result["reasons"]


def test_nc_t270_03_signature_migration_claim():
    scope = _scope()
    scope["handoff"]["signature_migration_claimed"] = True
    claimed = assess_scope_reviewer(scope)
    assert claimed["reasons"] == ["SIGNATURE_MIGRATION_CLAIM"]
    behalf = _scope()
    behalf["reviewer_separation"]["signed_on_behalf_of"] = HISTORICAL_AGENT_ID
    assert assess_scope_reviewer(behalf)["reasons"] == ["SIGNATURE_MIGRATION_CLAIM"]


def test_nc_t270_04_input_class_mixed():
    mixed = register_external_inputs([{
        "input_class": "temp_log",
        "issuer_allowlist": [FORMAL_REVIEWER_ID],
        "source_allowlist": ["session"],
        "custody_ref": "custody/raw.json",
        "bytes_sha256": "b" * 64,
        "sha256": "a" * 64,
    }])
    assert mixed["reasons"] == ["INPUT_CLASS_MIXED"]
    assert mixed["rule_config_log"] == []
    assert mixed["custody_log"] == []


def test_nc_t270_05_candidate_rewrite_forbidden():
    candidate = {"scope_bytes": "unchanged", "tree": TIP_F95_TREE}
    before = dict(candidate)
    refused = refuse_candidate_rewrite(candidate, {
        "rewrite_candidate": True,
        "purpose": "hash_cycle",
    })
    assert refused["reasons"] == ["CANDIDATE_REWRITE_FORBIDDEN"]
    assert candidate == before
    assert refused["candidate"] == before
    inside = register_external_inputs([{
        "bytes_sha256": "b" * 64,
        "custody_ref": "custody/raw.json",
        "inside_candidate": True,
        "purpose": "reconcile_hash",
    }])
    assert inside["reasons"] == ["CANDIDATE_REWRITE_FORBIDDEN"]
    assert inside["custody_log"] == []


def test_nc_t270_06_stale_pass():
    stored, current = _pass_pair(candidate_sha="f" * 40)
    kept = assess_pass_after_rule_change(stored, current, still_accepted=True)
    assert kept["reasons"] == ["STALE_PASS"]
    assert kept["invalidation"]["status"] == "INVALID"
    assert kept["invalidation"]["reasons"] == ["candidate_sha"]
    base_stored, base_current = _pass_pair(base_sha="1" * 40)
    base = assess_pass_after_rule_change(base_stored, base_current, still_accepted=True)
    assert base["invalidation"]["reasons"] == ["base_sha"]
    assert "STALE_PASS" in base["reasons"]


def test_nc_t270_07_independence_regressed():
    scope = _scope()
    scope["reviewer_separation"]["builder_may_sign_pass"] = True
    result = assess_scope_reviewer(scope)
    assert result["reasons"] == ["INDEPENDENCE_REGRESSED"]
    tb = _scope()
    tb["reviewer_separation"]["formal_reviewer_id"] = "TB"
    tb["reviewer_separation"]["g3_reviewer_agent_id"] = "TB"
    tb["handoff"]["formal_reviewer_id"] = "TB"
    regressed = assess_scope_reviewer(tb)
    assert "INDEPENDENCE_REGRESSED" in regressed["reasons"]
    assert "SCOPE_REVIEWER_STALE" in regressed["reasons"]


def test_nc_t270_08_nonfinal_false_seal():
    sealed = assess_tip_seal({
        "sha": TIP_F95,
        "final_sha": True,
        "treated_as_final_tuple": True,
        "role": "final_tuple",
    })
    assert sealed["reasons"] == ["NONFINAL_FALSE_SEAL"]
    order = assess_freeze_order([{"op": "false_seal", "tip": TIP_F95}])
    assert order["reasons"] == ["NONFINAL_FALSE_SEAL"]
    scope = _scope()
    scope["isolation_strategy"]["final_sha"] = True
    scope["isolation_strategy"]["freeze_status"] = "FINAL"
    assert "NONFINAL_FALSE_SEAL" in assess_scope_reviewer(scope)["reasons"]
