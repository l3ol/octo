"""Standard prefix: N1, N2, N3, N4, N5, N8.

The run metadata names N6 and N7 in ``scope_exclusions``. It does not build
envelopes for them. A route that is not OK yields no node envelopes.

Builder selftest support only.
"""

from __future__ import annotations

from typing import Any, Mapping

from octo.closing import run_n11, run_n12, run_n13
from octo.gateway import run_n10
from octo.n9 import run_n9
from octo.nodes import (
    EXCLUDED_NODE_IDS,
    emit_envelope,
    run_n1,
    run_n2,
    run_n3,
    run_n4,
    run_n5,
    run_n8,
    scope_exclusions,
)
from octo.router import route

PREFIX_NODE_IDS = ("N1", "N2", "N3", "N4", "N5", "N8")


def reject_excluded_envelopes(envelopes: list[dict]) -> None:
    for envelope in envelopes:
        if envelope.get("node_id") in EXCLUDED_NODE_IDS:
            raise RuntimeError("Standard run yielded an N6 or N7 envelope")
        if envelope.get("status") == "NOT_RUN_THIS_STAGE":
            raise RuntimeError("NOT_RUN_THIS_STAGE is not emitted as a Standard placeholder")


def run_prefix(route_request: Mapping[str, Any], pack: Mapping[str, Any], *, at: str) -> dict[str, Any]:
    """Run the Standard prefix after the action-type route."""
    decision = route(
        route_request,
        upgrade=bool(pack.get("upgrade", False)),
        upgrade_reason=str(pack.get("upgrade_reason", "")),
    )
    exclusions = scope_exclusions()
    body = {
        "status": decision.status,
        "envelopes": [],
        "scope_exclusions": exclusions,
        "decision": decision.to_dict(),
        "selftest": "builder",
    }
    if decision.status != "OK":
        return body
    envelopes = [
        run_n1(pack["n1"], at=at),
        run_n2(pack["n2"], at=at, bound=pack.get("n2_bound")),
        run_n3(pack["n3"], at=at),
        run_n4(pack["n4"], at=at, bound=pack.get("n4_bound")),
        run_n5(pack["n5"], at=at, bound=pack.get("n5_bound")),
        run_n8(pack["n8"], at=at),
    ]
    reject_excluded_envelopes(envelopes)
    if tuple(item["node_id"] for item in envelopes) != PREFIX_NODE_IDS:
        raise RuntimeError("Standard prefix node order drifted")
    body["envelopes"] = envelopes
    return body


def _guard_emitter() -> None:
    """Import-time proof that the shared emitter rejects N6 and N7."""
    try:
        emit_envelope(node_id="N6", at="2026-11-01T00:00:00+00:00", inputs={}, status="NOT_RUN_THIS_STAGE", output=None)
    except RuntimeError:
        return
    raise RuntimeError("N6 emitter guard failed")


_guard_emitter()


def _n9_inputs(request) -> dict:
    return {
        "action": request.action,
        "grant_id": request.grant_id,
        "request_digest": request.digest,
    }


def _n10_inputs(request, context_pack: dict) -> dict:
    return {
        "action": request.action,
        "grant_ref": request.grant_id,
        "context_pack": context_pack,
    }


def run_standard(route_request, pack, *, at: str, request, store, now=None) -> dict[str, Any]:
    """Full S1 run. N6 and N7 stay in scope_exclusions and are never envelopes."""
    body = run_prefix(route_request, pack, at=at)
    if body["status"] != "OK":
        return body
    gateway = pack["gateway"]
    envelopes = list(body["envelopes"])
    n9_env = run_n9(_n9_inputs(request), at=at, store=store, request=request, now=now)
    envelopes.append(n9_env)
    if n9_env["status"] != "OK":
        body["envelopes"] = envelopes
        body["status"] = n9_env["status"]
        reject_excluded_envelopes(envelopes)
        return body
    context_pack = {"intent_id": request.intent_id, "route": "internal_readonly"}
    n10_env = run_n10(
        _n10_inputs(request, context_pack),
        at=at,
        gateway=gateway,
        request=request,
        now=now,
    )
    envelopes.append(n10_env)
    if n10_env["status"] != "OK" or n10_env["output"] is None:
        body["envelopes"] = envelopes
        body["status"] = n10_env["status"]
        reject_excluded_envelopes(envelopes)
        return body
    n11_env = run_n11(
        {"candidate_sha": request.git_candidate_sha, "scope": {"route": "internal_readonly"}},
        at=at,
    )
    envelopes.append(n11_env)
    n12_env = run_n12(
        {
            "decisions": [],
            "evidence": [],
            "receipts": [{
                "receipt_id": n10_env["output"]["receipt_id"],
                "result": n10_env["output"]["result"],
            }],
            "failures": [],
        },
        at=at,
        store_root=store.root,
    )
    envelopes.append(n12_env)
    n13_env = run_n13(
        {
            "outcome": n10_env["output"]["result"],
            "verify_state": n11_env["output"]["verdict"],
            "writeback_state": "OK",
            "handoff_state": "NOT_READY",
        },
        at=at,
    )
    envelopes.append(n13_env)
    reject_excluded_envelopes(envelopes)
    body["envelopes"] = envelopes
    body["status"] = "OK"
    return body
