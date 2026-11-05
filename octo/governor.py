"""Policy primitives adapted from Mac ``octo/governor.py``.

Source candidate sha256 ``099b757c1be7face0bf048510e11080dd21a5929d636a4e1d08ee8ebe2349d44``
(commit ``4caf7ea4``). Manifest decision: adapt into the product Router.

``ROUTES`` keeps the source integer tuples as primitives. They are not a
frozen PRD and they are not the S1 node sequence. The public action-type
Router is ``octo.router.route``.

``FULL_ACTIONS`` is the Full set (needs N6, N7, and full N9). ``LOCAL_ACTIONS``
remains the Mac local-write set used by ``Governor.check_action`` only. S1
does not route that set as Standard.

No request-supplied policy and no risk downgrade is accepted here.
"""

from types import MappingProxyType


POLICY = MappingProxyType({
    "default_ttl_hours": 8,
    "amount_limit": 0,
    "chat_text_authorizes": False,
    "builder_self_pass": "deny",
    "eval_write_by_builder": "deny",
    "journal_before_dispatch": True,
    "retry_on_unknown": "reconcile_first",
    "overwrite_original": "deny",
    "supersede_with_link": True,
})
ROUTES = MappingProxyType({
    "Fast": (1, 2, 10, 12),
    "Standard": (1, 2, 3, 4, 5, 8, 10, 11, 12, 13),
    "Full": tuple(range(1, 14)),
})
FULL_ACTIONS = frozenset({
    "delete",
    "publish",
    "payment",
    "production_change",
    "eval_change",
    "cross_account",
    "irreversible",
})
LOCAL_ACTIONS = frozenset({"object.create", "object.supersede"})


class Denied(ValueError):
    """A refusal with a stable, auditable reason."""


class Governor:
    """Mac denial helpers. Not the S1 action-type Router."""

    @staticmethod
    def check_action(action: str, actor: str, bound_actor: str) -> None:
        if actor != bound_actor:
            raise Denied("SUBJECT_MISMATCH")
        if action not in LOCAL_ACTIONS:
            raise Denied("ACTION_NOT_ALLOWLISTED")

    @staticmethod
    def check_outcome(obj: dict) -> None:
        if obj.get("kind") == "Outcome" and (
            obj.get("verifier_result", "NOT_RUN") != "NOT_RUN"
            or obj.get("verifier_identity") is not None
        ):
            raise Denied("VERIFIER_INGRESS_NOT_CONFIGURED")
