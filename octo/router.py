"""13-node Router, three tiers. Upgrade must record reason in Receipt."""
from enum import Enum

class Tier(Enum):
    FAST = "Fast"
    STANDARD = "Standard"
    FULL = "Full"

def select_tier(complexity: str, reason: str = "") -> tuple:
    """Select tier. Reason required for upgrade beyond Fast."""
    if complexity == "simple":
        return Tier.FAST, reason
    elif complexity == "single":
        return Tier.STANDARD, reason or "single decision/file"
    else:
        return Tier.FULL, reason or "multi-file or cross-milestone"
