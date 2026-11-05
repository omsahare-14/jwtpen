"""The Finding data model shared by every attack, plus the status and severity constants.

Each attack fills in a Finding as it runs, and the report reads it to render that attack's section.
"""

from dataclasses import dataclass, field


# Verdict for one attack.
VULNERABLE = "VULNERABLE"
NOT_VULNERABLE = "NOT_VULNERABLE"
INCONCLUSIVE = "INCONCLUSIVE"
SKIPPED = "SKIPPED"

# How serious a finding is, shown in the report.
HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"


@dataclass
class Finding:
    """One attack's result and everything the report needs to present it."""

    attack: str        # name of the attack
    status: str        # VULNERABLE / NOT_VULNERABLE / INCONCLUSIVE / SKIPPED
    severity: str      # HIGH / MEDIUM / LOW
    summary: str       # one-line result

    # default_factory (not "= []") so each Finding gets its own list rather than a shared one.
    methodology: list = field(default_factory=list)      # what the tool did, step by step
    reproduction: list = field(default_factory=list)     # manual steps to reproduce by hand
    manual_followup: list = field(default_factory=list)  # what to verify manually
    evidence: dict = field(default_factory=dict)         # forged token, request sent, proof
    remediation: str = ""                                # how to fix it
    references: list = field(default_factory=list)       # [{"label": str, "url": str}, ...]


# Report/UI order: confirmed problems first, then uncertain, then clean, then skipped.
_STATUS_ORDER = {VULNERABLE: 0, INCONCLUSIVE: 1, NOT_VULNERABLE: 2, SKIPPED: 3}


def sort_findings(findings):
    """Return the findings ordered most-to-least important (see _STATUS_ORDER).

    Python's sort is stable, so findings with the same status keep the order they were run in.
    """
    return sorted(findings, key=lambda f: _STATUS_ORDER.get(f.status, 99))
