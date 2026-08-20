"""Compatibility entry point for the teammate scoring prototype.

The Flask application uses :mod:`services.scoring` as its only scoring
implementation. The original teammate file was a top-level interactive script
with conflicting weights and risk thresholds; importing it prompted for input
and could not be used safely by the web application.

This module remains as a clear reference boundary for older coursework imports.
New application code must import the typed functions from ``services.scoring``.
"""

from services.scoring import (
    AttackInput,
    AttackResult,
    OverallResult,
    PrivacyInput,
    ReliabilityInput,
    ReliabilityResult,
    calculate_attack_resistance,
    calculate_overall,
    calculate_privacy,
    calculate_reliability,
)

__all__ = [
    "AttackInput",
    "AttackResult",
    "OverallResult",
    "PrivacyInput",
    "ReliabilityInput",
    "ReliabilityResult",
    "calculate_attack_resistance",
    "calculate_overall",
    "calculate_privacy",
    "calculate_reliability",
]
