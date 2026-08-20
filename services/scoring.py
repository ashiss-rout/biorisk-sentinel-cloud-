"""Pure, deterministic scoring functions for BioRisk Sentinel.

These weights are project-defined for a student prototype. They are not a
banking or biometric-security standard and are deliberately kept here, rather
than hidden in route code, so they can be reviewed and changed transparently.
"""

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ReliabilityInput:
    total_attempts: int
    successful_attempts: int
    failed_attempts: int
    false_acceptances: int
    false_rejections: int
    genuine_attempts: int
    impostor_attempts: int
    average_response_time: float


@dataclass(frozen=True)
class ReliabilityResult:
    far: float
    frr: float
    accuracy: float
    score: float


@dataclass(frozen=True)
class PrivacyInput:
    template_encrypted: bool
    tls_enabled: bool
    raw_data_stored: bool
    access_control_enabled: bool
    audit_logging_enabled: bool
    retention_policy_exists: bool
    deletion_process_exists: bool
    consent_process_exists: bool
    secure_key_management: bool
    security_review_completed: bool


@dataclass(frozen=True)
class AttackInput:
    attack_type: str
    attempts: int
    detected_or_blocked: int


@dataclass(frozen=True)
class AttackResult:
    attack_type: str
    detection_rate: float
    risk_level: str


@dataclass(frozen=True)
class OverallResult:
    score: float
    risk_level: str
    urgent_review_required: bool
    override_reasons: tuple[str, ...]


def _percentage(numerator: int, denominator: int, label: str) -> float:
    if denominator <= 0:
        raise ValueError(f"{label} must be greater than zero.")
    return numerator / denominator * 100


def _score_response_time(seconds: float) -> float:
    if seconds < 0:
        raise ValueError("Average response time cannot be negative.")
    if seconds <= 1:
        return 100.0
    if seconds <= 2:
        return 90.0
    if seconds <= 3:
        return 75.0
    if seconds <= 5:
        return 50.0
    return 25.0


def calculate_reliability(data: ReliabilityInput) -> ReliabilityResult:
    """Calculate biometric reliability metrics and the project reliability score.

    Score composition: 45% accuracy, 30% FAR resistance, 20% FRR resistance,
    and 5% response time. FAR receives a steep penalty (30 points per 1% FAR)
    because an unauthorized acceptance is especially serious in financial use.
    """
    counts = (
        data.total_attempts,
        data.successful_attempts,
        data.failed_attempts,
        data.false_acceptances,
        data.false_rejections,
        data.genuine_attempts,
        data.impostor_attempts,
    )
    if any(value < 0 for value in counts):
        raise ValueError("Authentication counts cannot be negative.")
    if data.successful_attempts + data.failed_attempts != data.total_attempts:
        raise ValueError("Successful and failed attempts must equal total attempts.")
    if data.genuine_attempts + data.impostor_attempts != data.total_attempts:
        raise ValueError("Genuine and impostor attempts must equal total attempts.")
    if data.false_acceptances > data.impostor_attempts:
        raise ValueError("False acceptances cannot exceed impostor attempts.")
    if data.false_rejections > data.genuine_attempts:
        raise ValueError("False rejections cannot exceed genuine attempts.")

    far = _percentage(data.false_acceptances, data.impostor_attempts, "Impostor attempts")
    frr = _percentage(data.false_rejections, data.genuine_attempts, "Genuine attempts")
    accuracy = _percentage(data.successful_attempts, data.total_attempts, "Total attempts")

    far_quality = max(0.0, 100.0 - (far * 30.0))
    frr_quality = max(0.0, 100.0 - frr)
    response_quality = _score_response_time(data.average_response_time)
    score = (accuracy * 0.45) + (far_quality * 0.30) + (frr_quality * 0.20) + (response_quality * 0.05)

    return ReliabilityResult(
        far=round(far, 2), frr=round(frr, 2), accuracy=round(accuracy, 2), score=round(score, 2)
    )


def calculate_privacy(data: PrivacyInput) -> float:
    """Return the weighted privacy-controls score out of 100."""
    points = (
        (data.template_encrypted, 15),
        (data.tls_enabled, 10),
        (not data.raw_data_stored, 15),
        (data.access_control_enabled, 10),
        (data.audit_logging_enabled, 10),
        (data.retention_policy_exists, 10),
        (data.deletion_process_exists, 10),
        (data.consent_process_exists, 10),
        (data.secure_key_management, 5),
        (data.security_review_completed, 5),
    )
    return float(sum(weight for enabled, weight in points if enabled))


def calculate_attack_resistance(attacks: Iterable[AttackInput]) -> tuple[float, list[AttackResult]]:
    """Calculate an equal-weighted mean detection rate and per-attack results."""
    attacks = list(attacks)
    if not attacks:
        raise ValueError("At least one authorized simulated attack result is required.")

    results: list[AttackResult] = []
    for attack in attacks:
        if not attack.attack_type.strip():
            raise ValueError("Attack type is required.")
        if attack.attempts <= 0:
            raise ValueError("Attack attempts must be greater than zero.")
        if not 0 <= attack.detected_or_blocked <= attack.attempts:
            raise ValueError("Detected or blocked attacks must be between zero and attempted attacks.")
        rate = _percentage(attack.detected_or_blocked, attack.attempts, "Attack attempts")
        risk_level = "Low" if rate >= 95 else "Medium" if rate >= 85 else "High"
        results.append(AttackResult(attack.attack_type, round(rate, 2), risk_level))

    score = round(sum(result.detection_rate for result in results) / len(results), 2)
    return score, results


def calculate_overall(
    reliability_score: float,
    privacy_score: float,
    attack_resistance_score: float,
    *,
    template_encrypted: bool,
    raw_data_stored: bool,
    spoof_detection_rate: float | None,
    far: float,
    mfa_enabled: bool,
    audit_logging_enabled: bool,
    admin_accessible: bool = False,
) -> OverallResult:
    """Combine scores and apply transparent urgent-review override conditions."""
    scores = (reliability_score, privacy_score, attack_resistance_score)
    if any(not 0 <= score <= 100 for score in scores):
        raise ValueError("All component scores must be between 0 and 100.")

    score = round((reliability_score * 0.35) + (privacy_score * 0.30) + (attack_resistance_score * 0.35), 2)
    risk_level = "Low" if score >= 85 else "Medium" if score >= 70 else "High" if score >= 50 else "Critical"

    overrides = []
    if not template_encrypted:
        overrides.append("Biometric templates are not encrypted.")
    if raw_data_stored:
        overrides.append("Raw biometric data is stored.")
    if spoof_detection_rate is not None and spoof_detection_rate < 60:
        overrides.append("Spoof detection is below 60%.")
    if far >= 1 and not mfa_enabled:
        overrides.append("False acceptance rate is high while MFA is disabled.")
    if admin_accessible and not audit_logging_enabled:
        overrides.append("Audit logging is missing for an admin-accessible system.")

    return OverallResult(score, risk_level, bool(overrides), tuple(overrides))
