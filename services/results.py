"""Assessment results, findings generation, and completion checks."""

from dataclasses import dataclass

from extensions import db
from models import Assessment, AuditLog, Finding
from services.attacks import REQUIRED_ATTACK_TYPES
from services.scoring import ReliabilityInput, calculate_overall, calculate_reliability

OVERRIDE_RECOMMENDATIONS = {
    "Biometric templates are not encrypted.": (
        "Missing template encryption",
        "Biometric templates are not encrypted at rest.",
        "Encrypt stored biometric templates with managed, rotated keys.",
    ),
    "Raw biometric data is stored.": (
        "Raw biometric data stored",
        "The assessed system stores raw biometric samples.",
        "Do not store raw biometric samples.",
    ),
    "Spoof detection is below 60%.": (
        "Low spoof detection",
        "Presentation-attack detection is below the 60% review threshold.",
        "Improve anti-spoof/presentation-attack detection.",
    ),
    "False acceptance rate is high while MFA is disabled.": (
        "High FAR without MFA",
        "False acceptance risk is elevated while MFA is disabled.",
        "Enable MFA where false-acceptance risk is elevated.",
    ),
    "Audit logging is missing for an admin-accessible system.": (
        "Missing audit logging",
        "The assessed system provides administrator access without audit logging.",
        "Enable and retain appropriate audit logs.",
    ),
}


@dataclass(frozen=True)
class AssessmentResults:
    reliability_score: float
    privacy_score: float
    attack_resistance_score: float
    far: float
    frr: float
    accuracy: float
    overall_score: float
    risk_level: str
    urgent_review_required: bool
    override_reasons: tuple[str, ...]
    findings: tuple[Finding, ...]


class IncompleteAssessmentError(Exception):
    """Raised when one or more assessment sections are missing."""


def sections_complete(assessment: Assessment) -> bool:
    """Return True when reliability, privacy, and all attack results are present."""
    if assessment.reliability_metrics is None or assessment.privacy_controls is None:
        return False

    recorded_types = {result.attack_type for result in assessment.attack_results}
    return all(attack_type in recorded_types for attack_type in REQUIRED_ATTACK_TYPES)


def missing_sections(assessment: Assessment) -> list[str]:
    """Return human-readable names for incomplete assessment sections."""
    missing: list[str] = []
    if assessment.reliability_metrics is None:
        missing.append("Reliability metrics")
    if assessment.privacy_controls is None:
        missing.append("Privacy controls")
    recorded_types = {result.attack_type for result in assessment.attack_results}
    if any(attack_type not in recorded_types for attack_type in REQUIRED_ATTACK_TYPES):
        missing.append("Attack resistance results")
    return missing


def get_spoof_detection_rate(assessment: Assessment) -> float | None:
    """Return the spoofing detection rate when that attack result exists."""
    for result in assessment.attack_results:
        if result.attack_type == "Spoofing":
            return result.detection_rate
    return None


def _severity_for_score(score: float) -> str:
    if score < 50:
        return "High"
    if score < 70:
        return "Medium"
    return "Low"


def _build_finding_specs(assessment: Assessment, overall_result) -> list[dict]:
    """Build finding records from scores, controls, and urgent-review overrides."""
    specs: list[dict] = []
    metrics = assessment.reliability_metrics
    privacy = assessment.privacy_controls
    reliability = calculate_reliability(
        ReliabilityInput(
            metrics.total_attempts,
            metrics.successful_attempts,
            metrics.failed_attempts,
            metrics.false_acceptances,
            metrics.false_rejections,
            metrics.genuine_attempts,
            metrics.impostor_attempts,
            metrics.average_response_time,
        )
    )

    for reason in overall_result.override_reasons:
        title, description, recommendation = OVERRIDE_RECOMMENDATIONS[reason]
        specs.append(
            {
                "severity": "Critical",
                "title": title,
                "description": description,
                "recommendation": recommendation,
            }
        )

    if reliability.score < 70:
        specs.append(
            {
                "severity": _severity_for_score(reliability.score),
                "title": "Reliability score below target",
                "description": (
                    f"Reliability score is {reliability.score:.2f} with FAR {reliability.far:.2f}% "
                    f"and FRR {reliability.frr:.2f}%."
                ),
                "recommendation": (
                    "Review authentication accuracy, false-acceptance resistance, "
                    "and false-rejection resistance."
                ),
            }
        )

    if privacy.privacy_score < 70:
        specs.append(
            {
                "severity": _severity_for_score(privacy.privacy_score),
                "title": "Privacy score below target",
                "description": f"Privacy controls score is {privacy.privacy_score:.2f}.",
                "recommendation": "Strengthen privacy and data-protection controls.",
            }
        )

    attack_score = round(
        sum(result.detection_rate for result in assessment.attack_results)
        / len(assessment.attack_results),
        2,
    )
    if attack_score < 70:
        specs.append(
            {
                "severity": _severity_for_score(attack_score),
                "title": "Attack resistance below target",
                "description": f"Attack resistance score is {attack_score:.2f}.",
                "recommendation": "Improve detection rates for authorized simulated attacks.",
            }
        )

    if metrics.average_response_time > 3:
        specs.append(
            {
                "severity": "Medium",
                "title": "Slow authentication response time",
                "description": (
                    f"Average response time is {metrics.average_response_time:.2f} seconds."
                ),
                "recommendation": "Investigate unusually slow authentication response times.",
            }
        )

    if not (
        privacy.retention_policy_exists
        and privacy.deletion_process_exists
        and privacy.consent_process_exists
    ):
        specs.append(
            {
                "severity": "Medium",
                "title": "Lifecycle controls need strengthening",
                "description": (
                    "One or more retention, deletion, or consent controls are missing "
                    "on the assessed system."
                ),
                "recommendation": "Strengthen retention, deletion, and consent controls.",
            }
        )

    return specs


def sync_findings(assessment: Assessment, finding_specs: list[dict]) -> list[Finding]:
    """Replace generated findings for an assessment."""
    Finding.query.filter_by(assessment_id=assessment.id).delete()
    findings: list[Finding] = []
    for spec in finding_specs:
        finding = Finding(assessment_id=assessment.id, status="open", **spec)
        db.session.add(finding)
        findings.append(finding)
    db.session.commit()
    return findings


def build_assessment_results(assessment: Assessment) -> AssessmentResults:
    """Compute overall scores and regenerate findings for a complete assessment."""
    if not sections_complete(assessment):
        raise IncompleteAssessmentError(", ".join(missing_sections(assessment)))

    metrics = assessment.reliability_metrics
    privacy = assessment.privacy_controls
    reliability = calculate_reliability(
        ReliabilityInput(
            metrics.total_attempts,
            metrics.successful_attempts,
            metrics.failed_attempts,
            metrics.false_acceptances,
            metrics.false_rejections,
            metrics.genuine_attempts,
            metrics.impostor_attempts,
            metrics.average_response_time,
        )
    )
    attack_resistance_score = round(
        sum(result.detection_rate for result in assessment.attack_results)
        / len(assessment.attack_results),
        2,
    )
    overall = calculate_overall(
        reliability.score,
        privacy.privacy_score,
        attack_resistance_score,
        template_encrypted=privacy.template_encrypted,
        raw_data_stored=privacy.raw_data_stored,
        spoof_detection_rate=get_spoof_detection_rate(assessment),
        far=reliability.far,
        mfa_enabled=assessment.mfa_enabled,
        audit_logging_enabled=privacy.audit_logging_enabled,
        admin_accessible=assessment.admin_accessible,
    )
    findings = sync_findings(assessment, _build_finding_specs(assessment, overall))

    return AssessmentResults(
        reliability_score=reliability.score,
        privacy_score=privacy.privacy_score,
        attack_resistance_score=attack_resistance_score,
        far=reliability.far,
        frr=reliability.frr,
        accuracy=reliability.accuracy,
        overall_score=overall.score,
        risk_level=overall.risk_level,
        urgent_review_required=overall.urgent_review_required,
        override_reasons=overall.override_reasons,
        findings=tuple(findings),
    )


def record_results_view(assessment: Assessment, user_id: int) -> AssessmentResults:
    """Generate results and write an audit log entry."""
    results = build_assessment_results(assessment)
    db.session.add(
        AuditLog(
            user_id=user_id,
            assessment_id=assessment.id,
            action="Generated assessment results",
        )
    )
    db.session.commit()
    return results
