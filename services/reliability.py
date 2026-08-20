"""Reliability metrics validation and persistence."""

from extensions import db
from models import Assessment, AuditLog, ReliabilityMetrics
from services.scoring import ReliabilityInput, calculate_reliability


def _parse_int_field(value: str, label: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a whole number.")


def _parse_float_field(value: str, label: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a number.")


def validate_reliability_input(data: dict) -> tuple[dict | None, list[str]]:
    """Parse form data, validate counts, and calculate reliability scores."""
    try:
        reliability_input = ReliabilityInput(
            total_attempts=_parse_int_field(data.get("total_attempts", ""), "Total attempts"),
            successful_attempts=_parse_int_field(
                data.get("successful_attempts", ""), "Successful attempts"
            ),
            failed_attempts=_parse_int_field(data.get("failed_attempts", ""), "Failed attempts"),
            false_acceptances=_parse_int_field(
                data.get("false_acceptances", ""), "False acceptances"
            ),
            false_rejections=_parse_int_field(
                data.get("false_rejections", ""), "False rejections"
            ),
            genuine_attempts=_parse_int_field(
                data.get("genuine_attempts", ""), "Genuine attempts"
            ),
            impostor_attempts=_parse_int_field(
                data.get("impostor_attempts", ""), "Impostor attempts"
            ),
            average_response_time=_parse_float_field(
                data.get("average_response_time", ""), "Average response time"
            ),
        )
        result = calculate_reliability(reliability_input)
    except ValueError as exc:
        return None, [str(exc)]

    return {"input": reliability_input, "result": result}, []


def save_reliability_metrics(
    assessment: Assessment, user_id: int, payload: dict
) -> ReliabilityMetrics:
    """Create or update reliability metrics for an assessment."""
    reliability_input = payload["input"]
    result = payload["result"]
    metrics = assessment.reliability_metrics
    is_update = metrics is not None

    if metrics is None:
        metrics = ReliabilityMetrics(assessment_id=assessment.id)
        db.session.add(metrics)

    metrics.total_attempts = reliability_input.total_attempts
    metrics.successful_attempts = reliability_input.successful_attempts
    metrics.failed_attempts = reliability_input.failed_attempts
    metrics.false_acceptances = reliability_input.false_acceptances
    metrics.false_rejections = reliability_input.false_rejections
    metrics.genuine_attempts = reliability_input.genuine_attempts
    metrics.impostor_attempts = reliability_input.impostor_attempts
    metrics.average_response_time = reliability_input.average_response_time
    metrics.reliability_score = result.score

    action = "Updated reliability metrics" if is_update else "Saved reliability metrics"
    db.session.add(
        AuditLog(
            user_id=user_id,
            assessment_id=assessment.id,
            action=action,
        )
    )
    db.session.commit()
    return metrics
