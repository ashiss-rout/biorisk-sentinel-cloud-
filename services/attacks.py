"""Authorized simulated attack validation and persistence."""

from extensions import db
from models import Assessment, AttackResult as AttackResultModel, AuditLog
from services.scoring import AttackInput, calculate_attack_resistance

REQUIRED_ATTACK_TYPES = (
    "Replay",
    "Spoofing",
    "Brute force",
    "Bypass",
    "Template-related",
)

ATTACK_FORM_PREFIXES = {
    "Replay": "replay",
    "Spoofing": "spoofing",
    "Brute force": "brute_force",
    "Bypass": "bypass",
    "Template-related": "template_related",
}


def _parse_int_field(value: str, label: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a whole number.")


def validate_attack_input(data: dict) -> tuple[dict | None, list[str]]:
    """Validate aggregate authorized simulated attack counts."""
    attack_inputs: list[AttackInput] = []

    try:
        for attack_type in REQUIRED_ATTACK_TYPES:
            prefix = ATTACK_FORM_PREFIXES[attack_type]
            attempts = _parse_int_field(
                data.get(f"{prefix}_attempts", ""),
                f"{attack_type} attempts",
            )
            detected = _parse_int_field(
                data.get(f"{prefix}_detected", ""),
                f"{attack_type} detected or blocked",
            )
            attack_inputs.append(AttackInput(attack_type, attempts, detected))

        score, results = calculate_attack_resistance(attack_inputs)
    except ValueError as exc:
        return None, [str(exc)]

    return {"inputs": attack_inputs, "score": score, "results": results}, []


def save_attack_results(assessment: Assessment, user_id: int, payload: dict) -> list[AttackResultModel]:
    """Replace attack results for an assessment with the latest validated counts."""
    is_update = bool(assessment.attack_results)
    existing_by_type = {result.attack_type: result for result in assessment.attack_results}

    saved_results: list[AttackResultModel] = []
    for attack_input, attack_result in zip(payload["inputs"], payload["results"], strict=True):
        model = existing_by_type.get(attack_input.attack_type)
        if model is None:
            model = AttackResultModel(assessment_id=assessment.id, attack_type=attack_input.attack_type)
            db.session.add(model)

        model.attempts = attack_input.attempts
        model.detected_or_blocked = attack_input.detected_or_blocked
        model.detection_rate = attack_result.detection_rate
        model.risk_level = attack_result.risk_level
        saved_results.append(model)

    action = "Updated attack resistance results" if is_update else "Saved attack resistance results"
    db.session.add(
        AuditLog(
            user_id=user_id,
            assessment_id=assessment.id,
            action=action,
        )
    )
    db.session.commit()
    return saved_results
