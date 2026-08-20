"""Privacy controls validation and persistence."""

from extensions import db
from models import Assessment, AuditLog, PrivacyControls
from services.assessment import parse_yes_no
from services.scoring import PrivacyInput, calculate_privacy

PRIVACY_CONTROL_FIELDS = (
    ("template_encrypted", "Biometric templates encrypted"),
    ("tls_enabled", "TLS enabled in transit"),
    ("raw_data_stored", "Raw biometric data stored"),
    ("access_control_enabled", "Access control enabled"),
    ("audit_logging_enabled", "Audit logging enabled"),
    ("retention_policy_exists", "Retention policy exists"),
    ("deletion_process_exists", "Deletion process exists"),
    ("consent_process_exists", "Consent process exists"),
    ("secure_key_management", "Secure key management"),
    ("security_review_completed", "Security review completed"),
)


def validate_privacy_input(data: dict) -> tuple[dict | None, list[str]]:
    """Validate yes/no privacy control answers for the assessed fictional system."""
    errors: list[str] = []
    values: dict[str, bool] = {}

    for field_name, label in PRIVACY_CONTROL_FIELDS:
        parsed = parse_yes_no(data.get(field_name, ""))
        if parsed is None:
            errors.append(f"Select yes or no for {label}.")
        else:
            values[field_name] = parsed

    if errors:
        return None, errors

    privacy_input = PrivacyInput(**values)
    score = calculate_privacy(privacy_input)
    return {"input": privacy_input, "score": score}, []


def save_privacy_controls(assessment: Assessment, user_id: int, payload: dict) -> PrivacyControls:
    """Create or update privacy controls for an assessment."""
    privacy_input = payload["input"]
    score = payload["score"]
    controls = assessment.privacy_controls
    is_update = controls is not None

    if controls is None:
        controls = PrivacyControls(assessment_id=assessment.id)
        db.session.add(controls)

    controls.template_encrypted = privacy_input.template_encrypted
    controls.tls_enabled = privacy_input.tls_enabled
    controls.raw_data_stored = privacy_input.raw_data_stored
    controls.access_control_enabled = privacy_input.access_control_enabled
    controls.audit_logging_enabled = privacy_input.audit_logging_enabled
    controls.retention_policy_exists = privacy_input.retention_policy_exists
    controls.deletion_process_exists = privacy_input.deletion_process_exists
    controls.consent_process_exists = privacy_input.consent_process_exists
    controls.secure_key_management = privacy_input.secure_key_management
    controls.security_review_completed = privacy_input.security_review_completed
    controls.privacy_score = score

    action = "Updated privacy controls" if is_update else "Saved privacy controls"
    db.session.add(
        AuditLog(
            user_id=user_id,
            assessment_id=assessment.id,
            action=action,
        )
    )
    db.session.commit()
    return controls
