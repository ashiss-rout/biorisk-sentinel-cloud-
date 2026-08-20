"""Assessment creation and validation helpers."""

from extensions import db
from models import Assessment, AuditLog

ALLOWED_ENVIRONMENTS = (
    "Development",
    "Test",
    "Staging",
    "Production-simulation",
)

ALLOWED_BIOMETRIC_TYPES = (
    "Iris",
    "Fingerprint",
    "Face",
    "Voice",
    "Multi-modal",
    "Other",
)


def parse_yes_no(value: str) -> bool | None:
    """Return True/False for yes/no form values, or None when invalid."""
    normalized = (value or "").strip().lower()
    if normalized == "yes":
        return True
    if normalized == "no":
        return False
    return None


def validate_assessment_input(data: dict) -> tuple[dict | None, list[str]]:
    """Validate and normalize assessment metadata submitted from the creation form."""
    errors: list[str] = []

    organization_name = data.get("organization_name", "").strip()
    application_name = data.get("application_name", "").strip()
    environment = data.get("environment", "").strip()
    biometric_type = data.get("biometric_type", "").strip()

    if not organization_name:
        errors.append("Organisation name is required.")
    elif len(organization_name) > 255:
        errors.append("Organisation name must be 255 characters or fewer.")

    if not application_name:
        errors.append("Application name is required.")
    elif len(application_name) > 255:
        errors.append("Application name must be 255 characters or fewer.")

    if environment not in ALLOWED_ENVIRONMENTS:
        errors.append("Select a valid environment.")

    if biometric_type not in ALLOWED_BIOMETRIC_TYPES:
        errors.append("Select a valid biometric type.")

    mfa_enabled = parse_yes_no(data.get("mfa_enabled", ""))
    if mfa_enabled is None:
        errors.append("Select whether MFA is enabled.")

    liveness_enabled = parse_yes_no(data.get("liveness_enabled", ""))
    if liveness_enabled is None:
        errors.append("Select whether liveness detection is enabled.")

    admin_accessible = parse_yes_no(data.get("admin_accessible", ""))
    if admin_accessible is None:
        errors.append("Select whether the assessed system provides administrator access.")

    if errors:
        return None, errors

    return {
        "organization_name": organization_name,
        "application_name": application_name,
        "environment": environment,
        "biometric_type": biometric_type,
        "mfa_enabled": mfa_enabled,
        "liveness_enabled": liveness_enabled,
        "admin_accessible": admin_accessible,
    }, []


def create_assessment(assessor_id: int, data: dict) -> Assessment:
    """Persist a new assessment and record the creation in the audit log."""
    assessment = Assessment(assessor_id=assessor_id, **data)
    db.session.add(assessment)
    db.session.flush()

    audit_log = AuditLog(
        user_id=assessor_id,
        assessment_id=assessment.id,
        action="Created assessment",
    )
    db.session.add(audit_log)
    db.session.commit()
    return assessment
