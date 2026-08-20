"""Assessment workspace routes."""

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from services.access import get_assessment_for_user, list_assessments_for_user
from services.assessment import (
    ALLOWED_BIOMETRIC_TYPES,
    ALLOWED_ENVIRONMENTS,
    create_assessment,
    validate_assessment_input,
)
from services.attacks import ATTACK_FORM_PREFIXES, REQUIRED_ATTACK_TYPES, save_attack_results, validate_attack_input
from services.privacy import PRIVACY_CONTROL_FIELDS, save_privacy_controls, validate_privacy_input
from services.reliability import save_reliability_metrics, validate_reliability_input
from services.results import missing_sections, record_results_view, sections_complete


assessments_bp = Blueprint("assessments", __name__, url_prefix="/assessments")


def _attack_form_values(assessment) -> dict[str, str]:
    """Build form defaults from saved attack results."""
    values: dict[str, str] = {}
    for result in assessment.attack_results:
        prefix = ATTACK_FORM_PREFIXES.get(result.attack_type)
        if prefix:
            values[f"{prefix}_attempts"] = str(result.attempts)
            values[f"{prefix}_detected"] = str(result.detected_or_blocked)
    return values


@assessments_bp.get("/")
@login_required
def index():
    """Show assessment history for the signed-in user."""
    assessments = list_assessments_for_user(current_user)
    completion = {assessment.id: sections_complete(assessment) for assessment in assessments}
    return render_template(
        "assessments/index.html",
        assessments=assessments,
        completion=completion,
    )


@assessments_bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    """Create a new fictional-system assessment."""
    if request.method == "POST":
        payload, errors = validate_assessment_input(request.form)
        if errors:
            for message in errors:
                flash(message, "error")
        else:
            assessment = create_assessment(current_user.id, payload)
            flash("Assessment created. Continue with reliability metrics.", "success")
            return redirect(url_for("assessments.reliability", assessment_id=assessment.id))

    return render_template(
        "assessments/new.html",
        environments=ALLOWED_ENVIRONMENTS,
        biometric_types=ALLOWED_BIOMETRIC_TYPES,
    )


@assessments_bp.route("/<int:assessment_id>/reliability", methods=["GET", "POST"])
@login_required
def reliability(assessment_id: int):
    """Capture aggregate reliability metrics for an assessment."""
    assessment = get_assessment_for_user(assessment_id, current_user)

    if request.method == "POST":
        payload, errors = validate_reliability_input(request.form)
        if errors:
            for message in errors:
                flash(message, "error")
        else:
            save_reliability_metrics(assessment, current_user.id, payload)
            flash("Reliability metrics saved. Continue with privacy controls.", "success")
            return redirect(url_for("assessments.privacy", assessment_id=assessment.id))

    return render_template(
        "assessments/reliability.html",
        assessment=assessment,
        metrics=assessment.reliability_metrics,
    )


@assessments_bp.route("/<int:assessment_id>/privacy", methods=["GET", "POST"])
@login_required
def privacy(assessment_id: int):
    """Capture privacy controls for the assessed fictional system."""
    assessment = get_assessment_for_user(assessment_id, current_user)

    if request.method == "POST":
        payload, errors = validate_privacy_input(request.form)
        if errors:
            for message in errors:
                flash(message, "error")
        else:
            save_privacy_controls(assessment, current_user.id, payload)
            flash("Privacy controls saved. Continue with attack resistance tests.", "success")
            return redirect(url_for("assessments.attacks", assessment_id=assessment.id))

    controls = assessment.privacy_controls
    control_values = (
        {field_name: getattr(controls, field_name) for field_name, _ in PRIVACY_CONTROL_FIELDS}
        if controls
        else {}
    )
    return render_template(
        "assessments/privacy.html",
        assessment=assessment,
        controls=controls,
        control_values=control_values,
        privacy_fields=PRIVACY_CONTROL_FIELDS,
    )


@assessments_bp.route("/<int:assessment_id>/attacks", methods=["GET", "POST"])
@login_required
def attacks(assessment_id: int):
    """Capture authorized simulated attack aggregate counts."""
    assessment = get_assessment_for_user(assessment_id, current_user)

    if request.method == "POST":
        payload, errors = validate_attack_input(request.form)
        if errors:
            for message in errors:
                flash(message, "error")
        else:
            save_attack_results(assessment, current_user.id, payload)
            flash("Attack resistance results saved. View the assessment results.", "success")
            return redirect(url_for("assessments.results", assessment_id=assessment.id))

    return render_template(
        "assessments/attacks.html",
        assessment=assessment,
        attack_types=REQUIRED_ATTACK_TYPES,
        attack_prefixes=ATTACK_FORM_PREFIXES,
        form_values=_attack_form_values(assessment),
    )


@assessments_bp.get("/<int:assessment_id>/results")
@login_required
def results(assessment_id: int):
    """Show composite scores, risk band, and generated findings."""
    assessment = get_assessment_for_user(assessment_id, current_user)

    if not sections_complete(assessment):
        flash(
            "Complete all assessment sections before viewing results: "
            + ", ".join(missing_sections(assessment)),
            "error",
        )
        return render_template(
            "assessments/results.html",
            assessment=assessment,
            incomplete=True,
            missing_sections=missing_sections(assessment),
        )

    results_data = record_results_view(assessment, current_user.id)
    return render_template(
        "assessments/results.html",
        assessment=assessment,
        incomplete=False,
        results=results_data,
    )


@assessments_bp.get("/<int:assessment_id>/report")
@login_required
def report(assessment_id: int):
    """Render a printable HTML report for a completed assessment."""
    assessment = get_assessment_for_user(assessment_id, current_user)

    if not sections_complete(assessment):
        flash(
            "Complete all assessment sections before generating a report: "
            + ", ".join(missing_sections(assessment)),
            "error",
        )
        return redirect(url_for("assessments.results", assessment_id=assessment.id))

    results_data = record_results_view(assessment, current_user.id)
    return render_template(
        "assessments/report.html",
        assessment=assessment,
        results=results_data,
    )
