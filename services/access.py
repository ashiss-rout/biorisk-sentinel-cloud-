"""Assessment access control helpers."""

from flask import abort

from extensions import db
from models import Assessment, User


def get_assessment_for_user(assessment_id: int, user: User) -> Assessment:
    """Return an assessment the signed-in user may access, or abort."""
    assessment = db.session.get(Assessment, assessment_id)
    if assessment is None:
        abort(404)

    if user.role == "admin" or assessment.assessor_id == user.id:
        return assessment

    abort(403)


def list_assessments_for_user(user: User) -> list[Assessment]:
    """Return assessments visible in the workspace history view."""
    query = Assessment.query.order_by(Assessment.created_at.desc())
    if user.role != "admin":
        query = query.filter_by(assessor_id=user.id)
    return query.all()

