from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="assessor")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

    assessments = db.relationship("Assessment", back_populates="assessor")
    audit_logs = db.relationship("AuditLog", back_populates="user")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Assessment(db.Model):
    __tablename__ = "assessments"

    id = db.Column(db.Integer, primary_key=True)
    organization_name = db.Column(db.String(255), nullable=False)
    application_name = db.Column(db.String(255), nullable=False)
    environment = db.Column(db.String(80), nullable=False)
    biometric_type = db.Column(db.String(80), nullable=False)
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    liveness_enabled = db.Column(db.Boolean, nullable=False, default=False)
    admin_accessible = db.Column(db.Boolean, nullable=False, default=False)
    assessor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    assessor = db.relationship("User", back_populates="assessments")
    reliability_metrics = db.relationship(
        "ReliabilityMetrics", back_populates="assessment", uselist=False,
        cascade="all, delete-orphan"
    )
    privacy_controls = db.relationship(
        "PrivacyControls", back_populates="assessment", uselist=False,
        cascade="all, delete-orphan"
    )
    attack_results = db.relationship(
        "AttackResult", back_populates="assessment", cascade="all, delete-orphan"
    )
    findings = db.relationship(
        "Finding", back_populates="assessment", cascade="all, delete-orphan"
    )
    audit_logs = db.relationship("AuditLog", back_populates="assessment")


class ReliabilityMetrics(db.Model):
    __tablename__ = "reliability_metrics"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id"), nullable=False, unique=True
    )
    total_attempts = db.Column(db.Integer, nullable=False)
    successful_attempts = db.Column(db.Integer, nullable=False)
    failed_attempts = db.Column(db.Integer, nullable=False)
    false_acceptances = db.Column(db.Integer, nullable=False)
    false_rejections = db.Column(db.Integer, nullable=False)
    genuine_attempts = db.Column(db.Integer, nullable=False)
    impostor_attempts = db.Column(db.Integer, nullable=False)
    average_response_time = db.Column(db.Float, nullable=False)
    reliability_score = db.Column(db.Float, nullable=False)

    assessment = db.relationship("Assessment", back_populates="reliability_metrics")


class PrivacyControls(db.Model):
    __tablename__ = "privacy_controls"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(
        db.Integer, db.ForeignKey("assessments.id"), nullable=False, unique=True
    )
    template_encrypted = db.Column(db.Boolean, nullable=False)
    tls_enabled = db.Column(db.Boolean, nullable=False)
    raw_data_stored = db.Column(db.Boolean, nullable=False)
    access_control_enabled = db.Column(db.Boolean, nullable=False)
    audit_logging_enabled = db.Column(db.Boolean, nullable=False)
    retention_policy_exists = db.Column(db.Boolean, nullable=False)
    deletion_process_exists = db.Column(db.Boolean, nullable=False)
    consent_process_exists = db.Column(db.Boolean, nullable=False)
    secure_key_management = db.Column(db.Boolean, nullable=False)
    security_review_completed = db.Column(db.Boolean, nullable=False)
    privacy_score = db.Column(db.Float, nullable=False)

    assessment = db.relationship("Assessment", back_populates="privacy_controls")


class AttackResult(db.Model):
    __tablename__ = "attack_results"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessments.id"), nullable=False)
    attack_type = db.Column(db.String(80), nullable=False)
    attempts = db.Column(db.Integer, nullable=False)
    detected_or_blocked = db.Column(db.Integer, nullable=False)
    detection_rate = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)

    assessment = db.relationship("Assessment", back_populates="attack_results")


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessments.id"), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="open")

    assessment = db.relationship("Assessment", back_populates="findings")


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessments.id"), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

    user = db.relationship("User", back_populates="audit_logs")
    assessment = db.relationship("Assessment", back_populates="audit_logs")
