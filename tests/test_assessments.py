import unittest

from app import create_app
from extensions import db
from models import Assessment, AuditLog, User


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret-key"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class AssessmentCreationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()

        with self.app.app_context():
            db.drop_all()
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def register_and_login(self):
        self.client.post(
            "/auth/register",
            data={
                "name": "Asha Assessor",
                "email": "asha@example.test",
                "password": "secure-password",
                "confirm_password": "secure-password",
            },
            follow_redirects=True,
        )
        self.client.post(
            "/auth/login",
            data={"email": "asha@example.test", "password": "secure-password"},
            follow_redirects=True,
        )

    def valid_assessment_payload(self, **overrides):
        data = {
            "organization_name": "Fictional Finance Corp",
            "application_name": "BioGate Portal",
            "environment": "Test",
            "biometric_type": "Fingerprint",
            "mfa_enabled": "yes",
            "liveness_enabled": "no",
            "admin_accessible": "yes",
        }
        data.update(overrides)
        return data

    def test_guest_cannot_access_new_assessment(self):
        response = self.client.get("/assessments/new", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login", response.headers["Location"])

    def test_valid_assessment_creates_record_with_owner(self):
        self.register_and_login()
        response = self.client.post(
            "/assessments/new",
            data=self.valid_assessment_payload(),
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/assessments/1/reliability", response.headers["Location"])

        with self.app.app_context():
            user = User.query.filter_by(email="asha@example.test").one()
            assessment = Assessment.query.one()
            self.assertEqual(assessment.assessor_id, user.id)
            self.assertEqual(assessment.organization_name, "Fictional Finance Corp")
            self.assertEqual(assessment.application_name, "BioGate Portal")
            self.assertEqual(assessment.environment, "Test")
            self.assertEqual(assessment.biometric_type, "Fingerprint")
            self.assertTrue(assessment.mfa_enabled)
            self.assertFalse(assessment.liveness_enabled)
            self.assertTrue(assessment.admin_accessible)

    def test_invalid_assessment_values_rejected(self):
        self.register_and_login()
        response = self.client.post(
            "/assessments/new",
            data=self.valid_assessment_payload(
                organization_name="",
                environment="Invalid",
                admin_accessible="maybe",
            ),
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Organisation name is required.", response.data)
        self.assertIn(b"Select a valid environment.", response.data)
        self.assertIn(b"Select whether the assessed system provides administrator access.", response.data)

        with self.app.app_context():
            self.assertEqual(Assessment.query.count(), 0)

    def test_assessment_creation_writes_audit_log(self):
        self.register_and_login()
        self.client.post("/assessments/new", data=self.valid_assessment_payload(), follow_redirects=False)

        with self.app.app_context():
            user = User.query.filter_by(email="asha@example.test").one()
            assessment = Assessment.query.one()
            audit_log = AuditLog.query.one()
            self.assertEqual(audit_log.user_id, user.id)
            self.assertEqual(audit_log.assessment_id, assessment.id)
            self.assertEqual(audit_log.action, "Created assessment")
