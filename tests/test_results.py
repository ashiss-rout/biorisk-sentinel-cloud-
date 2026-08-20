import unittest

from app import create_app
from extensions import db
from models import User, Assessment, AuditLog


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret-key"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class ResultsTests(unittest.TestCase):
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

    def test_results_route_requires_all_sections_and_generates_findings(self):
        self.register_and_login()

        # Create assessment
        response = self.client.post(
            "/assessments/new",
            data={
                "organization_name": "X Corp",
                "application_name": "Gate",
                "environment": "Test",
                "biometric_type": "Fingerprint",
                "mfa_enabled": "no",
                "liveness_enabled": "no",
                "admin_accessible": "yes",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

        # Save reliability
        response = self.client.post(
            "/assessments/1/reliability",
            data={
                "total_attempts": "100",
                "successful_attempts": "95",
                "failed_attempts": "5",
                "false_acceptances": "2",
                "false_rejections": "3",
                "genuine_attempts": "98",
                "impostor_attempts": "2",
                "average_response_time": "1.0",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

        # Save privacy (intentionally missing audit_logging_enabled to test finding)
        privacy_payload = {
            "template_encrypted": "no",
            "tls_enabled": "yes",
            "raw_data_stored": "no",
            "access_control_enabled": "yes",
            "audit_logging_enabled": "no",
            "retention_policy_exists": "yes",
            "deletion_process_exists": "yes",
            "consent_process_exists": "yes",
            "secure_key_management": "no",
            "security_review_completed": "no",
        }
        response = self.client.post("/assessments/1/privacy", data=privacy_payload, follow_redirects=False)
        self.assertEqual(response.status_code, 302)

        # Save attacks
        attack_payload = {
            "replay_attempts": "10",
            "replay_detected": "9",
            "spoofing_attempts": "10",
            "spoofing_detected": "5",
            "brute_force_attempts": "10",
            "brute_force_detected": "8",
            "bypass_attempts": "10",
            "bypass_detected": "9",
            "template_related_attempts": "10",
            "template_related_detected": "7",
        }
        response = self.client.post("/assessments/1/attacks", data=attack_payload, follow_redirects=False)
        self.assertEqual(response.status_code, 302)

        # Now results should be available
        response = self.client.get("/assessments/1/results", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Overall score", response.data)
        self.assertIn(b"Findings", response.data)

        # Check audit log for results generation
        with self.app.app_context():
            audit = AuditLog.query.filter_by(assessment_id=1).order_by(AuditLog.id.desc()).first()
            self.assertIsNotNone(audit)
            self.assertEqual(audit.action, "Generated assessment results")


if __name__ == "__main__":
    unittest.main()
