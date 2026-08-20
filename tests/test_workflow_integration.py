import unittest

from app import create_app
from extensions import db
from models import Assessment, User


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret-key"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class WorkflowIntegrationTests(unittest.TestCase):
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

    def register_and_login(self, email="asha@example.test"):
        self.client.post(
            "/auth/register",
            data={
                "name": "Asha Assessor",
                "email": email,
                "password": "secure-password",
                "confirm_password": "secure-password",
            },
            follow_redirects=True,
        )
        self.client.post(
            "/auth/login",
            data={"email": email, "password": "secure-password"},
            follow_redirects=True,
        )

    def test_full_workflow_end_to_end(self):
        # Assessor creates assessment and completes all sections, then views report
        self.register_and_login()
        # Create
        resp = self.client.post(
            "/assessments/new",
            data={
                "organization_name": "EndToEnd Org",
                "application_name": "Portal",
                "environment": "Development",
                "biometric_type": "Face",
                "mfa_enabled": "yes",
                "liveness_enabled": "yes",
                "admin_accessible": "no",
            },
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)

        # Reliability
        self.client.post(
            "/assessments/1/reliability",
            data={
                "total_attempts": "100",
                "successful_attempts": "98",
                "failed_attempts": "2",
                "false_acceptances": "0",
                "false_rejections": "2",
                "genuine_attempts": "98",
                "impostor_attempts": "2",
                "average_response_time": "0.8",
            },
            follow_redirects=False,
        )

        # Privacy
        privacy_payload = {
            "template_encrypted": "yes",
            "tls_enabled": "yes",
            "raw_data_stored": "no",
            "access_control_enabled": "yes",
            "audit_logging_enabled": "yes",
            "retention_policy_exists": "yes",
            "deletion_process_exists": "yes",
            "consent_process_exists": "yes",
            "secure_key_management": "yes",
            "security_review_completed": "yes",
        }
        self.client.post("/assessments/1/privacy", data=privacy_payload, follow_redirects=False)

        # Attacks
        attack_payload = {
            "replay_attempts": "10",
            "replay_detected": "10",
            "spoofing_attempts": "10",
            "spoofing_detected": "10",
            "brute_force_attempts": "10",
            "brute_force_detected": "10",
            "bypass_attempts": "10",
            "bypass_detected": "10",
            "template_related_attempts": "10",
            "template_related_detected": "10",
        }
        self.client.post("/assessments/1/attacks", data=attack_payload, follow_redirects=False)

        # Results
        resp = self.client.get("/assessments/1/results", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Overall score", resp.data)
        self.assertIn(b"Risk level", resp.data)

        # Printable report
        resp = self.client.get("/assessments/1/report", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Assessment Report", resp.data)

        # Ensure owner can see assessment in workspace
        resp = self.client.get("/assessments/", follow_redirects=True)
        self.assertIn(b"EndToEnd Org", resp.data)

        # Create an admin and verify admin can view others' assessments
        # Use CLI command to create admin in-app context
        with self.app.app_context():
            admin = User(name="Admin User", email="admin@example.test", role="admin")
            admin.set_password("secure-password")
            db.session.add(admin)
            db.session.commit()

        # Login as admin
        self.client.post(
            "/auth/login",
            data={"email": "admin@example.test", "password": "secure-password"},
            follow_redirects=True,
        )
        resp = self.client.get("/assessments/", follow_redirects=True)
        self.assertIn(b"EndToEnd Org", resp.data)


if __name__ == "__main__":
    unittest.main()
