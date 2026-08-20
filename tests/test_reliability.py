import unittest

from app import create_app
from extensions import db
from models import Assessment, AuditLog, ReliabilityMetrics, User
from services.scoring import ReliabilityInput, calculate_reliability


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret-key"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class ReliabilityAssessmentTests(unittest.TestCase):
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

    def register_user(self, name, email, password="secure-password"):
        self.client.post(
            "/auth/register",
            data={
                "name": name,
                "email": email,
                "password": password,
                "confirm_password": password,
            },
            follow_redirects=True,
        )

    def login(self, email, password="secure-password"):
        self.client.post(
            "/auth/login",
            data={"email": email, "password": password},
            follow_redirects=True,
        )

    def create_assessment(self):
        return self.client.post(
            "/assessments/new",
            data={
                "organization_name": "Fictional Finance Corp",
                "application_name": "BioGate Portal",
                "environment": "Test",
                "biometric_type": "Fingerprint",
                "mfa_enabled": "yes",
                "liveness_enabled": "no",
                "admin_accessible": "yes",
            },
            follow_redirects=False,
        )

    def valid_reliability_payload(self, **overrides):
        data = {
            "total_attempts": "100000",
            "successful_attempts": "96500",
            "failed_attempts": "3500",
            "false_acceptances": "20",
            "false_rejections": "3480",
            "genuine_attempts": "98000",
            "impostor_attempts": "2000",
            "average_response_time": "1.2",
        }
        data.update(overrides)
        return data

    def test_guest_cannot_access_reliability(self):
        response = self.client.get("/assessments/1/reliability", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login", response.headers["Location"])

    def test_owner_can_save_valid_reliability_metrics(self):
        self.register_user("Asha Assessor", "asha@example.test")
        self.login("asha@example.test")
        self.create_assessment()

        response = self.client.post(
            "/assessments/1/reliability",
            data=self.valid_reliability_payload(),
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/assessments/1/privacy", response.headers["Location"])

        with self.app.app_context():
            metrics = ReliabilityMetrics.query.one()
            expected_score = calculate_reliability(
                ReliabilityInput(100000, 96500, 3500, 20, 3480, 98000, 2000, 1.2)
            ).score
            self.assertEqual(metrics.total_attempts, 100000)
            self.assertEqual(metrics.successful_attempts, 96500)
            self.assertEqual(metrics.false_acceptances, 20)
            self.assertEqual(metrics.reliability_score, expected_score)

    def test_invalid_reliability_values_rejected(self):
        self.register_user("Asha Assessor", "asha@example.test")
        self.login("asha@example.test")
        self.create_assessment()

        response = self.client.post(
            "/assessments/1/reliability",
            data=self.valid_reliability_payload(
                successful_attempts="90000",
                failed_attempts="3500",
            ),
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Successful and failed attempts must equal total attempts.",
            response.data,
        )

        with self.app.app_context():
            self.assertEqual(ReliabilityMetrics.query.count(), 0)

    def test_other_assessor_cannot_access_reliability(self):
        self.register_user("Asha Assessor", "asha@example.test")
        self.login("asha@example.test")
        self.create_assessment()

        self.client.post("/auth/logout", follow_redirects=True)
        self.register_user("Ben Assessor", "ben@example.test")
        self.login("ben@example.test")

        response = self.client.get("/assessments/1/reliability", follow_redirects=False)
        self.assertEqual(response.status_code, 403)

    def test_admin_can_access_other_assessors_reliability(self):
        self.register_user("Asha Assessor", "asha@example.test")
        self.login("asha@example.test")
        self.create_assessment()

        runner = self.app.test_cli_runner()
        runner.invoke(
            args=[
                "create-admin",
                "--name",
                "Project Admin",
                "--email",
                "admin@example.test",
                "--password",
                "admin-password",
            ],
        )

        self.client.post("/auth/logout", follow_redirects=True)
        self.login("admin@example.test", "admin-password")

        response = self.client.get("/assessments/1/reliability", follow_redirects=False)
        self.assertEqual(response.status_code, 200)

    def test_reliability_update_upserts_instead_of_duplicating(self):
        self.register_user("Asha Assessor", "asha@example.test")
        self.login("asha@example.test")
        self.create_assessment()

        self.client.post(
            "/assessments/1/reliability",
            data=self.valid_reliability_payload(),
            follow_redirects=False,
        )
        self.client.post(
            "/assessments/1/reliability",
            data=self.valid_reliability_payload(average_response_time="2.0"),
            follow_redirects=False,
        )

        with self.app.app_context():
            self.assertEqual(ReliabilityMetrics.query.count(), 1)
            metrics = ReliabilityMetrics.query.one()
            self.assertEqual(metrics.average_response_time, 2.0)

    def test_reliability_save_writes_audit_log(self):
        self.register_user("Asha Assessor", "asha@example.test")
        self.login("asha@example.test")
        self.create_assessment()
        self.client.post(
            "/assessments/1/reliability",
            data=self.valid_reliability_payload(),
            follow_redirects=False,
        )

        with self.app.app_context():
            user = User.query.filter_by(email="asha@example.test").one()
            assessment = Assessment.query.one()
            reliability_logs = AuditLog.query.filter_by(action="Saved reliability metrics").all()
            self.assertEqual(len(reliability_logs), 1)
            self.assertEqual(reliability_logs[0].user_id, user.id)
            self.assertEqual(reliability_logs[0].assessment_id, assessment.id)
