import unittest

from app import create_app
from extensions import db
from models import User


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret-key"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class AuthenticationTests(unittest.TestCase):
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

    def register(self, **overrides):
        data = {
            "name": "Asha Assessor",
            "email": "asha@example.test",
            "password": "secure-password",
            "confirm_password": "secure-password",
        }
        data.update(overrides)
        return self.client.post("/auth/register", data=data, follow_redirects=True)

    def test_registration_creates_hashed_assessor_account(self):
        response = self.register(role="admin")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Account created. Please sign in.", response.data)
        with self.app.app_context():
            user = User.query.filter_by(email="asha@example.test").one()
            self.assertEqual(user.role, "assessor")
            self.assertNotEqual(user.password_hash, "secure-password")
            self.assertTrue(user.check_password("secure-password"))

    def test_registration_rejects_short_or_duplicate_password_details(self):
        short_password = self.register(password="short", confirm_password="short")
        self.assertIn(b"Password must contain at least 12 characters.", short_password.data)

        self.register()
        duplicate = self.register()
        self.assertIn(b"An account with that email already exists.", duplicate.data)

    def test_login_logout_and_protected_workspace(self):
        self.register()
        guest_response = self.client.get("/assessments/", follow_redirects=False)
        self.assertEqual(guest_response.status_code, 302)
        self.assertIn("/auth/login", guest_response.headers["Location"])

        bad_login = self.client.post(
            "/auth/login", data={"email": "asha@example.test", "password": "wrong-password"}, follow_redirects=True
        )
        self.assertIn(b"Invalid email or password.", bad_login.data)

        response = self.client.post(
            "/auth/login", data={"email": "asha@example.test", "password": "secure-password"}, follow_redirects=True
        )
        self.assertIn(b"Assessment workspace", response.data)

        logout = self.client.post("/auth/logout", follow_redirects=True)
        self.assertIn(b"BioRisk Sentinel", logout.data)
        after_logout = self.client.get("/assessments/", follow_redirects=False)
        self.assertEqual(after_logout.status_code, 302)

    def test_local_command_creates_an_administrator(self):
        runner = self.app.test_cli_runner()
        result = runner.invoke(
            args=["create-admin", "--name", "Project Admin", "--email", "admin@example.test", "--password", "admin-password"],
        )

        self.assertEqual(result.exit_code, 0)
        with self.app.app_context():
            user = User.query.filter_by(email="admin@example.test").one()
            self.assertEqual(user.role, "admin")
            self.assertTrue(user.check_password("admin-password"))
