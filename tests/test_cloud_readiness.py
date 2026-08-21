import unittest

from app import create_app
from extensions import db
from config import ProductionConfig, normalize_database_url


class CloudReadinessTests(unittest.TestCase):
    def setUp(self):
        class TestProductionConfig(ProductionConfig):
            TESTING = False
            SECRET_KEY = "cloud-readiness-test-secret"
            SQLALCHEMY_DATABASE_URI = "sqlite://"
            SESSION_COOKIE_SECURE = True

        self.app = create_app(TestProductionConfig)
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_production_config_enables_secure_cookie_and_csrf(self):
        self.assertTrue(self.app.config["WTF_CSRF_ENABLED"])
        self.assertTrue(self.app.config["SESSION_COOKIE_SECURE"])
        self.assertTrue(self.app.config["SESSION_COOKIE_HTTPONLY"])

    def test_state_changing_request_without_csrf_token_is_rejected(self):
        response = self.client.post(
            "/auth/register",
            data={
                "name": "Cloud Test",
                "email": "cloud@example.test",
                "password": "cloud-password",
                "confirm_password": "cloud-password",
            },
        )

        self.assertEqual(response.status_code, 400)

    def test_render_postgresql_urls_use_psycopg_three(self):
        for prefix in ("postgres://", "postgresql://"):
            normalized = normalize_database_url(prefix + "user:pass@host/database")
            self.assertEqual(
                normalized,
                "postgresql+psycopg://user:pass@host/database",
            )


if __name__ == "__main__":
    unittest.main()
