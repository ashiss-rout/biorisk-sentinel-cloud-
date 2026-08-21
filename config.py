import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def normalize_database_url(database_url):
    """Use the Psycopg 3 SQLAlchemy dialect for Render PostgreSQL URLs."""
    if database_url.startswith("postgres://"):
        return "postgresql+psycopg://" + database_url[len("postgres://") :]
    if database_url.startswith("postgresql://"):
        return "postgresql+psycopg://" + database_url[len("postgresql://") :]
    return database_url


class Config:
    """Application settings loaded from environment variables where possible."""

    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-before-deployment")
    DATABASE_URL = normalize_database_url(os.getenv("DATABASE_URL", ""))
    SQLALCHEMY_DATABASE_URI = DATABASE_URL or f"sqlite:///{BASE_DIR / 'instance' / 'biorisk.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"


class ProductionConfig(Config):
    """Cloud deployment defaults; secrets and URLs come from environment variables."""

    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = "https"
