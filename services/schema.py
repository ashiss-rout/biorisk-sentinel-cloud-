"""Lightweight schema upgrades for local SQLite development."""

from sqlalchemy import inspect, text

from extensions import db


def ensure_schema() -> None:
    """Apply idempotent column additions that db.create_all() will not backfill."""
    inspector = inspect(db.engine)
    if not inspector.has_table("assessments"):
        return

    column_names = {column["name"] for column in inspector.get_columns("assessments")}
    if "admin_accessible" not in column_names:
        with db.engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE assessments "
                    "ADD COLUMN admin_accessible BOOLEAN NOT NULL DEFAULT 0"
                )
            )
