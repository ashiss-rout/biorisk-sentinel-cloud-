"""Local-only operational commands for BioRisk Sentinel."""

import click
from flask import Flask

from extensions import db
from models import User


def register_commands(app: Flask) -> None:
    """Register commands that should never be exposed through public routes."""

    @app.cli.command("create-admin")
    @click.option("--name", prompt="Administrator name")
    @click.option("--email", prompt="Administrator email")
    @click.password_option()
    def create_admin(name: str, email: str, password: str) -> None:
        """Create one administrator through a trusted local terminal."""
        normalized_email = email.strip().lower()
        if not name.strip():
            raise click.UsageError("Administrator name is required.")
        if not normalized_email or "@" not in normalized_email:
            raise click.UsageError("Provide a valid administrator email address.")
        if len(password) < 12:
            raise click.UsageError("Administrator passwords must contain at least 12 characters.")
        if User.query.filter_by(email=normalized_email).first():
            raise click.UsageError("An account with that email already exists.")

        user = User(name=name.strip(), email=normalized_email, role="admin")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Administrator account created for {normalized_email}.")
