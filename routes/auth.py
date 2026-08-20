"""Authentication routes for BioRisk Sentinel."""

from urllib.parse import urljoin, urlparse

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user

from extensions import db
from models import User


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _safe_redirect_target(target: str | None) -> str | None:
    """Accept only an on-site redirect target after successful sign-in."""
    if not target:
        return None
    host_url = urlparse(request.host_url)
    target_url = urlparse(urljoin(request.host_url, target))
    return target if target_url.scheme == host_url.scheme and target_url.netloc == host_url.netloc else None


def _valid_email(email: str) -> bool:
    """Perform deliberately modest format validation; uniqueness is database-enforced."""
    return "@" in email and "." in email.rsplit("@", 1)[-1]


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("assessments.index"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name:
            flash("Name is required.", "error")
        elif not _valid_email(email):
            flash("Enter a valid email address.", "error")
        elif len(password) < 12:
            flash("Password must contain at least 12 characters.", "error")
        elif password != confirm_password:
            flash("Password confirmation does not match.", "error")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
        else:
            # Public sign-up deliberately creates assessors only; admins use the local CLI command.
            user = User(name=name, email=email, role="assessor")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Account created. Please sign in.", "success")
            return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("assessments.index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user is None or not user.check_password(password):
            flash("Invalid email or password.", "error")
        else:
            login_user(user)
            flash("Signed in successfully.", "success")
            return redirect(_safe_redirect_target(request.args.get("next")) or url_for("assessments.index"))

    return render_template("auth/login.html")


@auth_bp.post("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash("You have been signed out.", "success")
    return redirect(url_for("main.index"))
