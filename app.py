import os

from flask import Flask

from config import Config
from extensions import csrf, db, login_manager


def create_app(config_class=Config):
    """Create and configure the BioRisk Sentinel application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    app.config.setdefault("WTF_CSRF_ENABLED", not app.config.get("TESTING", False))
    csrf.init_app(app)

    from models import User  # Imported here so Flask-Login can load users.

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from routes.main import main_bp
    from routes.auth import auth_bp
    from routes.assessments import assessments_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(assessments_bp)

    from commands import register_commands

    register_commands(app)

    with app.app_context():
        db.create_all()
        from services.schema import ensure_schema

        ensure_schema()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")
