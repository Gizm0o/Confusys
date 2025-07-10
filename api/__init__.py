import os
from typing import Any, Dict, Optional

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app(config: Optional[Dict[str, Any]] = None) -> Flask:
    app = Flask(__name__)

    if config:
        app.config.update(config)
    else:
        app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "your-secret-key")
        app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
            "DATABASE_URL", "sqlite:///confusys.db"
        )
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    with app.app_context():
        db.create_all()

    from api.routes.machine_routes import machine_bp
    from api.routes.role_routes import role_bp
    from api.routes.rule_routes import rule_bp
    from api.routes.user_routes import user_bp

    app.register_blueprint(user_bp, url_prefix="/user")
    app.register_blueprint(machine_bp, url_prefix="/machines")
    app.register_blueprint(role_bp, url_prefix="/roles")
    app.register_blueprint(rule_bp, url_prefix="/rules")

    return app


def init_db(app: Flask) -> None:
    """Initialize database with default admin user and role"""
    with app.app_context():
        from api.models.user import Role, User

        # Create admin role if it doesn't exist
        admin_role = Role.query.filter_by(name="admin").first()
        if not admin_role:
            admin_role = Role(name="admin", description="Administrator role")
            db.session.add(admin_role)
            db.session.commit()

        # Create admin user if it doesn't exist
        admin_user = User.query.filter_by(username="admin").first()
        if not admin_user:
            admin_user = User(username="admin", email="admin@example.com")
            admin_user.set_password("admin")
            admin_user.roles.append(admin_role)
            db.session.add(admin_user)
            db.session.commit()
