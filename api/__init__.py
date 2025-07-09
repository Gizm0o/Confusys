from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()

def create_app(test_config=None):
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev')
    if test_config:
        app.config.update(test_config)
    db.init_app(app)

    from api.routes.user_routes import user_bp
    app.register_blueprint(user_bp, url_prefix='/user')

    from api.routes.machine_routes import machine_bp
    app.register_blueprint(machine_bp)

    from api.routes.role_routes import role_bp
    app.register_blueprint(role_bp)

    @app.route('/')
    def index():
        return {'message': 'Confusys API is running.'}
    
    # Import models here to avoid circular import
    from api.models.user import User
    from api.models.machine import Machine
    with app.app_context():
        db.create_all()
        # Create default admin role and user if not exist
        from api.models.user import User, Role
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(name='admin', description='Administrator role with full rights')
            db.session.add(admin_role)
            db.session.commit()
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', email='admin@example.com')
            admin_user.set_password('admin')
            admin_user.roles.append(admin_role)
            db.session.add(admin_user)
            db.session.commit()

    return app 