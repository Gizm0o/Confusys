from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_restx import Api
import os

db = SQLAlchemy()

def create_app(config=None):
    app = Flask(__name__)
    
    if config:
        app.config.update(config)
    else:
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///confusys.db')
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    
    # Initialize Swagger API
    api = Api(app, 
              title='Confusys API',
              version='1.0',
              description='A Flask-based API for user, machine, and role management with audit script generation',
              doc='/docs/',
              authorizations={
                  'Bearer': {
                      'type': 'apiKey',
                      'in': 'header',
                      'name': 'Authorization',
                      'description': 'JWT token in format: Bearer <token>'
                  }
              },
              security='Bearer')
    
    with app.app_context():
        db.create_all()
        # Create default admin user and role
        from api.models.user import User, Role
        from werkzeug.security import generate_password_hash
        
        # Create admin role if it doesn't exist
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(name='admin', description='Administrator role')
            db.session.add(admin_role)
            db.session.commit()
        
        # Create admin user if it doesn't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin')
            )
            admin_user.roles.append(admin_role)
            db.session.add(admin_user)
            db.session.commit()
    
    from api.routes.user_routes import user_bp
    from api.routes.machine_routes import machine_bp
    from api.routes.role_routes import role_bp
    from api.routes.rule_routes import rule_bp
    
    app.register_blueprint(user_bp)
    app.register_blueprint(machine_bp)
    app.register_blueprint(role_bp)
    app.register_blueprint(rule_bp)
    
    return app 