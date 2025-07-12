from flask import Flask, jsonify
from api import create_app
import os
import time
import psycopg2

# Create API-only app (without UI routes)
def create_api_app():
    app = Flask(__name__)
    
    # Configure the app
    app.config["SECRET_KEY"] = "api-secret-key"
    
    # Use PostgreSQL in Docker, SQLite for local development
    if os.environ.get("DOCKER_ENV"):
        app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://confusys:confusys@db:5432/confusys"
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///confusys.db"
    
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    # Import and register API blueprints only
    from api import db
    db.init_app(app)
    
    # Wait for database to be ready in Docker environment
    if os.environ.get("DOCKER_ENV"):
        max_retries = 30
        retry_count = 0
        while retry_count < max_retries:
            try:
                with app.app_context():
                    db.session.execute("SELECT 1")
                    print("Database connection established")
                    break
            except Exception as e:
                print(f"Waiting for database... (attempt {retry_count + 1}/{max_retries})")
                retry_count += 1
                time.sleep(2)
        
        if retry_count >= max_retries:
            print("Warning: Could not connect to database during startup")
    
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print(f"Warning: Could not create database tables: {e}")
    
    from api.routes.machine_routes import machine_bp
    from api.routes.role_routes import role_bp
    from api.routes.rule_routes import rule_bp
    from api.routes.user_routes import user_bp
    
    app.register_blueprint(user_bp, url_prefix="/user")
    app.register_blueprint(machine_bp, url_prefix="/machines")
    app.register_blueprint(role_bp, url_prefix="/roles")
    app.register_blueprint(rule_bp, url_prefix="/rules")
    
    # Add health endpoint
    @app.route("/health")
    def health():
        try:
            # Test database connection
            db.session.execute("SELECT 1")
            db_status = "connected"
        except Exception:
            db_status = "disconnected"
        
        return jsonify({
            "status": "healthy",
            "database": db_status,
            "service": "confusys-api"
        })
    
    return app

app = create_api_app()

if __name__ == "__main__":
    app.run(debug=True, port=5000, host="0.0.0.0") 