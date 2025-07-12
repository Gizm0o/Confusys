#!/usr/bin/env python3
"""
Database initialization script for Confusys
Creates tables and default admin user
"""

import os
from api import create_app, db, init_db


def main():
    print("Initializing Confusys database...")

    # Create app with SQLite database
    app = create_app(
        {
            "SQLALCHEMY_DATABASE_URI": "sqlite:///confusys.db",
            "SECRET_KEY": "your-secret-key",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        }
    )

    with app.app_context():
        print("Creating database tables...")
        db.create_all()
        print("Tables created successfully!")

        print("Initializing with default admin user...")
        init_db(app)
        print("Database initialization complete!")

        # Verify admin user was created
        from api.models.user import User

        admin = User.query.filter_by(username="admin").first()
        if admin:
            print(f"Admin user created: {admin.username} ({admin.email})")
        else:
            print("Warning: Admin user not found!")


if __name__ == "__main__":
    main()
