#!/usr/bin/env python3
import os
import time

import psycopg2

from api import create_app, db, init_db


def wait_for_database():
    """Wait for database to be ready and initialize tables"""
    db_url = os.environ.get(
        "DATABASE_URL", "postgresql://confusys:confusys@db:5432/confusys"
    )

    print("Waiting for database...")
    while True:
        try:
            conn = psycopg2.connect(db_url)
            conn.close()
            print("Database is ready!")
            break
        except psycopg2.OperationalError:
            print("Database not ready, waiting...")
            time.sleep(2)

    # Create Flask app and initialize database
    app = create_app()
    print("Creating database tables...")
    with app.app_context():
        db.create_all()
        print("Tables created successfully!")
        print("Initializing with default admin user...")
        init_db(app)
        print("Database initialization complete!")
    
    # Start the API server
    print("Starting API server...")
    app.run(debug=True, port=5000, host="0.0.0.0")

if __name__ == "__main__":
    wait_for_database()
