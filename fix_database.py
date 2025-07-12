#!/usr/bin/env python3
"""
Script to fix the database schema by recreating tables with the technologies column
"""

import os
import psycopg2


def fix_database():
    """Fix the database schema"""
    db_url = os.environ.get(
        "DATABASE_URL", "postgresql://confusys:confusys@localhost:5432/confusys"
    )

    print("Connecting to database...")
    try:
        conn = psycopg2.connect(db_url)
        cursor = conn.cursor()

        # Check if technologies column exists
        cursor.execute(
            """
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'rule' AND column_name = 'technologies'
        """
        )

        if cursor.fetchone():
            print("✓ Technologies column already exists")
        else:
            print("✗ Technologies column missing, adding it...")
            cursor.execute("ALTER TABLE rule ADD COLUMN technologies BYTEA")
            conn.commit()
            print("✓ Technologies column added")

        # Check if the column is properly accessible
        cursor.execute("SELECT id, filename, technologies FROM rule LIMIT 1")
        cursor.fetchall()
        print("✓ Database schema is correct")

        cursor.close()
        conn.close()

    except Exception as e:
        print(f"Database error: {e}")
        return False

    return True


if __name__ == "__main__":
    if fix_database():
        print("Database schema fixed successfully!")
    else:
        print("Failed to fix database schema")
