#!/usr/bin/env python3
"""
Test script to verify Docker containers are working
"""

import sys
import time

import requests


def test_api():
    """Test the API server"""
    try:
        # Test API health
        resp = requests.get("http://localhost:5000/user/login", timeout=5)
        print(f"✅ API Server (port 5000): {resp.status_code}")
        return True
    except Exception as e:
        print(f"❌ API Server (port 5000): {e}")
        return False


def test_frontend():
    """Test the frontend server"""
    try:
        # Test frontend health
        resp = requests.get("http://localhost:3000", timeout=5)
        print(f"✅ Frontend Server (port 3000): {resp.status_code}")
        return True
    except Exception as e:
        print(f"❌ Frontend Server (port 3000): {e}")
        return False


def main():
    print("Testing Confusys Docker containers...")
    print("=" * 40)

    # Wait a bit for containers to start
    print("Waiting for containers to start...")
    time.sleep(10)

    api_ok = test_api()
    frontend_ok = test_frontend()

    print("=" * 40)
    if api_ok and frontend_ok:
        print("🎉 All containers are running!")
        print("\nAccess URLs:")
        print("- Frontend: http://localhost:3000")
        print("- API: http://localhost:5000")
        print("- Swagger: http://localhost:5000/swagger")
        print("\nDefault login: admin/admin")
    else:
        print("❌ Some containers failed to start")
        sys.exit(1)


if __name__ == "__main__":
    main()
