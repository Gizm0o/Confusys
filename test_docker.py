#!/usr/bin/env python3
"""
Test script for Docker setup
"""
import requests
import time
import sys

def test_api_health():
    """Test if the API server is running"""
    try:
        response = requests.get("http://localhost:5000/health", timeout=5)
        if response.status_code == 200:
            print("✅ API server is running")
            return True
        else:
            print(f"❌ API server returned status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ API server is not accessible: {e}")
        return False

def test_frontend_health():
    """Test if the frontend server is running"""
    try:
        response = requests.get("http://localhost:3000/", timeout=5)
        if response.status_code in [200, 302]:  # 302 is redirect to login
            print("✅ Frontend server is running")
            return True
        else:
            print(f"❌ Frontend server returned status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Frontend server is not accessible: {e}")
        return False

def test_database_connection():
    """Test database connection"""
    try:
        response = requests.get("http://localhost:5000/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("database") == "connected":
                print("✅ Database connection is working")
                return True
            else:
                print("❌ Database connection failed")
                return False
        else:
            print("❌ Could not check database connection")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Could not test database connection: {e}")
        return False

def main():
    print("Testing ConfuSys Docker setup...")
    print("=" * 40)
    
    # Wait a bit for services to start
    print("Waiting for services to start...")
    time.sleep(10)
    
    api_ok = test_api_health()
    frontend_ok = test_frontend_health()
    db_ok = test_database_connection()
    
    print("=" * 40)
    if api_ok and frontend_ok and db_ok:
        print("🎉 All services are running correctly!")
        print("\nAccess your application at:")
        print("- Frontend: http://localhost:3000")
        print("- API: http://localhost:5000")
        print("- Swagger UI: http://localhost:5000/swagger")
        return 0
    else:
        print("❌ Some services are not running correctly")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 