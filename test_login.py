#!/usr/bin/env python3
import requests


def test_login():
    try:
        resp = requests.post(
            "http://localhost:5000/user/login",
            json={"username": "admin", "password": "admin"},
        )
        print(f"Login status: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            print(f"Login successful! Token: {data.get('token', 'No token')[:20]}...")
        else:
            print(f"Login failed: {resp.text}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    test_login()
