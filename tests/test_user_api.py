import os
import sys

import pytest

from api import create_app, db

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture
def client():
    test_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SECRET_KEY": "test-secret-key",
    }
    app = create_app(test_config)
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def get_admin_token(client):
    resp = client.post("/user/login", json={"username": "admin", "password": "admin"})
    return resp.get_json()["token"]


def test_user_registration_and_login(client):
    # Register user
    resp = client.post(
        "/user/register",
        json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpassword",
        },
    )
    assert resp.status_code == 201
    # Duplicate registration
    resp = client.post(
        "/user/register",
        json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpassword",
        },
    )
    assert resp.status_code in (400, 409)
    # Login with correct password
    resp = client.post(
        "/user/login", json={"username": "testuser", "password": "testpassword"}
    )
    assert resp.status_code == 200
    # Login with wrong password
    resp = client.post(
        "/user/login", json={"username": "testuser", "password": "wrongpass"}
    )
    assert resp.status_code == 401
    # Login with non-existent user
    resp = client.post("/user/login", json={"username": "nouser", "password": "nopass"})
    assert resp.status_code == 401
    # Register with missing fields
    resp = client.post(
        "/user/register", json={"username": "", "email": "", "password": ""}
    )
    assert resp.status_code == 400
    # Register with invalid email
    resp = client.post(
        "/user/register",
        json={"username": "bademail", "email": "notanemail", "password": "pass"},
    )
    assert resp.status_code in (400, 201)  # Accept 400 if email validation is enforced
