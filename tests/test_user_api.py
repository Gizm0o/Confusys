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


def test_user_creation_and_login(client):
    # Get admin token
    admin_token = get_admin_token(client)

    # Create user via admin API
    resp = client.post(
        "/user/users",
        json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpassword",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201

    # Try to create duplicate user
    resp = client.post(
        "/user/users",
        json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpassword",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 409

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

    # Try to create user without admin token
    resp = client.post(
        "/user/users",
        json={
            "username": "unauthorized",
            "email": "unauthorized@example.com",
            "password": "pass",
        },
    )
    assert resp.status_code == 401

    # Create user with missing required fields
    resp = client.post(
        "/user/users",
        json={
            "username": "",
            "password": "",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 400
