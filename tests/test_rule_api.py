import io
import os
import sys

import pytest

from api import create_app, db
from api.models.user import Role, User

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def get_admin_token(client):
    resp = client.post("/user/login", json={"username": "admin", "password": "admin"})
    return resp.get_json()["token"]


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
        # Create admin role
        admin_role = Role(name="admin", description="Administrator role")
        db.session.add(admin_role)
        db.session.commit()
        # Create admin user
        admin_user = User(username="admin", email="admin@example.com")
        admin_user.set_password("admin")
        admin_user.roles.append(admin_role)
        db.session.add(admin_user)
        db.session.commit()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def test_rule_upload_download_update_delete(client):
    admin_token = get_admin_token(client)
    # Create role
    resp = client.post(
        "/roles",
        json={"name": "ruleop", "description": "desc"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    role_id = resp.get_json()["id"]
    # Create user via admin and assign role
    client.post(
        "/user/users",
        json={"username": "user", "email": "user@example.com", "password": "pass"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    resp = client.post("/user/login", json={"username": "user", "password": "pass"})
    token = resp.get_json()["token"]
    user_id = resp.get_json()["user_id"]
    client.post(
        f"/roles/{role_id}/assign_user/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # Upload rule
    data = {
        "file": (io.BytesIO(b"abc"), "a.txt"),
        "description": "desc",
        "roles": "ruleop",
    }
    resp = client.post(
        "/rules",
        headers={"Authorization": f"Bearer {token}"},
        content_type="multipart/form-data",
        data=data,
    )
    assert resp.status_code == 201
    rule_id = resp.get_json()["id"]
    # Download rule
    resp = client.get(
        f"/rules/{rule_id}?download=1", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    assert resp.data == b"abc"
    # Update rule
    update_data = {"description": "desc2", "roles": "ruleop"}
    resp = client.put(
        f"/rules/{rule_id}",
        headers={"Authorization": f"Bearer {token}"},
        content_type="multipart/form-data",
        data=update_data,
    )
    assert resp.status_code == 200
    # Delete rule
    resp = client.delete(
        f"/rules/{rule_id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    # Get deleted rule
    resp = client.get(f"/rules/{rule_id}", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 404


def test_rule_upload_errors_and_access(client):
    admin_token = get_admin_token(client)
    # Create user via admin
    client.post(
        "/user/users",
        json={"username": "user2", "email": "user2@example.com", "password": "pass"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    resp = client.post("/user/login", json={"username": "user2", "password": "pass"})
    token = resp.get_json()["token"]
    # Upload with no file
    resp = client.post(
        "/rules",
        headers={"Authorization": f"Bearer {token}"},
        content_type="multipart/form-data",
        data={},
    )
    assert resp.status_code == 400
    # Upload with empty filename
    data = {"file": (io.BytesIO(b""), "")}
    resp = client.post(
        "/rules",
        headers={"Authorization": f"Bearer {token}"},
        content_type="multipart/form-data",
        data=data,
    )
    assert resp.status_code == 400
    # Unauthorized delete
    # Create role and user
    resp = client.post(
        "/roles",
        json={"name": "ruleop2", "description": "desc"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    role_id = resp.get_json()["id"]
    client.post(
        "/user/users",
        json={"username": "user3", "email": "user3@example.com", "password": "pass"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    resp = client.post("/user/login", json={"username": "user3", "password": "pass"})
    token3 = resp.get_json()["token"]
    user_id3 = resp.get_json()["user_id"]
    client.post(
        f"/roles/{role_id}/assign_user/{user_id3}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # Upload rule as user3
    data = {
        "file": (io.BytesIO(b"abc"), "b.txt"),
        "description": "desc",
        "roles": "ruleop2",
    }
    resp = client.post(
        "/rules",
        headers={"Authorization": f"Bearer {token3}"},
        content_type="multipart/form-data",
        data=data,
    )
    rule_id = resp.get_json()["id"]
    # Try to delete as another user
    client.post(
        "/user/users",
        json={"username": "user4", "email": "user4@example.com", "password": "pass"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    resp = client.post("/user/login", json={"username": "user4", "password": "pass"})
    token4 = resp.get_json()["token"]
    resp = client.delete(
        f"/rules/{rule_id}", headers={"Authorization": f"Bearer {token4}"}
    )
    assert resp.status_code == 403
    # Admin can delete
    resp = client.delete(
        f"/rules/{rule_id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 200
