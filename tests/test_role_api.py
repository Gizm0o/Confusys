import sys
import os
import pytest
from api import create_app, db
from api.models.user import User, Role

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


def test_admin_can_create_and_delete_role(client):
    admin_token = get_admin_token(client)
    resp = client.post(
        "/roles",
        json={"name": "testrole", "description": "desc"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201
    role_id = resp.get_json()["id"]
    # Delete role
    resp = client.delete(
        f"/roles/{role_id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 200


def test_non_admin_cannot_create_or_delete_role(client):
    # Register and login as normal user
    client.post(
        "/user/register",
        json={"username": "user", "email": "user@example.com", "password": "pass"},
    )
    resp = client.post("/user/login", json={"username": "user", "password": "pass"})
    token = resp.get_json()["token"]
    # Try to create role
    resp = client.post(
        "/roles",
        json={"name": "failrole", "description": "desc"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_assign_remove_role_to_user_and_machine(client):
    admin_token = get_admin_token(client)
    # Create role
    resp = client.post(
        "/roles",
        json={"name": "assignrole", "description": "desc"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    role_id = resp.get_json()["id"]
    # Register user
    client.post(
        "/user/register",
        json={"username": "user2", "email": "user2@example.com", "password": "pass"},
    )
    resp = client.post("/user/login", json={"username": "user2", "password": "pass"})
    user_id = resp.get_json()["user_id"]
    # Assign role to user
    resp = client.post(
        f"/roles/{role_id}/assign_user/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    # Remove role from user
    resp = client.post(
        f"/roles/{role_id}/remove_user/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    # Register machine
    resp = client.post(
        "/machines",
        json={"name": "mach", "description": "desc", "roles": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    machine_id = resp.get_json()["machine_id"]
    # Assign role to machine
    resp = client.post(
        f"/roles/{role_id}/assign_machine/{machine_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    # Remove role from machine
    resp = client.post(
        f"/roles/{role_id}/remove_machine/{machine_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
