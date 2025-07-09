import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from api import create_app, db
from api.models.user import User, Role
from api.models.machine import Machine
import json

@pytest.fixture
def client():
    test_config = {
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'
    }
    app = create_app(test_config)
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()

def get_auth_token(client, username='testuser', password='testpassword', email='test@example.com', roles=None):
    # Register user if not exists
    if not roles:
        roles = []
    client.post('/user/register', json={
        'username': username,
        'email': email,
        'password': password
    })
    # Assign roles if needed
    if roles:
        login = client.post('/user/login', json={'username': username, 'password': password})
        user_id = login.get_json()['user_id']
        admin_token = get_admin_token(client)
        for role_id in roles:
            client.post(f'/roles/{role_id}/assign_user/{user_id}', headers={'Authorization': f'Bearer {admin_token}'})
    resp = client.post('/user/login', json={
        'username': username,
        'password': password
    })
    data = resp.get_json()
    return data['token'], data['user_id']

def get_admin_token(client):
    resp = client.post('/user/login', json={'username': 'admin', 'password': 'admin'})
    return resp.get_json()['token']

def test_role_management_and_machine_access(client):
    admin_token = get_admin_token(client)
    # Create a new role
    resp = client.post('/roles', json={'name': 'operator', 'description': 'Operator role'}, headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 201
    role_id = resp.get_json()['id']
    # List roles
    resp = client.get('/roles', headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 200
    assert any(r['name'] == 'operator' for r in resp.get_json())
    # Register a user and assign operator role
    token, user_id = get_auth_token(client, username='opuser', password='opuserpass', email='op@example.com')
    client.post(f'/roles/{role_id}/assign_user/{user_id}', headers={'Authorization': f'Bearer {admin_token}'})
    # Register a machine with operator role
    resp = client.post('/machines', json={'name': 'Machine1', 'description': 'Test machine', 'roles': ['operator']}, headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code == 201
    machine = resp.get_json()
    machine_id = machine['id']
    # User with operator role can access
    resp = client.get(f'/machines/{machine_id}', headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code == 200
    # Remove operator role from user
    client.post(f'/roles/{role_id}/remove_user/{user_id}', headers={'Authorization': f'Bearer {admin_token}'})
    # Now user cannot access the machine
    resp = client.get(f'/machines/{machine_id}', headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code == 404
    # Admin can always access
    resp = client.get(f'/machines/{machine_id}', headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 200
    # Assign operator role to machine
    client.post(f'/roles/{role_id}/assign_machine/{machine_id}', headers={'Authorization': f'Bearer {admin_token}'})
    # Assign operator role back to user
    client.post(f'/roles/{role_id}/assign_user/{user_id}', headers={'Authorization': f'Bearer {admin_token}'})
    # User can access again
    resp = client.get(f'/machines/{machine_id}', headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code == 200
    # Remove operator role from machine
    client.post(f'/roles/{role_id}/remove_machine/{machine_id}', headers={'Authorization': f'Bearer {admin_token}'})
    # User cannot access
    resp = client.get(f'/machines/{machine_id}', headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code == 404
    # Clean up: delete role
    resp = client.delete(f'/roles/{role_id}', headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 200 