import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from api import create_app, db
from api.models.user import User, Role
from api.models.machine import Machine
import json
import io

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

def test_machine_file_upload_and_list(client):
    admin_token = get_admin_token(client)
    # Create a new role
    resp = client.post('/roles', json={'name': 'fileop', 'description': 'File Operator'}, headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 201
    role_id = resp.get_json()['id']
    # Register a user and assign fileop role
    token, user_id = get_auth_token(client, username='fileuser', password='filepass', email='file@example.com')
    client.post(f'/roles/{role_id}/assign_user/{user_id}', headers={'Authorization': f'Bearer {admin_token}'})
    # Register a machine with fileop role
    resp = client.post('/machines', json={'name': 'FileMachine', 'description': 'For file upload', 'roles': ['fileop']}, headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code == 201
    machine_id = resp.get_json()['id']
    # Upload a file
    data = {'file': (io.BytesIO(b'hello world'), 'test.txt')}
    resp = client.post(f'/machines/{machine_id}/files', headers={'Authorization': f'Bearer {token}'}, content_type='multipart/form-data', data=data)
    assert resp.status_code == 201
    file_id = resp.get_json()['id']
    # List files
    resp = client.get(f'/machines/{machine_id}/files', headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code == 200
    files = resp.get_json()
    assert any(f['id'] == file_id and f['filename'] == 'test.txt' for f in files)
    # Access denied for user without role
    token2, _ = get_auth_token(client, username='otheruser', password='otherpass', email='other@example.com')
    data2 = {'file': (io.BytesIO(b'hello world'), 'test.txt')}
    resp = client.post(f'/machines/{machine_id}/files', headers={'Authorization': f'Bearer {token2}'}, content_type='multipart/form-data', data=data2)
    assert resp.status_code == 404
    # Admin can upload
    data3 = {'file': (io.BytesIO(b'admin file'), 'admin.txt')}
    resp = client.post(f'/machines/{machine_id}/files', headers={'Authorization': f'Bearer {admin_token}'}, content_type='multipart/form-data', data=data3)
    assert resp.status_code == 201
    # Upload with no file
    resp = client.post(f'/machines/{machine_id}/files', headers={'Authorization': f'Bearer {token}'}, content_type='multipart/form-data', data={})
    assert resp.status_code == 400
    # Upload with empty filename
    data4 = {'file': (io.BytesIO(b''), '')}
    resp = client.post(f'/machines/{machine_id}/files', headers={'Authorization': f'Bearer {token}'}, content_type='multipart/form-data', data=data4)
    assert resp.status_code == 400 