import sys
import os
import pytest
from api import create_app, db
from api.models.user import User, Role
import io

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def get_admin_token(client):
    resp = client.post('/user/login', json={'username': 'admin', 'password': 'admin'})
    return resp.get_json()['token']


@pytest.fixture
def client():
    test_config = {
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SECRET_KEY': 'test-secret-key'
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


def test_create_update_delete_machine(client):
    admin_token = get_admin_token(client)
    # Create machine
    resp = client.post('/machines', json={'name': 'mach1', 'description': 'desc', 'roles': []}, headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 201
    machine_id = resp.get_json()['machine_id']
    # Update machine
    resp = client.put(f'/machines/{machine_id}', json={'name': 'mach1-upd', 'description': 'desc2'}, headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 200
    # Get machine
    resp = client.get(f'/machines/{machine_id}', headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 200
    # Delete machine
    resp = client.delete(f'/machines/{machine_id}', headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 200
    # Get deleted machine
    resp = client.get(f'/machines/{machine_id}', headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 404


def test_machine_file_upload_list_delete(client):
    admin_token = get_admin_token(client)
    # Create machine
    resp = client.post('/machines', json={'name': 'mach2', 'description': 'desc', 'roles': []}, headers={'Authorization': f'Bearer {admin_token}'})
    machine_id = resp.get_json()['machine_id']
    # Upload file
    data = {'file': (io.BytesIO(b'abc'), 'a.txt')}
    resp = client.post(f'/machines/{machine_id}/files', headers={'Authorization': f'Bearer {admin_token}'}, content_type='multipart/form-data', data=data)
    assert resp.status_code == 201
    file_id = resp.get_json()['id']
    # List files
    resp = client.get(f'/machines/{machine_id}/files', headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 200
    files = resp.get_json()
    assert any(f['id'] == file_id for f in files)
    # Delete file
    resp = client.delete(f'/machines/{machine_id}/files/{file_id}', headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 200
    # List files (should be empty)
    resp = client.get(f'/machines/{machine_id}/files', headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 200
    assert not resp.get_json()


def test_machine_script_download_and_technologies(client):
    admin_token = get_admin_token(client)
    # List technologies
    resp = client.get('/machines/technologies')
    assert resp.status_code == 200
    techs = [item['key'] for item in resp.get_json()]
    # Register machine with subset
    payload = {'name': 'mach3', 'description': 'desc', 'roles': [], 'technologies': techs[:3]}
    resp = client.post('/machines', json=payload, headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 201
    machine_id = resp.get_json()['machine_id']
    # Download script
    resp = client.get(f'/machines/{machine_id}/script', headers={'Authorization': f'Bearer {admin_token}'})
    assert resp.status_code == 200
    script = resp.data.decode()
    # Check for unique comments from the script blocks
    block_comments = [
        '# OS and Kernel Info',
        '# Memory and CPU Info',
        '# Disk and Filesystem Info',
        '# Processes and Services',
        '# Network Info',
        '# Routing',
        '# Users and Authentication',
        '# User History',
        '# Installed Packages',
        '# Docker Info',
        '# LXC Container Info',
        '# SELinux Info',
        '# Firewall Info',
        '# Kernel Parameters',
        '# Kernel Vulnerabilities',
        '# Shared Memory',
        '# Udev Rules',
        '# DBUS Info',
        '# SUID/SGID Files',
        '# World Writable Files',
        '# File Capabilities',
        '# Environment and Umask',
        '# Exported Filesystems',
        '# RPC Services',
        '# X Access Controls',
    ]
    for comment in block_comments[:3]:
        assert comment in script


def test_machine_access_control(client):
    # Register as normal user
    client.post('/user/register', json={'username': 'user', 'email': 'user@example.com', 'password': 'pass'})
    resp = client.post('/user/login', json={'username': 'user', 'password': 'pass'})
    token = resp.get_json()['token']
    # Try to create machine (should succeed)
    resp = client.post('/machines', json={'name': 'mach4', 'description': 'desc', 'roles': []}, headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code == 201
    # Try to get/delete another machine (should fail)
    admin_token = get_admin_token(client)
    resp = client.post('/machines', json={'name': 'mach5', 'description': 'desc', 'roles': []}, headers={'Authorization': f'Bearer {admin_token}'})
    other_id = resp.get_json()['machine_id']
    resp = client.get(f'/machines/{other_id}', headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code in (403, 404)
    resp = client.delete(f'/machines/{other_id}', headers={'Authorization': f'Bearer {token}'})
    assert resp.status_code in (403, 404)
