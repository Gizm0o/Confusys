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


def test_create_update_delete_machine(client):
    admin_token = get_admin_token(client)
    # Create machine
    resp = client.post(
        "/machines",
        json={"name": "mach1", "description": "desc", "roles": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201
    machine_id = resp.get_json()["machine_id"]
    # Update machine
    resp = client.put(
        f"/machines/{machine_id}",
        json={"name": "mach1-upd", "description": "desc2"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    # Get machine
    resp = client.get(
        f"/machines/{machine_id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 200
    # Delete machine
    resp = client.delete(
        f"/machines/{machine_id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 200
    # Get deleted machine
    resp = client.get(
        f"/machines/{machine_id}", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 404


def test_machine_file_upload_list_delete(client):
    admin_token = get_admin_token(client)
    # Create machine
    resp = client.post(
        "/machines",
        json={"name": "mach2", "description": "desc", "roles": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    machine_id = resp.get_json()["machine_id"]
    # Upload file
    data = {"file": (io.BytesIO(b"abc"), "a.txt")}
    resp = client.post(
        f"/machines/{machine_id}/files",
        headers={"Authorization": f"Bearer {admin_token}"},
        content_type="multipart/form-data",
        data=data,
    )
    assert resp.status_code == 201
    file_id = resp.get_json()["id"]
    # List files
    resp = client.get(
        f"/machines/{machine_id}/files",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    files = resp.get_json()
    assert any(f["id"] == file_id for f in files)
    # Delete file
    resp = client.delete(
        f"/machines/{machine_id}/files/{file_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    # List files (should be empty)
    resp = client.get(
        f"/machines/{machine_id}/files",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert not resp.get_json()


def test_machine_script_download_and_technologies(client):
    admin_token = get_admin_token(client)
    # List technologies
    resp = client.get("/machines/technologies")
    assert resp.status_code == 200
    techs = [item["key"] for item in resp.get_json()]
    # Register machine with subset
    payload = {
        "name": "mach3",
        "description": "desc",
        "roles": [],
        "technologies": techs[:3],
    }
    resp = client.post(
        "/machines", json=payload, headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 201
    machine_id = resp.get_json()["machine_id"]
    # Download script
    resp = client.get(
        f"/machines/{machine_id}/script",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    script = resp.data.decode()
    # Check for unique comments from the script blocks
    block_comments = [
        "# OS and Kernel Info",
        "# Memory and CPU Info",
        "# Disk and Filesystem Info",
        "# Processes and Services",
        "# Network Info",
        "# Routing",
        "# Users and Authentication",
        "# User History",
        "# Installed Packages",
        "# Docker Info",
        "# LXC Container Info",
        "# SELinux Info",
        "# Firewall Info",
        "# Kernel Parameters",
        "# Kernel Vulnerabilities",
        "# Shared Memory",
        "# Udev Rules",
        "# DBUS Info",
        "# SUID/SGID Files",
        "# World Writable Files",
        "# File Capabilities",
        "# Environment and Umask",
        "# Exported Filesystems",
        "# RPC Services",
        "# X Access Controls",
    ]
    for comment in block_comments[:3]:
        assert comment in script


def test_machine_access_control(client):
    # Register as normal user
    client.post(
        "/user/register",
        json={"username": "user", "email": "user@example.com", "password": "pass"},
    )
    resp = client.post("/user/login", json={"username": "user", "password": "pass"})
    token = resp.get_json()["token"]
    # Try to create machine (should succeed)
    resp = client.post(
        "/machines",
        json={"name": "mach4", "description": "desc", "roles": []},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    # Try to get/delete another machine (should fail)
    admin_token = get_admin_token(client)
    resp = client.post(
        "/machines",
        json={"name": "mach5", "description": "desc", "roles": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    other_id = resp.get_json()["machine_id"]
    resp = client.get(
        f"/machines/{other_id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code in (403, 404)
    resp = client.delete(
        f"/machines/{other_id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code in (403, 404)


def test_scan_report_storage_and_endpoints(client):
    admin_token = get_admin_token(client)
    # Create machine
    resp = client.post(
        "/machines",
        json={"name": "machscan", "description": "desc", "roles": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201
    machine_id = resp.get_json()["machine_id"]
    # Upload file with content that matches a rule (simulate docker rule)
    dockerfile_content = b"FROM ubuntu\nUSER root\nRUN echo hi\n"
    data = {"file": (io.BytesIO(dockerfile_content), "Dockerfile")}
    resp = client.post(
        f"/machines/{machine_id}/files",
        headers={"Authorization": f"Bearer {admin_token}"},
        content_type="multipart/form-data",
        data=data,
    )
    assert resp.status_code == 201
    file_id = resp.get_json()["id"]
    report_id = resp.get_json()["report_id"]
    assert report_id is not None
    # Fetch scan reports for the file
    resp = client.get(
        f"/machines/{machine_id}/files/{file_id}/scan_reports",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    reports = resp.get_json()
    assert len(reports) == 1
    findings = reports[0]["findings"]
    assert any(f["id"] == "SEC002" for f in findings)  # USER root rule
    # Fetch all scan reports for the machine
    resp = client.get(
        f"/machines/{machine_id}/scan_reports",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    all_reports = resp.get_json()
    assert any(r["id"] == report_id for r in all_reports)
    # Filter by severity
    from datetime import datetime, timedelta
    now = datetime.utcnow().isoformat()
    resp = client.get(
        f"/machines/{machine_id}/scan_reports?severity=High",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    filtered = resp.get_json()
    assert all(any(f["severity"] == "High" for f in r["findings"]) for r in filtered)
    # Filter by rule_id
    resp = client.get(
        f"/machines/{machine_id}/scan_reports?rule_id=SEC002",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    filtered = resp.get_json()
    assert all(any(f["id"] == "SEC002" for f in r["findings"]) for r in filtered)
    # Filter by date
    resp = client.get(
        f"/machines/{machine_id}/scan_reports?start_date={now}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    # Should be empty since start_date is now
    assert resp.get_json() == []


def test_scan_report_permissions_and_edge_cases(client):
    # Setup admin and user
    client.post(
        "/user/register",
        json={"username": "user", "email": "user@example.com", "password": "pass"},
    )
    resp = client.post("/user/login", json={"username": "user", "password": "pass"})
    user_token = resp.get_json()["token"]
    admin_token = get_admin_token(client)
    # Admin creates a machine and uploads a file
    resp = client.post(
        "/machines",
        json={"name": "machperms", "description": "desc", "roles": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    machine_id = resp.get_json()["machine_id"]
    data = {"file": (io.BytesIO(b"USER root\n"), "Dockerfile")}
    resp = client.post(
        f"/machines/{machine_id}/files",
        headers={"Authorization": f"Bearer {admin_token}"},
        content_type="multipart/form-data",
        data=data,
    )
    file_id = resp.get_json()["id"]
    # User tries to fetch scan reports for admin's machine/file
    resp = client.get(
        f"/machines/{machine_id}/files/{file_id}/scan_reports",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code in (403, 404)
    resp = client.get(
        f"/machines/{machine_id}/scan_reports",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code in (403, 404)
    # User creates their own machine and uploads a file
    resp = client.post(
        "/machines",
        json={"name": "machuser", "description": "desc", "roles": []},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    user_machine_id = resp.get_json()["machine_id"]
    data = {"file": (io.BytesIO(b"no match here"), "file.txt")}
    resp = client.post(
        f"/machines/{user_machine_id}/files",
        headers={"Authorization": f"Bearer {user_token}"},
        content_type="multipart/form-data",
        data=data,
    )
    user_file_id = resp.get_json()["id"]
    # User fetches their own scan reports (should be empty findings)
    resp = client.get(
        f"/machines/{user_machine_id}/files/{user_file_id}/scan_reports",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 200
    reports = resp.get_json()
    assert len(reports) == 1
    assert reports[0]["findings"] == []
    # Non-existent file/machine
    import uuid
    fake_id = str(uuid.uuid4())
    resp = client.get(
        f"/machines/{fake_id}/files/{fake_id}/scan_reports",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code in (403, 404)
    resp = client.get(
        f"/machines/{fake_id}/scan_reports",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code in (403, 404)
    # Multiple reports per file (simulate by uploading the same file twice)
    data = {"file": (io.BytesIO(b"USER root\n"), "Dockerfile")}
    resp = client.post(
        f"/machines/{user_machine_id}/files",
        headers={"Authorization": f"Bearer {user_token}"},
        content_type="multipart/form-data",
        data=data,
    )
    new_file_id = resp.get_json()["id"]
    resp = client.get(
        f"/machines/{user_machine_id}/files/{new_file_id}/scan_reports",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 200
    reports = resp.get_json()
    assert len(reports) == 1
    assert any(f["id"] == "SEC002" for f in reports[0]["findings"])


def test_machine_upload_with_auto_scan(client):
    admin_token = get_admin_token(client)
    # Create machine
    resp = client.post(
        "/machines",
        json={"name": "autoscan", "description": "desc", "roles": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201
    machine_id = resp.get_json()["machine_id"]
    machine_token = resp.get_json()["token"]
    
    # Upload file as machine (with content that matches a rule)
    dockerfile_content = b"FROM ubuntu\nUSER root\nRUN echo hi\n"
    data = {"file": (io.BytesIO(dockerfile_content), "Dockerfile")}
    resp = client.post(
        f"/machines/{machine_id}/upload",
        headers={"Authorization": f"Bearer {machine_token}"},
        content_type="multipart/form-data",
        data=data,
    )
    assert resp.status_code == 201
    result = resp.get_json()
    assert "id" in result
    assert "filename" in result
    assert "scan_results" in result
    
    # Check scan results
    scan_results = result["scan_results"]
    assert "total_findings" in scan_results
    assert "critical_findings" in scan_results
    assert "high_findings" in scan_results
    assert "medium_findings" in scan_results
    assert "findings" in scan_results
    
    # Should have at least one finding (USER root rule)
    assert scan_results["total_findings"] > 0
    assert len(scan_results["findings"]) > 0
    
    # Test with invalid machine token
    resp = client.post(
        f"/machines/{machine_id}/upload",
        headers={"Authorization": f"Bearer invalid_token"},
        content_type="multipart/form-data",
        data=data,
    )
    assert resp.status_code == 401
    
    # Test with wrong machine ID
    resp = client.post(
        "/machines/00000000-0000-0000-0000-000000000000/upload",
        headers={"Authorization": f"Bearer {machine_token}"},
        content_type="multipart/form-data",
        data=data,
    )
    assert resp.status_code == 401
