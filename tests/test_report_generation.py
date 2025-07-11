import io
import pytest
from api import create_app, db
from api.models.machine import MachineFileScanReport, MachineFile
from api.models.user import Role, User


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


def test_report_generation_user_upload(client):
    admin_token = get_admin_token(client)
    # Create machine
    resp = client.post(
        "/machines",
        json={"name": "reportmach", "description": "desc", "roles": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    machine_id = resp.get_json()["machine_id"]
    # Upload file as user
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
    # Fetch scan reports for the file
    resp = client.get(
        f"/machines/{machine_id}/files/{file_id}/scan_reports",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    reports = resp.get_json()
    assert len(reports) == 1
    findings = reports[0]["findings"]
    assert any(f["id"] == "SEC002" for f in findings)
    # Check DB directly
    with client.application.app_context():
        scan_reports = MachineFileScanReport.query.filter_by(
            machine_file_id=file_id
        ).all()
        assert len(scan_reports) == 1
        assert any(f["id"] == "SEC002" for f in scan_reports[0].findings)


def test_report_generation_machine_upload(client):
    admin_token = get_admin_token(client)
    # Create machine
    resp = client.post(
        "/machines",
        json={"name": "reportmach2", "description": "desc", "roles": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    machine_id = resp.get_json()["machine_id"]
    machine_token = resp.get_json()["token"]
    # Upload file as machine
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
    file_id = result["id"]
    scan_results = result["scan_results"]
    assert scan_results["total_findings"] > 0
    assert any(f["id"] == "SEC002" for f in scan_results["findings"])
    # Check DB directly
    with client.application.app_context():
        scan_reports = MachineFileScanReport.query.filter_by(
            machine_file_id=file_id
        ).all()
        assert len(scan_reports) == 1
        assert any(f["id"] == "SEC002" for f in scan_reports[0].findings)
