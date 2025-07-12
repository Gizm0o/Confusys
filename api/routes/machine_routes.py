import uuid
from functools import wraps
from typing import Any, Callable, List, Tuple, Union

import jwt
from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

from api import db
from api.models.machine import Machine, MachineFile, MachineFileScanReport
from api.models.user import Role, User
from api.script_templates import SCRIPT_BLOCKS, generate_audit_script
from rules_engine import scan_file_with_rules

TECH_DESCRIPTIONS = {
    "os_kernel": "Operating system and kernel information",
    "memory_cpu": "Memory and CPU statistics",
    "disk_filesystems": "Disk usage and filesystem details",
    "processes_services": "Running processes and system services",
    "network": "Network interfaces and connections",
    "routing": "Network routing tables",
    "users_auth": "User accounts and authentication configuration",
    "history": "User login and shell history",
    "packages": "Installed software packages",
    "docker": "Docker container information",
    "lxc": "LXC container information",
    "selinux": "SELinux security status",
    "firewall": "Firewall and packet filter rules",
    "kernel_params": "Kernel parameters (sysctl)",
    "kernel_vuln": "Kernel CPU vulnerability status",
    "shared_memory": "Shared memory segments",
    "udev": "udev rules and device events",
    "dbus": "DBUS system information",
    "suid_sgid": "SUID/SGID files",
    "world_writable": "World-writable files",
    "capabilities": "File capabilities",
    "env_umask": "Environment variables and umask",
    "exports": "NFS exported filesystems",
    "rpc": "RPC services",
    "x_access": "X server access controls",
}


def token_required(f: Callable) -> Callable:
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Union[Tuple[Any, int], Any]:
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        if not token:
            return jsonify({"error": "Token is missing!"}), 401
        try:
            data = jwt.decode(
                token, current_app.config["SECRET_KEY"], algorithms=["HS256"]
            )
            current_user = db.session.get(User, data["user_id"])
            if not current_user:
                return jsonify({"error": "User not found!"}), 401
        except Exception:
            return jsonify({"error": "Token is invalid!"}), 401
        return f(current_user, *args, **kwargs)

    return decorated


def is_admin(user: User) -> bool:
    return any(role.name == "admin" for role in user.roles)


def user_can_access_machine(user: User, machine: Machine) -> bool:
    if is_admin(user):
        return True
    # Users can access machines they created
    if machine.user_id == user.id:
        return True
    # Users can access machines that share roles with them
    user_role_ids = {role.id for role in user.roles}
    machine_role_ids = {role.id for role in machine.roles}
    return bool(user_role_ids & machine_role_ids)


machine_bp = Blueprint("machine", __name__)


@machine_bp.route("", methods=["POST"])
@token_required
def register_machine(current_user: User) -> Tuple[Any, int]:
    data = request.get_json()
    name = data.get("name")
    description = data.get("description")
    role_names = data.get("roles", [])
    technologies = data.get("technologies", [])
    if not name:
        return jsonify({"error": "Missing machine name"}), 400
    roles = Role.query.filter(Role.name.in_(role_names)).all() if role_names else []
    # Generate the custom audit script
    script = generate_audit_script(technologies)
    machine = Machine(
        name=name,
        description=description,
        user_id=current_user.id,
        script=script,
        technologies=technologies,
    )
    db.session.add(machine)
    db.session.commit()
    machine.roles = list(roles)
    db.session.commit()
    return (
        jsonify({"machine_id": machine.id, "token": machine.token, "script": script}),
        201,
    )


@machine_bp.route("", methods=["GET"])
@token_required
def list_machines(current_user: User) -> Any:
    if is_admin(current_user):
        machines = Machine.query.all()
    else:
        user_role_ids = [role.id for role in current_user.roles]
        machines = (
            Machine.query.join(Machine.roles).filter(Role.id.in_(user_role_ids)).all()
        )
    return jsonify(
        [
            {
                "id": m.id,
                "name": m.name,
                "description": m.description,
                "token": m.token,
                "roles": [r.name for r in m.roles],
                "technologies": m.technologies or [],
            }
            for m in machines
        ]
    )


@machine_bp.route("/<machine_id>", methods=["GET"])
@token_required
def get_machine(current_user: User, machine_id: str) -> Union[Any, Tuple[Any, int]]:
    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({"error": "Invalid machine ID format"}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({"error": "Machine not found or access denied"}), 404
    return jsonify(
        {
            "id": machine.id,
            "name": machine.name,
            "description": machine.description,
            "token": machine.token,
            "roles": [r.name for r in machine.roles],
        }
    )


@machine_bp.route("/<machine_id>", methods=["PUT"])
@token_required
def update_machine(current_user: User, machine_id: str) -> Union[Any, Tuple[Any, int]]:
    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({"error": "Invalid machine ID format"}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({"error": "Machine not found or access denied"}), 404
    data = request.get_json()
    machine.name = data.get("name", machine.name)
    machine.description = data.get("description", machine.description)
    role_names = data.get("roles")
    if role_names is not None:
        roles = Role.query.filter(Role.name.in_(role_names)).all()
        machine.roles = list(roles)  # Ensure roles is a list
    db.session.commit()
    return jsonify({"message": "Machine updated successfully"})


@machine_bp.route("/<machine_id>", methods=["DELETE"])
@token_required
def delete_machine(current_user: User, machine_id: str) -> Union[Any, Tuple[Any, int]]:
    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({"error": "Invalid machine ID format"}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({"error": "Machine not found or access denied"}), 404
    db.session.delete(machine)
    db.session.commit()
    return jsonify({"message": "Machine deleted successfully"})


@machine_bp.route("/<machine_id>/files", methods=["POST"])
@token_required
def upload_machine_file(
    current_user: User, machine_id: str
) -> Union[Any, Tuple[Any, int]]:
    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({"error": "Invalid machine ID format"}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({"error": "Machine not found or access denied"}), 404
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "No selected file"}), 400
    filename = secure_filename(str(file.filename))
    data = file.read()
    machine_file = MachineFile(filename=filename, data=data, machine_id=machine.id)
    db.session.add(machine_file)
    db.session.commit()

    # Scan the uploaded file with rules
    report_id = None
    try:
        # Get language from request parameters or use system default
        language = request.args.get("language")
        report = scan_file_with_rules(filename, data, language=language)
        # Store the report in the database
        from uuid import uuid4

        scan_report = MachineFileScanReport(
            id=str(uuid4()),
            machine_file_id=machine_file.id,
            findings=report,
        )
        db.session.add(scan_report)
        db.session.commit()
        report_id = scan_report.id
    except Exception as e:
        # Log the error but don't fail the upload
        print(f"Scan failed for file {filename}: {e}")
        # Don't rollback the file upload, just continue without scan report

    return (
        jsonify(
            {
                "id": machine_file.id,
                "filename": machine_file.filename,
                "report_id": report_id,
            }
        ),
        201,
    )


@machine_bp.route("/<machine_id>/files", methods=["GET"])
@token_required
def list_machine_files(current_user: User, machine_id: str) -> Any:
    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({"error": "Invalid machine ID format"}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({"error": "Machine not found or access denied"}), 404
    files = [{"id": f.id, "filename": f.filename} for f in machine.files]
    return jsonify(files)


@machine_bp.route("/<machine_id>/files/<file_id>", methods=["DELETE"])
@token_required
def delete_machine_file(
    current_user: User, machine_id: str, file_id: str
) -> Union[Any, Tuple[Any, int]]:
    try:
        uuid.UUID(str(machine_id))
        uuid.UUID(str(file_id))
    except ValueError:
        return jsonify({"error": "Invalid ID format"}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({"error": "Machine not found or access denied"}), 404
    machine_file = db.session.get(MachineFile, file_id)
    if not machine_file or machine_file.machine_id != machine.id:
        return (
            jsonify({"error": "File not found or does not belong to this machine"}),
            404,
        )
    db.session.delete(machine_file)
    db.session.commit()
    return jsonify({"message": "File deleted successfully"})


@machine_bp.route("/<machine_id>/script", methods=["GET"])
@token_required
def get_machine_script(current_user: User, machine_id: str) -> Any:
    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({"error": "Invalid machine ID format"}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({"error": "Machine not found or access denied"}), 404
    return jsonify({"script": machine.script})


@machine_bp.route("/technologies", methods=["GET"])
def list_technologies() -> Any:
    return jsonify(
        [
            {"key": k, "description": TECH_DESCRIPTIONS.get(k, k)}
            for k in SCRIPT_BLOCKS.keys()
        ]
    )


@machine_bp.route("/<machine_id>/files/<file_id>/scan_reports", methods=["GET"])
@token_required
def get_file_scan_reports(current_user: User, machine_id: str, file_id: str):
    import uuid

    from api.models.machine import MachineFile, MachineFileScanReport

    try:
        uuid.UUID(str(machine_id))
        uuid.UUID(str(file_id))
    except ValueError:
        return jsonify({"error": "Invalid ID format"}), 400
    machine_file = db.session.get(MachineFile, file_id)
    if not machine_file or machine_file.machine_id != machine_id:
        return jsonify({"error": "File not found or does not belong to machine"}), 404

    # Check user access to the machine
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({"error": "Machine not found or access denied"}), 404

    reports = [
        {
            "id": r.id,
            "findings": r.findings,
            "scanned_at": r.scanned_at.isoformat(),
        }
        for r in machine_file.scan_reports
    ]
    return jsonify(reports)


@machine_bp.route("/<machine_id>/scan_reports", methods=["GET"])
@token_required
def get_machine_scan_reports(current_user: User, machine_id: str):
    import uuid
    from datetime import datetime

    from api.models.machine import Machine, MachineFile, MachineFileScanReport

    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({"error": "Invalid machine ID format"}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({"error": "Machine not found or access denied"}), 404
    # Get all files for this machine
    files = machine.files
    file_ids = [f.id for f in files]
    # Query params
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    severity = request.args.get("severity")
    rule_id = request.args.get("rule_id")
    # Build query
    query = MachineFileScanReport.query.filter(
        MachineFileScanReport.machine_file_id.in_(file_ids)
    )
    if start_date:
        try:
            dt = datetime.fromisoformat(start_date)
            query = query.filter(MachineFileScanReport.scanned_at >= dt)
        except Exception:
            return jsonify({"error": "Invalid start_date format, use ISO format"}), 400
    if end_date:
        try:
            dt = datetime.fromisoformat(end_date)
            query = query.filter(MachineFileScanReport.scanned_at <= dt)
        except Exception:
            return jsonify({"error": "Invalid end_date format, use ISO format"}), 400
    reports = query.all()
    # Filter by severity and rule_id in findings
    filtered_reports = []
    for r in reports:
        findings = r.findings
        if severity:
            findings = [f for f in findings if f.get("severity") == severity]
        if rule_id:
            findings = [f for f in findings if f.get("id") == rule_id]
        if findings:
            filtered_reports.append(
                {
                    "id": r.id,
                    "machine_file_id": r.machine_file_id,
                    "findings": findings,
                    "scanned_at": r.scanned_at.isoformat(),
                }
            )
    return jsonify(filtered_reports)


@machine_bp.route("/<machine_id>/upload", methods=["POST"])
def machine_upload_file(machine_id: str) -> Union[Any, Tuple[Any, int]]:
    """Endpoint for machines to upload files using their token"""
    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({"error": "Invalid machine ID format"}), 400

    # Get machine token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Machine token required"}), 401

    machine_token = auth_header.split(" ")[1]

    # Find machine by token
    machine = Machine.query.filter_by(token=machine_token).first()
    if not machine or machine.id != machine_id:
        return jsonify({"error": "Invalid machine token or machine not found"}), 401

    # Check if file is provided
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(str(file.filename))
    data = file.read()

    # Create machine file
    machine_file = MachineFile(filename=filename, data=data, machine_id=machine.id)
    db.session.add(machine_file)
    db.session.commit()

    # Automatically scan the uploaded file with rules
    try:
        # Use system default language for machine uploads
        report = scan_file_with_rules(filename, data)

        # Store the scan report
        from uuid import uuid4

        scan_report = MachineFileScanReport(
            id=str(uuid4()),
            machine_file_id=machine_file.id,
            findings=report,
        )
        db.session.add(scan_report)
        db.session.commit()

        # Return scan results immediately
        return (
            jsonify(
                {
                    "id": machine_file.id,
                    "filename": machine_file.filename,
                    "scan_results": {
                        "total_findings": len(report),
                        "critical_findings": len(
                            [f for f in report if f.get("severity") == "Critical"]
                        ),
                        "high_findings": len(
                            [f for f in report if f.get("severity") == "High"]
                        ),
                        "medium_findings": len(
                            [f for f in report if f.get("severity") == "Medium"]
                        ),
                        "findings": report,
                    },
                }
            ),
            201,
        )

    except Exception as e:
        # Still save the file even if scan fails
        return (
            jsonify(
                {
                    "id": machine_file.id,
                    "filename": machine_file.filename,
                    "scan_error": str(e),
                }
            ),
            201,
        )
