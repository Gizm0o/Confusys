from flask import Blueprint, request, jsonify
from api.models.machine import Machine, MachineFile
from api.models.user import User, Role
from api import db
import uuid
import jwt
from functools import wraps
from flask import current_app
from werkzeug.utils import secure_filename
from api.script_templates import generate_audit_script, SCRIPT_BLOCKS

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
    "x_access": "X server access controls"
}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = db.session.get(User, data['user_id'])
            if not current_user:
                return jsonify({'error': 'User not found!'}), 401
        except Exception as e:
            return jsonify({'error': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def is_admin(user):
    return any(role.name == 'admin' for role in user.roles)

def user_can_access_machine(user, machine):
    if is_admin(user):
        return True
    user_role_ids = {role.id for role in user.roles}
    machine_role_ids = {role.id for role in machine.roles}
    return bool(user_role_ids & machine_role_ids)

machine_bp = Blueprint('machine', __name__)

@machine_bp.route('/machines', methods=['POST'])
@token_required
def register_machine(current_user):
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    role_names = data.get('roles', [])
    technologies = data.get('technologies', [])
    if not name:
        return jsonify({'error': 'Missing machine name'}), 400
    roles = Role.query.filter(Role.name.in_(role_names)).all() if role_names else []
    # Generate the custom audit script
    script = generate_audit_script(technologies)
    machine = Machine(name=name, description=description, user_id=current_user.id, script=script)
    db.session.add(machine)
    db.session.commit()
    machine.roles = list(roles)
    db.session.commit()
    return jsonify({'machine_id': machine.id, 'token': machine.token, 'script': script}), 201

@machine_bp.route('/machines', methods=['GET'])
@token_required
def list_machines(current_user):
    if is_admin(current_user):
        machines = Machine.query.all()
    else:
        user_role_ids = [role.id for role in current_user.roles]
        machines = Machine.query.join(Machine.roles).filter(Role.id.in_(user_role_ids)).all()
    return jsonify([
        {'id': m.id, 'name': m.name, 'description': m.description, 'token': m.token, 'roles': [r.name for r in m.roles]}
        for m in machines
    ])

@machine_bp.route('/machines/<machine_id>', methods=['GET'])
@token_required
def get_machine(current_user, machine_id):
    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({'error': 'Invalid machine ID format'}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({'error': 'Machine not found or access denied'}), 404
    return jsonify({'id': machine.id, 'name': machine.name, 'description': machine.description, 'token': machine.token, 'roles': [r.name for r in machine.roles]})

@machine_bp.route('/machines/<machine_id>', methods=['PUT'])
@token_required
def update_machine(current_user, machine_id):
    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({'error': 'Invalid machine ID format'}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({'error': 'Machine not found or access denied'}), 404
    data = request.get_json()
    machine.name = data.get('name', machine.name)
    machine.description = data.get('description', machine.description)
    role_names = data.get('roles')
    if role_names is not None:
        roles = Role.query.filter(Role.name.in_(role_names)).all()
        machine.roles = list(roles)  # Ensure roles is a list
    db.session.commit()
    return jsonify({'message': 'Machine updated successfully'})

@machine_bp.route('/machines/<machine_id>', methods=['DELETE'])
@token_required
def delete_machine(current_user, machine_id):
    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({'error': 'Invalid machine ID format'}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({'error': 'Machine not found or access denied'}), 404
    db.session.delete(machine)
    db.session.commit()
    return jsonify({'message': 'Machine deleted successfully'})

@machine_bp.route('/machines/<machine_id>/files', methods=['POST'])
@token_required
def upload_machine_file(current_user, machine_id):
    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({'error': 'Invalid machine ID format'}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({'error': 'Machine not found or access denied'}), 404
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if not file or not file.filename:
        return jsonify({'error': 'No selected file'}), 400
    filename = secure_filename(str(file.filename))
    data = file.read()
    machine_file = MachineFile(filename=filename, data=data, machine_id=machine.id)
    db.session.add(machine_file)
    db.session.commit()
    return jsonify({'id': machine_file.id, 'filename': machine_file.filename}), 201

@machine_bp.route('/machines/<machine_id>/files', methods=['GET'])
@token_required
def list_machine_files(current_user, machine_id):
    try:
        uuid.UUID(str(machine_id))
    except ValueError:
        return jsonify({'error': 'Invalid machine ID format'}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({'error': 'Machine not found or access denied'}), 404
    files = [{'id': f.id, 'filename': f.filename} for f in machine.files]
    return jsonify(files)

@machine_bp.route('/machines/<machine_id>/files/<file_id>', methods=['DELETE'])
@token_required
def delete_machine_file(current_user, machine_id, file_id):
    try:
        uuid.UUID(str(machine_id))
        uuid.UUID(str(file_id))
    except ValueError:
        return jsonify({'error': 'Invalid ID format'}), 400
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({'error': 'Machine not found or access denied'}), 404
    machine_file = db.session.get(MachineFile, file_id)
    if not machine_file or machine_file.machine_id != machine.id:
        return jsonify({'error': 'File not found or does not belong to this machine'}), 404
    db.session.delete(machine_file)
    db.session.commit()
    return jsonify({'message': 'File deleted successfully'})

@machine_bp.route('/machines/<machine_id>/script', methods=['GET'])
@token_required
def get_machine_script(current_user, machine_id):
    machine = db.session.get(Machine, machine_id)
    if not machine or not user_can_access_machine(current_user, machine):
        return jsonify({'error': 'Machine not found or access denied'}), 404
    return (machine.script, 200, {'Content-Type': 'text/x-shellscript; charset=utf-8'})

@machine_bp.route('/machines/technologies', methods=['GET'])
def list_technologies():
    return jsonify([
        {"key": k, "description": TECH_DESCRIPTIONS.get(k, k)}
        for k in SCRIPT_BLOCKS.keys()
    ]) 