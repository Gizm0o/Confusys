from flask import Blueprint, request, jsonify, send_file
from api.models.machine import Rule
from api.models.user import User, Role
from api import db
import uuid
from functools import wraps
from flask import current_app
from werkzeug.utils import secure_filename
import io
from datetime import datetime, timezone

rule_bp = Blueprint('rule', __name__)

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
            import jwt
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

def user_can_access_rule(user, rule):
    if is_admin(user) or rule.user_id == user.id:
        return True
    user_role_ids = {role.id for role in user.roles}
    rule_role_ids = {role.id for role in rule.roles}
    return bool(user_role_ids & rule_role_ids)

@rule_bp.route('', methods=['POST'])
@token_required
def upload_rule(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if not file or not file.filename:
        return jsonify({'error': 'No selected file'}), 400
    filename = secure_filename(str(file.filename))
    data = file.read()
    description = request.form.get('description')
    role_names = request.form.getlist('roles')
    roles = Role.query.filter(Role.name.in_(role_names)).all() if role_names else []
    rule = Rule(filename=filename, data=data, description=description, user_id=current_user.id)
    rule.roles = roles
    db.session.add(rule)
    db.session.commit()
    return jsonify({'id': rule.id, 'filename': rule.filename, 'description': rule.description, 'roles': [r.name for r in rule.roles]}), 201

@rule_bp.route('', methods=['GET'])
@token_required
def list_rules(current_user):
    if is_admin(current_user):
        rules = Rule.query.all()
    else:
        user_role_ids = [role.id for role in current_user.roles]
        rules = Rule.query.join(Rule.roles).filter(Role.id.in_(user_role_ids)).all()
        # Also include rules owned by the user
        owned_rules = Rule.query.filter_by(user_id=current_user.id).all()
        rules = list({r.id: r for r in rules + owned_rules}.values())
    return jsonify([
        {'id': r.id, 'filename': r.filename, 'description': r.description, 'roles': [role.name for role in r.roles], 'owner': r.user_id}
        for r in rules
    ])

@rule_bp.route('/<rule_id>', methods=['GET'])
@token_required
def get_rule(current_user, rule_id):
    try:
        uuid.UUID(str(rule_id))
    except ValueError:
        return jsonify({'error': 'Invalid rule ID format'}), 400
    rule = db.session.get(Rule, rule_id)
    if not rule or not user_can_access_rule(current_user, rule):
        return jsonify({'error': 'Rule not found or access denied'}), 404
    # Optionally allow download
    if request.args.get('download') == '1':
        return send_file(io.BytesIO(rule.data), as_attachment=True, download_name=rule.filename)
    return jsonify({'id': rule.id, 'filename': rule.filename, 'description': rule.description, 'roles': [role.name for role in rule.roles], 'owner': rule.user_id})

@rule_bp.route('/<rule_id>', methods=['PUT'])
@token_required
def update_rule(current_user, rule_id):
    try:
        uuid.UUID(str(rule_id))
    except ValueError:
        return jsonify({'error': 'Invalid rule ID format'}), 400
    rule = db.session.get(Rule, rule_id)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404
    if not user_can_access_rule(current_user, rule):
        return jsonify({'error': 'Rule access denied'}), 403
    # Only owner or admin can update
    if not (is_admin(current_user) or rule.user_id == current_user.id):
        return jsonify({'error': 'Only owner or admin can update rule'}), 403
    # Update description
    if 'description' in request.form:
        rule.description = request.form['description']
    # Update roles
    if 'roles' in request.form or 'roles[]' in request.form:
        role_names = request.form.getlist('roles') or request.form.getlist('roles[]')
        roles = Role.query.filter(Role.name.in_(role_names)).all() if role_names else []
        rule.roles = roles
    # Update file
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename:
            rule.filename = secure_filename(str(file.filename))
            rule.data = file.read()
    db.session.commit()
    return jsonify({'message': 'Rule updated successfully'})

@rule_bp.route('/<rule_id>', methods=['DELETE'])
@token_required
def delete_rule(current_user, rule_id):
    try:
        uuid.UUID(str(rule_id))
    except ValueError:
        return jsonify({'error': 'Invalid rule ID format'}), 400
    rule = db.session.get(Rule, rule_id)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404
    if not user_can_access_rule(current_user, rule):
        return jsonify({'error': 'Rule access denied'}), 403
    # Only owner or admin can delete
    if not (is_admin(current_user) or rule.user_id == current_user.id):
        return jsonify({'error': 'Only owner or admin can delete rule'}), 403
    db.session.delete(rule)
    db.session.commit()
    return jsonify({'message': 'Rule deleted successfully'}) 