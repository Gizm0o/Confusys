import io
import uuid
from functools import wraps
from typing import Any, Callable, Tuple, Union

from flask import Blueprint, current_app, jsonify, request, send_file
from werkzeug.utils import secure_filename

from api import db
from api.models.machine import Rule
from api.models.user import Role, User

rule_bp = Blueprint("rule", __name__)


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
            import jwt

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


def user_can_access_rule(user: User, rule: Rule) -> bool:
    if is_admin(user) or rule.user_id == user.id:
        return True
    user_role_ids = {role.id for role in user.roles}
    rule_role_ids = {role.id for role in rule.roles}
    return bool(user_role_ids & rule_role_ids)


@rule_bp.route("", methods=["POST"])
@token_required
def upload_rule(current_user: User) -> Union[Any, Tuple[Any, int]]:
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "No selected file"}), 400
    filename = secure_filename(str(file.filename))
    data = file.read()
    description = request.form.get("description")
    role_names = request.form.getlist("roles")
    technologies = request.form.getlist("technologies")
    roles = Role.query.filter(Role.name.in_(role_names)).all() if role_names else []
    rule = Rule(
        filename=filename, data=data, description=description, user_id=current_user.id
    )
    rule.roles = roles
    rule.technologies = technologies
    db.session.add(rule)
    db.session.commit()
    return (
        jsonify(
            {
                "id": rule.id,
                "filename": rule.filename,
                "description": rule.description,
                "roles": [r.name for r in rule.roles],
                "technologies": rule.technologies or [],
            }
        ),
        201,
    )


@rule_bp.route("", methods=["GET"])
@token_required
def list_rules(current_user: User) -> Any:
    if is_admin(current_user):
        rules = Rule.query.all()
    else:
        user_role_ids = [role.id for role in current_user.roles]
        rules = Rule.query.join(Rule.roles).filter(Role.id.in_(user_role_ids)).all()
        # Also include rules owned by the user
        owned_rules = Rule.query.filter_by(user_id=current_user.id).all()
        rules = list({r.id: r for r in rules + owned_rules}.values())
    return jsonify(
        [
            {
                "id": r.id,
                "filename": r.filename,
                "description": r.description,
                "technologies": r.technologies or [],
                "roles": [role.name for role in r.roles],
                "owner": r.user_id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rules
        ]
    )


@rule_bp.route("/<rule_id>", methods=["GET"])
@token_required
def get_rule(current_user: User, rule_id: str) -> Union[Any, Tuple[Any, int]]:
    try:
        uuid.UUID(str(rule_id))
    except ValueError:
        return jsonify({"error": "Invalid rule ID format"}), 400
    rule = db.session.get(Rule, rule_id)
    if not rule or not user_can_access_rule(current_user, rule):
        return jsonify({"error": "Rule not found or access denied"}), 404
    # Optionally allow download
    if request.args.get("download") == "1":
        return send_file(
            io.BytesIO(rule.data), as_attachment=True, download_name=rule.filename
        )
    return jsonify(
        {
            "id": rule.id,
            "filename": rule.filename,
            "description": rule.description,
            "technologies": rule.technologies or [],
            "roles": [role.name for role in rule.roles],
            "owner": rule.user_id,
            "content": rule.data.decode("utf-8") if rule.data else "",
            "created_at": rule.created_at.isoformat() if rule.created_at else None,
        }
    )


@rule_bp.route("/<rule_id>", methods=["PUT"])
@token_required
def update_rule(current_user: User, rule_id: str) -> Union[Any, Tuple[Any, int]]:
    try:
        uuid.UUID(str(rule_id))
    except ValueError:
        return jsonify({"error": "Invalid rule ID format"}), 400
    rule = db.session.get(Rule, rule_id)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404
    if not user_can_access_rule(current_user, rule):
        return jsonify({"error": "Rule access denied"}), 403
    # Only owner or admin can update
    if not (is_admin(current_user) or rule.user_id == current_user.id):
        return jsonify({"error": "Only owner or admin can update rule"}), 403
    # Update description
    if "description" in request.form:
        rule.description = request.form["description"]
    # Update roles
    if "roles" in request.form or "roles[]" in request.form:
        role_names = request.form.getlist("roles") or request.form.getlist("roles[]")
        roles = Role.query.filter(Role.name.in_(role_names)).all() if role_names else []
        rule.roles = roles
    # Update technologies
    if "technologies" in request.form or "technologies[]" in request.form:
        technologies = request.form.getlist("technologies") or request.form.getlist(
            "technologies[]"
        )
        rule.technologies = technologies
    # Update file content
    if "content" in request.form:
        try:
            # Validate YAML content
            import yaml

            content = request.form["content"]
            yaml.safe_load(content)  # This will raise an exception if invalid
            rule.data = content.encode("utf-8")
        except yaml.YAMLError as e:
            return jsonify({"error": f"Invalid YAML content: {str(e)}"}), 400
        except Exception as e:
            return jsonify({"error": f"Error updating content: {str(e)}"}), 400

    # Update file
    if "file" in request.files:
        file = request.files["file"]
        if file and file.filename:
            rule.filename = secure_filename(str(file.filename))
            rule.data = file.read()

    db.session.commit()
    return jsonify({"message": "Rule updated successfully"})


@rule_bp.route("/<rule_id>", methods=["DELETE"])
@token_required
def delete_rule(current_user: User, rule_id: str) -> Union[Any, Tuple[Any, int]]:
    try:
        uuid.UUID(str(rule_id))
    except ValueError:
        return jsonify({"error": "Invalid rule ID format"}), 400
    rule = db.session.get(Rule, rule_id)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404
    if not user_can_access_rule(current_user, rule):
        return jsonify({"error": "Rule access denied"}), 403
    # Only owner or admin can delete
    if not (is_admin(current_user) or rule.user_id == current_user.id):
        return jsonify({"error": "Only owner or admin can delete rule"}), 403
    db.session.delete(rule)
    db.session.commit()
    return jsonify({"message": "Rule deleted successfully"})
