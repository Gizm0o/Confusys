from typing import Any, Tuple, Union

from flask import Blueprint, jsonify, request

from api import db
from api.models.machine import Machine
from api.models.user import Role, User
from api.routes.machine_routes import is_admin, token_required

role_bp = Blueprint("role", __name__)


@role_bp.route("", methods=["POST"])
@token_required
def create_role(current_user: User) -> Union[Any, Tuple[Any, int]]:
    if not is_admin(current_user):
        return jsonify({"error": "Admin only"}), 403
    data = request.get_json()
    name = data.get("name")
    description = data.get("description")
    if not name:
        return jsonify({"error": "Missing role name"}), 400
    if Role.query.filter_by(name=name).first():
        return jsonify({"error": "Role already exists"}), 409
    role = Role(name=name, description=description)
    db.session.add(role)
    db.session.commit()
    return (
        jsonify({"id": role.id, "name": role.name, "description": role.description}),
        201,
    )


@role_bp.route("", methods=["GET"])
@token_required
def list_roles(current_user: User) -> Any:
    roles = Role.query.all()
    return jsonify(
        [{"id": r.id, "name": r.name, "description": r.description} for r in roles]
    )


@role_bp.route("/<int:role_id>", methods=["GET"])
@token_required
def get_role(current_user: User, role_id: int) -> Union[Any, Tuple[Any, int]]:
    role = db.session.get(Role, role_id)
    if not role:
        return jsonify({"error": "Role not found"}), 404
    return jsonify({"id": role.id, "name": role.name, "description": role.description})


@role_bp.route("/<int:role_id>", methods=["PUT"])
@token_required
def update_role(current_user: User, role_id: int) -> Union[Any, Tuple[Any, int]]:
    if not is_admin(current_user):
        return jsonify({"error": "Admin only"}), 403
    role = db.session.get(Role, role_id)
    if not role:
        return jsonify({"error": "Role not found"}), 404
    data = request.get_json()
    role.name = data.get("name", role.name)
    role.description = data.get("description", role.description)
    db.session.commit()
    return jsonify({"message": "Role updated successfully"})


@role_bp.route("/<int:role_id>", methods=["DELETE"])
@token_required
def delete_role(current_user: User, role_id: int) -> Union[Any, Tuple[Any, int]]:
    if not is_admin(current_user):
        return jsonify({"error": "Admin only"}), 403
    role = db.session.get(Role, role_id)
    if not role:
        return jsonify({"error": "Role not found"}), 404
    db.session.delete(role)
    db.session.commit()
    return jsonify({"message": "Role deleted successfully"})


@role_bp.route("/<int:role_id>/assign_user/<user_id>", methods=["POST"])
@token_required
def assign_role_to_user(current_user: User, role_id: int, user_id: str) -> Union[Any, Tuple[Any, int]]:
    if not is_admin(current_user):
        return jsonify({"error": "Admin only"}), 403
    role = db.session.get(Role, role_id)
    user = db.session.get(User, user_id)
    if not role or not user:
        return jsonify({"error": "Role or user not found"}), 404
    if role not in user.roles:
        user.roles.append(role)
        db.session.commit()
    return jsonify({"message": "Role assigned to user"})


@role_bp.route("/<int:role_id>/remove_user/<user_id>", methods=["POST"])
@token_required
def remove_role_from_user(current_user: User, role_id: int, user_id: str) -> Union[Any, Tuple[Any, int]]:
    if not is_admin(current_user):
        return jsonify({"error": "Admin only"}), 403
    role = db.session.get(Role, role_id)
    user = db.session.get(User, user_id)
    if not role or not user:
        return jsonify({"error": "Role or user not found"}), 404
    if role in user.roles:
        user.roles.remove(role)
        db.session.commit()
    return jsonify({"message": "Role removed from user"})


@role_bp.route("/<int:role_id>/assign_machine/<machine_id>", methods=["POST"])
@token_required
def assign_role_to_machine(current_user: User, role_id: int, machine_id: str) -> Union[Any, Tuple[Any, int]]:
    if not is_admin(current_user):
        return jsonify({"error": "Admin only"}), 403
    role = db.session.get(Role, role_id)
    machine = db.session.get(Machine, machine_id)
    if not role or not machine:
        return jsonify({"error": "Role or machine not found"}), 404
    if role not in machine.roles:
        machine.roles.append(role)
        db.session.commit()
    return jsonify({"message": "Role assigned to machine"})


@role_bp.route("/<int:role_id>/remove_machine/<machine_id>", methods=["POST"])
@token_required
def remove_role_from_machine(current_user: User, role_id: int, machine_id: str) -> Union[Any, Tuple[Any, int]]:
    if not is_admin(current_user):
        return jsonify({"error": "Admin only"}), 403
    role = db.session.get(Role, role_id)
    machine = db.session.get(Machine, machine_id)
    if not role or not machine:
        return jsonify({"error": "Role or machine not found"}), 404
    if role in machine.roles:
        machine.roles.remove(role)
        db.session.commit()
    return jsonify({"message": "Role removed from machine"})
