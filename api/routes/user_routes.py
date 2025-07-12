from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, Dict, Tuple, Union

import jwt
from flask import Blueprint, current_app, jsonify, request

from api import db
from api.models.user import Role, User

user_bp = Blueprint("user", __name__)


def admin_required(f: Callable) -> Callable:
    """Decorator to require admin role"""
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
            data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = db.session.get(User, data["user_id"])
            if not current_user:
                return jsonify({"error": "User not found!"}), 401
            
            # Check if user is admin
            if not any(role.name == "admin" for role in current_user.roles):
                return jsonify({"error": "Admin access required!"}), 403
                
        except Exception:
            return jsonify({"error": "Token is invalid!"}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated





@user_bp.route("/login", methods=["POST"])
def login() -> Tuple[Any, int]:
    """Login user and return JWT token"""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        expiration = datetime.now(timezone.utc) + timedelta(hours=10)
        issued_at = datetime.now(timezone.utc)
        payload = {"user_id": user.id, "exp": expiration, "iat": issued_at}
        token = jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")
        return (
            jsonify(
                {
                    "message": "Authenticated successfully",
                    "user_id": user.id,
                    "token": token,
                }
            ),
            200,
        )

    return jsonify({"error": "Invalid credentials"}), 401


@user_bp.route("/users", methods=["GET"])
@admin_required
def list_users(current_user: User) -> Any:
    """List all users (admin only)"""
    users = User.query.all()
    return jsonify([
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": [role.name for role in user.roles]
        }
        for user in users
    ])


@user_bp.route("/users", methods=["POST"])
@admin_required
def create_user(current_user: User) -> Tuple[Any, int]:
    """Create a new user (admin only)"""
    data = request.get_json()
    username = data.get("username")
    email = data.get("email", "")  # Make email optional
    password = data.get("password")
    role_names = data.get("roles", [])

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # Check for existing username
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409

    # Check for existing email only if email is provided
    if email and User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 409

    user = User(username=username, email=email)
    user.set_password(password)
    
    # Assign roles
    if role_names:
        roles = Role.query.filter(Role.name.in_(role_names)).all()
        user.roles = roles
    
    db.session.add(user)
    db.session.commit()

    return jsonify({
        "message": "User created successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": [role.name for role in user.roles]
        }
    }), 201


@user_bp.route("/users/<user_id>", methods=["GET", "PUT", "DELETE"])
@admin_required
def manage_user(current_user: User, user_id: str) -> Union[Any, Tuple[Any, int]]:
    """Get, update, or delete a user (admin only)"""
    try:
        import uuid
        uuid.UUID(str(user_id))
    except ValueError:
        return jsonify({"error": "Invalid user ID format"}), 400

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if request.method == "GET":
        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": [role.name for role in user.roles]
        })
    elif request.method == "PUT":
        data = request.get_json()
        
        if "username" in data:
            # Check if username is already taken by another user
            existing_user = User.query.filter_by(username=data["username"]).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({"error": "Username already taken"}), 409
            user.username = data["username"]
        
        if "email" in data:
            email = data["email"].strip() if data["email"] else ""
            # Check if email is already taken by another user (only if email is provided)
            if email:
                existing_user = User.query.filter_by(email=email).first()
                if existing_user and existing_user.id != user_id:
                    return jsonify({"error": "Email already taken"}), 409
            user.email = email
        
        if "password" in data:
            user.set_password(data["password"])
        
        if "roles" in data:
            role_names = data["roles"]
            roles = Role.query.filter(Role.name.in_(role_names)).all()
            user.roles = roles
        
        db.session.commit()
        return jsonify({"message": "User updated successfully"})
    elif request.method == "DELETE":
        # Prevent admin from deleting themselves
        if user.id == current_user.id:
            return jsonify({"error": "Cannot delete your own account"}), 400
        
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"})
    else:
        return jsonify({"error": "Method not allowed"}), 405


@user_bp.route("/roles", methods=["GET"])
@admin_required
def list_roles(current_user: User) -> Any:
    """List all roles (admin only)"""
    roles = Role.query.all()
    return jsonify([
        {
            "id": role.id,
            "name": role.name,
            "description": role.description,
            "user_count": role.users.count()
        }
        for role in roles
    ])


@user_bp.route("/roles", methods=["POST"])
@admin_required
def create_role(current_user: User) -> Tuple[Any, int]:
    """Create a new role (admin only)"""
    data = request.get_json()
    name = data.get("name")
    description = data.get("description", "")

    if not name:
        return jsonify({"error": "Role name is required"}), 400

    if Role.query.filter_by(name=name).first():
        return jsonify({"error": "Role already exists"}), 409

    role = Role(name=name, description=description)
    db.session.add(role)
    db.session.commit()

    return jsonify({
        "message": "Role created successfully",
        "role": {
            "id": role.id,
            "name": role.name,
            "description": role.description
        }
    }), 201


@user_bp.route("/roles/<role_id>", methods=["GET", "PUT", "DELETE"])
@admin_required
def manage_role(current_user: User, role_id: int) -> Union[Any, Tuple[Any, int]]:
    """Get, update, or delete a role (admin only)"""
    role = db.session.get(Role, role_id)
    if not role:
        return jsonify({"error": "Role not found"}), 404

    if request.method == "GET":
        return jsonify({
            "id": role.id,
            "name": role.name,
            "description": role.description,
            "user_count": role.users.count()
        })
    elif request.method == "PUT":
        data = request.get_json()
        
        if "name" in data:
            # Check if name is already taken by another role
            existing_role = Role.query.filter_by(name=data["name"]).first()
            if existing_role and existing_role.id != role_id:
                return jsonify({"error": "Role name already taken"}), 409
            role.name = data["name"]
        
        if "description" in data:
            role.description = data["description"]
        
        db.session.commit()
        return jsonify({"message": "Role updated successfully"})
    elif request.method == "DELETE":
        # Prevent deletion of admin role
        if role.name == "admin":
            return jsonify({"error": "Cannot delete admin role"}), 400
        
        db.session.delete(role)
        db.session.commit()
        return jsonify({"message": "Role deleted successfully"})
    else:
        return jsonify({"error": "Method not allowed"}), 405
