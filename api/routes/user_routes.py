from datetime import datetime, timedelta, timezone

import jwt
from flask import Blueprint, current_app, jsonify, request

from api import db
from api.models.user import User

user_bp = Blueprint("user", __name__)


@user_bp.route("/register", methods=["POST"])
def register():
    """Register a new user"""
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "User already exists"}), 409

    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


@user_bp.route("/login", methods=["POST"])
def login():
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


@user_bp.route("/<user_id>", methods=["GET", "PUT", "DELETE"])
def manage_user(user_id):
    """Get, update, or delete a user"""
    try:
        import uuid

        uuid.UUID(str(user_id))
    except ValueError:
        return jsonify({"error": "Invalid user ID format"}), 400

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if request.method == "GET":
        return jsonify({"id": user.id, "username": user.username, "email": user.email})
    elif request.method == "PUT":
        data = request.get_json()
        user.username = data.get("username", user.username)
        user.email = data.get("email", user.email)
        if "password" in data:
            user.set_password(data["password"])
        db.session.commit()
        return jsonify({"message": "User updated successfully"})
    elif request.method == "DELETE":
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"})
