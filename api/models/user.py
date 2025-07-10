from __future__ import annotations

from uuid import uuid4

from sqlalchemy.orm import Mapped
from werkzeug.security import check_password_hash, generate_password_hash

from api import db

user_roles = db.Table(
    "user_roles",
    db.Column("user_id", db.String(36), db.ForeignKey("user.id"), primary_key=True),
    db.Column("role_id", db.Integer, db.ForeignKey("role.id"), primary_key=True),
)


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(255))


class User(db.Model):
    id = db.Column(
        db.String(36), primary_key=True, default=lambda: str(uuid4()), unique=True
    )
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    roles: Mapped[list[Role]] = db.relationship(
        "Role", secondary=user_roles, backref=db.backref("users", lazy="dynamic")
    )  # type: ignore

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
