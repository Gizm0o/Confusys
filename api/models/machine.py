from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy.orm import Mapped

from api import db

if TYPE_CHECKING:
    from api.models.user import Role

machine_roles = db.Table(
    "machine_roles",
    db.Column(
        "machine_id", db.String(36), db.ForeignKey("machine.id"), primary_key=True
    ),
    db.Column("role_id", db.Integer, db.ForeignKey("role.id"), primary_key=True),
)


class MachineFile(db.Model):
    id = db.Column(
        db.String(36), primary_key=True, default=lambda: str(uuid4()), unique=True
    )
    filename = db.Column(db.String(255), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)
    machine_id = db.Column(db.String(36), db.ForeignKey("machine.id"), nullable=False)


class Machine(db.Model):
    id = db.Column(
        db.String(36), primary_key=True, default=lambda: str(uuid4()), unique=True
    )
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    technologies = db.Column(db.PickleType)
    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("machines", lazy=True))
    script = db.Column(db.Text)
    token = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        default=lambda: str(uuid4()).replace("-", ""),
    )
    files = db.relationship("MachineFile", backref="machine", lazy=True)
    roles = db.relationship(
        "Role",
        secondary="machine_roles",
        backref=db.backref("machines", lazy="dynamic"),
    )


# Association table for rules and roles
rule_roles = db.Table(
    "rule_roles",
    db.Column("rule_id", db.String(36), db.ForeignKey("rule.id"), primary_key=True),
    db.Column("role_id", db.Integer, db.ForeignKey("role.id"), primary_key=True),
)


class Rule(db.Model):
    id = db.Column(
        db.String(36), primary_key=True, default=lambda: str(uuid4()), unique=True
    )
    filename = db.Column(db.String(255), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)
    description = db.Column(db.String(255))
    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("rules", lazy=True))
    roles: Mapped[list["Role"]] = db.relationship("Role", secondary=rule_roles, backref=db.backref("rules", lazy="dynamic"))  # type: ignore
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
