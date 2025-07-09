from __future__ import annotations
from api import db
from uuid import uuid4
from typing import List, TYPE_CHECKING
from sqlalchemy.orm import Mapped
if TYPE_CHECKING:
    from api.models.user import Role

machine_roles = db.Table('machine_roles',
    db.Column('machine_id', db.String(36), db.ForeignKey('machine.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class MachineFile(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()), unique=True)
    filename = db.Column(db.String(255), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)
    machine_id = db.Column(db.String(36), db.ForeignKey('machine.id'), nullable=False)
    machine = db.relationship('Machine', backref=db.backref('files', lazy=True))

class Machine(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()), unique=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    token = db.Column(db.String(64), unique=True, nullable=False, default=lambda: str(uuid4()).replace('-', ''))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('machines', lazy=True))
    roles: Mapped[list[Role]] = db.relationship('Role', secondary=machine_roles, backref=db.backref('machines', lazy='dynamic'))  # type: ignore 