from api import db
from uuid import uuid4

machine_roles = db.Table('machine_roles',
    db.Column('machine_id', db.String(36), db.ForeignKey('machine.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class Machine(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()), unique=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    token = db.Column(db.String(64), unique=True, nullable=False, default=lambda: str(uuid4()).replace('-', ''))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('machines', lazy=True))
    roles = db.relationship('Role', secondary=machine_roles, backref=db.backref('machines', lazy='dynamic')) 