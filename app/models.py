from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager
import uuid
import os

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Association table for user roles
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    profile_image = db.Column(db.String(128), default='default.png')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_password_hash = db.Column(db.String(128))  # For password reuse prevention
    
    # Foreign key to role table
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    role = db.relationship('Role', backref='users')
    
    # Logs relationship
    logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    
    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        # Store previous password hash before setting new one (for reuse prevention)
        if self.password_hash:
            self.last_password_hash = self.password_hash
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.utcnow()
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def check_password_reuse(self, password):
        if self.last_password_hash:
            return check_password_hash(self.last_password_hash, password)
        return False
    
    def has_role(self, role_name):
        if self.role and self.role.name == role_name:
            return True
        return False
    
    def is_admin(self):
        return self.has_role('admin')
    
    def increment_login_attempts(self):
        self.login_attempts += 1
        db.session.commit()
    
    def reset_login_attempts(self):
        self.login_attempts = 0
        self.locked_until = None
        db.session.commit()
    
    def lock_account(self, minutes=15):
        from datetime import timedelta
        self.locked_until = datetime.utcnow() + timedelta(minutes=minutes)
        db.session.commit()
    
    def is_locked(self):
        if not self.locked_until:
            return False
        return datetime.utcnow() < self.locked_until
    
    def __repr__(self):
        return f'<User {self.username}>'


class Role(db.Model):
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, index=True)
    description = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Role {self.name}>'


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    action = db.Column(db.String(128), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(46))  # IPv6-compatible length
    
    def __repr__(self):
        return f'<AuditLog {self.action}>'


class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref=db.backref('reset_tokens', lazy='dynamic'))
    
    @classmethod
    def generate_token(cls, user_id):
        # Generate a unique token
        token = str(uuid.uuid4())
        
        # Set expiration (24 hours)
        from datetime import timedelta
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        # Create token record
        reset_token = cls(user_id=user_id, token=token, expires_at=expires_at)
        db.session.add(reset_token)
        db.session.commit()
        
        return token
    
    @classmethod
    def validate_token(cls, token):
        token_record = cls.query.filter_by(token=token, used=False).first()
        
        if not token_record:
            return None
        
        if datetime.utcnow() > token_record.expires_at:
            return None
        
        return token_record.user_id
    
    @classmethod
    def invalidate_token(cls, token):
        token_record = cls.query.filter_by(token=token).first()
        if token_record:
            token_record.used = True
            db.session.commit()
