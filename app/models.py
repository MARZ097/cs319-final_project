"""
Database models for the Access Control System.
"""
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import pyotp
import secrets

from app import db


class User(UserMixin, db.Model):
    """User model with authentication and profile information."""
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Profile information
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    profile_picture = db.Column(db.String(255), nullable=True)
    
    # Role-based access control
    role = db.Column(db.String(20), nullable=False, default='user')
    
    # Account status
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_locked = db.Column(db.Boolean, nullable=False, default=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # Two-factor authentication
    totp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    backup_codes = db.Column(db.Text, nullable=True)  # JSON string
    
    # Password policy
    password_changed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    
    # Timestamps
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    login_attempts = db.relationship('LoginAttempt', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.utcnow()
    
    def check_password(self, password):
        """Check if the provided password matches the user's password."""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        """Check if the user has admin role."""
        return self.role == 'admin'
    
    def is_account_locked(self):
        """Check if the account is currently locked."""
        if not self.is_locked:
            return False
        
        if self.locked_until and datetime.utcnow() > self.locked_until:
            # Auto-unlock expired locks
            self.is_locked = False
            self.locked_until = None
            self.failed_login_attempts = 0
            db.session.commit()
            return False
        
        return True
    
    def lock_account(self, duration_seconds=300):
        """Lock the account for the specified duration."""
        self.is_locked = True
        self.locked_until = datetime.utcnow() + timedelta(seconds=duration_seconds)
    
    def unlock_account(self):
        """Unlock the account and reset failed attempts."""
        self.is_locked = False
        self.locked_until = None
        self.failed_login_attempts = 0
    
    def increment_failed_attempts(self, max_attempts=5, lockout_duration=300):
        """Increment failed login attempts and lock if threshold exceeded."""
        self.failed_login_attempts += 1
        
        if self.failed_login_attempts >= max_attempts:
            self.lock_account(lockout_duration)
        
        db.session.commit()
    
    def reset_failed_attempts(self):
        """Reset failed login attempts counter."""
        self.failed_login_attempts = 0
        db.session.commit()
    
    def generate_totp_secret(self):
        """Generate a new TOTP secret for 2FA."""
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret
    
    def get_totp_uri(self):
        """Get TOTP URI for QR code generation."""
        if not self.totp_secret:
            return None
        
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email,
            issuer_name="Access Control System"
        )
    
    def verify_totp(self, token):
        """Verify TOTP token."""
        if not self.totp_secret:
            return False
        
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)
    
    def generate_backup_codes(self, count=10):
        """Generate backup codes for 2FA recovery."""
        import json
        codes = [secrets.token_hex(4).upper() for _ in range(count)]
        self.backup_codes = json.dumps(codes)
        return codes
    
    def verify_backup_code(self, code):
        """Verify and consume a backup code."""
        if not self.backup_codes:
            return False
        
        import json
        codes = json.loads(self.backup_codes)
        
        if code.upper() in codes:
            codes.remove(code.upper())
            self.backup_codes = json.dumps(codes)
            db.session.commit()
            return True
        
        return False
    
    @property
    def full_name(self):
        """Get the user's full name."""
        return f"{self.first_name} {self.last_name}"
    
    def __repr__(self):
        return f'<User {self.username}>'


class AuditLog(db.Model):
    """Audit log for tracking system events."""
    
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource = db.Column(db.String(100), nullable=True)
    resource_id = db.Column(db.String(50), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    @staticmethod
    def log_event(action, user=None, resource=None, resource_id=None, details=None, ip_address=None, user_agent=None):
        """Log an audit event."""
        log_entry = AuditLog(
            user_id=user.id if user else None,
            action=action,
            resource=resource,
            resource_id=str(resource_id) if resource_id else None,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.session.add(log_entry)
        db.session.commit()
    
    def __repr__(self):
        return f'<AuditLog {self.action} by {self.user_id} at {self.timestamp}>'


class LoginAttempt(db.Model):
    """Track login attempts for security monitoring."""
    
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(80), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    user_agent = db.Column(db.Text, nullable=True)
    success = db.Column(db.Boolean, nullable=False, index=True)
    failure_reason = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    @staticmethod
    def log_attempt(username, ip_address, success, user=None, failure_reason=None, user_agent=None):
        """Log a login attempt."""
        attempt = LoginAttempt(
            user_id=user.id if user else None,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            failure_reason=failure_reason
        )
        db.session.add(attempt)
        db.session.commit()
    
    def __repr__(self):
        return f'<LoginAttempt {self.username} from {self.ip_address} at {self.timestamp}>'

