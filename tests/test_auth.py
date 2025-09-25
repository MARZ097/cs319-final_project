"""
Tests for authentication functionality.
"""
import pytest
from app.models import User, LoginAttempt
from app import db
from tests.conftest import login_user, logout_user


class TestAuthentication:
    """Test authentication functionality."""
    
    def test_login_page_loads(self, client):
        """Test that login page loads correctly."""
        response = client.get('/auth/login')
        assert response.status_code == 200
        assert b'Access Control System' in response.data
        assert b'Username or Email' in response.data
    
    def test_successful_login(self, client):
        """Test successful user login."""
        response = login_user(client, 'admin', 'AdminPass123!')
        assert response.status_code == 200
        assert b'Welcome back, Admin!' in response.data
    
    def test_invalid_credentials(self, client):
        """Test login with invalid credentials."""
        response = login_user(client, 'admin', 'wrongpassword')
        assert response.status_code == 200
        assert b'Invalid username or password' in response.data
    
    def test_nonexistent_user(self, client):
        """Test login with nonexistent user."""
        response = login_user(client, 'nonexistent', 'password')
        assert response.status_code == 200
        assert b'Invalid username or password' in response.data
    
    def test_logout(self, client):
        """Test user logout."""
        # Login first
        login_user(client, 'admin', 'AdminPass123!')
        
        # Then logout
        response = logout_user(client)
        assert response.status_code == 200
        assert b'logged out successfully' in response.data
    
    def test_account_lockout(self, client, app):
        """Test account lockout after failed attempts."""
        with app.app_context():
            user = User.query.filter_by(username='admin').first()
            
            # Make multiple failed attempts
            for i in range(5):
                login_user(client, 'admin', 'wrongpassword')
            
            # Check if account is locked
            db.session.refresh(user)
            assert user.is_account_locked()
            
            # Try to login with correct password (should fail due to lock)
            response = login_user(client, 'admin', 'AdminPass123!')
            assert b'temporarily locked' in response.data
    
    def test_password_change(self, client, app):
        """Test password change functionality."""
        # Login first
        login_user(client, 'admin', 'AdminPass123!')
        
        # Change password
        response = client.post('/auth/change-password', data={
            'current_password': 'AdminPass123!',
            'password': 'NewAdminPass123!',
            'password2': 'NewAdminPass123!'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'password has been changed' in response.data
        
        # Logout and try login with new password
        logout_user(client)
        response = login_user(client, 'admin', 'NewAdminPass123!')
        assert b'Welcome back, Admin!' in response.data


class TestUserModel:
    """Test User model functionality."""
    
    def test_password_hashing(self, app):
        """Test password hashing."""
        with app.app_context():
            user = User(username='test', email='test@test.com',
                       first_name='Test', last_name='User')
            user.set_password('testpassword')
            
            assert user.password_hash != 'testpassword'
            assert user.check_password('testpassword')
            assert not user.check_password('wrongpassword')
    
    def test_user_roles(self, app, admin_user, regular_user):
        """Test user role functionality."""
        with app.app_context():
            assert admin_user.is_admin()
            assert not regular_user.is_admin()
    
    def test_account_locking(self, app, admin_user):
        """Test account locking functionality."""
        with app.app_context():
            assert not admin_user.is_account_locked()
            
            admin_user.lock_account(300)
            assert admin_user.is_account_locked()
            
            admin_user.unlock_account()
            assert not admin_user.is_account_locked()
    
    def test_failed_attempts_tracking(self, app, admin_user):
        """Test failed login attempts tracking."""
        with app.app_context():
            initial_attempts = admin_user.failed_login_attempts
            
            admin_user.increment_failed_attempts(max_attempts=3, lockout_duration=300)
            assert admin_user.failed_login_attempts == initial_attempts + 1
            
            admin_user.reset_failed_attempts()
            assert admin_user.failed_login_attempts == 0


class TestTwoFactorAuth:
    """Test two-factor authentication functionality."""
    
    def test_totp_secret_generation(self, app, admin_user):
        """Test TOTP secret generation."""
        with app.app_context():
            secret = admin_user.generate_totp_secret()
            assert secret is not None
            assert len(secret) == 32
            assert admin_user.totp_secret == secret
    
    def test_totp_uri_generation(self, app, admin_user):
        """Test TOTP URI generation for QR codes."""
        with app.app_context():
            admin_user.generate_totp_secret()
            uri = admin_user.get_totp_uri()
            
            assert uri is not None
            assert 'otpauth://totp/' in uri
            assert admin_user.email in uri
    
    def test_backup_codes_generation(self, app, admin_user):
        """Test backup codes generation."""
        with app.app_context():
            codes = admin_user.generate_backup_codes(count=5)
            
            assert len(codes) == 5
            assert all(len(code) == 8 for code in codes)
            assert admin_user.backup_codes is not None
    
    def test_backup_code_verification(self, app, admin_user):
        """Test backup code verification and consumption."""
        with app.app_context():
            codes = admin_user.generate_backup_codes(count=3)
            test_code = codes[0]
            
            # Verify valid code
            assert admin_user.verify_backup_code(test_code)
            
            # Code should be consumed (can't use again)
            assert not admin_user.verify_backup_code(test_code)
            
            # Invalid code should fail
            assert not admin_user.verify_backup_code('INVALID')
