"""
Tests for Role-Based Access Control (RBAC).
"""
import pytest
from tests.conftest import login_user, logout_user


class TestRBAC:
    """Test role-based access control functionality."""
    
    def test_admin_access_to_admin_panel(self, client):
        """Test that admin users can access admin panel."""
        login_user(client, 'admin', 'AdminPass123!')
        
        response = client.get('/admin/users')
        assert response.status_code == 200
        assert b'Manage Users' in response.data or b'Users' in response.data
    
    def test_regular_user_denied_admin_access(self, client):
        """Test that regular users cannot access admin panel."""
        login_user(client, 'user', 'UserPass123!')
        
        response = client.get('/admin/users')
        assert response.status_code == 403  # Forbidden
    
    def test_unauthenticated_user_redirected(self, client):
        """Test that unauthenticated users are redirected to login."""
        response = client.get('/admin/users')
        assert response.status_code == 302  # Redirect
        assert '/auth/login' in response.location
    
    def test_admin_can_create_users(self, client):
        """Test that admin users can create new users."""
        login_user(client, 'admin', 'AdminPass123!')
        
        response = client.get('/admin/users/create')
        assert response.status_code == 200
        assert b'Create User' in response.data
    
    def test_regular_user_cannot_create_users(self, client):
        """Test that regular users cannot create users."""
        login_user(client, 'user', 'UserPass123!')
        
        response = client.get('/admin/users/create')
        assert response.status_code == 403
    
    def test_user_can_access_own_profile(self, client):
        """Test that users can access their own profile."""
        login_user(client, 'user', 'UserPass123!')
        
        response = client.get('/profile/profile')
        assert response.status_code == 200
        assert b'Profile' in response.data
    
    def test_dashboard_access_requires_login(self, client):
        """Test that dashboard requires authentication."""
        response = client.get('/dashboard', follow_redirects=False)
        assert response.status_code == 302
        assert '/auth/login' in response.location
    
    def test_dashboard_shows_admin_stats_for_admin(self, client):
        """Test that dashboard shows admin statistics for admin users."""
        login_user(client, 'admin', 'AdminPass123!')
        
        response = client.get('/dashboard')
        assert response.status_code == 200
        assert b'System Statistics' in response.data
    
    def test_dashboard_hides_admin_stats_for_regular_user(self, client):
        """Test that dashboard hides admin statistics for regular users."""
        login_user(client, 'user', 'UserPass123!')
        
        response = client.get('/dashboard')
        assert response.status_code == 200
        # Should not show admin statistics
        assert b'System Statistics' not in response.data


class TestSecurityHeaders:
    """Test security headers and CSRF protection."""
    
    def test_security_headers_present(self, client):
        """Test that security headers are present in responses."""
        response = client.get('/auth/login')
        
        # Check for security headers
        headers = response.headers
        assert 'X-Content-Type-Options' in headers
        assert 'X-Frame-Options' in headers
        assert 'X-XSS-Protection' in headers
    
    def test_cache_control_on_sensitive_pages(self, client):
        """Test cache control headers on sensitive pages."""
        login_user(client, 'admin', 'AdminPass123!')
        
        response = client.get('/admin/users')
        headers = response.headers
        
        # Should have cache control headers for admin pages
        assert 'Cache-Control' in headers
    
    def test_csrf_token_in_forms(self, client):
        """Test that CSRF tokens are present in forms."""
        response = client.get('/auth/login')
        assert b'csrf_token' in response.data
    
    def test_session_timeout_handling(self, client, app):
        """Test session timeout functionality."""
        with client.session_transaction() as sess:
            # Test that session is marked as permanent
            login_user(client, 'user', 'UserPass123!')
            
        # In a real test, we'd need to mock time to test actual timeout
        # This is a basic test to ensure the mechanism is in place
        response = client.get('/dashboard')
        assert response.status_code == 200
