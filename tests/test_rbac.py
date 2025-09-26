import pytest

def test_admin_access(client):
    """Test that admin user can access admin routes"""
    # Login as admin
    client.post('/login', data={
        'username': 'admin',
        'password': 'Admin123!',
    })
    
    # Try to access admin dashboard
    response = client.get('/admin/')
    assert response.status_code == 200
    assert b'Admin Dashboard' in response.data
    
    # Try to access user management
    response = client.get('/admin/users')
    assert response.status_code == 200
    assert b'Manage Users' in response.data
    
    # Try to access audit logs
    response = client.get('/admin/audit-logs')
    assert response.status_code == 200
    assert b'Audit Logs' in response.data

def test_regular_user_blocked_from_admin(client):
    """Test that regular users cannot access admin routes"""
    # Login as regular user
    client.post('/login', data={
        'username': 'user',
        'password': 'User123!',
    })
    
    # Try to access admin dashboard
    response = client.get('/admin/')
    assert response.status_code == 403  # Forbidden
    
    # Try to access user management
    response = client.get('/admin/users')
    assert response.status_code == 403  # Forbidden
    
    # Try to access audit logs
    response = client.get('/admin/audit-logs')
    assert response.status_code == 403  # Forbidden

def test_unauthenticated_user_redirected(client):
    """Test that unauthenticated users are redirected to login page"""
    # Try to access admin dashboard without login
    response = client.get('/admin/', follow_redirects=True)
    assert b'Login' in response.data
    
    # Try to access user profile without login
    response = client.get('/profile/dashboard', follow_redirects=True)
    assert b'Login' in response.data
    
    # Try to access user management without login
    response = client.get('/admin/users', follow_redirects=True)
    assert b'Login' in response.data
