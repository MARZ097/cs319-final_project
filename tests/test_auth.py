import pytest
from flask import session, url_for

def test_login_page(client):
    """Test that login page loads correctly"""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data
    assert b'Username' in response.data
    assert b'Password' in response.data
    assert b'Remember Me' in response.data

def test_successful_login(client):
    """Test successful login"""
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'Admin123!',
        'remember_me': False
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Welcome' in response.data
    assert b'admin' in response.data

def test_failed_login_invalid_credentials(client):
    """Test login with invalid credentials"""
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'wrongpassword',
        'remember_me': False
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Invalid username or password' in response.data

def test_login_inactive_user(client):
    """Test login with inactive user"""
    response = client.post('/login', data={
        'username': 'inactive',
        'password': 'Inactive123!',
        'remember_me': False
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'This account has been deactivated' in response.data

def test_logout(client):
    """Test logout functionality"""
    # First login
    client.post('/login', data={
        'username': 'admin',
        'password': 'Admin123!',
        'remember_me': False
    })
    
    # Then logout
    response = client.get('/logout', follow_redirects=True)
    
    assert response.status_code == 200
    assert b'You have been logged out' in response.data
    assert b'Login' in response.data

def test_password_reset_request(client):
    """Test password reset request page"""
    response = client.get('/reset-password-request')
    
    assert response.status_code == 200
    assert b'Reset Password' in response.data
    assert b'Email' in response.data

def test_submit_password_reset_request(client):
    """Test submitting password reset request"""
    response = client.post('/reset-password-request', data={
        'email': 'admin@test.com'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'If that email address exists' in response.data
    assert b'Login' in response.data
