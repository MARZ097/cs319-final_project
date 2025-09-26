import pytest
from io import BytesIO
from app.models import User
from app import db

def test_dashboard_access(client):
    """Test that authenticated user can access dashboard"""
    # Login as regular user
    client.post('/login', data={
        'username': 'user',
        'password': 'User123!',
    })
    
    # Access dashboard
    response = client.get('/profile/dashboard')
    
    assert response.status_code == 200
    assert b'Welcome' in response.data
    assert b'Profile' in response.data
    assert b'Recent Activity' in response.data

def test_edit_profile(client, app):
    """Test that user can edit their profile"""
    # Login as regular user
    client.post('/login', data={
        'username': 'user',
        'password': 'User123!',
    })
    
    # Edit profile
    response = client.post('/profile/edit', data={
        'first_name': 'Updated',
        'last_name': 'Name',
        'email': 'user@test.com'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Your profile has been updated' in response.data
    
    # Verify profile was updated
    with app.app_context():
        user = User.query.filter_by(username='user').first()
        assert user.first_name == 'Updated'
        assert user.last_name == 'Name'

def test_change_password(client, app):
    """Test that user can change their password"""
    # Login as regular user
    client.post('/login', data={
        'username': 'user',
        'password': 'User123!',
    })
    
    # Change password
    response = client.post('/profile/change-password', data={
        'current_password': 'User123!',
        'new_password': 'NewPass123!',
        'confirm_password': 'NewPass123!'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Your password has been updated' in response.data
    
    # Logout
    client.get('/logout', follow_redirects=True)
    
    # Try to login with new password
    response = client.post('/login', data={
        'username': 'user',
        'password': 'NewPass123!',
        'remember_me': False
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Welcome' in response.data

def test_password_change_incorrect_current(client):
    """Test password change with incorrect current password"""
    # Login as regular user
    client.post('/login', data={
        'username': 'user',
        'password': 'User123!',
    })
    
    # Try to change password with incorrect current password
    response = client.post('/profile/change-password', data={
        'current_password': 'wrong',
        'new_password': 'NewPass123!',
        'confirm_password': 'NewPass123!'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Current password is incorrect' in response.data

def test_password_change_reuse_prevention(client, app):
    """Test that password reuse prevention works"""
    # Login as admin (since we know their current password)
    client.post('/login', data={
        'username': 'admin',
        'password': 'Admin123!',
    })
    
    # First change password
    response = client.post('/profile/change-password', data={
        'current_password': 'Admin123!',
        'new_password': 'TempPass123!',
        'confirm_password': 'TempPass123!'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Your password has been updated' in response.data
    
    # Try to change back to original password
    response = client.post('/profile/change-password', data={
        'current_password': 'TempPass123!',
        'new_password': 'Admin123!',
        'confirm_password': 'Admin123!'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'This password was used before' in response.data
