import pytest
from app.models import User, Role
from app import db

def test_create_user(client, app):
    """Test creating a new user as admin"""
    # Login as admin
    client.post('/login', data={
        'username': 'admin',
        'password': 'Admin123!',
    })
    
    # Get the role id for the user role
    with app.app_context():
        user_role = Role.query.filter_by(name='user').first()
        role_id = user_role.id
    
    # Create a new user
    response = client.post('/admin/users/create', data={
        'username': 'newuser',
        'email': 'newuser@test.com',
        'first_name': 'New',
        'last_name': 'User',
        'password': 'NewUser123!',
        'confirm_password': 'NewUser123!',
        'role': role_id,
        'is_active': True
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'User newuser has been created' in response.data
    
    # Verify user was created in the database
    with app.app_context():
        user = User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.email == 'newuser@test.com'
        assert user.first_name == 'New'
        assert user.last_name == 'User'
        assert user.is_active == True
        assert user.role.name == 'user'

def test_edit_user(client, app):
    """Test editing a user as admin"""
    # Login as admin
    client.post('/login', data={
        'username': 'admin',
        'password': 'Admin123!',
    })
    
    # Get user id and role id
    with app.app_context():
        user = User.query.filter_by(username='user').first()
        user_id = user.id
        admin_role = Role.query.filter_by(name='admin').first()
        role_id = admin_role.id
    
    # Edit the user
    response = client.post(f'/admin/users/edit/{user_id}', data={
        'username': 'updateduser',
        'email': 'updated@test.com',
        'first_name': 'Updated',
        'last_name': 'User',
        'role': role_id,
        'is_active': True
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'User updateduser has been updated' in response.data
    
    # Verify user was updated in the database
    with app.app_context():
        user = User.query.get(user_id)
        assert user.username == 'updateduser'
        assert user.email == 'updated@test.com'
        assert user.first_name == 'Updated'
        assert user.last_name == 'User'
        assert user.role.name == 'admin'

def test_delete_user(client, app):
    """Test deleting a user as admin"""
    # Login as admin
    client.post('/login', data={
        'username': 'admin',
        'password': 'Admin123!',
    })
    
    # Get user id for inactive user
    with app.app_context():
        user = User.query.filter_by(username='inactive').first()
        user_id = user.id
    
    # Delete the user
    response = client.post(f'/admin/users/delete/{user_id}', data={}, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'User inactive has been deleted' in response.data
    
    # Verify user was deleted from the database
    with app.app_context():
        user = User.query.get(user_id)
        assert user is None

def test_cant_delete_self(client, app):
    """Test that admin cannot delete themselves"""
    # Login as admin
    client.post('/login', data={
        'username': 'admin',
        'password': 'Admin123!',
    })
    
    # Get admin user id
    with app.app_context():
        user = User.query.filter_by(username='admin').first()
        user_id = user.id
    
    # Try to delete self
    response = client.post(f'/admin/users/delete/{user_id}', data={}, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'You cannot delete your own account' in response.data
    
    # Verify admin user still exists
    with app.app_context():
        user = User.query.get(user_id)
        assert user is not None
