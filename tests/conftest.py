"""
Pytest configuration and fixtures for testing.
"""
import pytest
import tempfile
import os
from app import create_app, db
from app.models import User


@pytest.fixture
def app():
    """Create application for testing."""
    # Create temporary database file
    db_fd, db_path = tempfile.mkstemp()
    
    app = create_app('testing')
    app.config['DATABASE_URL'] = f'sqlite:///{db_path}'
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.app_context():
        db.create_all()
        
        # Create test users
        admin_user = User(
            username='admin',
            email='admin@test.com',
            first_name='Admin',
            last_name='User',
            role='admin'
        )
        admin_user.set_password('AdminPass123!')
        
        regular_user = User(
            username='user',
            email='user@test.com',
            first_name='Regular',
            last_name='User',
            role='user'
        )
        regular_user.set_password('UserPass123!')
        
        db.session.add(admin_user)
        db.session.add(regular_user)
        db.session.commit()
    
    yield app
    
    # Cleanup
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create test CLI runner."""
    return app.test_cli_runner()


@pytest.fixture
def admin_user(app):
    """Get admin user for testing."""
    with app.app_context():
        return User.query.filter_by(username='admin').first()


@pytest.fixture
def regular_user(app):
    """Get regular user for testing."""
    with app.app_context():
        return User.query.filter_by(username='user').first()


def login_user(client, username, password, totp_code=None):
    """Helper function to login a user."""
    data = {
        'username': username,
        'password': password
    }
    
    if totp_code:
        data['totp_code'] = totp_code
    
    return client.post('/auth/login', data=data, follow_redirects=True)


def logout_user(client):
    """Helper function to logout a user."""
    return client.get('/auth/logout', follow_redirects=True)
