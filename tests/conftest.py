import os
import pytest
from app import create_app, db
from app.models import User, Role

@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False
    })

    # Create the database and tables for testing
    with app.app_context():
        db.create_all()

        # Create roles
        admin_role = Role(name='admin', description='Administrator')
        user_role = Role(name='user', description='Regular User')
        db.session.add(admin_role)
        db.session.add(user_role)

        # Create test users
        from werkzeug.security import generate_password_hash
        
        # Admin user
        admin = User(
            username='admin',
            email='admin@test.com',
            password_hash=generate_password_hash('Admin123!'),
            first_name='Admin',
            last_name='User',
            role=admin_role,
            is_active=True
        )
        
        # Regular user
        regular_user = User(
            username='user',
            email='user@test.com',
            password_hash=generate_password_hash('User123!'),
            first_name='Regular',
            last_name='User',
            role=user_role,
            is_active=True
        )
        
        # Inactive user
        inactive_user = User(
            username='inactive',
            email='inactive@test.com',
            password_hash=generate_password_hash('Inactive123!'),
            first_name='Inactive',
            last_name='User',
            role=user_role,
            is_active=False
        )
        
        db.session.add(admin)
        db.session.add(regular_user)
        db.session.add(inactive_user)
        
        db.session.commit()

    yield app

    # Clean up the database after tests
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()
