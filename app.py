"""
Main application entry point for the Access Control System.
"""
import os
from app import create_app, db
from app.models import User, AuditLog, LoginAttempt

app = create_app()


@app.shell_context_processor
def make_shell_context():
    """Make database models available in Flask shell."""
    return {
        'db': db,
        'User': User,
        'AuditLog': AuditLog,
        'LoginAttempt': LoginAttempt
    }


@app.cli.command('init-db')
def init_db():
    """Initialize the database with tables."""
    db.create_all()
    print('Database initialized successfully.')


@app.cli.command('create-admin')
def create_admin():
    """Create an admin user."""
    import getpass
    
    print("Creating admin user...")
    username = input("Username: ")
    email = input("Email: ")
    first_name = input("First Name: ")
    last_name = input("Last Name: ")
    password = getpass.getpass("Password: ")
    
    # Check if user already exists
    if User.query.filter_by(username=username).first():
        print(f"Error: User '{username}' already exists.")
        return
    
    if User.query.filter_by(email=email).first():
        print(f"Error: Email '{email}' already registered.")
        return
    
    # Create admin user
    admin_user = User(
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        role='admin'
    )
    admin_user.set_password(password)
    
    db.session.add(admin_user)
    db.session.commit()
    
    # Log admin creation
    AuditLog.log_event(
        action='admin_created',
        details=f'Admin user {username} created via CLI'
    )
    
    print(f"Admin user '{username}' created successfully.")


@app.cli.command('reset-password')
def reset_password():
    """Reset a user's password."""
    import getpass
    
    username = input("Username: ")
    user = User.query.filter_by(username=username).first()
    
    if not user:
        print(f"Error: User '{username}' not found.")
        return
    
    new_password = getpass.getpass("New Password: ")
    user.set_password(new_password)
    user.unlock_account()  # Also unlock if locked
    
    db.session.commit()
    
    # Log password reset
    AuditLog.log_event(
        action='password_reset',
        user=user,
        details=f'Password reset via CLI for user {username}'
    )
    
    print(f"Password reset for user '{username}'.")


if __name__ == '__main__':
    app.run(debug=True)
