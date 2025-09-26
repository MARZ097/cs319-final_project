import os
import sys
from app import create_app, db
from app.models import User, Role
from werkzeug.security import generate_password_hash

print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}")

# Create app instance
print("Creating app...")
app = create_app()

# Create instance directory if it doesn't exist
instance_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
if not os.path.exists(instance_dir):
    print(f"Creating instance directory at: {instance_dir}")
    os.makedirs(instance_dir)

# Create database
with app.app_context():
    print("Creating database tables...")
    db.create_all()
    print("Database tables created.")
    
    # Create roles if they don't exist
    print("Setting up initial data...")
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role(name='admin', description='Administrator')
        db.session.add(admin_role)
        print("Created admin role")
    
    user_role = Role.query.filter_by(name='user').first()
    if not user_role:
        user_role = Role(name='user', description='Regular user')
        db.session.add(user_role)
        print("Created user role")
    
    # Create admin user if it doesn't exist
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),
            role=admin_role,
            is_active=True
        )
        db.session.add(admin)
        print("Created admin user")
    
    # Commit changes
    db.session.commit()
    print("Initial data setup completed")

print("Database setup completed successfully!")
