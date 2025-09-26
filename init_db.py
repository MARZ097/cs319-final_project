import os
import sys
from app import create_app, db
from app.models import User, Role
from flask_migrate import Migrate, init, migrate, upgrade

# Print information about the environment
print("Python version:", sys.version)
print("Current working directory:", os.getcwd())
print("FLASK_APP environment variable:", os.environ.get('FLASK_APP', 'Not set'))

# Try to import Flask-Migrate to verify it's installed
try:
    import flask_migrate
    print("Flask-Migrate version:", flask_migrate.__version__)
except ImportError:
    print("Flask-Migrate is not installed!")

app = create_app()
migrate = Migrate(app, db)

# Create a context for database operations
with app.app_context():
    try:
        print("Creating migrations directory...")
        # Create the migrations directory
        init()
        print("Migrations directory created.")
    except Exception as e:
        print(f"Error creating migrations directory: {e}")
    
    try:
        print("Creating migration...")
        # Create a migration with a message
        migrate("Initial migration")
        print("Migration created.")
    except Exception as e:
        print(f"Error creating migration: {e}")
    
    try:
        print("Applying migration...")
        # Apply the migration
        upgrade()
        print("Migration applied.")
    except Exception as e:
        print(f"Error applying migration: {e}")
    
    try:
        print("Creating database tables directly...")
        # Create tables directly
        db.create_all()
        print("Database tables created.")
        
        # Create initial admin user if no users exist
        if User.query.count() == 0:
            # Create roles if they don't exist
            admin_role = Role.query.filter_by(name='admin').first()
            if not admin_role:
                admin_role = Role(name='admin', description='Administrator')
                db.session.add(admin_role)
            
            user_role = Role.query.filter_by(name='user').first()
            if not user_role:
                user_role = Role(name='user', description='Regular user')
                db.session.add(user_role)
                
            # Create admin user
            from werkzeug.security import generate_password_hash
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                role=admin_role,
                is_active=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully")
    except Exception as e:
        print(f"Error creating database tables or admin user: {e}")
    
    print("Database initialization process completed")
