"""
Setup script for the Access Control System.
This script helps initialize the application for first-time use.
"""
import os
import sys
import subprocess
import getpass
from pathlib import Path


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required.")
        sys.exit(1)
    print(f"✓ Python {sys.version.split()[0]} detected")


def create_virtual_environment():
    """Create a virtual environment if it doesn't exist."""
    venv_path = Path("venv")
    
    if not venv_path.exists():
        print("Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
        print("✓ Virtual environment created")
    else:
        print("✓ Virtual environment already exists")


def get_venv_python():
    """Get the path to the Python executable in the virtual environment."""
    if os.name == 'nt':  # Windows
        return Path("venv/Scripts/python.exe")
    else:  # Unix-like systems
        return Path("venv/bin/python")


def install_dependencies():
    """Install required dependencies."""
    python_exe = get_venv_python()
    
    if not python_exe.exists():
        print("Error: Virtual environment not found. Run create_virtual_environment() first.")
        return False
    
    print("Installing dependencies...")
    subprocess.run([str(python_exe), "-m", "pip", "install", "-r", "requirements.txt"], check=True)
    print("✓ Dependencies installed")


def setup_environment_file():
    """Set up the .env file from template."""
    env_path = Path(".env")
    env_example_path = Path(".env.example")
    
    if not env_path.exists() and env_example_path.exists():
        print("Setting up environment file...")
        
        # Read template
        with open(env_example_path, 'r') as f:
            content = f.read()
        
        # Generate a secure secret key
        import secrets
        secret_key = secrets.token_urlsafe(32)
        content = content.replace('your-secret-key-here-change-this-in-production', secret_key)
        
        # Write .env file
        with open(env_path, 'w') as f:
            f.write(content)
        
        print("✓ Environment file created with secure secret key")
    else:
        print("✓ Environment file already exists")


def initialize_database():
    """Initialize the database."""
    python_exe = get_venv_python()
    
    print("Initializing database...")
    env = os.environ.copy()
    env['FLASK_APP'] = 'app.py'
    
    subprocess.run([str(python_exe), "-m", "flask", "init-db"], 
                   env=env, check=True)
    print("✓ Database initialized")


def create_admin_user():
    """Create an admin user."""
    python_exe = get_venv_python()
    
    print("\nCreating admin user...")
    print("Please provide the following information:")
    
    username = input("Admin Username: ")
    email = input("Admin Email: ")
    first_name = input("First Name: ")
    last_name = input("Last Name: ")
    password = getpass.getpass("Admin Password: ")
    confirm_password = getpass.getpass("Confirm Password: ")
    
    if password != confirm_password:
        print("Error: Passwords don't match!")
        return False
    
    # Create a temporary script to create the admin user
    script_content = f"""
import os
import sys
sys.path.insert(0, os.getcwd())

from app import create_app, db
from app.models import User, AuditLog

app = create_app()

with app.app_context():
    # Check if user already exists
    if User.query.filter_by(username='{username}').first():
        print("Error: User '{username}' already exists.")
        sys.exit(1)
    
    if User.query.filter_by(email='{email}').first():
        print("Error: Email '{email}' already registered.")
        sys.exit(1)
    
    # Create admin user
    admin_user = User(
        username='{username}',
        email='{email}',
        first_name='{first_name}',
        last_name='{last_name}',
        role='admin'
    )
    admin_user.set_password('{password}')
    
    db.session.add(admin_user)
    db.session.commit()
    
    # Log admin creation
    AuditLog.log_event(
        action='admin_created',
        details='Admin user {username} created via setup script'
    )
    
    print("✓ Admin user '{username}' created successfully.")
"""
    
    # Write and execute the script
    with open('temp_create_admin.py', 'w') as f:
        f.write(script_content)
    
    try:
        subprocess.run([str(python_exe), 'temp_create_admin.py'], check=True)
    finally:
        # Clean up temporary script
        if os.path.exists('temp_create_admin.py'):
            os.remove('temp_create_admin.py')
    
    return True


def main():
    """Main setup function."""
    print("=== Access Control System Setup ===\n")
    
    try:
        # Step 1: Check Python version
        check_python_version()
        
        # Step 2: Create virtual environment
        create_virtual_environment()
        
        # Step 3: Install dependencies
        install_dependencies()
        
        # Step 4: Setup environment file
        setup_environment_file()
        
        # Step 5: Initialize database
        initialize_database()
        
        # Step 6: Create admin user
        if create_admin_user():
            print("\n=== Setup Complete! ===")
            print("\nTo run the application:")
            if os.name == 'nt':  # Windows
                print("1. venv\\Scripts\\activate")
            else:  # Unix-like
                print("1. source venv/bin/activate")
            print("2. python app.py")
            print("\nThen visit http://localhost:5000 in your browser.")
        else:
            print("\nSetup completed with errors. Please check the admin user creation.")
            
    except subprocess.CalledProcessError as e:
        print(f"Error during setup: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nSetup interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
