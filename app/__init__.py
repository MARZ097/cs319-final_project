import os
from flask import Flask, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    
    # Configure app
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-for-testing-only')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///app.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = int(os.getenv('SESSION_TIMEOUT', 1800))  # Default 30 minutes
    
    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Cache control for sensitive pages
        if request.path.startswith('/admin') or request.path.startswith('/profile'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        
        return response
    
    # Initialize extensions with app
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'danger'
    
    # Import and register blueprints
    from app.auth.routes import auth_bp
    app.register_blueprint(auth_bp)
    
    from app.admin.routes import admin_bp
    app.register_blueprint(admin_bp)
    
    from app.profile.routes import profile_bp
    app.register_blueprint(profile_bp)
    
    @app.route('/')
    def index():
        return redirect(url_for('auth.login'))
    
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Create initial admin user if no users exist
        from app.models import User, Role
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
    
    return app
