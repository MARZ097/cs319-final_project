# Access Control System - CS319 Final Project

A comprehensive secure Access Control System built with Flask, featuring strong authentication, Role-Based Access Control (RBAC), and advanced security features.

## 🔐 Features

### Core Features (Baseline Requirements)
- **User Authentication**: Secure login/logout with password hashing using bcrypt
- **Role-Based Access Control (RBAC)**: Admin and Regular User roles with proper enforcement
- **User Management**: Admin-only user creation, listing, and management
- **Profile Management**: Self-service profile editing with picture upload
- **Security Controls**: CSRF protection, session timeout, cache control headers
- **Comprehensive Logging**: Authentication events and administrative actions
- **Secure Configuration**: Environment-based configuration with secrets management

### Enhanced Features (Selected 3+ Enhancements)
1. **Two-Factor Authentication (2FA)**: TOTP-based 2FA with QR code setup and backup codes
2. **Advanced Password Policy**: Complexity requirements and breach checking via HaveIBeenPwned API
3. **Audit Log Viewer**: Comprehensive audit logging with filtering and search capabilities
4. **Account Lockout Protection**: Automatic lockout after failed login attempts
5. **Session Management**: Advanced session controls with timeout and security headers

## 🏗️ Architecture

### Framework Choice: Flask
**Rationale**: Flask was chosen for its:
- Mature security ecosystem (Flask-Login, Flask-WTF, etc.)
- Extensive documentation and community support
- Flexibility for custom security implementations
- Well-established patterns for web application security

### Directory Structure
```
access-control-system/
├── app/
│   ├── __init__.py              # Application factory
│   ├── models.py                # Database models
│   ├── auth/                    # Authentication blueprint
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   └── forms.py
│   ├── admin/                   # Admin management blueprint
│   │   ├── __init__.py
│   │   └── routes.py
│   ├── profile/                 # Profile management blueprint
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   └── forms.py
│   ├── main/                    # Main application blueprint
│   │   ├── __init__.py
│   │   └── routes.py
│   ├── security/                # Security utilities
│   │   ├── __init__.py
│   │   └── utils.py
│   ├── templates/               # Jinja2 templates
│   └── static/                  # Static assets
├── tests/                       # Test suite
├── logs/                        # Application logs
├── config.py                    # Configuration management
├── app.py                       # Application entry point
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variables template
└── README.md                    # This file
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment tool (venv, virtualenv, or conda)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd access-control-system
   ```

2. **Create and activate virtual environment**
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate
   
   # Linux/Mac
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   copy .env.example .env
   # Edit .env file with your configuration
   ```

5. **Initialize the database**
   ```bash
   flask init-db
   ```

6. **Create an admin user**
   ```bash
   flask create-admin
   ```

7. **Run the application**
   ```bash
   python app.py
   ```

8. **Access the application**
   - Open your browser to `http://localhost:5000`
   - Login with your admin credentials

## 🔧 Configuration

### Environment Variables
Create a `.env` file based on `.env.example`:

```env
# Flask Configuration
SECRET_KEY=your-secret-key-here-change-this-in-production
FLASK_ENV=development

# Database Configuration
DATABASE_URL=sqlite:///access_control.db

# Security Configuration
SESSION_TIMEOUT=1800
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=300

# File Upload Configuration
UPLOAD_FOLDER=app/static/uploads
MAX_CONTENT_LENGTH=16777216
ALLOWED_EXTENSIONS=png,jpg,jpeg,gif
```

### Database Schema
The application uses SQLAlchemy ORM with the following models:
- **User**: User accounts with authentication and profile data
- **AuditLog**: System event logging
- **LoginAttempt**: Login attempt tracking for security

## 🛡️ Security Features

### Threat Model
The system addresses the following security concerns:

| Threat | Mitigation |
|--------|------------|
| Credential Stuffing | Account lockout after failed attempts |
| Session Hijacking | Secure session cookies, timeout, HTTPS enforcement |
| CSRF Attacks | CSRF tokens on all forms |
| Password Attacks | Strong password policy, breach checking |
| Privilege Escalation | Strict RBAC enforcement |
| Data Exposure | Input validation, output encoding, secure headers |

### Security Controls
- **Authentication**: bcrypt password hashing with salt
- **Authorization**: Role-based access control at UI and API levels
- **Session Management**: Secure cookies, timeout, regeneration
- **Input Validation**: Server-side validation on all forms
- **CSRF Protection**: Built-in Flask-WTF CSRF protection
- **Security Headers**: XSS, clickjacking, and content-type protection
- **Audit Logging**: Comprehensive event logging for security monitoring
- **2FA**: TOTP-based two-factor authentication

## 👥 User Roles

### Administrator
- Full system access
- User management (create, edit, disable, delete)
- Audit log viewing
- System statistics and monitoring
- Role management

### Regular User
- Profile management
- Password changes
- 2FA setup/management
- Personal activity log viewing

## 🧪 Testing

### Running Tests
```bash
# Install test dependencies
pip install pytest pytest-flask coverage

# Run test suite
pytest

# Run with coverage
coverage run -m pytest
coverage report
coverage html  # Generate HTML report
```

### Test Coverage
The test suite includes:
- Unit tests for models and utilities
- Integration tests for authentication flow
- Role-based access control tests
- Security feature tests
- Form validation tests

## 📊 Monitoring and Logging

### Audit Logging
All significant events are logged including:
- User authentication (success/failure)
- Administrative actions
- Profile changes
- Security events (2FA setup, password changes)
- Access control violations

### Log Locations
- Application logs: `logs/access_control.log`
- Audit events: Database (`audit_logs` table)
- Login attempts: Database (`login_attempts` table)

## 🔒 Security Best Practices

### Password Policy
- Minimum 8 characters
- Must contain uppercase, lowercase, digit, and special character
- Breach checking via HaveIBeenPwned API
- Password history prevention

### Session Security
- 30-minute timeout with warning at 25 minutes
- Secure cookie flags in production
- Session regeneration on login
- Automatic logout on timeout

### File Upload Security
- File type validation
- File size limits
- Secure filename generation
- Image processing and optimization

## 🚀 Deployment

### Production Considerations
1. **Environment Configuration**
   - Set `FLASK_ENV=production`
   - Use strong `SECRET_KEY`
   - Configure proper database URL
   - Enable HTTPS

2. **Security Headers**
   - All security headers are automatically applied
   - HTTPS enforcement in production
   - Secure cookie flags

3. **Database**
   - Use PostgreSQL or MySQL for production
   - Regular backups
   - Connection pooling

4. **Monitoring**
   - Log rotation configured
   - Monitor failed login attempts
   - Regular audit log reviews

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Ensure all tests pass
6. Submit a pull request

## 📝 License

This project is created for educational purposes as part of CS319 coursework.

## 🔗 Dependencies

### Core Dependencies
- **Flask**: Web framework
- **Flask-Login**: User session management
- **Flask-WTF**: Form handling and CSRF protection
- **Flask-SQLAlchemy**: Database ORM
- **bcrypt**: Password hashing
- **pyotp**: TOTP implementation for 2FA
- **Pillow**: Image processing
- **requests**: HTTP client for breach checking

### Development Dependencies
- **pytest**: Testing framework
- **coverage**: Test coverage reporting
- **flake8**: Code linting

## 📞 Support

For questions or issues:
1. Check the documentation
2. Review the test suite for usage examples
3. Create an issue in the repository

---

**Note**: This is a educational project demonstrating security best practices. For production use, conduct a thorough security audit and penetration testing.