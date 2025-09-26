# Access Control System

A secure access control system for small organizations, implemented using Flask.

## Features

### Baseline Features
- User Authentication (login/logout, password hashing)
- Role-Based Access Control (RBAC)
- User Management (Admin only)
- Profile Management
- Security & Session Controls
- Data Layer with SQLAlchemy ORM
- Logging
- Secure Configuration

### Enhancements
- Password Policy (complexity, reuse prevention)
- Audit Log Viewer
- Secure Password Reset

## Getting Started

1. Clone the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Copy `env.example` to `.env` and update with your settings
6. Initialize the database: `flask db init && flask db migrate && flask db upgrade`
7. Run the application: `flask run`

## Project Structure

```
project/
  app/__init__.py
  app/models.py
  app/auth/routes.py
  app/admin/routes.py
  app/profile/routes.py
  app/security/utils.py
  app/templates/... (Jinja2)
  app/static/
  migrations/
  tests/
```

## Testing

Run the test suite: `pytest`

## Security Features

- Password hashing with bcrypt
- CSRF protection
- Session timeout
- Role-based access control
- Input validation
- Error handling with no sensitive information leakage