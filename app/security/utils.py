import re
import logging
from functools import wraps
from flask import abort, request, current_app
from flask_login import current_user
import os

# Set up logger
logger = logging.getLogger(__name__)
handler = logging.FileHandler('security.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def role_required(role):
    """Decorator to require a specific role for a route"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                logger.warning(f"Unauthenticated access attempt to {request.path}")
                abort(401)
            if not current_user.has_role(role):
                logger.warning(f"Unauthorized access attempt by {current_user.username} to {request.path}")
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """Decorator to require admin role for a route"""
    return role_required('admin')(f)

def validate_password(password):
    """
    Validates password complexity.
    
    Requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password meets complexity requirements"

def log_authentication(success, username, ip_address=None):
    """Log authentication attempts"""
    if success:
        logger.info(f"Authentication success: {username} from {ip_address or 'unknown'}")
    else:
        logger.warning(f"Authentication failure: {username} from {ip_address or 'unknown'}")

def log_admin_action(user, action, details=None, ip_address=None):
    """Log admin actions"""
    logger.info(f"Admin action: {user.username} performed {action} {details or ''} from {ip_address or 'unknown'}")

def get_client_ip():
    """Get client IP address from request"""
    if request.headers.getlist("X-Forwarded-For"):
        # If behind a proxy, get real IP
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def sanitize_input(input_str):
    """Basic input sanitization"""
    if not input_str:
        return input_str
        
    # Remove any script tags
    sanitized = re.sub(r'<script.*?>.*?</script>', '', input_str, flags=re.DOTALL)
    # Remove any on* attributes
    sanitized = re.sub(r' on\w+=".*?"', '', sanitized)
    sanitized = re.sub(r" on\w+='.*?'", '', sanitized)
    sanitized = re.sub(r' on\w+=.*?( |>)', ' \\1', sanitized)
    
    return sanitized
