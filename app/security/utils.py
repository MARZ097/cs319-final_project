"""
Security utilities for the Access Control System.
"""
import hashlib
import requests
from flask import request
from functools import wraps
from flask_login import current_user
from flask import abort


def get_client_ip():
    """Get the client's IP address, handling proxies."""
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    elif request.headers.get("X-Real-IP"):
        ip = request.headers.get("X-Real-IP")
    else:
        ip = request.remote_addr
    return ip


def admin_required(f):
    """Decorator to require admin role for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def is_password_breached(password):
    """
    Check if password has been breached using HaveIBeenPwned k-Anonymity API.
    
    Args:
        password (str): Password to check
        
    Returns:
        bool: True if password has been breached, False otherwise
    """
    try:
        # Create SHA-1 hash of password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Use k-Anonymity: send only first 5 characters
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Query HaveIBeenPwned API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            # Check if our suffix appears in the response
            hashes = response.text.upper().split('\n')
            for hash_line in hashes:
                if hash_line.startswith(suffix):
                    # Password found in breach data
                    return True
        
        return False
    
    except Exception:
        # If API is unavailable, don't block the user
        return False


def validate_file_upload(file, allowed_extensions=None, max_size=None):
    """
    Validate uploaded file for security.
    
    Args:
        file: File object from request
        allowed_extensions (set): Set of allowed file extensions
        max_size (int): Maximum file size in bytes
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not file or file.filename == '':
        return False, "No file selected"
    
    # Check file extension
    if allowed_extensions:
        if '.' not in file.filename:
            return False, "File must have an extension"
        
        ext = file.filename.rsplit('.', 1)[1].lower()
        if ext not in allowed_extensions:
            return False, f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
    
    # Check file size
    if max_size:
        file.seek(0, 2)  # Seek to end
        size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if size > max_size:
            return False, f"File too large. Maximum size: {max_size // (1024*1024)}MB"
    
    # Additional security checks could be added here:
    # - MIME type validation
    # - File content scanning
    # - Virus scanning
    
    return True, None


def sanitize_filename(filename):
    """
    Sanitize filename for safe storage.
    
    Args:
        filename (str): Original filename
        
    Returns:
        str: Sanitized filename
    """
    import re
    import os
    
    # Get file extension
    name, ext = os.path.splitext(filename)
    
    # Remove or replace dangerous characters
    name = re.sub(r'[^a-zA-Z0-9_\-]', '_', name)
    
    # Limit length
    name = name[:50]
    
    # Ensure it's not empty
    if not name:
        name = 'file'
    
    return name + ext.lower()


def generate_csrf_token():
    """Generate a CSRF token for manual CSRF protection."""
    import secrets
    return secrets.token_urlsafe(32)


def verify_csrf_token(token, session_token):
    """Verify CSRF token."""
    return token and session_token and token == session_token


class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self):
        self.requests = {}
    
    def is_allowed(self, key, max_requests=10, window_seconds=60):
        """
        Check if request is allowed based on rate limiting.
        
        Args:
            key (str): Unique identifier (e.g., IP address)
            max_requests (int): Maximum requests allowed in window
            window_seconds (int): Time window in seconds
            
        Returns:
            bool: True if request is allowed
        """
        import time
        
        now = time.time()
        
        if key not in self.requests:
            self.requests[key] = []
        
        # Remove old requests outside the window
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if now - req_time < window_seconds
        ]
        
        # Check if limit exceeded
        if len(self.requests[key]) >= max_requests:
            return False
        
        # Add current request
        self.requests[key].append(now)
        return True


# Global rate limiter instance
rate_limiter = RateLimiter()

