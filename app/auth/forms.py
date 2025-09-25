"""
Authentication forms for the Access Control System.
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from app.models import User
import re


class LoginForm(FlaskForm):
    """Login form with username/email and password."""
    
    username = StringField('Username or Email', validators=[
        DataRequired(),
        Length(min=3, max=80)
    ])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    totp_code = StringField('2FA Code', validators=[
        Length(min=6, max=6, message="2FA code must be 6 digits")
    ])
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    """User registration form (admin only)."""
    
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=80, message="Username must be 3-80 characters long")
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message="Please enter a valid email address")
    ])
    first_name = StringField('First Name', validators=[
        DataRequired(),
        Length(min=1, max=50)
    ])
    last_name = StringField('Last Name', validators=[
        DataRequired(),
        Length(min=1, max=50)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    password2 = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match")
    ])
    role = StringField('Role', validators=[DataRequired()])
    submit = SubmitField('Create User')
    
    def validate_username(self, username):
        """Check if username is already taken."""
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Username already exists. Please choose a different one.')
    
    def validate_email(self, email):
        """Check if email is already registered."""
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Email already registered. Please choose a different one.')
    
    def validate_password(self, password):
        """Validate password complexity."""
        pwd = password.data
        
        # Check length
        if len(pwd) < 8:
            raise ValidationError('Password must be at least 8 characters long.')
        
        # Check for uppercase letter
        if not re.search(r'[A-Z]', pwd):
            raise ValidationError('Password must contain at least one uppercase letter.')
        
        # Check for lowercase letter
        if not re.search(r'[a-z]', pwd):
            raise ValidationError('Password must contain at least one lowercase letter.')
        
        # Check for digit
        if not re.search(r'\d', pwd):
            raise ValidationError('Password must contain at least one digit.')
        
        # Check for special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', pwd):
            raise ValidationError('Password must contain at least one special character.')


class ChangePasswordForm(FlaskForm):
    """Form for changing user password."""
    
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    password2 = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match")
    ])
    submit = SubmitField('Change Password')
    
    def validate_password(self, password):
        """Validate password complexity."""
        pwd = password.data
        
        # Check length
        if len(pwd) < 8:
            raise ValidationError('Password must be at least 8 characters long.')
        
        # Check for uppercase letter
        if not re.search(r'[A-Z]', pwd):
            raise ValidationError('Password must contain at least one uppercase letter.')
        
        # Check for lowercase letter
        if not re.search(r'[a-z]', pwd):
            raise ValidationError('Password must contain at least one lowercase letter.')
        
        # Check for digit
        if not re.search(r'\d', pwd):
            raise ValidationError('Password must contain at least one digit.')
        
        # Check for special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', pwd):
            raise ValidationError('Password must contain at least one special character.')


class TwoFactorSetupForm(FlaskForm):
    """Form for setting up two-factor authentication."""
    
    totp_code = StringField('Verification Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message="Code must be 6 digits")
    ])
    submit = SubmitField('Enable 2FA')


class TwoFactorDisableForm(FlaskForm):
    """Form for disabling two-factor authentication."""
    
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Disable 2FA')

