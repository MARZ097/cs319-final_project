from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional
import re

class UserCreateForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    first_name = StringField('First Name', validators=[Optional(), Length(max=64)])
    last_name = StringField('Last Name', validators=[Optional(), Length(max=64)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', coerce=int, validators=[DataRequired()])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Create User')
    
    def validate_password(self, field):
        """Validate password complexity"""
        password = field.data
        
        # Check for at least one uppercase letter
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Password must contain at least one uppercase letter')
        
        # Check for at least one lowercase letter
        if not re.search(r'[a-z]', password):
            raise ValidationError('Password must contain at least one lowercase letter')
        
        # Check for at least one digit
        if not re.search(r'\d', password):
            raise ValidationError('Password must contain at least one digit')
        
        # Check for at least one special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError('Password must contain at least one special character')


class UserEditForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    first_name = StringField('First Name', validators=[Optional(), Length(max=64)])
    last_name = StringField('Last Name', validators=[Optional(), Length(max=64)])
    password = PasswordField('Password', validators=[Optional(), Length(min=8, max=128)])
    confirm_password = PasswordField('Confirm Password', validators=[EqualTo('password')])
    role = SelectField('Role', coerce=int, validators=[DataRequired()])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Update User')
    
    def validate_password(self, field):
        """Validate password complexity if provided"""
        password = field.data
        if not password:
            return
        
        # Check for at least one uppercase letter
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Password must contain at least one uppercase letter')
        
        # Check for at least one lowercase letter
        if not re.search(r'[a-z]', password):
            raise ValidationError('Password must contain at least one lowercase letter')
        
        # Check for at least one digit
        if not re.search(r'\d', password):
            raise ValidationError('Password must contain at least one digit')
        
        # Check for at least one special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError('Password must contain at least one special character')
