"""
Profile management forms.
"""
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from flask_login import current_user

from app.models import User


class EditProfileForm(FlaskForm):
    """Form for editing user profile."""
    
    first_name = StringField('First Name', validators=[
        DataRequired(),
        Length(min=1, max=50)
    ])
    last_name = StringField('Last Name', validators=[
        DataRequired(),
        Length(min=1, max=50)
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message="Please enter a valid email address")
    ])
    profile_picture = FileField('Profile Picture', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])
    submit = SubmitField('Update Profile')
    
    def validate_email(self, email):
        """Check if email is already taken by another user."""
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user is not None:
                raise ValidationError('Email already registered. Please choose a different one.')

