from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid

from app import db
from app.models import User, AuditLog
from app.profile.forms import ProfileEditForm, ChangePasswordForm
from app.security.utils import log_authentication, get_client_ip, validate_password

profile_bp = Blueprint('profile', __name__, url_prefix='/profile')

@profile_bp.route('/dashboard')
@login_required
def dashboard():
    # Get recent audit logs for the current user
    logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    return render_template('profile/dashboard.html', logs=logs)


@profile_bp.route('/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = ProfileEditForm(obj=current_user)
    
    if form.validate_on_submit():
        # Update user data
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.email = form.email.data
        
        # Handle profile picture upload
        if form.profile_picture.data:
            file = form.profile_picture.data
            
            # Check if it's a valid image file
            if file.filename != '':
                # Create a secure filename
                filename = secure_filename(file.filename)
                
                # Generate a unique filename with UUID
                ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
                new_filename = f"{uuid.uuid4().hex}.{ext}" if ext else f"{uuid.uuid4().hex}"
                
                # Save the file
                file.save(os.path.join(current_app.root_path, 'static/profile_pics', new_filename))
                
                # Update the user's profile image
                current_user.profile_image = new_filename
        
        db.session.commit()
        
        # Log the action
        log = AuditLog(
            user_id=current_user.id,
            action='edit_profile',
            ip_address=get_client_ip()
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Your profile has been updated', 'success')
        return redirect(url_for('profile.dashboard'))
    
    return render_template('profile/edit_profile.html', form=form)


@profile_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        # Check current password
        if not current_user.verify_password(form.current_password.data):
            flash('Current password is incorrect', 'danger')
            return render_template('profile/change_password.html', form=form)
        
        # Validate new password
        is_valid, message = validate_password(form.new_password.data)
        if not is_valid:
            flash(message, 'danger')
            return render_template('profile/change_password.html', form=form)
        
        # Check if the new password is the same as the old one
        if current_user.verify_password(form.new_password.data):
            flash('New password must be different from the current password', 'danger')
            return render_template('profile/change_password.html', form=form)
        
        # Check if the new password was used before
        if current_user.check_password_reuse(form.new_password.data):
            flash('This password was used before. Please choose a different one', 'danger')
            return render_template('profile/change_password.html', form=form)
        
        # Update password
        current_user.password = form.new_password.data
        db.session.commit()
        
        # Log the action
        log = AuditLog(
            user_id=current_user.id,
            action='change_password',
            ip_address=get_client_ip()
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Your password has been updated', 'success')
        return redirect(url_for('profile.dashboard'))
    
    return render_template('profile/change_password.html', form=form)
