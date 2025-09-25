"""
Profile management routes.
"""
import os
import uuid
from flask import render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from PIL import Image

from app import db
from app.profile import bp
from app.profile.forms import EditProfileForm
from app.models import AuditLog
from app.security.utils import get_client_ip, validate_file_upload, sanitize_filename


@bp.route('/profile')
@login_required
def profile():
    """View user profile."""
    return render_template('profile/profile.html', user=current_user)


@bp.route('/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile."""
    form = EditProfileForm()
    
    if form.validate_on_submit():
        # Update basic profile information
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.email = form.email.data
        
        # Handle profile picture upload
        if form.profile_picture.data:
            file = form.profile_picture.data
            
            # Validate file
            is_valid, error_msg = validate_file_upload(
                file,
                allowed_extensions=current_app.config['ALLOWED_EXTENSIONS'],
                max_size=current_app.config['MAX_CONTENT_LENGTH']
            )
            
            if not is_valid:
                flash(f'Profile picture upload failed: {error_msg}', 'error')
                return render_template('profile/edit_profile.html', form=form)
            
            # Generate unique filename
            filename = secure_filename(file.filename)
            filename = sanitize_filename(filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            
            # Save file
            upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
            
            # Ensure upload directory exists
            os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            try:
                # Process image (resize and optimize)
                image = Image.open(file)
                
                # Convert to RGB if necessary
                if image.mode in ('RGBA', 'LA', 'P'):
                    image = image.convert('RGB')
                
                # Resize to maximum 300x300 while maintaining aspect ratio
                image.thumbnail((300, 300), Image.Resampling.LANCZOS)
                
                # Save optimized image
                image.save(upload_path, 'JPEG', quality=85, optimize=True)
                
                # Remove old profile picture if exists
                if current_user.profile_picture:
                    old_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 
                                          current_user.profile_picture)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                
                # Update user profile picture
                current_user.profile_picture = unique_filename
                
            except Exception as e:
                flash(f'Error processing profile picture: {str(e)}', 'error')
                return render_template('profile/edit_profile.html', form=form)
        
        db.session.commit()
        
        # Log profile update
        AuditLog.log_event(
            action='profile_updated',
            user=current_user,
            details='Profile information updated',
            ip_address=get_client_ip(),
            user_agent=request.headers.get('User-Agent', '')
        )
        
        flash('Your profile has been updated successfully.', 'success')
        return redirect(url_for('profile.profile'))
    
    elif request.method == 'GET':
        # Pre-populate form with current user data
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.email.data = current_user.email
    
    return render_template('profile/edit_profile.html', form=form)


@bp.route('/security')
@login_required
def security():
    """View security settings."""
    return render_template('profile/security.html', user=current_user)


@bp.route('/activity')
@login_required
def activity():
    """View user activity log."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    activities = AuditLog.query.filter_by(user_id=current_user.id)\
        .order_by(AuditLog.timestamp.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('profile/activity.html', activities=activities)

