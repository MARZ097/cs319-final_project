from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import os

from app import db
from app.models import User, AuditLog, PasswordResetToken
from app.auth.forms import LoginForm, RegistrationForm, ResetPasswordRequestForm, ResetPasswordForm
from app.security.utils import log_authentication, get_client_ip, validate_password

auth_bp = Blueprint('auth', __name__)

# Redirect old Tailwind UI route to main login
@auth_bp.route('/tailwind/login')
def tailwind_login():
    return redirect(url_for('auth.login'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile.tailwind_dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        # Log the attempt
        ip_address = get_client_ip()
        
        if user is None:
            log_authentication(False, form.username.data, ip_address)
            flash('Invalid username or password', 'danger')
            return render_template('auth/tailwind_login.html', form=form)
        
        if not user.is_active:
            log_authentication(False, user.username, ip_address)
            flash('This account has been deactivated', 'danger')
            return render_template('auth/tailwind_login.html', form=form)
        
        # Check if account is locked
        if user.is_locked():
            log_authentication(False, user.username, ip_address)
            remaining_time = user.locked_until - datetime.utcnow()
            minutes = remaining_time.seconds // 60
            flash(f'Account is locked. Please try again in {minutes} minutes', 'danger')
            return render_template('auth/tailwind_login.html', form=form)
        
        if user.verify_password(form.password.data):
            # Reset login attempts on successful login
            user.reset_login_attempts()
            
            # Update last login timestamp
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log successful login
            log_authentication(True, user.username, ip_address)
            
            # Create audit log entry
            log = AuditLog(
                user_id=user.id,
                action='login',
                ip_address=ip_address
            )
            db.session.add(log)
            db.session.commit()
            
            # Set session timeout
            session.permanent = True
            
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('profile.tailwind_dashboard'))
        else:
            # Increment login attempts
            user.increment_login_attempts()
            
            # Lock account after 5 failed attempts
            if user.login_attempts >= 5:
                user.lock_account(15)  # Lock for 15 minutes
                flash('Too many failed login attempts. Account locked for 15 minutes', 'danger')
            else:
                flash('Invalid username or password', 'danger')
                
            log_authentication(False, user.username, ip_address)
            
    return render_template('auth/tailwind_login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    ip_address = get_client_ip()
    username = current_user.username
    user_id = current_user.id
    
    # Log logout action
    log = AuditLog(
        user_id=user_id,
        action='logout',
        ip_address=ip_address
    )
    db.session.add(log)
    db.session.commit()
    
    logout_user()
    flash('You have been logged out', 'info')
    
    log_authentication(True, f"{username} logged out", ip_address)
    return redirect(url_for('auth.login'))


@auth_bp.route('/reset-password-request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('profile.dashboard'))
    
    form = ResetPasswordRequestForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user:
            # Generate token
            token = PasswordResetToken.generate_token(user.id)
            
            # In a real app, send email here
            # For this project, we'll just display the token (simulating email)
            flash(f'Password reset token: {token}', 'info')
            flash('In a production environment, this would be emailed to you.', 'info')
            
            # Log the request
            log = AuditLog(
                user_id=user.id,
                action='password_reset_request',
                ip_address=get_client_ip()
            )
            db.session.add(log)
            db.session.commit()
        else:
            # Don't reveal that the email doesn't exist, for security
            pass
        
        flash('If that email address exists in our database, a password reset link has been sent', 'info')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/tailwind_reset_password_request.html', form=form)


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('profile.dashboard'))
    
    # Validate token
    user_id = PasswordResetToken.validate_token(token)
    
    if not user_id:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('auth.login'))
    
    user = User.query.get(user_id)
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('auth.login'))
    
    form = ResetPasswordForm()
    
    if form.validate_on_submit():
        # Validate password complexity
        is_valid, message = validate_password(form.password.data)
        
        if not is_valid:
            flash(message, 'danger')
            return render_template('auth/tailwind_reset_password.html', form=form, token=token)
        
        # Check if the new password is the same as the old one
        if user.verify_password(form.password.data):
            flash('New password must be different from the old password', 'danger')
            return render_template('auth/tailwind_reset_password.html', form=form, token=token)
        
        # Check if the new password was used before
        if user.check_password_reuse(form.password.data):
            flash('This password was used before. Please choose a different one', 'danger')
            return render_template('auth/tailwind_reset_password.html', form=form, token=token)
        
        # Update password
        user.password = form.password.data
        
        # Invalidate the token
        PasswordResetToken.invalidate_token(token)
        
        # Log the action
        log = AuditLog(
            user_id=user.id,
            action='password_reset',
            ip_address=get_client_ip()
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Your password has been reset successfully', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/tailwind_reset_password.html', form=form, token=token)
