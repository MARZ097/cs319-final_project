"""
Authentication routes for the Access Control System.
"""
from flask import render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from datetime import datetime
import pyotp
import qrcode
import io
import base64

from app import db
from app.auth import bp
from app.auth.forms import LoginForm, ChangePasswordForm, TwoFactorSetupForm, TwoFactorDisableForm
from app.models import User, AuditLog, LoginAttempt
from app.security.utils import get_client_ip, is_password_breached


@bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login with 2FA support."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        # Find user by username or email
        user = User.query.filter(
            (User.username == form.username.data) | 
            (User.email == form.username.data)
        ).first()
        
        ip_address = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')
        
        # Check if user exists and password is correct
        if user is None or not user.check_password(form.password.data):
            # Log failed attempt
            LoginAttempt.log_attempt(
                username=form.username.data,
                ip_address=ip_address,
                success=False,
                user=user,
                failure_reason='Invalid credentials',
                user_agent=user_agent
            )
            
            if user:
                user.increment_failed_attempts(
                    max_attempts=current_app.config['MAX_LOGIN_ATTEMPTS'],
                    lockout_duration=current_app.config['LOCKOUT_DURATION']
                )
            
            flash('Invalid username or password', 'error')
            return render_template('auth/login.html', form=form)
        
        # Check if account is locked
        if user.is_account_locked():
            LoginAttempt.log_attempt(
                username=form.username.data,
                ip_address=ip_address,
                success=False,
                user=user,
                failure_reason='Account locked',
                user_agent=user_agent
            )
            flash('Account is temporarily locked due to too many failed login attempts. Please try again later.', 'error')
            return render_template('auth/login.html', form=form)
        
        # Check if account is active
        if not user.is_active:
            LoginAttempt.log_attempt(
                username=form.username.data,
                ip_address=ip_address,
                success=False,
                user=user,
                failure_reason='Account disabled',
                user_agent=user_agent
            )
            flash('Account is disabled. Please contact an administrator.', 'error')
            return render_template('auth/login.html', form=form)
        
        # Check 2FA if enabled
        if user.is_2fa_enabled:
            if not form.totp_code.data:
                flash('2FA code is required', 'error')
                return render_template('auth/login.html', form=form, show_2fa=True)
            
            # Verify TOTP or backup code
            if not (user.verify_totp(form.totp_code.data) or 
                    user.verify_backup_code(form.totp_code.data)):
                LoginAttempt.log_attempt(
                    username=form.username.data,
                    ip_address=ip_address,
                    success=False,
                    user=user,
                    failure_reason='Invalid 2FA code',
                    user_agent=user_agent
                )
                user.increment_failed_attempts(
                    max_attempts=current_app.config['MAX_LOGIN_ATTEMPTS'],
                    lockout_duration=current_app.config['LOCKOUT_DURATION']
                )
                flash('Invalid 2FA code', 'error')
                return render_template('auth/login.html', form=form, show_2fa=True)
        
        # Successful login
        login_user(user, remember=form.remember_me.data)
        
        # Update user login information
        user.last_login_at = datetime.utcnow()
        user.last_login_ip = ip_address
        user.reset_failed_attempts()
        db.session.commit()
        
        # Log successful login
        LoginAttempt.log_attempt(
            username=form.username.data,
            ip_address=ip_address,
            success=True,
            user=user,
            user_agent=user_agent
        )
        
        AuditLog.log_event(
            action='login',
            user=user,
            details=f'Successful login from {ip_address}',
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.dashboard')
        
        flash(f'Welcome back, {user.first_name}!', 'success')
        return redirect(next_page)
    
    return render_template('auth/login.html', form=form)


@bp.route('/logout')
@login_required
def logout():
    """User logout."""
    # Log logout event
    AuditLog.log_event(
        action='logout',
        user=current_user,
        details=f'User logged out from {get_client_ip()}',
        ip_address=get_client_ip(),
        user_agent=request.headers.get('User-Agent', '')
    )
    
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))


@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password."""
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        # Verify current password
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'error')
            return render_template('auth/change_password.html', form=form)
        
        # Check if new password is the same as current
        if current_user.check_password(form.password.data):
            flash('New password must be different from current password.', 'error')
            return render_template('auth/change_password.html', form=form)
        
        # Check if password is breached (optional enhancement)
        if is_password_breached(form.password.data):
            flash('This password has been found in data breaches. Please choose a different password.', 'warning')
            return render_template('auth/change_password.html', form=form)
        
        # Update password
        current_user.set_password(form.password.data)
        db.session.commit()
        
        # Log password change
        AuditLog.log_event(
            action='password_change',
            user=current_user,
            details='Password changed successfully',
            ip_address=get_client_ip(),
            user_agent=request.headers.get('User-Agent', '')
        )
        
        flash('Your password has been changed successfully.', 'success')
        return redirect(url_for('profile.profile'))
    
    return render_template('auth/change_password.html', form=form)


@bp.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    """Set up two-factor authentication."""
    if current_user.is_2fa_enabled:
        flash('2FA is already enabled for your account.', 'info')
        return redirect(url_for('profile.profile'))
    
    form = TwoFactorSetupForm()
    
    # Generate TOTP secret if not exists
    if not current_user.totp_secret:
        current_user.generate_totp_secret()
        db.session.commit()
    
    # Generate QR code
    totp_uri = current_user.get_totp_uri()
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    qr_code_data = base64.b64encode(img_io.getvalue()).decode()
    
    if form.validate_on_submit():
        # Verify TOTP code
        if current_user.verify_totp(form.totp_code.data):
            # Enable 2FA and generate backup codes
            current_user.is_2fa_enabled = True
            backup_codes = current_user.generate_backup_codes()
            db.session.commit()
            
            # Log 2FA setup
            AuditLog.log_event(
                action='2fa_enabled',
                user=current_user,
                details='Two-factor authentication enabled',
                ip_address=get_client_ip(),
                user_agent=request.headers.get('User-Agent', '')
            )
            
            flash('Two-factor authentication has been enabled successfully!', 'success')
            return render_template('auth/backup_codes.html', backup_codes=backup_codes)
        else:
            flash('Invalid verification code. Please try again.', 'error')
    
    return render_template('auth/setup_2fa.html', 
                         form=form, 
                         qr_code_data=qr_code_data,
                         secret=current_user.totp_secret)


@bp.route('/disable-2fa', methods=['GET', 'POST'])
@login_required
def disable_2fa():
    """Disable two-factor authentication."""
    if not current_user.is_2fa_enabled:
        flash('2FA is not enabled for your account.', 'info')
        return redirect(url_for('profile.profile'))
    
    form = TwoFactorDisableForm()
    
    if form.validate_on_submit():
        # Verify password
        if current_user.check_password(form.password.data):
            # Disable 2FA
            current_user.is_2fa_enabled = False
            current_user.totp_secret = None
            current_user.backup_codes = None
            db.session.commit()
            
            # Log 2FA disable
            AuditLog.log_event(
                action='2fa_disabled',
                user=current_user,
                details='Two-factor authentication disabled',
                ip_address=get_client_ip(),
                user_agent=request.headers.get('User-Agent', '')
            )
            
            flash('Two-factor authentication has been disabled.', 'success')
            return redirect(url_for('profile.profile'))
        else:
            flash('Incorrect password.', 'error')
    
    return render_template('auth/disable_2fa.html', form=form)

