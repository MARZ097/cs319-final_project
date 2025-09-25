"""
Admin routes for user management and system administration.
"""
from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timedelta

from app import db
from app.admin import bp
from app.auth.forms import RegistrationForm
from app.models import User, AuditLog, LoginAttempt
from app.security.utils import admin_required, get_client_ip


@bp.route('/users')
@login_required
@admin_required
def users():
    """List all users."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    users = User.query.order_by(User.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/users.html', users=users)


@bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    """Create a new user."""
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            role=form.role.data
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        # Log user creation
        AuditLog.log_event(
            action='user_created',
            user=current_user,
            resource='user',
            resource_id=user.id,
            details=f'Created user: {user.username} ({user.email}) with role: {user.role}',
            ip_address=get_client_ip(),
            user_agent=request.headers.get('User-Agent', '')
        )
        
        flash(f'User {user.username} created successfully.', 'success')
        return redirect(url_for('admin.users'))
    
    return render_template('admin/create_user.html', form=form)


@bp.route('/users/<int:user_id>')
@login_required
@admin_required
def user_detail(user_id):
    """View user details."""
    user = User.query.get_or_404(user_id)
    
    # Get user's recent activities
    activities = AuditLog.query.filter_by(user_id=user.id)\
        .order_by(AuditLog.timestamp.desc())\
        .limit(20)\
        .all()
    
    # Get user's login attempts
    login_attempts = LoginAttempt.query.filter_by(user_id=user.id)\
        .order_by(LoginAttempt.timestamp.desc())\
        .limit(10)\
        .all()
    
    return render_template('admin/user_detail.html', 
                         user=user, 
                         activities=activities,
                         login_attempts=login_attempts)


@bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    """Toggle user active status."""
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from disabling themselves
    if user.id == current_user.id:
        flash('You cannot disable your own account.', 'error')
        return redirect(url_for('admin.user_detail', user_id=user_id))
    
    # Toggle status
    user.is_active = not user.is_active
    action = 'enabled' if user.is_active else 'disabled'
    
    db.session.commit()
    
    # Log status change
    AuditLog.log_event(
        action=f'user_{action}',
        user=current_user,
        resource='user',
        resource_id=user.id,
        details=f'User {user.username} {action}',
        ip_address=get_client_ip(),
        user_agent=request.headers.get('User-Agent', '')
    )
    
    flash(f'User {user.username} has been {action}.', 'success')
    return redirect(url_for('admin.user_detail', user_id=user_id))


@bp.route('/users/<int:user_id>/unlock', methods=['POST'])
@login_required
@admin_required
def unlock_user(user_id):
    """Unlock a locked user account."""
    user = User.query.get_or_404(user_id)
    
    if not user.is_locked:
        flash('User account is not locked.', 'info')
        return redirect(url_for('admin.user_detail', user_id=user_id))
    
    # Unlock account
    user.unlock_account()
    db.session.commit()
    
    # Log unlock action
    AuditLog.log_event(
        action='user_unlocked',
        user=current_user,
        resource='user',
        resource_id=user.id,
        details=f'User {user.username} unlocked by admin',
        ip_address=get_client_ip(),
        user_agent=request.headers.get('User-Agent', '')
    )
    
    flash(f'User {user.username} has been unlocked.', 'success')
    return redirect(url_for('admin.user_detail', user_id=user_id))


@bp.route('/users/<int:user_id>/change-role', methods=['POST'])
@login_required
@admin_required
def change_user_role(user_id):
    """Change user role."""
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    
    if new_role not in ['admin', 'user']:
        flash('Invalid role specified.', 'error')
        return redirect(url_for('admin.user_detail', user_id=user_id))
    
    # Prevent admin from demoting themselves if they're the only admin
    if (user.id == current_user.id and 
        current_user.role == 'admin' and 
        new_role != 'admin'):
        admin_count = User.query.filter_by(role='admin', is_active=True).count()
        if admin_count <= 1:
            flash('Cannot change role: you are the only active admin.', 'error')
            return redirect(url_for('admin.user_detail', user_id=user_id))
    
    old_role = user.role
    user.role = new_role
    db.session.commit()
    
    # Log role change
    AuditLog.log_event(
        action='role_changed',
        user=current_user,
        resource='user',
        resource_id=user.id,
        details=f'User {user.username} role changed from {old_role} to {new_role}',
        ip_address=get_client_ip(),
        user_agent=request.headers.get('User-Agent', '')
    )
    
    flash(f'User {user.username} role changed to {new_role}.', 'success')
    return redirect(url_for('admin.user_detail', user_id=user_id))


@bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user account."""
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin.user_detail', user_id=user_id))
    
    # Prevent deleting the last admin
    if user.role == 'admin':
        admin_count = User.query.filter_by(role='admin', is_active=True).count()
        if admin_count <= 1:
            flash('Cannot delete the last active admin user.', 'error')
            return redirect(url_for('admin.user_detail', user_id=user_id))
    
    username = user.username
    
    # Log deletion before deleting
    AuditLog.log_event(
        action='user_deleted',
        user=current_user,
        resource='user',
        resource_id=user.id,
        details=f'User {username} deleted',
        ip_address=get_client_ip(),
        user_agent=request.headers.get('User-Agent', '')
    )
    
    # Delete user
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {username} has been deleted.', 'success')
    return redirect(url_for('admin.users'))


@bp.route('/audit-logs')
@login_required
@admin_required
def audit_logs():
    """View audit logs with filtering."""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Filter parameters
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Build query
    query = AuditLog.query
    
    if action_filter:
        query = query.filter(AuditLog.action.contains(action_filter))
    
    if user_filter:
        user = User.query.filter(
            (User.username.contains(user_filter)) |
            (User.email.contains(user_filter))
        ).first()
        if user:
            query = query.filter(AuditLog.user_id == user.id)
    
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp >= date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AuditLog.timestamp <= date_to_obj)
        except ValueError:
            pass
    
    logs = query.order_by(AuditLog.timestamp.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    # Get unique actions for filter dropdown
    actions = db.session.query(AuditLog.action.distinct()).all()
    actions = [action[0] for action in actions]
    
    return render_template('admin/audit_logs.html', 
                         logs=logs, 
                         actions=actions,
                         filters={
                             'action': action_filter,
                             'user': user_filter,
                             'date_from': date_from,
                             'date_to': date_to
                         })


@bp.route('/system-stats')
@login_required
@admin_required
def system_stats():
    """System statistics and monitoring."""
    # User statistics
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    locked_users = User.query.filter_by(is_locked=True).count()
    admin_users = User.query.filter_by(role='admin').count()
    users_with_2fa = User.query.filter_by(is_2fa_enabled=True).count()
    
    # Recent activity
    recent_logins = LoginAttempt.query.filter_by(success=True)\
        .order_by(LoginAttempt.timestamp.desc())\
        .limit(10)\
        .all()
    
    failed_logins_24h = LoginAttempt.query.filter(
        LoginAttempt.success == False,
        LoginAttempt.timestamp >= datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    # Audit log statistics
    total_audit_logs = AuditLog.query.count()
    recent_audit_logs = AuditLog.query\
        .order_by(AuditLog.timestamp.desc())\
        .limit(10)\
        .all()
    
    stats = {
        'users': {
            'total': total_users,
            'active': active_users,
            'locked': locked_users,
            'admin': admin_users,
            'with_2fa': users_with_2fa
        },
        'security': {
            'failed_logins_24h': failed_logins_24h,
            'total_audit_logs': total_audit_logs
        }
    }
    
    return render_template('admin/system_stats.html', 
                         stats=stats,
                         recent_logins=recent_logins,
                         recent_audit_logs=recent_audit_logs)

