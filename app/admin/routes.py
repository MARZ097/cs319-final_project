from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash

from app import db
from app.models import User, Role, AuditLog
from app.admin.forms import UserCreateForm, UserEditForm
from app.security.utils import admin_required, log_admin_action, get_client_ip, sanitize_input

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin/dashboard.html', users=users)


@admin_bp.route('/users')
@login_required
@admin_required
def list_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)


@admin_bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    form = UserCreateForm()
    
    # Get all roles for the form
    roles = Role.query.all()
    form.role.choices = [(role.id, role.name) for role in roles]
    
    if form.validate_on_submit():
        # Check if user already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return render_template('admin/create_user.html', form=form)
        
        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email:
            flash('Email already exists', 'danger')
            return render_template('admin/create_user.html', form=form)
        
        # Create new user
        user = User(
            username=sanitize_input(form.username.data),
            email=sanitize_input(form.email.data),
            first_name=sanitize_input(form.first_name.data),
            last_name=sanitize_input(form.last_name.data),
            is_active=form.is_active.data
        )
        
        # Set password
        user.password = form.password.data
        
        # Set role
        role = Role.query.get(form.role.data)
        user.role = role
        
        # Save user
        db.session.add(user)
        db.session.commit()
        
        # Log the action
        ip_address = get_client_ip()
        log_admin_action(current_user, 'create_user', f'Created user {user.username}', ip_address)
        
        # Create audit log entry
        log = AuditLog(
            user_id=current_user.id,
            action='create_user',
            details=f'Created user {user.username}',
            ip_address=ip_address
        )
        db.session.add(log)
        db.session.commit()
        
        flash(f'User {user.username} has been created', 'success')
        return redirect(url_for('admin.list_users'))
    
    return render_template('admin/create_user.html', form=form)


@admin_bp.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserEditForm(obj=user)
    
    # Get all roles for the form
    roles = Role.query.all()
    form.role.choices = [(role.id, role.name) for role in roles]
    
    if form.validate_on_submit():
        # Update user data
        user.username = sanitize_input(form.username.data)
        user.email = sanitize_input(form.email.data)
        user.first_name = sanitize_input(form.first_name.data)
        user.last_name = sanitize_input(form.last_name.data)
        user.is_active = form.is_active.data
        
        # Update role
        role = Role.query.get(form.role.data)
        user.role = role
        
        # Update password if provided
        if form.password.data:
            user.password = form.password.data
        
        db.session.commit()
        
        # Log the action
        ip_address = get_client_ip()
        log_admin_action(current_user, 'edit_user', f'Edited user {user.username}', ip_address)
        
        # Create audit log entry
        log = AuditLog(
            user_id=current_user.id,
            action='edit_user',
            details=f'Edited user {user.username}',
            ip_address=ip_address
        )
        db.session.add(log)
        db.session.commit()
        
        flash(f'User {user.username} has been updated', 'success')
        return redirect(url_for('admin.list_users'))
    
    # Pre-select the current role
    if user.role:
        form.role.data = user.role.id
    
    return render_template('admin/edit_user.html', form=form, user=user)


@admin_bp.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Don't allow deletion of self
    if user.id == current_user.id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin.list_users'))
    
    username = user.username
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    
    # Log the action
    ip_address = get_client_ip()
    log_admin_action(current_user, 'delete_user', f'Deleted user {username}', ip_address)
    
    # Create audit log entry
    log = AuditLog(
        user_id=current_user.id,
        action='delete_user',
        details=f'Deleted user {username}',
        ip_address=ip_address
    )
    db.session.add(log)
    db.session.commit()
    
    flash(f'User {username} has been deleted', 'success')
    return redirect(url_for('admin.list_users'))


@admin_bp.route('/audit-logs')
@login_required
@admin_required
def audit_logs():
    # Get query parameters for filtering
    user_id = request.args.get('user_id', type=int)
    action = request.args.get('action')
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    
    # Base query
    query = AuditLog.query
    
    # Apply filters
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    if action:
        query = query.filter(AuditLog.action == action)
    
    if from_date:
        from datetime import datetime
        try:
            from_date = datetime.strptime(from_date, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp >= from_date)
        except ValueError:
            pass
    
    if to_date:
        from datetime import datetime
        try:
            to_date = datetime.strptime(to_date, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp <= to_date)
        except ValueError:
            pass
    
    # Get logs with pagination
    page = request.args.get('page', 1, type=int)
    logs = query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20)
    
    # Get users for the filter dropdown
    users = User.query.all()
    
    # Get unique actions for filter dropdown
    actions = db.session.query(AuditLog.action).distinct().all()
    actions = [action[0] for action in actions]
    
    return render_template('admin/audit_logs.html', logs=logs, users=users, actions=actions)
