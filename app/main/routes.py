"""
Main application routes.
"""
from flask import render_template, redirect, url_for
from flask_login import login_required, current_user

from app.main import bp
from app.models import User, AuditLog


@bp.route('/')
def index():
    """Home page - redirect to dashboard if logged in, otherwise to login."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard."""
    # Get recent activity for current user
    recent_activities = AuditLog.query.filter_by(user_id=current_user.id)\
        .order_by(AuditLog.timestamp.desc())\
        .limit(10)\
        .all()
    
    # Get system statistics for admin users
    stats = {}
    if current_user.is_admin():
        stats = {
            'total_users': User.query.count(),
            'active_users': User.query.filter_by(is_active=True).count(),
            'admin_users': User.query.filter_by(role='admin').count(),
            'locked_users': User.query.filter_by(is_locked=True).count(),
            'users_with_2fa': User.query.filter_by(is_2fa_enabled=True).count()
        }
    
    return render_template('main/dashboard.html', 
                         recent_activities=recent_activities,
                         stats=stats)

