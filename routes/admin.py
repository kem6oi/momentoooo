from flask import Blueprint, render_template, request, flash, redirect, url_for
from functools import wraps
from core.auth.user_manager import UserManager
from core.marketplace.models import Product, Seller, Payment, PaymentStatus, User
from core.database import db_session
from datetime import datetime, timedelta
import json
import os
from werkzeug.utils import secure_filename
from core.shared import challenge_manager  # Import from core.shared instead of app.py
from flask_login import login_required, current_user

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Configure upload folder
UPLOAD_FOLDER = 'static/challenges'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', '7z', 'bin', 'exe', 'py', 'c', 'cpp', 'java'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not UserManager.is_admin():
            flash('Admin access required.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard showing all challenges."""
    challenges = challenge_manager.get_all_challenges()
    return render_template('admin/dashboard.html', challenges=challenges)

@admin_bp.route('/challenges/create', methods=['GET', 'POST'])
@admin_required
def create_challenge():
    if request.method == 'POST':
        challenge_id = request.form.get('challenge_id')
        challenge_type = request.form.get('challenge_type')
        difficulty = request.form.get('difficulty')
        description = request.form.get('description')
        points = request.form.get('points', 100)
        flag = request.form.get('flag')
        files = request.files.getlist('challenge_file')

        # Crypto parameters
        key_length_str = request.form.get('key_length')
        encryption_mode = request.form.get('encryption_mode')
        message_to_encrypt = request.form.get('message')

        # Process crypto params
        key_length = int(key_length_str) if key_length_str and key_length_str.isdigit() else None
        if not message_to_encrypt:
            message_to_encrypt = None

        # Save uploaded files
        saved_files = []
        if files:
            challenge_dir = os.path.join('static', 'challenges', challenge_id)
            os.makedirs(challenge_dir, exist_ok=True)
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(challenge_dir, filename)
                    file.save(file_path)
                    saved_files.append(filename)

        try:
            # Corrected create_challenge() call
            challenge = challenge_manager.create_challenge(
                challenge_id=challenge_id,
                challenge_type=challenge_type,
                difficulty=difficulty,
                description=description,
                points=int(points),  # Ensure points is an int
                flag=flag,
                key_length=key_length,       # New: crypto param
                mode=encryption_mode,        # New: crypto param
                message_to_encrypt=message_to_encrypt,  # New: crypto param
                hints=[h.strip() for h in request.form.get('hints', '').splitlines() if h.strip()],  # Corrected hints
                files=saved_files
            )
            flash('Challenge created successfully!', 'success')
            return render_template('admin/create_challenge.html', challenge_info=challenge)
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('admin/create_challenge.html')

    return render_template('admin/create_challenge.html')

@admin_bp.route('/admin/challenge/<challenge_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_challenge(challenge_id):
    """Edit an existing challenge."""
    challenge = challenge_manager.get_challenge(challenge_id)
    if not challenge:
        flash('Challenge not found.', 'error')
        return redirect(url_for('admin.admin_dashboard'))

    if request.method == 'POST':
        challenge_data = {
            'description': request.form.get('description'),
            'points': request.form.get('points'),
            'hints': request.form.getlist('hints[]'),
            'is_active': bool(request.form.get('is_active'))
        }

        try:
            challenge_manager.update_challenge(challenge_id, challenge_data)
            flash('Challenge updated successfully!', 'success')
            return redirect(url_for('admin.admin_dashboard'))
        except ValueError as e:
            flash(str(e), 'error')

    return render_template('admin/edit_challenge.html', challenge=challenge)

@admin_bp.route('/admin/challenge/<challenge_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_challenge(challenge_id):
    """Delete a challenge."""
    try:
        challenge_manager.delete_challenge(challenge_id)
        flash('Challenge deleted successfully!', 'success')
    except ValueError as e:
        flash(str(e), 'error')
    
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/user-management')
@admin_required
def user_management():
    users = User.query.all()
    return render_template('admin/user_management.html', users=users)

@admin_bp.route('/user/<username>/toggle-status', methods=['POST'])
@admin_required
def toggle_user_status(username):
    user = User.query.get_or_404(username)
    user.is_active = not user.is_active
    db_session.commit()

    status = "activated" if user.is_active else "deactivated"
    flash(f"User {username} has been {status}.", "success")
    return redirect(url_for('admin.user_management'))

@admin_bp.route('/user/<username>/make-admin', methods=['POST'])
@admin_required
def make_admin(username):
    user = User.query.get_or_404(username)
    user.is_admin = True
    db_session.commit()
    flash(f"User {username} has been made an admin.", "success")
    return redirect(url_for('admin.user_management'))

