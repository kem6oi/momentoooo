from flask import Blueprint, render_template, flash, redirect, url_for, request
from flask_login import login_required, current_user
from core.database import db_session
from core.auth.models import User
from core.marketplace.models import Seller, Buyer
from werkzeug.security import generate_password_hash, check_password_hash

profile_bp = Blueprint('profile', __name__)

@profile_bp.route('/profile', methods=['GET'])
@login_required
def view_profile():
    """View user profile"""
    return render_template('profile/view.html')

@profile_bp.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile"""
    if request.method == 'POST':
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Update email if changed
        if email and email != current_user.email:
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'error')
                return render_template('profile/edit.html')
            current_user.email = email
            current_user.email_verified = False
        
        # Update password if provided
        if current_password and new_password:
            if not check_password_hash(current_user.password_hash, current_password):
                flash('Current password is incorrect', 'error')
                return render_template('profile/edit.html')
            
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return render_template('profile/edit.html')
            
            current_user.password_hash = generate_password_hash(new_password)
            flash('Password updated successfully', 'success')
        
        db_session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile.view_profile'))
    
    return render_template('profile/edit.html') 