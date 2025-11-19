from flask import Blueprint, flash, redirect, url_for, render_template, request
from core.auth.models import User
from core.database import db_session
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from core.email.service import mail
from flask_mail import Message
import secrets

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('auth/register.html')
        
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            is_active=True,
            is_admin=False,
            created_at=datetime.utcnow()
        )
        db_session.add(user)
        db_session.commit()
        
        login_user(user)
        flash('Registration successful!', 'success')
        return redirect(url_for('list_challenges'))
    
    return render_template('auth/register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    admin_login = request.args.get('admin', '0') == '1'
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin_login = request.form.get('admin_login') == '1'
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            if admin_login and not user.is_admin:
                flash('Access denied. Admin privileges required.', 'error')
                return render_template('auth/login.html', admin_login=True)
                
            if not user.is_active:
                flash('Your account has been deactivated. Please contact support.', 'error')
                return render_template('auth/login.html', admin_login=admin_login)
                
            login_user(user)
            flash('Logged in successfully!', 'success')
            
            if user.is_admin:
                return redirect(url_for('admin.admin_dashboard'))
            return redirect(url_for('index'))
            
        flash('Invalid username or password', 'error')
    
    return render_template('auth/login.html', admin_login=admin_login)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@auth_bp.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(email_token=token).first()
    
    if not user:
        flash('Invalid verification link', 'error')
        return redirect(url_for('index'))
    
    if user.email_token_expiry < datetime.utcnow():
        flash('Verification link has expired. Please request a new one.', 'error')
        return redirect(url_for('index'))
    
    user.email_verified = True
    user.email_token = None
    user.email_token_expiry = None
    db_session.commit()
    
    flash('Email verified successfully!', 'success')
    return redirect(url_for('marketplace.index'))

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate password reset token
            user.reset_token = secrets.token_urlsafe(32)
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db_session.commit()
            
            # Send password reset email
            send_password_reset_email(user)
            
        # Always show success message to prevent email enumeration
        flash('If an account exists with that email, you will receive a password reset link.', 'info')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/forgot_password.html')

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or user.reset_token_expiry < datetime.utcnow():
        flash('Invalid or expired password reset link', 'error')
        return redirect(url_for('auth.login'))
        
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('auth/reset_password.html', token=token)
            
        user.password_hash = generate_password_hash(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db_session.commit()
        
        flash('Your password has been reset successfully!', 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('auth/reset_password.html', token=token)

def send_password_reset_email(user):
    msg = Message('Reset your password',
                 recipients=[user.email])
    msg.html = render_template('email/reset_password.html',
                             reset_url=url_for('auth.reset_password',
                                             token=user.reset_token,
                                             _external=True))
    mail.send(msg)
