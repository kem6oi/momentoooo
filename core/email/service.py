from flask_mail import Mail, Message
from flask import current_app, url_for
from threading import Thread

mail = Mail()

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(subject, recipients, html_body):
    """Send email asynchronously"""
    msg = Message(subject, recipients=recipients)
    msg.html = html_body
    Thread(target=send_async_email, args=(current_app._get_current_object(), msg)).start()

def send_verification_email(user):
    """Send verification email to user"""
    token = user.generate_email_token()
    verify_url = url_for('auth.verify_email', token=token, _external=True)
    
    html = f'''
    <h1>Welcome to Momento!</h1>
    <p>Thank you for registering. To verify your email address, please click the link below:</p>
    <p><a href="{verify_url}">Verify Email</a></p>
    <p>This link will expire in 24 hours.</p>
    <p>If you did not register for Momento, please ignore this email.</p>
    '''
    
    send_email(
        'Verify Your Email - Momento',
        [user.email],
        html
    )
