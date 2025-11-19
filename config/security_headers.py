"""
Security headers middleware for Flask application.
Adds important security headers to all responses.
"""
from functools import wraps
from flask import make_response


def add_security_headers(app):
    """
    Add security headers to all responses.

    Headers included:
    - Content-Security-Policy: Prevents XSS attacks
    - X-Frame-Options: Prevents clickjacking
    - X-Content-Type-Options: Prevents MIME sniffing
    - Strict-Transport-Security: Forces HTTPS
    - X-XSS-Protection: Additional XSS protection for older browsers
    - Referrer-Policy: Controls referrer information
    - Permissions-Policy: Controls browser features
    """

    @app.after_request
    def set_security_headers(response):
        # Content Security Policy - restricts sources of content
        # Adjust this based on your application's needs
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        # Prevent clickjacking attacks
        response.headers['X-Frame-Options'] = 'DENY'

        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # Force HTTPS (only enable if using HTTPS)
        # Uncomment the next line when deploying with HTTPS
        # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # XSS Protection for older browsers
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # Control referrer information
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Control browser features and APIs
        response.headers['Permissions-Policy'] = (
            'geolocation=(), '
            'microphone=(), '
            'camera=(), '
            'payment=(), '
            'usb=(), '
            'magnetometer=(), '
            'gyroscope=(), '
            'accelerometer=()'
        )

        return response

    return app
