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
        # NOTE: 'unsafe-inline' is a security risk but may be needed for some apps
        # Consider using nonces or hashes instead of 'unsafe-inline' for production
        # See: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net https://unpkg.com https://js.stripe.com; "
            "style-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self' https://api.stripe.com; "
            "frame-src https://js.stripe.com https://hooks.stripe.com; "
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
