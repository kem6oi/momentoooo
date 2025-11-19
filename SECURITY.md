# Security Documentation

## Overview

This document outlines the security improvements and best practices implemented in this Flask application.

## Security Fixes Implemented

### 1. Environment Variable Configuration

**Issue**: Hardcoded credentials and API keys were stored directly in the `.env` file and committed to version control.

**Fix**:
- Created `.env.example` template with placeholder values
- Replaced all real credentials with placeholders in `.env`
- Added `.env` to `.gitignore` to prevent future commits
- Added comprehensive `.gitignore` for sensitive files

**Action Required**:
1. Copy `.env.example` to `.env`
2. Replace all placeholder values with your actual credentials
3. Generate strong secret keys:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

### 2. CSRF Protection

**Issue**: CSRF protection was disabled in `app.py`.

**Fix**: Re-enabled `CSRFProtect` middleware to protect against Cross-Site Request Forgery attacks.

**Impact**: All state-changing operations now require valid CSRF tokens.

### 3. Debug Mode

**Issue**: Debug mode was hardcoded to `True` in production.

**Fix**:
- Debug mode now controlled by `FLASK_DEBUG` environment variable
- Defaults to `False` for security
- Set to `True` only in development environments

### 4. Admin Credentials

**Issue**: Weak hardcoded admin password `'admin123'` in `init_db.py`.

**Fix**:
- Admin credentials now read from environment variables
- Application raises error if `ADMIN_PASSWORD` not set
- Forces use of strong passwords

### 5. Security Headers

**Issue**: Missing critical security headers.

**Fix**: Implemented comprehensive security headers middleware in `config/security_headers.py`:

- **Content-Security-Policy**: Prevents XSS attacks by controlling resource sources
- **X-Frame-Options**: Prevents clickjacking (set to DENY)
- **X-Content-Type-Options**: Prevents MIME sniffing
- **X-XSS-Protection**: Additional XSS protection for older browsers
- **Referrer-Policy**: Controls referrer information leakage
- **Permissions-Policy**: Restricts browser features and APIs

**Note**: Uncomment `Strict-Transport-Security` header when deploying with HTTPS.

### 6. Rate Limiting

**Issue**: Basic rate limiting with several flaws:
- Used request context (`g`) which didn't persist
- Not proxy-aware
- No cleanup mechanism

**Fix**: Comprehensive rate limiting improvements:
- Persistent in-memory storage across requests
- Proxy-aware IP detection (checks `X-Forwarded-For` and `X-Real-IP`)
- Sliding window algorithm
- Thread-safe implementation
- Automatic cleanup of expired entries
- Better error messages with retry timing

## Configuration

### Required Environment Variables

```bash
# Flask Configuration
FLASK_SECRET_KEY=<generate-random-key>
SECRET_KEY=<generate-random-key>
FLASK_DEBUG=False

# Admin Credentials
ADMIN_USERNAME=<your-admin-username>
ADMIN_PASSWORD=<strong-password>

# Email Settings
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=<your-email@gmail.com>
MAIL_PASSWORD=<your-app-password>
MAIL_DEFAULT_SENDER=<your-email@gmail.com>

# Stripe Settings
STRIPE_PUBLIC_KEY=<your-stripe-public-key>
STRIPE_SECRET_KEY=<your-stripe-secret-key>
STRIPE_WEBHOOK_SECRET=<your-webhook-secret>

# Rate Limiting
RATE_LIMIT_WINDOW=60
RATE_LIMIT_MAX_REQUESTS=10

# Cryptography
RSA_KEY_SIZE=2048
HASH_ALGORITHM=sha256
```

## Deployment Checklist

Before deploying to production:

- [ ] Generate strong random secret keys
- [ ] Set `FLASK_DEBUG=False`
- [ ] Use strong admin credentials
- [ ] Configure email with app-specific passwords
- [ ] Set up Stripe production keys
- [ ] Enable HTTPS and uncomment HSTS header
- [ ] Review CSP policy for your specific needs
- [ ] Consider using Redis for rate limiting (for multi-server deployments)
- [ ] Set up proper logging and monitoring
- [ ] Regular security audits
- [ ] Keep dependencies updated
- [ ] Review and test all authentication flows

## Additional Security Recommendations

### 1. Database Security
- Use database migrations instead of dropping tables in `init_db.py`
- Implement database backups
- Use parameterized queries (already using SQLAlchemy ORM)

### 2. Input Validation
- Implement comprehensive input validation on all forms
- Sanitize user inputs before storage
- Validate file uploads (type, size, content)

### 3. Authentication & Authorization
- Implement password complexity requirements
- Add account lockout after failed login attempts
- Enable email verification
- Implement 2FA for admin accounts
- Add session timeout
- Implement proper privilege escalation logging

### 4. Logging & Monitoring
- Log all authentication attempts
- Log privilege escalations
- Log sensitive operations (product creation, payments)
- Set up alerts for suspicious activities
- Store logs securely

### 5. HTTPS
- Always use HTTPS in production
- Redirect HTTP to HTTPS
- Use valid SSL/TLS certificates
- Enable HSTS header

### 6. Production Considerations
- Use a production WSGI server (Gunicorn, uWSGI)
- Never use Flask's built-in development server
- Implement proper error handling without exposing stack traces
- Use environment-specific configurations
- Regular dependency updates and security patches

### 7. Rate Limiting Production
For production with multiple servers, replace the in-memory rate limiting with Redis:

```python
# Install: pip install redis
from redis import Redis
redis_client = Redis(host='localhost', port=6379, db=0)
```

## Git Security

### Removing Sensitive Data from Git History

If credentials were committed to git history, use these steps:

```bash
# Install BFG Repo Cleaner
# Download from: https://rtyley.github.io/bfg-repo-cleaner/

# Remove .env file from history
bfg --delete-files .env

# Clean up
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Force push (WARNING: Coordinate with team)
git push --force
```

## Security Contacts

For security issues or questions:
- Review this documentation
- Check Flask security best practices: https://flask.palletsprojects.com/en/latest/security/
- OWASP Top 10: https://owasp.org/www-project-top-ten/

## Regular Security Tasks

- [ ] Monthly: Review access logs for suspicious activity
- [ ] Monthly: Update dependencies with security patches
- [ ] Quarterly: Security audit and penetration testing
- [ ] Quarterly: Review and rotate credentials
- [ ] Annually: Full security assessment

## Changelog

### 2024 - Security Hardening
- Removed hardcoded credentials
- Enabled CSRF protection
- Disabled debug mode by default
- Implemented security headers
- Improved rate limiting
- Added comprehensive documentation
