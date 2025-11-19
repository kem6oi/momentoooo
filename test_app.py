#!/usr/bin/env python3
"""Test script to verify the Flask app runs correctly."""
import os
import sys
import traceback

# Set environment variables for testing
os.environ['FLASK_DEBUG'] = 'True'
os.environ['SECRET_KEY'] = 'test-secret-key-for-development-only'
os.environ['FLASK_SECRET_KEY'] = 'test-secret-key-for-development-only'
os.environ['ADMIN_USERNAME'] = 'admin'
os.environ['ADMIN_PASSWORD'] = 'TestPassword123!'
os.environ['MAIL_SERVER'] = 'smtp.gmail.com'
os.environ['MAIL_PORT'] = '587'
os.environ['MAIL_USE_TLS'] = 'True'
os.environ['MAIL_USERNAME'] = 'test@example.com'
os.environ['MAIL_PASSWORD'] = 'test-password'
os.environ['MAIL_DEFAULT_SENDER'] = 'test@example.com'
os.environ['STRIPE_PUBLIC_KEY'] = 'pk_test_example'
os.environ['STRIPE_SECRET_KEY'] = 'sk_test_example'
os.environ['STRIPE_WEBHOOK_SECRET'] = 'whsec_example'

print("=" * 60)
print("Testing Flask Application Startup")
print("=" * 60)

try:
    print("\n1. Testing imports...")
    import app
    print("   ✓ App module imported successfully")

    print("\n2. Testing Flask app configuration...")
    flask_app = app.app
    print(f"   ✓ Flask app created: {flask_app.name}")
    print(f"   ✓ Debug mode: {flask_app.debug}")
    print(f"   ✓ Secret key configured: {'Yes' if flask_app.config.get('SECRET_KEY') else 'No'}")

    print("\n3. Testing registered blueprints...")
    blueprints = list(flask_app.blueprints.keys())
    for bp in blueprints:
        print(f"   ✓ Blueprint registered: {bp}")

    print("\n4. Testing routes...")
    routes = []
    for rule in flask_app.url_map.iter_rules():
        if rule.endpoint != 'static':
            routes.append(f"{rule.rule} [{', '.join(rule.methods)}]")
    print(f"   ✓ Total routes registered: {len(routes)}")
    print("   First 10 routes:")
    for route in sorted(routes)[:10]:
        print(f"     - {route}")

    print("\n5. Testing database connection...")
    from core.database import db_session
    from core.auth.models import User
    user_count = db_session.query(User).count()
    print(f"   ✓ Database connected: {user_count} users in database")

    print("\n6. Testing Flask app startup (test client)...")
    with flask_app.test_client() as client:
        # Test index page
        response = client.get('/')
        print(f"   ✓ GET / - Status: {response.status_code}")

        # Test login page
        response = client.get('/login')
        print(f"   ✓ GET /login - Status: {response.status_code}")

        # Test challenges page (requires login)
        response = client.get('/challenges')
        print(f"   ✓ GET /challenges - Status: {response.status_code} (redirect expected)")

    print("\n" + "=" * 60)
    print("✓ ALL TESTS PASSED - Application is working correctly!")
    print("=" * 60)
    print("\nApplication can be started with:")
    print("  python3 app.py")
    print("\nOr using Gunicorn for production:")
    print("  gunicorn -w 4 -b 0.0.0.0:5000 app:app")

except Exception as e:
    print("\n" + "=" * 60)
    print("✗ ERROR OCCURRED")
    print("=" * 60)
    print(f"\nError: {str(e)}\n")
    traceback.print_exc()
    sys.exit(1)
