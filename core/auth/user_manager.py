from flask_login import current_user
from core.auth.models import User
from core.database import db_session

class UserManager:
    @staticmethod
    def is_admin():
        """Check if the current user is an admin."""
        return current_user.is_authenticated and current_user.is_admin

    @staticmethod
    def get_user(username):
        """Get a user by username."""
        return User.query.filter_by(username=username).first()

    @staticmethod
    def get_all_users():
        """Get all users."""
        return User.query.all()

    @staticmethod
    def toggle_user_status(username):
        """Toggle a user's active status."""
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_active = not user.is_active
            db_session.commit()
            return True
        return False

    @staticmethod
    def make_admin(username):
        """Make a user an admin."""
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_admin = True
            db_session.commit()
            return True
        return False

    @staticmethod
    def get_user_stats():
        """Get user statistics."""
        users = User.query.all()
        total_users = len(users)
        verified_users = sum(1 for user in users if user.email_verified)
        active_users = sum(1 for user in users if user.is_active)
        admin_users = sum(1 for user in users if user.is_admin)
        
        return {
            'total': total_users,
            'verified': verified_users,
            'active': active_users,
            'admin': admin_users
        } 