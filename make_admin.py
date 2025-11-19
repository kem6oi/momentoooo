from core.database import db_session
from core.auth.models import User
import sys

def make_admin(username):
    """Make a user an admin."""
    user = User.query.filter_by(username=username).first()
    if user:
        user.is_admin = True
        db_session.commit()
        print(f"User {username} is now an admin.")
    else:
        print(f"User {username} not found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    make_admin(username) 