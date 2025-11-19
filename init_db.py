from core.database import Base, engine, db_session
from core.auth.models import User
from core.marketplace.models import Seller, Product, Buyer, Payment
from werkzeug.security import generate_password_hash
from datetime import datetime
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

def init_db():
    """Initialize the database."""
    # Drop all existing tables
    Base.metadata.drop_all(bind=engine)

    # Create all tables
    Base.metadata.create_all(bind=engine)

    # Create default admin user if it doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        # Get admin credentials from environment variables
        admin_username = os.getenv('ADMIN_USERNAME', 'admin')
        admin_password = os.getenv('ADMIN_PASSWORD')

        if not admin_password:
            raise ValueError(
                "ADMIN_PASSWORD must be set in .env file. "
                "Never use default passwords in production!"
            )

        admin = User(
            username=admin_username,
            password_hash=generate_password_hash(admin_password),
            email='admin@example.com',
            email_verified=True,
            is_active=True,
            is_admin=True,
            created_at=datetime.utcnow()
        )
        db_session.add(admin)
        db_session.commit()
        print(f"Default admin user '{admin_username}' created successfully!")

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully!")
