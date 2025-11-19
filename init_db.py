from core.database import Base, engine, db_session
from core.auth.models import User
from core.marketplace.models import Seller, Product, Buyer, Payment
from werkzeug.security import generate_password_hash
from datetime import datetime

def init_db():
    """Initialize the database."""
    # Drop all existing tables
    Base.metadata.drop_all(bind=engine)
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Create default admin user if it doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            email='admin@example.com',
            email_verified=True,
            is_active=True,
            is_admin=True,
            created_at=datetime.utcnow()
        )
        db_session.add(admin)
        db_session.commit()
        print("Default admin user created successfully!")

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully!")
