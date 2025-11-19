from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
import os

# Create database directory if it doesn't exist
DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance')
os.makedirs(DB_DIR, exist_ok=True)

# Database configuration
SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(DB_DIR, "marketplace.db")}'
engine = create_engine(SQLALCHEMY_DATABASE_URI)

# Create a session factory
session_factory = sessionmaker(bind=engine)
db_session = scoped_session(session_factory)

# Base class for all models
Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    """Initialize the database with all models."""
    # Import all models here to ensure they are registered with Base
    from core.marketplace.models import User, Product, Seller, Buyer, Payment
    from core.challenges.models import Challenge
    
    # Create all tables
    Base.metadata.create_all(engine)
