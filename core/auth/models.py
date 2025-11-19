from core.database import Base
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from flask_login import UserMixin
from datetime import datetime
import secrets

class User(Base, UserMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(120), nullable=False)
    email = Column(String(120), unique=True, nullable=True)
    email_verified = Column(Boolean, default=False)
    email_token = Column(String(100), unique=True)
    email_token_expiry = Column(DateTime)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)

    # Relationships
    buyer_profile = relationship("Buyer", back_populates="user", uselist=False)
    seller_profile = relationship("Seller", back_populates="user", uselist=False)
    
    def get_id(self):
        return str(self.username)
    
    def generate_email_token(self):
        """Generate a new email verification token"""
        self.email_token = secrets.token_urlsafe(32)
        self.email_token_expiry = datetime.utcnow() + datetime.timedelta(hours=24)
        return self.email_token
