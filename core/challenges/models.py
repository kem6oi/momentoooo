from core.database import Base, db_session
from sqlalchemy import Column, Integer, String, Boolean, JSON, Text

class Challenge(Base):
    __tablename__ = 'challenges'

    id = Column(String(50), primary_key=True)
    type = Column(String(20), nullable=False)
    difficulty = Column(String(10), nullable=False)
    description = Column(Text, nullable=False)
    points = Column(String(10), nullable=False)
    hints = Column(JSON, nullable=False)
    encrypted_message = Column(Text, nullable=False)
    flag = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    files = Column(JSON, nullable=True)

    def to_dict(self , exclude_flag = False):
        """Convert challenge to dictionary format."""
        return {
            'id': self.id,
            'type': self.type,
            'difficulty': self.difficulty,
            'description': self.description,
            'points': self.points,
            'hints': self.hints,
            'encrypted_message': self.encrypted_message,
            'flag': self.flag,
            'is_active': self.is_active,
            'files': self.files or []
        }

    def __repr__(self):
        return f"<Challenge(id='{self.id}', type='{self.type}', difficulty='{self.difficulty}')>" 
