import os
import sys

# Add the project root directory to the Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from core.database import db_session
from core.challenges.models import Challenge
from sqlalchemy import text

def migrate():
    """Add files column to challenges table."""
    try:
        # Add files column
        db_session.execute(text("""
            ALTER TABLE challenges 
            ADD COLUMN files JSON
        """))
        db_session.commit()
        print("Successfully added files column to challenges table")
    except Exception as e:
        print(f"Error adding files column: {e}")
        db_session.rollback()

if __name__ == "__main__":
    migrate() 