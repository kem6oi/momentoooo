from core.database import db_session, engine
from sqlalchemy import text

def migrate():
    """Add hard_challenges_completed column to sellers table"""
    try:
        # Add the new column
        with engine.connect() as conn:
            conn.execute(text("""
                ALTER TABLE sellers 
                ADD COLUMN hard_challenges_completed INTEGER DEFAULT 0
            """))
            conn.commit()
        print("Successfully added hard_challenges_completed column to sellers table")
    except Exception as e:
        print(f"Error during migration: {str(e)}")
        db_session.rollback()

if __name__ == '__main__':
    migrate() 