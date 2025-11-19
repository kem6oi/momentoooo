import os
import sys

# Add the project root directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import db_session, engine
from core.marketplace.models import Buyer
from sqlalchemy import text

def upgrade():
    """Add solved_challenges column to buyers table"""
    # SQLite doesn't support ALTER TABLE ADD COLUMN with DEFAULT value
    # So we need to create a new table, copy data, drop old table, and rename new table
    db_session.execute(text("""
        CREATE TABLE buyers_new (
            id INTEGER PRIMARY KEY,
            user_id VARCHAR(80) NOT NULL,
            display_name VARCHAR(100) NOT NULL,
            stripe_customer_id VARCHAR(100) UNIQUE,
            is_verified INTEGER DEFAULT 0,
            solved_challenges VARCHAR(500) DEFAULT '[]',
            created_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(username)
        )
    """))
    
    # Copy data from old table to new table
    db_session.execute(text("""
        INSERT INTO buyers_new (id, user_id, display_name, stripe_customer_id, is_verified, created_at)
        SELECT id, user_id, display_name, stripe_customer_id, is_verified, created_at
        FROM buyers
    """))
    
    # Drop old table and rename new table
    db_session.execute(text("DROP TABLE buyers"))
    db_session.execute(text("ALTER TABLE buyers_new RENAME TO buyers"))
    
    db_session.commit()

def downgrade():
    """Remove solved_challenges column from buyers table"""
    # Similar process to upgrade but in reverse
    db_session.execute(text("""
        CREATE TABLE buyers_old (
            id INTEGER PRIMARY KEY,
            user_id VARCHAR(80) NOT NULL,
            display_name VARCHAR(100) NOT NULL,
            stripe_customer_id VARCHAR(100) UNIQUE,
            is_verified INTEGER DEFAULT 0,
            created_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(username)
        )
    """))
    
    # Copy data from current table to old table structure
    db_session.execute(text("""
        INSERT INTO buyers_old (id, user_id, display_name, stripe_customer_id, is_verified, created_at)
        SELECT id, user_id, display_name, stripe_customer_id, is_verified, created_at
        FROM buyers
    """))
    
    # Drop current table and rename old table
    db_session.execute(text("DROP TABLE buyers"))
    db_session.execute(text("ALTER TABLE buyers_old RENAME TO buyers"))
    
    db_session.commit()

if __name__ == "__main__":
    upgrade() 