from dotenv import load_dotenv
import os
import secrets

# Load environment variables from a .env file
load_dotenv()

# Retrieve secret keys from environment variables or use fallback values
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))  # Get from environment or generate

# Master Admin User (for setting up challenges initially)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "password") # Change this!

# Rate Limiting Configuration
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 10

# RSA Key Size
RSA_KEY_SIZE = 2048

# Hashing Algorithm
HASH_ALGORITHM = "sha256"

# Flag Format
FLAG_FORMAT = "FLAG{.*}"  # Basic regex for flag