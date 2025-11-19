import hmac
import hashlib
from config.security import HASH_ALGORITHM

def generate_hmac(key, message):
    """Generates an HMAC for the given message using the provided key."""
    key = key.encode('utf-8')  # Ensure key is bytes
    message = message.encode('utf-8')
    hashed = hmac.new(key, message, getattr(hashlib, HASH_ALGORITHM)) #getattr to get hash func
    return hashed.hexdigest()

def verify_hmac(key, message, hmac_value):
    """Verifies the HMAC for the given message and HMAC value."""
    expected_hmac = generate_hmac(key, message)
    return hmac.compare_digest(expected_hmac, hmac_value) #compare_digest for security