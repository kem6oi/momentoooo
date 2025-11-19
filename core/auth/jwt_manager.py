import jwt
from config.security import SECRET_KEY
import datetime

class JWTManager:
    def __init__(self, secret_key=SECRET_KEY, algorithm="HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def encode(self, payload, expiry=datetime.timedelta(hours=5)):  # Increased expiry to 5 hours
        """Encodes a payload into a JWT."""
        payload['exp'] = datetime.datetime.utcnow() + expiry
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode(self, token):
        """Decodes a JWT and returns the payload, or None if invalid."""
        try:
            decoded_payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            print(f"✅ Decoded Token: {decoded_payload}")  # Debugging output
            return decoded_payload
        except jwt.ExpiredSignatureError:
            print("❌ JWT has expired")
            return None
        except jwt.InvalidTokenError as e:
            print(f"❌ JWT is invalid: {e}")
            return None
