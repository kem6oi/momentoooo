import secrets
import string
import re
from config.security import FLAG_FORMAT

class ChallengeGenerator:

    def generate_flag(self, challenge_id):
        """Generates a flag based on the challenge ID."""
        random_string = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        flag = f"FLAG{{{challenge_id}-{random_string}}}"
        return flag

    def generate_random_data(self, length=16):
        """Generates random data for challenges."""
        return secrets.token_hex(length)

    def validate_flag_format(self, flag):
        """Validates that the flag matches the expected format."""
        pattern = re.compile(FLAG_FORMAT)  # Compile the regex for efficiency
        return bool(pattern.match(flag))