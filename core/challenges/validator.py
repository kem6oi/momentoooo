import re
# Use typing for clarity, though not strictly necessary if challenge type isn't enforced
from typing import Dict, Any, Union
# Assuming Challenge model is imported where needed
from core.challenges.models import Challenge
from core.crypto.ciphers import HashFunction # Only HashFunction seems used here

class ChallengeValidator:
    @staticmethod
    def validate_flag_format(flag: str) -> bool:
        """Validate the format of a flag (basic check)."""
        # Simple validation - ensures flag is not empty or None
        return bool(flag and len(flag.strip()) > 0)

    @staticmethod
    def validate_solution(challenge: Challenge, submitted_flag: str) -> bool:
        """
        Validates a submitted flag against the challenge's expected flag.
        This is the primary method called by ChallengeManager.

        Args:
            challenge (Challenge): The SQLAlchemy Challenge model object.
            submitted_flag (str): The flag submitted by the user.

        Returns:
            bool: True if the flag is correct, False otherwise.
        """
        if not challenge or not submitted_flag:
             print("[Validator Debug] Invalid challenge object or submitted flag.")
             return False # Can't validate if challenge or flag missing

        if not ChallengeValidator.validate_flag_format(submitted_flag):
            print(f"[Validator Debug] Submitted flag format invalid: '{submitted_flag}'")
            return False

        # --- FIX: Access the attribute directly from the Challenge OBJECT ---
        # Old way (expected dict): expected_flag = challenge.get('flag', '')
        # New way (using object):
        expected_flag = challenge.flag
        # --- End Fix ---

        if not expected_flag:
             print(f"[Validator Debug] Challenge object (ID: {challenge.id}) has no expected flag stored.")
             return False # Cannot validate if the expected flag is missing

        # --- Simple comparison (Default) ---
        # Consider trimming whitespace and case-insensitivity based on requirements
        is_correct = (submitted_flag.strip() == expected_flag.strip())
        # Example case-insensitive:
        # is_correct = (submitted_flag.strip().lower() == expected_flag.strip().lower())

        print(f"[Validator Debug] Submitted: '{submitted_flag}', Expected: '{expected_flag}', Correct: {is_correct}")

        # --- Optional: Dispatch to type-specific validation if needed ---
        # If different challenge types required more than direct flag comparison,
        # you could dispatch here based on challenge.type.
        # Example:
        # if challenge.type == 'hash':
        #     return ChallengeValidator._validate_hash_internal(challenge, submitted_flag)
        # elif challenge.type == 'layered_crypto': # Hypothetical
        #     return ChallengeValidator._validate_layered_crypto(challenge, submitted_flag)
        # else:
        #     # Default to direct comparison for other types (AES, Vigenere, Web, Binary etc.)
        #     return is_correct
        # --- End Optional Dispatch ---

        # For now, stick to direct comparison as per the original logic's intent
        return is_correct


    # --- NOTE: The methods below seem unused based on the current call flow ---
    # The ChallengeManager calls validate_solution directly. These specific
    # validators would only be called if validate_solution dispatched to them.
    # They also expect 'challenge' to be a dictionary, which needs fixing
    # if you intend to use them.
    # If keeping them, they should accept the Challenge object and access attributes.

    @staticmethod
    def _validate_hash_internal(challenge: Challenge, submitted_flag: str) -> bool:
        """Internal helper if validating hash specifically."""
        # Access attributes from the Challenge object
        expected_hash = challenge.encrypted_message # Assuming hash is stored here
        hash_type = challenge.hash_type # Assuming hash_type is stored on the model

        if not expected_hash or not hash_type:
             print(f"[Validator Debug] Hash challenge (ID: {challenge.id}) missing hash value or type.")
             return False

        try:
            # Use the imported HashFunction or standard hashlib
            # submitted_hash = getattr(HashFunction, hash_type)(submitted_flag.encode()).hex() # If using custom class
            import hashlib
            hasher = getattr(hashlib, hash_type)()
            hasher.update(submitted_flag.strip().encode('utf-8'))
            submitted_hash = hasher.hexdigest()

            print(f"[Validator Debug - Hash] Submitted Hash: '{submitted_hash}', Expected Hash: '{expected_hash}'")
            return submitted_hash == expected_hash
        except AttributeError:
             print(f"[Validator Debug - Hash] Invalid hash type specified: {hash_type}")
             return False
        except Exception as e:
             print(f"[Validator Debug - Hash] Error during hashing: {e}")
             return False


    # --- Keeping other methods commented out unless needed and refactored ---
    # @staticmethod
    # def validate_xor_solution(challenge: Dict[str, Any], submitted_flag: str) -> bool:
    #     # ... needs refactoring to use Challenge object ...
    #     pass

    # @staticmethod
    # def validate_des_solution(challenge: Dict[str, Any], submitted_flag: str) -> bool:
    #     # ... needs refactoring to use Challenge object ...
    #     pass

    # @staticmethod
    # def validate_rc4_solution(challenge: Dict[str, Any], submitted_flag: str) -> bool:
    #     # ... needs refactoring to use Challenge object ...
    #     pass

    # @staticmethod
    # def validate_blowfish_solution(challenge: Dict[str, Any], submitted_flag: str) -> bool:
    #     # ... needs refactoring to use Challenge object ...
    #     pass

    # @staticmethod
    # def validate_web_solution(challenge: Dict[str, Any], submitted_flag: str) -> bool:
    #     # ... needs refactoring to use Challenge object ...
    #     pass

    # @staticmethod
    # def validate_binary_solution(challenge: Dict[str, Any], submitted_flag: str) -> bool:
    #     # ... needs refactoring to use Challenge object ...
    #     pass

    # @staticmethod
    # def validate_forensics_solution(challenge: Dict[str, Any], submitted_flag: str) -> bool:
    #     # ... needs refactoring to use Challenge object ...
    #     pass
