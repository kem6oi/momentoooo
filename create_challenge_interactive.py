"""
This script creates a challenge directly in the Python interpreter.
Run this script with the Python interpreter to create a challenge.
"""

from core.shared import challenge_manager

def create_challenge_interactive():
    """Interactive script to create a new challenge"""
    print("\n=== Challenge Creation ===")
    
    # Get challenge ID
    challenge_id = input("Enter challenge ID: ").strip()
    if challenge_id in challenge_manager.get_all_challenges():
        print(f"Error: Challenge with ID '{challenge_id}' already exists!")
        return
    
    # Get challenge type
    print("\nAvailable challenge types:")
    print("1. AES")
    print("2. Vigenere")
    print("3. RSA")
    type_choice = input("Select challenge type (1-3): ").strip()
    
    challenge_type = {
        "1": "aes",
        "2": "vigenere",
        "3": "rsa"
    }.get(type_choice)
    
    if not challenge_type:
        print("Invalid challenge type!")
        return
    
    # Get difficulty
    print("\nAvailable difficulties:")
    print("1. Easy")
    print("2. Medium")
    print("3. Hard")
    diff_choice = input("Select difficulty (1-3): ").strip()
    
    difficulty = {
        "1": "easy",
        "2": "medium",
        "3": "hard"
    }.get(diff_choice)
    
    if not difficulty:
        print("Invalid difficulty!")
        return
    
    try:
        # Create the challenge
        challenge = challenge_manager.create_challenge(challenge_id, challenge_type, difficulty)
        print(f"\nChallenge '{challenge_id}' created successfully!")
        print(f"Type: {challenge_type}")
        print(f"Difficulty: {difficulty}")
        print(f"Points: {challenge.get('points', 'N/A')}")
    except Exception as e:
        print(f"Error creating challenge: {str(e)}")

if __name__ == "__main__":
    create_challenge_interactive() 