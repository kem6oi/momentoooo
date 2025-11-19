from core.shared import challenge_manager

def add_challenge(challenge_id, challenge_type, difficulty):
    """Add a new challenge to the database"""
    print(f"\nAdding challenge: {challenge_id}")
    print(f"Type: {challenge_type}")
    print(f"Difficulty: {difficulty}")
    
    # Check if challenge already exists
    if challenge_id in challenge_manager.get_all_challenges():
        print(f"Error: Challenge with ID '{challenge_id}' already exists!")
        return False
    
    try:
        # Create the challenge
        challenge = challenge_manager.create_challenge(challenge_id, challenge_type, difficulty)
        print(f"\nChallenge '{challenge_id}' created successfully!")
        print(f"Type: {challenge_type}")
        print(f"Difficulty: {difficulty}")
        print(f"Points: {challenge.get('points', 'N/A')}")
        return True
    except Exception as e:
        print(f"Error creating challenge: {str(e)}")
        return False

if __name__ == "__main__":
    # Example usage
    add_challenge("test_challenge_1", "aes", "easy")
    add_challenge("test_challenge_2", "vigenere", "medium")
    add_challenge("test_challenge_3", "rsa", "hard") 