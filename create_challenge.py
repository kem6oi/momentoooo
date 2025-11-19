from core.database import db_session
from core.challenges.challenge_manager import ChallengeManager

def create_challenge():
    """Create a sample challenge directly using ChallengeManager"""
    try:
        # Create challenge using challenge manager
        challenge_manager = ChallengeManager()
        
        # Create a challenge with the required parameters
        challenge = challenge_manager.create_challenge(
            challenge_id='test_challenge_1',
            challenge_type='aes',
            difficulty='easy'
        )
        
        # Print challenge details
        print(f"Successfully created challenge: {challenge['id']}")
        print(f"Type: {challenge['type']}")
        print(f"Difficulty: {challenge.get('difficulty', 'easy')}")
        print(f"Description: {challenge['description']}")
        print(f"Encrypted message: {challenge['encrypted_message']}")
        
        # If you want to add this challenge to the database, you would need to
        # create a Challenge model instance and add it to the session
        # This depends on how challenges are stored in your database
        
    except Exception as e:
        print(f"Error creating challenge: {str(e)}")
        db_session.rollback()

if __name__ == '__main__':
    create_challenge() 