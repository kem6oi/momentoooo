import re

def add_challenge_to_app():
    """Add a new challenge to the app.py file's startup code"""
    try:
        # Read the app.py file
        with open('app.py', 'r') as file:
            app_content = file.read()
        
        # Find the section where challenges are initialized
        pattern = r'# --- Initialize default challenges here, to make sure they exists at startup ---\s+try:\s+(.*?)\s+except ValueError as e:\s+print\(f"Challenge creation error: \{e\}"\)'
        match = re.search(pattern, app_content, re.DOTALL)
        
        if match:
            # Extract the existing challenge creation code
            existing_code = match.group(1)
            
            # Create new challenge creation code
            new_challenge_code = '    challenge_manager.create_challenge("test_challenge_1", "aes", "easy")\n'
            
            # Add the new challenge creation code to the existing code
            updated_code = existing_code + new_challenge_code
            
            # Replace the existing code with the updated code
            updated_content = app_content.replace(existing_code, updated_code)
            
            # Write the updated content back to the app.py file
            with open('app.py', 'w') as file:
                file.write(updated_content)
            
            print("Successfully added new challenge to app.py")
        else:
            print("Could not find the challenge initialization section in app.py")
        
    except Exception as e:
        print(f"Error adding challenge to app.py: {str(e)}")

if __name__ == '__main__':
    add_challenge_to_app() 