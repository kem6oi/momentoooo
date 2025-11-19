from flask import session
import secrets

def create_session(user_id, username):
    """Creates a session for the user."""
    session['user_id'] = user_id
    session['username'] = username
    session['session_token'] = secrets.token_hex(16) # Session token
    session['is_authenticated'] = True

def destroy_session():
    """Destroys the current session."""
    session.clear()

def is_authenticated():
    """Checks if the user is authenticated."""
    return session.get('is_authenticated', False)

def get_current_user():
    """Returns the current user's information from the session."""
    if is_authenticated():
        return {
            'user_id': session['user_id'],
            'username': session['username'],
            'session_token': session['session_token']
        }
    return None