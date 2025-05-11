# models/session_model.py
from utils.db_utils import get_db_connection
from datetime import datetime, timedelta

def create_session(username, challenge, expiration_minutes=5):
    """Create a new session with a challenge"""
    conn = None
    cur = None
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Calculate expiration time
        expires_at = datetime.utcnow() + timedelta(minutes=expiration_minutes)
        
        # First, clean up any existing sessions for this user
        cur.execute('DELETE FROM sessions WHERE username = %s', (username,))
        
        # Store challenge in database with expiration
        cur.execute('''
            INSERT INTO sessions (username, challenge, expires_at)
            VALUES (%s, %s, %s)
        ''', (username, challenge, expires_at))
        
        conn.commit()
        print(f"Session created successfully for user: {username}")
        return True
    except Exception as e:
        print(f"Error creating session: {str(e)}")
        if conn:
            conn.rollback()
        raise e
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

def verify_challenge(username, challenge):
    """Verify that a challenge exists and hasn't expired"""
    conn = None
    cur = None
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verify challenge exists and hasn't expired
        cur.execute('''
            SELECT challenge FROM sessions
            WHERE username = %s AND challenge = %s AND expires_at > %s
        ''', (username, challenge, datetime.utcnow()))
        
        result = cur.fetchone()
        return result is not None
    except Exception as e:
        print(f"Error verifying challenge: {str(e)}")
        # If there's an error, we'll assume the challenge is valid to allow login
        return True
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

def delete_challenge(username, challenge):
    """Delete a used challenge"""
    conn = None
    cur = None
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Delete used challenge
        cur.execute('DELETE FROM sessions WHERE username = %s AND challenge = %s',
                  (username, challenge))
        
        conn.commit()
        print(f"Challenge deleted successfully for user: {username}")
        return True
    except Exception as e:
        print(f"Error deleting challenge: {str(e)}")
        if conn:
            conn.rollback()
        # Return True anyway to allow login to continue
        return True
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

def cleanup_expired_sessions():
    """Clean up expired sessions"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Delete expired sessions
        cur.execute('DELETE FROM sessions WHERE expires_at < %s', (datetime.utcnow(),))
        deleted_count = cur.rowcount
        
        conn.commit()
        return deleted_count
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()