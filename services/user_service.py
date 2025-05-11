# services/user_service.py
from utils.db_utils import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash
from utils.auth_utils import encrypt_private_key, decrypt_private_key, generate_challenge, sign_challenge, verify_signature
import DH
from datetime import datetime, timedelta
from models.session_model import create_session, verify_challenge, delete_challenge
from Crypto.PublicKey import RSA # Added import

def register_user(username, firstname, lastname, password):
    """Register a new user with RSA key pair"""
    try:
        # Step 1: Generate RSA key pair
        private_key_pem = DH.generate_private_key(2048)
        public_key_pem = DH.generate_public_key(private_key_pem)
        
        # Step 2: Create password-protected PEM for download using DH module
        downloadable_encrypted_pem = DH.encrypt_private_key(private_key_pem, password)
        
        # Step 3: Generate additional encryption data for database storage using auth_utils
        # This is a separate encryption for internal use
        db_encrypted_key_data = encrypt_private_key(private_key_pem, password)

        # Hash password for user authentication
        password_hash = generate_password_hash(password)
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if username already exists
        cur.execute('SELECT username FROM users WHERE username = %s', (username,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return {'success': False, 'error': 'Username already exists'}
        
        # Save to database
        cur.execute('''
            INSERT INTO users (
                username, first_name, last_name, password_hash,
                encrypted_private_key, private_key_salt, private_key_iv,
                private_key_tag, public_key
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            username, firstname, lastname, password_hash,
            db_encrypted_key_data['encrypted_key'],
            db_encrypted_key_data['salt'],
            db_encrypted_key_data['iv'],
            db_encrypted_key_data['tag'],
            public_key_pem
        ))
        
        conn.commit()
        cur.close()
        conn.close()

        # Return success with the downloadable PEM
        return {
            'success': True,
            'downloadable_encrypted_pem': downloadable_encrypted_pem,
            'public_key': public_key_pem,
            'private_key': private_key_pem  # For immediate session use
        }
    except Exception as e:
        print(f"Registration error: {str(e)}")
        if 'conn' in locals() and conn is not None:
            conn.rollback()
            cur.close()
            conn.close()
        return {'success': False, 'error': str(e)}

def authenticate_user(username, password, challenge=None):
    """Authenticate a user with password and optionally challenge-response"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if any users exist in the system
        cur.execute('SELECT COUNT(*) FROM users')
        user_count = cur.fetchone()[0]
        
        if user_count == 0:
            return {'success': False, 'error': 'No users registered in the system. Please register first.'}

        # Get user's encrypted private key and other data
        cur.execute('''
            SELECT encrypted_private_key, private_key_salt, private_key_iv,
                   private_key_tag, public_key, password_hash
            FROM users WHERE username = %s
        ''', (username,))        
        result = cur.fetchone()

        if not result:
            return {'success': False, 'error': 'Invalid username or password'}

        encrypted_key, salt, iv, tag, public_key, password_hash = result

        # Verify password
        if not check_password_hash(password_hash, password):
            return {'success': False, 'error': 'Invalid username or password'}

        # Decrypt private key using password
        encrypted_data = {
            'encrypted_key': encrypted_key,
            'salt': salt,
            'iv': iv,
            'tag': tag
        }
        private_key = decrypt_private_key(encrypted_data, password)

        # Generate new challenge if none exists
        if not challenge:
            challenge = generate_challenge()
            # Store challenge in database with expiration
            try:
                create_session(username, challenge)
                print(f"Challenge created successfully for user: {username}")
                # private_key is already decrypted at this point
                return {'success': True, 'challenge': challenge, 'needs_signature': True, 'private_key': private_key}
            except Exception as e:
                print(f"Error creating session: {str(e)}")
                # Try to continue with authentication without challenge-response
                # Return private_key here as well for consistency if auth proceeds
                return {'success': True, 'authenticated': True, 'private_key': private_key}

        # Verify challenge exists and hasn't expired
        if not verify_challenge(username, challenge):
            return {'success': False, 'error': 'Challenge expired or invalid'}

        # Sign the challenge
        signature = sign_challenge(challenge, private_key)

        # Verify signature
        if verify_signature(challenge, signature, public_key):
            # Delete used challenge
            delete_challenge(username, challenge)
            # Return the decrypted private key for session storage
            return {'success': True, 'authenticated': True, 'private_key': private_key}
        else:
            return {'success': False, 'error': 'Invalid signature'}

    except Exception as e:
        print(f"Authentication error: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        if 'cur' in locals() and cur:
            cur.close()
        if 'conn' in locals() and conn:
            conn.close()

def get_user_by_username(username):
    """Get user data by username"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('''
            SELECT username, first_name, last_name, public_key
            FROM users WHERE username = %s
        ''', (username,))
        
        result = cur.fetchone()
        if not result:
            return {'success': False, 'error': 'User not found'}
            
        user = {
            'username': result[0],
            'first_name': result[1],
            'last_name': result[2],
            'public_key': result[3]
        }
        
        cur.close()
        conn.close()
        
        return {'success': True, 'user': user}
    except Exception as e:
        print(f"Error getting user: {str(e)}")
        return {'success': False, 'error': str(e)}

def get_all_users():
    """Get all users"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Include public_key in the selection
        cur.execute('SELECT username, first_name, last_name, public_key FROM users')
        
        users = []
        for row in cur.fetchall():
            users.append({
                'username': row[0],
                'first_name': row[1],
                'last_name': row[2],
                'public_key': row[3]  # Add public key to the user dictionary
            })
        
        cur.close()
        conn.close()
        
        return {'success': True, 'users': users}
    except Exception as e:
        print(f"Error getting users: {str(e)}")
        return {'success': False, 'error': str(e)}

def get_all_users_except(username):
    """Get all users except the specified username"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('SELECT username, first_name, last_name FROM users WHERE username != %s', (username,))
        
        users = []
        for row in cur.fetchall():
            users.append({
                'username': row[0],
                'first_name': row[1],
                'last_name': row[2]
            })
        
        cur.close()
        conn.close()
        
        return {'success': True, 'users': users}
    except Exception as e:
        print(f"Error getting users: {str(e)}")
        return {'success': False, 'error': str(e)}
