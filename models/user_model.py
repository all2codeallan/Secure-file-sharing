# models/user_model.py
from utils.db_utils import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash
from utils.auth_utils import encrypt_private_key
import DH

def get_user_by_username(username):
    """Get user data by username"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute('''
        SELECT encrypted_private_key, private_key_salt, private_key_iv,
               private_key_tag, public_key, password_hash
        FROM users WHERE username = %s
    ''', (username,))
    
    result = cur.fetchone()
    cur.close()
    conn.close()
    
    return result

def create_user(username, firstname, lastname, password):
    """Create a new user with RSA key pair"""
    # Generate RSA key pair
    private_key = DH.generate_private_key(2048)
    public_key = DH.generate_public_key(private_key)

    # Encrypt private key with password
    encrypted_key_data = encrypt_private_key(private_key, password)

    # Hash the password
    password_hash = generate_password_hash(password)
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Save to database
    cur.execute('''
        INSERT INTO users (
            username, first_name, last_name, password_hash,
            encrypted_private_key, private_key_salt, private_key_iv,
            private_key_tag, public_key
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    ''', (
        username, firstname, lastname, password_hash,
        encrypted_key_data['encrypted_key'],
        encrypted_key_data['salt'],
        encrypted_key_data['iv'],
        encrypted_key_data['tag'],
        public_key
    ))
    
    conn.commit()
    cur.close()
    conn.close()
    
    # Return the key pair for saving
    return private_key, public_key

def get_all_users_except(username):
    """Get all users except the specified username"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute('SELECT username FROM users WHERE username != %s', (username,))
    users = [row[0] for row in cur.fetchall()]
    
    cur.close()
    conn.close()
    
    return users

def get_all_users():
    """Get all users"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute('SELECT username FROM users')
    users = [row[0] for row in cur.fetchall()]
    
    cur.close()
    conn.close()
    
    return users