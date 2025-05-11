from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def generate_challenge():
    """Generate a random challenge string"""
    return base64.b64encode(os.urandom(32)).decode('utf-8')

def sign_challenge(challenge, private_key_str, key_password=None):
    """Sign a challenge with the user's private key"""
    try:
        # Import the private key
        if key_password:
            private_key = RSA.import_key(private_key_str, passphrase=key_password)
        else:
            private_key = RSA.import_key(private_key_str)
        
        # Create the signature
        challenge_bytes = challenge.encode('utf-8')
        h = SHA256.new(challenge_bytes)
        signature = pkcs1_15.new(private_key).sign(h)
        
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        print(f"Error signing challenge: {str(e)}")
        raise

def verify_signature(challenge, signature, public_key_str):
    """Verify a signature using the user's public key"""
    try:
        # Decode the signature
        signature = base64.b64decode(signature)
        
        # Import the public key
        public_key = RSA.import_key(public_key_str)
        
        # Verify the signature
        challenge_bytes = challenge.encode('utf-8')
        h = SHA256.new(challenge_bytes)
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    except Exception as e:
        print(f"Error verifying signature: {str(e)}")
        return False

def encrypt_private_key(private_key_str, password):
    """Encrypt a private key with a password"""
    try:
        # Generate a random salt
        salt = get_random_bytes(16)
        
        # Derive a key from the password
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, 32)
        
        # Encrypt the private key
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(private_key_str.encode('utf-8'))
        
        # Return the encrypted key data
        return {
            'encrypted_key': base64.b64encode(ciphertext).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(cipher.nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }
    except Exception as e:
        print(f"Error encrypting private key: {str(e)}")
        raise

def decrypt_private_key(encrypted_data, password):
    """Decrypt a private key with a password"""
    try:
        # Decode the encrypted data
        ciphertext = base64.b64decode(encrypted_data['encrypted_key'])
        salt = base64.b64decode(encrypted_data['salt'])
        nonce = base64.b64decode(encrypted_data['iv'])
        tag = base64.b64decode(encrypted_data['tag'])
        
        # Derive the key from the password
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, 32)
        
        # Decrypt the private key
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        private_key_str = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        
        return private_key_str
    except Exception as e:
        print(f"Error decrypting private key: {str(e)}")
        raise

# Add missing import
import hashlib