from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import binascii  # Added for base64 error handling
import os
import json
import ast  # Added for ast.literal_eval

def generate_rsa_key_pair(key_size=2048):
    """
    Generate a new RSA key pair.

    Args:
        key_size (int): Size of the key in bits, default is 2048

    Returns:
        tuple: (private_key_pem, public_key_pem) where both are strings in PEM format
    """
    # Generate a new RSA key
    key = RSA.generate(key_size)

    # Export private key in PEM format
    private_key_pem = key.export_key().decode('utf-8')

    # Export public key in PEM format
    public_key_pem = key.publickey().export_key().decode('utf-8')

    return private_key_pem, public_key_pem

def generate_aes_key():
    """Generate a random AES key"""
    return get_random_bytes(32)  # 256-bit key

def encrypt_file_aes(file_data, aes_key):
    """Encrypt file data using AES"""
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return (cipher.nonce, tag, ciphertext)

def decrypt_file_aes(encrypted_data, aes_key, nonce, tag):
    """Decrypt file data using AES"""
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(encrypted_data, tag)
    return data

def encrypt_aes_key_with_public_key(aes_key, public_key_str):
    """Encrypt the AES key using recipient's public key"""
    try:
        # Import the public key
        public_key = RSA.import_key(public_key_str)
        
        # Create a cipher object using the public key
        cipher = PKCS1_OAEP.new(public_key)
        
        # Encrypt the AES key
        encrypted_key = cipher.encrypt(aes_key)
        
        return base64.b64encode(encrypted_key).decode('utf-8')
    except Exception as e:
        print(f"Error encrypting AES key: {str(e)}")
        raise

def decrypt_aes_key_with_private_key(encrypted_key_str, private_key_str):
    """Decrypt the AES key using recipient's private key"""
    try:
        # Decode the encrypted key
        encrypted_key = base64.b64decode(encrypted_key_str)
        
        # Import the private key
        private_key = RSA.import_key(private_key_str)
        
        # Create a cipher object using the private key
        cipher = PKCS1_OAEP.new(private_key)
        
        # Decrypt the AES key
        aes_key = cipher.decrypt(encrypted_key)
        
        return aes_key
    except Exception as e:
        print(f"Error decrypting AES key: {str(e)}")
        raise

def encrypt_file_for_user(file_data, recipient_public_key):
    """Encrypt a file for a specific user"""
    try:
        # Generate a random AES key
        aes_key = generate_aes_key()
        
        # Encrypt the file with the AES key
        nonce, tag, ciphertext = encrypt_file_aes(file_data, aes_key)
        
        # Encrypt the AES key with the recipient's public key
        encrypted_key = encrypt_aes_key_with_public_key(aes_key, recipient_public_key)
        
        # Return the encrypted data
        return {
            'encrypted_key': encrypted_key,
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    except Exception as e:
        print(f"Error encrypting file: {str(e)}")
        raise

def decrypt_file_for_user(encrypted_data, private_key_str):
    """Decrypt a file using the user's private key"""
    try:
        # Decode the encrypted data
        encrypted_key = encrypted_data['encrypted_key']
        nonce = base64.b64decode(encrypted_data['nonce'])
        tag = base64.b64decode(encrypted_data['tag'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        # Decrypt the AES key with the private key
        aes_key = decrypt_aes_key_with_private_key(encrypted_key, private_key_str)
        
        # Decrypt the file with the AES key
        decrypted_data = decrypt_file_aes(ciphertext, aes_key, nonce, tag)
        
        return decrypted_data
    except Exception as e:
        print(f"Error decrypting file: {str(e)}")
        raise