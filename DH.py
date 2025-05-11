import hashlib
import ssl
import binascii
import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

def generate_private_key(length=2048):
    """Generate an RSA key pair and return the PEM-formatted private key"""
    try:
        # Generate new RSA key pair
        key = RSA.generate(length)
        # Export private key in PEM format, unencrypted
        private_key = key.export_key(format='PEM').decode('utf-8')
        return private_key
    except Exception as e:
        print(f"Error generating private key: {str(e)}")
        raise

def generate_public_key(private_key_pem):
    """Extract public key from private key and return in PEM format"""
    try:
        # Import the private key from PEM
        private_key = RSA.import_key(private_key_pem)
        # Extract and export public key in PEM format
        public_key = private_key.publickey().export_key(format='PEM').decode('utf-8')
        return public_key
    except Exception as e:
        print(f"Error generating public key: {str(e)}")
        raise

def encrypt_private_key(private_key_pem, password):
    """Encrypt a PEM private key with a password"""
    try:
        # Import the key
        key = RSA.import_key(private_key_pem)
        # Export with password protection using PKCS#8
        encrypted_key = key.export_key(format='PEM', 
                                     passphrase=password,
                                     pkcs=8,
                                     protection="scryptAndAES128-CBC")
        return encrypted_key.decode('utf-8')
    except Exception as e:
        print(f"Error encrypting private key: {str(e)}")
        raise

def decrypt_private_key(encrypted_key_pem, password):
    """Decrypt a password-protected PEM private key"""
    try:
        # Import and decrypt the key
        key = RSA.import_key(encrypted_key_pem, passphrase=password)
        # Re-export as unencrypted PEM for immediate use
        decrypted_key = key.export_key(format='PEM').decode('utf-8')
        return decrypted_key
    except Exception as e:
        print(f"Error decrypting private key: {str(e)}")
        raise
