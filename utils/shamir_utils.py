"""Enhanced Shamir's Secret Sharing implementation for secure file sharing.
This version addresses issues in the original implementation and improves robustness.
"""

import random
import base64
from functools import reduce
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import json
import tempfile
import os
import uuid
import time


# Finite field arithmetic over prime field GF(p)
# Using a safe prime for cryptographic use
PRIME = 2**256 - 189

# Create a secure temporary directory for share data
TEMP_SHARE_DIR = tempfile.mkdtemp(prefix="shamir_shares_")
# Set a cleanup interval (in seconds)
TEMP_FILE_MAX_AGE = 3600  # 1 hour

def mod_inverse(x, p=PRIME):
    """Calculate the modular multiplicative inverse of x in field GF(p)"""
    return pow(x, p - 2, p)  # Using Fermat's Little Theorem

def evaluate_polynomial(poly, x, p=PRIME):
    """Evaluate a polynomial at point x in field GF(p) using Horner's method"""
    result = 0
    for coef in reversed(poly):
        result = (result * x + coef) % p
    return result

def generate_random_polynomial(degree, secret, p=PRIME):
    """Generate a random polynomial of specified degree with constant term = secret"""
    poly = [secret]
    for _ in range(degree):
        poly.append(random.randint(1, p - 1))
    return poly

def generate_shares(secret, threshold, num_shares, p=PRIME):
    """Generate Shamir's secret shares"""
    if threshold > num_shares:
        raise ValueError("Threshold cannot be greater than the number of shares")
    
    # Convert secret to integer if it's bytes
    if isinstance(secret, bytes):
        secret_int = int.from_bytes(secret, byteorder='big')
    else:
        secret_int = secret
    
    # Generate a random polynomial with constant term = secret
    poly = generate_random_polynomial(threshold - 1, secret_int, p)
    
    # Generate shares as (x, f(x)) pairs
    shares = []
    for i in range(1, num_shares + 1):
        shares.append((i, evaluate_polynomial(poly, i, p)))
    
    return shares

def lagrange_interpolation(shares, x, p=PRIME):
    """Compute the Lagrange interpolation at point x given the shares"""
    if not shares:
        raise ValueError("No shares provided")
    
    k = len(shares)
    result = 0
    
    for i in range(k):
        xi, yi = shares[i]
        numerator = 1
        denominator = 1
        
        for j in range(k):
            if i == j:
                continue
            xj, _ = shares[j]
            
            numerator = (numerator * (x - xj)) % p
            denominator = (denominator * (xi - xj)) % p
        
        # Compute the Lagrange basis polynomial evaluated at x
        lagrange_basis = (yi * numerator * mod_inverse(denominator, p)) % p
        result = (result + lagrange_basis) % p
    
    return result

def reconstruct_secret(shares, p=PRIME):
    """Reconstruct the secret from shares using Lagrange interpolation"""
    return lagrange_interpolation(shares, 0, p)

def encrypt_with_threshold(file_data, threshold, recipients, recipient_public_keys):
    """Encrypt a file using threshold encryption"""
    try:
        # logger.info(f"Starting threshold encryption for {len(recipients)} recipients with threshold {threshold}")
        
        # Generate a random AES key
        aes_key = get_random_bytes(32)  # 256-bit key
        # logger.debug(f"Generated AES key of length {len(aes_key)} bytes")
        
        # Encrypt the file with the AES key
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(file_data)
        nonce = cipher.nonce
        
        # logger.debug(f"File encrypted: ciphertext length {len(ciphertext)}, tag length {len(tag)}")
        
        # Generate shares for the AES key
        shares = generate_shares(aes_key, threshold, len(recipients))
        # logger.debug(f"Generated {len(shares)} shares for the AES key")
        
        # Encrypt each share for its recipient
        encrypted_shares = {}
        for i, recipient in enumerate(recipients):
            share = shares[i]
            public_key = recipient_public_keys[recipient]
            
            # Encrypt the share for this recipient
            encrypted_share = encrypt_share_for_user(share, public_key)
            encrypted_shares[recipient] = encrypted_share
        
        # logger.info(f"Successfully encrypted shares for all {len(recipients)} recipients")
        
        # Return the encrypted data
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'threshold': threshold,
            'total_shares': len(recipients),
            'encrypted_shares': encrypted_shares
        }
    except Exception as e:
        # logger.error(f"Error in threshold encryption: {str(e)}")
        print(f"Error in threshold encryption: {str(e)}") # Keep print for now if essential
        raise

def encrypt_share_for_user(share, public_key_str):
    """Encrypt a share for a specific user using their public key"""
    try:
        # Import the public key
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        
        public_key = RSA.import_key(public_key_str)
        
        # Convert share to bytes
        share_data = json.dumps(share).encode('utf-8')
        
        # Create a cipher object using the public key
        cipher = PKCS1_OAEP.new(public_key)
        
        # Encrypt the share
        encrypted_share = cipher.encrypt(share_data)
        
        return base64.b64encode(encrypted_share).decode('utf-8')
    except Exception as e:
        # logger.error(f"Error encrypting share: {str(e)}")
        print(f"Error encrypting share: {str(e)}") # Keep print for now
        raise

def decrypt_share(encrypted_share_str, private_key_str):
    """Decrypt a share using the user's private key"""
    try:
        # Import the private key
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        
        # Decode the encrypted share
        encrypted_share = base64.b64decode(encrypted_share_str)
        
        # Import the private key
        private_key = RSA.import_key(private_key_str)
        
        # Create a cipher object using the private key
        cipher = PKCS1_OAEP.new(private_key)
        
        # Decrypt the share
        share_data = cipher.decrypt(encrypted_share)
        
        # Convert bytes back to share tuple
        share = json.loads(share_data.decode('utf-8'))
        
        return (int(share[0]), int(share[1]))
    except Exception as e:
        # logger.error(f"Error decrypting share: {str(e)}")
        print(f"Error decrypting share: {str(e)}") # Keep print for now
        raise

def store_shares_for_decryption(file_id, shares):
    """Store shares temporarily for later decryption"""
    try:
        # Create a unique identifier for this set of shares
        session_id = str(uuid.uuid4())
        
        # Create a file to store the shares
        share_file = os.path.join(TEMP_SHARE_DIR, f"{session_id}.json")
        
        # Store the shares with expiration time
        share_data = {
            'file_id': file_id,
            'shares': shares,
            'created_at': time.time(),
            'expires_at': time.time() + TEMP_FILE_MAX_AGE
        }
        
        with open(share_file, 'w') as f:
            json.dump(share_data, f)
        
        # logger.info(f"Stored {len(shares)} shares for file {file_id} with session ID {session_id}")
        
        return session_id
    except Exception as e:
        # logger.error(f"Error storing shares: {str(e)}")
        print(f"Error storing shares: {str(e)}") # Keep print for now
        raise

def retrieve_shares_for_decryption(session_id):
    """Retrieve shares for decryption"""
    try:
        # Get the share file
        share_file = os.path.join(TEMP_SHARE_DIR, f"{session_id}.json")
        
        if not os.path.exists(share_file):
            # logger.error(f"Share file not found for session {session_id}")
            print(f"Share file not found for session {session_id}") # Keep print for now
            return None
        
        # Read the share data
        with open(share_file, 'r') as f:
            share_data = json.load(f)
        
        # Check if the shares have expired
        if time.time() > share_data['expires_at']:
            # logger.warning(f"Shares for session {session_id} have expired")
            print(f"Shares for session {session_id} have expired") # Keep print for now
            os.remove(share_file)
            return None
        
        # Convert share strings back to tuples
        shares = []
        for share in share_data['shares']:
            shares.append((int(share[0]), int(share[1])))
        
        # logger.info(f"Retrieved {len(shares)} shares for file {share_data['file_id']}")
        
        # Delete the share file after retrieval
        os.remove(share_file)
        
        return {
            'file_id': share_data['file_id'],
            'shares': shares
        }
    except Exception as e:
        # logger.error(f"Error retrieving shares: {str(e)}")
        print(f"Error retrieving shares: {str(e)}") # Keep print for now
        return None

def decrypt_with_threshold(encrypted_data, shares):
    """Decrypt a file using threshold decryption"""
    try:
        # logger.info(f"Starting threshold decryption with {len(shares)} shares")
        
        # Reconstruct the AES key from the shares
        aes_key = reconstruct_secret(shares)
        aes_key_bytes = aes_key.to_bytes(32, byteorder='big')
        # logger.debug(f"Reconstructed AES key of length {len(aes_key_bytes)} bytes")
        
        # Decode the encrypted data
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        
        # Decrypt the file with the AES key
        cipher = AES.new(aes_key_bytes, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        # logger.info(f"Successfully decrypted file of length {len(decrypted_data)} bytes")
        
        return decrypted_data
    except Exception as e:
        # logger.error(f"Error in threshold decryption: {str(e)}")
        print(f"Error in threshold decryption: {str(e)}") # Keep print for now
        raise

def cleanup_temp_files():
    """Clean up expired temporary files"""
    try:
        count = 0
        now = time.time()
        
        # Iterate through all files in the temporary directory
        for filename in os.listdir(TEMP_SHARE_DIR):
            if not filename.endswith('.json'):
                continue
            
            file_path = os.path.join(TEMP_SHARE_DIR, filename)
            
            try:
                # Read the file to check expiration
                with open(file_path, 'r') as f:
                    share_data = json.load(f)
                
                # Check if the file has expired
                if now > share_data.get('expires_at', 0):
                    os.remove(file_path)
                    count += 1
                    # logger.debug(f"Removed expired share file {filename}")
            except Exception as e:
                # logger.warning(f"Error processing file {filename}: {str(e)}")
                print(f"Warning: Error processing temp share file {filename}: {str(e)}") # Keep print for now
                # If we can't read the file, it might be corrupted, so remove it
                try:
                    os.remove(file_path)
                    count += 1
                except:
                    pass # Ignore error if removal fails
        
        # logger.info(f"Cleaned up {count} expired temporary files")
        if count > 0:
            print(f"Cleaned up {count} expired temporary share files.")
    except Exception as e:
        # logger.error(f"Error cleaning up temporary files: {str(e)}")
        print(f"Error cleaning up temporary share files: {str(e)}") # Keep print for now
