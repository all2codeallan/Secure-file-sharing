# Secure File Sharing Encryption System Documentation

This document provides a detailed overview of the encryption system implementation across different components of the application.

## 1. Core Components and Responsibilities

### crypto_utils.py
Core cryptographic operations handler responsible for:

#### Key Management Functions
- `generate_rsa_key_pair(key_size=2048)`: Generates RSA key pairs for asymmetric encryption
- `generate_aes_key()`: Creates 256-bit AES keys for symmetric encryption
- `get_key_fingerprint(key_str)`: Generates fingerprints for key verification

#### Encryption/Decryption Operations
- `encrypt_file_aes(file_data, aes_key)`: File encryption using AES-GCM mode
- `decrypt_file_aes(encrypted_data, aes_key, nonce, tag)`: File decryption with AES-GCM
- `encrypt_with_public_key(data, public_key_str)`: RSA public key encryption
- `decrypt_with_private_key(encrypted_data_str, private_key_str)`: RSA private key decryption

### shamir_utils.py
Implements Shamir's Secret Sharing (SSS) scheme with the following key functions:

#### Secret Sharing Implementation
- `split_secret_into_chunks(secret_bytes, chunk_size=30)`: Splits large secrets into manageable chunks
- `generate_shares(secret, threshold, total_shares)`: Creates SSS shares
- `generate_polynomial(secret_int, degree, p)`: Generates random polynomials for SSS
- `evaluate_polynomial(poly, x, p)`: Evaluates polynomials at specific points

#### Share Management
- `encrypt_share_for_user(share, recipient_public_key, crypto_utils)`: Encrypts individual shares
- `decrypt_share(encrypted_share, private_key, crypto_utils)`: Decrypts individual shares
- `reconstruct_secret(shares, is_chunked=False, chunk_count=0)`: Reconstructs the original secret
- `reconstruct_secret_from_chunks(chunk_shares, chunk_count, chunk_size=30)`: Handles chunked secret reconstruction

### auth_utils.py
Manages authentication and key protection:

#### Key Protection Functions
- `encrypt_private_key(private_key_str, password)`: Secures private keys with password protection
- `decrypt_private_key(encrypted_key_data, password)`: Recovers protected private keys
- `verify_signature(public_key, signature, challenge)`: Validates digital signatures

### app.py
Handles web routes and file operations:

#### File Operations
- `threshold_upload_file_fixed()`: Manages secure file uploads with threshold encryption
- `threshold_file_decrypt(file_id)`: Handles threshold-based file decryption
- `threshold_file_retrieve(file_id)`: Manages secure file retrieval

## 2. Encryption Flow Implementation

### File Upload Process
1. File Selection and Parameter Setting:
```python
# In app.py: threshold_upload_file_fixed()
file = request.files['file']
threshold = int(request.form.get('threshold', 2))
recipients = request.form.getlist('recipients')
```

2. File Encryption Key (FEK) Generation:
```python
# In shamir_utils.py: encrypt_with_threshold()
fek = get_random_bytes(32)  # 256-bit AES key
cipher = AES.new(fek, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(file_data)
```

3. Share Generation and Distribution:
```python
# In shamir_utils.py: generate_shares()
shares = generate_shares(fek, threshold, total_shares)
formatted_shares = [
    (x, base64.b64encode(y.to_bytes((y.bit_length() + 7) // 8, byteorder='big')).decode('utf-8'))
    for x, y in shares
]
```

### Share Encryption Process
1. Share Preparation:
```python
# In shamir_utils.py: encrypt_share_for_user()
share_metadata = {
    'value': share_value_str,
    'public_key_fingerprint': public_key_fingerprint,
    'format_version': '1.0'
}
```

2. Individual Share Encryption:
```python
# In crypto_utils.py: encrypt_with_public_key()
encrypted_share = crypto_utils.encrypt_with_public_key(json.dumps(share_metadata), recipient_public_key)
```

### Decryption Flow
1. Share Collection and Verification:
```python
# In app.py: threshold_file_decrypt()
decrypted_shares = []
for share in accessed_shares:
    decrypted_share = decrypt_share(encrypted_share_obj, private_key, crypto_utils)
    decrypted_shares.append(decrypted_share)
```

2. Secret Reconstruction:
```python
# In shamir_utils.py: reconstruct_secret()
secret_int = _lagrange_interpolation(normalized_shares, PRIME)
secret_bytes = secret_int.to_bytes(bytes_needed, byteorder='big')
```

3. File Decryption:
```python
# In crypto_utils.py: decrypt_file_aes()
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
```

## 3. Security Features

### Key Management
- RSA-2048 for asymmetric encryption
- AES-256 in GCM mode for symmetric encryption
- Secure key generation using cryptographically secure random numbers
- Key fingerprinting for verification
- Password-protected private keys

### Share Protection
- Threshold-based secret sharing (k-of-n scheme)
- Share format versioning
- Public key fingerprint verification
- Share validation and normalization
- Support for large secrets through chunking

### Data Security
- AES-GCM mode providing authenticated encryption
- Secure temporary file handling
- Comprehensive error handling and logging
- Database-level encryption for stored shares

## 4. Best Practices Implementation

### Error Handling
- Comprehensive validation of all cryptographic operations
- Secure error messages that don't leak sensitive information
- Proper cleanup of sensitive data in memory

### Key Validation
```python
# In crypto_utils.py: verify_key_pair()
try:
    private_key = RSA.import_key(private_key_str)
    public_key = RSA.import_key(public_key_str)
    derived_public_key = private_key.publickey()
    return public_key.n == derived_public_key.n
except Exception:
    return False
```

### Share Management
- Automatic cleanup of temporary files
- Secure share storage in database
- Version control for share formats
- Support for share recovery and verification

This implementation provides a robust and secure system for sharing encrypted files using threshold cryptography, ensuring that files can only be accessed when the required number of participants provide their shares while maintaining strong cryptographic properties through modern algorithms and proper key management practices.