# services/file_service.py
import os
import json
import hashlib
import datetime
import base64 # Added for encoding ciphertext for decryption function
from werkzeug.utils import secure_filename
from flask import current_app
from utils.db_utils import get_db_connection
from utils.crypto_utils import encrypt_file_for_user, decrypt_file_for_user
# PEER_INSTANCES_CONFIG will be accessed from current_app.config

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png', 'zip', 'rar'}

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def _generate_timestamped_filename(original_filename):
    """Generates a unique, timestamped filename."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
    secure_name = secure_filename(original_filename)
    return f"{timestamp}_{secure_name}"

def upload_file(file_data, filename, recipient_username, uploader_username):
    """Upload and encrypt a file for a recipient, storing ciphertext on filesystem."""
    conn = None
    try:
        # Get recipient's public key
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT public_key FROM users WHERE username = %s', (recipient_username,))
        recipient_public_key_pem = cur.fetchone()
        if not recipient_public_key_pem:
            return {'success': False, 'error': f"Recipient {recipient_username} not found or has no public key."}
        recipient_public_key_pem = recipient_public_key_pem[0]

        # Encrypt the file data. Result is a dict with ciphertext and crypto metadata.
        # {'encrypted_aes_key': ..., 'nonce': ..., 'tag': ..., 'ciphertext': ...}
        # encrypt_file_for_user returns ciphertext as a base64 encoded string.
        encryption_result = encrypt_file_for_user(file_data, recipient_public_key_pem)
        
        base64_encoded_ciphertext_str = encryption_result.pop('ciphertext') # This is a base64 string
        ciphertext_bytes_to_write = base64.b64decode(base64_encoded_ciphertext_str) # Decode to bytes for writing

        crypto_metadata_json = json.dumps(encryption_result) # Store the rest (enc_key, nonce, tag) in DB

        # Generate file hash for integrity check (hash of original data)
        file_hash = hashlib.sha256(file_data).hexdigest()
        file_size = len(file_data) # Size of original data
        mime_type = 'application/octet-stream' # Basic MIME type

        # Construct peer-specific save path for the ciphertext
        timestamped_filename = _generate_timestamped_filename(filename)
        # This is the actual filename on the uploader's disk
        physical_filename_on_uploader_disk = timestamped_filename + ".enc"
        
        # Construct user-specific upload folder within the instance's DATA_DIR
        # DATA_DIR is like ./peer_data/A (for PeerA instance)
        # uploader_username is the logged-in user (e.g., admin1)
        instance_data_dir = current_app.config['DATA_DIR']
        user_specific_upload_folder = os.path.join(instance_data_dir, uploader_username, 'media', 'text-files')
        os.makedirs(user_specific_upload_folder, exist_ok=True)
        
        physical_file_path_on_disk = os.path.join(user_specific_upload_folder, physical_filename_on_uploader_disk)

        with open(physical_file_path_on_disk, 'wb') as f:
            f.write(ciphertext_bytes_to_write) # Write the actual bytes

        # Logical path for DB: INSTANCE_ID/UPLOADER_ACCOUNT_USERNAME/ACTUAL_FILENAME.enc
        # INSTANCE_ID is current_app.config['PEER_USERNAME'] (e.g., "userA")
        # UPLOADER_ACCOUNT_USERNAME is the 'uploader_username' param (e.g., "admin1")
        instance_id = current_app.config['PEER_USERNAME']
        logical_file_path = f"{instance_id}/{uploader_username}/{physical_filename_on_uploader_disk}"

        cur.execute('''
            INSERT INTO files (
                filename, file_path, encrypted_data, file_hash,
                file_size, mime_type, uploaded_by, recipient
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (
            filename,  # Original filename for display
            logical_file_path,  # Logical path including uploader username
            crypto_metadata_json, # JSON of encrypted_aes_key, nonce, tag
            file_hash,
            file_size,
            mime_type,
            uploader_username,
            recipient_username
        ))
        file_id = cur.fetchone()[0]
        conn.commit()

        return {'success': True, 'file_id': file_id, 'stored_path': logical_file_path}
    except Exception as e:
        current_app.logger.error(f"Upload error: {str(e)}")
        if conn:
            conn.rollback()
        return {'success': False, 'error': str(e)}
    finally:
        if conn:
            cur.close()
            conn.close()

def get_user_files(username):
    """Get files shared with the specified user"""
    conn = None
    cur = None # Initialize cur
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Get files shared with the user. encrypted_data now holds crypto metadata.
        # file_path holds the logical path.
        cur.execute('''
            SELECT f.id, f.filename, f.uploaded_by, f.uploaded_at, f.file_path, f.encrypted_data
            FROM files f
            WHERE f.recipient = %s
            ORDER BY f.uploaded_at DESC
        ''', (username,))
        files = []
        for row in cur.fetchall():
            files.append({
                'id': row[0],
                'filename': row[1],       # Original display filename
                'uploaded_by': row[2],
                'uploaded_at': row[3],
                'logical_path': row[4],   # Logical path e.g. "uploader_user/timestamp_file.enc"
                'crypto_metadata': row[5] # JSON of enc_aes_key, nonce, tag
            })
        return {'success': True, 'files': files}
    except Exception as e:
        current_app.logger.error(f"Error retrieving files for {username}: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        if cur: # Check if cur was initialized
            cur.close()
        if conn:
            conn.close()

def get_physical_path_for_peer_file(hosting_instance_id, uploader_account_username, actual_filename):
    """
    (SIMULATION ONLY) Constructs the physical file path to an uploader's file,
    hosted on a specific peer instance.
    This is a temporary helper for LOCALHOST_ONLY + SINGLE_LAPTOP simulation.
    Example: hosting_instance_id='userA', uploader_account_username='admin1', actual_filename='file.enc'
    """
    if not (current_app.config.get('SIMULATION_MODE') == 'SINGLE_LAPTOP' and \
            current_app.config.get('OPERATING_MODE') == 'LOCALHOST_ONLY'):
        current_app.logger.warning(
            "get_physical_path_for_peer_file called outside of SINGLE_LAPTOP/LOCALHOST_ONLY simulation mode."
        )
        return None

    fixed_peer_data_base_path = './peer_data/' # Base directory for all peer instances' data
    
    peer_configs = current_app.config.get('PEER_INSTANCES_CONFIG')
    if not peer_configs:
        current_app.logger.error("PEER_INSTANCES_CONFIG not found in app.config.")
        return None
        
    hosting_instance_data_dir_suffix = None
    for peer_info in peer_configs:
        # 'username' in PEER_INSTANCES_CONFIG is the instance identifier (e.g., "userA")
        if peer_info['username'] == hosting_instance_id:
            hosting_instance_data_dir_suffix = peer_info['data_dir_suffix']
            break
    
    if not hosting_instance_data_dir_suffix:
        current_app.logger.error(f"Could not find data_dir_suffix for hosting instance: {hosting_instance_id}")
        return None

    # Path: ./peer_data/<instance_suffix>/<uploader_account_username>/media/text-files/<actual_filename>
    physical_path = os.path.join(
        fixed_peer_data_base_path,
        hosting_instance_data_dir_suffix,
        uploader_account_username,
        'media',
        'text-files',
        actual_filename
    )
    return physical_path

def get_file_for_download(file_id, recipient_username, decrypted_private_key_pem):
    """Get and decrypt a file for download using the user's decrypted private key."""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute('''
            SELECT filename, file_path, encrypted_data, uploaded_by
            FROM files
            WHERE id = %s AND recipient = %s
        ''', (file_id, recipient_username))
        result = cur.fetchone()

        if not result:
            return {'success': False, 'error': "File not found or you don't have permission to access it."}

        original_filename, logical_path_from_db, crypto_metadata_json, db_uploader_username = result
        # db_uploader_username is the account that uploaded the file (e.g., "admin1")
        # logical_path_from_db is like "instance_id/uploader_account/actual_file.enc" (e.g., "userA/admin1/file.enc")
        crypto_metadata = json.loads(crypto_metadata_json)

        try:
            path_parts = logical_path_from_db.split('/', 2)
            if len(path_parts) != 3:
                current_app.logger.error(f"Invalid logical_file_path format: {logical_path_from_db}")
                return {'success': False, 'error': "Invalid file path format."}
            hosting_instance_id = path_parts[0]
            uploader_account_in_path = path_parts[1] # This should match db_uploader_username
            actual_filename = path_parts[2]
            
            # Sanity check:
            if uploader_account_in_path != db_uploader_username:
                current_app.logger.warning(f"Mismatch in uploader username from DB ({db_uploader_username}) and path ({uploader_account_in_path}) for logical path {logical_path_from_db}")
                # Proceeding with uploader_account_in_path for path construction as it's part of the physical structure.
        except Exception as e:
            current_app.logger.error(f"Error parsing logical_file_path '{logical_path_from_db}': {str(e)}")
            return {'success': False, 'error': "Error processing file path."}

        physical_file_path = get_physical_path_for_peer_file(hosting_instance_id, uploader_account_in_path, actual_filename)
        
        if not physical_file_path or not os.path.exists(physical_file_path):
            current_app.logger.error(f"Simulated physical file not found at: {physical_file_path} (derived from logical path: {logical_path_from_db})")
            return {'success': False, 'error': "File content not found on custodian peer (simulation error)."}

        with open(physical_file_path, 'rb') as f:
            ciphertext_from_file_bytes = f.read()

        # Combine ciphertext with other crypto metadata for decryption
        # decrypt_file_for_user expects 'ciphertext' to be a base64 encoded string
        full_encrypted_package = {
            **crypto_metadata, # nonce and tag are already base64 strings from DB
            'ciphertext': base64.b64encode(ciphertext_from_file_bytes).decode('utf-8')
        }
        
        decrypted_file_content = decrypt_file_for_user(full_encrypted_package, decrypted_private_key_pem)
        
        return {
            'success': True,
            'filename': original_filename, # Original filename for download
            'data': decrypted_file_content
        }
    except Exception as e:
        current_app.logger.error(f"Error downloading file {file_id}: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        if conn:
            cur.close()
            conn.close()

def get_available_recipients(current_user_username):
    """Get list of users available as recipients"""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT username FROM users WHERE username != %s', (current_user_username,))
        users = [row[0] for row in cur.fetchall()]
        return {'success': True, 'users': users}
    except Exception as e:
        current_app.logger.error(f"Error getting recipients: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        if conn:
            cur.close()
            conn.close()
