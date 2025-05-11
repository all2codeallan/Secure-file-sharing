# services/threshold_service.py
import os
import json
import hashlib
import datetime # Added for timestamp
from werkzeug.utils import secure_filename # Added for secure_filename
from flask import current_app # Added for current_app
from utils.db_utils import get_db_connection
# Assuming get_physical_path_for_peer_file is in file_service, or move to a common util
from services.file_service import get_physical_path_for_peer_file, _generate_timestamped_filename 
from utils.shamir_utils import generate_shares as shamir_generate_shares, \
                               encrypt_share_for_user as shamir_encrypt_share_for_user, \
                               decrypt_share as shamir_decrypt_share, \
                               reconstruct_secret as shamir_reconstruct_secret, \
                               decrypt_with_threshold as shamir_decrypt_with_threshold
# Note: The original `encrypt_with_threshold` from shamir_utils is not directly used by the service's encrypt_file_with_threshold.
# The service function orchestrates the steps.

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64 # For encoding binary data for JSON storage

# _generate_timestamped_filename is imported from file_service, or define locally if preferred:
# def _generate_timestamped_filename(original_filename):
#     """Generates a unique, timestamped filename."""
#     timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
#     secure_name = secure_filename(original_filename)
#     return f"{timestamp}_{secure_name}"

def encrypt_file_with_threshold(file_data, filename, uploader_username, threshold_k, share_holders_list):
    """
    Encrypts a file, generates FEK shares, stores encrypted file content on filesystem,
    and prepares metadata for DB storage.
    Returns raw FEK shares to be individually encrypted by store_encrypted_shares.
    """
    conn = None
    try:
        # Using a simpler file_id generation for now, can be made more robust
        file_id_hash = hashlib.sha256(f"{filename}_{uploader_username}_{os.urandom(8).hex()}".encode()).hexdigest()
        actual_total_shares = len(share_holders_list)

        if actual_total_shares == 0:
             return {'success': False, 'error': "No share holders provided."}
        if threshold_k <= 0 or threshold_k > actual_total_shares:
            return {'success': False, 'error': "Invalid threshold or number of share holders."}


        # 1. Generate FEK (File Encryption Key)
        fek = get_random_bytes(32)  # 256-bit AES key

        # 2. Encrypt the file_data with FEK using AES-GCM
        cipher_aes_gcm = AES.new(fek, AES.MODE_GCM)
        encrypted_content_bytes, tag_bytes = cipher_aes_gcm.encrypt_and_digest(file_data)
        nonce_bytes = cipher_aes_gcm.nonce

        # Store only tag and nonce in DB, ciphertext goes to file system
        crypto_metadata_for_db = {
            'tag': base64.b64encode(tag_bytes).decode('utf-8'),
            'nonce': base64.b64encode(nonce_bytes).decode('utf-8')
        }

        # Calculate hash and size of the original file data
        original_file_hash = hashlib.sha256(file_data).hexdigest()
        original_file_size = len(file_data)

        # Construct peer-specific save path for the encrypted file content
        timestamped_filename = _generate_timestamped_filename(filename)
        physical_filename_on_uploader_disk = timestamped_filename + ".enc"
        
        # Construct user-specific upload folder within the instance's DATA_DIR
        instance_data_dir = current_app.config['DATA_DIR'] # e.g., ./peer_data/A/
        # uploader_username is the logged-in user (e.g., admin1)
        user_specific_upload_folder = os.path.join(instance_data_dir, uploader_username, 'media', 'text-files')
        os.makedirs(user_specific_upload_folder, exist_ok=True)
        
        physical_file_path_on_disk = os.path.join(user_specific_upload_folder, physical_filename_on_uploader_disk)

        with open(physical_file_path_on_disk, 'wb') as f:
            f.write(encrypted_content_bytes)
        
        # Logical path for DB: INSTANCE_ID/UPLOADER_ACCOUNT_USERNAME/ACTUAL_FILENAME.enc
        instance_id = current_app.config['PEER_USERNAME'] # e.g., "userA"
        logical_file_path = f"{instance_id}/{uploader_username}/{physical_filename_on_uploader_disk}"

        # 3. Generate raw shares of the FEK
        raw_fek_shares = shamir_generate_shares(fek, threshold_k, actual_total_shares)

        conn = get_db_connection()
        cur = conn.cursor()
        
        # 4. Store metadata about the threshold-encrypted file
        # Assuming threshold_files table has a 'file_path' column
        cur.execute('''
            INSERT INTO threshold_files (
                file_id, filename, file_path, encrypted_data, file_hash, file_size, 
                threshold, total_shares, uploaded_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (
            file_id_hash, filename, logical_file_path, json.dumps(crypto_metadata_for_db),
            original_file_hash, original_file_size,
            threshold_k, actual_total_shares, uploader_username
        ))
        db_table_id = cur.fetchone()[0]
        conn.commit()
        
        return {
            'success': True,
            'file_id': file_id_hash, # Use the generated file_id_hash
            'db_table_id': db_table_id,
            'raw_fek_shares': raw_fek_shares,
            'stored_path': logical_file_path
        }
    except Exception as e:
        current_app.logger.error(f"Service Threshold encryption error: {str(e)}")
        if conn:
            conn.rollback()
        return {'success': False, 'error': str(e)}
    finally:
        if conn:
            if 'cur' in locals() and cur: cur.close()
            conn.close()

def store_encrypted_shares(file_id_hash, raw_fek_shares, share_holders_list):
    """Store encrypted shares for users"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        holder_keys = {}
        for holder in share_holders_list:
            cur.execute('SELECT public_key FROM users WHERE username = %s', (holder,))
            result = cur.fetchone()
            if result and result[0]:
                holder_keys[holder] = result[0]
            else:
                # Handle case where a public key might be missing for a selected share_holder
                raise ValueError(f"Public key not found for share holder: {holder}")

        # Encrypt and store each raw FEK share
        # raw_fek_shares is a list of (index, share_value_int)
        # shamir_encrypt_share_for_user expects share (which is (index, value_int)) and public_key_str
        for i, share_tuple in enumerate(raw_fek_shares):
            holder_username = share_holders_list[i] # Assumes share_holders_list is in same order as raw_fek_shares generation
            share_index_from_tuple = share_tuple[0] # This is the x-coordinate (1, 2, ...)
            
            if holder_username in holder_keys:
                encrypted_share_for_user = shamir_encrypt_share_for_user(share_tuple, holder_keys[holder_username])
                
                cur.execute('''
                    INSERT INTO file_shares (
                        file_id, share_index, share_holder, encrypted_share
                    )
                    VALUES (%s, %s, %s, %s)
                ''', (
                    file_id_hash, # Corrected variable name to match function parameter
                    share_index_from_tuple, # Use the actual share index from the tuple
                    holder_username, 
                    json.dumps(encrypted_share_for_user) # shamir_encrypt_share_for_user returns string
                ))
            # else: Error already raised if key not found

        conn.commit()
        cur.close()
        conn.close()
        return {'success': True}
    except Exception as e:
        print(f"Error storing shares: {str(e)}")
        return {'success': False, 'error': str(e)}

def get_user_threshold_files(username):
    """Get threshold files where the user has a share"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('''
            -- Select files where the user is a share_holder
            -- Also get the user's own access status and the total accessed shares for that file
            SELECT 
                tf.id, 
                tf.file_id, 
                tf.filename, 
                tf.uploaded_by, 
                tf.uploaded_at, 
                tf.threshold, 
                tf.total_shares,
                BOOL_OR(ts_user.has_accessed) as current_user_has_accessed, 
                SUM(CASE WHEN ts_all.has_accessed THEN 1 ELSE 0 END) as total_accessed_shares
            FROM threshold_files tf
            JOIN file_shares ts_user ON tf.file_id = ts_user.file_id AND ts_user.share_holder = %s 
            LEFT JOIN file_shares ts_all ON tf.file_id = ts_all.file_id 
            WHERE tf.is_deleted = FALSE -- Added this condition to filter out soft-deleted files
            GROUP BY tf.id, tf.file_id, tf.filename, tf.uploaded_by, tf.uploaded_at, tf.threshold, tf.total_shares
            ORDER BY tf.uploaded_at DESC
        ''', (username,))
        
        
        main_file_records = cur.fetchall()
        cur.close() # Close main cursor after fetching initial file list

        # Optimize N+1 query for pooled shares count
        # Step 1: Get all relevant file_id_hashes from the initial query
        file_ids_for_pooling_check = [record[1] for record in main_file_records]
        
        pooled_counts_map = {}
        if file_ids_for_pooling_check:
            # Step 2: Fetch all pooled share counts for these file_ids in one query
            # Need a new cursor for this, or ensure the previous one is fully processed if reusing.
            # For safety, using a new scope for this cursor.
            with conn.cursor() as cur_pooled_agg:
                now_utc_for_pool = datetime.datetime.utcnow()
                # Use a tuple for the IN clause
                placeholders = ','.join(['%s'] * len(file_ids_for_pooling_check))
                sql_pooled_counts = f"""
                    SELECT file_id_hash, COUNT(*) as num_pooled
                    FROM pooled_decrypted_shares
                    WHERE file_id_hash IN ({placeholders}) AND expires_at > %s
                    GROUP BY file_id_hash
                """
                # Arguments: list of file_ids followed by now_utc_for_pool
                cur_pooled_agg.execute(sql_pooled_counts, tuple(file_ids_for_pooling_check) + (now_utc_for_pool,))
                for rec in cur_pooled_agg.fetchall():
                    pooled_counts_map[rec[0]] = rec[1]

        files = []
        for row in main_file_records:
            file_id_hash = row[1]
            num_currently_pooled = pooled_counts_map.get(file_id_hash, 0) # Get from map, default to 0

            files.append({
                'id': row[0], 
                'file_id': file_id_hash, 
                'filename': row[2],
                'uploaded_by': row[3],
                'uploaded_at': row[4],
                'threshold': row[5], 
                'total_shares': row[6], 
                'current_user_has_accessed': bool(row[7]), 
                'total_accessed_shares': int(row[8]), 
                'num_pooled_shares': num_currently_pooled
            })
        
        # Main connection cursor was closed earlier, conn itself will be closed in finally
        conn.close()
        return {'success': True, 'files': files}
    except Exception as e:
        print(f"Error retrieving threshold files: {str(e)}")
        return {'success': False, 'error': str(e)}

def get_user_share(file_id, username, password): # Password here is user's main password
    """Get and decrypt a user's share for a threshold file"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('''
            SELECT encrypted_share, share_index
            FROM file_shares
            WHERE file_id = %s AND share_holder = %s
        ''', (file_id, username)) # file_id here is file_id_hash
        
        result = cur.fetchone()
        if not result:
            cur.close()
            conn.close()
            return {'success': False, 'error': 'Share not found'}
        
        encrypted_share_json_str, share_index = result
        encrypted_share_for_user = json.loads(encrypted_share_json_str)
        
        cur.execute('''
            SELECT encrypted_private_key, private_key_salt, private_key_iv, private_key_tag
            FROM users WHERE username = %s
        ''', (username,))
        key_data = cur.fetchone()

        if not key_data:
            cur.close()
            conn.close()
            raise ValueError("User not found for private key decryption.")
        
        encrypted_key_bundle_for_db = {
            'encrypted_key': key_data[0], 'salt': key_data[1],
            'iv': key_data[2], 'tag': key_data[3]
        }
        from utils.auth_utils import decrypt_private_key # Local import
        decrypted_user_private_key_pem = decrypt_private_key(encrypted_key_bundle_for_db, password)
        
        raw_fek_share_tuple = shamir_decrypt_share(encrypted_share_for_user, decrypted_user_private_key_pem)

        cur.execute("""
            UPDATE file_shares
            SET has_accessed = TRUE, last_accessed = NOW()
            WHERE file_id = %s AND share_holder = %s
        """, (file_id, username))
        conn.commit()
        
        return {
            'success': True,
            'share': raw_fek_share_tuple,
            'share_index': share_index
        }
    except ValueError as ve:
        current_app.logger.error(f"ValueError retrieving share for {username}, file {file_id}: {str(ve)}")
        return {'success': False, 'error': f"Failed to process share: {str(ve)}"}
    except Exception as e:
        current_app.logger.error(f"Generic error retrieving share for {username}, file {file_id}: {str(e)}")
        return {'success': False, 'error': f"An unexpected server error occurred: {str(e)}"}
    finally:
        if cur: cur.close()
        if conn: conn.close()

def decrypt_threshold_file(file_id_hash):
    """Decrypt a threshold file using shares from the server-side pool."""
    conn = None
    cur = None
    try:
        pooled_shares_result = get_pooled_shares(file_id_hash)
        if not pooled_shares_result['success']:
            return {'success': False, 'error': pooled_shares_result.get('error', 'Failed to retrieve pooled shares.')}
        
        share_tuples_for_reconstruction = pooled_shares_result['shares']

        conn = get_db_connection()
        cur = conn.cursor()
        
        # Fetch file_path and uploader_username along with other metadata
        cur.execute('''
            SELECT tf.id, tf.file_path, tf.encrypted_data, tf.threshold, tf.filename, tf.uploaded_by
            FROM threshold_files tf
            WHERE tf.file_id = %s
        ''', (file_id_hash,))
        
        file_meta = cur.fetchone()
        if not file_meta:
            return {'success': False, 'error': 'File metadata not found'}
        
        db_table_id, logical_file_path, crypto_metadata_json, threshold_k, original_filename, uploader_username = file_meta
        crypto_metadata = json.loads(crypto_metadata_json) # Should contain 'tag' and 'nonce'
        
        if len(share_tuples_for_reconstruction) < threshold_k:
            return {'success': False, 'error': f'Not enough shares in the pool. Need {threshold_k}, have {len(share_tuples_for_reconstruction)}.'}

        # Reconstruct the FEK
        fek_int = shamir_reconstruct_secret(share_tuples_for_reconstruction)
        fek_bytes = fek_int.to_bytes(32, byteorder='big')

        # Get physical path to the encrypted file content
        # logical_file_path is "instance_id/uploader_account/actual_file.enc"
        # uploader_username from DB is the uploader_account
        try:
            path_parts = logical_file_path.split('/', 2)
            if len(path_parts) != 3:
                current_app.logger.error(f"Invalid logical_file_path format for threshold file: {logical_file_path}")
                return {'success': False, 'error': "Invalid file path format."}
            hosting_instance_id = path_parts[0]
            uploader_account_in_path = path_parts[1] # Should match uploader_username from DB
            actual_filename = path_parts[2]

            if uploader_account_in_path != uploader_username: # uploader_username is db_uploader_username
                 current_app.logger.warning(f"Mismatch in threshold file uploader username from DB ({uploader_username}) and path ({uploader_account_in_path}) for logical path {logical_file_path}")
                 # Trusting the path structure for now.
        except Exception as e:
            current_app.logger.error(f"Error parsing logical_file_path '{logical_file_path}' for threshold file: {str(e)}")
            return {'success': False, 'error': "Error processing file path."}
            
        physical_file_path = get_physical_path_for_peer_file(hosting_instance_id, uploader_account_in_path, actual_filename)

        if not physical_file_path or not os.path.exists(physical_file_path):
            current_app.logger.error(f"Simulated physical file for threshold not found at: {physical_file_path} (derived from logical path {logical_file_path})")
            return {'success': False, 'error': "Encrypted file content not found on custodian peer (simulation error)."}

        with open(physical_file_path, 'rb') as f:
            ciphertext_bytes = f.read()

        # Decrypt the file content using reconstructed FEK, and tag/nonce from DB
        cipher_aes_gcm = AES.new(
            fek_bytes, 
            AES.MODE_GCM, 
            nonce=base64.b64decode(crypto_metadata['nonce'])
        )
        decrypted_content = cipher_aes_gcm.decrypt_and_verify(
            ciphertext_bytes, # Ciphertext read from file
            base64.b64decode(crypto_metadata['tag'])
        )
        
        cur.execute("UPDATE threshold_files SET download_count = download_count + 1, last_downloaded_at = NOW() WHERE id = %s", (db_table_id,))
        
        actual_contributors = []
        if share_tuples_for_reconstruction:
            # Simplified contributor fetching for now; assumes pool query is sufficient
            cur.execute("""
                SELECT DISTINCT share_holder 
                FROM pooled_decrypted_shares 
                WHERE file_id_hash = %s AND expires_at > NOW() 
            """, (file_id_hash,))
            contributors_records = cur.fetchall()
            actual_contributors = [rec[0] for rec in contributors_records]

        conn.commit()
        
        return {
            'success': True,
            'data': decrypted_content,
            'filename': original_filename,
            'contributors': actual_contributors 
        }
    except Exception as e:
        current_app.logger.error(f"Error decrypting threshold file {file_id_hash}: {str(e)}")
        if conn: conn.rollback()
        return {'success': False, 'error': str(e)}
    finally:
        if cur: cur.close()
        if conn: conn.close()

def get_available_share_holders(current_user_username):
    """Get list of users available as share holders"""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT username FROM users WHERE username != %s', (current_user_username,)) # Corrected variable
        users = [row[0] for row in cur.fetchall()]
        return {'success': True, 'users': users}
    except Exception as e:
        current_app.logger.error(f"Error getting share holders: {str(e)}") # Use logger
        return {'success': False, 'error': str(e)}
    finally:
        if cur: cur.close() # Add finally block
        if conn: conn.close()

# --- Service functions for Pooled Decrypted Shares ---
# datetime is already imported at the top

# Expiry time for pooled shares (e.g., 1 hour)
POOLED_SHARE_EXPIRY_SECONDS = 3600 

def pool_decrypted_share(file_id_hash, share_holder, share_index, share_value_int):
    """
    Stores a decrypted FEK share into the temporary pool.
    share_value_int is the integer y-coordinate of the share.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=POOLED_SHARE_EXPIRY_SECONDS)
        
        # Upsert: Insert or update if the share for this user/file already exists (e.g., they re-contribute)
        cur.execute("""
            INSERT INTO pooled_decrypted_shares (file_id_hash, share_holder, share_index, share_value, expires_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (file_id_hash, share_holder) DO UPDATE SET
                share_index = EXCLUDED.share_index,
                share_value = EXCLUDED.share_value,
                expires_at = EXCLUDED.expires_at,
                created_at = NOW()
            -- Removed the second ON CONFLICT clause. The (file_id_hash, share_index) UNIQUE constraint violation
            -- will now raise an IntegrityError if it occurs, which should be handled by the calling route if necessary.
            -- This situation (same index for same file by different users) should ideally be prevented by logic.
        """, (file_id_hash, share_holder, share_index, str(share_value_int), expires_at))
        
        conn.commit()
        # Removed SERVICE_DEBUG print
        cur.close()
        conn.close()
        return {'success': True}
    except Exception as e:
        print(f"ERROR pooling share for file {file_id_hash}, holder {share_holder}: {str(e)}")
        return {'success': False, 'error': f"Database error during share pooling: {str(e)}"}

def get_pooled_shares(file_id_hash):
    """
    Retrieves all valid (non-expired) decrypted FEK shares for a given file.
    Returns a list of (share_index, share_value_int) tuples.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        now_utc = datetime.datetime.utcnow()
        
        cur.execute("""
            SELECT share_index, share_value 
            FROM pooled_decrypted_shares
            WHERE file_id_hash = %s AND expires_at > %s
        """, (file_id_hash, now_utc))
        
        fetched_records = cur.fetchall()
        
        pooled_shares_tuples = []
        for record in fetched_records:
            share_index, share_value_str = record
            pooled_shares_tuples.append((int(share_index), int(share_value_str)))
            
        cur.close()
        conn.close()
        # Removed SERVICE_DEBUG print
        return {'success': True, 'shares': pooled_shares_tuples}
    except Exception as e:
        print(f"ERROR getting pooled shares for file {file_id_hash}: {str(e)}")
        return {'success': False, 'error': f"Database error retrieving pooled shares: {str(e)}", 'shares': []}

def clear_pooled_shares(file_id_hash):
    """Deletes all pooled shares for a given file_id_hash."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM pooled_decrypted_shares WHERE file_id_hash = %s", (file_id_hash,))
        conn.commit()
        cur.close()
        conn.close()
        return {'success': True}
    except Exception as e:
        print(f"Error clearing pooled shares for file {file_id_hash}: {str(e)}")
        return {'success': False, 'error': str(e)}

def cleanup_expired_pooled_shares():
    """Periodically called to delete expired shares from the pool."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        now_utc = datetime.datetime.utcnow()
        
        cur.execute("DELETE FROM pooled_decrypted_shares WHERE expires_at <= %s", (now_utc,))
        deleted_count = cur.rowcount
        conn.commit()
        
        cur.close()
        conn.close()
        if deleted_count > 0:
            print(f"Cleaned up {deleted_count} expired pooled shares.")
        return {'success': True, 'deleted_count': deleted_count}
    except Exception as e:
        print(f"Error cleaning up expired pooled shares: {str(e)}")
        return {'success': False, 'error': str(e)}

def soft_delete_threshold_file(file_id_hash, current_username):
    """
    Marks a threshold file as deleted if the current user is the uploader.
    Also clears any associated shares from the pool.
    """
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # First, verify the current user is the uploader of this file
        cur.execute("SELECT filename, uploaded_by FROM threshold_files WHERE file_id = %s AND is_deleted = FALSE", (file_id_hash,))
        file_record = cur.fetchone()

        if not file_record:
            return {'success': False, 'error': 'File not found or already deleted.'}
        
        filename, uploader = file_record
        if uploader != current_username:
            return {'success': False, 'error': 'You are not authorized to delete this file.'}

        # Mark the file as deleted in threshold_files table
        cur.execute("""
            UPDATE threshold_files
            SET is_deleted = TRUE, deleted_at = NOW()
            WHERE file_id = %s
        """, (file_id_hash,))

        # Clear any shares for this file from the pool
        # This uses file_id_hash which matches the column name in pooled_decrypted_shares
        clear_pooled_shares_result = clear_pooled_shares(file_id_hash) 
        if not clear_pooled_shares_result['success']:
            # Log this, but don't necessarily fail the whole delete operation if the main record was marked.
            # However, for consistency, it might be better to roll back if pool clearing fails.
            # For now, just log and proceed.
            print(f"Warning: Failed to clear pooled shares for soft-deleted file {file_id_hash}: {clear_pooled_shares_result.get('error')}")
            # If this is critical, you might raise an exception here to trigger a rollback if in a transaction.

        conn.commit()
        return {'success': True, 'filename': filename}

    except Exception as e:
        if conn:
            conn.rollback() # Rollback on any error during the process
        print(f"Error soft-deleting threshold file {file_id_hash}: {str(e)}")
        return {'success': False, 'error': f"Database error during file deletion: {str(e)}"}
    finally:
        if cur: cur.close()
        if conn: conn.close()
