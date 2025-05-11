import psycopg2
import json
from config.db_config import DB_CONFIG

def init_db():
    """
    Initialize the database schema for the secure file sharing application.
    This is the only file that should define the database structure.
    """
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # Drop existing tables if they exist
    cur.execute('DROP TABLE IF EXISTS file_access_logs CASCADE')
    cur.execute('DROP TABLE IF EXISTS file_shares CASCADE')
    cur.execute('DROP TABLE IF EXISTS threshold_files CASCADE')
    cur.execute('DROP TABLE IF EXISTS files CASCADE')
    cur.execute('DROP TABLE IF EXISTS sessions CASCADE')
    cur.execute('DROP TABLE IF EXISTS users CASCADE')
    cur.execute('DROP TABLE IF EXISTS pooled_decrypted_shares CASCADE') # Added drop for the new table
    
    # Create users table with encrypted keys and authentication fields
    cur.execute('''
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            first_name VARCHAR(50) NOT NULL,
            last_name VARCHAR(50) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            encrypted_private_key TEXT NOT NULL,
            private_key_salt TEXT NOT NULL,
            private_key_iv TEXT NOT NULL,
            private_key_tag TEXT NOT NULL,
            public_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Create sessions table for login challenges
    cur.execute('''
        CREATE TABLE sessions (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) REFERENCES users(username),
            challenge TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create files table with encrypted data and better tracking
    cur.execute('''
        CREATE TABLE files (
            id SERIAL PRIMARY KEY,
            filename VARCHAR(255) NOT NULL,
            file_path VARCHAR(255) NOT NULL,
            encrypted_data TEXT NOT NULL,
            file_hash VARCHAR(64) NOT NULL,
            file_size BIGINT NOT NULL,
            mime_type VARCHAR(127),
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            uploaded_by VARCHAR(50) REFERENCES users(username),
            recipient VARCHAR(50) REFERENCES users(username),
            is_deleted BOOLEAN DEFAULT FALSE,
            deleted_at TIMESTAMP,
            download_count INTEGER DEFAULT 0,
            last_downloaded_at TIMESTAMP
        )
    ''')
    
    # Create threshold files table for implementing Shamir's Secret Sharing
    # Note: encrypted_data field can contain a JSON with the structure:
    # {
    #    "encrypted_data": "<base64 encoded encrypted data>",
    #    "is_chunked": true/false,
    #    "chunk_count": <integer>
    # }
    cur.execute('''
        CREATE TABLE threshold_files (
            id SERIAL PRIMARY KEY, -- Auto-incrementing internal ID
            file_id VARCHAR(64) UNIQUE NOT NULL, -- Hash-based unique ID used by application logic
            filename VARCHAR(255) NOT NULL,
            file_path TEXT NOT NULL, -- Logical path to the encrypted file content on filesystem
            encrypted_data TEXT NOT NULL,  -- Stores JSON: {'tag': ..., 'nonce': ...} (ciphertext is on filesystem)
            file_hash VARCHAR(64) NOT NULL, -- Hash of original unencrypted file
            file_size BIGINT NOT NULL, -- Size of original unencrypted file
            threshold INTEGER NOT NULL DEFAULT 2,
            total_shares INTEGER NOT NULL,
            -- nonce TEXT NOT NULL, -- Redundant if in encrypted_data JSON
            -- auth_tag TEXT NOT NULL, -- Redundant if in encrypted_data JSON
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            uploaded_by VARCHAR(50) REFERENCES users(username),
            description TEXT,
            is_deleted BOOLEAN DEFAULT FALSE,
            deleted_at TIMESTAMP,
            download_count INTEGER DEFAULT 0,
            last_downloaded_at TIMESTAMP
        )
    ''')
    
    # Create file shares table to store the encrypted key shares
    cur.execute('''
        CREATE TABLE file_shares (
            id SERIAL PRIMARY KEY,
            file_id VARCHAR(64) REFERENCES threshold_files(file_id) ON DELETE CASCADE, -- Links to the hash-based file_id
            share_holder VARCHAR(50) REFERENCES users(username), -- Changed back to share_holder to match queries
            encrypted_share TEXT NOT NULL,
            share_index INTEGER NOT NULL, -- Index of the share (e.g., 0 to n-1 or 1 to n)
            has_accessed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_accessed TIMESTAMP
        )
    ''')
    
    # Create file access logs table for auditing purposes
    cur.execute('''
        CREATE TABLE file_access_logs (
            id SERIAL PRIMARY KEY,
            file_id INTEGER REFERENCES threshold_files(id) ON DELETE CASCADE,
            user_id VARCHAR(50) REFERENCES users(username),
            access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            access_type VARCHAR(50) NOT NULL,
            access_details TEXT,
            ip_address VARCHAR(50),
            CONSTRAINT unique_access_entry UNIQUE (file_id, user_id, access_type)
        )
    ''')
    
    # Create index for faster file retrieval
    cur.execute('''
        CREATE INDEX idx_files_recipient ON files(recipient) 
        WHERE NOT is_deleted
    ''')
    
    # Create indexes for threshold files
    cur.execute('''
        CREATE INDEX idx_threshold_files_uploader ON threshold_files(uploaded_by)
        WHERE NOT is_deleted
    ''')
    
    # Create index for file shares
    cur.execute('''
        CREATE INDEX idx_file_shares_user ON file_shares(share_holder)
    ''')
    
    # Create index for file shares by threshold file (now file_id)
    cur.execute('''
        CREATE INDEX idx_file_shares_file_id ON file_shares(file_id)
    ''')
    
    # Create index for file access logs
    cur.execute('''
        CREATE INDEX idx_file_access_logs ON file_access_logs(file_id, user_id)
    ''')

    # Create table for temporarily storing pooled decrypted FEK shares
    cur.execute('''
        CREATE TABLE pooled_decrypted_shares (
            id SERIAL PRIMARY KEY,
            file_id_hash VARCHAR(64) REFERENCES threshold_files(file_id) ON DELETE CASCADE, -- Links to the hash-based file_id
            share_holder VARCHAR(50) REFERENCES users(username) ON DELETE CASCADE,
            share_index INTEGER NOT NULL, -- The x-coordinate of the share
            share_value TEXT NOT NULL, -- The y-coordinate of the share (decrypted FEK share part), stored as text
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (file_id_hash, share_holder), -- A user can only pool one share per file
            UNIQUE (file_id_hash, share_index) -- A specific share index can only be pooled once per file
        )
    ''')
    cur.execute('''
        CREATE INDEX idx_pooled_shares_file_id ON pooled_decrypted_shares(file_id_hash)
    ''')
    cur.execute('''
        CREATE INDEX idx_pooled_shares_expiry ON pooled_decrypted_shares(expires_at)
    ''')
    
    print("Database schema initialized successfully.")
    print("If upgrading from an older version, run: python311 init_db.py upgrade")
    
    conn.commit()
    cur.close()
    conn.close()

def upgrade_existing_data():
    """
    Upgrade existing threshold_files records to use the new JSON format for encrypted_data.
    This function should be run when upgrading from an older database version.
    """
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # Check if threshold_files table exists
    cur.execute("""
        SELECT EXISTS (
            SELECT 1 
            FROM information_schema.tables 
            WHERE table_name = 'threshold_files'
        )
    """)
    
    if not cur.fetchone()[0]:
        print("No threshold_files table found. Nothing to upgrade.")
        cur.close()
        conn.close()
        return
    
    # Get all threshold files
    cur.execute("SELECT id, encrypted_data FROM threshold_files")
    records = cur.fetchall()
    
    if not records:
        print("No threshold_files records found. Nothing to upgrade.")
        cur.close()
        conn.close()
        return
    
    count = 0
    for record_id, encrypted_data in records:
        try:
            # Try to parse as JSON first
            try:
                data = json.loads(encrypted_data)
                # Skip if it's already in the new format
                if isinstance(data, dict) and 'encrypted_data' in data:
                    continue
            except (json.JSONDecodeError, TypeError):
                # Not JSON, assume it's just the encrypted data
                pass
            
            # Create the new format
            new_data = {
                'encrypted_data': encrypted_data,
                'is_chunked': False,
                'chunk_count': 0
            }
            
            # Update the record
            cur.execute(
                "UPDATE threshold_files SET encrypted_data = %s WHERE id = %s",
                (json.dumps(new_data), record_id)
            )
            count += 1
        except Exception as e:
            print(f"Error updating record {record_id}: {str(e)}")
    
    conn.commit()
    print(f"Updated {count} records to new format.")
    
    # Check for and handle columns that might have been in older versions
    try:
        # Check if is_chunked column exists
        cur.execute("""
            SELECT EXISTS (
                SELECT 1 
                FROM information_schema.columns 
                WHERE table_name='threshold_files' AND column_name='is_chunked'
            )
        """)
        
        is_chunked_exists = cur.fetchone()[0]
        
        if is_chunked_exists:
            print("Found is_chunked column. Transferring data to JSON format...")
            
            # Get records with is_chunked=true
            cur.execute("""
                SELECT id, encrypted_data, is_chunked, chunk_count 
                FROM threshold_files 
                WHERE is_chunked = true
            """)
            
            chunked_records = cur.fetchall()
            for record_id, encrypted_data, is_chunked, chunk_count in chunked_records:
                try:
                    # Parse existing JSON
                    try:
                        data = json.loads(encrypted_data)
                        actual_encrypted_data = data.get('encrypted_data', encrypted_data)
                    except (json.JSONDecodeError, TypeError):
                        actual_encrypted_data = encrypted_data
                    
                    # Create updated format with chunking info from columns
                    updated_data = {
                        'encrypted_data': actual_encrypted_data,
                        'is_chunked': True,
                        'chunk_count': chunk_count
                    }
                    
                    # Update the record
                    cur.execute(
                        "UPDATE threshold_files SET encrypted_data = %s WHERE id = %s",
                        (json.dumps(updated_data), record_id)
                    )
                except Exception as e:
                    print(f"Error updating chunked record {record_id}: {str(e)}")
            
            conn.commit()
            print(f"Transferred chunking information for {len(chunked_records)} records.")
            
            # Optionally, you can drop these columns, but it's safer to leave them 
            # and let a database admin clean them up later
            # cur.execute("ALTER TABLE threshold_files DROP COLUMN is_chunked, DROP COLUMN chunk_count")
            # conn.commit()
            # print("Dropped obsolete columns.")
    except Exception as e:
        print(f"Error checking for old columns: {str(e)}")
    
    cur.close()
    conn.close()
    print("Database upgrade complete.")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'upgrade':
        print("Upgrading existing database records...")
        upgrade_existing_data()
    else:
        init_db()
