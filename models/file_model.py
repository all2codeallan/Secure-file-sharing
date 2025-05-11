# models/file_model.py
from utils.db_utils import get_db_connection
import json
import hashlib
from werkzeug.utils import secure_filename

def save_encrypted_file(filename, encrypted_data, file_hash, file_size, mime_type, uploaded_by, recipient):
    """Save an encrypted file to the database"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Generate a secure filename
        secure_name = secure_filename(filename)
        encrypted_filename = f"encrypted_{secure_name}"
        
        # Save encrypted data to database
        cur.execute('''
            INSERT INTO files (
                filename, file_path, encrypted_data, file_hash,
                file_size, mime_type, uploaded_by, recipient
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (
            filename, encrypted_filename, json.dumps(encrypted_data),
            file_hash, file_size, mime_type, uploaded_by, recipient
        ))
        
        file_id = cur.fetchone()[0]
        conn.commit()
        return file_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()

def get_file_by_id(file_id, recipient=None):
    """Get file data by ID, optionally verifying recipient"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        if recipient:
            # Get file data and verify recipient
            cur.execute('''
                SELECT id, filename, encrypted_data, file_hash, file_size, mime_type, uploaded_by
                FROM files
                WHERE id = %s AND recipient = %s
            ''', (file_id, recipient))
        else:
            # Get file data without recipient verification
            cur.execute('''
                SELECT id, filename, encrypted_data, file_hash, file_size, mime_type, uploaded_by, recipient
                FROM files
                WHERE id = %s
            ''', (file_id,))
        
        result = cur.fetchone()
        
        if not result:
            return None
        
        # Parse the result into a dictionary
        if recipient:
            file_data = {
                'id': result[0],
                'filename': result[1],
                'encrypted_data': json.loads(result[2]),
                'file_hash': result[3],
                'file_size': result[4],
                'mime_type': result[5],
                'uploaded_by': result[6],
                'recipient': recipient
            }
        else:
            file_data = {
                'id': result[0],
                'filename': result[1],
                'encrypted_data': json.loads(result[2]),
                'file_hash': result[3],
                'file_size': result[4],
                'mime_type': result[5],
                'uploaded_by': result[6],
                'recipient': result[7]
            }
        
        return file_data
    except Exception as e:
        raise e
    finally:
        cur.close()
        conn.close()

def get_files_for_user(username):
    """Get files shared with a specific user"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Get files shared with the current user
        cur.execute('''
            SELECT id, filename, uploaded_by, uploaded_at, encrypted_data
            FROM files
            WHERE recipient = %s
            ORDER BY uploaded_at DESC
        ''', (username,))
        
        files = []
        for row in cur.fetchall():
            files.append({
                'id': row[0],
                'filename': row[1],
                'uploaded_by': row[2],
                'uploaded_at': row[3],
                'encrypted_data': row[4]
            })
        
        return files
    except Exception as e:
        raise e
    finally:
        cur.close()
        conn.close()

def calculate_file_hash(file_data):
    """Calculate SHA-256 hash of file data"""
    return hashlib.sha256(file_data).hexdigest()

def get_file_size(file_data):
    """Get the size of file data in bytes"""
    return len(file_data)