# models/threshold_model.py
from utils.db_utils import get_db_connection
import json

def save_threshold_file(filename, encrypted_data, file_hash, file_size, mime_type, uploaded_by, recipients, threshold):
    """Save a threshold-encrypted file to the database"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Save threshold file metadata
        cur.execute('''
            INSERT INTO threshold_files (
                filename, encrypted_data, file_hash, file_size, mime_type,
                uploaded_by, threshold, total_shares
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (
            filename, json.dumps(encrypted_data), file_hash, file_size, mime_type,
            uploaded_by, threshold, len(recipients)
        ))
        
        file_id = cur.fetchone()[0]
        
        # Save share information for each recipient
        for recipient in recipients:
            encrypted_share = encrypted_data['encrypted_shares'][recipient]
            cur.execute('''
                INSERT INTO threshold_shares (
                    file_id, recipient, encrypted_share
                )
                VALUES (%s, %s, %s)
            ''', (file_id, recipient, encrypted_share))
        
        conn.commit()
        return file_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()

def get_threshold_file_by_id(file_id):
    """Get threshold file data by ID"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Get file data
        cur.execute('''
            SELECT id, filename, encrypted_data, file_hash, file_size, mime_type,
                   uploaded_by, threshold, total_shares, uploaded_at
            FROM threshold_files
            WHERE id = %s
        ''', (file_id,))
        
        result = cur.fetchone()
        
        if not result:
            return None
        
        # Parse the result into a dictionary
        file_data = {
            'id': result[0],
            'filename': result[1],
            'encrypted_data': json.loads(result[2]),
            'file_hash': result[3],
            'file_size': result[4],
            'mime_type': result[5],
            'uploaded_by': result[6],
            'threshold': result[7],
            'total_shares': result[8],
            'uploaded_at': result[9]
        }
        
        return file_data
    except Exception as e:
        raise e
    finally:
        cur.close()
        conn.close()

def get_threshold_files_for_user(username):
    """Get threshold files where the user has a share"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Get threshold files where the user has a share
        cur.execute('''
            SELECT tf.id, tf.filename, tf.uploaded_by, tf.uploaded_at,
                   tf.threshold, tf.total_shares
            FROM threshold_files tf
            JOIN threshold_shares ts ON tf.id = ts.file_id
            WHERE ts.recipient = %s
            ORDER BY tf.uploaded_at DESC
        ''', (username,))
        
        files = []
        for row in cur.fetchall():
            files.append({
                'id': row[0],
                'filename': row[1],
                'uploaded_by': row[2],
                'uploaded_at': row[3],
                'threshold': row[4],
                'total_shares': row[5]
            })
        
        return files
    except Exception as e:
        raise e
    finally:
        cur.close()
        conn.close()

def get_share_for_user(file_id, username):
    """Get a user's encrypted share for a threshold file"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Get the user's encrypted share
        cur.execute('''
            SELECT encrypted_share
            FROM threshold_shares
            WHERE file_id = %s AND recipient = %s
        ''', (file_id, username))
        
        result = cur.fetchone()
        
        if not result:
            return None
        
        return result[0]
    except Exception as e:
        raise e
    finally:
        cur.close()
        conn.close()

def get_all_recipients_for_file(file_id):
    """Get all recipients who have shares for a threshold file"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Get all recipients
        cur.execute('''
            SELECT recipient
            FROM threshold_shares
            WHERE file_id = %s
        ''', (file_id,))
        
        recipients = [row[0] for row in cur.fetchall()]
        
        return recipients
    except Exception as e:
        raise e
    finally:
        cur.close()
        conn.close()