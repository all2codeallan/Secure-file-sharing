# routes/threshold_routes.py
from flask import Blueprint, request, redirect, url_for, render_template, session, flash, send_file
from services.auth_service import login_required
from services.threshold_service import (
    encrypt_file_with_threshold, store_encrypted_shares, 
    get_user_threshold_files, get_user_share, decrypt_threshold_file, 
    get_available_share_holders, pool_decrypted_share, get_pooled_shares,
    soft_delete_threshold_file # Added soft_delete_threshold_file
)
from utils.db_utils import get_db_connection
import io

threshold_bp = Blueprint('threshold', __name__)

@threshold_bp.route('/threshold-upload')
@login_required
def threshold_upload_page():
    # Get list of users for share holders selection
    result = get_available_share_holders(session['username'])
    if result['success']:
        return render_template('threshold-upload.html', users=result['users'])
    else:
        flash(result['error'])
        return redirect(url_for('dashboard.dashboard'))

@threshold_bp.route('/threshold-upload', methods=['POST'])
@login_required
def threshold_upload():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    # Get threshold parameters
    threshold = int(request.form.get('threshold', 2))
    # Get selected share holders
    share_holders = request.form.getlist('share_holders')
    total_shares = len(share_holders) # total_shares is the count of selected recipients

    # Validations
    if total_shares < 2:
        flash('You must select at least 2 share holders.', 'danger')
        return redirect(url_for('threshold.threshold_upload_page')) # Redirect back to the form page

    if threshold < 2:
        flash('Threshold (k) must be at least 2.', 'danger')
        return redirect(url_for('threshold.threshold_upload_page'))

    if threshold > total_shares:
        flash(f'Threshold (k={threshold}) cannot be greater than the number of selected share holders (N={total_shares}).', 'danger')
        return redirect(url_for('threshold.threshold_upload_page'))
    
    # The line `share_holders = share_holders[:total_shares]` is no longer needed as total_shares is derived from len(share_holders)
    
    try:
        # Read the file data
        file_data = file.read()
        
        # Step 1: Encrypt file and generate raw FEK shares using the service
        # The service function now expects the list of share_holders, not just the count.
        encryption_result = encrypt_file_with_threshold(
            file_data, 
            file.filename, 
            session['username'], 
            threshold, 
            share_holders # Pass the list of selected share holders
        )
        
        if not encryption_result['success']:
            flash(encryption_result.get('error', 'File encryption failed.'), 'danger')
            return redirect(url_for('threshold.threshold_upload_page'))
        
        # Step 2: Store the (now individually encrypted) shares for each user
        # The service function `store_encrypted_shares` takes the raw FEK shares from encryption_result
        share_storage_result = store_encrypted_shares(
            encryption_result['file_id'], 
            encryption_result['raw_fek_shares'], # Pass the raw FEK shares
            share_holders
        )
        
        if not share_storage_result['success']:
            flash(share_storage_result.get('error', 'Storing encrypted shares failed.'), 'danger')
            return redirect(url_for('threshold.threshold_upload_page'))
        
        # Success
        flash('File successfully uploaded and shared using threshold encryption!', 'success')
        # Redirect to the 'My Uploads' page to display all files including the new one
        return redirect(url_for('threshold.threshold_files_uploaded'))
    except Exception as e:
        flash(f'Error: {str(e)}')
        return redirect(request.url)

@threshold_bp.route('/threshold-files')
@login_required
def threshold_files():
    # Get threshold files where the user has a share
    result = get_user_threshold_files(session['username'])
    
    if result['success']:
        # Removed debug prints for file list
        return render_template('threshold-files.html', files=result['files'])
    else:
        # Removed debug print for error
        flash(result['error'])
        return redirect(url_for('dashboard.dashboard'))

@threshold_bp.route('/threshold-files/uploaded')
@login_required
def threshold_files_uploaded():
    # Get threshold files that the user has uploaded/shared with others
    conn = get_db_connection()
    cur = conn.cursor()
    files = []
    
    try:
        # Get files uploaded by the current user
        cur.execute('''
            SELECT tf.file_id, tf.filename, tf.file_size, tf.threshold, tf.total_shares, 
                   tf.uploaded_at, tf.description
            FROM threshold_files tf
            WHERE tf.uploaded_by = %s AND tf.is_deleted = FALSE
            ORDER BY tf.uploaded_at DESC
        ''', (session['username'],))
        
        file_records = cur.fetchall()
        
        for record in file_records:
            file_id, filename, file_size, threshold, total_shares, uploaded_at, description = record
            
            # Get share information for this file
            cur.execute('''
                SELECT ts.share_holder, ts.has_accessed
                FROM file_shares ts
                WHERE ts.file_id = %s
            ''', (file_id,))
            
            shares_info_list = [] # Renamed variable for clarity
            accessed_shares_count = 0 # Renamed variable for clarity
            
            for share_record in cur.fetchall():
                username, has_accessed = share_record
                shares_info_list.append({ # Appending to the new list name
                    'username': username,
                    'has_accessed': has_accessed
                })
                
                if has_accessed:
                    accessed_shares_count += 1 # Incrementing the new count name
            
            # Get download count from the threshold_files table itself
            cur.execute('''
                SELECT download_count 
                FROM threshold_files 
                WHERE file_id = %s
            ''', (file_id,))
            
            download_count_result = cur.fetchone()
            download_count = download_count_result[0] if download_count_result else 0
            
            files.append({
                'file_id': file_id,
                'filename': filename,
                'file_size': file_size,
                'threshold': threshold,
                'total_shares': total_shares,
                'uploaded_at': uploaded_at,
                'description': description,
                'shares_info': shares_info_list, # Changed key to 'shares_info'
                'accessed_shares_count': accessed_shares_count, # Changed key to 'accessed_shares_count'
                'download_count': download_count
            })
        
        return render_template('threshold-files-uploaded.html', files=files)
    except Exception as e:
        flash(f'Error: {str(e)}')
        return redirect(url_for('dashboard.dashboard'))
    finally:
        cur.close()
        conn.close()

@threshold_bp.route('/threshold-decrypt/<file_id>', methods=['GET', 'POST']) # Allow POST
@login_required
def threshold_decrypt_page(file_id):
    # This route now handles both displaying the page (GET) 
    # and processing the user's own share contribution (POST)
    
    if request.method == 'POST':
        # User is submitting their password to process and pool their share
        user_main_password = request.form.get('user_password')
        if not user_main_password:
            flash('Password is required to process your share.', 'danger')
            # To redirect back to the same page, we might need to re-fetch GET data or pass it through
            # For simplicity, redirecting to the general threshold files list.
            # Consider rendering the same template with an error if password is blank.
            return redirect(url_for('threshold.threshold_decrypt_page', file_id=file_id))

        try:
            share_result = get_user_share(file_id, session['username'], user_main_password)
            if not share_result['success']:
                flash(share_result.get('error', 'Could not process your share. Password incorrect or other issue.'), 'danger')
                # Re-render the same page with the error
                context = _get_threshold_decrypt_page_context(file_id, session['username'])
                if not context:
                    return redirect(url_for('threshold.threshold_files')) # Fallback if context fails
                return render_template('threshold-decrypt.html', **context)

            decrypted_share_tuple = share_result['share'] # (index, value_int)
            share_index = share_result['share_index'] # This should match decrypted_share_tuple[0]

            # Pool the decrypted share
            # Note: file_id here is the hash-based one, matching pool_decrypted_share's file_id_hash
            pool_result = pool_decrypted_share(
                file_id_hash=file_id, 
                share_holder=session['username'], 
                share_index=share_index, 
                share_value_int=decrypted_share_tuple[1] # The y-value of the share
            )

            # Removed debug print for pooling result
            if pool_result['success']:
                flash('Your share has been successfully processed and contributed to the pool!', 'success')

                # Check if this contribution met the threshold to offer immediate final decryption
                conn_check = get_db_connection()
                cur_check = conn_check.cursor()
                cur_check.execute("SELECT threshold FROM threshold_files WHERE file_id = %s", (file_id,))
                file_threshold_record = cur_check.fetchone()
                
                if file_threshold_record:
                    file_k_threshold = file_threshold_record[0]
                    current_pooled_shares_result = get_pooled_shares(file_id)
                    num_currently_pooled = 0
                    if current_pooled_shares_result['success']:
                        num_currently_pooled = len(current_pooled_shares_result['shares'])
                    
                    if num_currently_pooled >= file_k_threshold:
                        flash('This file is now ready for final decryption with the pooled shares.', 'info')
                        cur_check.close()
                        conn_check.close()
                        return redirect(url_for('threshold.threshold_decrypt_page', file_id=file_id)) # Redirect back to same page (GET)
                
                cur_check.close()
                conn_check.close()
                # If not ready or check failed, fall through to redirect to /threshold-files
            else: # pool_result was not successful
                flash(pool_result.get('error', 'Failed to pool your share. Please try again.'), 'danger')
                # Re-render the same page with the error
                context = _get_threshold_decrypt_page_context(file_id, session['username'])
                if not context:
                    return redirect(url_for('threshold.threshold_files')) # Fallback
                return render_template('threshold-decrypt.html', **context)
            
            return redirect(url_for('threshold.threshold_files')) # Default redirect if not caught by specific conditions above

        except Exception as e:
            flash(f'An unexpected error occurred while processing your share: {str(e)}', 'danger')
            # Re-render the same page with the error
            context = _get_threshold_decrypt_page_context(file_id, session['username'])
            if not context:
                return redirect(url_for('threshold.threshold_files')) # Fallback
            return render_template('threshold-decrypt.html', **context)

    # --- GET Request Logic ---
    context = _get_threshold_decrypt_page_context(file_id, session['username'])
    if not context:
        return redirect(url_for('threshold.threshold_files')) # Helper flashed error or file not found
    
    return render_template('threshold-decrypt.html', **context)

def _get_threshold_decrypt_page_context(file_id, current_username):
    """Helper function to fetch context data for the threshold-decrypt.html page."""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get file details
        cur.execute("""
            SELECT filename, threshold, total_shares, uploaded_by, uploaded_at 
            FROM threshold_files 
            WHERE file_id = %s
        """, (file_id,))
        file_info_record = cur.fetchone()
        if not file_info_record:
            flash('File not found.', 'danger')
            return None 
        
        filename, threshold, total_shares, uploaded_by, uploaded_at = file_info_record

        # Get all share holders involved in this file (username, share_index)
        cur.execute("""
            SELECT share_holder, share_index 
            FROM file_shares 
            WHERE file_id = %s 
            ORDER BY share_index
        """, (file_id,))
        all_share_holders_for_file = cur.fetchall() 

        # Get current user's contribution status for this specific file
        cur.execute("""
            SELECT has_accessed 
            FROM file_shares 
            WHERE file_id = %s AND share_holder = %s
        """, (file_id, current_username))
        user_share_status_record = cur.fetchone()
        current_user_has_contributed = user_share_status_record[0] if user_share_status_record else False

        # Get current number of successfully pooled shares for this file
        pooled_shares_result = get_pooled_shares(file_id) # file_id is the hash
        num_pooled_shares = 0
        if pooled_shares_result['success']:
            num_pooled_shares = len(pooled_shares_result['shares'])
        
        context_data = {
            'file_id': file_id,
            'filename': filename,
            'threshold': threshold,
            'total_shares': total_shares, 
            'uploaded_by': uploaded_by,
            'uploaded_at': uploaded_at,
            'share_holders': all_share_holders_for_file, 
            'current_user': current_username,
            'current_user_has_contributed': current_user_has_contributed,
            'num_pooled_shares': num_pooled_shares
        }
        
        # Removed debug prints for context_data
            
        return context_data
    except Exception as e:
        print(f"Error in _get_threshold_decrypt_page_context for file {file_id}: {str(e)}")
        flash(f'Error fetching page data: {str(e)}', 'danger')
        return None
    finally:
        if cur: cur.close()
        if conn: conn.close()

@threshold_bp.route('/threshold-decrypt-confirm/<file_id>', methods=['POST'])
@login_required
def threshold_decrypt_confirm(file_id):
    # The service function `decrypt_threshold_file` now fetches pooled shares.
    # No need to collect shares from session or form here.
    
    # Decrypt the file using pooled shares
    result = decrypt_threshold_file(file_id) # Pass only file_id (which is file_id_hash)
    
    if not result['success']:
        flash(result['error'])
        return redirect(url_for('threshold.threshold_files'))
    
    # Create a BytesIO object from the decrypted data
    file_data = io.BytesIO(result['data'])
    
    # Get filename from the result
    filename = result.get('filename', f"decrypted_file_{file_id}.txt")
    
    # Show success message with contributor information
    contributors = result.get('contributors', [])
    if contributors:
        flash(f'File successfully decrypted with contributions from: {", ".join(contributors)}', 'success')
    else:
        flash('File successfully decrypted', 'success')
    
    # Send the file to the user
    return send_file(
        file_data,
        download_name=filename,
        as_attachment=True
    )

@threshold_bp.route('/threshold-files/delete/<file_id>', methods=['POST'])
@login_required
def delete_threshold_file(file_id):
    """Soft deletes a threshold file uploaded by the current user."""
    username = session.get('username')
    result = soft_delete_threshold_file(file_id, username)
    
    if result.get('success'):
        flash(f"File '{result.get('filename', file_id)}' has been successfully marked for deletion.", 'success')
    else:
        flash(f"Error deleting file: {result.get('error', 'Unknown error')}", 'danger')
        
    return redirect(url_for('threshold.threshold_files_uploaded'))
