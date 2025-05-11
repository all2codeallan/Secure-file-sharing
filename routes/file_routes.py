# routes/file_routes.py
from flask import Blueprint, request, redirect, url_for, render_template, session, flash, send_file
from services.auth_service import login_required
from services.file_service import upload_file, get_user_files, get_file_for_download, get_available_recipients, allowed_file
import io

file_bp = Blueprint('file', __name__)

@file_bp.route('/upload-file')
@login_required
def call_page_upload():
    # Get list of users for recipient selection
    result = get_available_recipients(session['username'])
    if result['success']:
        return render_template('upload.html', users=result['users'])
    else:
        flash(result['error'])
        return redirect(url_for('dashboard'))

@file_bp.route('/data', methods=['GET', 'POST'])
@login_required
def upload_file_route():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']
        recipient = request.form.get('recipient')

        if file.filename == '':
            flash('No selected file')
            return 'NO FILE SELECTED'

        if not allowed_file(file.filename):
            flash('Invalid file type. Allowed types: txt, pdf, doc, docx, xls, xlsx, jpg, jpeg, png, zip, rar', 'danger')
            # It's better to redirect back to the upload page so it can be re-rendered with the recipient list
            return redirect(url_for('file.call_page_upload'))

        if file and recipient:
            try:
                # Read the file data
                file_data = file.read()

                # Upload and encrypt the file
                result = upload_file(file_data, file.filename, recipient, session['username'])

                if result['success']:
                    return render_template('post-upload.html')
                else:
                    return f'An error occurred during file upload: {result["error"]}'
            except Exception as e:
                print(f"Upload error: {str(e)}")
                return 'An error occurred during file upload'
        return 'Invalid File Format!'

@file_bp.route('/file-directory/')
@login_required
def download_f():
    try:
        # Get current user
        username = session.get('username')
        if not username:
            return redirect(url_for('auth.login'))

        # Get files shared with the current user
        result = get_user_files(username)

        if result['success']:
            return render_template('file-list.html', files=result['files'])
        else:
            return render_template('file-list.html', error_message=result['error'])
    except Exception as e:
        print(f"Error in file directory: {str(e)}")
        return render_template('file-list.html', error_message="An error occurred while retrieving files.")

@file_bp.route('/file-directory/retrieve/file/<int:file_id>')
@login_required
def download_file(file_id):
    try:
        # Get current user
        username = session.get('username')
        if not username:
            return redirect(url_for('auth.login'))

        # Get decrypted private key from session
        decrypted_private_key = session.get('decrypted_private_key')
        if not decrypted_private_key:
            flash('Your session has expired or is missing necessary credentials. Please log in again.', 'warning')
            return redirect(url_for('auth.login'))

        # Get and decrypt the file
        result = get_file_for_download(file_id, username, decrypted_private_key)

        if not result['success']:
            flash(result.get('error', 'Could not download file.'), 'danger')
            return redirect(url_for('file.download_f')) # Redirect back to file list page

        # Create a BytesIO object from the decrypted data
        file_data = io.BytesIO(result['data'])

        # Send the file to the user
        return send_file(
            file_data,
            download_name=result['filename'],
            as_attachment=True
        )
    except Exception as e:
        print(f"Error downloading file: {str(e)}")
        return render_template('file-list.html', error_message="An error occurred while downloading the file.")
