# routes/auth_routes.py
from flask import Blueprint, request, redirect, url_for, render_template, session, flash, send_file
from services.auth_service import login_required
from services.user_service import register_user, authenticate_user, get_all_users # Added get_all_users
import io
from datetime import datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def intro():
    if 'username' in session:
        return redirect(url_for('dashboard.dashboard'))
    return render_template('intro.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        challenge = request.form.get('challenge')

        if not all([username, password]):
            return render_template('login.html', error='Please fill in all fields')

        try:
            # Authenticate user
            result = authenticate_user(username, password, challenge)

            if not result['success']:
                return render_template('login.html', error=result['error'])

            # If we need a challenge-response
            if 'needs_signature' in result and result['needs_signature']:
                return render_template('login.html', challenge=result['challenge'])

            # If authentication is successful
            if 'authenticated' in result and result['authenticated']:
                if 'private_key' in result and result['private_key']:
                    session['username'] = username
                    session['decrypted_private_key'] = result['private_key'] # Store decrypted key
                    session.pop('password', None) # Ensure password is not in session
                    # flash('Login successful!', 'success') # Optional: flash success message
                    return redirect(url_for('dashboard.dashboard'))
                else:
                    # If authentication was marked successful but the private key is missing,
                    # this is a critical issue for app functionality.
                    error_message = result.get('error', 'Login succeeded but failed to retrieve necessary credentials. Please try again or contact support.')
                    flash(error_message, 'danger')
                    # Log this server-side as it indicates an issue in authenticate_user logic
                    print(f"CRITICAL LOGIN ISSUE for {username}: Authenticated but no private key returned by authenticate_user. Result: {result}")
                    return render_template('login.html', error=error_message)
        except Exception as e:
            print(f"Login error: {str(e)}")
            return render_template('login.html', error='An error occurred during login. Please try again.')

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    # Clear all session data for a clean logout
    session.clear()
    # Removed flash message: flash('You have been successfully logged out.', 'info')
    return redirect(url_for('auth.intro'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('dashboard.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        firstname = request.form.get('first-name')
        lastname = request.form.get('last-name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        # Validate input
        if not all([username, firstname, lastname, password, confirm_password]):
            return render_template('register.html', error='Please fill in all fields')

        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')

        # Register user
        result = register_user(username, firstname, lastname, password)

        if not result['success']:
            return render_template('register.html', error=result['error'])
        # Registration successful - prepare for private key download
        if 'downloadable_encrypted_pem' in result: # Use the correct key from user_service
            # Store the encrypted private key PEM in session
            session['username'] = username
            session['downloadable_encrypted_pem'] = result['downloadable_encrypted_pem'] # Assign correct result key
            # Flash a message that will be displayed on the key-display page
            flash('Registration successful! Please download your encrypted private key PEM file. You will need your registration password to use it.', 'success')
            # The download_private_key route pops the key, making it effectively one-time.
            # session['key_download_enabled'] = True # This flag is not used by the current download_private_key
            return render_template('key-display.html')
        else:
            flash('Registration successful but private key data not available. Please log in.', 'warning')
            return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth_bp.route('/download_private_key')
def download_private_key():
    """
    Download private key endpoint. This is only available immediately after registration.
    The key is stored temporarily in the session and is removed after download.
    """
    # Check if we have encrypted PEM key in session from registration
    encrypted_pem_key = session.get('downloadable_encrypted_pem')
    username = session.get('username')

    if not encrypted_pem_key:
        # Return a direct error response instead of redirecting
        # The flash message here won't be seen as we are not rendering a template that shows it.
        # The text response itself is the feedback.
        return "Error: Private key is no longer available for download. For security reasons, it can only be downloaded once immediately after registration, or your session may have expired.", 403 # 403 Forbidden or 404 Not Found

    try:
        # Create filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{username}_private_key_{timestamp}.pem"

        # Create PEM-formatted key content with header/footer if needed
        if not encrypted_pem_key.startswith('-----BEGIN'):
            pem_content = "-----BEGIN PRIVATE KEY-----\n"
            pem_content += encrypted_pem_key.strip()
            pem_content += "\n-----END PRIVATE KEY-----"
        else:
            pem_content = encrypted_pem_key

        # Set up stream for file
        key_stream = io.BytesIO(pem_content.encode('utf-8'))
        key_stream.seek(0)

        # Clear sensitive data from session 
        session.pop('downloadable_encrypted_pem', None)
        
        # Set up response with security headers
        response = send_file(
            key_stream,
            mimetype='application/x-pem-file',
            as_attachment=True,
            download_name=filename
        )

        # Add security headers
        response.headers.update({
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma': 'no-cache',
            'Expires': '0',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'none'",
            'X-Frame-Options': 'DENY'
        })

        flash('Private key downloaded successfully. Keep it safe!', 'success') # This flash will be seen on the *next* page load
        return response

    except Exception as e:
        print(f"Error during private key download: {str(e)}")
        # flash('An error occurred while downloading your private key.', 'danger') # This flash won't be seen if we return plain text
        session.pop('downloadable_encrypted_pem', None)  # Clean up on error too
        return f"Server error during private key download: {str(e)}", 500 # Return direct error

@auth_bp.route('/public-key-directory')
@login_required
def public_key_directory():
    result = get_all_users()
    if result['success']:
        return render_template('public-key-list.html', users_with_keys=result['users'])
    else:
        flash(result.get('error', 'Could not retrieve public key directory.'), 'danger')
        return redirect(url_for('dashboard.dashboard'))
