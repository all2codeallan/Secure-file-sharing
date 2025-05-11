import os
import threading
import time
from flask import Flask, session, redirect, url_for
from dotenv import load_dotenv # For loading .env file if present

# Load environment variables from .env file if it exists, for development
load_dotenv()

# Logging setup has been removed.

# Import routes
from routes.auth_routes import auth_bp
from routes.file_routes import file_bp
from routes.threshold_routes import threshold_bp
from routes.dashboard_routes import dashboard_bp

# Import services
from services.auth_service import login_required

# Import cleanup functions
from utils.shamir_utils import cleanup_temp_files
from services.threshold_service import cleanup_expired_pooled_shares # Added import

# Logger setup has been removed.

# Initialize Flask app
app = Flask(__name__)

# --- Application Configuration from Environment Variables & Launcher Config ---

# Import PEER_INSTANCES_CONFIG for runtime access (e.g., by helper functions)
from config.launcher_config import PEER_INSTANCES_CONFIG
app.config['PEER_INSTANCES_CONFIG'] = PEER_INSTANCES_CONFIG

# Core instance configuration
app.config['FLASK_RUN_PORT'] = os.environ.get('FLASK_RUN_PORT', 5000)
app.config['PEER_USERNAME'] = os.environ.get('PEER_USERNAME', 'default_peer')
app.config['SESSION_COOKIE_NAME'] = f"session_peer_{app.config['PEER_USERNAME']}" # Unique session cookie per peer
app.config['P2P_PORT'] = os.environ.get('P2P_PORT', '6000') # For future P2P communication
app.config['RELAY_SERVER_URL'] = os.environ.get('RELAY_SERVER_URL', 'http://localhost:7000/relay')
app.config['OPERATING_MODE'] = os.environ.get('OPERATING_MODE', 'LOCALHOST_ONLY') # LOCALHOST_ONLY, RELAY_ONLY, LOCAL_P2P
app.config['SIMULATION_MODE'] = os.environ.get('SIMULATION_MODE', 'SINGLE_LAPTOP') # SINGLE_LAPTOP, MULTI_LAPTOP

# Data directory configuration
DATA_DIR_BASE = os.environ.get('DATA_DIR_BASE', './peer_data/')
DATA_DIR_SUFFIX = os.environ.get('DATA_DIR_SUFFIX', 'default')
full_data_dir = os.path.join(DATA_DIR_BASE, DATA_DIR_SUFFIX)
app.config['DATA_DIR'] = full_data_dir

# UPLOAD_FOLDER and UPLOAD_KEY_FOLDER will now be constructed dynamically in service functions
# based on app.config['DATA_DIR'] and the logged-in user.
# So, global configuration and directory creation for these are removed from here.

# Flask specific configurations
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_default_fallback_secret_key') # Launcher should set this
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Database configuration (to be used by SQLAlchemy setup)
app.config['DB_HOST'] = os.environ.get('DB_HOST', 'localhost')
app.config['DB_PORT'] = os.environ.get('DB_PORT', '5432')
app.config['DB_NAME'] = os.environ.get('DB_NAME', 'central')
app.config['DB_USER'] = os.environ.get('DB_USER', 'postgres')
app.config['DB_PASSWORD'] = os.environ.get('DB_PASSWORD', 'password')

# Construct SQLAlchemy Database URI
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(file_bp)
app.register_blueprint(threshold_bp)
app.register_blueprint(dashboard_bp, url_prefix='/dashboard')

# Root route redirects to intro page
@app.route('/')
def index():
    return redirect(url_for('auth.intro'))

# Background thread for cleaning up temporary files
def background_cleanup():
    """Background thread that periodically cleans up expired temporary files"""
    while True:
        with app.app_context(): # Create an application context
            try:
                # Use app.logger now that we have an app context
                app.logger.info("Background Cleanup: Running temporary file cleanup (Shamir utils)...")
                cleanup_temp_files()
                app.logger.info("Background Cleanup: Running cleanup for expired pooled shares...")
                cleanup_expired_pooled_shares()
            except Exception as e:
                app.logger.error(f"Background Cleanup: Error in cleanup thread: {str(e)}")
        
        # Sleep outside the app context
        time.sleep(900)  # Run every 15 minutes (e.g., 15 * 60 seconds)

# Start the cleanup thread when the app starts
cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
cleanup_thread.start()

# Redirect /dashboard to dashboard blueprint
@app.route('/dashboard')
@login_required
def dashboard_redirect():
    return redirect(url_for('dashboard.dashboard'))

# Add missing import
from flask import render_template, flash, request
from werkzeug.exceptions import RequestEntityTooLarge

# Error handler for 413 Request Entity Too Large
@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge) # Catch by specific exception too
def handle_request_entity_too_large(e):
    flash("The file you tried to upload exceeds the maximum allowed size of 16MB. Please choose a smaller file.", "danger")
    # Redirect to the upload page, or a more general error page if preferred
    # Assuming the error most likely occurs during threshold upload or standard upload
    if request.referrer and 'upload' in request.referrer:
        return redirect(request.referrer)
    return redirect(url_for('dashboard.dashboard')) # Fallback redirect

# Main entry point
if __name__ == '__main__':
    # Port should be controlled by FLASK_RUN_PORT from environment,
    # especially when running multiple instances.
    port = int(app.config.get('FLASK_RUN_PORT', 5000))
    app.run(debug=True, port=port, host='0.0.0.0')
