# routes/dashboard_routes.py
from flask import Blueprint, render_template, session
from services.auth_service import login_required
from utils.db_utils import get_db_connection

# Create dashboard blueprint
dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def dashboard():
    # Debug information
    print(f"Dashboard accessed by user: {session['username']}")
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Count files shared with this user
        cur.execute('''
            SELECT COUNT(*) FROM file_shares
            WHERE share_holder = %s
        ''', (session['username'],))
        shared_count = cur.fetchone()[0]

        print(f"User {session['username']} has {shared_count} shared files")

        cur.close()
        conn.close()
        return render_template('index.html', username=session['username'])
    except Exception as e:
        print(f"Error in dashboard: {str(e)}")
        return render_template('index.html', username=session['username'], error='An error occurred loading your dashboard data.')
