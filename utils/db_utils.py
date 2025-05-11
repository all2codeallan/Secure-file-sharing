# utils/db_utils.py
import psycopg2
from flask import current_app

def get_db_connection():
    """Create and return a database connection using settings from current_app.config"""
    try:
        db_config = {
            "host": current_app.config['DB_HOST'],
            "port": current_app.config['DB_PORT'],
            "dbname": current_app.config['DB_NAME'],
            "user": current_app.config['DB_USER'],
            "password": current_app.config['DB_PASSWORD']
        }
        return psycopg2.connect(**db_config)
    except psycopg2.Error as e:
        current_app.logger.error(f"Database connection error: {e}")
        raise
    except Exception as e:
        # Catch if current_app or config keys are not available (e.g. called outside app context)
        print(f"Error accessing app config for DB connection: {e}")
        # Fallback or re-raise, depending on desired behavior. For now, re-raise.
        raise
