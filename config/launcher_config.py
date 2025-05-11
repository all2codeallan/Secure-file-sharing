# config/launcher_config.py

# Define a list of peer configurations
# Each peer needs: name, flask_port, p2p_port (for future use),
# username, data_dir_suffix (e.g., "A", "B"),
# operating_mode (default LOCALHOST_ONLY), simulation_mode (default SINGLE_LAPTOP).
PEER_INSTANCES_CONFIG = [
    {
        "name": "PeerA",
        "flask_port": 5001,
        "p2p_port": 6001,
        "username": "userA",
        "data_dir_suffix": "A",
        "operating_mode": "LOCALHOST_ONLY",  # Options: LOCALHOST_ONLY, RELAY_ONLY, LOCAL_P2P
        "simulation_mode": "SINGLE_LAPTOP"  # Options: SINGLE_LAPTOP, MULTI_LAPTOP
    },
    {
        "name": "PeerB",
        "flask_port": 5002,
        "p2p_port": 6002,
        "username": "userB",
        "data_dir_suffix": "B",
        "operating_mode": "LOCALHOST_ONLY",
        "simulation_mode": "SINGLE_LAPTOP"
    },
    {
        "name": "PeerC",
        "flask_port": 5003,
        "p2p_port": 6003,
        "username": "userC",
        "data_dir_suffix": "C",
        "operating_mode": "LOCALHOST_ONLY",
        "simulation_mode": "SINGLE_LAPTOP"
    },
    {
        "name": "PeerD",
        "flask_port": 5004,
        "p2p_port": 6004,
        "username": "userD",
        "data_dir_suffix": "D",
        "operating_mode": "LOCALHOST_ONLY",
        "simulation_mode": "SINGLE_LAPTOP"
    }
]

# Define central PostgreSQL connection details
# These will be overridden by environment variables if set,
# but provide defaults for local development.
DB_HOST = "localhost"
DB_PORT = 5432
DB_NAME = "central"
DB_USER = "postgres"  # Replace with your actual DB user
DB_PASSWORD = "123456789"  # Replace with your actual DB password

# Define DEFAULT_RELAY_SERVER_URL
DEFAULT_RELAY_SERVER_URL = "http://localhost:7000/relay"

# Static secret key for Flask app during simulation
# In a real production environment, this should be unique and kept secret.
FLASK_SECRET_KEY = "a_very_static_secret_key_for_simulation"

# Base directory for peer data
DATA_DIR_BASE = "./peer_data/"
