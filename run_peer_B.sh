#!/bin/bash
echo "Starting Peer B..."

# Common Configuration (from config/launcher_config.py)
export DB_HOST="localhost"
export DB_PORT="5432"
export DB_NAME="central"
export DB_USER="postgres"
export DB_PASSWORD="123456789"
export DEFAULT_RELAY_SERVER_URL="http://localhost:7000/relay"
export FLASK_SECRET_KEY="a_very_static_secret_key_for_simulation"
export DATA_DIR_BASE="./peer_data/"

# Peer B Specific Configuration
export FLASK_APP="app.py"
export FLASK_RUN_PORT="5002"
export PEER_USERNAME="userB"
export DATA_DIR_SUFFIX="B"
export P2P_PORT="6002"
export OPERATING_MODE="LOCALHOST_ONLY"
export SIMULATION_MODE="SINGLE_LAPTOP"
export FLASK_DEBUG="1"

# Navigate to the script's directory (Web_app) to ensure paths are correct
cd "$(dirname "$0")"

python -m flask run --no-reload
