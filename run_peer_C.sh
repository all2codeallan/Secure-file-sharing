#!/bin/bash
echo "Starting Peer C..."

# Common Configuration (from config/launcher_config.py)
export DB_HOST="localhost"
export DB_PORT="5432"
export DB_NAME="central"
export DB_USER="postgres"
export DB_PASSWORD="123456789"
export DEFAULT_RELAY_SERVER_URL="http://localhost:7000/relay"
export FLASK_SECRET_KEY="a_very_static_secret_key_for_simulation"
export DATA_DIR_BASE="./peer_data/"

# Peer C Specific Configuration
export FLASK_APP="app.py"
export FLASK_RUN_PORT="5003"
export PEER_USERNAME="userC"
export DATA_DIR_SUFFIX="C"
export P2P_PORT="6003"
export OPERATING_MODE="LOCALHOST_ONLY"
export SIMULATION_MODE="SINGLE_LAPTOP"
export FLASK_DEBUG="1"

# Navigate to the script's directory (Web_app) to ensure paths are correct
cd "$(dirname "$0")"

python -m flask run --no-reload
