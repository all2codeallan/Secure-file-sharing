import sys
import subprocess
import os
import time
from config.launcher_config import (
    PEER_INSTANCES_CONFIG,
    DB_HOST,
    DB_PORT,
    DB_NAME,
    DB_USER,
    DB_PASSWORD,
    DEFAULT_RELAY_SERVER_URL,
    FLASK_SECRET_KEY,
    DATA_DIR_BASE
)

def main():
    processes = []
    print("Starting Flask peer instances...")

    for peer_config in PEER_INSTANCES_CONFIG:
        env = os.environ.copy()

        # Set environment variables for the subprocess
        env["FLASK_APP"] = "app.py" # Explicitly set the Flask app
        env["FLASK_RUN_PORT"] = str(peer_config["flask_port"])
        env["PEER_USERNAME"] = peer_config["username"]
        env["DATA_DIR_BASE"] = DATA_DIR_BASE
        env["DATA_DIR_SUFFIX"] = peer_config["data_dir_suffix"]
        env["P2P_PORT"] = str(peer_config["p2p_port"])
        env["RELAY_SERVER_URL"] = peer_config.get("relay_server_url", DEFAULT_RELAY_SERVER_URL)
        env["OPERATING_MODE"] = peer_config["operating_mode"]
        env["SIMULATION_MODE"] = peer_config["simulation_mode"]
        
        # Central Database configuration
        env["DB_HOST"] = DB_HOST
        env["DB_PORT"] = str(DB_PORT)
        env["DB_NAME"] = DB_NAME
        env["DB_USER"] = DB_USER
        env["DB_PASSWORD"] = DB_PASSWORD
        
        env["FLASK_SECRET_KEY"] = FLASK_SECRET_KEY
        
        # For Flask's development server, FLASK_ENV is deprecated in favor of FLASK_DEBUG
        # FLASK_DEBUG=1 enables debug mode (reloader, debugger)
        # FLASK_DEBUG=0 disables it.
        # For production, you'd typically use a production WSGI server like Gunicorn or uWSGI.
        env["FLASK_DEBUG"] = "1" # Run in debug mode for development/simulation

        print(f"Launching {peer_config['name']} ({peer_config['username']}) on port {peer_config['flask_port']}...")
        print(f"  Data directory: {os.path.join(DATA_DIR_BASE, peer_config['data_dir_suffix'])}")
        print(f"  Operating Mode: {peer_config['operating_mode']}, Simulation Mode: {peer_config['simulation_mode']}")

        # Command to run: python -m flask run --no-reload
        # --no-reload is important to prevent the reloader from starting threads twice
        # or causing issues in a multi-process simulation.
        # The port is handled by FLASK_RUN_PORT in app.py
        # Host is set to 0.0.0.0 in app.py to be accessible
        cmd = [sys.executable, "-m", "flask", "run", "--no-reload"]
        
        # Using cwd parameter to ensure Flask picks up app.py correctly from the Web_app directory
        # if launcher.py is run from Web_app/
        process = subprocess.Popen(cmd, env=env, cwd=os.path.dirname(os.path.abspath(__file__)))
        processes.append(process)
        
        # Give a little time for each app to start before launching the next
        time.sleep(2) 

    print(f"\nLaunched {len(processes)} peer instances.")
    print("Press Ctrl+C to terminate all instances.")

    try:
        for process in processes:
            process.wait()
    except KeyboardInterrupt:
        print("\nTerminating all peer instances...")
        for process in processes:
            process.terminate() # Send SIGTERM
            try:
                process.wait(timeout=5) # Wait for graceful shutdown
            except subprocess.TimeoutExpired:
                process.kill() # Force kill if not terminated
        print("All instances terminated.")

if __name__ == "__main__":
    main()
