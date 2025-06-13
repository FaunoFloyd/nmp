import requests
import time
import socket
import threading
import os
from pathlib import Path
from typing import Optional
import configparser
from flask import Flask, request, jsonify
import subprocess
from utils import setup_logging, safe_run_command
import logging
from functools import wraps
import ssl

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

# Configuration with environment variable fallback
CONTROLLER_URL = os.getenv('CONTROLLER_URL', config.get('DEFAULT', 'CONTROLLER_URL'))
API_KEY = os.getenv('API_KEY', config.get('DEFAULT', 'API_KEY'))
HEARTBEAT_INTERVAL = config.getint('DEFAULT', 'HEARTBEAT_INTERVAL', fallback=300)
MAX_RETRIES = config.getint('DEFAULT', 'MAX_RETRIES', fallback=3)
RETRY_DELAY = config.getint('DEFAULT', 'RETRY_DELAY', fallback=5)
COMMAND_TIMEOUT = config.getint('DEFAULT', 'COMMAND_TIMEOUT', fallback=60)

# Setup logging
setup_logging()

class RegistrationError(Exception):
    """Raised when agent registration fails"""
    pass

def retry_on_failure(max_retries: int = MAX_RETRIES, delay: int = RETRY_DELAY):
    """Decorator to retry failed operations"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    logging.warning(f"Attempt {attempt + 1} failed: {str(e)}. Retrying...")
                    time.sleep(delay)
        return wrapper
    return decorator

@retry_on_failure()
def register_self() -> Optional[str]:
    """
    Register the agent with the controller server.
    
    Returns:
        Optional[str]: The agent's IP address if registration successful, None otherwise
        
    Raises:
        RegistrationError: If registration fails after all retries
    """
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    payload = {"hostname": hostname, "ip": ip_address}
    headers = {'Authorization': f'Bearer {API_KEY}'}
    
    try:
        response = requests.post(
            f"{CONTROLLER_URL}/register",
            json=payload,
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        logging.info(f"Successfully registered with controller as {hostname} ({ip_address})")
        return ip_address
    except requests.exceptions.RequestException as e:
        logging.error(f"Registration failed: {str(e)}")
        raise RegistrationError(f"Could not register with controller: {str(e)}")

class HeartbeatThread(threading.Thread):
    """Thread class for sending periodic heartbeats"""
    
    def __init__(self, ip_address: str):
        super().__init__(daemon=True)
        self._stop_event = threading.Event()
        self.ip_address = ip_address
        
    def run(self):
        while not self._stop_event.is_set():
            try:
                self._send_heartbeat()
            except Exception as e:
                logging.error(f"Heartbeat failed: {str(e)}")
            self._stop_event.wait(HEARTBEAT_INTERVAL)
    
    @retry_on_failure()
    def _send_heartbeat(self):
        payload = {"ip": self.ip_address}
        headers = {'Authorization': f'Bearer {API_KEY}'}
        response = requests.post(
            f"{CONTROLLER_URL}/heartbeat",
            json=payload,
            headers=headers,
            timeout=5
        )
        response.raise_for_status()
        logging.debug("Heartbeat sent successfully")
    
    def stop(self):
        self._stop_event.set()

# Flask application setup
app = Flask(__name__)

def require_api_key(f):
    """Decorator to check for valid API key"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or auth_header != f"Bearer {API_KEY}":
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/run-test', methods=['POST'])
@require_api_key
def run_test():
    """
    Execute a command received from the controller.
    
    Expected request format:
    {
        "command": ["command", "arg1", "arg2", ...]
    }
    """
    data = request.json
    command = data.get('command')

    if not command or not isinstance(command, list):
        return jsonify({"error": "Invalid command format"}), 400

    logging.info(f"Received command to execute: {' '.join(command)}")

    try:
        stdout, stderr, return_code = safe_run_command(
            command,
            timeout=COMMAND_TIMEOUT
        )
        
        return jsonify({
            "stdout": stdout,
            "stderr": stderr,
            "return_code": return_code
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 504
    except subprocess.SubprocessError as e:
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        logging.error(f"Unexpected error executing command: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

def main():
    """Main entry point for the agent"""
    try:
        # Initial registration
        ip_address = register_self()
        if not ip_address:
            logging.error("Registration failed. Exiting.")
            return

        # Start heartbeat thread
        heartbeat = HeartbeatThread(ip_address)
        heartbeat.start()

        # Setup SSL if enabled
        ssl_context = None
        if config.getboolean('DEFAULT', 'SSL_ENABLED', fallback=False):
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(
                certfile='cert.pem',
                keyfile='key.pem'
            )

        # Start Flask server
        app.run(
            host='0.0.0.0',
            port=config.getint('DEFAULT', 'AGENT_PORT', fallback=5000),
            ssl_context=ssl_context
        )

    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        raise

if __name__ == '__main__':
    main()