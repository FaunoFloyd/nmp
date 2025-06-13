import re
import logging
import platform
import os
from pathlib import Path
import subprocess
from typing import Optional, Tuple, List, Dict
import ctypes

def setup_logging(log_file: str = "logs.log") -> None:
    """Configure logging with both file and console handlers."""
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(
        level=logging.DEBUG,
        format=log_format,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def is_valid_ip_or_domain(target: str) -> bool:
    """
    Validate if a string is a valid IP address or domain name.
    
    Args:
        target (str): The string to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    domain_regex = r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?$"

    if re.match(ip_regex, target):
        parts = list(map(int, target.split('.')))
        if all(0 <= part <= 255 for part in parts):
            logging.debug(f"Target '{target}' identified as a valid IPv4 address.")
            return True
    if re.match(domain_regex, target):
        logging.debug(f"Target '{target}' identified as a valid domain name.")
        return True
    
    logging.warning(f"Target '{target}' is not a valid IP or domain format.")
    return False

def is_valid_port(port_str: str) -> bool:
    """
    Validate if a string represents a valid port number.
    
    Args:
        port_str (str): The string to validate
        
    Returns:
        bool: True if valid port number or empty, False otherwise
    """
    if not port_str:
        return True
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except ValueError:
        return False

def check_admin_privileges() -> bool:
    """
    Check if the current process has administrative privileges.
    
    Returns:
        bool: True if running with admin privileges, False otherwise
    """
    if platform.system().lower() == "windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    return os.geteuid() == 0

def get_sudo_password() -> Optional[str]:
    """
    Get sudo password from environment or user input.
    
    Returns:
        Optional[str]: The sudo password or None if not available/needed
    """
    if platform.system().lower() == "windows":
        return None
        
    sudo_pass = os.getenv("SUDO_PASS")
    if not sudo_pass:
        try:
            import getpass
            sudo_pass = getpass.getpass("Enter sudo password: ")
        except Exception:
            logging.error("Error retrieving sudo password.")
            sudo_pass = None
    return sudo_pass

def safe_run_command(
    command: List[str],
    timeout: int = 60,
    use_sudo: bool = False
) -> Tuple[str, str, int]:
    """
    Safely execute a command with proper error handling.
    
    Args:
        command (List[str]): Command and arguments to execute
        timeout (int): Command timeout in seconds
        use_sudo (bool): Whether to run with sudo
        
    Returns:
        Tuple[str, str, int]: stdout, stderr, and return code
        
    Raises:
        subprocess.TimeoutExpired: If command exceeds timeout
        subprocess.SubprocessError: If command fails to execute
    """
    try:
        if use_sudo and platform.system().lower() != "windows":
            sudo_pass = get_sudo_password()
            if sudo_pass:
                command = ["sudo", "-S"] + command
                
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as e:
        logging.error(f"Command timed out after {timeout}s: {' '.join(command)}")
        raise
    except subprocess.SubprocessError as e:
        logging.error(f"Command failed: {' '.join(command)}, Error: {str(e)}")
        raise
