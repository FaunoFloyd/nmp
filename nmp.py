# net.py
import subprocess
import platform
import shutil
import sys
import time
import argparse
from pathlib import Path
from datetime import datetime
import os
import signal
import distro
import unittest
import urllib.request
from threading import Thread
from queue import Queue, Empty
import logging
import re

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("logs.log"), logging.StreamHandler()]
)

def install_linux_tool(package_name, tool_friendly_name, output_file):
    logging.debug(f"Attempting to install {tool_friendly_name} ({package_name}) on Linux.")
    print(f"\n[!] {tool_friendly_name} not found.")
    
    # Check if admin privileges are available, which are needed for apt-get
    if not check_admin_privileges():
        logging.error(f"Cannot install {tool_friendly_name}: Admin privileges required.")
        print(f"[-] Cannot install {tool_friendly_name}: Admin privileges required. Please run the script as administrator/root.")
        if output_file:
            output_file.write(f"[-] Cannot install {tool_friendly_name}: Admin privileges required.\n")
        return False

    choice = input(f"Do you want to install {tool_friendly_name} using apt-get? (y/N): ").strip().lower()
    if choice == 'y':
        logging.info(f"User chose to install {tool_friendly_name}.")
        print(f"[+] Attempting to install {tool_friendly_name}. This may require your sudo password.")
        try:
            # Update package lists first
            run_command(["sudo", "-S", "apt-get", "update"], "Apt-get Update", output_file, use_sudo=True)
            # Install the package
            run_command(["sudo", "-S", "apt-get", "install", "-y", package_name], f"Install {tool_friendly_name}", output_file, use_sudo=True)
            
            # Verify installation
            if shutil.which(tool_friendly_name.split()[0].lower()): # Splitting for tools like "Nmap suite" to check "nmap"
                logging.info(f"{tool_friendly_name} installed successfully.")
                print(f"[+] {tool_friendly_name} installed successfully.")
                if output_file:
                    output_file.write(f"[+] {tool_friendly_name} installed successfully.\n")
                return True
            else:
                logging.error(f"Failed to verify {tool_friendly_name} installation.")
                print(f"[-] Failed to verify {tool_friendly_name} installation. Please check manually.")
                if output_file:
                    output_file.write(f"[-] Failed to verify {tool_friendly_name} installation.\n")
                return False
        except Exception as e:
            logging.error(f"Error during {tool_friendly_name} installation: {e}")
            print(f"[-] Error during {tool_friendly_name} installation: {e}")
            if output_file:
                output_file.write(f"[-] Error during {tool_friendly_name} installation: {e}\n")
            return False
    else:
        logging.info(f"User declined to install {tool_friendly_name}.")
        print(f"[-] {tool_friendly_name} will not be installed. Cannot proceed with this test.")
        if output_file:
            output_file.write(f"[-] {tool_friendly_name} not installed. Cannot proceed with this test.\n")
        return False

def ensure_curl_windows(output_file):
    logging.debug("Checking for curl.exe on Windows...")
    
    # Check if curl is already in PATH
    if shutil.which("curl"):
        curl_path = shutil.which("curl")
        logging.debug(f"curl.exe found in PATH at {curl_path}")
        return True, curl_path

    # Define a specific directory for downloaded portable curl
    curl_dir = Path("C:/Program Files/CurlPortable")
    curl_exe_path = curl_dir / "curl.exe"

    if curl_exe_path.exists():
        logging.debug(f"curl.exe found in portable directory at {curl_exe_path}")
        return True, str(curl_exe_path)

    print(f"\n[!] curl.exe not found in PATH or '{curl_dir}'.")
    choice = input(f"Do you want to download portable curl.exe to '{curl_dir}'? (y/N): ").strip().lower()
    if choice == 'y':
        try:
            curl_dir.mkdir(parents=True, exist_ok=True)
            logging.debug(f"Downloading curl.exe to {curl_exe_path}...")
            # Using a direct download link for a common version (might need updating over time)
            # You might want to point to a more stable or official direct link if possible
            # For simplicity, using a known portable build.
            # Official source: https://curl.se/windows/
            # For example, from an official mirror or a reliable source.
            # Example for 64-bit: https://curl.se/windows/dl/curl-8.7.1_1-win64-mingw.zip
            # For direct .exe download, it's usually from a zip file.
            # A direct .exe URL for a stable portable version is harder to guarantee over time.
            # Let's simulate a direct download.
            # A better approach would be to download the zip, extract it.
            # For demonstration, let's assume we can download a bare .exe directly (less common).
            # A more robust solution would involve checking for a zip, extracting it.
            
            # Fallback to guide if direct download of bare .exe is complex
            print("Due to complexities of direct curl.exe download (often bundled in zips),")
            print("please download it manually from https://curl.se/windows/ and place curl.exe in:")
            print(f"  {curl_dir}")
            print("After placing it, re-run the script.")
            if output_file:
                output_file.write(f"[-] curl.exe not found. User guided to download manually to {curl_dir}.\n")
            return False, None # Guide the user instead of complex auto-download/extract logic

            # If you were to implement download and extract, it would look like this:
            # zip_url = "https://curl.se/windows/dl/curl-8.7.1_1-win64-mingw.zip" # Example
            # zip_path = curl_dir / "curl.zip"
            # urllib.request.urlretrieve(zip_url, zip_path)
            # import zipfile
            # with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            #     zip_ref.extractall(curl_dir)
            # # Assuming curl.exe is directly in the extracted folder or a subfolder like 'bin'
            # # Need to adjust curl_exe_path based on zip content
            # if (curl_dir / "bin" / "curl.exe").exists():
            #     curl_exe_path = curl_dir / "bin" / "curl.exe"

            # logging.debug("curl.exe downloaded and extracted successfully.")
            # return True, str(curl_exe_path)

        except Exception as e:
            logging.error(f"Failed to download/prepare curl.exe: {e}")
            print(f"[-] Failed to download/prepare curl.exe: {e}")
            if output_file:
                output_file.write(f"[-] Failed to download/prepare curl.exe: {e}\n")
            return False, None
    else:
        logging.info("User declined to download curl.exe.")
        print("[-] curl.exe will not be downloaded. Cannot proceed with Curl test.")
        if output_file:
            output_file.write("[-] curl.exe not downloaded. Cannot proceed with Curl test.\n")
        return False, None

def guide_nmap_suite_windows(output_file):
    logging.debug("Guiding user to install Nmap suite on Windows.")
    print("\n[!] Nmap or Nping not found.")
    print("    On Windows, it's recommended to install the official Nmap suite.")
    print("    Please download and run the installer from: https://nmap.org/download.html")
    print("    After installation, you can restart this script to use Nmap/Nping.")
    if output_file:
        output_file.write("[-] Nmap/Nping not found. User guided to install from https://nmap.org/download.html.\n")
    return False

def ensure_etl2pcapng():
    logging.debug("Checking for etl2pcapng.exe...")
    exe_path = Path("C:/etl2pcapng/etl2pcapng.exe")
    if exe_path.exists():
        logging.debug(f"etl2pcapng.exe found at {exe_path}")
        return True, str(exe_path)

    try:
        exe_path.parent.mkdir(parents=True, exist_ok=True)
        logging.debug("Downloading etl2pcapng.exe...")
        url = "https://github.com/microsoft/etl2pcapng/releases/latest/download/etl2pcapng.exe"
        urllib.request.urlretrieve(url, exe_path)
        logging.debug("etl2pcapng.exe downloaded successfully.")
        return True, str(exe_path)
    except Exception as e:
        logging.error(f"Failed to download etl2pcapng.exe: {e}")
        return False, None

def check_admin_privileges():
    logging.debug("Checking admin privileges...")
    if platform.system().lower() == "windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            logging.debug(f"Admin privileges: {'Yes' if is_admin else 'No'}")
            return is_admin
        except:
            logging.error("Error checking admin privileges.")
            return False
    else:
        is_admin = os.geteuid() == 0
        logging.debug(f"Admin privileges: {'Yes' if is_admin else 'No'}")
        return is_admin

def print_progress_bar_dynamic(progress_queue, label):
    import sys
    import time

    start_time = time.time()
    spinner = ['|', '/', '-', '\\']
    idx = 0

    while True:
        try:
            if progress_queue.get_nowait() == "done":
                break
        except Empty:
            pass

        elapsed = int(time.time() - start_time)
        sys.stdout.write(f"\r[+] {label} running... {spinner[idx % len(spinner)]} Elapsed: {elapsed}s")
        sys.stdout.flush()
        idx += 1
        time.sleep(0.1)

    sys.stdout.write("\n")
    sys.stdout.flush()

def get_sudo_password():
    logging.debug("Retrieving sudo password...")
    # On Windows, sudo is not used, so return None immediately
    if platform.system().lower() == "windows":
        return None
    # On Linux, if user is in admin group and doesn't need password, return empty string
    sudo_password = os.getenv("SUDO_PASS")
    if not sudo_password:
        try:
            import getpass
            sudo_password = getpass.getpass("Enter sudo password: ")
        except Exception:
            logging.error("Error retrieving sudo password.")
            sudo_password = None
    return sudo_password

def run_command(command: list, label: str, output_file=None, use_sudo=False):
    logging.debug(f"Preparing to run command: {command} with label: {label}")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[+] Running {label} at {timestamp}:")
    print(f"Running command: {' '.join(command)}")
    if output_file:
        output_file.write(f"\n[+] Running {label} at {timestamp}:\n")

    original_handler = signal.getsignal(signal.SIGINT)

    def stop_handler(signum, frame):
        raise KeyboardInterrupt("Ctrl+S pressed. Stopping the command.")

    signal.signal(signal.SIGINT, stop_handler)

    progress_queue = Queue()
    progress_thread = Thread(target=print_progress_bar_dynamic, args=(progress_queue, label))
    progress_thread.start()

    try:
        if use_sudo and platform.system().lower() != "windows":
            logging.debug("Adding sudo to the command.")
            command = ["sudo", "-S"] + command

        process = subprocess.Popen(
            command,
            text=True,
            stdin=subprocess.PIPE if use_sudo else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if platform.system().lower() == "windows" else 0,
            preexec_fn=os.setsid if platform.system().lower() != "windows" else None
        )

        logging.debug(f"Command started: {command}")
        if use_sudo:
            sudo_password = get_sudo_password()
            if sudo_password:
                stdout, stderr = process.communicate(input=sudo_password + "\n")
            else:
                stdout, stderr = process.communicate()
        else:
            stdout, stderr = process.communicate()

        progress_queue.put("done")
        progress_thread.join()

        print(stdout)
        if output_file:
            output_file.write(f"{stdout}\n")
        if process.returncode != 0:
            logging.error(f"{label} failed: {stderr.strip()}")
            print(f"[-] {label} failed: {stderr.strip()}")
            if output_file:
                output_file.write(f"[-] {label} failed: {stderr.strip()}\n")
    except KeyboardInterrupt:
        logging.warning(f"{label} interrupted by user.")
        print(f"\n[!] {label} interrupted.")
        progress_queue.put("done")
        progress_thread.join()
        if use_sudo:
            subprocess.run(["sudo", "kill", str(process.pid)])
        else:
            if platform.system().lower() == "windows":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except Exception as e:
        logging.error(f"Error running {label}: {e}")
        print(f"[-] Error running {label}: {e}")
        progress_queue.put("done")
        progress_thread.join()
        if output_file:
            output_file.write(f"[-] Error running {label}: {e}\n")
    finally:
        logging.debug(f"Command {label} finished.")
        signal.signal(signal.SIGINT, original_handler)

def detect_os():
    os_type = "windows" if platform.system().lower() == "windows" else "linux"
    logging.debug(f"Detected OS: {os_type}")
    return "linux" if platform.system() != "Windows" else "windows"

def display_banner():
    """
    Displays the ASCII art banner for the tool.
    """
    banner = r"""
##########################################################
##########################################################    
           /^\/^\
         _|__|  O|     Network Management Package v1.0
\/     /~     \_/ \
 \____|__________/  \
        \_______      \
                `\     \                 \
                  |     |                  \
                 /      /                    \
                /     /                       \\
              /      /                         \ \
             /     /                            \  \
           /     /             _----_            \   \
          /     /           _-~      ~-_         |   |
         (      (        _-~    _--_    ~-_     _/   |
          \      ~-____-~    _-~    ~-_    ~-_-~    /
            ~-_           _-~          ~-_       _-~
               ~--______-~                ~-___-~
##########################################################
##########################################################               
"""
    print(banner)
    
def select_menu():
    print("\nSelect diagnostic test to run:")
    print("1. Nmap")
    print("2. Nping")
    print("3. Curl")
    print("4. Extended ping test")
    print("5. PCAP capture")
    print("6. MTU Discovery Test")
    print("7. List Active Connections")
    print("8. Full Diagnostic")
    print("9. Exit")
    return input("Enter choice [1-9]: ").strip()

def run_nmap(output_file, os_type):
    print("Running nmap...")
    if shutil.which("nmap"):
        target = input("Enter target IP for nmap: ").strip()
        port = input("Enter port for nmap: ").strip()
        logging.debug(f"Running Nmap scan on target: {target}, port: {port}")
        run_command(["nmap", "-p", port, "-T4", "-A", "-v", target], "Nmap scan", output_file) # Corrected '-sO' to just '-p' or add '-sS' for SYN scan if desired
    else:
        logging.error("Nmap is not installed or not in PATH.")
        if os_type == "windows":
            guide_nmap_suite_windows(output_file)
        else: # Linux
            install_linux_tool("nmap", "Nmap suite", output_file)

def run_nping(output_file, os_type): # <--- MODIFIED: Added os_type
    print("Running nping...")
    if shutil.which("nping"):
        target = input("Enter target IP for nping: ").strip()
        port = input("Enter port for nping: ").strip()
        count="20"
        logging.debug(f"Running Nping test on target: {target}, port: {port}")
        run_command(["nping", "--tcp", "-c", count, target, "-p", port], "Nping test", output_file, use_sudo=True)
    else:
        logging.error("Nping is not installed or not in PATH.")
        if os_type == "windows":
            guide_nmap_suite_windows(output_file)
        else: # Linux
            # Nping is part of the nmap package on most Linux distros
            install_linux_tool("nmap", "Nmap suite", output_file)

# Helper function to validate IP address or domain name
def is_valid_ip_or_domain(target):
    # Regex for a basic IPv4 address (e.g., 192.168.1.1)
    # and a basic domain name (e.g., example.com, subdomain.example.org)
    # This regex is simplified and might not cover all edge cases,
    # but it's good for a common diagnostic tool.
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    domain_regex = r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?$"

    if re.match(ip_regex, target):
        # Further check for valid IP segments (0-255)
        parts = list(map(int, target.split('.')))
        if all(0 <= part <= 255 for part in parts):
            logging.debug(f"Target '{target}' identified as a valid IPv4 address.")
            return True
    if re.match(domain_regex, target):
        logging.debug(f"Target '{target}' identified as a valid domain name.")
        return True
    
    logging.warning(f"Target '{target}' is not a valid IP or domain format.")
    return False

# Helper function to validate port number
def is_valid_port(port_str):
    if not port_str: # Port is optional, so an empty string is valid
        logging.debug("Port input is empty (optional).")
        return True
    try:
        port = int(port_str)
        if 1 <= port <= 65535:
            logging.debug(f"Port '{port_str}' is a valid port number.")
            return True
        else:
            logging.warning(f"Port '{port_str}' is out of valid range (1-65535).")
            return False
    except ValueError:
        logging.warning(f"Port '{port_str}' is not a valid integer.")
        return False

# Helper function to validate IP address or domain name
def is_valid_ip_or_domain(target):
    # Regex for a basic IPv4 address (e.g., 192.168.1.1)
    # and a basic domain name (e.g., example.com, subdomain.example.org)
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


def run_curl(output_file, os_type):
    """
    Runs various curl tests based on user selection.
    This function is enhanced to include:
    1. HTTP Header Check (Original Test)
    2. TCP Port Connectivity Test
    3. Detailed Latency/Timing Analysis
    """
    curl_path = shutil.which("curl")
    
    # --- Step 1: Ensure curl is available ---
    print("Running curl...")
    if os_type == "windows" and not curl_path:
        found_curl, path = ensure_curl_windows(output_file)
        if found_curl:
            curl_path = path
        else:
            print("[-] Cannot proceed with Curl test as curl is not available.")
            return

    elif os_type == "linux" and not curl_path:
        installed = install_linux_tool("curl", "curl", output_file)
        if installed:
            curl_path = shutil.which("curl")
        else:
            print("[-] Cannot proceed with Curl test as curl is not available.")
            return

    if not curl_path:
        logging.error("Curl is not available after checks.")
        print("[-] Curl is not available. Cannot run Curl test.")
        return

    # --- Step 2: Present the new Curl test menu ---
    print("\nSelect a Curl test type:")
    print("1. HTTP Header Check (Checks web server response)")
    print("2. TCP Port Connectivity (Checks if a port is open)")
    print("3. Detailed Latency/Timing Test (Measures performance)")
    
    choice = input("Enter choice [1-3]: ").strip()
    logging.debug(f"User selected Curl test type: {choice}")

    # --- Step 3: Execute the chosen test ---
    if choice == "1":
        # --- Test 1: HTTP Header Check (Original) ---
        print("\n[+] Running HTTP Header Check...")
        target = input("Enter target (IP or domain) for curl: ").strip()
        if not is_valid_ip_or_domain(target):
            print("[-] Invalid target. Please enter a valid IP address or domain name.")
            return

        protocol = input("Enter protocol (http or https): ").strip().lower()
        if protocol not in ["http", "https"]:
            print("[-] Invalid protocol. Please enter 'http' or 'https'.")
            return

        port = input("Enter port for curl (optional, press Enter to skip): ").strip()
        if not is_valid_port(port):
            print("[-] Invalid port. Please enter a number between 1 and 65535, or leave empty.")
            return

        url = f"{protocol}://{target}"
        if port:
            url += f":{port}"

        logging.debug(f"Running Curl Header Check on URL: {url}")
        run_command([curl_path, "-I", "-v", url], "Curl Header Check", output_file)

    elif choice == "2":
        # --- Test 2: TCP Port Connectivity ---
        print("\n[+] Running TCP Port Connectivity Test...")
        target = input("Enter target IP or domain for port check: ").strip()
        if not is_valid_ip_or_domain(target):
            print("[-] Invalid target. Please enter a valid IP address or domain name.")
            return
            
        port = input("Enter port to check: ").strip()
        if not is_valid_port(port) or not port:
            print("[-] Invalid port. Please enter a number between 1 and 65535.")
            return
            
        # Using telnet syntax with curl to check raw port connectivity
        # The -v flag is essential to see the connection attempt details.
        url = f"telnet://{target}:{port}"
        logging.debug(f"Running Curl Port Connectivity test on: {url}")
        print(f"[!] Checking connection to {target} on port {port}. Look for 'Connected to...' in the output.")
        run_command([curl_path, "-v", "--connect-timeout", "10", url], "Curl Port Connectivity", output_file)

    elif choice == "3":
        # --- Test 3: Detailed Latency/Timing Test ---
        print("\n[+] Running Detailed Latency/Timing Test...")
        target = input("Enter full URL (e.g., https://www.google.com): ").strip()

        # A simple check to ensure it looks like a URL
        if not target.startswith(("http://", "https://")):
            print("[-] Invalid URL. Please include 'http://' or 'https://'.")
            return

        # This format string tells curl what timing details to output.
        # Each metric is explained in the documentation below.
        curl_format = """
        ---------------------------------
        DNS Lookup Time:    %{time_namelookup}s
        TCP Connect Time:   %{time_connect}s
        TLS Handshake Time: %{time_appconnect}s
        Pre-Transfer Time:  %{time_pretransfer}s
        Time to First Byte: %{time_starttransfer}s
        ---------------------------------
        Total Request Time: %{time_total}s
        """
        
        logging.debug(f"Running Curl Latency Test on URL: {target}")
        print(f"[!] Fetching detailed timings for {target}. Output will be shown below.")

        # -w: Use the format string
        # -s: Silent mode to hide progress
        # -o /dev/null: Discard the body of the response so we only see our formatted output.
        # os.devnull is a cross-platform way to write to a null device.
        run_command(
            [curl_path, "-w", curl_format, "-s", "-o", os.devnull, target],
            "Curl Latency Test",
            output_file
        )
    else:
        logging.warning("Invalid selection for Curl test.")
        print("[-] Invalid selection.")

def run_extended_ping(output_file, os_type):
    print("Running extended ping...")
    target = input("Enter target IP for extended ping: ").strip()
    count = "https"
    logging.debug(f"Running extended ping test on target: {target}, count: {count}")
    run_command(["ping", "-n" if os_type == "windows" else "-c", count, target], "Extended ping test", output_file)

def run_pcap_capture(output_file, os_type):
    print("Running pcap capture...")
    target = input("Enter target IP for PCAP capture: ").strip()
    duration = 5  # Duration in minutes
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    desktop = Path.home() / "desktop"
    desktop.mkdir(parents=True, exist_ok=True)

    if os_type == "windows":
        etl_file = desktop / f"net_trace_{timestamp}.etl"
        pcap_file = desktop / f"net_trace_{timestamp}.pcap"
        logging.debug(f"Starting PCAP capture on Windows for target: {target}")
        run_command(["netsh", "trace", "start", "capture=yes", f"IPv4.Address={target}",
                     f"Maxsize=2000M", f"tracefile={etl_file}", "overwrite=yes", "persistent=yes"],
                     "PCAP capture (Windows)", output_file)
        time.sleep(duration * 60)
        run_command(["netsh", "trace", "stop"], "Stop PCAP (Windows)", output_file)

        found, path = ensure_etl2pcapng()
        if found:
            logging.debug(f"Converting ETL to PCAP using etl2pcapng.exe at {path}")
            run_command([path, str(etl_file), str(pcap_file)], "Convert ETL to PCAP", output_file)
        else:
            logging.error("etl2pcapng.exe not found.")
            print("[-] etl2pcapng.exe not found at C:\\etl2pcapng\\etl2pcapng.exe")
            if output_file:
                output_file.write("[-] etl2pcapng.exe not found at C:\\etl2pcapng\\etl2pcapng.exe\n")
    else: # Linux
        pcap_file = desktop / f"pcap-{target.replace('.', '_')}-{timestamp}.pcap"
        tcpdump_path = shutil.which("tcpdump")

        if not tcpdump_path: # Check if tcpdump is missing
            installed = install_linux_tool("tcpdump", "tcpdump", output_file)
            if installed:
                tcpdump_path = shutil.which("tcpdump") # Get path after installation
            else:
                print("[-] Cannot proceed with PCAP capture as tcpdump is not available.")
                if output_file:
                    output_file.write("[-] PCAP capture failed: tcpdump not available.\n")
                return # Exit if tcpdump is still not available

        if tcpdump_path: # Now proceed if tcpdump_path is available
            logging.debug(f"Starting PCAP capture on Linux for target: {target}")
            process = subprocess.Popen(
                ["sudo", "-S", tcpdump_path, "-i", "any", "-w", str(pcap_file), "host", target], # Use tcpdump_path
                stdin=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            try:
                sudo_password = get_sudo_password()
                if sudo_password:
                    process.stdin.write((sudo_password + "\n").encode())
                    process.stdin.flush()
                logging.debug(f"PCAP capture started. File will be saved to {pcap_file}")
                print(f"Starting PCAP capture for {duration} minutes...")
                time.sleep(duration * 60)
            except KeyboardInterrupt:
                logging.warning("PCAP capture interrupted by user.")
                print("\n[!] PCAP capture interrupted by user.")
            finally:
                subprocess.run(["sudo", "kill", str(process.pid)])
                process.wait()
                logging.debug(f"PCAP capture completed. File saved to {pcap_file}")
                print(f"PCAP capture completed. File saved to {pcap_file}")
                if output_file:
                    output_file.write(f"\n[+] PCAP capture completed. File saved to {pcap_file}\n")

    if os_type == "windows":
        etl_file = desktop / f"net_trace_{timestamp}.etl"
        pcap_file = desktop / f"net_trace_{timestamp}.pcap"
        logging.debug(f"Starting PCAP capture on Windows for target: {target}")
        run_command(["netsh", "trace", "start", "capture=yes", f"IPv4.Address={target}",
                     f"Maxsize=2000M", f"tracefile={etl_file}", "overwrite=yes", "persistent=yes"],
                    "PCAP capture (Windows)", output_file)
        time.sleep(duration * 60)
        run_command(["netsh", "trace", "stop"], "Stop PCAP (Windows)", output_file)

        found, path = ensure_etl2pcapng()
        if found:
            logging.debug(f"Converting ETL to PCAP using etl2pcapng.exe at {path}")
            run_command([path, str(etl_file), str(pcap_file)], "Convert ETL to PCAP", output_file)
        else:
            logging.error("etl2pcapng.exe not found.")
            print("[-] etl2pcapng.exe not found at C:\\etl2pcapng\\etl2pcapng.exe")
            if output_file:
                output_file.write("[-] etl2pcapng.exe not found at C:\\etl2pcapng\\etl2pcapng.exe\n")
    else:
        pcap_file = desktop / f"pcap-{target.replace('.', '_')}-{timestamp}.pcap"
        if shutil.which("tcpdump"):
            logging.debug(f"Starting PCAP capture on Linux for target: {target}")
            process = subprocess.Popen(
                ["sudo", "-S", "tcpdump", "-i", "any", "-w", str(pcap_file), "host", target],
                stdin=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            try:
                sudo_password = get_sudo_password()
                if sudo_password:
                    process.stdin.write((sudo_password + "\n").encode())
                    process.stdin.flush()
                logging.debug(f"PCAP capture started. File will be saved to {pcap_file}")
                print(f"Starting PCAP capture for {duration} minutes...")
                time.sleep(duration * 60)
            except KeyboardInterrupt:
                logging.warning("PCAP capture interrupted by user.")
                print("\n[!] PCAP capture interrupted by user.")
            finally:
                subprocess.run(["sudo", "kill", str(process.pid)])
                process.wait()
                logging.debug(f"PCAP capture completed. File saved to {pcap_file}")
                print(f"PCAP capture completed. File saved to {pcap_file}")
                if output_file:
                    output_file.write(f"\n[+] PCAP capture completed. File saved to {pcap_file}\n")

# --- [NEW] run_mtu_discovery Function ---
def run_mtu_discovery(output_file, os_type):
    """
    Performs an iterative ping test to discover the optimal MTU for a path.
    It sends pings with the "Don't Fragment" bit set, decreasing the packet
    size until a ping succeeds.
    """
    print("\n[+] Starting MTU Discovery Test...")
    target = input("Enter target IP or domain for MTU discovery: ").strip()

    if not is_valid_ip_or_domain(target):
        print(f"[-] Invalid target: {target}. Please enter a valid IP address or domain name.")
        return

    # The payload size is the part of the ICMP packet we control.
    # The total MTU is this payload size + 28 bytes (20 for IP header, 8 for ICMP header).
    # We start high and work our way down.
    for payload_size in range(1472, 1300, -10): # Test from 1500 MTU downwards
        mtu = payload_size + 28
        print(f"\n[!] Testing with MTU {mtu} (payload size {payload_size})...")
        if output_file:
            output_file.write(f"\n[!] Testing with MTU {mtu} (payload size {payload_size})...\n")

        if os_type == "windows":
            command = ["ping", target, "-f", "-l", str(payload_size), "-n", "1", "-w", "2000"]
        else: # linux
            command = ["ping", target, "-M", "do", "-s", str(payload_size), "-c", "1", "-W", "2"]

        try:
            # We use subprocess.run directly here for simpler output capturing.
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)

            # Check for success (return code 0 and no fragmentation error)
            if result.returncode == 0:
                print(f"[+] SUCCESS!")
                print(f"[+] MTU Discovery Complete. Optimal MTU for the path to {target} is {mtu}.")
                if output_file:
                    output_file.write(f"[+] SUCCESS! Optimal MTU is {mtu}.\n")
                return # Exit after the first success
            
            # Check for the specific fragmentation error message
            elif "fragmented" in result.stdout.lower() or "frag needed" in result.stderr.lower():
                print("[-] FAILED: Packet needs to be fragmented.")
                if output_file:
                    output_file.write("[-] FAILED: Packet needs to be fragmented.\n")
            else:
                # Handle other errors like host unreachable
                print(f"[-] FAILED: Ping failed. Error: {result.stderr.strip() or result.stdout.strip()}")
                if output_file:
                    output_file.write(f"[-] FAILED: {result.stderr.strip() or result.stdout.strip()}\n")
                time.sleep(1) # Brief pause before next attempt

        except subprocess.TimeoutExpired:
            print("[-] FAILED: Ping timed out.")
            if output_file:
                output_file.write("[-] FAILED: Ping timed out.\n")

    print("\n[-] MTU Discovery Failed. Could not find a working MTU in the tested range.")
    if output_file:
        output_file.write("\n[-] MTU Discovery Failed.\n")

# --- [NEW] run_netstat Function ---
def run_netstat(output_file, os_type):
    """
    Lists all active network connections and listening ports using the
    native 'netstat' command.
    """
    print("\n[+] Listing active network connections and listening ports...")
    
    if os_type == "windows":
        # -a: all connections, -n: numeric, -o: show owning process ID
        command = ["netstat", "-ano"]
    else: # linux
        # -a: all, -n: numeric, -t: tcp, -p: show program name/PID
        command = ["netstat", "-antp"]
        
    # We can reuse our main run_command function for this.
    run_command(command, "List Active Connections (netstat)", output_file, use_sudo=True if os_type == 'linux' else False)

def run_full_diagnostic(output_file, os_type): # <--- MODIFIED: Added os_type
    print("Running full diagnostic...")
    target = input("Enter target IP or domain for full diagnostic: ").strip()
    port = input("Enter port for full diagnostic tools: ").strip()
    count = "20"
    logging.debug(f"Running full diagnostic on target: {target}, port: {port}")

    # Nmap
    nmap_present = shutil.which("nmap")
    if not nmap_present:
        if os_type == "windows":
            guide_nmap_suite_windows(output_file)
        else:
            nmap_present = install_linux_tool("nmap", "Nmap suite", output_file)
    if nmap_present:
        run_command(["nmap", "-p", port, "-T4", "-A", "-v", target], "Nmap scan", output_file)

    # Nping
    nping_present = shutil.which("nping")
    if not nping_present:
        if os_type == "windows":
            guide_nmap_suite_windows(output_file)
        else:
            nping_present = install_linux_tool("nmap", "Nmap suite", output_file) # nping is part of nmap
    if nping_present:
        run_command(["nping", "--tcp", "-c", count, target, "-p", port], "Nping test", output_file, use_sudo=True)
    
    # Curl
    curl_present = shutil.which("curl")
    curl_actual_path = None
    if os_type == "windows" and not curl_present:
        found_curl, path = ensure_curl_windows(output_file)
        if found_curl:
            curl_actual_path = path
            curl_present = True
    elif os_type == "linux" and not curl_present: 
        installed = install_linux_tool("curl", "curl", output_file)
        if installed:
            curl_actual_path = shutil.which("curl")
            curl_present = True

    if curl_present:
        protocol = input("Enter protocol for curl (http or https): ").strip().lower()
        if protocol not in ["http", "https"]:
            logging.warning("Invalid protocol entered for Curl test in full diagnostic.")
            print("[-] Invalid protocol. Please enter 'http' or 'https'.")
            return

        curl_url = f"{protocol}://{target}:{port}"
        curl_command_full_diag = [curl_actual_path, "-I", curl_url] if curl_actual_path else ["curl", "-I", curl_url]
        run_command(curl_command_full_diag, "Curl test (Full Diagnostic)", output_file)
    
    # Ping
    run_command(["ping", "-n" if os_type == "windows" else "-c", count, target], "Ping test", output_file)
    
    # PCAP Capture 
    run_pcap_capture(output_file, os_type)
    
    
def get_output_file(): 
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"tool_diagn_{timestamp}.txt"
    try:
        desktop = Path.home() / "desktop"
        desktop.mkdir(parents=True, exist_ok=True)
        logging.debug(f"Creating output file at {desktop / filename}")
        return open(desktop / filename, "w")
    except Exception as e:
        logging.error(f"Failed to create output file on desktop: {e}. Using fallback directory.")
        try:
            fallback_dir = Path(".") / "logs"
            fallback_dir.mkdir(parents=True, exist_ok=True)
            return open(fallback_dir / filename, "w")
        except Exception as e2:
            logging.error(f"Failed to create output file in fallback directory: {e2}. Using os.devnull.")
            return open(os.devnull, 'w')

def main():
    display_banner() # Banner is called here!
    logging.debug("Starting main function.")
    os_type = detect_os()
    is_admin = check_admin_privileges()

    logging.info(f"OS detected: {os_type}")
    logging.info(f"Admin privileges: {'Yes' if is_admin else 'No'}")

    if os_type == "windows":
        etl_found, etl_path = ensure_etl2pcapng()
        logging.debug(f"etl2pcapng.exe found: {'Yes' if etl_found else 'No'} at {etl_path}")

    output_file = get_output_file()
    logging.debug("Output file created.")

    while True:
        choice = select_menu()
        logging.debug(f"User selected menu option: {choice}")
        if choice == "1":
            run_nmap(output_file, os_type)
        elif choice == "2":
            run_nping(output_file, os_type)
        elif choice == "3":
            run_curl(output_file, os_type)
        elif choice == "4":
            run_extended_ping(output_file, os_type)
        elif choice == "5":
            run_pcap_capture(output_file, os_type)
        elif choice == "6": # New option
            run_mtu_discovery(output_file, os_type)
        elif choice == "7": # New option
            run_netstat(output_file, os_type)
        elif choice == "8": # Re-numbered
            run_full_diagnostic(output_file, os_type)
        elif choice == "9": # Re-numbered
            logging.info("Exiting program.")
            print("[+] Exiting. Log saved.")
            output_file.close()
            break
        else:
            logging.warning("Invalid selection.")
            print("[-] Invalid selection.")

if __name__ == "__main__":
    # Helper functions for validation, assuming they are defined somewhere above main
    def is_valid_ip_or_domain(target):
        ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
        if re.match(ip_regex, target) or re.match(domain_regex, target):
            return True
        return False
    
    main()

