# NMP - Network Management Portal v1.0


A versatile and interactive command-line toolkit for network diagnostics. Designed for network administrators and support engineers, NMP provides a suite of essential tools to troubleshoot network issues on both Windows and Linux systems.

## ✨ Features

NMP wraps powerful command-line tools into a single, user-friendly script, making network diagnostics faster and more efficient.

- **Cross-Platform:** Fully functional on both **Windows** and **Linux** operating systems.
- **Interactive Menu:** An easy-to-navigate menu to select the right tool for the job.
- **Automated Tool Installation:** Automatically prompts to install missing dependencies like Nmap, Nping, and Curl on Linux.
- **Comprehensive Logging:** Saves the output of every test to a timestamped log file on your desktop for easy review.
- **Cross-Platform Tools Suite:**
    - **Nmap & Nping:** For advanced port scanning and packet crafting.
    - **Curl:** For detailed HTTP/S analysis, including header checks, port connectivity, and latency timing.
    - **PCAP Capture:** Captures network traffic to a `.pcap` file for deep-dive analysis in tools like Wireshark.
    - **MTU Discovery:** Automatically determines the optimal Maximum Transmission Unit for a network path to diagnose fragmentation issues.
    - **Netstat:** Displays all active network connections and listening ports.
    - **Full Diagnostic:** Runs a comprehensive suite of tests against a single target for a complete network health check.

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.6+**
- **pip** (for installing dependencies)

For some tests, administrative/root privileges are required to install packages or capture packets. The script will prompt you if elevated permissions are needed.

### Installation & Usage

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/nmp.git](https://github.com/your-username/nmp.git)
    cd nmp
    ```

2.  **Install the required Python package:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the script:**
    ```bash
    python net.py
    ```
    On Linux, you may need to run with `sudo` for certain features:
    ```bash
    sudo python net.py
    ```

4.  **Follow the on-screen menu** to select and run your desired diagnostic test.

---

## 🛠️ Available Tests

1.  **Nmap:** Advanced port and service scanning.
2.  **Nping:** Network packet generation and analysis.
3.  **Curl:** In-depth web request diagnostics (headers, port connectivity, latency).
4.  **Extended ping test:** A standard, continuous ping test.
5.  **PCAP capture:** Captures network packets for offline analysis.
6.  **MTU Discovery Test:** Finds the optimal packet size for a network path.
7.  **List Active Connections:** Shows all active TCP/UDP connections via `netstat`.
8.  **Full Diagnostic:** A sequential run of the most critical tests.
9.  **Exit:** Closes the application.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/your-username/nmp/issues).

---

## 📝 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
