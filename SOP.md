Got it 👍 — the Confluence formatting won’t look clean in GitHub, so I’ll reformat your SOP into a **GitHub-friendly Markdown (.md)** style with proper headers, tables, and code blocks.

Here’s the cleaned-up version:


## Standard Operating Procedure: NMP Network Diagnostic Toolkit

| Field        | Value                  |
|--------------|------------------------|
| **Document ID** | SOP-NET-NMP-v1.0     |
| **Version**     | 1.0                  |
| **Author**      | Your Name/Team       |
| **Date**        | June 7, 2025         |
| **Status**      | Final                |

---

## 1.0 Purpose
This document provides the Standard Operating Procedure (SOP) for using the **NMP Network Diagnostic Toolkit (`net.py`)**.  
The purpose of this tool is to provide a standardized, cross-platform suite of utilities for troubleshooting and diagnosing network connectivity and performance issues within our infrastructure.

---

## 2.0 Scope
This SOP applies to all **Network Administrators, System Engineers, and IT Support personnel** responsible for maintaining and troubleshooting servers and network services on both **Windows** and **Linux** operating systems.

---

## 3.0 Prerequisites
Before using the NMP toolkit, ensure the following are met on the client machine:

1. **Python**: Python 3.6 or newer must be installed.
2. **Git**: Git client must be installed to clone the repository.
3. **Repository Files**: Clone the toolkit from GitHub:
   ````
   git clone https://github.com/your-username/nmp.git
   cd nmp
   ````

4. **Python Dependencies**: Install required packages:

   ```bash
   pip install -r requirements.txt
   ```
5. **Administrative Privileges**:
   Required for some tests (e.g., PCAP capture, nping, package installation). Use **sudo** on Linux or run as **Administrator** on Windows.

---

## 4.0 General Operation

### 4.1 Launching the Tool

Run the script from your terminal:

* **Windows (PowerShell):**

  ```powershell
  python net.py
  ```

* **Linux (with sudo for full functionality):**

  ```bash
  sudo python net.py
  ```

A banner will display, followed by the main test menu.

---

### 4.2 Logging

All results are saved to timestamped log files.

* **Format:**
  `tool_diagn_YYYYMMDD_HHMMSS.txt`

* **Location:**
  Saved in the `logs/` directory or on the user’s Desktop.

---

## 5.0 Test Procedures

This section explains each diagnostic test available in the toolkit.

---

### 5.1 Nmap Scan

* **Purpose:** Scan a target host for open ports, services, and OS info.
* **Execution:** Select option `1`.

**Input Format:**

| Prompt                   | Example Input        | Description                          |
| ------------------------ | -------------------- | ------------------------------------ |
| Enter target IP for nmap | `10.0.0.5`           | The target machine’s IP address.     |
| Enter port for nmap      | `443` or `22,80,443` | Single port or comma-separated list. |

**Interpreting Results:**

| Output Scenario            | Meaning  | Possible Next Step                          |
| -------------------------- | -------- | ------------------------------------------- |
| `Host is up... STATE open` | ✅ OK     | Target reachable, port open and listening.  |
| `STATE closed`             | ❌ Not OK | Target reachable, no service on that port.  |
| `STATE filtered`           | ❌ Not OK | Firewall blocking access → check rules.     |
| `Host seems down`          | ❌ Not OK | Target unresponsive → check IP/host status. |

---

### 5.2 Nping Test

* **Purpose:** Send TCP packets to test connectivity/latency (bypasses ICMP).
* **Execution:** Select option `2`.

**Input Format:**

| Prompt               | Example Input | Description           |
| -------------------- | ------------- | --------------------- |
| Enter target IP      | `10.0.0.5`    | Target machine’s IP.  |
| Enter port for nping | `3389`        | Destination TCP port. |

**Interpreting Results:**

| Output Scenario               | Meaning  | Possible Next Step                       |
| ----------------------------- | -------- | ---------------------------------------- |
| `Rcvd: 20... Lost: 0 (0.00%)` | ✅ OK     | Excellent connectivity.                  |
| `Lost: > 0`                   | ❌ Not OK | Packet loss → check congestion/firewall. |
| `Failed to resolve target`    | ❌ Not OK | DNS issue → verify hostname.             |

---

### 5.3 Curl Tests

* **Purpose:** Diagnostics for HTTP/S services.
* **Execution:** Select option `3` → choose sub-test.

#### 5.3.1 HTTP Header Check

* ✅ OK: `HTTP/2 200 OK`
* ❌ Not OK: `4xx`/`5xx`, `Could not resolve host`, `Connection refused`

#### 5.3.2 TCP Port Connectivity

* ✅ OK: Output contains `* Connected to <target> (<ip>) port <port>`
* ❌ Not OK: `Connection timed out` or `refused` → firewall/service issue.

#### 5.3.3 Detailed Latency/Timing Test

* High values = ❌ Not OK

  * **High DNS Lookup Time** → slow/unresponsive DNS.
  * **High Time to First Byte** → slow backend app or DB.

---

### 5.4 Extended Ping Test

* **Purpose:** Continuous ICMP ping.
* **Execution:** Option `4`.

**Input Format:**

| Prompt          | Example Input | Description          |
| --------------- | ------------- | -------------------- |
| Enter target IP | `8.8.8.8`     | IP or domain to ping |

**Interpreting Results:**

| Output Scenario                | Meaning  | Possible Next Step       |
| ------------------------------ | -------- | ------------------------ |
| `Reply from <IP>... 0% loss`   | ✅ OK     | Target fully reachable.  |
| `Request timed out`            | ❌ Not OK | Check routing/firewalls. |
| `Destination host unreachable` | ❌ Not OK | Routing problem.         |

---

### 5.5 PCAP Capture

* **Purpose:** Capture all traffic to/from a target for Wireshark analysis.
* **Execution:** Option `5` (admin/sudo required).

**Input Format:**

| Prompt          | Example Input | Description                 |
| --------------- | ------------- | --------------------------- |
| Enter target IP | `10.0.0.5`    | IP to capture traffic from. |

**Interpreting Results:**

| Output Scenario                            | Meaning  | Next Step                       |
| ------------------------------------------ | -------- | ------------------------------- |
| `PCAP capture completed. File saved to...` | ✅ OK     | Capture successful.             |
| `permission denied` / `requires elevation` | ❌ Not OK | Run with admin/sudo privileges. |

---

### 5.6 MTU Discovery Test

* **Purpose:** Find max packet size without fragmentation.
* **Execution:** Option `6`.

**Input Format:**

| Prompt                 | Example Input    | Description           |
| ---------------------- | ---------------- | --------------------- |
| Enter target IP/domain | `www.google.com` | Destination for test. |

**Interpreting Results:**

| Output Scenario                | Meaning  | Next Step                                 |
| ------------------------------ | -------- | ----------------------------------------- |
| `SUCCESS! Optimal MTU is XXXX` | ✅ OK     | MTU successfully identified.              |
| `MTU Discovery Failed.`        | ❌ Not OK | Complex connectivity issue → investigate. |

---

### 5.7 List Active Connections (netstat)

* **Purpose:** Show active network connections/listening ports.
* **Execution:** Option `7`.

**Notes:**

* Look for `LISTENING` → ports open.
* Look for `ESTABLISHED` → ongoing connections.
* Use to confirm apps/services or spot unusual activity.

---

## 6.0 Full Diagnostic Procedure

Option `8` runs **all tests sequentially** (Nmap, Nping, Curl, Ping, PCAP) on a target.
You’ll be prompted for IP/port once.
Interpret each section as per **5.0 Test Procedures**.

```
```

![image](https://github.com/user-attachments/assets/a0f87676-8493-4c24-8e86-0efd121cc57e)
